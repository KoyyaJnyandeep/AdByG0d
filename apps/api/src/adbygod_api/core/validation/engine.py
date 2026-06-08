from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.validation.contracts import ExpertVerdict, FusionResult
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.experts.evidence_quality import EvidenceQualityExpert
from adbygod_api.core.validation.experts.contradiction import ContradictionExpert
from adbygod_api.core.validation.experts.graph_reachability import GraphReachabilityExpert
from adbygod_api.core.validation.experts.kerberos import KerberosExpert
from adbygod_api.core.validation.experts.ntlm_relay import NTLMRelayExpert
from adbygod_api.core.validation.experts.acl import ACLExpert
from adbygod_api.core.validation.experts.dcsync import DCSyncExpert
from adbygod_api.core.validation.experts.trust import TrustExpert
from adbygod_api.core.validation.experts.delegation import (
    UnconstrainedDelegationExpert, ConstrainedDelegationExpert, RBCDExpert,
    DelegationChainExpert, KerberosOnlyDCExpert
)
from adbygod_api.core.validation.experts.password_policy import (
    DefaultPasswordPolicyExpert, FineGrainedPolicyExpert, SprayCandidateExpert,
    PasswordNotRequiredExpert
)
from adbygod_api.core.validation.experts.sid_history import (
    SIDHistoryPresenceExpert, SIDHistoryPrivilegedExpert, SIDFilteringTrustExpert
)
from adbygod_api.core.validation.experts.maq_rbcd import (
    MAQExpert, RBCDViaMaqExpert, CreateChildComputerExpert, ComputerTakeoverChainExpert
)
from adbygod_api.core.validation.scoring import ConsensusArbitrator
from adbygod_api.models import ValidationRun, ValidationExpertDecision

log = logging.getLogger(__name__)

_COMMON_EXPERTS: list[type[BaseExpert]] = [
    GraphReachabilityExpert,
    EvidenceQualityExpert,
    ContradictionExpert,
]

_MODULE_DOMAIN_EXPERTS: dict[str, list[type[BaseExpert]]] = {
    "kerberos":        [KerberosExpert],
    "ntlm_relay":      [NTLMRelayExpert],
    "acl":             [ACLExpert],
    "dcsync":          [DCSyncExpert],
    "trust":           [TrustExpert],
    "delegation":      [UnconstrainedDelegationExpert, ConstrainedDelegationExpert, RBCDExpert, DelegationChainExpert, KerberosOnlyDCExpert],
    "password_policy": [DefaultPasswordPolicyExpert, FineGrainedPolicyExpert, SprayCandidateExpert, PasswordNotRequiredExpert],
    "sid_history":     [SIDHistoryPresenceExpert, SIDHistoryPrivilegedExpert, SIDFilteringTrustExpert],
    "maq_rbcd":        [MAQExpert, RBCDViaMaqExpert, CreateChildComputerExpert, ComputerTakeoverChainExpert],
}


def _select_experts(module_id: str) -> list[BaseExpert]:
    domain = _MODULE_DOMAIN_EXPERTS.get(module_id, [])
    return [cls() for cls in domain + _COMMON_EXPERTS]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ValidationConsensusEngine:
    """
    Consensus validation engine.
    Deterministic, assessment-aware, evidence-backed.
    Safe by default — simulation only, no live exploitation.
    """

    execution_mode = "SIMULATION_CONSENSUS"

    def __init__(self, db: AsyncSession):
        self.db = db
        self.arbitrator = ConsensusArbitrator()

    async def run(
        self,
        module_id: str,
        assessment_id: str,
        target: str,
        requested_mode: str,
        created_by: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        from adbygod_api.core.validation.context import build_validation_context
        logs: list[dict[str, Any]] = []
        t0 = 0.0
        mode = requested_mode

        def _log(level: str, msg: str) -> None:
            nonlocal t0
            logs.append({"timestamp": round(t0, 2), "level": level, "message": msg})
            t0 += 0.1
            log.info("[consensus:%s] %s", module_id, msg)

        _log("INFO", f"[{self.execution_mode}] Building validation context for assessment {assessment_id}")
        ctx = await build_validation_context(assessment_id, self.db)
        _log("INFO", f"Domain: {ctx.domain or 'unknown'} | Mode: {mode.upper()} | Module: {module_id}")
        _log("INFO",
             f"Context: {len(ctx.entities)} entities, {len(ctx.edges)} edges, "
             f"{len(ctx.findings)} findings, {len(ctx.evidence)} evidence records")

        # Persist run record (RUNNING)
        run = ValidationRun(
            assessment_id=uuid.UUID(assessment_id),
            module_id=module_id,
            target=target,
            requested_mode=mode,
            execution_mode=self.execution_mode,
            status="RUNNING",
            simulated=True,
            origin="SIMULATED",
            created_by=created_by,
            created_at=_utcnow(),
        )
        self.db.add(run)
        await self.db.flush()
        run_id = str(run.id)
        _log("INFO", f"Validation run {run_id} created (status=RUNNING)")

        # Select and run experts
        experts = _select_experts(module_id)
        _log("INFO", f"Expert router selected {len(experts)} expert(s) for module '{module_id}'")

        expert_decisions = []
        for expert in experts:
            _log("INFO", f"Running {expert.expert_name}...")
            try:
                decision = await expert.analyze(ctx)
            except NotImplementedError:
                decision = expert.evaluate(module_id, ctx)
            expert_decisions.append(decision)
            _log(
                "WARN" if decision.verdict == ExpertVerdict.SUPPORTS_EXPOSURE else "INFO",
                f"{expert.expert_name}: {decision.verdict.value} — {decision.summary[:120]}",
            )

        # Fuse
        _log("INFO", "Fusing expert decisions via ConsensusArbitrator...")
        fusion = self.arbitrator.fuse(expert_decisions, ctx, module_id)
        _log(
            "SUCCESS" if fusion.final_verdict.value in ("LIKELY_EXPOSED", "CONDITIONALLY_EXPOSED") else "INFO",
            f"Final verdict: {fusion.final_verdict.value} | Risk: {fusion.risk_score}/10 | "
            f"Confidence: {fusion.confidence}%",
        )

        # Persist expert decisions
        for decision in expert_decisions:
            ed = ValidationExpertDecision(
                validation_run_id=run.id,
                expert_id=decision.expert_id,
                expert_name=decision.expert_name,
                verdict=decision.verdict.value,
                score_delta=decision.score_delta,
                confidence=decision.confidence,
                severity_hint=decision.severity_hint,
                summary=decision.summary,
                reasoning_json=decision.reasoning,
                supporting_signals_json=decision.supporting_signals,
                contradicting_signals_json=decision.contradicting_signals,
                missing_signals_json=decision.missing_signals,
                evidence_refs_json=decision.evidence_refs,
                related_finding_ids_json=decision.related_finding_ids,
                related_entity_ids_json=decision.related_entity_ids,
                related_edge_ids_json=decision.related_edge_ids,
                telemetry_json=decision.telemetry,
                created_at=_utcnow(),
            )
            self.db.add(ed)

        # Update run to COMPLETED
        run.status = "COMPLETED"
        run.final_verdict = fusion.final_verdict.value
        run.risk_score = fusion.risk_score
        run.confidence = fusion.confidence
        run.consensus_score = fusion.consensus_score
        run.evidence_quality_score = fusion.evidence_quality_score
        run.severity_projection = fusion.severity_projection
        run.summary = fusion.summary
        run.reasoning_json = {
            "what_increased_confidence": fusion.what_increased_confidence,
            "what_reduced_confidence": fusion.what_reduced_confidence,
            "what_would_raise_confidence": fusion.what_would_raise_confidence,
        }
        run.telemetry_json = fusion.telemetry
        run.completed_at = _utcnow()
        await self.db.commit()
        _log("INFO", f"Validation run {run_id} committed (status=COMPLETED)")

        # Build expert decision payloads
        expert_decision_payloads = [
            {
                "expert_id": d.expert_id,
                "expert_name": d.expert_name,
                "verdict": d.verdict.value,
                "score_delta": d.score_delta,
                "confidence": d.confidence,
                "severity_hint": d.severity_hint,
                "summary": d.summary,
                "reasoning": d.reasoning,
                "supporting_signals": d.supporting_signals,
                "contradicting_signals": d.contradicting_signals,
                "missing_signals": d.missing_signals,
                "telemetry": d.telemetry,
            }
            for d in expert_decisions
        ]

        return {
            "run_id": run_id,
            "assessment_id": ctx.assessment_id,
            "module_id": module_id,
            "target": target,
            "status": "completed",
            "execution_mode": self.execution_mode,
            "origin": "SIMULATED",
            "simulated": True,
            "requested_mode": mode,
            # Backward-compatible fields
            "module": _module_display_name(module_id),
            "findings": len(ctx.findings),
            "risk_score": fusion.risk_score,
            "confidence": fusion.confidence,
            "operator_brief": fusion.operator_brief,
            "impact": fusion.impact,
            "blast_radius": fusion.blast_radius,
            "mapped_attack_steps": fusion.mapped_attack_steps,
            "affected_assets": [ctx.entity_name(eid) for d in expert_decisions for eid in d.related_entity_ids[:2]][:8],
            "evidence": [{"title": r, "detail": "", "signal": "", "confidence": 80} for r in fusion.what_increased_confidence[:3]],
            "safeguards": fusion.safeguards,
            "recommended_actions": fusion.recommended_actions,
            "control_mapping": fusion.control_mapping,
            "estimated_time_to_validate": "evidence-based",
            "telemetry": fusion.telemetry,
            # Rich new fields
            "final_verdict": fusion.final_verdict.value,
            "confidence_band": fusion.confidence_band.value,
            "consensus_score": fusion.consensus_score,
            "evidence_quality_score": fusion.evidence_quality_score,
            "evidence_quality_band": fusion.evidence_quality_band.value,
            "severity_projection": fusion.severity_projection,
            "expert_decisions": expert_decision_payloads,
            "evidence_summary": fusion.evidence_summary,
            "contradictions": fusion.contradictions,
            "what_increased_confidence": fusion.what_increased_confidence,
            "what_reduced_confidence": fusion.what_reduced_confidence,
            "what_would_raise_confidence": fusion.what_would_raise_confidence,
            "counts": {
                "experts_run": len(expert_decisions),
                "supporting_experts": fusion.support_count,
                "contradicting_experts": fusion.contradiction_count,
                "insufficient_data_experts": fusion.insufficient_count,
                "supporting_evidence": len(ctx.evidence),
                "contradicting_signals": len(fusion.contradictions),
            },
            "logs": logs,
            "next_action": {
                "title": fusion.recommended_actions[0] if fusion.recommended_actions else "Review findings",
                "impact": fusion.severity_projection,
            },
        }


def _serialize_fusion(fusion: Any) -> dict:
    def _j(v: Any) -> Any:
        if hasattr(v, "value"):
            return v.value
        if hasattr(v, "__dataclass_fields__"):
            return {k: _j(getattr(v, k)) for k in v.__dataclass_fields__}
        if isinstance(v, (list, tuple, set)):
            return [_j(i) for i in v]
        if isinstance(v, dict):
            return {str(k): _j(val) for k, val in v.items()}
        return v
    return _j(fusion) if fusion is not None else {}


class ValidationConsensusEngineV2:
    """Consensus validation engine V2 with SSE streaming and analytics pipeline."""

    def __init__(self) -> None:
        self._arbitrator = ConsensusArbitrator()
        self._last_fusion: FusionResult | None = None

    async def run_stream(
        self,
        module_id: str,
        assessment_id: str,
        db: AsyncSession | None,
        synthetic_context: Any | None = None,
    ):
        import asyncio
        import time
        from .context import build_validation_context
        from .registry import get_experts_for
        from .scoring import compute_mitre_coverage

        def _ts() -> float:
            return time.time()

        t0 = _ts()
        run_id = str(uuid.uuid4())

        yield {"type": "log", "message": f"Starting {module_id} validation (run {run_id[:8]})", "ts": _ts()}

        # Load context
        if synthetic_context is not None:
            ctx = synthetic_context
            user_count = getattr(ctx, 'user_count', 0)
            computer_count = getattr(ctx, 'computer_count', 0)
            yield {"type": "log", "message": f"Using synthetic context: {user_count} users, {computer_count} computers", "ts": _ts()}
        elif db is not None:
            try:
                ctx = await build_validation_context(assessment_id, db)
                user_count = getattr(ctx, 'user_count', 0)
                entities = getattr(ctx, 'entities', [])
                yield {"type": "log", "message": f"Loaded assessment context: {user_count} users, {len(entities)} entities", "ts": _ts()}
            except Exception as e:
                yield {"type": "error", "message": f"Failed to load context: {e}", "ts": _ts()}
                return
        else:
            yield {"type": "error", "message": "No DB or synthetic context provided", "ts": _ts()}
            return

        # Discover experts via registry
        expert_classes = get_experts_for(module_id)
        if not expert_classes:
            yield {"type": "log", "message": f"No experts registered for module '{module_id}', using legacy engine", "ts": _ts()}
            yield {"type": "fusion_complete", "verdict": "INSUFFICIENT_DATA", "risk_score": 0.0, "confidence": 0, "ts": _ts()}
            return

        yield {"type": "log", "message": f"Dispatching {len(expert_classes)} experts for {module_id}", "ts": _ts()}

        # Run all experts concurrently
        decisions: list = []
        expert_instances = [cls() for cls in expert_classes]

        async def run_expert(expert):
            try:
                return await expert.analyze(ctx)
            except Exception:
                return None

        tasks = [run_expert(e) for e in expert_instances]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        for expert, decision in zip(expert_instances, results, strict=True):
            if decision is None:
                yield {"type": "log", "message": f"Expert {type(expert).__name__} returned no decision", "ts": _ts()}
                continue
            decisions.append(decision)
            yield {
                "type": "expert_decision",
                "expert_id": decision.expert_id,
                "expert_name": decision.expert_name,
                "verdict": decision.verdict.value if hasattr(decision.verdict, 'value') else str(decision.verdict),
                "score_delta": decision.score_delta,
                "confidence": decision.confidence,
                "summary": decision.summary,
                "mitre_techniques": getattr(decision, 'mitre_techniques', []),
                "kill_chain_stage": getattr(decision, 'kill_chain_stage', ""),
                "ts": _ts(),
            }

        if not decisions:
            yield {"type": "fusion_complete", "verdict": "INSUFFICIENT_DATA", "risk_score": 0.0, "confidence": 0, "ts": _ts()}
            return

        yield {"type": "fusion_start", "expert_count": len(decisions), "ts": _ts()}

        # Fuse decisions
        try:
            fusion = self._arbitrator.fuse(decisions, ctx, module_id)
        except Exception as e:
            yield {"type": "error", "message": f"Fusion failed: {e}", "ts": _ts()}
            return

        # Enrich fusion result with metadata
        fusion.module_id = module_id
        fusion.run_id = run_id
        fusion.assessment_id = assessment_id
        fusion.duration_ms = int((_ts() - t0) * 1000)
        fusion.telemetry.update({
            "run_id": run_id,
            "assessment_id": assessment_id,
            "module_id": module_id,
            "experts_registered": len(expert_classes),
            "experts_run": len(decisions),
            "duration_ms": fusion.duration_ms,
        })
        try:
            fusion.mitre_coverage = compute_mitre_coverage(decisions)
            fusion.telemetry["mitre_coverage"] = fusion.mitre_coverage
        except Exception:
            pass

        yield {
            "type": "fusion_complete",
            "verdict": fusion.final_verdict.value if hasattr(fusion.final_verdict, 'value') else str(fusion.final_verdict),
            "risk_score": fusion.risk_score,
            "confidence": fusion.confidence,
            "severity_projection": fusion.severity_projection,
            "ts": _ts(),
        }

        # Analytics pipeline
        yield {"type": "analytics_start", "pipeline": ["kill_chain", "blast_radius", "cross_module", "threat_actor", "playbook", "narrative"], "ts": _ts()}

        try:
            from .analytics.kill_chain import KillChainComposer
            kill_chains = KillChainComposer().compose(decisions, module_id)
            fusion.kill_chains = kill_chains
        except Exception:
            pass

        try:
            from .analytics.blast_radius import BlastRadiusEngine
            entities = getattr(ctx, 'entities', [])
            if entities:
                def _entity_id(e):
                    return str(e.id) if hasattr(e, 'id') else e.get('id', '')

                def _entity_name(e):
                    if hasattr(e, 'sam_account_name'):
                        return (e.sam_account_name or e.display_name or '').lower()
                    return e.get('name', '').lower()

                origin = next(
                    (_entity_id(e) for e in entities if 'admin' in _entity_name(e)),
                    _entity_id(entities[0])
                )
                if origin:
                    fusion.blast_radius = BlastRadiusEngine().compute(origin, ctx)
        except Exception:
            pass

        try:
            from .analytics.threat_actor import ThreatActorMatcher
            fusion.threat_actor_matches = ThreatActorMatcher().match(decisions)
        except Exception:
            pass

        try:
            from .analytics.playbook import PlaybookGenerator
            fusion.remediation_playbook = PlaybookGenerator().generate(decisions, ctx, module_id)
        except Exception:
            pass

        try:
            from .analytics.narrative import RedTeamNarrativeGenerator
            fusion.red_team_narrative = RedTeamNarrativeGenerator().generate(
                fusion.kill_chains, decisions, fusion, ctx
            )
        except Exception:
            pass

        fusion.duration_ms = int((_ts() - t0) * 1000)
        fusion.telemetry.update({
            "duration_ms": fusion.duration_ms,
            "kill_chain_count": len(fusion.kill_chains),
            "threat_actor_count": len(fusion.threat_actor_matches),
            "playbook_steps": len(fusion.remediation_playbook),
        })

        yield {
            "type": "analytics_complete",
            "kill_chains": len(fusion.kill_chains),
            "threat_actors": len(fusion.threat_actor_matches),
            "playbook_steps": len(fusion.remediation_playbook),
            "duration_ms": fusion.duration_ms,
            "ts": _ts(),
        }

        # Persist to DB if available
        if db is not None:
            try:
                await self._persist(fusion, decisions, assessment_id, db)
            except Exception:
                pass

        self._last_fusion = fusion
        yield {"type": "result", "fusion": _serialize_fusion(fusion), "ts": _ts()}

    async def run(
        self,
        module_id: str,
        assessment_id: str,
        db: AsyncSession | None,
        synthetic_context: Any | None = None,
    ) -> FusionResult:
        from .contracts import FinalVerdict, EvidenceQualityBand, ConfidenceBand, BlastRadiusResult

        self._last_fusion = None
        default_fusion = FusionResult(
            final_verdict=FinalVerdict.INSUFFICIENT_DATA,
            risk_score=0.0,
            confidence=0,
            consensus_score=0,
            evidence_quality_score=0,
            evidence_quality_band=EvidenceQualityBand.FRAGILE,
            confidence_band=ConfidenceBand.LOW,
            severity_projection="INFO",
            summary="",
            operator_brief="",
            impact="",
            blast_radius=BlastRadiusResult(),
            mapped_attack_steps=0,
            what_increased_confidence=[],
            what_reduced_confidence=[],
            what_would_raise_confidence=[],
            recommended_actions=[],
            safeguards=[],
            control_mapping=[],
            telemetry={},
            support_count=0,
            contradiction_count=0,
            insufficient_count=0,
            evidence_summary={},
            contradictions=[],
        )
        async for _ in self.run_stream(module_id, assessment_id, db, synthetic_context):
            pass
        return self._last_fusion if self._last_fusion is not None else default_fusion

    async def _persist(self, fusion: FusionResult, decisions: list, assessment_id: str, db: AsyncSession) -> None:
        """Persist run and decisions to DB."""
        try:
            from adbygod_api.models import ValidationRun, ValidationExpertDecision
            run = ValidationRun(
                id=fusion.run_id,
                assessment_id=assessment_id,
                module_id=fusion.module_id,
                final_verdict=fusion.final_verdict.value if hasattr(fusion.final_verdict, 'value') else str(fusion.final_verdict),
                risk_score=fusion.risk_score,
                confidence=fusion.confidence,
            )
            db.add(run)
            for d in decisions:
                row = ValidationExpertDecision(
                    id=str(uuid.uuid4()),
                    run_id=fusion.run_id,
                    expert_id=d.expert_id,
                    expert_name=d.expert_name,
                    verdict=d.verdict.value if hasattr(d.verdict, 'value') else str(d.verdict),
                    score_delta=d.score_delta,
                    confidence=d.confidence,
                    summary=d.summary,
                )
                db.add(row)
            await db.commit()
        except Exception:
            pass


def _module_display_name(module_id: str) -> str:
    names = {
        "kerberos": "Kerberos Exposure Validation",
        "ntlm_relay": "Relay Exposure Assessment",
        "acl": "Privilege Delegation Risk",
        "dcsync": "Replication Rights Exposure",
        "trust": "Trust Boundary Risk",
    }
    return names.get(module_id, module_id.title())
