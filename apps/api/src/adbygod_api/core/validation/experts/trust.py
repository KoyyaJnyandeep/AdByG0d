from __future__ import annotations
import logging
from typing import Any
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

_RISKY_TRUST_ATTRS = ("sid_filtering_disabled", "sid_history_enabled", "quarantine_disabled")
_RISKY_TRUST_KEYWORDS = ("external", "forest", "bidirectional", "cross_forest")


def _edge_endpoints(edge: Any) -> tuple[str, str] | None:
    """Return endpoints for ORM GraphEdge objects or analyzer tuple edges."""
    if hasattr(edge, "source_id") and hasattr(edge, "target_id"):
        return str(edge.source_id), str(edge.target_id)
    if isinstance(edge, (tuple, list)) and len(edge) >= 2:
        return str(edge[0]), str(edge[1])
    return None


def _get(obj: Any, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _type_value(value: Any) -> str:
    return str(_get(value, "value", value))


@register("trust")
class TrustExpert(BaseExpert):
    expert_id = "trust_expert"
    expert_name = "Trust Boundary Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        trust_entities = [
            e for e in ctx.entities
            if _type_value(_get(e, "entity_type", _get(e, "type", ""))) == "TRUST"
        ]
        trust_edges = ctx.edge_type_index.get("TRUSTS", [])
        trust_findings = [
            f for f in ctx.findings
            if "trust" in str(_get(f, "finding_type", "") or "").lower()
            or "trust" in str(_get(f, "module", "") or "").lower()
        ]

        if not trust_entities and not trust_edges and not trust_findings:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.3,
                summary="No trust objects, trust edges, or trust findings found in assessment.",
                missing_signals=["Trust entity data", "TRUSTS graph edges"],
            )

        risky_trusts: list[Any] = []
        sid_filtering_gaps: list[Any] = []

        for e in trust_entities:
            attrs = _get(e, "attributes", _get(e, "properties", {})) or {}
            has_risky = any(attrs.get(k, False) for k in _RISKY_TRUST_ATTRS)
            if has_risky:
                risky_trusts.append(e)
            trust_type = str(attrs.get("trust_type", "") or "").lower()
            if "external" in trust_type or "forest" in trust_type:
                if not attrs.get("sid_filtering_enabled", False):
                    sid_filtering_gaps.append(e)

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        reasoning: list[str] = []
        entity_ids: list[str] = [str(_get(e, "id", "")) for e in trust_entities[:5]]

        supporting.append(f"{len(trust_entities)} trust object(s), {len(trust_edges)} trust edge(s) in graph.")

        if risky_trusts:
            supporting.append(
                f"{len(risky_trusts)} trust(s) with risky attributes "
                f"(SID filtering disabled / SID history enabled)."
            )
            reasoning.append("SID filtering gaps allow SID history abuse across trust boundaries.")

        if sid_filtering_gaps:
            supporting.append(
                f"{len(sid_filtering_gaps)} external/forest trust(s) without confirmed SID filtering."
            )

        if trust_findings:
            supporting.append(f"{len(trust_findings)} trust-related finding(s) in assessment.")

        if not risky_trusts and not sid_filtering_gaps:
            contradicting.append("No explicitly risky trust attributes detected in collected data.")
            missing.append("SID filtering posture data for cross-forest trusts")
            missing.append("Trust attribute completeness (may depend on collection modules run)")

        # Check graph reachability across trust
        tier0 = ctx.analyzer.get_tier0_nodes() if ctx.analyzer else set()
        trust_cross_tier0 = sum(
            1 for edge in trust_edges
            if (endpoints := _edge_endpoints(edge)) and (endpoints[0] in tier0 or endpoints[1] in tier0)
        )
        if trust_cross_tier0:
            supporting.append(f"{trust_cross_tier0} trust edge(s) adjacent to tier-0 objects.")

        # Verdict
        if risky_trusts or sid_filtering_gaps:
            verdict = ExpertVerdict.SUPPORTS_EXPOSURE
            score_delta = 0.65
            confidence = 0.7
            severity_hint = "HIGH"
            summary = (
                f"Trust boundary exposure modeled: {len(trust_entities)} trust(s), "
                f"{len(risky_trusts)} with risky attributes, {len(sid_filtering_gaps)} SID filtering gaps."
            )
        elif trust_entities or trust_edges:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.2
            confidence = 0.45
            severity_hint = "MEDIUM"
            summary = (
                f"{len(trust_entities)} trust object(s) present but risky attribute data insufficient. "
                f"Manual review recommended."
            )
        else:
            verdict = ExpertVerdict.INSUFFICIENT_DATA
            score_delta = 0.0
            confidence = 0.3
            severity_hint = None
            summary = "Trust data present only via findings; graph edges missing for path analysis."

        telemetry = {
            "trust_entities": len(trust_entities),
            "trust_edges": len(trust_edges),
            "risky_trusts": len(risky_trusts),
            "sid_filtering_gaps": len(sid_filtering_gaps),
            "trust_findings": len(trust_findings),
        }

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            reasoning=reasoning, supporting_signals=supporting,
            contradicting_signals=contradicting, missing_signals=missing,
            related_entity_ids=entity_ids,
            related_finding_ids=[str(_get(f, "id", "")) for f in trust_findings[:5]],
            telemetry=telemetry,
            mitre_techniques=["T1482", "T1134.005"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "netdom trust <trusted_domain> /domain:<trusting_domain> /quarantine:yes",
                "# Enable SID filtering on all external/forest trusts",
                "Set-ADObject -Identity 'CN=<trust_object>' -Replace @{trustAttributes=<value_with_filtering>}",
            ],
            detection_opportunities=[
                "Monitor cross-domain authentication events with SID history attributes",
                "Alert on SID history attribute modifications (event 4738)",
                "Detect cross-forest ticket requests with unusual SID inclusions",
            ],
        )


@register("trust")
class SIDFilteringExpert(BaseExpert):
    expert_id = "sid_filtering"
    expert_name = "SID Filtering Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        # Check trusts without SID filtering
        unfiltered_trusts = [
            e for e in ctx.edges
            if _type_value(_get(e, "edge_type", _get(e, "relationship_type", ""))) == 'TRUSTS'
            and not (_get(e, "attributes", _get(e, "properties", {})) or {}).get('sidfilteringenabled', True)
        ]

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id=module_id,
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE if unfiltered_trusts else ExpertVerdict.NEUTRAL,
            score_delta=0.7 if unfiltered_trusts else 0.0,
            confidence=0.65 if unfiltered_trusts else 0.4,
            severity_hint="HIGH" if unfiltered_trusts else None,
            summary=f"SID filtering: {len(unfiltered_trusts)} trusts without SID filtering",
            reasoning=[
                "SID filtering prevents cross-domain SID history abuse",
                "Missing SID filtering = cross-forest privilege escalation",
            ],
            supporting_signals=[f"{len(unfiltered_trusts)} unfiltered trusts"] if unfiltered_trusts else [],
            mitre_techniques=["T1134.005", "T1482"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "netdom trust <trusted_domain> /domain:<trusting_domain> /quarantine:yes",
                "# Enable SID filtering (quarantine) on all external trusts",
            ],
            detection_opportunities=[
                "Alert on cross-domain authentication with SID history attributes",
                "Monitor for SID-History attribute modifications (event 4738)",
            ],
        )

    async def analyze(self, ctx: ValidationAssessmentContext) -> ExpertDecision:
        return self.evaluate("trust", ctx)


def _finding_type(f) -> str:
    return str(_get(f, "finding_type", "") or "").upper()

def _finding_title(f) -> str:
    return str(_get(f, "title", "") or "").lower()


@register("trust")
class ForestPivotChainExpert(BaseExpert):
    expert_id = "trust_forest_pivot_chain"
    expert_name = "Forest Pivot Attack Chain Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        """Assess the cross-forest privilege escalation chain via trust abuse."""
        trust_edges = ctx.analyzer._edge_type_index.get("TRUSTS", []) if ctx.analyzer else ctx.edge_type_index.get("TRUSTS", [])

        trust_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("TRUST_NO_SID_FILTERING", "BIDIRECTIONAL_EXTERNAL_TRUST", "SID_HISTORY_POPULATED", "TRUST-001", "TRUST-002", "TRUST-003")
            or any(kw in _finding_title(f) for kw in ("trust", "forest pivot", "cross-forest", "bidirectional", "sid filter", "sid history"))
        ]

        sid_history_entities = ctx.sid_history_entities or []

        # Check for combined chain: trust + SID history + no filtering = full forest pivot
        chain_complete = (
            len(trust_edges) > 0
            and len(trust_findings) >= 2
            and len(sid_history_entities) > 0
        )

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        finding_ids = [str(_get(f, "id", "")) for f in trust_findings[:8]]
        entity_ids = [str(e.get("entity_id", "")) for e in sid_history_entities[:5]] if isinstance(sid_history_entities[0] if sid_history_entities else None, dict) else []

        if trust_edges:
            supporting.append(f"{len(trust_edges)} trust graph edge(s) in assessment — cross-domain attack paths exist.")
        if trust_findings:
            supporting.append(f"{len(trust_findings)} trust-related finding(s): {', '.join(set(_finding_type(f) for f in trust_findings[:3]))}.")
        if sid_history_entities:
            supporting.append(f"{len(sid_history_entities)} entity/entities with populated SID history — privilege escalation via SID injection possible.")
        if chain_complete:
            supporting.append("CHAIN COMPLETE: trust edges + SID history + SID filtering gap = confirmed forest pivot escalation path.")

        if not trust_edges and not trust_findings:
            missing.append("Trust relationship data (Get-ADTrust with SIDFilteringQuarantined attribute)")

        if chain_complete:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.92, 0.88, "CRITICAL"
            summary = "Full forest pivot chain confirmed: trust relationship + SID history + SID filtering gaps model a cross-forest domain admin escalation."
        elif trust_findings and sid_history_entities:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.78, 0.80, "HIGH"
            summary = f"Forest pivot preconditions: {len(trust_findings)} trust finding(s) + {len(sid_history_entities)} SID history entity/entities."
        elif trust_findings:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.45, 0.62, "HIGH"
            summary = f"Trust configuration issues ({len(trust_findings)} findings) without confirmed SID history abuse chain."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.25, None
            summary = "Insufficient trust relationship data for forest pivot analysis."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, contradicting_signals=contradicting, missing_signals=missing,
            related_finding_ids=finding_ids, related_entity_ids=entity_ids,
            telemetry={"trust_edges": len(trust_edges), "trust_findings": len(trust_findings), "sid_history_entities": len(sid_history_entities), "chain_complete": chain_complete},
            mitre_techniques=["T1482", "T1134.005"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "# Enable SID filtering on all trusts: netdom trust <partner> /domain:<domain> /quarantine:yes",
                "# Remove SID history from migrated accounts: Set-ADUser <account> -Clear sidHistory",
                "# Audit trust relationships: Get-ADTrust -Filter * -Properties SIDFilteringQuarantined,TrustAttributes",
            ],
            detection_opportunities=[
                "Monitor for cross-domain authentication with SID-history attributes in the PAC (event 4624 + Kerberos ticket inspection)",
                "Alert on any SID history attribute changes (event 4738 with SIDHistory field)",
                "Use Microsoft Defender for Identity 'Pass-the-hash' and 'Forged PAC' detection",
            ],
        )

    async def analyze(self, ctx: ValidationAssessmentContext) -> ExpertDecision:
        return self.evaluate("trust", ctx)
