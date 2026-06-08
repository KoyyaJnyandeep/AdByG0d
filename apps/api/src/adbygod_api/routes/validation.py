import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.validation.engine import ValidationConsensusEngine
from adbygod_api.core.validation.catalog import VALIDATION_MODULE_INDEX, list_validation_modules as list_validation_module_payloads
from adbygod_api.core.analyzers.scoring_service import RiskScoringService
from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
from adbygod_api.database import get_db
from adbygod_api.models import (
    Entity, Finding, GraphEdge, PlatformUser,
    ValidationRun, ValidationExpertDecision,
)
from adbygod_api.core.security.authorization import require_assessment_access, require_assessment_write_access
from adbygod_api.routes.auth import get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/validation", tags=["validation"])


class ValidationModule(BaseModel):
    id: str
    name: str
    description: str
    risk_category: str
    version: str = "1.0"
    expert_count: int = 0
    mitre_techniques: list[str] = []
    severity_range: tuple[str, str] = ("LOW", "CRITICAL")


class SimulationRequest(BaseModel):
    target: str
    mode: str = "simulation"


def _jsonable(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {k: _jsonable(getattr(value, k)) for k in value.__dataclass_fields__}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return value


def _fusion_payload(result: Any) -> dict[str, Any]:
    return {
        "final_verdict": _jsonable(result.final_verdict),
        "risk_score": result.risk_score,
        "confidence": result.confidence,
        "consensus_score": getattr(result, "consensus_score", 0),
        "evidence_quality_score": getattr(result, "evidence_quality_score", 0),
        "evidence_quality_band": _jsonable(getattr(result, "evidence_quality_band", "FRAGILE")),
        "confidence_band": _jsonable(getattr(result, "confidence_band", "LOW")),
        "severity_projection": getattr(result, "severity_projection", "INFO"),
        "summary": getattr(result, "summary", ""),
        "operator_brief": getattr(result, "operator_brief", ""),
        "impact": getattr(result, "impact", ""),
        "blast_radius": _jsonable(getattr(result, "blast_radius", {})),
        "mapped_attack_steps": getattr(result, "mapped_attack_steps", 0),
        "what_increased_confidence": _jsonable(getattr(result, "what_increased_confidence", [])),
        "what_reduced_confidence": _jsonable(getattr(result, "what_reduced_confidence", [])),
        "what_would_raise_confidence": _jsonable(getattr(result, "what_would_raise_confidence", [])),
        "recommended_actions": _jsonable(getattr(result, "recommended_actions", [])),
        "safeguards": _jsonable(getattr(result, "safeguards", [])),
        "control_mapping": _jsonable(getattr(result, "control_mapping", [])),
        "kill_chains": _jsonable(getattr(result, "kill_chains", [])),
        "cross_module_chains": _jsonable(getattr(result, "cross_module_chains", [])),
        "threat_actor_matches": _jsonable(getattr(result, "threat_actor_matches", [])),
        "remediation_playbook": _jsonable(getattr(result, "remediation_playbook", [])),
        "red_team_narrative": getattr(result, "red_team_narrative", ""),
        "mitre_coverage": _jsonable(getattr(result, "mitre_coverage", {})),
        "remediation_impact": _jsonable(getattr(result, "remediation_impact", {})),
        "posture_delta": getattr(result, "posture_delta", None),
        "module_id": getattr(result, "module_id", ""),
        "run_id": getattr(result, "run_id", ""),
        "assessment_id": getattr(result, "assessment_id", ""),
        "duration_ms": getattr(result, "duration_ms", 0),
        "telemetry": _jsonable(getattr(result, "telemetry", {})),
        "support_count": getattr(result, "support_count", 0),
        "contradiction_count": getattr(result, "contradiction_count", 0),
        "insufficient_count": getattr(result, "insufficient_count", 0),
        "evidence_summary": _jsonable(getattr(result, "evidence_summary", {})),
        "contradictions": _jsonable(getattr(result, "contradictions", [])),
    }


def _run_payload(run: ValidationRun, decisions: list[ValidationExpertDecision] | None = None) -> dict[str, Any]:
    decision_payloads = []
    for d in decisions or []:
        telemetry = d.telemetry_json or {}
        decision_payloads.append({
            "expert_id": d.expert_id,
            "expert_name": d.expert_name,
            "module_id": run.module_id,
            "verdict": d.verdict,
            "score_delta": d.score_delta,
            "confidence": d.confidence,
            "severity_hint": d.severity_hint,
            "summary": d.summary or "",
            "reasoning": d.reasoning_json or [],
            "supporting_signals": d.supporting_signals_json or [],
            "contradicting_signals": d.contradicting_signals_json or [],
            "missing_signals": d.missing_signals_json or [],
            "evidence_refs": d.evidence_refs_json or [],
            "related_finding_ids": d.related_finding_ids_json or [],
            "related_entity_ids": d.related_entity_ids_json or [],
            "related_edge_ids": d.related_edge_ids_json or [],
            "mitre_techniques": telemetry.get("mitre_techniques", []),
            "kill_chain_stage": telemetry.get("kill_chain_stage", ""),
            "blast_radius_hint": telemetry.get("blast_radius_hint", 0),
            "remediation_commands": telemetry.get("remediation_commands", []),
            "detection_opportunities": telemetry.get("detection_opportunities", []),
            "cve_refs": telemetry.get("cve_refs", []),
            "telemetry": telemetry,
        })

    telemetry = run.telemetry_json or {}
    reasoning = run.reasoning_json or {}
    return {
        "final_verdict": run.final_verdict or "INSUFFICIENT_DATA",
        "risk_score": float(run.risk_score or 0.0),
        "confidence": int(run.confidence or 0),
        "consensus_score": int(run.consensus_score or 0),
        "evidence_quality_score": int(run.evidence_quality_score or 0),
        "evidence_quality_band": telemetry.get("evidence_quality_band", "FRAGILE"),
        "confidence_band": telemetry.get("confidence_band", "LOW"),
        "severity_projection": run.severity_projection or "INFO",
        "summary": run.summary or "",
        "operator_brief": reasoning.get("operator_brief", run.summary or ""),
        "impact": reasoning.get("impact", ""),
        "blast_radius": telemetry.get("blast_radius", {
            "origin_entity_id": "",
            "reachable_computers": 0,
            "reachable_domain_controllers": 0,
            "reachable_domains": 0,
            "reachable_ous": 0,
            "reachable_groups": 0,
            "reachable_users": 0,
            "total_reachable": 0,
            "tier0_reachable": False,
            "critical_paths": [],
        }),
        "mapped_attack_steps": telemetry.get("mapped_attack_steps", 0),
        "what_increased_confidence": reasoning.get("what_increased_confidence", []),
        "what_reduced_confidence": reasoning.get("what_reduced_confidence", []),
        "what_would_raise_confidence": reasoning.get("what_would_raise_confidence", []),
        "recommended_actions": reasoning.get("recommended_actions", []),
        "safeguards": reasoning.get("safeguards", []),
        "control_mapping": telemetry.get("control_mapping", []),
        "kill_chains": telemetry.get("kill_chains", []),
        "cross_module_chains": telemetry.get("cross_module_chains", []),
        "threat_actor_matches": telemetry.get("threat_actor_matches", []),
        "remediation_playbook": telemetry.get("remediation_playbook", []),
        "red_team_narrative": reasoning.get("red_team_narrative", ""),
        "mitre_coverage": telemetry.get("mitre_coverage", {}),
        "remediation_impact": telemetry.get("remediation_impact", {}),
        "posture_delta": telemetry.get("posture_delta"),
        "module_id": run.module_id,
        "run_id": str(run.id),
        "assessment_id": str(run.assessment_id),
        "duration_ms": int(telemetry.get("duration_ms", 0)),
        "telemetry": telemetry,
        "support_count": sum(1 for d in decision_payloads if d["verdict"] in ("SUPPORTS_EXPOSURE", "WEAK_SUPPORT")),
        "contradiction_count": sum(1 for d in decision_payloads if d["verdict"] == "CONTRADICTS_EXPOSURE"),
        "insufficient_count": sum(1 for d in decision_payloads if d["verdict"] == "INSUFFICIENT_DATA"),
        "evidence_summary": telemetry.get("evidence_summary", {}),
        "contradictions": reasoning.get("contradictions", []),
        "expert_decisions": decision_payloads,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
    }


@router.get("/modules")
async def list_validation_modules():
    modules = list_validation_module_payloads()
    # Enrich with expert_count and extra catalog fields if available
    try:
        import adbygod_api.core.validation.experts  # noqa: F401  # ensure registered
        from adbygod_api.core.validation.registry import get_experts_for
        enriched = []
        for m in modules:
            mid = m["id"] if isinstance(m, dict) else m.id
            base = dict(m) if isinstance(m, dict) else m.dict()
            base["expert_count"] = len(get_experts_for(mid))
            enriched.append(base)
        return enriched
    except Exception:
        return modules


@router.get("/global-score/{assessment_id}")
async def get_global_score(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)

    findings = (await db.execute(select(Finding).where(Finding.assessment_id == assessment_id))).scalars().all()
    entities = (await db.execute(select(Entity).where(Entity.assessment_id == assessment_id))).scalars().all()
    edges = (await db.execute(select(GraphEdge).where(GraphEdge.assessment_id == assessment_id))).scalars().all()

    analyzer = ADGraphAnalyzer()
    analyzer.load_from_db(entities, edges)
    scorer = RiskScoringService(analyzer)

    return {
        "assessment_id": str(assessment_id),
        **scorer.calculate_global_score(findings),
        "execution_mode": "GRAPH_BACKED",
        "simulated": False,
    }


@router.post("/simulate/{module_id}/{assessment_id}")
async def run_validation(
    module_id: str,
    assessment_id: UUID,
    req: SimulationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    if module_id not in VALIDATION_MODULE_INDEX:
        raise HTTPException(status_code=400, detail="Invalid module ID provided")

    await require_assessment_write_access(assessment_id, db, current_user)

    engine = ValidationConsensusEngine(db)
    try:
        result = await engine.run(
            module_id=module_id,
            assessment_id=str(assessment_id),
            target=req.target,
            requested_mode=req.mode,
            created_by=current_user.id,
        )
        return result
    except Exception as exc:
        log.error("Validation consensus engine error %s/%s: %s", module_id, assessment_id, exc)
        raise HTTPException(status_code=500, detail="Validation backend error") from exc


@router.get("/overview/{assessment_id}")
async def get_validation_overview(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Per-module posture summary: latest run verdict + readiness for each module."""
    await require_assessment_access(assessment_id, db, current_user)

    modules = list_validation_module_payloads()
    # Fetch latest completed run per module
    runs_q = await db.execute(
        select(ValidationRun)
        .where(
            ValidationRun.assessment_id == assessment_id,
            ValidationRun.status == "COMPLETED",
        )
        .order_by(desc(ValidationRun.created_at))
    )
    all_runs = runs_q.scalars().all()

    latest_by_module: dict[str, ValidationRun] = {}
    for run in all_runs:
        if run.module_id not in latest_by_module:
            latest_by_module[run.module_id] = run

    overview = []
    for m in modules:
        mid = m["id"]
        run = latest_by_module.get(mid)
        overview.append({
            "module_id": mid,
            "module_name": m["name"],
            "has_run": run is not None,
            "last_run_id": str(run.id) if run else None,
            "last_run_at": run.created_at.isoformat() if run else None,
            "final_verdict": run.final_verdict if run else None,
            "risk_score": run.risk_score if run else None,
            "confidence": run.confidence if run else None,
            "severity_projection": run.severity_projection if run else None,
        })

    return {
        "assessment_id": str(assessment_id),
        "modules": overview,
        "total_modules": len(modules),
        "modules_with_runs": sum(1 for o in overview if o["has_run"]),
    }


@router.get("/runs/{assessment_id}")
async def list_validation_runs(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Run history for an assessment."""
    await require_assessment_access(assessment_id, db, current_user)

    total_q = await db.execute(
        select(func.count(ValidationRun.id)).where(ValidationRun.assessment_id == assessment_id)
    )
    total = int(total_q.scalar_one() or 0)

    runs_q = await db.execute(
        select(ValidationRun)
        .where(ValidationRun.assessment_id == assessment_id)
        .order_by(desc(ValidationRun.created_at))
        .limit(100)
    )
    runs = runs_q.scalars().all()

    return {
        "assessment_id": str(assessment_id),
        "runs": [
            {
                "run_id": str(r.id),
                "module_id": r.module_id,
                "status": r.status,
                "final_verdict": r.final_verdict,
                "risk_score": r.risk_score,
                "confidence": r.confidence,
                "severity_projection": r.severity_projection,
                "execution_mode": r.execution_mode,
                "simulated": r.simulated,
                "origin": r.origin,
                "created_at": r.created_at.isoformat(),
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            }
            for r in runs
        ],
        "total": total,
        "returned": len(runs),
    }


@router.get("/runs/detail/{run_id}")
async def get_validation_run_detail(
    run_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Full run with all expert decisions."""
    run_q = await db.execute(select(ValidationRun).where(ValidationRun.id == run_id))
    run = run_q.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Validation run not found")

    await require_assessment_access(run.assessment_id, db, current_user)

    decisions_q = await db.execute(
        select(ValidationExpertDecision)
        .where(ValidationExpertDecision.validation_run_id == run_id)
        .order_by(ValidationExpertDecision.created_at)
    )
    decisions = decisions_q.scalars().all()

    return {
        "run_id": str(run.id),
        "assessment_id": str(run.assessment_id),
        "module_id": run.module_id,
        "target": run.target,
        "status": run.status,
        "execution_mode": run.execution_mode,
        "simulated": run.simulated,
        "origin": run.origin,
        "final_verdict": run.final_verdict,
        "risk_score": run.risk_score,
        "confidence": run.confidence,
        "consensus_score": run.consensus_score,
        "evidence_quality_score": run.evidence_quality_score,
        "severity_projection": run.severity_projection,
        "summary": run.summary,
        "reasoning": run.reasoning_json,
        "created_at": run.created_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "expert_decisions": [
            {
                "expert_id": d.expert_id,
                "expert_name": d.expert_name,
                "verdict": d.verdict,
                "score_delta": d.score_delta,
                "confidence": d.confidence,
                "severity_hint": d.severity_hint,
                "summary": d.summary,
                "reasoning": d.reasoning_json,
                "supporting_signals": d.supporting_signals_json,
                "contradicting_signals": d.contradicting_signals_json,
                "missing_signals": d.missing_signals_json,
                "evidence_refs": d.evidence_refs_json,
                "telemetry": d.telemetry_json,
            }
            for d in decisions
        ],
    }


# ---------------------------------------------------------------------------
# SSE streaming endpoint
# ---------------------------------------------------------------------------

@router.get("/stream/{module_id}/{assessment_id}")
async def stream_validation(
    module_id: str,
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """SSE stream of validation events for a single module."""
    from adbygod_api.core.validation.engine import ValidationConsensusEngineV2

    if module_id not in VALIDATION_MODULE_INDEX:
        raise HTTPException(status_code=400, detail="Invalid module ID provided")
    await require_assessment_write_access(assessment_id, db, current_user)

    engine = ValidationConsensusEngineV2()

    async def event_generator():
        try:
            async for event in engine.run_stream(module_id, str(assessment_id), db):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/simulate-all/{assessment_id}")
async def simulate_all_modules(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Run all V2 validation modules and return a result map."""
    from adbygod_api.core.validation.engine import ValidationConsensusEngineV2

    await require_assessment_write_access(assessment_id, db, current_user)

    engine = ValidationConsensusEngineV2()
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for module_id in VALIDATION_MODULE_INDEX:
        try:
            fusion = await engine.run(module_id, str(assessment_id), db)
            results[module_id] = _fusion_payload(fusion)
        except Exception as exc:
            log.exception("Validation V2 simulate-all failed for %s/%s", module_id, assessment_id)
            errors[module_id] = str(exc)

    return {
        "assessment_id": str(assessment_id),
        "results": results,
        "errors": errors,
        "module_count": len(VALIDATION_MODULE_INDEX),
        "completed": len(results),
    }


@router.get("/stream-all/{assessment_id}")
async def stream_all_validation(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """SSE stream that runs all V2 validation modules sequentially."""
    from adbygod_api.core.validation.engine import ValidationConsensusEngineV2

    await require_assessment_write_access(assessment_id, db, current_user)

    async def event_generator():
        engine = ValidationConsensusEngineV2()
        for module_id in VALIDATION_MODULE_INDEX:
            yield f"data: {json.dumps({'type': 'module_start', 'module_id': module_id})}\n\n"
            try:
                async for event in engine.run_stream(module_id, str(assessment_id), db):
                    event["module_id"] = module_id
                    yield f"data: {json.dumps(event)}\n\n"
            except Exception as exc:
                yield f"data: {json.dumps({'type': 'error', 'module_id': module_id, 'message': str(exc)})}\n\n"
        yield f"data: {json.dumps({'type': 'all_complete', 'module_count': len(VALIDATION_MODULE_INDEX)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Synthetic data routes
# ---------------------------------------------------------------------------

@router.post("/synthetic/generate")
async def generate_synthetic(
    config: dict,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Generate a synthetic AD context from config."""
    try:
        from adbygod_api.core.validation.synthetic.generator import SyntheticADGenerator, SyntheticADConfig

        cfg_data = {k: v for k, v in config.items() if k in SyntheticADConfig.__dataclass_fields__}
        cfg = SyntheticADConfig(**cfg_data)
        ctx = SyntheticADGenerator().generate(cfg)

        return {
            "context_id": ctx.assessment_id,
            "user_count": getattr(ctx, 'user_count', len([e for e in ctx.entities if isinstance(e, dict) and e.get('type') == 'User'])),
            "computer_count": ctx.computer_count,
            "dc_count": ctx.dc_count,
            "entity_count": len(ctx.entities),
            "edge_count": len(ctx.edges),
            "finding_count": len(ctx.findings),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/synthetic/presets")
async def list_synthetic_presets(current_user: PlatformUser = Depends(get_current_user)):
    """List all synthetic AD scenario presets."""
    try:
        from adbygod_api.core.validation.synthetic.presets import PRESETS
        from adbygod_api.core.validation.synthetic.apt_scenarios import APT_SCENARIOS

        result = {
            "presets": {
                name: {
                    "name": name,
                    "description": cfg.description,
                    "user_count": cfg.user_count,
                    "computer_count": cfg.computer_count,
                }
                for name, cfg in PRESETS.items()
            },
            "apt_scenarios": {
                name: {
                    "name": scenario["name"],
                    "description": scenario["description"],
                    "expected_modules": scenario["expected_modules"],
                    "threat_actor": scenario["threat_actor"],
                }
                for name, scenario in APT_SCENARIOS.items()
            },
        }
        return result
    except Exception as e:
        return {"presets": {}, "apt_scenarios": {}, "error": str(e)}


@router.post("/simulate-synthetic/{module_id}/{preset_name}")
async def simulate_with_synthetic(
    module_id: str,
    preset_name: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Run validation module against a synthetic preset (no DB needed)."""
    if module_id not in VALIDATION_MODULE_INDEX:
        raise HTTPException(status_code=400, detail="Invalid module ID provided")

    try:
        from adbygod_api.core.validation.synthetic.presets import PRESETS
        from adbygod_api.core.validation.synthetic.apt_scenarios import APT_SCENARIOS
        from adbygod_api.core.validation.synthetic.generator import SyntheticADGenerator
        from adbygod_api.core.validation.engine import ValidationConsensusEngineV2

        if preset_name in PRESETS:
            config = PRESETS[preset_name]
        elif preset_name in APT_SCENARIOS:
            config = APT_SCENARIOS[preset_name]["config"]
        else:
            raise HTTPException(status_code=404, detail=f"Preset '{preset_name}' not found")

        ctx = SyntheticADGenerator().generate(config)
        engine = ValidationConsensusEngineV2()
        result = await engine.run(module_id, ctx.assessment_id, db=None, synthetic_context=ctx)

        return {
            "module_id": module_id,
            "preset": preset_name,
            "verdict": result.final_verdict.value if hasattr(result.final_verdict, 'value') else str(result.final_verdict),
            "risk_score": result.risk_score,
            "confidence": result.confidence,
            "severity_projection": result.severity_projection,
            "kill_chains": len(result.kill_chains),
            "threat_actors": [m.actor_name for m in result.threat_actor_matches],
            "playbook_steps": len(result.remediation_playbook),
            "summary": result.summary,
        }
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Synthetic validation failed for module=%s preset=%s", module_id, preset_name)
        raise HTTPException(status_code=500, detail="Synthetic validation failed") from e


# ---------------------------------------------------------------------------
# Run analytics and export endpoints
# ---------------------------------------------------------------------------

@router.get("/analytics/{run_id}")
async def get_run_analytics(
    run_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return the fullest available V2 result payload for a persisted run."""
    run_q = await db.execute(select(ValidationRun).where(ValidationRun.id == run_id))
    run = run_q.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Validation run not found")

    await require_assessment_access(run.assessment_id, db, current_user)

    decisions_q = await db.execute(
        select(ValidationExpertDecision)
        .where(ValidationExpertDecision.validation_run_id == run_id)
        .order_by(ValidationExpertDecision.created_at)
    )
    return _run_payload(run, decisions_q.scalars().all())


@router.get("/kill-chains/{run_id}")
async def get_run_kill_chains(
    run_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    payload = await get_run_analytics(run_id, db, current_user)
    return {
        "run_id": str(run_id),
        "module_id": payload["module_id"],
        "kill_chains": payload["kill_chains"],
    }


@router.get("/blast-radius/{run_id}/{entity_id}")
async def get_run_blast_radius(
    run_id: UUID,
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    from adbygod_api.core.validation.analytics.blast_radius import BlastRadiusEngine
    from adbygod_api.core.validation.context import build_validation_context

    run_q = await db.execute(select(ValidationRun).where(ValidationRun.id == run_id))
    run = run_q.scalar_one_or_none()
    if not run:
        raise HTTPException(status_code=404, detail="Validation run not found")

    await require_assessment_access(run.assessment_id, db, current_user)

    try:
        ctx = await build_validation_context(str(run.assessment_id), db)
        return _jsonable(BlastRadiusEngine().compute(entity_id, ctx))
    except Exception as exc:
        log.exception("Blast radius calculation failed for run %s entity %s", run_id, entity_id)
        telemetry_radius = (run.telemetry_json or {}).get("blast_radius")
        if telemetry_radius:
            return telemetry_radius
        raise HTTPException(status_code=500, detail=f"Blast radius calculation failed: {exc}") from exc


@router.get("/comparison/{run_id_a}/{run_id_b}")
async def compare_validation_runs(
    run_id_a: UUID,
    run_id_b: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    before = await get_run_analytics(run_id_a, db, current_user)
    after = await get_run_analytics(run_id_b, db, current_user)
    before_chains = {c.get("chain_id") for c in before.get("kill_chains", []) if isinstance(c, dict)}
    after_chains = {c.get("chain_id") for c in after.get("kill_chains", []) if isinstance(c, dict)}

    return {
        "before": before,
        "after": after,
        "diff": {
            "risk_score_delta": after["risk_score"] - before["risk_score"],
            "confidence_delta": after["confidence"] - before["confidence"],
            "verdict_changed": before["final_verdict"] != after["final_verdict"],
            "before_verdict": before["final_verdict"],
            "after_verdict": after["final_verdict"],
            "chains_added": sorted(after_chains - before_chains),
            "chains_removed": sorted(before_chains - after_chains),
        },
    }


@router.get("/export/{run_id}/json")
async def export_validation_run_json(
    run_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    payload = await get_run_analytics(run_id, db, current_user)
    return {
        "schema": "adbygod.validation.v1.export",
        "version": "1.0",
        "run": payload,
    }


# ---------------------------------------------------------------------------
# Posture timeline
# ---------------------------------------------------------------------------

@router.get("/posture-timeline/{assessment_id}")
async def posture_timeline(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return historical trend of validation runs for an assessment."""
    try:
        await require_assessment_access(assessment_id, db, current_user)
        result = await db.execute(
            select(ValidationRun)
            .where(ValidationRun.assessment_id == assessment_id)
            .order_by(desc(ValidationRun.created_at))
            .limit(50)
        )
        runs = result.scalars().all()

        return {
            "assessment_id": str(assessment_id),
            "run_count": len(runs),
            "runs": [
                {
                    "run_id": str(r.id),
                    "module_id": r.module_id,
                    "verdict": r.final_verdict,
                    "risk_score": float(r.risk_score) if r.risk_score else 0.0,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in runs
            ],
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        log.exception("Posture timeline failed for assessment %s", assessment_id)
        raise HTTPException(status_code=500, detail="Posture timeline failed") from e
