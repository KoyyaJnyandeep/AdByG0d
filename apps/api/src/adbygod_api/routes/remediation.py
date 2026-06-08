from __future__ import annotations

import asyncio
import logging
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
from adbygod_api.core.security.authorization import require_assessment_access
from adbygod_api.database import get_db
from adbygod_api.models import Entity, Finding, FindingStatus, GraphEdge, PlatformUser
from adbygod_api.routes.auth import get_current_user
from adbygod_api.schemas import RemediationCandidate, RemediationSimInput, RemediationSimResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/remediation", tags=["remediation"])


async def _load_graph_analyzer_for_assessment(
    assessment_id: UUID, db: AsyncSession
) -> ADGraphAnalyzer:
    """Load and populate a graph analyzer from the DB for a given assessment."""
    entities = (
        await db.execute(select(Entity).where(Entity.assessment_id == assessment_id))
    ).scalars().all()
    edges = (
        await db.execute(select(GraphEdge).where(GraphEdge.assessment_id == assessment_id))
    ).scalars().all()
    analyzer = ADGraphAnalyzer()
    analyzer.load_from_db(entities, edges)
    return analyzer


def _extract_node_ids_from_findings(findings: list[Finding]) -> list[str]:
    """Extract entity SIDs/IDs from finding affected_objects and attack_path fields."""
    node_ids: list[str] = []
    for finding in findings:
        for obj in (finding.affected_objects or []):
            if isinstance(obj, str) and obj:
                node_ids.append(obj)
            elif isinstance(obj, dict):
                for key in ("sid", "id", "object_sid", "entity_id"):
                    val = obj.get(key)
                    if val:
                        node_ids.append(str(val))
                        break
        for step in (finding.attack_path or []):
            if isinstance(step, dict):
                for key in ("source_id", "target_id", "entity_id"):
                    val = step.get(key)
                    if val:
                        node_ids.append(str(val))
    return list(set(node_ids))


@router.get("/candidates/{assessment_id}", response_model=list[RemediationCandidate])
async def remediation_candidates(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    findings = (
        await db.execute(
            select(Finding)
            .where(
                Finding.assessment_id == assessment_id,
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_REVIEW, FindingStatus.REGRESSED]),
            )
            .order_by(desc(Finding.composite_score).nullslast(), desc(Finding.affected_count))
            .limit(25)
        )
    ).scalars().all()
    return [
        {
            "finding_id": str(f.id),
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "score": f.composite_score or 0,
            "effort": f.estimated_effort or f.fix_complexity or "medium",
            "impact": "High" if (f.composite_score or 0) >= 70 else "Medium",
        }
        for f in findings
    ]


@router.post("/simulate", response_model=RemediationSimResult)
async def simulate_remediation(
    request: RemediationSimInput,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(request.assessment_id, db, current_user)
    findings = (
        await db.execute(
            select(Finding)
            .where(
                Finding.assessment_id == request.assessment_id,
                Finding.id.in_(request.finding_ids),
            )
            .order_by(desc(Finding.composite_score).nullslast(), desc(Finding.affected_count))
        )
    ).scalars().all()

    total_open = (
        await db.execute(
            select(func.count(Finding.id)).where(
                Finding.assessment_id == request.assessment_id,
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_REVIEW, FindingStatus.REGRESSED]),
            )
        )
    ).scalar_one()

    graph_powered = False
    paths_eliminated = 0
    paths_remaining = 0
    risk_reduction = 0.0
    blast_radius_reduction = 0

    # Empty finding_ids is a valid dry-run: returns current risk baseline with 0 reduction
    node_ids = _extract_node_ids_from_findings(findings)
    try:
        analyzer = await _load_graph_analyzer_for_assessment(request.assessment_id, db)
        if analyzer.graph.number_of_nodes() > 0 and node_ids:
            graph_result = await asyncio.to_thread(
                analyzer.simulate_node_hardening, node_ids
            )
            if graph_result.get("paths_before", 0) > 0:
                paths_eliminated = graph_result["paths_eliminated"]
                paths_remaining = graph_result["paths_after"]
                risk_reduction = round(graph_result["reduction_pct"], 1)
                blast_radius_reduction = graph_result.get("blast_radius_reduction", 0)
                graph_powered = True
    except Exception as exc:
        logger.warning("Graph simulation failed, falling back to heuristic: %s", exc)

    if not graph_powered:
        paths_eliminated = sum(max(1, f.affected_count or 1) for f in findings)
        score_sum = sum(f.composite_score or 0 for f in findings)
        risk_reduction = min(95.0, round(score_sum / max(len(findings), 1), 1)) if findings else 0.0
        paths_remaining = max(0, total_open - len(findings))
        blast_radius_reduction = 0

    fix_order = [
        {
            "finding_id": str(f.id),
            "title": f.title,
            "priority": idx + 1,
            "effort": f.estimated_effort or f.fix_complexity or "medium",
            "impact": "High" if (f.composite_score or 0) >= 70 else "Medium",
            "dependencies": [],
        }
        for idx, f in enumerate(findings)
    ]

    return RemediationSimResult(
        assessment_id=request.assessment_id,
        paths_eliminated=paths_eliminated,
        paths_remaining=paths_remaining,
        findings_resolved=[f.id for f in findings],
        risk_reduction_pct=risk_reduction,
        blast_radius_reduction=blast_radius_reduction,
        graph_powered=graph_powered,
        operational_impact=[
            "Simulation only: no directory changes were made.",
            "Validate dependency and ownership impact before production remediation.",
        ],
        fix_order=fix_order,
    )
