from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.security.authorization import require_assessment_access
from adbygod_api.core.analyzers.lateral_movement_analyzer import (
    LM_EDGE_TYPES,
    LM_TECHNIQUE_CATALOGUE,
    detect_lm_techniques,
    match_chains,
    summarise_lm,
)
from adbygod_api.database import get_db
from adbygod_api.models import ExposurePath, GraphEdge, PlatformUser
from adbygod_api.routes.auth import get_current_user

router = APIRouter(prefix="/lateral-movement", tags=["lateral-movement"])


async def _fetch_lm_data(
    assessment_id: UUID, db: AsyncSession
) -> tuple[list[dict], list[dict]]:
    edges_rows = (
        await db.execute(
            select(GraphEdge).where(GraphEdge.assessment_id == assessment_id)
        )
    ).scalars().all()

    edges = [
        {
            "edge_type": str(e.edge_type.value if hasattr(e.edge_type, "value") else e.edge_type),
            "source_id": str(e.source_id),
            "target_id": str(e.target_id),
            "risk_weight": float(e.risk_weight or 0.5),
        }
        for e in edges_rows
        if str(e.edge_type.value if hasattr(e.edge_type, "value") else e.edge_type) in LM_EDGE_TYPES
    ]

    path_rows = (
        await db.execute(
            select(ExposurePath).where(ExposurePath.assessment_id == assessment_id)
        )
    ).scalars().all()

    paths = [
        {
            "id": str(p.id),
            "source_entity_id": str(p.source_entity_id) if p.source_entity_id else None,
            "target_entity_id": str(p.target_entity_id) if p.target_entity_id else None,
            "steps": list(p.path_steps or []),
            "hop_count": p.hop_count or 0,
            "path_score": float(p.path_score or 0),
        }
        for p in path_rows
    ]

    return edges, paths


@router.get("/summary")
async def lm_summary(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Return lateral movement summary statistics."""
    await require_assessment_access(assessment_id, db, current_user)
    edges, paths = await _fetch_lm_data(assessment_id, db)
    return summarise_lm(edges, paths)


@router.get("/techniques")
async def lm_techniques(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Return detected lateral movement techniques."""
    await require_assessment_access(assessment_id, db, current_user)
    edges, paths = await _fetch_lm_data(assessment_id, db)
    return detect_lm_techniques(edges, paths)


@router.get("/paths")
async def lm_paths(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    technique: str | None = Query(None, description="Filter by technique ID"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Return exposure paths relevant to lateral movement, optionally filtered by technique."""
    await require_assessment_access(assessment_id, db, current_user)
    edges, paths = await _fetch_lm_data(assessment_id, db)

    if technique:
        cat = LM_TECHNIQUE_CATALOGUE.get(technique)
        if cat:
            relevant_edge_types = cat.get("edge_types", set())
            edge_set = {e["edge_type"] for e in edges if e["edge_type"] in relevant_edge_types}
            paths = [
                p for p in paths
                if any(
                    step.get("edge_type") in edge_set
                    for step in p.get("steps", [])
                )
            ]

    return paths


@router.get("/chains")
async def lm_chains(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Return detected multi-step attack chains."""
    await require_assessment_access(assessment_id, db, current_user)
    edges, paths = await _fetch_lm_data(assessment_id, db)
    techniques = detect_lm_techniques(edges, paths)
    return match_chains(techniques)
