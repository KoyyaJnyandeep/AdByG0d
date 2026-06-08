from __future__ import annotations

import uuid
import logging
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from adbygod_api.routes.auth import get_current_user
from adbygod_api.models import PlatformUser
from adbygod_api.core.kill_chain.tracker import compute_phase_coverage_sync, suggest_next_techniques
from adbygod_api.core.security.authorization import require_assessment_access

log = logging.getLogger(__name__)
router = APIRouter(prefix="/kill-chain", tags=["kill-chain"])


class PhaseOut(BaseModel):
    phase_id: int
    label: str
    status: str
    completion_pct: int
    techniques_run: list[str]
    findings_count: int


class SuggestionOut(BaseModel):
    technique_id: str
    title: str
    reason: str
    mitre_id: str
    phase_id: int


class KillChainOut(BaseModel):
    assessment_id: str | None
    phases: list[PhaseOut]
    suggestions: list[SuggestionOut]


@router.get("", response_model=KillChainOut)
async def get_kill_chain(
    assessment_id: str | None = Query(default=None),
    current_user: PlatformUser = Depends(get_current_user),
):
    from adbygod_api.database import AsyncSessionLocal
    from adbygod_api.models import ReconScan, OffensiveJob
    from sqlalchemy import select

    recon_findings: list[dict] = []
    techniques_run: list[str] = []

    if assessment_id:
        async with AsyncSessionLocal() as db:
            await require_assessment_access(uuid.UUID(assessment_id), db, current_user)
            q = select(ReconScan).where(
                ReconScan.assessment_id == uuid.UUID(assessment_id),
            ).order_by(ReconScan.created_at.desc()).limit(1)
            result = await db.execute(q)
            scan = result.scalar_one_or_none()
            if scan and scan.findings:
                recon_findings = scan.findings

            q2 = select(OffensiveJob.technique_id).where(
                OffensiveJob.assessment_id == uuid.UUID(assessment_id),
                OffensiveJob.technique_id.isnot(None),
            )
            result2 = await db.execute(q2)
            techniques_run = list({row[0] for row in result2.fetchall() if row[0]})

    phases = compute_phase_coverage_sync(recon_findings=recon_findings, techniques_run=techniques_run)
    suggestions = suggest_next_techniques(
        recon_findings=recon_findings,
        techniques_run=techniques_run,
        graph_signals={},
    )

    return KillChainOut(
        assessment_id=assessment_id,
        phases=[PhaseOut(**p) for p in phases],
        suggestions=[SuggestionOut(**s) for s in suggestions],
    )
