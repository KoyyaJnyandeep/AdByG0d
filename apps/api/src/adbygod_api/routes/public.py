from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.config import settings
from adbygod_api.database import get_db
from adbygod_api.models import Assessment, CertTemplate, Entity, ExposurePath, Finding, GraphEdge, SeverityLevel

router = APIRouter(prefix="/public", tags=["public"])


class PublicAssessmentSummary(BaseModel):
    has_data: bool
    assessment_id: UUID | None = None
    name: str | None = None
    domain: str | None = None
    status: str | None = None
    exposure_score: float = 0.0
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    total_entities: int = 0
    total_edges: int = 0
    tier0_assets: int = 0
    crown_jewels: int = 0
    admin_accounts: int = 0
    exposure_paths: int = 0
    certificate_templates: int = 0
    analysis_tracks: int = 0
    research_modules: int = 0
    zero_day_refs: int = 0
    certificate_chains: int = 0
    coverage: dict[str, int]


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _pct(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        return 0
    return min(100, max(0, round((numerator / denominator) * 100)))


def _empty_summary() -> PublicAssessmentSummary:
    return PublicAssessmentSummary(
        has_data=False,
        coverage={
            "kerberos": 0,
            "adcs": 0,
            "acl": 0,
            "replication": 0,
            "graph": 0,
        },
    )


@router.get("/assessment-summary", response_model=PublicAssessmentSummary)
async def assessment_summary(db: AsyncSession = Depends(get_db)):
    # The login page can render safely without this telemetry.  Keep the data
    # private unless an operator intentionally enables it in .env.
    if not settings.ENABLE_PUBLIC_ASSESSMENT_SUMMARY:
        return _empty_summary()

    assessment = (
        await db.execute(select(Assessment).order_by(desc(Assessment.created_at)).limit(1))
    ).scalars().first()

    if assessment is None:
        return _empty_summary()

    assessment_id = assessment.id
    total_findings = (
        await db.execute(select(func.count(Finding.id)).where(Finding.assessment_id == assessment_id))
    ).scalar_one()
    critical_findings = (
        await db.execute(select(func.count(Finding.id)).where(Finding.assessment_id == assessment_id, Finding.severity == SeverityLevel.CRITICAL))
    ).scalar_one()
    high_findings = (
        await db.execute(select(func.count(Finding.id)).where(Finding.assessment_id == assessment_id, Finding.severity == SeverityLevel.HIGH))
    ).scalar_one()
    total_entities = (
        await db.execute(select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id))
    ).scalar_one()
    total_edges = (
        await db.execute(select(func.count(GraphEdge.id)).where(GraphEdge.assessment_id == assessment_id))
    ).scalar_one()
    tier0_assets = (
        await db.execute(select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id, Entity.tier == 0))
    ).scalar_one()
    crown_jewels = (
        await db.execute(select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id, Entity.is_crown_jewel.is_(True)))
    ).scalar_one()
    admin_accounts = (
        await db.execute(select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id, Entity.is_admin_count.is_(True)))
    ).scalar_one()
    exposure_paths = (
        await db.execute(select(func.count(ExposurePath.id)).where(ExposurePath.assessment_id == assessment_id))
    ).scalar_one()
    certificate_templates = (
        await db.execute(select(func.count(CertTemplate.id)).where(CertTemplate.assessment_id == assessment_id))
    ).scalar_one()
    module_rows = (
        await db.execute(
            select(Finding.module, func.count(Finding.id))
            .where(Finding.assessment_id == assessment_id)
            .group_by(Finding.module)
        )
    ).all()
    module_counts = {str(module or "Unknown").lower(): count for module, count in module_rows}
    analysis_tracks = len(module_counts)
    research_modules = len(assessment.modules_run or []) or analysis_tracks

    kerberos = module_counts.get("kerberos", 0) + module_counts.get("password policy", 0) + module_counts.get("user accounts", 0)
    adcs = module_counts.get("ad cs", 0)
    acl = module_counts.get("acl abuse", 0) + module_counts.get("gpo / sysvol", 0)
    replication = (
        await db.execute(
            select(func.count(Finding.id)).where(
                Finding.assessment_id == assessment_id,
                Finding.title.ilike("%dcsync%"),
            )
        )
    ).scalar_one()
    cve_rows = (
        await db.execute(select(Finding.cve_ids).where(Finding.assessment_id == assessment_id))
    ).scalars().all()
    cve_refs = sum(1 for cve_ids in cve_rows if cve_ids)

    coverage = {
        "kerberos": _pct(kerberos, max(total_findings, 1)),
        "adcs": _pct(adcs, max(total_findings, 1)),
        "acl": _pct(acl, max(total_findings, 1)),
        "replication": _pct(replication, max(total_findings, 1)),
        "graph": 100 if total_entities > 0 and total_edges > 0 else 0,
    }

    return PublicAssessmentSummary(
        has_data=True,
        assessment_id=assessment_id,
        name=assessment.name,
        domain=assessment.domain,
        status=_enum_value(assessment.status),
        exposure_score=assessment.exposure_score or 0.0,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        total_entities=total_entities,
        total_edges=total_edges,
        tier0_assets=tier0_assets,
        crown_jewels=crown_jewels,
        admin_accounts=admin_accounts,
        exposure_paths=exposure_paths,
        certificate_templates=certificate_templates,
        analysis_tracks=analysis_tracks,
        research_modules=research_modules,
        zero_day_refs=cve_refs,
        certificate_chains=0,  # attack-chain count; not the same as template count
        coverage=coverage,
    )
