from __future__ import annotations

import json
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import bindparam, delete, desc, func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from adbygod_api.core.security.authorization import (
    get_accessible_workspace_ids,
    require_assessment_access,
    require_assessment_write_access,
    require_workspace_write_access,
    scope_assessment_query,
)
from adbygod_api.core.connectivity.resolved_connection import resolve_connection
from adbygod_api.core.security.at_rest import reveal_json_from_db
from adbygod_api.database import get_db
from adbygod_api.models import (
    Assessment,
    AssessmentDiff,
    AssessmentStatus,
    AttackChain,
    CertTemplate,
    Entity,
    EntityType,
    EvidenceRecord,
    ExposurePath,
    Finding,
    FindingEvidence,
    FindingStatus,
    GraphEdge,
    JobOutput,
    ConnectivityProfile,
    OffensiveJob,
    PlatformUser,
    SeverityLevel,
    ValidationExpertDecision,
    ValidationRun,
    Workspace,
)
from adbygod_api.routes.auth import get_current_user
from adbygod_api.schemas import (
    AssessmentCreate,
    AssessmentDetail,
    AssessmentOut,
    AssessmentUpdate,
    CoverageItem,
    DashboardData,
    ExposureSummary,
    WorkspaceOption,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/assessments", tags=["assessments"])


def _sev_key(value: SeverityLevel | str) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _with_display_modules(assessment: Assessment) -> Assessment:
    if assessment.modules_run:
        return assessment
    config = assessment.collection_config or {}
    modules = config.get("modules") if isinstance(config, dict) else None
    if isinstance(modules, list):
        assessment.modules_run = [str(module) for module in modules if str(module)]
    return assessment


def _raw_json_value(value):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


async def _apply_display_modules_from_config(db: AsyncSession, assessments: list[Assessment]) -> list[Assessment]:
    missing = [assessment for assessment in assessments if not assessment.modules_run]
    if not missing:
        return assessments

    rows = (
        await db.execute(
            text("SELECT id, collection_config FROM assessments WHERE id IN :ids").bindparams(
                bindparam("ids", expanding=True)
            ),
            {"ids": [str(assessment.id) for assessment in missing]},
        )
    ).all()
    configs_by_id = {str(row.id): row.collection_config for row in rows}

    for assessment in missing:
        try:
            config = reveal_json_from_db(_raw_json_value(configs_by_id.get(str(assessment.id)))) or {}
        except RuntimeError:
            log.warning("Skipping undecryptable collection_config for assessment list row %s", assessment.id)
            continue
        modules = config.get("modules") if isinstance(config, dict) else None
        if isinstance(modules, list):
            assessment.modules_run = [str(module) for module in modules if str(module)]
    return assessments


async def _severity_counts(db: AsyncSession, assessment_id: UUID) -> dict[str, int]:
    rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.assessment_id == assessment_id)
            .group_by(Finding.severity)
        )
    ).all()
    counts = {level.value: 0 for level in SeverityLevel}
    for severity, count in rows:
        counts[_sev_key(severity)] = count
    return counts


async def _delete_assessment_children(db: AsyncSession, assessment_id: UUID) -> None:
    finding_ids = select(Finding.id).where(Finding.assessment_id == assessment_id)
    evidence_ids = select(EvidenceRecord.id).where(EvidenceRecord.assessment_id == assessment_id)
    offensive_job_ids = select(OffensiveJob.id).where(OffensiveJob.assessment_id == assessment_id)

    await db.execute(delete(FindingEvidence).where(FindingEvidence.finding_id.in_(finding_ids)))
    await db.execute(delete(FindingEvidence).where(FindingEvidence.evidence_id.in_(evidence_ids)))
    await db.execute(delete(JobOutput).where(JobOutput.job_id.in_(offensive_job_ids)))

    validation_run_ids = select(ValidationRun.id).where(ValidationRun.assessment_id == assessment_id)
    await db.execute(delete(ValidationExpertDecision).where(ValidationExpertDecision.validation_run_id.in_(validation_run_ids)))
    await db.execute(delete(ValidationRun).where(ValidationRun.assessment_id == assessment_id))

    await db.execute(delete(GraphEdge).where(GraphEdge.assessment_id == assessment_id))
    await db.execute(delete(ExposurePath).where(ExposurePath.assessment_id == assessment_id))
    await db.execute(delete(CertTemplate).where(CertTemplate.assessment_id == assessment_id))
    await db.execute(delete(Finding).where(Finding.assessment_id == assessment_id))
    await db.execute(delete(EvidenceRecord).where(EvidenceRecord.assessment_id == assessment_id))
    await db.execute(delete(Entity).where(Entity.assessment_id == assessment_id))
    await db.execute(delete(AttackChain).where(AttackChain.assessment_id == assessment_id))
    await db.execute(delete(OffensiveJob).where(OffensiveJob.assessment_id == assessment_id))
    await db.execute(
        delete(AssessmentDiff).where(
            or_(
                AssessmentDiff.baseline_assessment_id == assessment_id,
                AssessmentDiff.current_assessment_id == assessment_id,
            )
        )
    )
    await db.execute(
        update(Assessment)
        .where(Assessment.previous_assessment_id == assessment_id)
        .values(previous_assessment_id=None)
    )


@router.get("/workspaces", response_model=list[WorkspaceOption])
async def list_workspaces(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    q = select(Workspace).order_by(Workspace.name)
    if not current_user.is_superadmin:
        workspace_ids = await get_accessible_workspace_ids(db, current_user)
        if not workspace_ids:
            return []
        q = q.where(Workspace.id.in_(workspace_ids))
    return (await db.execute(q.offset(offset).limit(limit))).scalars().all()


@router.get("", response_model=list[AssessmentOut])
@router.get("/", response_model=list[AssessmentOut])
async def list_assessments(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status_filter: str | None = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    q = select(Assessment).options(defer(Assessment.collection_config))
    q = await scope_assessment_query(q, db, current_user)
    if status_filter:
        try:
            q = q.where(Assessment.status == AssessmentStatus(status_filter.upper()))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid assessment status") from exc
    q = q.order_by(desc(Assessment.created_at)).offset(offset).limit(limit)
    assessments = (await db.execute(q)).scalars().all()
    return await _apply_display_modules_from_config(db, list(assessments))


@router.post("", response_model=AssessmentOut, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=AssessmentOut, status_code=status.HTTP_201_CREATED)
async def create_assessment(
    payload: AssessmentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    workspace_id = await require_workspace_write_access(payload.workspace_id, db, current_user)
    profile = None
    if payload.connectivity_profile_id:
        profile = await db.get(ConnectivityProfile, payload.connectivity_profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Connectivity profile not found")
        if not current_user.is_superadmin and profile.created_by != current_user.id:
            raise HTTPException(status_code=403, detail="Connectivity profile access denied")

    initial_config = dict(payload.collection_config or {})
    provisional = Assessment(
        workspace_id=workspace_id,
        name=payload.name,
        domain=payload.domain,
        dc_ip=payload.dc_ip,
        collection_mode=payload.collection_mode,
        collection_config=initial_config,
        connectivity_profile_id=payload.connectivity_profile_id,
        created_by=current_user.id,
        status=AssessmentStatus.PENDING,
        modules_run=[],
        stats={},
        exposure_score=0.0,
    )
    resolved = resolve_connection(provisional, profile)
    overrides = resolved.collection_overrides()
    if overrides.get("resolved_target"):
        initial_config["resolved_target"] = overrides["resolved_target"]

    assessment = Assessment(
        workspace_id=workspace_id,
        name=payload.name,
        domain=overrides["domain"],
        dc_ip=overrides["dc_ip"],
        collection_mode=payload.collection_mode,
        collection_config=initial_config,
        connectivity_profile_id=payload.connectivity_profile_id,
        created_by=current_user.id,
        status=AssessmentStatus.PENDING,
        modules_run=[],
        stats={},
        exposure_score=0.0,
    )
    db.add(assessment)
    await db.commit()
    await db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}", response_model=AssessmentDetail)
async def get_assessment(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    return _with_display_modules(
        await require_assessment_access(
            assessment_id,
            db,
            current_user,
            include_collection_config=True,
        )
    )


@router.delete("/{assessment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_assessment(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    assessment = await require_assessment_write_access(assessment_id, db, current_user)
    await _delete_assessment_children(db, assessment_id)
    await db.delete(assessment)
    await db.commit()
    return None


@router.patch("/{assessment_id}", response_model=AssessmentOut)
async def update_assessment(
    assessment_id: UUID,
    payload: AssessmentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    assessment = await require_assessment_write_access(
        assessment_id,
        db,
        current_user,
        include_collection_config=True,
    )
    if payload.name is not None:
        assessment.name = payload.name
    if payload.domain is not None:
        assessment.domain = payload.domain
    if payload.dc_ip is not None:
        assessment.dc_ip = payload.dc_ip

    if payload.username is not None or payload.password is not None:
        # SQLAlchemy JSON columns often need reassignment to trigger update
        config = dict(assessment.collection_config or {})
        if "target" not in config:
            config["target"] = {}
        if payload.username is not None:
            config["target"]["username"] = payload.username
        if payload.password is not None:
            config["target"]["password"] = payload.password
        assessment.collection_config = config
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(assessment, "collection_config")

    await db.commit()
    await db.refresh(assessment)
    return assessment


@router.get("/{assessment_id}/stats")
async def get_assessment_stats(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    assessment = await require_assessment_access(assessment_id, db, current_user)
    entity_count = (
        await db.execute(select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id))
    ).scalar_one()
    finding_count = (
        await db.execute(select(func.count(Finding.id)).where(Finding.assessment_id == assessment_id))
    ).scalar_one()
    counts = await _severity_counts(db, assessment_id)
    return {
        **(assessment.stats or {}),
        "total_entities": entity_count,
        "total_findings": finding_count,
        **{key.lower(): value for key, value in counts.items()},
        **counts,
    }


@router.get("/{assessment_id}/dashboard", response_model=DashboardData)
async def get_dashboard(
    assessment_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    assessment = await require_assessment_access(assessment_id, db, current_user)
    severity_counts = await _severity_counts(db, assessment_id)
    total_findings = sum(severity_counts.values())
    status_rows = (
        await db.execute(
            select(Finding.status, func.count(Finding.id))
            .where(Finding.assessment_id == assessment_id)
            .group_by(Finding.status)
        )
    ).all()
    status_counts = {
        (status_value.value if hasattr(status_value, "value") else str(status_value)): count
        for status_value, count in status_rows
    }
    top_findings = (
        await db.execute(
            select(Finding)
            .where(Finding.assessment_id == assessment_id)
            .order_by(desc(Finding.composite_score).nullslast(), desc(Finding.created_at))
            .limit(10)
        )
    ).scalars().all()
    module_rows = (
        await db.execute(
            select(Finding.module, func.count(Finding.id))
            .where(Finding.assessment_id == assessment_id)
            .group_by(Finding.module)
        )
    ).all()
    entity_count = (
        await db.execute(select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id))
    ).scalar_one()

    coverage = [
        CoverageItem(name="Entities", covered=entity_count, total=max(entity_count, 1), pct=100.0 if entity_count else 0.0, status="good" if entity_count else "warn"),
        CoverageItem(name="Findings", covered=total_findings, total=max(total_findings, 1), pct=100.0 if total_findings else 0.0, status="good" if total_findings else "warn"),
    ]
    exposure = ExposureSummary(
        exposure_score=assessment.exposure_score or 0.0,
        score_delta=None,
        severity_counts=severity_counts,
        severity_deltas={},
        total_findings=total_findings,
        new_findings=status_counts.get(FindingStatus.OPEN.value, 0),
        resolved_findings=status_counts.get(FindingStatus.REMEDIATED.value, 0),
        regressed_findings=status_counts.get(FindingStatus.REGRESSED.value, 0),
    )
    _user_types = [EntityType.USER, EntityType.SERVICE_ACCOUNT, EntityType.GMSA, EntityType.DMSA]
    _computer_types = [EntityType.COMPUTER, EntityType.DC]
    total_users = (await db.execute(
        select(func.count(Entity.id)).where(
            Entity.assessment_id == assessment_id,
            Entity.entity_type.in_(_user_types),
        )
    )).scalar_one()
    total_computers = (await db.execute(
        select(func.count(Entity.id)).where(
            Entity.assessment_id == assessment_id,
            Entity.entity_type.in_(_computer_types),
        )
    )).scalar_one()
    tier0_count = (await db.execute(
        select(func.count(Entity.id)).where(
            Entity.assessment_id == assessment_id,
            Entity.tier == 0,
        )
    )).scalar_one()
    kerberoastable_count = (await db.execute(
        select(func.count(Entity.id)).where(
            Entity.assessment_id == assessment_id,
            Entity.attributes["has_spn"].as_boolean() == True,  # noqa: E712
        )
    )).scalar_one()
    esc1_count = (await db.execute(
        select(func.count(CertTemplate.id)).where(
            CertTemplate.assessment_id == assessment_id,
            CertTemplate.esc1_vulnerable == True,  # noqa: E712
        )
    )).scalar_one()
    return DashboardData(
        assessment=assessment,
        exposure=exposure,
        top_findings=top_findings,
        coverage=coverage,
        domain_info={
            "domain": assessment.domain,
            "dc_ip": assessment.dc_ip,
            "total_users": total_users,
            "total_computers": total_computers,
            "tier0_exposure": tier0_count,
            "kerberoastable": kerberoastable_count,
            "esc1_templates": esc1_count,
        },
        module_breakdown={module or "Unknown": count for module, count in module_rows},
    )
