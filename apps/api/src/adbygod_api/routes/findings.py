from __future__ import annotations

from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.security.authorization import (
    require_assessment_access,
    require_assessment_write_access,
    require_finding_access,
    scope_assessment_child_query,
)
from adbygod_api.database import get_db
from adbygod_api.models import EvidenceRecord, Finding, FindingEvidence, FindingStatus, PlatformUser, SeverityLevel
from adbygod_api.routes.auth import get_current_user
from adbygod_api.schemas import EvidenceOut, FindingDetail, FindingEvidenceLinkOut, FindingOut, FindingsPage, FindingUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


def _module_terms(value: str) -> list[str]:
    term = value.strip()
    normalized = term.lower().replace(" ", "").replace("-", "").replace("_", "")
    aliases = {
        "adcs": ["AD CS", "ADCS", "Certificate Services", "PKI"],
        "pki": ["AD CS", "ADCS", "Certificate Services", "PKI"],
        "trust": ["Trust", "Trusts", "Topology and Trusts", "Domain and Forest Trust Analysis", "Cross-Forest Enumeration"],
        "trusts": ["Trust", "Trusts", "Topology and Trusts", "Domain and Forest Trust Analysis", "Cross-Forest Enumeration"],
        "acl": ["ACL", "ACL Abuse", "Directory ACL"],
        "kerberos": ["Kerberos", "Kerberos Posture"],
        "serviceaccount": ["Service Account", "Service Accounts", "Service Account Review"],
        "serviceaccounts": ["Service Account", "Service Accounts", "Service Account Review"],
    }
    expanded = [term, *aliases.get(normalized, [])]
    seen: set[str] = set()
    return [item for item in expanded if item and not (item.lower() in seen or seen.add(item.lower()))]


def _serialize_evidence_link(link: FindingEvidence, evidence: EvidenceRecord) -> FindingEvidenceLinkOut:
    return FindingEvidenceLinkOut(
        id=link.id,
        evidence_id=link.evidence_id,
        relation_type=link.relation_type or "supports",
        relevance=link.relevance,
        source_ref=link.source_ref or {},
        source_type=evidence.source_type,
        source_host=evidence.source_host,
        collection_method=evidence.collection_method,
        origin=evidence.origin,
        confidence=evidence.confidence,
        is_corroborated=evidence.is_corroborated,
    )


@router.get("/modules/summary")
async def module_summary(
    assessment_id: UUID = Query(...),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    rows = (
        await db.execute(
            select(Finding.module, func.count(Finding.id))
            .where(Finding.assessment_id == assessment_id)
            .group_by(Finding.module)
            .order_by(desc(func.count(Finding.id)))
        )
    ).all()
    return [{"module": module or "Unknown", "total": count} for module, count in rows]


@router.get("", response_model=FindingsPage)
@router.get("/", response_model=FindingsPage)
async def list_findings(
    assessment_id: UUID | None = None,
    severity: list[str] | None = Query(None),
    module: list[str] | None = Query(None),
    status: list[str] | None = Query(None),
    min_score: float | None = None,
    drift_status: str | None = None,
    assigned_to: UUID | None = None,
    search: str | None = Query(None, max_length=128),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = "composite_score",
    sort_desc: bool = True,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    q = select(Finding)
    if assessment_id:
        await require_assessment_access(assessment_id, db, current_user)
        q = q.where(Finding.assessment_id == assessment_id)
    else:
        q = await scope_assessment_child_query(q, Finding.assessment_id, db, current_user)

    if severity:
        try:
            q = q.where(Finding.severity.in_([SeverityLevel(item.upper()) for item in severity]))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid severity") from exc
    if module:
        module_clauses = []
        for item in module:
            for term in _module_terms(item):
                module_clauses.append(Finding.module.ilike(term))
                module_clauses.append(Finding.module.ilike(f"%{term}%"))
        if module_clauses:
            q = q.where(or_(*module_clauses))
    if status:
        try:
            q = q.where(Finding.status.in_([FindingStatus(item.upper()) for item in status]))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid finding status") from exc
    if min_score is not None:
        q = q.where(Finding.composite_score >= min_score)
    if drift_status:
        q = q.where(Finding.drift_status == drift_status)
    if assigned_to:
        q = q.where(Finding.assigned_to == assigned_to)
    if search:
        term = f"%{search.strip()}%"
        q = q.where(or_(Finding.title.ilike(term), Finding.description.ilike(term), Finding.root_cause.ilike(term)))

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    _ALLOWED_SORT = {"composite_score", "created_at", "severity", "title", "affected_count", "confidence"}
    if sort_by not in _ALLOWED_SORT:
        sort_by = "composite_score"
    sort_column = getattr(Finding, sort_by, Finding.composite_score)
    order_expr = desc(sort_column).nullslast() if sort_desc else sort_column.asc().nullsfirst()
    items = (
        await db.execute(q.order_by(order_expr, desc(Finding.created_at)).offset((page - 1) * page_size).limit(page_size))
    ).scalars().all()
    return FindingsPage(items=items, total=total, page=page, page_size=page_size, pages=ceil(total / page_size) if total else 0)


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    finding = await require_finding_access(finding_id, db, current_user)
    rows = (
        await db.execute(
            select(FindingEvidence, EvidenceRecord)
            .join(EvidenceRecord, FindingEvidence.evidence_id == EvidenceRecord.id)
            .where(FindingEvidence.finding_id == finding_id)
            .order_by(EvidenceRecord.collected_at)
        )
    ).all()
    detail = FindingDetail.model_validate(finding)
    detail.evidence_links = [_serialize_evidence_link(link, evidence) for link, evidence in rows]
    return detail


@router.patch("/{finding_id}", response_model=FindingOut)
async def update_finding(
    finding_id: UUID,
    payload: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    finding = await require_finding_access(finding_id, db, current_user)
    await require_assessment_write_access(finding.assessment_id, db, current_user)

    updates = payload.model_dump(exclude_unset=True)
    for key, value in updates.items():
        setattr(finding, key, value)
    await db.commit()
    await db.refresh(finding)
    return finding


@router.get("/{finding_id}/evidence", response_model=list[EvidenceOut])
async def finding_evidence(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_finding_access(finding_id, db, current_user)
    rows = (
        await db.execute(
            select(EvidenceRecord)
            .join(FindingEvidence, FindingEvidence.evidence_id == EvidenceRecord.id)
            .where(FindingEvidence.finding_id == finding_id)
            .order_by(EvidenceRecord.collected_at)
        )
    ).scalars().all()
    return rows
