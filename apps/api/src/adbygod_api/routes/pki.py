from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.database import get_db
from adbygod_api.models import CertTemplate, PlatformUser
from adbygod_api.core.security.authorization import require_assessment_access
from adbygod_api.routes.auth import get_current_user

router = APIRouter(prefix="/pki", tags=["pki"])


def _template_dict(t: CertTemplate) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "ca_name": t.ca_name,
        "distinguished_name": t.distinguished_name,
        "enrollee_supplies_subject": t.enrollee_supplies_subject,
        "requires_manager_approval": t.requires_manager_approval,
        "authorized_signatures_required": t.authorized_signatures_required,
        "validity_period": t.validity_period,
        "ekus": t.ekus or [],
        "enrollment_rights": t.enrollment_rights or [],
        "write_rights": t.write_rights or [],
        "esc1_vulnerable": t.esc1_vulnerable,
        "esc2_vulnerable": t.esc2_vulnerable,
        "esc3_vulnerable": t.esc3_vulnerable,
        "esc4_vulnerable": t.esc4_vulnerable,
    }


@router.get("/templates")
async def list_cert_templates(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    vulnerable_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    q = select(CertTemplate).where(CertTemplate.assessment_id == assessment_id)

    if vulnerable_only:
        q = q.where(or_(
            CertTemplate.esc1_vulnerable.is_(True),
            CertTemplate.esc2_vulnerable.is_(True),
            CertTemplate.esc3_vulnerable.is_(True),
            CertTemplate.esc4_vulnerable.is_(True),
        ))

    q = q.order_by(CertTemplate.esc1_vulnerable.desc(), CertTemplate.esc2_vulnerable.desc(), CertTemplate.name)
    return [_template_dict(t) for t in (await db.execute(q)).scalars().all()]


@router.get("/summary")
async def pki_summary(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    templates = (await db.execute(select(CertTemplate).where(CertTemplate.assessment_id == assessment_id))).scalars().all()

    esc1 = esc2 = esc3 = esc4 = vulnerable = 0
    for t in templates:
        if t.esc1_vulnerable:
            esc1 += 1
        if t.esc2_vulnerable:
            esc2 += 1
        if t.esc3_vulnerable:
            esc3 += 1
        if t.esc4_vulnerable:
            esc4 += 1
        if t.esc1_vulnerable or t.esc2_vulnerable or t.esc3_vulnerable or t.esc4_vulnerable:
            vulnerable += 1

    return {
        "assessment_id": str(assessment_id),
        "total_templates": len(templates),
        "vulnerable_templates": vulnerable,
        "esc1_count": esc1,
        "esc2_count": esc2,
        "esc3_count": esc3,
        "esc4_count": esc4,
        "ca_names": list({t.ca_name for t in templates if t.ca_name}),
    }
