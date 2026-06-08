from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.database import get_db
from adbygod_api.models import Entity, Finding, PlatformUser
from adbygod_api.core.security.authorization import require_assessment_access, scope_assessment_child_query
from adbygod_api.routes.auth import get_current_user
from adbygod_api.routes._utils import ev

router = APIRouter(prefix="/search", tags=["search"])


@router.get("")
async def global_search(
    q: str = Query(..., min_length=2, max_length=128),
    assessment_id: Optional[UUID] = None,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    term = f"%{q.strip()}%"

    findings_query = select(Finding).where(or_(
        Finding.title.ilike(term),
        Finding.description.ilike(term),
        Finding.finding_type.ilike(term),
    ))
    entities_query = select(Entity).where(or_(
        Entity.sam_account_name.ilike(term),
        Entity.display_name.ilike(term),
        Entity.dns_hostname.ilike(term),
        Entity.object_sid.ilike(term),
    ))

    if assessment_id:
        await require_assessment_access(assessment_id, db, current_user)
        findings_query = findings_query.where(Finding.assessment_id == assessment_id)
        entities_query = entities_query.where(Entity.assessment_id == assessment_id)
    else:
        findings_query = await scope_assessment_child_query(findings_query, Finding.assessment_id, db, current_user)
        entities_query = await scope_assessment_child_query(entities_query, Entity.assessment_id, db, current_user)

    findings = (await db.execute(findings_query.order_by(Finding.composite_score.desc().nullslast()).limit(8))).scalars().all()
    entities = (await db.execute(entities_query.order_by(Entity.is_crown_jewel.desc(), Entity.sam_account_name).limit(8))).scalars().all()

    return {
        "findings": [{"id": str(f.id), "title": f.title, "severity": ev(f.severity)} for f in findings],
        "entities": [
            {
                "id": str(e.id),
                "label": e.display_name or e.sam_account_name or e.dns_hostname or str(e.id),
                "entity_type": ev(e.entity_type),
            }
            for e in entities
        ],
    }
