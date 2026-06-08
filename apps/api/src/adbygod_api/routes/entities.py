from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.database import get_db
from adbygod_api.models import Entity, EntityType, PlatformUser
from adbygod_api.schemas import EntityDetail, EntityOut
from adbygod_api.core.security.authorization import require_assessment_access, require_entity_access
from adbygod_api.routes.auth import get_current_user
from adbygod_api.routes._utils import parse_enum

router = APIRouter(prefix="/entities", tags=["entities"])


def _enum_value(value) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _entity_card(entity: Entity) -> dict:
    return {
        "id": str(entity.id),
        "label": entity.display_name or entity.sam_account_name or entity.dns_hostname or "Unnamed entity",
        "sam_account_name": entity.sam_account_name,
        "entity_type": _enum_value(entity.entity_type),
        "domain": entity.domain,
        "tier": entity.tier,
        "is_crown_jewel": entity.is_crown_jewel,
        "is_admin_count": entity.is_admin_count,
        "is_enabled": entity.is_enabled,
        "is_sensitive": entity.is_sensitive,
        "last_logon": entity.last_logon.isoformat() if entity.last_logon else None,
        "password_last_set": entity.password_last_set.isoformat() if entity.password_last_set else None,
    }


@router.get("/", response_model=List[EntityOut])
async def list_entities(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    entity_type: Optional[str] = None,
    tier: Optional[int] = None,
    is_crown_jewel: Optional[bool] = None,
    is_admin_count: Optional[bool] = None,
    is_enabled: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    q = select(Entity).where(Entity.assessment_id == assessment_id)

    if entity_type:
        q = q.where(Entity.entity_type == parse_enum(EntityType, entity_type, "entity_type"))
    if tier is not None:
        q = q.where(Entity.tier == tier)
    if is_crown_jewel is not None:
        q = q.where(Entity.is_crown_jewel == is_crown_jewel)
    if is_admin_count is not None:
        q = q.where(Entity.is_admin_count == is_admin_count)
    if is_enabled is not None:
        q = q.where(Entity.is_enabled == is_enabled)
    if search:
        term = f"%{search}%"
        q = q.where(or_(
            Entity.sam_account_name.ilike(term),
            Entity.display_name.ilike(term),
            Entity.dns_hostname.ilike(term),
        ))

    q = q.order_by(Entity.entity_type, Entity.sam_account_name).offset(offset).limit(limit)
    return (await db.execute(q)).scalars().all()


@router.get("/summary")
async def entity_type_summary(
    assessment_id: UUID = Query(..., description="Assessment to summarise"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)
    rows = (await db.execute(
        select(Entity.entity_type, func.count(Entity.id))
        .where(Entity.assessment_id == assessment_id)
        .group_by(Entity.entity_type)
    )).all()
    counts = {(et.value if hasattr(et, 'value') else str(et)): c for et, c in rows}

    tier0 = (await db.execute(
        select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id, Entity.tier == 0)
    )).scalar() or 0
    crown = (await db.execute(
        select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id, Entity.is_crown_jewel.is_(True))
    )).scalar() or 0
    admin = (await db.execute(
        select(func.count(Entity.id)).where(Entity.assessment_id == assessment_id, Entity.is_admin_count.is_(True))
    )).scalar() or 0

    return {
        "assessment_id": str(assessment_id),
        "total": sum(counts.values()),
        "by_type": counts,
        "tier0_count": tier0,
        "crown_jewel_count": crown,
        "admin_count": admin,
    }


@router.get("/intelligence")
async def entity_intelligence(
    assessment_id: UUID = Query(..., description="Assessment to analyze"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_access(assessment_id, db, current_user)

    stale_cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=90)
    base = Entity.assessment_id == assessment_id

    totals = (
        await db.execute(
            select(
                func.count(Entity.id).label("total"),
                func.sum(case((Entity.tier == 0, 1), else_=0)).label("tier0"),
                func.sum(case((Entity.tier == 1, 1), else_=0)).label("tier1"),
                func.sum(case((Entity.is_crown_jewel.is_(True), 1), else_=0)).label("crown_jewel"),
                func.sum(case((Entity.is_admin_count.is_(True), 1), else_=0)).label("admin_count"),
                func.sum(case((Entity.is_sensitive.is_(True), 1), else_=0)).label("sensitive"),
                func.sum(case((Entity.is_protected_user.is_(True), 1), else_=0)).label("protected_users"),
                func.sum(case((Entity.is_enabled.is_(False), 1), else_=0)).label("disabled"),
                func.sum(case((Entity.last_logon < stale_cutoff, 1), else_=0)).label("stale_logon"),
                func.sum(case((Entity.password_last_set < stale_cutoff, 1), else_=0)).label("stale_password"),
            ).where(base)
        )
    ).mappings().one()

    by_tier = (
        await db.execute(
            select(Entity.tier, func.count(Entity.id))
            .where(base)
            .group_by(Entity.tier)
            .order_by(Entity.tier)
        )
    ).all()
    by_flags = {
        "tier0": totals["tier0"] or 0,
        "tier1": totals["tier1"] or 0,
        "crown_jewel": totals["crown_jewel"] or 0,
        "admin_count": totals["admin_count"] or 0,
        "sensitive": totals["sensitive"] or 0,
        "protected_users": totals["protected_users"] or 0,
        "disabled": totals["disabled"] or 0,
        "stale_logon": totals["stale_logon"] or 0,
        "stale_password": totals["stale_password"] or 0,
    }
    watchlist = (
        await db.execute(
            select(Entity)
            .where(
                base,
                or_(
                    Entity.tier == 0,
                    Entity.is_crown_jewel.is_(True),
                    Entity.is_admin_count.is_(True),
                    Entity.is_sensitive.is_(True),
                ),
            )
            .order_by(
                desc(Entity.is_crown_jewel),
                desc(Entity.is_admin_count),
                Entity.tier.asc().nullslast(),
                Entity.entity_type,
                Entity.sam_account_name,
            )
            .limit(12)
        )
    ).scalars().all()
    dormant_privileged = (
        await db.execute(
            select(Entity)
            .where(
                base,
                or_(Entity.tier == 0, Entity.is_admin_count.is_(True), Entity.is_crown_jewel.is_(True)),
                or_(Entity.is_enabled.is_(False), Entity.last_logon < stale_cutoff, Entity.password_last_set < stale_cutoff),
            )
            .order_by(Entity.last_logon.asc().nullsfirst(), Entity.password_last_set.asc().nullsfirst())
            .limit(8)
        )
    ).scalars().all()

    total = totals["total"] or 0
    exposure_pressure = 0 if total == 0 else round(
        min(
            100,
            ((by_flags["tier0"] * 3.2) + (by_flags["crown_jewel"] * 2.8) + (by_flags["admin_count"] * 2.1) + by_flags["sensitive"]) / total * 100,
        ),
        1,
    )

    return {
        "assessment_id": str(assessment_id),
        "total": total,
        "by_tier": {("unknown" if tier is None else str(tier)): count for tier, count in by_tier},
        "by_flags": by_flags,
        "exposure_pressure": exposure_pressure,
        "stale_cutoff_days": 90,
        "watchlist": [_entity_card(entity) for entity in watchlist],
        "dormant_privileged": [_entity_card(entity) for entity in dormant_privileged],
    }


@router.get("/{entity_id}", response_model=EntityDetail)
async def get_entity(
    entity_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    return await require_entity_access(entity_id, db, current_user)
