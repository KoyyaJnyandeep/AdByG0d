from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.security.authorization import require_assessment_access
from adbygod_api.database import get_db
from adbygod_api.models import Entity, EntityType, PlatformUser
from adbygod_api.routes.auth import get_current_user

router = APIRouter(prefix="/service-accounts", tags=["service-accounts"])

_SVC_TYPES = [EntityType.SERVICE_ACCOUNT, EntityType.GMSA, EntityType.DMSA]


def _password_age_days(entity: Entity) -> int:
    """Calculate password age in days from entity password_last_set."""
    ts = entity.password_last_set
    if not ts:
        return 0
    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        ts_naive = ts.replace(tzinfo=None) if ts.tzinfo else ts
        return (now - ts_naive).days
    except (TypeError, AttributeError):
        return 0


def _score_account(entity: Entity, pwd_age: int) -> tuple[float, str]:
    """Return (numeric_score 0-100, risk_grade) for a service account entity."""
    attrs = entity.attributes or {}

    # Unconstrained delegation → immediate CRITICAL cap
    if attrs.get("unconstrained_delegation"):
        return 100.0, "CRITICAL"

    # Collect individual risk components
    components: list[float] = []

    if entity.is_admin_count:
        components.append(85.0)
    if attrs.get("asrep_roastable"):
        components.append(75.0)
    spns = attrs.get("spns") or []
    if attrs.get("kerberoastable") or (isinstance(spns, list) and len(spns) > 0):
        components.append(70.0)
    if attrs.get("constrained_delegation") or attrs.get("resource_based_delegation"):
        components.append(60.0)
    priv_groups = attrs.get("privileged_groups") or []
    if isinstance(priv_groups, list) and len(priv_groups) > 0:
        components.append(55.0)
    if getattr(entity, "is_sensitive", False) or getattr(entity, "is_crown_jewel", False):
        components.append(50.0)
    if pwd_age > 730:
        components.append(45.0)
    elif pwd_age > 365:
        components.append(30.0)

    if not components:
        base = 10.0
    else:
        base = max(components)
        # Additional factors add 15% of their value (diminishing returns)
        bonus = sum(sorted(components)[:-1]) * 0.15
        base = min(100.0, base + bonus)

    # Disabled account halves risk (can't be exploited while disabled)
    if getattr(entity, "is_enabled", True) is False:
        base = base * 0.5

    score = round(base, 1)
    if score >= 85:
        grade = "CRITICAL"
    elif score >= 65:
        grade = "HIGH"
    elif score >= 40:
        grade = "MEDIUM"
    else:
        grade = "LOW"

    return score, grade


def _entity_to_service_account(entity: Entity) -> dict[str, Any]:
    attrs = entity.attributes or {}
    pwd_age = _password_age_days(entity)
    spns = attrs.get("spns", []) or []
    privileged_groups = attrs.get("privileged_groups", []) or []
    _risk_score, _risk_grade = _score_account(entity, pwd_age)
    return {
        "id": str(entity.id),
        "assessment_id": str(entity.assessment_id),
        "sam_account_name": entity.sam_account_name or "",
        "display_name": entity.display_name or entity.sam_account_name or "",
        "domain": entity.domain,
        "entity_type": entity.entity_type.value if hasattr(entity.entity_type, "value") else str(entity.entity_type),
        "tier": entity.tier,
        "is_enabled": entity.is_enabled,
        "is_admin_count": entity.is_admin_count,
        "is_sensitive": entity.is_sensitive,
        "spns": spns if isinstance(spns, list) else [str(spns)],
        "kerberoastable": bool(attrs.get("kerberoastable", len(spns) > 0)),
        "asrep_roastable": bool(attrs.get("asrep_roastable", False)),
        "unconstrained_delegation": bool(attrs.get("unconstrained_delegation", False)),
        "constrained_delegation": bool(attrs.get("constrained_delegation", False)),
        "resource_based_delegation": bool(attrs.get("resource_based_delegation", False)),
        "password_age_days": pwd_age,
        "password_last_set": entity.password_last_set.isoformat() if entity.password_last_set else None,
        "last_logon": entity.last_logon.isoformat() if entity.last_logon else None,
        "in_privileged_group": bool(privileged_groups) or entity.is_admin_count,
        "privileged_groups": privileged_groups if isinstance(privileged_groups, list) else [str(privileged_groups)],
        "risk_score": _risk_score,
        "risk": _risk_grade,
        "distinguished_name": entity.distinguished_name,
        "object_sid": entity.object_sid,
        "attributes": attrs,
    }


@router.get("")
async def list_service_accounts(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict]:
    """Return all service account entities with enriched risk data."""
    await require_assessment_access(assessment_id, db, current_user)
    entities = (
        await db.execute(
            select(Entity)
            .where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type.in_(_SVC_TYPES),
            )
            .offset(offset)
            .limit(limit)
        )
    ).scalars().all()
    accounts = [_entity_to_service_account(e) for e in entities]
    accounts.sort(key=lambda a: a["risk_score"], reverse=True)
    return accounts


@router.get("/summary")
async def service_account_summary(
    assessment_id: UUID = Query(..., description="Assessment to query"),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Return aggregated service account risk metrics for an assessment."""
    await require_assessment_access(assessment_id, db, current_user)

    total = (
        await db.execute(
            select(func.count(Entity.id)).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type.in_(_SVC_TYPES),
            )
        )
    ).scalar_one()

    # Load all for derived metrics — cap at 500 for performance
    entities = (
        await db.execute(
            select(Entity).where(
                Entity.assessment_id == assessment_id,
                Entity.entity_type.in_(_SVC_TYPES),
            ).limit(500)
        )
    ).scalars().all()

    accounts = [_entity_to_service_account(e) for e in entities]
    return {
        "assessment_id": str(assessment_id),
        "total": total,
        "capped": total > len(accounts),
        "privileged": sum(1 for a in accounts if a["in_privileged_group"]),
        "kerberoastable": sum(1 for a in accounts if a["kerberoastable"]),
        "asrep_roastable": sum(1 for a in accounts if a["asrep_roastable"]),
        "unconstrained_delegation": sum(1 for a in accounts if a["unconstrained_delegation"]),
        "stale_password": sum(1 for a in accounts if a["password_age_days"] > 180),
        "by_risk": {
            "CRITICAL": sum(1 for a in accounts if a["risk"] == "CRITICAL"),
            "HIGH": sum(1 for a in accounts if a["risk"] == "HIGH"),
            "MEDIUM": sum(1 for a in accounts if a["risk"] == "MEDIUM"),
            "LOW": sum(1 for a in accounts if a["risk"] == "LOW"),
            "avg_risk_score": round(
                sum(a["risk_score"] for a in accounts) / max(len(accounts), 1), 1
            ),
        },
        "by_type": {
            # str(EntityType.SERVICE_ACCOUNT) == 'EntityType.SERVICE_ACCOUNT'
            # in Python enum default repr, not 'SERVICE_ACCOUNT'. Always compare .value
            "SERVICE_ACCOUNT": sum(1 for e in entities if getattr(e.entity_type, 'value', str(e.entity_type)) == "SERVICE_ACCOUNT"),
            "GMSA": sum(1 for e in entities if getattr(e.entity_type, 'value', str(e.entity_type)) == "GMSA"),
            "DMSA": sum(1 for e in entities if getattr(e.entity_type, 'value', str(e.entity_type)) == "DMSA"),
        },
    }
