from typing import List, Literal, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import asc, select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, ConfigDict

from adbygod_api.database import get_db
from adbygod_api.models import AuditLog, PlatformUser
from adbygod_api.core.security.authorization import require_superadmin
from adbygod_api.routes.auth import get_current_user

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: dict
    created_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@router.get("", response_model=List[AuditLogOut])
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    user_id: Optional[UUID] = None,
    sort_by: Literal["created_at", "action", "resource_type"] = "created_at",
    sort_asc: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_superadmin(current_user)
    q = select(AuditLog)
    if action:
        q = q.where(AuditLog.action == action)
    if resource_type:
        q = q.where(AuditLog.resource_type == resource_type)
    if user_id is not None:
        q = q.where(AuditLog.user_id == user_id)
    sort_col = getattr(AuditLog, sort_by, AuditLog.created_at)
    q = q.order_by(asc(sort_col) if sort_asc else desc(sort_col)).offset(offset).limit(limit)
    return (await db.execute(q)).scalars().all()
