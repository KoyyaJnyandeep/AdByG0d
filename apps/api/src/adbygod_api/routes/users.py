from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.security.authorization import require_superadmin
from adbygod_api.database import get_db
from adbygod_api.models import PlatformUser
from adbygod_api.routes.auth import get_current_user, _hash_password

log = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["users"])


class UserUpdate(BaseModel):
    email: str | None = Field(None, max_length=254)
    full_name: str | None = Field(None, max_length=200)
    password: str | None = Field(None, max_length=128)


def _normalize_email(value: str) -> str:
    email = str(value or "").strip().lower()
    if not email or "@" not in email or email.startswith("@") or email.endswith("@"):
        raise HTTPException(status_code=422, detail="Invalid email address")
    return email


def _user_to_dict(user: PlatformUser) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "is_superadmin": user.is_superadmin,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }


@router.get("")
async def list_users(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """List all platform users. Requires superadmin."""
    await require_superadmin(current_user)
    users = (
        await db.execute(
            select(PlatformUser).order_by(PlatformUser.username).offset(offset).limit(limit)
        )
    ).scalars().all()
    return [_user_to_dict(u) for u in users]


@router.get("/me")
async def get_me(
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Return current authenticated user profile."""
    return _user_to_dict(current_user)


@router.patch("/{user_id}")
async def update_user(
    user_id: UUID,
    payload: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Update a user profile. Users can update themselves; superadmins can update anyone."""
    # Authorization: self or superadmin
    if current_user.id != user_id and not current_user.is_superadmin:
        raise HTTPException(status_code=403, detail="Forbidden: can only update your own profile")

    user = await db.get(PlatformUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.email is not None:
        email = _normalize_email(payload.email)
        existing = (
            await db.execute(
                select(PlatformUser).where(
                    func.lower(PlatformUser.email) == email,
                    PlatformUser.id != user_id,
                )
            )
        ).scalars().first()
        if existing:
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = email

    if payload.full_name is not None:
        user.full_name = payload.full_name

    if payload.password is not None:
        if len(payload.password) < 8:
            raise HTTPException(status_code=422, detail="Password must be at least 8 characters")
        user.hashed_password = _hash_password(payload.password)

    await db.commit()
    await db.refresh(user)
    return _user_to_dict(user)


@router.post("/{user_id}/deactivate", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def deactivate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> None:
    """Deactivate a platform user. Requires superadmin."""
    await require_superadmin(current_user)

    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    user = await db.get(PlatformUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await db.commit()


@router.post("/{user_id}/activate", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def activate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> None:
    """Re-activate a platform user. Requires superadmin."""
    await require_superadmin(current_user)

    user = await db.get(PlatformUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = True
    await db.commit()
