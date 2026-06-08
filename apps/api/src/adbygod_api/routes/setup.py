"""Dev-only setup router — no auth required. Returns 404 in production."""
from __future__ import annotations
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.config import settings
from adbygod_api.database import get_db
from adbygod_api.models import PlatformUser
from adbygod_api.routes.auth import _hash_password, get_current_user

router = APIRouter(prefix="/setup", tags=["setup"])

# Resolve to repo-root/.dev-profile.json
DEV_PROFILE_PATH = Path(__file__).resolve().parents[5] / ".dev-profile.json"

_SUPERADMIN_ROLE = "Superadmin · Local Dev"


def _require_dev() -> None:
    if settings.is_production:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")



async def _require_setup_admin(request: Request, db: AsyncSession) -> None:
    """Require superadmin auth for destructive setup changes.

    Skipped only before the first local operator exists when DEBUG=true and
    ALLOW_DEV_BOOTSTRAP=true.
    """
    if settings.dev_bootstrap_enabled and not await _admin_exists(db):
        return
    user = await get_current_user(request=request, credentials=None, db=db)
    if not user.is_superadmin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superadmin access required")

def _read_profile() -> dict | None:
    try:
        data = json.loads(DEV_PROFILE_PATH.read_text())
        if isinstance(data, dict) and "callsign" in data and "role" in data:
            return data
        return None
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _write_profile(callsign: str) -> None:
    from datetime import datetime, timezone
    DEV_PROFILE_PATH.write_text(
        json.dumps({
            "callsign": callsign,
            "role": _SUPERADMIN_ROLE,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }, indent=2)
    )


def _delete_profile() -> None:
    DEV_PROFILE_PATH.unlink(missing_ok=True)


async def _admin_exists(db: AsyncSession) -> bool:
    result = await db.execute(
        select(func.count()).select_from(PlatformUser).where(PlatformUser.is_superadmin == True)  # noqa: E712
    )
    return (result.scalar() or 0) > 0


class InitRequest(BaseModel):
    callsign: str = Field(min_length=1, max_length=64)
    passphrase: str = Field(min_length=8, max_length=128)


class ProfileOut(BaseModel):
    callsign: str
    role: str


class StatusOut(BaseModel):
    setup_complete: bool
    profile: ProfileOut | None = None


class UpdateRequest(BaseModel):
    callsign: str | None = Field(default=None, min_length=1, max_length=64)
    passphrase: str | None = Field(default=None, min_length=8, max_length=128)


@router.get("/status", response_model=StatusOut)
async def setup_status(db: AsyncSession = Depends(get_db)):
    _require_dev()
    complete = await _admin_exists(db)
    profile_data = _read_profile() if complete else None
    profile = ProfileOut(**profile_data) if profile_data else None
    return StatusOut(setup_complete=complete, profile=profile)


@router.post("/init", response_model=ProfileOut, status_code=status.HTTP_201_CREATED)
async def setup_init(body: InitRequest, db: AsyncSession = Depends(get_db)):
    _require_dev()
    if not settings.dev_bootstrap_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dev bootstrap is disabled. Set DEBUG=true and ALLOW_DEV_BOOTSTRAP=true.",
        )
    if await _admin_exists(db):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Operator already initialised")

    user = PlatformUser(
        username=body.callsign.lower(),
        email=f"{body.callsign.lower()}@local.dev",
        full_name=body.callsign,
        hashed_password=_hash_password(body.passphrase),
        is_active=True,
        is_superadmin=True,
    )
    db.add(user)
    await db.commit()
    _write_profile(body.callsign)
    return ProfileOut(callsign=body.callsign, role=_SUPERADMIN_ROLE)


@router.put("/profile", response_model=ProfileOut)
async def update_profile(body: UpdateRequest, request: Request, db: AsyncSession = Depends(get_db)):
    _require_dev()
    await _require_setup_admin(request, db)
    result = await db.execute(
        select(PlatformUser).where(PlatformUser.is_superadmin == True).limit(1)  # noqa: E712
    )
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No operator found")
    if body.callsign:
        user.username = body.callsign.lower()
        user.full_name = body.callsign
        user.email = f"{body.callsign.lower()}@local.dev"
    if body.passphrase:
        user.hashed_password = _hash_password(body.passphrase)
    await db.commit()
    await db.refresh(user)
    new_callsign = body.callsign or user.full_name or user.username
    _write_profile(new_callsign)
    return ProfileOut(callsign=new_callsign, role=_SUPERADMIN_ROLE)


@router.delete("/profile", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(request: Request, db: AsyncSession = Depends(get_db)):
    _require_dev()
    await _require_setup_admin(request, db)
    result = await db.execute(
        select(PlatformUser).where(PlatformUser.is_superadmin == True)  # noqa: E712
    )
    users = result.scalars().all()
    for u in users:
        await db.delete(u)
    await db.commit()
    _delete_profile()
