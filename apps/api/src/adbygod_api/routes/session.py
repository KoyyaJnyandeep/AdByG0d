from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.core.session.manager import get_or_create_session, update_session, reset_session
from adbygod_api.database import get_db
from adbygod_api.models import PlatformUser
from adbygod_api.routes.auth import get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/session", tags=["session"])


class SessionOut(BaseModel):
    id: str
    target_ip: str | None
    domain: str | None
    auth_level: str
    commands_run: int
    findings_count: int
    machines_owned: int
    users_owned: int
    started_at: datetime


class SessionUpdateRequest(BaseModel):
    target_ip: str | None = Field(None, max_length=100)
    domain: str | None = Field(None, max_length=255)
    auth_level: str | None = None
    commands_delta: int = Field(0, ge=0)
    findings_delta: int = Field(0, ge=0)
    machines_delta: int = Field(0, ge=0)
    users_delta: int = Field(0, ge=0)


def _session_out(s) -> SessionOut:
    return SessionOut(
        id=str(s.id),
        target_ip=s.target_ip,
        domain=s.domain,
        auth_level=s.auth_level,
        commands_run=s.commands_run,
        findings_count=s.findings_count,
        machines_owned=s.machines_owned,
        users_owned=s.users_owned,
        started_at=s.started_at,
    )


@router.get("", response_model=SessionOut)
async def get_session(
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    return _session_out(session)


@router.post("/update", response_model=SessionOut)
async def update_session_route(
    body: SessionUpdateRequest,
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    updated = await update_session(
        db,
        session.id,
        target_ip=body.target_ip,
        domain=body.domain,
        auth_level=body.auth_level,
        commands_delta=body.commands_delta,
        findings_delta=body.findings_delta,
        machines_delta=body.machines_delta,
        users_delta=body.users_delta,
    )
    return _session_out(updated)


@router.post("/reset", response_model=SessionOut)
async def reset_session_route(
    current_user: PlatformUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session = await get_or_create_session(db, current_user.id)
    reset = await reset_session(db, session.id)
    return _session_out(reset)
