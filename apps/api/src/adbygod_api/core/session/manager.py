"""Operator session state manager."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.models import OperatorSession, AuthLevel

AUTH_LEVEL_RANK = {
    AuthLevel.ANON: 0,
    AuthLevel.AUTHENTICATED: 1,
    AuthLevel.LOCAL_ADMIN: 2,
    AuthLevel.DOMAIN_ADMIN: 3,
    AuthLevel.DA_FOREST: 4,
    AuthLevel.SYSTEM: 5,
}


async def get_or_create_session(
    db: AsyncSession,
    user_id: uuid.UUID,
    assessment_id: uuid.UUID | None = None,
) -> OperatorSession:
    result = await db.execute(
        select(OperatorSession)
        .where(OperatorSession.created_by == user_id)
        .order_by(OperatorSession.started_at.desc())
        .limit(1)
    )
    session = result.scalar_one_or_none()
    if session is None:
        session = OperatorSession(
            id=uuid.uuid4(),
            created_by=user_id,
            assessment_id=assessment_id,
            auth_level=AuthLevel.ANON,
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        db.add(session)
        await db.commit()
        await db.refresh(session)
    return session


async def update_session(
    db: AsyncSession,
    session_id: uuid.UUID,
    *,
    target_ip: str | None = None,
    domain: str | None = None,
    auth_level: str | None = None,
    commands_delta: int = 0,
    findings_delta: int = 0,
    machines_delta: int = 0,
    users_delta: int = 0,
) -> OperatorSession:
    result = await db.execute(select(OperatorSession).where(OperatorSession.id == session_id))
    session = result.scalar_one_or_none()
    if session is None:
        raise ValueError(f"Session {session_id} not found")

    if target_ip is not None:
        session.target_ip = target_ip
    if domain is not None:
        session.domain = domain
    if auth_level is not None:
        new_rank = AUTH_LEVEL_RANK.get(AuthLevel(auth_level), 0)
        current_rank = AUTH_LEVEL_RANK.get(AuthLevel(session.auth_level), 0)
        if new_rank > current_rank:
            session.auth_level = auth_level
    session.commands_run += commands_delta
    session.findings_count += findings_delta
    session.machines_owned += machines_delta
    session.users_owned += users_delta
    session.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)

    await db.commit()
    await db.refresh(session)
    return session


async def reset_session(db: AsyncSession, session_id: uuid.UUID) -> OperatorSession:
    result = await db.execute(select(OperatorSession).where(OperatorSession.id == session_id))
    session = result.scalar_one_or_none()
    if session is None:
        raise ValueError(f"Session {session_id} not found")
    session.auth_level = AuthLevel.ANON
    session.commands_run = 0
    session.findings_count = 0
    session.machines_owned = 0
    session.users_owned = 0
    session.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.commit()
    await db.refresh(session)
    return session
