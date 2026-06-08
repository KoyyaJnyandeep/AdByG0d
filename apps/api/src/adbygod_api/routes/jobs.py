"""
AdByG0d Platform — Job Progress Store & SSE Endpoint

The default in-memory store is intentionally development-oriented. Production
installations should swap this interface for a Redis-backed implementation.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, Protocol
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from jose import JWTError, jwt
from sse_starlette.sse import EventSourceResponse

from adbygod_api.config import settings
from adbygod_api.models import PlatformUser
from adbygod_api.routes.auth import get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/jobs", tags=["jobs"])


@dataclass
class JobRecord:
    owner_user_id: UUID
    created_at: datetime
    subscribers: set[asyncio.Queue] = field(default_factory=set)
    history: deque[dict] = field(default_factory=lambda: deque(maxlen=200))
    done: bool = False
    terminal_status: str = "RUNNING"
    finished_at: datetime | None = None
    last_event: dict = field(default_factory=dict)
    last_event_at: datetime | None = None


class JobStore(Protocol):
    def create(self, job_id: str, owner_user_id: UUID) -> JobRecord: ...
    def get(self, job_id: str) -> JobRecord | None: ...
    def items(self) -> list[tuple[str, JobRecord]]: ...
    def remove(self, job_id: str) -> None: ...


class InMemoryJobStore:
    def __init__(self):
        self._jobs: dict[str, JobRecord] = {}

    def create(self, job_id: str, owner_user_id: UUID) -> JobRecord:
        record = JobRecord(
            owner_user_id=owner_user_id,
            created_at=datetime.now(timezone.utc),
        )
        self._jobs[job_id] = record
        return record

    def get(self, job_id: str) -> JobRecord | None:
        return self._jobs.get(job_id)

    def items(self) -> list[tuple[str, JobRecord]]:
        return list(self._jobs.items())

    def remove(self, job_id: str) -> None:
        self._jobs.pop(job_id, None)


_JOB_STORE: JobStore = InMemoryJobStore()


def create_job(job_id: str, owner_user_id: UUID) -> JobRecord:
    _gc_stale_jobs()
    return _JOB_STORE.create(job_id, owner_user_id)


def get_job(job_id: str) -> JobRecord | None:
    return _JOB_STORE.get(job_id)


def remove_job(job_id: str) -> None:
    _JOB_STORE.remove(job_id)


async def emit(job_id: str, event: dict):
    """Emit a progress event to every active subscriber and keep bounded history."""
    record = get_job(job_id)
    if record is None:
        return

    record.last_event = dict(event)
    record.last_event_at = datetime.now(timezone.utc)
    record.history.append(dict(event))
    if event.get("error"):
        record.done = True
        record.terminal_status = "FAILED"
        record.finished_at = datetime.now(timezone.utc)
    elif event.get("done"):
        record.done = True
        record.terminal_status = event.get("status", "COMPLETED")
        record.finished_at = datetime.now(timezone.utc)

    dead: list[asyncio.Queue] = []
    for queue in list(record.subscribers):
        try:
            queue.put_nowait(dict(event))
        except asyncio.QueueFull:
            dead.append(queue)
            log.warning("Job subscriber queue full, removing subscriber", extra={"job_id": job_id})
    for queue in dead:
        record.subscribers.discard(queue)


class InvalidStreamTokenError(Exception):
    pass


def create_stream_token(job_id: str, owner_user_id: UUID) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.STREAM_TOKEN_EXPIRE_MINUTES)
    payload = {
        "type": "job_stream",
        "job_id": job_id,
        "sub": str(owner_user_id),
        "exp": expires_at,
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def validate_stream_token(job_id: str, token: str) -> UUID:
    if not token:
        raise InvalidStreamTokenError("Missing stream token")

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as exc:
        raise InvalidStreamTokenError("Invalid stream token") from exc

    if payload.get("type") != "job_stream" or payload.get("job_id") != job_id:
        raise InvalidStreamTokenError("Invalid stream token")

    subject = payload.get("sub")
    if not subject:
        raise InvalidStreamTokenError("Invalid stream token")

    try:
        return UUID(subject)
    except ValueError as exc:
        raise InvalidStreamTokenError("Invalid stream token") from exc


_JOB_TTL_SECONDS = 3600  # max lifetime for finished/abandoned jobs
_JOB_ACTIVE_TTL_SECONDS = 14400  # 4 h — GC ceiling even for still-running jobs


def _gc_stale_jobs() -> None:
    """Remove job records that are done (or abandoned) for more than TTL seconds."""
    now = datetime.now(timezone.utc)
    stale = []
    for jid, rec in _JOB_STORE.items():
        if rec.done and rec.finished_at and (now - rec.finished_at).total_seconds() > _JOB_TTL_SECONDS:
            stale.append(jid)
        # only GC running jobs if they truly appear abandoned
        # (no event in the last 10 minutes AND created a very long time ago).
        elif not rec.done:
            last_activity = rec.last_event_at or rec.created_at
            if (now - last_activity).total_seconds() > _JOB_ACTIVE_TTL_SECONDS:
                stale.append(jid)
    for jid in stale:
        _JOB_STORE.remove(jid)
    if stale:
        log.debug("GC: removed %d stale job records", len(stale))


async def _event_generator(job_id: str) -> AsyncGenerator[str, None]:
    _gc_stale_jobs()  # opportunistic GC on each new stream connection
    record = get_job(job_id)
    if record is None:
        yield json.dumps({"error": "job not found"})
        return

    queue: asyncio.Queue = asyncio.Queue(maxsize=256)
    for event in list(record.history):
        try:
            queue.put_nowait(dict(event))
        except asyncio.QueueFull:
            break
    record.subscribers.add(queue)

    # cap the total SSE session at 4 h to prevent generator
    # running forever if a client stops reading without disconnecting
    import time as _time
    session_deadline = _time.monotonic() + 14400

    try:
        while True:
            if _time.monotonic() > session_deadline:
                yield json.dumps({"error": "stream timeout", "done": True})
                break
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
            except asyncio.TimeoutError:
                yield json.dumps({"heartbeat": True})
                if record.done:
                    break
                continue

            yield json.dumps(event)

            if event.get("done") or event.get("error"):
                break
    finally:
        record.subscribers.discard(queue)


@router.get("/stream/{job_id}")
async def stream_job_progress(
    job_id: str,
    token: str = Query("", description="Short-lived signed token for the specific job stream"),
):
    """SSE stream for a running import or collection job."""
    _gc_stale_jobs()
    record = get_job(job_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found or already completed")

    try:
        subject = validate_stream_token(job_id, token)
    except InvalidStreamTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    if subject != record.owner_user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Job stream access denied")

    response = EventSourceResponse(_event_generator(job_id))
    # P3: token in query string is a known SSE limitation — browsers cannot send
    # custom headers on EventSource connections. Mitigated by short token TTL and
    # Cache-Control/no-store so the URL is not stored in browser or proxy caches.
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@router.get("/status/{job_id}")
async def job_status(
    job_id: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Quick ownership-checked status query for an active job."""
    _gc_stale_jobs()
    record = get_job(job_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    if not current_user.is_superadmin and record.owner_user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Job access denied")

    return {
        "job_id": job_id,
        "active": not record.done,
        "status": record.terminal_status,
        "done": record.done,
        "created_at": record.created_at.isoformat(),
    }
