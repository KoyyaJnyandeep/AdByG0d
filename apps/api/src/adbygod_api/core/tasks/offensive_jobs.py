"""
Celery task: run an offensive ImpacketWorker job.

This task is enqueued by the /ops/execute route and executed by the Celery
worker process.  It is self-contained: it creates its own DB session, Redis
client, and event loop.  The API process itself does no subprocess work.

Design contract
---------------
- DB is the source of truth for job state.
- Redis pub/sub carries real-time output to connected WebSocket clients.
- The task publishes job output to the channel ``job:<job_id>:output`` and
  updates OffensiveJob rows (RUNNING → COMPLETED / FAILED) in PostgreSQL.
- On Celery worker restart mid-job, acks_late=True causes the broker to
  redeliver the task.  The task re-reads job state from DB and skips if the
  job is already in a terminal state.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone

from adbygod_api.core.celery_app import celery_app

log = logging.getLogger(__name__)


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@celery_app.task(
    bind=True,
    name="adbygod.run_offensive_job",
    queue="offensive_jobs",
    acks_late=True,
    max_retries=0,
    reject_on_worker_lost=True,
)
def run_offensive_job(
    self,
    job_id: str,
    executor_name: str,
    assessment_id: str | None = None,
) -> None:
    """Execute a single offensive job; update DB status; publish to Redis."""
    asyncio.run(_execute(job_id, executor_name, assessment_id))


async def _execute(
    job_id: str,
    executor_name: str,
    assessment_id: str | None,
) -> None:
    from adbygod_api.config import settings
    from adbygod_api.database import AsyncSessionLocal
    from adbygod_api.models import (
        JobOutput,
        OffensiveJob,
        OffensiveJobStatus,
    )
    from adbygod_api.core.streaming import publish_line
    from adbygod_api.core.workers.impacket_worker import ImpacketWorker

    import redis.asyncio as aioredis

    job_uuid = uuid.UUID(job_id)
    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)

    # Fetch job params from DB (the route already persisted them).
    async with AsyncSessionLocal() as db:
        job = await db.get(OffensiveJob, job_uuid)
        if job is None:
            log.error("Celery: job %s not found in DB; dropping task", job_id)
            await redis_client.aclose()
            return
        if job.status not in (OffensiveJobStatus.PENDING, OffensiveJobStatus.RUNNING):
            log.info("Celery: job %s already in terminal state %s; skip", job_id, job.status)
            await redis_client.aclose()
            return
        params = dict(job.params or {})

    # Build proxy transport if the job has an assessment with a connectivity profile.
    proxy = None
    if assessment_id:
        try:
            proxy = await _resolve_proxy(assessment_id)
        except Exception:
            log.warning("Celery: could not resolve proxy for job %s; running without proxy", job_id, exc_info=True)

    # Mark as RUNNING in DB.
    async with AsyncSessionLocal() as db:
        job = await db.get(OffensiveJob, job_uuid)
        if job and job.status == OffensiveJobStatus.PENDING:
            job.status = OffensiveJobStatus.RUNNING
            job.started_at = _utcnow()
            await db.commit()

    EXECUTOR_MAP = {"impacket": ImpacketWorker}
    worker_cls = EXECUTOR_MAP.get(executor_name, ImpacketWorker)
    worker = worker_cls(proxy_transport=proxy)

    line_buffer: list[JobOutput] = []
    last_flush_ts = time.time()

    async def flush_outputs() -> None:
        nonlocal last_flush_ts
        if not line_buffer:
            return
        try:
            async with AsyncSessionLocal() as db:
                db.add_all(line_buffer[:])
                await db.commit()
            line_buffer.clear()
            last_flush_ts = time.time()
        except Exception:
            log.exception("Celery: flush failed for job %s", job_id)

    async def emit(data: dict) -> None:
        data["job_id"] = job_id
        try:
            await publish_line(redis_client, job_id, data)
        except Exception:
            log.error("Celery: Redis publish failed for job %s", job_id)

        line = data.get("line")
        if line:
            line_buffer.append(
                JobOutput(
                    id=uuid.uuid4(),
                    job_id=job_uuid,
                    stream=data.get("stream", "stdout"),
                    line=line,
                    ts=_utcnow(),
                )
            )
            if len(line_buffer) >= 25 or (time.time() - last_flush_ts > 1.5):
                await flush_outputs()

        if data.get("done") or data.get("error"):
            await flush_outputs()
            exit_code = data.get("exit_code", 1)
            killed = data.get("killed", False)
            new_status = (
                OffensiveJobStatus.COMPLETED
                if (not killed and exit_code == 0)
                else OffensiveJobStatus.FAILED
            )
            async with AsyncSessionLocal() as db:
                finish_job = await db.get(OffensiveJob, job_uuid)
                if finish_job and finish_job.status == OffensiveJobStatus.RUNNING:
                    finish_job.status = new_status
                    finish_job.completed_at = _utcnow()
                    finish_job.exit_code = exit_code
                    await db.commit()
            try:
                await redis_client.aclose()
            except Exception:
                pass

    try:
        exit_code = await worker.execute(job_id, params, emit)
        await emit({"done": True, "exit_code": exit_code})
    except asyncio.CancelledError:
        await emit({"done": True, "exit_code": -1, "killed": True})
    except Exception as exc:
        log.exception("Celery: worker error for job %s", job_id)
        await emit({"error": str(exc), "done": True, "exit_code": 1})
        async with AsyncSessionLocal() as db:
            err_job = await db.get(OffensiveJob, job_uuid)
            if err_job and err_job.status == OffensiveJobStatus.RUNNING:
                err_job.status = OffensiveJobStatus.FAILED
                err_job.completed_at = _utcnow()
                err_job.exit_code = 1
                await db.commit()
        try:
            await redis_client.aclose()
        except Exception:
            pass


async def _resolve_proxy(assessment_id: str):
    """Return a ProxyTransport for the given assessment, or None."""
    from adbygod_api.database import AsyncSessionLocal
    from adbygod_api.models import Assessment, ConnectivityProfile
    from adbygod_api.core.connectivity.transport import resolve_transport

    assessment_uuid = uuid.UUID(assessment_id)
    async with AsyncSessionLocal() as db:
        asmt = await db.get(Assessment, assessment_uuid)
        if asmt is None or asmt.connectivity_profile_id is None:
            return None
        cp = await db.get(ConnectivityProfile, asmt.connectivity_profile_id)
        if cp is None:
            return None
        return await resolve_transport(cp, db)
