from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sse_starlette.sse import EventSourceResponse

from adbygod_api.core.arsenal.cve_database import (
    CVE_DATABASE, get_stats, get_categories,
)
from adbygod_api.core.arsenal.checker import run_check
from adbygod_api.config import settings
from adbygod_api.core.security.authorization import (
    require_assessment_access,
    scope_assessment_query,
)
from adbygod_api.database import get_db, AsyncSessionLocal
from adbygod_api.models import Assessment, JobOutput, OffensiveJob, OffensiveJobStatus, PlatformUser
from adbygod_api.routes.auth import get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/arsenal", tags=["arsenal"])

# Keep strong references to fire-and-forget tasks so the GC doesn't collect them
# before they finish. Callbacks remove the entry on completion.
_background_tasks: set[asyncio.Task] = set()

def _fire_task(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _background_tasks.add(t)
    t.add_done_callback(_background_tasks.discard)
    return t

# In-memory run store (job_id → {status, results, queue})
# Also persisted to OffensiveJob/JobOutput tables for durability across restarts.
_runs: dict[str, dict[str, Any]] = {}
_RUN_TTL_SECONDS = 3600
_RUN_ACTIVE_TTL_SECONDS = 14400
_FAILED_VERDICTS = {"ERROR", "TIMEOUT"}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _cleanup_runs(now: datetime | None = None) -> None:
    """Bound the in-memory SSE run registry without touching durable DB jobs."""
    current = now or _utcnow()
    expired: list[str] = []
    for job_id, run in list(_runs.items()):
        created_at = run.get("created_at")
        finished_at = run.get("finished_at")
        if isinstance(finished_at, datetime):
            age = (current - finished_at).total_seconds()
            if age > _RUN_TTL_SECONDS:
                expired.append(job_id)
        elif isinstance(created_at, datetime):
            age = (current - created_at).total_seconds()
            if age > _RUN_ACTIVE_TTL_SECONDS:
                expired.append(job_id)

    for job_id in expired:
        _runs.pop(job_id, None)


def _arsenal_key(index: int, cve: dict[str, Any]) -> str:
    return f"{cve['id']}#{index}"


def _with_arsenal_key(index: int, cve: dict[str, Any]) -> dict[str, Any]:
    return {**cve, "arsenal_key": _arsenal_key(index, cve)}


def _resolve_cve(ref: str) -> tuple[int, dict[str, Any]] | None:
    """Resolve either a plain CVE id or the per-row arsenal_key exposed by /cves."""
    if "#" in ref:
        cve_id, index_str = ref.rsplit("#", 1)
        if index_str.isdigit():
            index = int(index_str)
            if 0 <= index < len(CVE_DATABASE) and CVE_DATABASE[index]["id"] == cve_id:
                return index, CVE_DATABASE[index]

    for index, cve in enumerate(CVE_DATABASE):
        if cve["id"] == ref:
            return index, cve
    return None


# ── DTOs ──────────────────────────────────────────────────────────────────

class CheckRequest(BaseModel):
    cve_id: str
    params: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=60, ge=1, le=900)


class BatchCheckRequest(BaseModel):
    cve_ids: list[str] = Field(min_length=1, max_length=100)
    params: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=60, ge=1, le=900)


async def _persist_output(job_id: uuid.UUID, line: str, stream: str = "stdout") -> None:
    try:
        async with AsyncSessionLocal() as db:
            db.add(JobOutput(job_id=job_id, stream=stream, line=line))
            await db.commit()
    except Exception:
        pass  # output persistence is best-effort; never block the SSE stream


def _queue_put_lossy(queue: asyncio.Queue, item: dict | None) -> None:
    try:
        queue.put_nowait(item)
    except asyncio.QueueFull:
        pass


def _queue_close(queue: asyncio.Queue) -> None:
    try:
        queue.put_nowait(None)
        return
    except asyncio.QueueFull:
        pass

    # Drop one buffered line so a completion sentinel can still be delivered.
    # Without this, a saturated stream can leave the SSE endpoint hanging forever.
    try:
        queue.get_nowait()
    except asyncio.QueueEmpty:
        pass

    try:
        queue.put_nowait(None)
    except asyncio.QueueFull:
        pass


def _ensure_arsenal_execution_allowed(cves: list[dict[str, Any]], current_user: PlatformUser) -> None:
    if not current_user.is_superadmin:
        raise HTTPException(status_code=403, detail="Superadmin access required")
    if not settings.ENABLE_COMMAND_EXECUTION:
        raise HTTPException(status_code=403, detail="Command execution is disabled by default")

    allowlist = settings.command_execution_allowlist
    blocked = sorted({
        str(cve.get("technique_id", "")).strip()
        for cve in cves
        if not str(cve.get("technique_id", "")).strip()
        or str(cve.get("technique_id", "")).strip() not in allowlist
    })
    if blocked:
        visible = ", ".join(item or "<missing-technique>" for item in blocked)
        raise HTTPException(
            status_code=403,
            detail=f"Technique is not allowlisted for execution: {visible}",
        )


# ── LIST / FILTER ─────────────────────────────────────────────────────────

@router.get("/cves")
async def list_cves(
    severity: str | None = Query(None),
    category: str | None = Query(None),
    search: str | None = Query(None),
    poc_only: bool = Query(False),
    _: PlatformUser = Depends(get_current_user),
):
    cves = list(enumerate(CVE_DATABASE))
    if severity:
        cves = [(i, c) for i, c in cves if c["severity"].upper() == severity.upper()]
    if category:
        cves = [(i, c) for i, c in cves if c["category"].lower() == category.lower()]
    if search:
        q = search.lower()
        cves = [(i, c) for i, c in cves if q in c["id"].lower() or q in c["name"].lower()
                or q in c.get("description","").lower() or any(q in t for t in c.get("tags",[]))]
    if poc_only:
        cves = [(i, c) for i, c in cves if c.get("poc_available")]
    cves.sort(key=lambda item: (SEVERITY_ORDER.get(item[1]["severity"], 9), item[1]["id"], item[0]))
    return {"cves": [_with_arsenal_key(i, c) for i, c in cves], "total": len(cves)}


@router.get("/cves/{cve_id}")
async def get_cve_detail(
    cve_id: str,
    _: PlatformUser = Depends(get_current_user),
):
    resolved = _resolve_cve(cve_id)
    if not resolved:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    index, cve = resolved
    return _with_arsenal_key(index, cve)


@router.get("/target-from-assessment/{assessment_id}")
async def target_from_assessment(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Extract reusable target params from an existing assessment."""
    import uuid as _uuid
    try:
        aid = _uuid.UUID(assessment_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid assessment ID") from exc
    asmt = await require_assessment_access(aid, db, current_user, include_collection_config=True)
    cfg = asmt.collection_config or {}
    return {
        "domain": asmt.domain or "",
        "dc_ip": asmt.dc_ip or "",
        "target": asmt.dc_ip or "",
        "dc_name": cfg.get("dc_name", "") or cfg.get("domain_controller", ""),
        "username": cfg.get("username", "") or cfg.get("user", ""),
        "exchange_host": cfg.get("exchange_host", "") or cfg.get("exchange", ""),
        "ca_host": cfg.get("ca_host", "") or cfg.get("ca", ""),
        "attacker_ip": cfg.get("attacker_ip", "") or cfg.get("lhost", ""),
    }


@router.get("/assessments-list")
async def list_assessments_for_arsenal(
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Lightweight assessment list for target picker, scoped to the caller."""
    statement = select(Assessment).order_by(Assessment.created_at.desc()).limit(50)
    statement = await scope_assessment_query(statement, db, current_user)
    result = await db.execute(statement)
    rows = result.scalars().all()
    return [
        {"id": str(a.id), "name": a.name, "domain": a.domain, "dc_ip": a.dc_ip or ""}
        for a in rows
    ]


@router.get("/stats")
async def arsenal_stats(_: PlatformUser = Depends(get_current_user)):
    return {"stats": get_stats(), "categories": get_categories()}


# ── SINGLE CHECK ──────────────────────────────────────────────────────────

@router.post("/check", status_code=status.HTTP_202_ACCEPTED)
async def run_single_check(
    req: CheckRequest,
    current_user: PlatformUser = Depends(get_current_user),
):
    _cleanup_runs()
    resolved = _resolve_cve(req.cve_id)
    if not resolved:
        raise HTTPException(status_code=404, detail=f"CVE {req.cve_id} not found")
    index, cve = resolved
    _ensure_arsenal_execution_allowed([cve], current_user)
    arsenal_key = _arsenal_key(index, cve)

    job_id = str(uuid.uuid4())
    queue: asyncio.Queue[dict | None] = asyncio.Queue(maxsize=512)
    _runs[job_id] = {
        "status": "RUNNING",
        "cve_id": cve["id"],
        "arsenal_key": arsenal_key,
        "queue": queue,
        "results": [],
        "owner_user_id": current_user.id,
        "created_at": _utcnow(),
        "finished_at": None,
    }

    # Persist the job record so it survives a restart.
    db_job_id = uuid.UUID(job_id)
    async with AsyncSessionLocal() as db:
        db.add(OffensiveJob(
            id=db_job_id,
            technique_id=cve.get("technique_id") or cve["id"],
            target=cve["id"],
            params={},
            executor="arsenal",
            status=OffensiveJobStatus.RUNNING,
            owner_user_id=current_user.id,
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
        ))
        await db.commit()

    async def _run():
        def emit(line: str, kind: str = "output"):
            msg = {"line": line, "type": kind, "ts": _utcnow().isoformat()}
            _queue_put_lossy(queue, msg)
            _fire_task(_persist_output(db_job_id, line, kind))

        verdict = "ERROR"
        try:
            verdict = await run_check(cve, req.params, emit, req.timeout)
        except Exception:
            log.exception("Arsenal single-check runner crashed for %s", arsenal_key)
            emit("Unexpected arsenal check failure; see server logs.", "stderr")

        result = {
            "cve_id": cve["id"],
            "arsenal_key": arsenal_key,
            "verdict": verdict,
            "name": cve["name"],
            "severity": cve["severity"],
        }
        final_status = OffensiveJobStatus.COMPLETED if verdict not in _FAILED_VERDICTS else OffensiveJobStatus.FAILED
        try:
            async with AsyncSessionLocal() as db:
                job_row = await db.get(OffensiveJob, db_job_id)
                if job_row:
                    job_row.status = final_status
                    job_row.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                    job_row.exit_code = 0 if final_status == OffensiveJobStatus.COMPLETED else 1
                await db.commit()
        except Exception:
            log.exception("Failed to persist arsenal single-check completion for %s", arsenal_key)
        finally:
            run = _runs.get(job_id)
            if run is not None:
                run["status"] = verdict
                run["results"].append(result)
                run["finished_at"] = _utcnow()
            _queue_close(queue)

    _fire_task(_run())
    return {"job_id": job_id, "cve_id": cve["id"], "arsenal_key": arsenal_key, "status": "RUNNING"}


# ── BATCH CHECK ───────────────────────────────────────────────────────────

@router.post("/check-batch", status_code=status.HTTP_202_ACCEPTED)
async def run_batch_check(
    req: BatchCheckRequest,
    current_user: PlatformUser = Depends(get_current_user),
):
    _cleanup_runs()
    resolved_items = [(cid, _resolve_cve(cid)) for cid in req.cve_ids]
    missing = [cid for cid, resolved in resolved_items if not resolved]
    if missing:
        raise HTTPException(status_code=404, detail=f"CVEs not found: {missing}")

    _ensure_arsenal_execution_allowed([resolved[1] for _ref, resolved in resolved_items if resolved], current_user)

    job_id = str(uuid.uuid4())
    queue: asyncio.Queue[dict | None] = asyncio.Queue(maxsize=2048)
    _runs[job_id] = {
        "status": "RUNNING",
        "batch": True,
        "total": len(req.cve_ids),
        "queue": queue,
        "results": [],
        "owner_user_id": current_user.id,
        "created_at": _utcnow(),
        "finished_at": None,
    }

    db_job_id = uuid.UUID(job_id)
    first_cve_ids = ",".join(req.cve_ids[:5])
    async with AsyncSessionLocal() as db:
        db.add(OffensiveJob(
            id=db_job_id,
            technique_id="batch",
            target=first_cve_ids,
            params={"cve_ids": req.cve_ids},
            executor="arsenal",
            status=OffensiveJobStatus.RUNNING,
            owner_user_id=current_user.id,
            started_at=datetime.now(timezone.utc).replace(tzinfo=None),
        ))
        await db.commit()

    async def _run_batch():
        had_failure = False
        try:
            for ref, resolved in resolved_items:
                if not resolved:
                    continue
                index, cve = resolved
                cve_id = cve["id"]
                arsenal_key = _arsenal_key(index, cve)

                def emit(line: str, kind: str = "output", _cid: str = cve_id):
                    msg = {"line": line, "type": kind, "cve_id": _cid, "ts": _utcnow().isoformat()}
                    _queue_put_lossy(queue, msg)
                    _fire_task(_persist_output(db_job_id, line, kind))

                sep_msg = {"line": f"━━━ [{cve_id}] {cve['name']} ━━━", "type": "header", "cve_id": cve_id, "ts": _utcnow().isoformat()}
                _queue_put_lossy(queue, sep_msg)

                try:
                    verdict = await run_check(cve, req.params, emit, req.timeout)
                except Exception:
                    log.exception("Arsenal batch-check runner crashed for %s", arsenal_key)
                    emit("Unexpected arsenal check failure; see server logs.", "stderr")
                    verdict = "ERROR"

                if verdict in _FAILED_VERDICTS:
                    had_failure = True

                run = _runs.get(job_id)
                if run is not None:
                    run["results"].append({
                        "cve_id": cve_id,
                        "arsenal_key": arsenal_key,
                        "request_id": ref,
                        "verdict": verdict,
                        "name": cve["name"],
                        "severity": cve["severity"],
                    })
        except Exception:
            had_failure = True
            log.exception("Arsenal batch runner aborted unexpectedly")
            _queue_put_lossy(queue, {
                "line": "Unexpected arsenal batch failure; see server logs.",
                "type": "stderr",
                "ts": _utcnow().isoformat(),
            })
        finally:
            status_label = "FAILED" if had_failure else "DONE"
            final_status = OffensiveJobStatus.FAILED if had_failure else OffensiveJobStatus.COMPLETED
            try:
                async with AsyncSessionLocal() as db:
                    job_row = await db.get(OffensiveJob, db_job_id)
                    if job_row:
                        job_row.status = final_status
                        job_row.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                        job_row.exit_code = 1 if had_failure else 0
                    await db.commit()
            except Exception:
                log.exception("Failed to persist arsenal batch completion for %s", job_id)
            finally:
                run = _runs.get(job_id)
                if run is not None:
                    run["status"] = status_label
                    run["finished_at"] = _utcnow()
                _queue_close(queue)

    _fire_task(_run_batch())
    return {"job_id": job_id, "total": len(req.cve_ids), "status": "RUNNING"}


# ── SSE STREAM ────────────────────────────────────────────────────────────

@router.get("/stream/{job_id}")
async def stream_job(
    job_id: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    _cleanup_runs()
    run = _runs.get(job_id)
    if not run:
        raise HTTPException(status_code=404, detail="Job not found")
    if not current_user.is_superadmin and run.get("owner_user_id") != current_user.id:
        raise HTTPException(status_code=403, detail="Arsenal job access denied")

    async def event_gen():
        queue: asyncio.Queue = run["queue"]
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30)
            except asyncio.TimeoutError:
                yield {"event": "ping", "data": ""}
                continue
            if msg is None:
                yield {"event": "done", "data": json.dumps({"results": run.get("results", [])})}
                break
            yield {"event": "line", "data": json.dumps(msg)}

    return EventSourceResponse(event_gen())


@router.get("/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    _cleanup_runs()
    run = _runs.get(job_id)
    if run:
        if not current_user.is_superadmin and run.get("owner_user_id") != current_user.id:
            raise HTTPException(status_code=403, detail="Arsenal job access denied")
        return {
            "job_id": job_id,
            "status": run["status"],
            "results": run.get("results", []),
            "total": run.get("total"),
        }

    # Fall back to DB — job may have been created in a previous server instance.
    try:
        db_job_id = uuid.UUID(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Job not found") from exc

    job_row = await db.get(OffensiveJob, db_job_id)
    if not job_row:
        raise HTTPException(status_code=404, detail="Job not found")
    if not current_user.is_superadmin and job_row.owner_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Arsenal job access denied")

    output_rows = (
        await db.execute(
            select(JobOutput).where(JobOutput.job_id == db_job_id).order_by(JobOutput.ts)
        )
    ).scalars().all()

    return {
        "job_id": job_id,
        "status": job_row.status.value if hasattr(job_row.status, "value") else str(job_row.status),
        "results": [{"cve_id": job_row.target, "verdict": job_row.status.value}] if job_row.exit_code is not None else [],
        "total": None,
        "output_lines": [r.line for r in output_rows],
        "started_at": job_row.started_at.isoformat() if job_row.started_at else None,
        "completed_at": job_row.completed_at.isoformat() if job_row.completed_at else None,
    }
