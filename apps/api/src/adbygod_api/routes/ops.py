from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.config import settings
from adbygod_api.core.streaming import subscribe_lines
from adbygod_api.core.tasks.offensive_jobs import run_offensive_job as _celery_run_job
from adbygod_api.database import AsyncSessionLocal, get_db
from adbygod_api.models import (
    JobOutput, OffensiveJob, OffensiveJobStatus, OpsecProfile, PlatformUser,
)
from adbygod_api.routes.auth import get_current_user, _get_user_cached
from adbygod_api.core.security.authorization import require_assessment_write_access, require_superadmin

log = logging.getLogger(__name__)

router = APIRouter(prefix="/ops", tags=["ops"])


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _get_redis():
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


TECHNIQUE_EXECUTOR = {
    # recon
    "echo_test":           "impacket",
    "ldap_enum":           "impacket",
    "smb_enum":            "impacket",
    "rpcdump":             "impacket",
    "nmap_scan":           "impacket",
    "lookupsid":           "impacket",
    "samrdump":            "impacket",
    "netview":             "impacket",
    "find_delegation":     "impacket",
    "user_enum":           "impacket",
    "acl_enum":            "impacket",
    "delegation_enum":     "impacket",
    "gpo_enum":            "impacket",
    # kerberos
    "kerberoast":          "impacket",
    "asreproast":          "impacket",
    "getnpusers":          "impacket",
    "getuserspns":         "impacket",
    "getTGT":              "impacket",
    "getst":               "impacket",
    "ticketer":            "impacket",
    "rubeus_monitor":      "impacket",
    # credential access
    "dcsync":              "impacket",
    "secretsdump":         "impacket",
    "reg_query":           "impacket",
    "laps_dump":           "impacket",
    "gmsa_dump":           "impacket",
    # lateral movement / exec
    "smbexec":             "impacket",
    "wmiexec":             "impacket",
    "atexec":              "impacket",
    "psexec":              "impacket",
    # coercion / relay
    "coerce":              "impacket",
    "ntlmrelayx":          "impacket",
    "ntlmrelayx_adcs":     "impacket",
    # persistence / account ops
    "addcomputer":         "impacket",
    "changepasswd":        "impacket",
    "renamemachine":       "impacket",
    "password_reset":      "impacket",
    # acl / object abuse
    "dacledit":            "impacket",
    "rbcd_write":          "impacket",
    "whisker":             "impacket",
    # certificate services
    "certipy_find":        "impacket",
    "certipy_req":         "impacket",
    "certipy_auth":        "impacket",
    "certipy_template":    "impacket",
    # group policy
    "gpo_inject":          "impacket",
    # sccm
    "sccm_enum":           "impacket",
    "sccm_naa":            "impacket",
    # cve exploits
    "zerologon":           "impacket",
    "zerologon_restore":   "impacket",
    # service enum
    "services_enum":       "impacket",
    # attack chain
    "password_spray":      "impacket",
    "password_spray_smb":  "impacket",
    "manual_crack":        "impacket",
    # network posture checks
    "smb_signing_check":   "impacket",
    "llmnr_nbtns_check":   "impacket",
    "ntlm_config_check":   "impacket",
    "ldap_signing_check":  "impacket",
    "winrm_check":         "impacket",
    "open_shares_check":   "impacket",
    "cred_manager_check":  "impacket",
    "kerberoast_spn_enum": "impacket",
    # credential dump
    "cred_dump_lsass":      "impacket",
    "cred_dump_ntds_vss":   "impacket",
    "cred_dump_secretsdump":"impacket",
    "dpapi_backup_key":     "impacket",
    "dpapi_sharpdpapi":     "impacket",
    # PKI / certificate attacks
    "certipy_ca_backup":    "impacket",
    "certipy_forge":        "impacket",
    "certipy_unpac":        "impacket",
    "passthe_cert":         "impacket",
    # WMI / COM persistence
    "wmi_subscription":     "impacket",
    "com_hijack":           "impacket",
    "dcom_exec":            "impacket",
    # cloud assessment
    "cloud_entra_enum":     "impacket",
    "cloud_adfs_enum":      "impacket",
    "cloud_m365_enum":      "impacket",
}


class ExecuteRequest(BaseModel):
    technique_id: str
    target: str
    params: dict[str, Any] = Field(default_factory=dict)
    opsec_profile: OpsecProfile = OpsecProfile.BALANCED
    assessment_id: UUID | None = None
    # OBFSC pipeline config — forwarded to ImpacketWorker
    obfuscation_enabled: bool = False
    obfuscation_technique: int | str = "auto"


class JobOut(BaseModel):
    id: UUID
    technique_id: str
    target: str
    executor: str
    opsec_profile: str
    status: str
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    exit_code: int | None


def _job_to_out(j: OffensiveJob) -> JobOut:
    return JobOut(
        id=j.id,
        technique_id=j.technique_id,
        target=j.target,
        executor=j.executor,
        opsec_profile=j.opsec_profile.value if hasattr(j.opsec_profile, "value") else j.opsec_profile,
        status=j.status.value if hasattr(j.status, "value") else j.status,
        created_at=j.created_at,
        started_at=j.started_at,
        completed_at=j.completed_at,
        exit_code=j.exit_code,
    )


@router.post("/execute", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
async def execute_technique(
    req: ExecuteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    # Keep the legacy ops executor under the same safety gates as
    # /ad-commands/execute/{technique_id}. Otherwise any authenticated user
    # can bypass the global kill switch and technique allowlist.
    await require_superadmin(current_user)
    if not settings.ENABLE_COMMAND_EXECUTION:
        raise HTTPException(status_code=403, detail="Command execution is disabled by default")
    if req.technique_id not in settings.command_execution_allowlist:
        raise HTTPException(status_code=403, detail="Technique is not allowlisted for execution")
    if req.assessment_id is not None:
        await require_assessment_write_access(req.assessment_id, db, current_user)

    executor_name = TECHNIQUE_EXECUTOR.get(req.technique_id)
    if not executor_name:
        raise HTTPException(status_code=400, detail=f"Unknown technique: {req.technique_id}")

    from adbygod_api.core.connectivity.transport import resolve_transport as _resolve_transport
    _proxy = None
    if req.assessment_id is not None:
        from adbygod_api.models import Assessment as _Asmt, ConnectivityProfile as _CP
        _asmt = await db.get(_Asmt, req.assessment_id)
        if _asmt and _asmt.connectivity_profile_id:
            _cp = await db.get(_CP, _asmt.connectivity_profile_id)
            if not _cp:
                raise HTTPException(status_code=409, detail="Configured connectivity profile no longer exists")
            try:
                await _resolve_transport(_cp, db)
            except RuntimeError as exc:
                raise HTTPException(status_code=409, detail=f"Connectivity transport unavailable: {exc}") from exc

    job = OffensiveJob(
        id=uuid.uuid4(),
        assessment_id=req.assessment_id,
        technique_id=req.technique_id,
        target=req.target,
        params={
            **req.params,
            "technique": req.technique_id,
            "target": req.target,
            "obfuscation_enabled": req.obfuscation_enabled,
            "obfuscation_technique": req.obfuscation_technique,
        },
        executor=executor_name,
        opsec_profile=req.opsec_profile,
        status=OffensiveJobStatus.PENDING,
        owner_user_id=current_user.id,
        created_at=_utcnow(),
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    job_id_str = str(job.id)

    # Dispatch to Celery worker.  The worker process handles execution,
    # DB status updates, and Redis pub/sub streaming.
    try:
        celery_task = _celery_run_job.delay(
            job_id_str,
            executor_name,
            str(req.assessment_id) if req.assessment_id else None,
        )
        # Store Celery task ID in Redis so kill_job can revoke it.
        redis = _get_redis()
        try:
            await redis.setex(f"job:{job_id_str}:celery_task_id", 86400, celery_task.id)
        finally:
            await redis.aclose()
    except Exception as exc:
        job.status = OffensiveJobStatus.FAILED
        job.completed_at = _utcnow()
        job.exit_code = -1
        await db.commit()
        raise HTTPException(status_code=503, detail="Job queue unavailable; ensure Celery worker is running") from exc

    return _job_to_out(job)


@router.get("/jobs", response_model=list[JobOut])
async def list_jobs(
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    q = select(OffensiveJob).order_by(desc(OffensiveJob.created_at)).limit(limit)
    if not current_user.is_superadmin:
        q = q.where(OffensiveJob.owner_user_id == current_user.id)
    rows = (await db.execute(q)).scalars().all()
    return [_job_to_out(j) for j in rows]


@router.get("/jobs/{job_id}", response_model=JobOut)
async def get_job(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    job = await db.get(OffensiveJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not current_user.is_superadmin and job.owner_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return _job_to_out(job)


@router.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def kill_job(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    job = await db.get(OffensiveJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not current_user.is_superadmin and job.owner_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")

    # Revoke the Celery task if we have its ID.
    redis = _get_redis()
    try:
        celery_task_id = await redis.get(f"job:{job_id}:celery_task_id")
    finally:
        await redis.aclose()
    if celery_task_id:
        try:
            from adbygod_api.core.celery_app import celery_app as _celery
            _celery.control.revoke(celery_task_id, terminate=True, signal="SIGTERM")
        except Exception:
            log.warning("Failed to revoke Celery task %s for job %s", celery_task_id, job_id)

    if job.status in (OffensiveJobStatus.RUNNING, OffensiveJobStatus.PENDING):
        job.status = OffensiveJobStatus.KILLED
        job.completed_at = _utcnow()
        job.exit_code = -1
        await db.commit()


@router.get("/jobs/{job_id}/output")
async def get_job_output(
    job_id: UUID,
    limit: int = Query(500, ge=1, le=2000),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    job = await db.get(OffensiveJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if not current_user.is_superadmin and job.owner_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")

    rows = (await db.execute(
        select(JobOutput)
        .where(JobOutput.job_id == job_id)
        .order_by(JobOutput.ts)
        .limit(limit)
    )).scalars().all()

    return [{"stream": r.stream, "line": r.line, "ts": r.ts.isoformat()} for r in rows]


@router.websocket("/ws/jobs/{job_id}")
async def job_output_ws(
    websocket: WebSocket,
    job_id: str,
):
    """WebSocket endpoint — streams job output lines in real-time.
    Requires authentication via HttpOnly session cookie.
    """
    # Must accept() BEFORE sending close frames — the ASGI spec
    # requires the handshake to complete before any control frames are sent.
    # Origin check is done post-accept and we close immediately if rejected.
    await websocket.accept()

    origin = websocket.headers.get("origin")
    if origin:
        from adbygod_api.routes.auth import _origin_allowed
        if not _origin_allowed(origin):
            await websocket.send_json({"error": "Origin not allowed", "code": 403})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    # Authentication — cookie only; query-token param removed (P1-6)
    final_token = websocket.cookies.get(settings.AUTH_COOKIE_NAME)
    if not final_token:
        await websocket.send_json({"error": "Unauthorized", "code": 401})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    async with AsyncSessionLocal() as db:
        try:
            user = await _get_user_cached(final_token, db)
        except Exception:
            await websocket.send_json({"error": "Invalid token", "code": 401})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        # Validate job_id is a valid UUID before passing to db.get()
        try:
            job_uuid = UUID(job_id)
        except ValueError:
            await websocket.send_json({"error": "Invalid job ID", "code": 400})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        job = await db.get(OffensiveJob, job_uuid)
        if not job:
            await websocket.send_json({"error": "Job not found", "code": 404})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        if not user.is_superadmin and job.owner_user_id != user.id:
            await websocket.send_json({"error": "Forbidden", "code": 403})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    redis = _get_redis()
    try:
        async for data in subscribe_lines(redis, job_id):
            await websocket.send_json(data)
            if data.get("done") or data.get("error"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await redis.aclose()
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass


import json as _json  # noqa: E402


class TargetProfileSchema(BaseModel):
    target: str = ""
    domain: str = ""
    username: str = ""
    password: str = ""
    dc_ip: str = ""


def _profile_key(user_id) -> str:
    return f"user:{user_id}:ops_target_profile"


@router.get("/profile", response_model=TargetProfileSchema)
async def get_ops_profile(
    current_user: PlatformUser = Depends(get_current_user),
):
    redis = _get_redis()
    try:
        raw = await redis.get(_profile_key(current_user.id))
        if raw:
            return TargetProfileSchema(**_json.loads(raw))
        return TargetProfileSchema()
    finally:
        await redis.aclose()


@router.put("/profile", response_model=TargetProfileSchema)
async def save_ops_profile(
    profile: TargetProfileSchema,
    current_user: PlatformUser = Depends(get_current_user),
):
    redis = _get_redis()
    try:
        await redis.set(_profile_key(current_user.id), _json.dumps(profile.model_dump()))
        return profile
    finally:
        await redis.aclose()
