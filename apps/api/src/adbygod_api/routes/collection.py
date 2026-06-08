from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.database import get_db
from adbygod_api.models import Assessment, AssessmentStatus, PlatformUser
from adbygod_api.schemas import CollectorIngest
from adbygod_api.core.collection.ldap_collector import LDAPCollector
from adbygod_api.core.connectivity.resolved_connection import resolve_connection
from adbygod_api.core.security.authorization import require_assessment_access, require_assessment_write_access
from adbygod_api.core.pipeline import CommandPlan
from adbygod_api.routes.auth import get_current_user
from adbygod_api.routes.ingest import _process_ingest, _utcnow_naive
from adbygod_api.routes.jobs import create_job, create_stream_token, emit

log = logging.getLogger(__name__)
router = APIRouter(prefix="/collection", tags=["collection"])
PROXIED_COLLECTION_LOCK = asyncio.Lock()


class LDAPCollectionRequest(BaseModel):
    dc_ip: str = Field(..., min_length=1, max_length=253, description="Domain controller IP or hostname")
    domain: str = Field(..., min_length=1, max_length=253, description="Fully qualified domain name (e.g. corp.local)")
    username: str = Field(..., min_length=1, max_length=256, description="Username for LDAP bind (SAMAccountName or UPN)")
    password: str = Field("", max_length=512, description="Account password or NTLM hash (LM:NT format)")
    auth_method: Literal["NTLM", "SIMPLE", "ANONYMOUS"] = Field("NTLM", description="NTLM | SIMPLE | ANONYMOUS")
    use_ssl: bool = Field(False, description="Connect via LDAPS (port 636)")
    port: int = Field(389, ge=1, le=65535, description="LDAP port (389 or 636)")
    enum_adcs: bool = Field(True, description="Include AD CS / certificate template enumeration")
    enum_trusts: bool = Field(True, description="Include domain trust enumeration")
    enum_gpos: bool = Field(True, description="Include GPO enumeration")
    enum_acls: bool = Field(True, description="Enumerate DACLs for ACL abuse edges (DCSync, GenericAll, etc.)")
    enum_gpo_acls: bool = Field(True, description="Parse gPLink to emit APPLIES_GPO edges")
    scan_sysvol: bool = Field(False, description="Scan SYSVOL for GPP cpassword exposure (requires SMB)")
    check_adcs_web: bool = Field(True, description="Check whether AD CS Web Enrollment endpoints exist")
    check_esc6: bool = Field(True, description="Check ESC6 CA policy flags when the collector supports a safe read path")
    acl_include_inherited: bool = Field(True, description="Include inherited ACEs in ACL analysis")
    acl_max_objects: int = Field(5000, ge=1, le=50000, description="Max LDAP objects to scan for DACLs")
    # ── OBFSC pipeline config ─────────────────────────────────────────
    obfuscation_enabled: bool = Field(False, description="Enable remote collection obfuscation")
    obfuscation_technique: int | str = Field("auto", description="Technique id 0-13 or 'auto'")
    opsec_jitter_ms: int = Field(0, ge=0, le=10000, description="Random inter-step jitter 0-N ms (0=disabled)")
    opsec_shuffle_attrs: bool = Field(False, description="Randomise LDAP attribute ordering for OPSEC")

    @field_validator("domain", mode="before")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        domain = str(value or "").strip().lower()
        if not domain or domain.startswith(".") or domain.endswith(".") or ".." in domain:
            raise ValueError("domain must be a valid DNS name without leading, trailing, or repeated dots")
        labels = domain.split(".")
        if any(not label or len(label) > 63 for label in labels):
            raise ValueError("domain contains an invalid DNS label")
        return domain

    @field_validator("dc_ip", "username", mode="before")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        return str(value or "").strip()

    @model_validator(mode="after")
    def require_password_for_authenticated_bind(self) -> "LDAPCollectionRequest":
        if self.auth_method in {"NTLM", "SIMPLE"} and not self.password:
            raise ValueError("password is required for NTLM and SIMPLE authentication")
        return self


class _SystemSuperadmin:
    id = UUID("00000000-0000-0000-0000-000000000001")
    is_superadmin = True
    is_active = True
    username = "__system__"
    email = "__system__@internal"


async def _set_assessment_status(assessment_id: UUID, status: AssessmentStatus, progress_pct: int | None = None, last_message: str | None = None, **kwargs):
    from adbygod_api.database import AsyncSessionLocal
    from adbygod_api.routes.ingest import _utcnow_naive

    async with AsyncSessionLocal() as db:
        assessment = await require_assessment_access(assessment_id, db, _SystemSuperadmin())
        if status == AssessmentStatus.RUNNING and assessment.status != AssessmentStatus.RUNNING:
            assessment.started_at = _utcnow_naive()
            assessment.error_message = None

        assessment.status = status
        if progress_pct is not None:
            assessment.progress_pct = progress_pct
        if last_message is not None:
            assessment.last_message = last_message

        for k, v in kwargs.items():
            setattr(assessment, k, v)
        await db.commit()


async def _run_collection(job_id: str, assessment_id: UUID, req: LDAPCollectionRequest):
    loop = asyncio.get_running_loop()

    def progress_cb(message: str, pct: int, level: str = "INFO") -> None:
        try:
            # Emit SSE event
            future_sse = asyncio.run_coroutine_threadsafe(
                emit(job_id, {"phase": "collect", "message": message, "pct": pct, "level": level}),
                loop,
            )
            # Log callback failures so progress drops are visible.
            def _log_exc(f, tag):
                if f.cancelled():
                    log.debug("Progress callback [%s] cancelled", tag)
                    return
                exc = f.exception()
                if exc:
                    log.warning("Progress callback [%s] failed: %s", tag, exc)
            future_sse.add_done_callback(lambda f: _log_exc(f, "sse"))

            future_db = asyncio.run_coroutine_threadsafe(
                _set_assessment_status(assessment_id, AssessmentStatus.RUNNING, progress_pct=pct, last_message=message),
                loop,
            )
            future_db.add_done_callback(lambda f: _log_exc(f, "db"))
        except RuntimeError:
            log.debug("Progress callback dropped — event loop gone")

    try:
        await _set_assessment_status(assessment_id, AssessmentStatus.RUNNING)

        # ── Build pipeline config ─────────────────────────────────────
        # Remote LDAP Collection / Directory Inventory uses ldap3, not PowerShell.
        # When OBFSC is toggled, force LDAP-level OPSEC so it changes actual
        # remote query shape/timing instead of only lighting up the UI.
        effective_shuffle_attrs = req.opsec_shuffle_attrs or req.obfuscation_enabled
        effective_jitter_ms = req.opsec_jitter_ms if req.opsec_jitter_ms > 0 else (250 if req.obfuscation_enabled else 0)
        plan = CommandPlan(
            assessment_id=str(assessment_id),
            operation="ldap_collection",
            obfuscation_enabled=req.obfuscation_enabled,
            obfuscation_technique=req.obfuscation_technique,
            opsec_jitter_ms=effective_jitter_ms,
            opsec_shuffle_attrs=effective_shuffle_attrs,
        )

        if req.obfuscation_enabled:
            await emit(job_id, {
                "phase": "pipeline",
                "message": f"[OBFSC] remote LDAP obfuscation active — technique={req.obfuscation_technique} attr_shuffle={effective_shuffle_attrs} jitter={effective_jitter_ms}ms",
                "pct": 1, "level": "INFO",
            })

        await emit(job_id, {"phase": "connect", "message": f"Connecting to {req.dc_ip} ({req.auth_method})…", "pct": 2, "level": "INFO"})

        from adbygod_api.core.connectivity.transport import resolve_transport
        proxy_transport = None
        resolved_dc_ip = req.dc_ip
        resolved_domain = req.domain
        from adbygod_api.database import AsyncSessionLocal as _ASL
        from adbygod_api.models import Assessment as _Asmt, ConnectivityProfile as _CP
        async with _ASL() as _db:
            _asmt = await _db.get(_Asmt, assessment_id)
            if _asmt and getattr(_asmt, "connectivity_profile_id", None):
                _cp = await _db.get(_CP, _asmt.connectivity_profile_id)
                if not _cp:
                    raise RuntimeError("Configured connectivity profile no longer exists")
                resolved = resolve_connection(_asmt, _cp)
                resolved_dc_ip = resolved.dc_ip or resolved.dc_hostname or req.dc_ip
                resolved_domain = resolved.domain or req.domain
                try:
                    proxy_transport = await resolve_transport(_cp, _db)
                except RuntimeError as exc:
                    raise RuntimeError(f"Connectivity transport unavailable: {exc}") from exc

        collector = LDAPCollector(
            dc_ip=resolved_dc_ip, domain=resolved_domain, username=req.username, password=req.password,
            auth_method=req.auth_method, use_ssl=req.use_ssl, port=req.port,
            enum_adcs=req.enum_adcs, enum_trusts=req.enum_trusts, enum_gpos=req.enum_gpos,
            enum_acls=req.enum_acls, enum_gpo_acls=req.enum_gpo_acls, scan_sysvol=req.scan_sysvol,
            check_adcs_web=req.check_adcs_web, check_esc6=req.check_esc6,
            acl_include_inherited=req.acl_include_inherited, acl_max_objects=req.acl_max_objects,
            pipeline_plan=plan,
            proxy_transport=proxy_transport,
        )
        collector.set_progress_callback(progress_cb)
        proxied = bool(proxy_transport and proxy_transport.proxy_url)
        if proxied:
            await emit(job_id, {"phase": "connectivity", "message": "Serializing proxied collection for SOCKS isolation", "pct": 2, "level": "INFO"})
        lock_ctx = PROXIED_COLLECTION_LOCK if proxied else contextlib.nullcontext()
        async with lock_ctx:
            payload_dict = await collector.collect()

        entity_count = len(payload_dict.get("entities", []))
        edge_count = len(payload_dict.get("edges", []))

        if entity_count == 0:
            msg = "Collection returned 0 entities. Check connectivity, credentials, and Base DN."
            await _set_assessment_status(assessment_id, AssessmentStatus.FAILED, error_message=msg)
            await emit(job_id, {"error": msg, "message": "Collection failed", "done": True})
            return

        await emit(job_id, {"phase": "collect", "message": f"Collected {entity_count} entities, {edge_count} edges — writing…", "pct": 70, "level": "INFO"})

        try:
            payload = CollectorIngest(**payload_dict)
        except Exception as exc:
            await _set_assessment_status(assessment_id, AssessmentStatus.FAILED, error_message=f"Payload validation failed: {exc}")
            await emit(job_id, {"error": f"Payload validation failed: {exc}", "message": "Collection failed", "done": True})
            return

        await emit(job_id, {"phase": "ingest", "message": "Running ingest, rules, and scoring…", "pct": 82, "level": "INFO"})
        await _process_ingest(assessment_id=assessment_id, payload=payload, job_id=job_id)
        await _set_assessment_status(assessment_id, AssessmentStatus.COMPLETED, progress_pct=100, last_message="Collection and analysis complete")
        await emit(job_id, {"phase": "complete", "message": "Collection and analysis complete", "pct": 100, "status": "COMPLETED", "done": True})
        log.info("LDAP collection complete", extra={"job_id": job_id, "assessment_id": str(assessment_id)})

    except Exception as exc:
        log.error("Collection failed", exc_info=True, extra={"job_id": job_id, "assessment_id": str(assessment_id)})
        try:
            await _set_assessment_status(assessment_id, AssessmentStatus.FAILED, error_message=str(exc))
        except Exception:
            log.warning("Failed to mark collection assessment as failed", exc_info=True)
        await emit(job_id, {"error": str(exc), "message": "Collection failed", "done": True})


@router.post("/ldap/{assessment_id}", status_code=status.HTTP_202_ACCEPTED)
async def run_ldap_collection(
    assessment_id: UUID,
    req: LDAPCollectionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_assessment_write_access(assessment_id, db, current_user)

    locked_result = await db.execute(
        select(Assessment).where(Assessment.id == assessment_id).with_for_update()
    )
    assessment = locked_result.scalars().first()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    if assessment.status in (AssessmentStatus.RUNNING, AssessmentStatus.COMPLETED):
        raise HTTPException(status_code=409, detail="Assessment already running or completed")
    assessment.status = AssessmentStatus.RUNNING
    assessment.started_at = assessment.started_at or _utcnow_naive()
    assessment.error_message = None
    await db.commit()

    job_id = str(uuid4())
    create_job(job_id, current_user.id)
    stream_token = create_stream_token(job_id, current_user.id)
    background_tasks.add_task(_run_collection, job_id=job_id, assessment_id=assessment_id, req=req)

    return {
        "job_id": job_id,
        "stream_token": stream_token,
        "assessment_id": str(assessment_id),
        "target": f"{req.dc_ip} / {req.domain}",
        "auth_method": req.auth_method,
        "message": "Collection queued — connect to /api/v1/jobs/stream/{job_id}?token=<stream_token> for progress",
    }


@router.get("/capabilities")
async def collection_capabilities():
    return {
        "auth_methods": ["NTLM", "SIMPLE", "ANONYMOUS"],
        "object_types": ["users", "computers", "groups", "domain_policy", "trusts", "gpos", "adcs", "ous", "acls", "sysvol"],
        "detections": [
            "AS-REP roastable accounts",
            "Kerberoastable accounts",
            "Unconstrained delegation (computers)",
            "Constrained delegation with SPN targets",
            "RBCD configuration",
            "LAPS deployment status",
            "Admin count accounts",
            "Disabled accounts",
            "Password not required flag",
            "Protected Users membership",
            "ESC1 / ESC2 / ESC3 vulnerable cert templates",
            "ESC4 dangerous certificate template ACLs",
            "ESC8 AD CS Web Enrollment endpoint exposure",
            "ESC6 CA SAN policy flag coverage when supported by collector mode",
            "Domain trust SID filtering status",
            "GPO inheritance / linkage",
            "Core AD TCP service exposure",
            "WinRM exposure from the scanner host",
            "Fast exposure quick-check module coverage",
        ],
        "max_upload_mb": 256,
    }
