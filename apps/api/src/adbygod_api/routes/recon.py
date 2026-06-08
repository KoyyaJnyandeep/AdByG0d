from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status as ws_status
from pydantic import BaseModel, Field

from adbygod_api.models import ReconScan, ReconScanStatus, PlatformUser
from adbygod_api.database import AsyncSessionLocal
from adbygod_api.routes.auth import get_current_user
from adbygod_api.core.security.authorization import (
    require_superadmin,
    require_assessment_access,
    scope_assessment_child_query,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/recon", tags=["recon"])


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ScanRequest(BaseModel):
    assessment_id: str | None = None
    target_dc_ip: str = Field(..., min_length=4, max_length=50)
    domain: str = Field(..., min_length=2, max_length=255)


class ScanFinding(BaseModel):
    type: str
    severity: str
    title: str
    detail: str
    finding_type: str
    mitre_id: str | None = None
    mitre_name: str | None = None
    tactic: str | None = None
    cvss: float | None = None


class ScanSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int


class ScanOut(BaseModel):
    scan_id: str
    assessment_id: str | None
    status: str
    target_dc_ip: str | None
    domain: str | None
    started_at: datetime | None
    completed_at: datetime | None
    findings: list[ScanFinding]
    summary: ScanSummary


@router.post("/scan", response_model=dict)
async def start_recon_scan(
    body: ScanRequest,
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_superadmin(current_user)
    scan_id = uuid.uuid4()
    try:
        assessment_uuid = uuid.UUID(body.assessment_id) if body.assessment_id else None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid assessment_id UUID") from exc
    scan = ReconScan(
        id=scan_id,
        assessment_id=assessment_uuid,
        target_dc_ip=body.target_dc_ip,
        domain=body.domain,
        status=ReconScanStatus.QUEUED,
        created_at=_utcnow(),
    )
    async with AsyncSessionLocal() as db:
        db.add(scan)
        await db.commit()

    from adbygod_api.core.recon.recon_engine import run_recon_scan
    run_recon_scan.apply_async(args=[str(scan_id)], queue="recon_jobs")

    log.info("Recon scan %s enqueued for %s", scan_id, body.target_dc_ip)
    return {"scan_id": str(scan_id), "status": "queued"}


@router.get("/scan/{scan_id}", response_model=ScanOut)
async def get_recon_scan(
    scan_id: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid scan_id UUID") from exc
    async with AsyncSessionLocal() as db:
        scan = await db.get(ReconScan, scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    # Scope: only superadmins and users with assessment access may read a scan.
    if not current_user.is_superadmin:
        if scan.assessment_id is None:
            raise HTTPException(status_code=403, detail="Access denied: scan is not linked to an assessment")
        async with AsyncSessionLocal() as db:
            await require_assessment_access(scan.assessment_id, db, current_user)
    findings_raw = scan.findings or []
    findings = [
        ScanFinding(**{k: v for k, v in f.items() if k != "raw"})
        for f in findings_raw
        if isinstance(f, dict) and all(k in f for k in ("type", "severity", "title", "detail", "finding_type"))
    ]
    summary_raw = scan.summary or {}
    status_val = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
    return ScanOut(
        scan_id=str(scan.id),
        assessment_id=str(scan.assessment_id) if scan.assessment_id else None,
        status=status_val,
        target_dc_ip=scan.target_dc_ip,
        domain=scan.domain,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        findings=findings,
        summary=ScanSummary(**{k: summary_raw.get(k, 0) for k in ("total", "critical", "high", "medium", "low")}),
    )


@router.websocket("/ws/scan/{scan_id}")
async def recon_scan_ws(websocket: WebSocket, scan_id: str):
    """Stream recon scan output lines via WebSocket (mirrors /ops/ws/jobs but for ReconScan)."""
    await websocket.accept()

    origin = websocket.headers.get("origin")
    if origin:
        from adbygod_api.routes.auth import _origin_allowed
        if not _origin_allowed(origin):
            await websocket.send_json({"error": "Origin not allowed", "code": 403})
            await websocket.close(code=ws_status.WS_1008_POLICY_VIOLATION)
            return

    from adbygod_api.config import settings
    final_token = websocket.cookies.get(settings.AUTH_COOKIE_NAME)
    if not final_token:
        await websocket.send_json({"error": "Unauthorized", "code": 401})
        await websocket.close(code=ws_status.WS_1008_POLICY_VIOLATION)
        return

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        await websocket.send_json({"error": "Invalid scan ID", "code": 400})
        await websocket.close(code=ws_status.WS_1008_POLICY_VIOLATION)
        return

    async with AsyncSessionLocal() as db:
        from adbygod_api.routes.auth import _get_user_cached
        try:
            user = await _get_user_cached(final_token, db)
        except Exception:
            await websocket.send_json({"error": "Invalid token", "code": 401})
            await websocket.close(code=ws_status.WS_1008_POLICY_VIOLATION)
            return

        scan = await db.get(ReconScan, scan_uuid)
        if not scan:
            await websocket.send_json({"error": "Scan not found", "code": 404})
            await websocket.close(code=ws_status.WS_1008_POLICY_VIOLATION)
            return

        if not user.is_superadmin:
            if scan.assessment_id is None:
                await websocket.send_json({"error": "Forbidden", "code": 403})
                await websocket.close(code=ws_status.WS_1008_POLICY_VIOLATION)
                return
            try:
                await require_assessment_access(scan.assessment_id, db, user)
            except HTTPException:
                await websocket.send_json({"error": "Forbidden", "code": 403})
                await websocket.close(code=ws_status.WS_1008_POLICY_VIOLATION)
                return

    import redis.asyncio as aioredis
    from adbygod_api.config import settings as _s
    from adbygod_api.core.streaming import subscribe_lines, get_stored_lines

    redis_client = aioredis.from_url(_s.REDIS_URL, decode_responses=True)
    try:
        scan_status = scan.status.value if hasattr(scan.status, "value") else str(scan.status)
        stored = await get_stored_lines(redis_client, scan_id)

        if scan_status == "completed":
            # Scan already done — replay all stored lines then signal done.
            for data in stored:
                await websocket.send_json(data)
            if not any(d.get("done") for d in stored):
                await websocket.send_json({"done": True, "exit_code": 0})
        else:
            # Scan is running/queued — replay buffered lines first, then
            # subscribe to pub/sub for the remainder. We subscribe BEFORE
            # replaying stored lines to avoid missing messages published
            # in the gap between the two.
            pubsub_gen = subscribe_lines(redis_client, scan_id)

            # Replay already-stored lines (skip the trailing "done" if present)
            for data in stored:
                if data.get("done"):
                    continue
                await websocket.send_json(data)

            # Stream live from pub/sub
            try:
                async for data in pubsub_gen:
                    await websocket.send_json(data)
                    if data.get("done") or data.get("error"):
                        break
            except WebSocketDisconnect:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        try:
            await redis_client.aclose()
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass


@router.get("/scan/{scan_id}/output")
async def get_recon_scan_output(
    scan_id: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return stored output lines for a completed recon scan (fallback for LiveOutputTerminal)."""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid scan_id UUID") from exc

    async with AsyncSessionLocal() as db:
        scan = await db.get(ReconScan, scan_uuid)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not current_user.is_superadmin:
        if scan.assessment_id is None:
            raise HTTPException(status_code=403, detail="Access denied")
        async with AsyncSessionLocal() as db:
            await require_assessment_access(scan.assessment_id, db, current_user)

    import redis.asyncio as aioredis
    from adbygod_api.config import settings as _s
    from adbygod_api.core.streaming import get_stored_lines

    redis_client = aioredis.from_url(_s.REDIS_URL, decode_responses=True)
    try:
        lines = await get_stored_lines(redis_client, scan_id)
    finally:
        await redis_client.aclose()

    return [
        {"stream": d.get("stream", "stdout"), "line": d.get("line", ""), "ts": ""}
        for d in lines
        if d.get("line") is not None
    ]


@router.get("/scans", response_model=list[dict])
async def list_recon_scans(
    assessment_id: str | None = None,
    current_user: PlatformUser = Depends(get_current_user),
):
    from sqlalchemy import select
    async with AsyncSessionLocal() as db:
        if assessment_id:
            # Verify the caller has access to this specific assessment.
            try:
                assessment_uuid = uuid.UUID(assessment_id)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail="Invalid assessment_id UUID") from exc
            await require_assessment_access(assessment_uuid, db, current_user)
            q = (
                select(ReconScan)
                .where(ReconScan.assessment_id == assessment_uuid)
                .order_by(ReconScan.created_at.desc())
                .limit(50)
            )
        else:
            # Scope the list to scans belonging to assessments the user can access.
            q = select(ReconScan).order_by(ReconScan.created_at.desc()).limit(50)
            q = await scope_assessment_child_query(
                q, ReconScan.assessment_id, db, current_user
            )
        result = await db.execute(q)
        scans = result.scalars().all()
    return [
        {
            "scan_id": str(s.id),
            "assessment_id": str(s.assessment_id) if s.assessment_id else None,
            "status": s.status.value if hasattr(s.status, "value") else str(s.status),
            "domain": s.domain,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "findings_count": len(s.findings or []),
            "summary": s.summary or {},
        }
        for s in scans
    ]
