from __future__ import annotations

import asyncio
import io
import json
import logging
import zipfile
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.database import get_db, AsyncSessionLocal
from adbygod_api.models import Assessment, AssessmentStatus, CollectionMode, PlatformUser
from adbygod_api.schemas import CollectorIngest
from adbygod_api.core.parsers.bloodhound import BloodHoundParser
from adbygod_api.core.security.authorization import require_assessment_access, require_assessment_write_access, require_workspace_write_access
from adbygod_api.core.analyzers.collector_analyzer import build_rule_data_from_collector
from adbygod_api.routes.auth import get_current_user
from adbygod_api.routes.ingest import _process_ingest, _utcnow_naive
from adbygod_api.routes.jobs import create_job, create_stream_token, emit


log = logging.getLogger(__name__)
router = APIRouter(prefix="/import", tags=["import"])

_BH_PARSE_TIMEOUT = 120  # seconds


async def _parse_bloodhound_in_thread(parser_fn, *args):
    """Run a synchronous BloodHound parse in a thread with a timeout."""
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1) as pool:
        return await asyncio.wait_for(
            loop.run_in_executor(pool, parser_fn, *args),
            timeout=_BH_PARSE_TIMEOUT,
        )

MAX_UPLOAD_BYTES = 256 * 1024 * 1024  # 256 MB


def _payload_has_importable_bloodhound_data(payload_dict: dict) -> bool:
    """Reject wrapper/empty archives that parse but contain no usable SharpHound payload."""
    return any(
        bool(payload_dict.get(key))
        for key in ("entities", "edges", "evidence", "cert_templates", "findings")
    )


class _SystemSuperadmin:
    # add all attributes that authorization helpers may access to
    # prevent AttributeError when this sentinel is used as a fake current_user
    id = UUID("00000000-0000-0000-0000-000000000001")
    is_superadmin = True
    is_active = True
    username = "__system__"
    email = "__system__@internal"


async def _set_assessment_failed(assessment_id: UUID, error_message: str):
    async with AsyncSessionLocal() as db:
        assessment = await require_assessment_access(assessment_id, db, _SystemSuperadmin())
        assessment.status = AssessmentStatus.FAILED
        assessment.error_message = error_message
        await db.commit()


async def _mark_assessment_running(assessment_id: UUID, modules_run: list[str]):
    async with AsyncSessionLocal() as db:
        assessment = await require_assessment_access(assessment_id, db, _SystemSuperadmin())
        if assessment.status == AssessmentStatus.COMPLETED:
            raise RuntimeError("Assessment already completed")
        assessment.status = AssessmentStatus.RUNNING
        if assessment.started_at is None:
            assessment.started_at = _utcnow_naive()
        assessment.modules_run = modules_run
        assessment.error_message = None
        await db.commit()


async def _run_import(job_id: str, assessment_id: UUID, data: bytes, filename: str):
    """
    Background: parse BloodHound file → build CollectorIngest → run ingest pipeline.
    Emits progress events to the SSE job queue throughout.
    """
    try:
        await emit(job_id, {"phase": "parse", "message": f"Parsing {filename}…", "pct": 5})

        parser = BloodHoundParser()
        try:
            if filename.lower().endswith(".zip"):
                payload_dict = await _parse_bloodhound_in_thread(parser.parse_zip, data)
            else:
                payload_dict = await _parse_bloodhound_in_thread(parser.parse_json, data)
        except asyncio.TimeoutError:
            raise RuntimeError("BloodHound parse timed out — file may be too complex")
        except ValueError as exc:
            raise RuntimeError(str(exc))

        if not _payload_has_importable_bloodhound_data(payload_dict):
            message = "Import archive contained no recognized BloodHound/SharpHound data payloads"
            await _set_assessment_failed(assessment_id, message)
            await emit(job_id, {"error": message, "message": "Import failed", "done": True})
            return

        entity_count = len(payload_dict.get("entities", []))
        edge_count = len(payload_dict.get("edges", []))
        await emit(job_id, {
            "phase": "parse",
            "message": f"Parsed {entity_count} entities, {edge_count} edges",
            "pct": 25,
        })

        try:
            payload = CollectorIngest(**payload_dict)
        except Exception as exc:
            message = f"Schema validation failed: {exc}"
            await _set_assessment_failed(assessment_id, message)
            await emit(job_id, {"error": message, "done": True})
            return

        await _mark_assessment_running(assessment_id, payload.modules_run or ["BloodHound Import"])
        await emit(job_id, {"phase": "ingest", "message": "Writing to database…", "pct": 35})
        await emit(job_id, {"phase": "ingest", "message": "Running rule engine…", "pct": 50})

        ingest_ok = await _process_ingest(assessment_id=assessment_id, payload=payload, job_id=job_id)
        if not ingest_ok:
            message = "Import parsed, but ingest failed while writing assessment data"
            await emit(job_id, {"error": message, "message": "Import failed", "done": True})
            return

        # Sync operator session so the top bar reflects the active target
        try:
            from adbygod_api.core.session.manager import get_or_create_session
            async with AsyncSessionLocal() as db:
                assessment = await require_assessment_access(assessment_id, db, _SystemSuperadmin())
                user_id = assessment.created_by
                if user_id:
                    session = await get_or_create_session(db, user_id, assessment_id=assessment_id)
                    changed = False
                    if not session.domain and assessment.domain:
                        session.domain = assessment.domain
                        changed = True
                    if not session.target_ip and assessment.dc_ip:
                        session.target_ip = assessment.dc_ip
                        changed = True
                    if changed:
                        from datetime import datetime, timezone as _tz
                        session.updated_at = datetime.now(_tz.utc).replace(tzinfo=None)
                        await db.commit()
        except Exception as _exc:
            log.warning("Session sync after import failed (non-fatal): %s", _exc)

        await emit(job_id, {
            "phase": "complete",
            "message": "Import complete — graph ready",
            "pct": 100,
            "status": "COMPLETED",
            "done": True,
        })
        log.info("BloodHound import complete", extra={"job_id": job_id, "assessment_id": str(assessment_id)})
        try:
            from adbygod_api.core.graph.websocket_manager import broadcast_graph_delta
            await broadcast_graph_delta(str(assessment_id), entity_count=entity_count, edge_count=edge_count)
        except Exception:
            pass

    except Exception as exc:
        log.error("BloodHound import failed", exc_info=True, extra={"job_id": job_id, "assessment_id": str(assessment_id)})
        try:
            await _set_assessment_failed(assessment_id, str(exc))
        except Exception:
            log.warning("Failed to mark import assessment as failed", exc_info=True)
        await emit(job_id, {
            "error": str(exc),
            "message": "Import failed",
            "done": True,
        })


_ZIP_MAX_MEMBERS = 256
_ZIP_MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024  # 256 MB
_ZIP_MAX_RATIO = 100  # reject if any member expands > 100× its compressed size
_RAW_PREVIEW_CHARS = 2048
_NESTED_ARCHIVE_SUFFIXES = (".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz")


def _summarize_module_outputs(module_data: dict[str, dict]) -> dict[str, dict]:
    summaries: dict[str, dict] = {}
    for module_id, module in module_data.items():
        commands = list(module.get("commands") or [])
        output_chars = 0
        previews: list[dict] = []
        for command in commands:
            output = str(command.get("output") or "")
            output_chars += len(output)
            previews.append(
                {
                    "command": str(command.get("command") or "")[:512],
                    "exit_code": command.get("exit_code"),
                    "output_preview": output[:_RAW_PREVIEW_CHARS],
                    "output_truncated": len(output) > _RAW_PREVIEW_CHARS,
                    "output_chars": len(output),
                }
            )
        summaries[module_id] = {
            "command_count": len(commands),
            "output_chars": output_chars,
            "commands": previews[:25],
            "commands_truncated": len(previews) > 25,
        }
    return summaries


def _parse_collector_zip(data: bytes) -> tuple[dict, dict[str, dict]]:
    """
    Parse an AdByGod native collector zip.
    Returns (manifest_dict, {module_id: module_dict}).
    Raises ValueError on invalid/missing data.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:
        raise ValueError(f"Cannot open zip: {exc}") from exc

    members = zf.infolist()
    if len(members) > _ZIP_MAX_MEMBERS:
        raise ValueError(f"ZIP contains too many members ({len(members)} > {_ZIP_MAX_MEMBERS})")

    total_uncompressed = sum(m.file_size for m in members)
    if total_uncompressed > _ZIP_MAX_UNCOMPRESSED_BYTES:
        raise ValueError(
            f"ZIP total uncompressed size {total_uncompressed} exceeds limit {_ZIP_MAX_UNCOMPRESSED_BYTES}"
        )

    for m in members:
        normalized_name = m.filename.replace("\\", "/")
        parts = [part for part in normalized_name.split("/") if part]
        if m.filename.startswith(("/", "\\")) or ".." in parts:
            raise ValueError(f"ZIP member {m.filename!r} uses an unsafe path")
        if normalized_name.lower().endswith(_NESTED_ARCHIVE_SUFFIXES):
            raise ValueError(f"Nested archive member {m.filename!r} is not supported")
        if m.compress_size == 0 and m.file_size > 0:
            raise ValueError(
                f"ZIP member {m.filename!r} has zero compressed size but non-zero "
                f"uncompressed size ({m.file_size}) — malformed entry rejected"
            )
        if m.compress_size > 0 and m.file_size / m.compress_size > _ZIP_MAX_RATIO:
            raise ValueError(
                f"ZIP member {m.filename!r} has suspicious compression ratio "
                f"({m.file_size}/{m.compress_size})"
            )

    if "manifest.json" not in zf.namelist():
        raise ValueError("Missing manifest.json — not an AdByGod collector zip")

    try:
        manifest = json.loads(zf.read("manifest.json"))
    except Exception as exc:
        raise ValueError(f"Invalid manifest.json: {exc}") from exc

    if manifest.get("generator") != "AdByGod-Native-Collector":
        raise ValueError(
            f"Not an AdByGod-Native-Collector zip (generator={manifest.get('generator')!r})"
        )

    modules: dict[str, dict] = {}
    for name in zf.namelist():
        if name.endswith(".json") and name != "manifest.json":
            basename = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if basename != name:
                continue  # reject path-traversal entries
            module_id = basename.removesuffix(".json")
            try:
                modules[module_id] = json.loads(zf.read(name))
            except Exception:
                log.warning("Skipping malformed module JSON: %s", name)

    return manifest, modules


def _collector_rule_data_to_ingest(
    manifest: dict,
    module_ids: list[str],
    rule_data: dict,
) -> CollectorIngest:
    # Materialize native collector analysis into the standard ingest payload.
    domain_info = dict(rule_data.get("domain_info") or {})
    domain = str(
        manifest.get("domain")
        or domain_info.get("dns_root")
        or domain_info.get("domain")
        or "unknown"
    )
    metadata = {
        "domain_info": domain_info,
        "password_policy": dict(rule_data.get("password_policy") or {}),
        "trusts": list(rule_data.get("trusts") or []),
        "network_config": dict(rule_data.get("network_config") or {}),
    }
    return CollectorIngest(
        schema_version="4.0",
        tool="AdByG0d Native Collector",
        collection_mode=CollectionMode.WINDOWS_LOCAL.value,
        domain=domain,
        dc_ip=manifest.get("dc_ip") or None,
        collected_at=str(manifest.get("collected_at") or "imported"),
        collector_version=str(
            manifest.get("collector_version")
            or manifest.get("version")
            or "native-collector/unknown"
        ),
        modules_run=module_ids,
        entities=list(rule_data.get("entities") or []),
        edges=list(rule_data.get("edges") or []),
        evidence=list(rule_data.get("evidence") or []),
        findings=list(rule_data.get("findings") or []),
        cert_templates=list(rule_data.get("cert_templates") or []),
        ca_flags=list(rule_data.get("ca_flags") or []),
        metadata=metadata,
    )


async def _run_collector_import(
    job_id: str,
    assessment_id: UUID,
    manifest: dict,
    module_data: dict[str, dict],
) -> None:
    try:
        module_ids = list(module_data.keys())
        cmd_count = sum(len(m.get("commands", [])) for m in module_data.values())

        await emit(job_id, {
            "phase": "parse",
            "message": f"Loaded {len(module_ids)} modules, {cmd_count} command results",
            "pct": 30,
        })

        async with AsyncSessionLocal() as db:
            assessment = await require_assessment_access(
                assessment_id,
                db,
                _SystemSuperadmin(),
                include_collection_config=True,
            )
            assessment.status = AssessmentStatus.RUNNING
            assessment.started_at = _utcnow_naive()
            assessment.modules_run = module_ids
            await db.commit()

        await emit(job_id, {"phase": "ingest", "message": "Parsing command outputs…", "pct": 50})

        rule_data = await asyncio.to_thread(build_rule_data_from_collector, module_data)
        payload = _collector_rule_data_to_ingest(manifest, module_ids, rule_data)

        async with AsyncSessionLocal() as db:
            assessment = await require_assessment_access(
                assessment_id, db, _SystemSuperadmin(),
                include_collection_config=True,
            )
            cfg = dict(assessment.collection_config or {})
            cfg["native_collector"] = True
            cfg["module_output_summary"] = _summarize_module_outputs(module_data)
            cfg["parsed_collector_summary"] = {
                "entities": len(payload.entities),
                "edges": len(payload.edges),
                "cert_templates": len(payload.cert_templates),
                "ca_flags": len(payload.ca_flags),
            }
            assessment.collection_config = cfg
            await db.commit()

        await emit(job_id, {
            "phase": "ingest",
            "message": (
                f"Materializing {len(payload.entities)} entities, "
                f"{len(payload.edges)} edges, and running analysis…"
            ),
            "pct": 65,
        })

        ingest_ok = await _process_ingest(assessment_id=assessment_id, payload=payload, job_id=job_id)
        if not ingest_ok:
            message = "Collector ZIP parsed, but ingest failed while writing assessment data"
            await emit(job_id, {"error": message, "message": "Import failed", "done": True})
            return

        # Sync operator session so the top bar reflects the active target
        try:
            from adbygod_api.core.session.manager import get_or_create_session
            async with AsyncSessionLocal() as db:
                assessment = await require_assessment_access(assessment_id, db, _SystemSuperadmin())
                user_id = assessment.created_by
                if user_id:
                    session = await get_or_create_session(db, user_id, assessment_id=assessment_id)
                    changed = False
                    if not session.domain and assessment.domain:
                        session.domain = assessment.domain
                        changed = True
                    if not session.target_ip and assessment.dc_ip:
                        session.target_ip = assessment.dc_ip
                        changed = True
                    if changed:
                        from datetime import datetime, timezone as _tz
                        session.updated_at = datetime.now(_tz.utc).replace(tzinfo=None)
                        await db.commit()
        except Exception as _exc:
            log.warning("Session sync after import failed (non-fatal): %s", _exc)

        await emit(job_id, {
            "phase": "complete",
            "message": (
                f"Imported {len(module_ids)} modules — "
                f"{len(payload.entities)} entities and {len(payload.edges)} edges materialized"
            ),
            "pct": 100,
            "status": "COMPLETED",
            "done": True,
        })
        log.info(
            "Collector import complete",
            extra={"job_id": job_id, "assessment_id": str(assessment_id)},
        )

    except Exception as exc:
        log.error("Collector import failed", exc_info=True)
        try:
            await _set_assessment_failed(assessment_id, str(exc))
        except Exception:
            pass
        await emit(job_id, {"error": str(exc), "message": "Import failed", "done": True})


@router.post("/collector-zip")
async def import_collector_zip(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """
    Upload an AdByGod native collector zip produced by Invoke-AdByGodCollector.ps1.
    Auto-creates a WINDOWS_LOCAL assessment and queues background ingestion.
    Returns {job_id, stream_token, assessment_id} compatible with the existing import store.
    """
    fname = file.filename or "collector.zip"
    if not fname.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files accepted")

    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds 256 MB limit")

    try:
        manifest, module_data = _parse_collector_zip(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    workspace_id = await require_workspace_write_access(None, db, current_user)

    domain = manifest.get("domain", "unknown")
    dc_ip  = manifest.get("dc_ip", "")
    collected_at = manifest.get("collected_at", "")

    assessment = Assessment(
        name=f"Windows Local — {domain}",
        domain=domain,
        dc_ip=dc_ip or None,
        collection_mode=CollectionMode.WINDOWS_LOCAL,
        workspace_id=workspace_id,
        created_by=current_user.id,
        status=AssessmentStatus.PENDING,
        modules_run=[],
        collection_config={
            "modules": manifest.get("modules", []),
            "collected_at": collected_at,
            "native_collector": True,
        },
    )
    db.add(assessment)
    await db.commit()
    await db.refresh(assessment)

    job_id = str(uuid4())
    create_job(job_id, current_user.id)
    stream_token = create_stream_token(job_id, current_user.id)

    background_tasks.add_task(
        _run_collector_import,
        job_id=job_id,
        assessment_id=assessment.id,
        manifest=manifest,
        module_data=module_data,
    )

    return {
        "job_id": job_id,
        "stream_token": stream_token,
        "assessment_id": str(assessment.id),
        "filename": fname,
        "message": "Assessment created and collector import queued",
    }


@router.post("/bloodhound/auto")
async def import_bloodhound_auto(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """
    Upload a BloodHound/SharpHound ZIP or JSON export without requiring a
    pre-existing assessment. Auto-creates a PENDING assessment, then ingests.
    """
    fname = file.filename or ""
    if not (fname.lower().endswith(".zip") or fname.lower().endswith(".json")):
        raise HTTPException(
            status_code=400,
            detail="Only .zip and .json BloodHound exports are accepted",
        )

    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds 256 MB limit")

    workspace_id = await require_workspace_write_access(None, db, current_user)

    # Native collector zips may be renamed before upload. Detect by manifest
    # server-side instead of relying on the UI filename heuristic.
    if fname.lower().endswith(".zip"):
        try:
            manifest, module_data = _parse_collector_zip(data)
        except ValueError:
            manifest = None
            module_data = None
        if manifest is not None and module_data is not None:
            native_domain = manifest.get("domain", "unknown")
            native_dc_ip = manifest.get("dc_ip", "")
            native_collected_at = manifest.get("collected_at", "")
            native_assessment = Assessment(
                name=f"Windows Local — {native_domain}",
                domain=native_domain,
                dc_ip=native_dc_ip or None,
                collection_mode=CollectionMode.WINDOWS_LOCAL,
                workspace_id=workspace_id,
                created_by=current_user.id,
                status=AssessmentStatus.PENDING,
                modules_run=[],
                collection_config={
                    "modules": manifest.get("modules", []),
                    "collected_at": native_collected_at,
                    "native_collector": True,
                    "auto_detected": True,
                },
            )
            db.add(native_assessment)
            await db.commit()
            await db.refresh(native_assessment)

            job_id = str(uuid4())
            create_job(job_id, current_user.id)
            stream_token = create_stream_token(job_id, current_user.id)
            background_tasks.add_task(
                _run_collector_import,
                job_id=job_id,
                assessment_id=native_assessment.id,
                manifest=manifest,
                module_data=module_data,
            )
            return {
                "job_id": job_id,
                "stream_token": stream_token,
                "assessment_id": str(native_assessment.id),
                "filename": fname,
                "message": "Native collector zip detected and import queued",
            }

    import_name = fname.removesuffix(".zip").removesuffix(".json")
    assessment = Assessment(
        name=f"BloodHound Import — {import_name}",
        domain="imported",
        collection_mode=CollectionMode.IMPORT,
        workspace_id=workspace_id,
        created_by=current_user.id,
        status=AssessmentStatus.PENDING,
        modules_run=[],
    )
    db.add(assessment)
    await db.commit()
    await db.refresh(assessment)

    job_id = str(uuid4())
    create_job(job_id, current_user.id)
    stream_token = create_stream_token(job_id, current_user.id)

    background_tasks.add_task(
        _run_import,
        job_id=job_id,
        assessment_id=assessment.id,
        data=data,
        filename=fname,
    )

    return {
        "job_id": job_id,
        "stream_token": stream_token,
        "assessment_id": str(assessment.id),
        "filename": fname,
        "message": "Assessment created and import queued",
    }


@router.post("/{assessment_id}/bloodhound")
async def import_bloodhound(
    assessment_id: UUID,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """
    Upload a BloodHound/SharpHound ZIP or JSON export and ingest it into
    the specified assessment. Returns a job_id plus a signed stream token.
    """
    await require_assessment_write_access(assessment_id, db, current_user)

    fname = file.filename or ""
    if not (fname.lower().endswith(".zip") or fname.lower().endswith(".json")):
        raise HTTPException(
            status_code=400,
            detail="Only .zip and .json BloodHound exports are accepted",
        )

    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds 256 MB limit")

    # Reserve the assessment before queueing the background job so concurrent
    # upload requests cannot both enqueue work for the same assessment.
    from sqlalchemy import select as _select
    locked_result = await db.execute(
        _select(Assessment).where(Assessment.id == assessment_id).with_for_update()
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

    background_tasks.add_task(
        _run_import,
        job_id=job_id,
        assessment_id=assessment_id,
        data=data,
        filename=fname,
    )

    return {
        "job_id": job_id,
        "stream_token": stream_token,
        "assessment_id": str(assessment_id),
        "filename": fname,
        "message": "Import queued — connect to /api/v1/jobs/stream/{job_id}?token=<stream_token> for progress",
    }
