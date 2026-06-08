from __future__ import annotations

import copy
import ipaddress
import logging
import re
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from adbygod_api.config import settings
from adbygod_api.core.connectivity.process_manager import get_chisel_manager, get_ligolo_manager
from adbygod_api.core.connectivity.ssh_tunnel import get_ssh_manager, is_local_tcp_listener, start_tunnel
from adbygod_api.core.connectivity.probe import multi_probe
from adbygod_api.core.connectivity.transport import resolve_transport
from adbygod_api.database import get_db
from adbygod_api.models import Assessment, AuditLog, ConnectivityMode, ConnectivityProfile, ConnectivityProfileStatus, PlatformUser, TunnelSession, TunnelSessionStatus
from adbygod_api.routes.auth import get_current_user
from adbygod_api.schemas import (
    ChiselServerStatus,
    ConnectivityProfileCreate,
    ConnectivityProfileOut,
    ConnectivityProfileUpdate,
    ConnectivityStats,
    ConnectivityTestResult,
    LigoloStatus,
    TunnelSessionOut,
    TunnelStartRequest,
)

log = logging.getLogger(__name__)
router = APIRouter(prefix="/connectivity", tags=["connectivity"])
REDACTED = "***REDACTED***"
SENSITIVE_CONFIG_KEYS = {"auth_token", "client_cmd", "server_pid", "ssh_key_path"}
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _require_tunnel_management(user: PlatformUser) -> None:
    """Raise 403 if tunnel management is disabled or user is not superadmin."""
    if not settings.ENABLE_TUNNEL_MANAGEMENT:
        raise HTTPException(
            status_code=403,
            detail="Tunnel management is disabled. Set ENABLE_TUNNEL_MANAGEMENT=true in server config.",
        )
    if not user.is_superadmin:
        raise HTTPException(status_code=403, detail="Tunnel management requires superadmin role.")


def _validate_cidr(cidr: str) -> None:
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid CIDR: {cidr!r}") from exc


def _validate_port(port: int, name: str = "port") -> None:
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=422, detail=f"Invalid {name}: must be 1-65535")


def _config_port(config: dict, key: str, default: int | None = None) -> int:
    value = config.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {key}: must be an integer") from exc


def _validate_host(value: str, name: str) -> None:
    if not value or not str(value).strip():
        raise HTTPException(status_code=422, detail=f"{name} is required")
    raw = str(value).strip()
    try:
        ipaddress.ip_address(raw)
        return
    except ValueError:
        pass
    if not HOSTNAME_RE.match(raw) or ".." in raw:
        raise HTTPException(status_code=422, detail=f"Invalid {name}: {raw!r}")


def _validate_optional_ip(value: object, name: str) -> None:
    if value in (None, ""):
        return
    try:
        ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {name}: {value!r}") from exc


def _validate_optional_host(value: object, name: str) -> None:
    if value in (None, ""):
        return
    _validate_host(str(value), name)


def _is_forbidden_nonadmin_probe_target(value: str) -> bool:
    raw = str(value or "").strip().lower().rstrip(".")
    if raw in {"localhost", "localhost.localdomain"} or raw.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified


def _validate_target_config(config: dict) -> None:
    _validate_optional_host(config.get("target_domain"), "target_domain")
    _validate_optional_ip(config.get("dc_ip"), "dc_ip")
    _validate_optional_host(config.get("dc_hostname"), "dc_hostname")
    _validate_optional_ip(config.get("dns_server"), "dns_server")
    subnets = config.get("target_subnets") or []
    if isinstance(subnets, str):
        subnets = [item.strip() for item in subnets.split(",") if item.strip()]
    if not isinstance(subnets, list):
        raise HTTPException(status_code=422, detail="target_subnets must be a list of CIDRs")
    for cidr in subnets:
        _validate_cidr(str(cidr))


def _validate_profile_config(mode: str, config: dict) -> None:
    _validate_target_config(config)
    if mode == "DIRECT":
        return
    if mode == "SOCKS5":
        _validate_host(str(config.get("proxy_host", "")), "proxy_host")
        _validate_port(_config_port(config, "proxy_port"), "proxy_port")
        return
    if mode == "CHISEL":
        _validate_port(_config_port(config, "server_port", 8080), "server_port")
        _validate_port(_config_port(config, "socks_port", 1080), "socks_port")
        return
    if mode == "LIGOLO":
        _validate_port(_config_port(config, "proxy_port", 11601), "proxy_port")
        if not str(config.get("tun_interface", "ligolo")).strip():
            raise HTTPException(status_code=422, detail="tun_interface is required")
        return
    if mode == "RELAY_AGENT":
        _validate_host(str(config.get("relay_host", "")), "relay_host")
        _validate_port(_config_port(config, "relay_port"), "relay_port")
        return
    if mode == "MANAGED_SSH_SOCKS":
        errs = _validate_managed_ssh_config(config)
        if errs:
            raise HTTPException(status_code=400, detail="; ".join(errs))
        return
    raise HTTPException(status_code=422, detail=f"Unsupported connectivity mode: {mode}")


def _validate_managed_ssh_config(config: dict) -> list[str]:
    """Returns list of validation error strings, empty if valid."""
    errors = []
    required = ["jumpbox_host", "jumpbox_port", "jumpbox_username"]
    for req_field in required:
        if config.get(req_field) is None or not str(config.get(req_field)).strip():
            errors.append(f"Missing required field: {req_field}")

    auth_method = str(config.get("auth_method", "ssh_key"))
    if auth_method not in {"ssh_key", "password_dev"}:
        errors.append("auth_method must be ssh_key or password_dev")
    username = str(config.get("jumpbox_username", ""))
    if username and any(ch in username for ch in ["@", " ", "\t", "\n", "\r"]):
        errors.append("jumpbox_username must not contain spaces, @, or control characters")

    port = config.get("jumpbox_port")
    if port is not None:
        try:
            p = int(port)
            if not (1 <= p <= 65535):
                errors.append("jumpbox_port must be 1–65535")
        except (TypeError, ValueError):
            errors.append("jumpbox_port must be an integer")
    host = config.get("jumpbox_host", "")
    if host:
        try:
            _validate_host(str(host), "jumpbox_host")
        except HTTPException as exc:
            errors.append(f"jumpbox_host: {exc.detail}")
    return errors


def _merge_config(existing: dict | None, incoming: dict | None) -> dict:
    merged = copy.deepcopy(existing or {})
    for key, value in (incoming or {}).items():
        if key in SENSITIVE_CONFIG_KEYS and value == REDACTED:
            continue
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def _is_allowed_probe_target(profile: ConnectivityProfile, target_host: str, user: PlatformUser) -> bool:
    if user.is_superadmin:
        return True
    config = profile.config or {}
    allowed = {str(config.get("dc_ip", "")).strip(), str(config.get("dc_hostname", "")).strip()}
    if target_host in {item for item in allowed if item}:
        return True
    try:
        target_ip = ipaddress.ip_address(target_host)
    except ValueError:
        return False
    for cidr in config.get("target_subnets") or []:
        try:
            if target_ip in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def _redact_profile(profile: ConnectivityProfile) -> dict:
    """Return profile as dict with sensitive config fields redacted."""
    d = {c.key: getattr(profile, c.key) for c in profile.__table__.columns}
    cfg = copy.deepcopy(d.get("config") or {})
    for key in SENSITIVE_CONFIG_KEYS:
        if key in cfg:
            cfg[key] = REDACTED
    d["config"] = cfg
    return d


async def _require_profile_access(
    profile_id: UUID,
    db: AsyncSession,
    user: PlatformUser,
) -> ConnectivityProfile:
    """Return a profile only when the current user owns it or is superadmin.

    Connectivity profiles are not workspace-scoped in the current schema, so
    ``created_by`` is the only durable ownership boundary available.  Legacy
    rows with ``created_by=NULL`` remain superadmin-only instead of becoming
    globally mutable infrastructure.
    """
    profile = await db.get(ConnectivityProfile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    if not user.is_superadmin and profile.created_by != user.id:
        raise HTTPException(status_code=403, detail="Connectivity profile access denied")
    return profile


def _same_owner_default_scope(profile: ConnectivityProfile):
    if profile.created_by is None:
        return ConnectivityProfile.id == profile.id
    return ConnectivityProfile.created_by == profile.created_by


async def _audit(db: AsyncSession, user: PlatformUser, action: str, resource_id: str, details: dict) -> None:
    log_entry = AuditLog(
        user_id=user.id,
        action=action,
        resource_type="connectivity_profile",
        resource_id=resource_id,
        details=details,
    )
    db.add(log_entry)
    # Do not commit here — caller commits


@router.get("/profiles", response_model=list[ConnectivityProfileOut])
async def list_profiles(
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    query = select(ConnectivityProfile).order_by(ConnectivityProfile.created_at.desc())
    if not user.is_superadmin:
        query = query.where(ConnectivityProfile.created_by == user.id)
    rows = await db.execute(query)
    return [_redact_profile(profile) for profile in rows.scalars().all()]


@router.get("/stats", response_model=ConnectivityStats)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    query = select(ConnectivityProfile)
    if not user.is_superadmin:
        query = query.where(ConnectivityProfile.created_by == user.id)
    rows = (await db.execute(query)).scalars().all()

    counts: dict[str, int] = {"ONLINE": 0, "OFFLINE": 0, "DEGRADED": 0, "UNKNOWN": 0}
    active_tunnels = 0
    latencies: list[int] = []
    total_open_ports = 0
    modes_used: set[str] = set()

    for p in rows:
        status_val = p.status.value if hasattr(p.status, "value") else str(p.status)
        counts[status_val] = counts.get(status_val, 0) + 1
        mode_val = p.mode.value if hasattr(p.mode, "value") else str(p.mode)
        modes_used.add(mode_val)
        if p.last_latency_ms is not None:
            latencies.append(p.last_latency_ms)
        cfg = p.config or {}
        open_ports = cfg.get("last_probe", {}).get("open_ports") or []
        total_open_ports += len(open_ports)
        if mode_val in ("CHISEL", "LIGOLO"):
            try:
                if mode_val == "CHISEL":
                    mgr = get_chisel_manager(str(p.id))
                else:
                    mgr = get_ligolo_manager(str(p.id))
                if mgr.running:
                    active_tunnels += 1
            except Exception:
                pass
        elif mode_val == "MANAGED_SSH_SOCKS":
            try:
                mgr = get_ssh_manager(str(p.id))
                if mgr.running:
                    active_tunnels += 1
            except Exception:
                pass

    return ConnectivityStats(
        total=len(rows),
        online=counts["ONLINE"],
        offline=counts["OFFLINE"],
        degraded=counts["DEGRADED"],
        unknown=counts["UNKNOWN"],
        active_tunnels=active_tunnels,
        best_latency_ms=min(latencies) if latencies else None,
        total_open_ports=total_open_ports,
        modes_used=sorted(modes_used),
    )


@router.post("/profiles", response_model=ConnectivityProfileOut, status_code=status.HTTP_201_CREATED)
async def create_profile(
    body: ConnectivityProfileCreate,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    config = dict(body.config or {})
    _validate_profile_config(body.mode.value, config)
    if body.is_default:
        await db.execute(
            update(ConnectivityProfile)
            .where(ConnectivityProfile.created_by == user.id)
            .values(is_default=False)
        )
    profile = ConnectivityProfile(
        name=body.name,
        mode=body.mode,
        config=config,
        is_default=body.is_default,
        notes=body.notes,
        created_by=user.id,
    )
    db.add(profile)
    await db.flush()  # get profile.id without committing
    await _audit(db, user, "connectivity.profile.create", str(profile.id), {"name": profile.name, "mode": profile.mode.value})
    await db.commit()
    await db.refresh(profile)
    return _redact_profile(profile)


@router.get("/profiles/{profile_id}", response_model=ConnectivityProfileOut)
async def get_profile(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    row = await _require_profile_access(profile_id, db, user)
    return _redact_profile(row)


@router.patch("/profiles/{profile_id}", response_model=ConnectivityProfileOut)
async def update_profile(
    profile_id: UUID,
    body: ConnectivityProfileUpdate,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    profile = await _require_profile_access(profile_id, db, user)
    if body.name is not None:
        profile.name = body.name
    if body.config is not None:
        profile.config = _merge_config(profile.config, body.config)
        _validate_profile_config(profile.mode.value, profile.config)
        flag_modified(profile, "config")
    if body.notes is not None:
        profile.notes = body.notes
    if body.is_default is not None:
        if body.is_default:
            await db.execute(
                update(ConnectivityProfile)
                .where(_same_owner_default_scope(profile))
                .values(is_default=False)
            )
        profile.is_default = body.is_default
    await _audit(db, user, "connectivity.profile.update", str(profile_id), {"name": body.name, "config_changed": body.config is not None})
    await db.commit()
    await db.refresh(profile)
    return _redact_profile(profile)


@router.delete("/profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    profile = await _require_profile_access(profile_id, db, user)
    attached_assessments = (
        await db.execute(
            select(func.count(Assessment.id)).where(Assessment.connectivity_profile_id == profile_id)
        )
    ).scalar_one()
    if attached_assessments:
        raise HTTPException(
            status_code=409,
            detail=f"Connectivity profile is linked to {attached_assessments} assessment(s); detach it before deletion",
        )
    mode = profile.mode.value if hasattr(profile.mode, "value") else str(profile.mode)
    try:
        if mode == "CHISEL":
            await get_chisel_manager(str(profile_id)).stop()
        elif mode == "LIGOLO":
            await get_ligolo_manager(str(profile_id)).stop()
        elif mode == "MANAGED_SSH_SOCKS":
            await get_ssh_manager(str(profile_id)).stop()
    except Exception:
        log.warning("Failed to stop tunnel process while deleting profile %s", profile_id, exc_info=True)

    await _audit(db, user, "connectivity.profile.delete", str(profile_id), {"name": profile.name, "mode": mode})
    await db.delete(profile)
    await db.commit()


@router.post("/profiles/{profile_id}/clone", response_model=ConnectivityProfileOut, status_code=status.HTTP_201_CREATED)
async def clone_profile(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    source = await _require_profile_access(profile_id, db, user)
    clean_config = copy.deepcopy(source.config or {})
    # Strip runtime-only and sensitive keys from clone
    for key in ("client_cmd", "client_cmd_template", "server_pid", "last_probe"):
        clean_config.pop(key, None)
    for key in SENSITIVE_CONFIG_KEYS:
        clean_config.pop(key, None)
    cloned = ConnectivityProfile(
        name=f"{source.name} (copy)",
        mode=source.mode,
        config=clean_config,
        is_default=False,
        notes=source.notes,
        created_by=user.id,
    )
    db.add(cloned)
    await db.flush()
    await _audit(db, user, "connectivity.profile.clone", str(cloned.id), {"source_id": str(profile_id), "name": cloned.name})
    await db.commit()
    await db.refresh(cloned)
    return _redact_profile(cloned)


@router.post("/profiles/{profile_id}/test", response_model=ConnectivityTestResult)
async def test_profile(
    profile_id: UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    profile = await _require_profile_access(profile_id, db, user)

    target_host: str = body.get("target_host", "")
    if not target_host:
        raise HTTPException(status_code=422, detail="target_host required")
    target_host = target_host.strip()
    _validate_host(target_host, "target_host")
    if not user.is_superadmin and _is_forbidden_nonadmin_probe_target(target_host):
        raise HTTPException(status_code=403, detail="target_host resolves to a local/reserved address that only superadmins may probe")
    if not _is_allowed_probe_target(profile, target_host, user):
        raise HTTPException(
            status_code=403,
            detail="target_host must match profile dc_ip/dc_hostname or target_subnets unless user is superadmin",
        )

    try:
        transport = await resolve_transport(profile, db)
        result = await multi_probe(target_host, transport)
    except Exception as exc:
        result = {"success": False, "status": "OFFLINE", "latency_ms": None, "error": str(exc), "probes": {}}

    profile.status = ConnectivityProfileStatus(result.get("status", "OFFLINE"))
    profile.last_tested_at = _utcnow()
    profile.last_latency_ms = result.get("latency_ms")
    cfg = profile.config or {}
    history = list(cfg.get("probe_history", []))
    history.insert(0, {
        "target_host": target_host,
        "status": profile.status.value,
        "latency_ms": result.get("latency_ms"),
        "open_ports": result.get("open_ports", []),
        "capabilities": result.get("capabilities", {}),
        "readiness_pct": result.get("readiness_pct", 0),
        "tested_at": _utcnow().isoformat(),
    })
    profile.config = {
        **cfg,
        "last_probe": {
            "target_host": target_host,
            "status": profile.status.value,
            "capabilities": result.get("capabilities", {}),
            "readiness_pct": result.get("readiness_pct", 0),
            "open_ports": result.get("open_ports", []),
            "probes": result.get("probes", {}),
        },
        "probe_history": history[:20],
    }
    flag_modified(profile, "config")

    await _audit(db, user, "connectivity.profile.test", str(profile_id), {"target_host": target_host, "success": result["success"]})
    await db.commit()

    return ConnectivityTestResult(
        profile_id=profile_id,
        success=result["success"],
        status=profile.status,
        latency_ms=result.get("latency_ms"),
        error=result.get("error"),
        details=result.get("probes", {}),
        capabilities=result.get("capabilities", {}),
        readiness_pct=result.get("readiness_pct", 0),
        open_ports=result.get("open_ports", []),
    )


@router.post("/profiles/{profile_id}/chisel/start", response_model=ChiselServerStatus)
async def chisel_start(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "CHISEL":
        raise HTTPException(status_code=400, detail="Profile is not CHISEL mode")

    cfg = profile.config
    _validate_port(int(cfg.get("server_port", 8080)), "server_port")
    _validate_port(int(cfg.get("socks_port", 1080)), "socks_port")
    mgr = get_chisel_manager(
        str(profile_id),
        port=int(cfg.get("server_port", 8080)),
        socks_port=int(cfg.get("socks_port", 1080)),
        auth_token=cfg.get("auth_token"),
    )
    client_cmd_template = await mgr.start()
    profile.config = {**cfg, "client_cmd_template": client_cmd_template, "server_pid": mgr.pid}
    profile.config.pop("client_cmd", None)
    flag_modified(profile, "config")
    await _audit(db, user, "connectivity.chisel.start", str(profile_id), {"port": mgr.port, "pid": mgr.pid})
    await db.commit()
    return ChiselServerStatus(
        running=mgr.running,
        pid=mgr.pid,
        port=mgr.port,
        client_cmd=None,
        client_cmd_template=client_cmd_template,
    )


@router.post("/profiles/{profile_id}/chisel/stop", response_model=ChiselServerStatus)
async def chisel_stop(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "CHISEL":
        raise HTTPException(status_code=400, detail="Profile is not CHISEL mode")
    mgr = get_chisel_manager(str(profile_id))
    await mgr.stop()
    await _audit(db, user, "connectivity.chisel.stop", str(profile_id), {})
    await db.commit()
    return ChiselServerStatus(running=False)


@router.get("/profiles/{profile_id}/chisel/status", response_model=ChiselServerStatus)
async def chisel_status(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "CHISEL":
        raise HTTPException(status_code=400, detail="Profile is not CHISEL mode")
    cfg = profile.config or {}
    mgr = get_chisel_manager(
        str(profile_id),
        port=int(cfg.get("server_port", 8080)),
        socks_port=int(cfg.get("socks_port", 1080)),
        auth_token=cfg.get("auth_token"),
    )
    return ChiselServerStatus(
        running=mgr.running,
        pid=mgr.pid,
        port=mgr.port,
        client_cmd=None,
        client_cmd_template=cfg.get("client_cmd_template") or (mgr.client_cmd_template() if mgr.running else None),
    )


@router.get("/profiles/{profile_id}/chisel/logs")
async def chisel_logs(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "CHISEL":
        raise HTTPException(status_code=400, detail="Profile is not CHISEL mode")
    cfg = profile.config or {}
    mgr = get_chisel_manager(
        str(profile_id),
        port=int(cfg.get("server_port", 8080)),
        socks_port=int(cfg.get("socks_port", 1080)),
        auth_token=cfg.get("auth_token"),
    )
    lines = await mgr.log_lines()
    return {"lines": lines}


@router.post("/profiles/{profile_id}/ligolo/start", response_model=LigoloStatus)
async def ligolo_start(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "LIGOLO":
        raise HTTPException(status_code=400, detail="Profile is not LIGOLO mode")
    cfg = profile.config
    _validate_port(int(cfg.get("proxy_port", 11601)), "proxy_port")
    mgr = get_ligolo_manager(
        str(profile_id),
        port=int(cfg.get("proxy_port", 11601)),
        tun_interface=cfg.get("tun_interface", "ligolo"),
    )
    await mgr.start()
    await _audit(db, user, "connectivity.ligolo.start", str(profile_id), {"port": mgr.port, "pid": mgr.pid})
    await db.commit()
    return LigoloStatus(running=mgr.running, pid=mgr.pid, port=mgr.port, tun_interface=mgr.tun_interface)


@router.post("/profiles/{profile_id}/ligolo/stop", response_model=LigoloStatus)
async def ligolo_stop(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "LIGOLO":
        raise HTTPException(status_code=400, detail="Profile is not LIGOLO mode")
    mgr = get_ligolo_manager(str(profile_id))
    await mgr.stop()
    await _audit(db, user, "connectivity.ligolo.stop", str(profile_id), {})
    await db.commit()
    return LigoloStatus(running=False)


@router.post("/profiles/{profile_id}/ligolo/route")
async def ligolo_add_route(
    profile_id: UUID,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    cidr: str = body.get("cidr", "")
    if not cidr:
        raise HTTPException(status_code=422, detail="cidr required")
    _validate_cidr(cidr)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "LIGOLO":
        raise HTTPException(status_code=400, detail="Profile is not LIGOLO mode")
    cfg = profile.config or {}
    mgr = get_ligolo_manager(
        str(profile_id),
        port=int(cfg.get("proxy_port", 11601)),
        tun_interface=cfg.get("tun_interface", "ligolo"),
    )
    if not mgr.running:
        raise HTTPException(status_code=409, detail="Ligolo proxy is not running; start it before adding routes")
    await mgr.add_route(cidr)
    await _audit(db, user, "connectivity.ligolo.route.add", str(profile_id), {"cidr": cidr})
    await db.commit()
    return {"routes": mgr.routes}


@router.get("/profiles/{profile_id}/ligolo/status", response_model=LigoloStatus)
async def ligolo_status(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "LIGOLO":
        raise HTTPException(status_code=400, detail="Profile is not LIGOLO mode")
    cfg = profile.config or {}
    mgr = get_ligolo_manager(
        str(profile_id),
        port=int(cfg.get("proxy_port", 11601)),
        tun_interface=cfg.get("tun_interface", "ligolo"),
    )
    return LigoloStatus(
        running=mgr.running,
        pid=mgr.pid,
        port=mgr.port,
        tun_interface=mgr.tun_interface,
        routes=mgr.routes,
    )

@router.get("/profiles/{profile_id}/ligolo/logs")
async def ligolo_logs(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "LIGOLO":
        raise HTTPException(status_code=400, detail="Profile is not LIGOLO mode")
    cfg = profile.config or {}
    mgr = get_ligolo_manager(
        str(profile_id),
        port=int(cfg.get("proxy_port", 11601)),
        tun_interface=cfg.get("tun_interface", "ligolo"),
    )
    lines = await mgr.log_lines()
    return {"lines": lines}


def _tunnel_session_payload(session: TunnelSession) -> dict:
    status_value = session.status.value if hasattr(session.status, "value") else str(session.status)
    mode_value = session.mode.value if hasattr(session.mode, "value") else str(session.mode)
    return {
        "id": session.id,
        "profile_id": session.profile_id,
        "mode": mode_value,
        "jumpbox_host": session.jumpbox_host,
        "jumpbox_port": session.jumpbox_port,
        "jumpbox_username": session.jumpbox_username,
        "local_host": session.local_host,
        "local_port": session.local_port,
        "process_pid": session.process_pid,
        "status": status_value,
        "started_by": session.started_by,
        "started_at": session.started_at,
        "stopped_at": session.stopped_at,
        "last_healthcheck_at": session.last_healthcheck_at,
        "error_summary": session.error_summary,
        "sanitized_command_preview": session.sanitized_command_preview,
        "metadata_json": session.metadata_json or {},
        "tunnel_endpoint": f"socks5h://{session.local_host}:{session.local_port}" if status_value == TunnelSessionStatus.ACTIVE.value else None,
    }


async def _latest_tunnel_session(db: AsyncSession, profile_id: UUID, *, active_only: bool = False) -> TunnelSession | None:
    q = select(TunnelSession).where(TunnelSession.profile_id == profile_id)
    if active_only:
        q = q.where(TunnelSession.status == TunnelSessionStatus.ACTIVE)
    q = q.order_by(TunnelSession.started_at.desc()).limit(1)
    result = await db.execute(q)
    return result.scalar_one_or_none()


def _managed_ssh_manager_from_profile(profile: ConnectivityProfile):
    cfg = profile.config or {}
    return get_ssh_manager(
        str(profile.id),
        jumpbox_host=str(cfg.get("jumpbox_host", "")).strip(),
        jumpbox_port=int(cfg.get("jumpbox_port", 22)),
        username=str(cfg.get("jumpbox_username", "")).strip(),
        auth_method=str(cfg.get("auth_method", "ssh_key")),
        ssh_key_path=cfg.get("ssh_key_path"),
    )


@router.post("/profiles/{profile_id}/tunnel/start", response_model=TunnelSessionOut)
async def managed_ssh_tunnel_start(
    profile_id: UUID,
    body: TunnelStartRequest,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "MANAGED_SSH_SOCKS":
        raise HTTPException(status_code=400, detail="Profile is not MANAGED_SSH_SOCKS mode")
    cfg = profile.config or {}
    errors = _validate_managed_ssh_config(cfg)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))

    active = await _latest_tunnel_session(db, profile_id, active_only=True)
    mgr = _managed_ssh_manager_from_profile(profile)
    if active and mgr.running:
        active.local_port = mgr.local_port or active.local_port
        active.process_pid = mgr.pid
        active.last_healthcheck_at = _utcnow()
        await db.commit()
        await db.refresh(active)
        return _tunnel_session_payload(active)

    if active and not mgr.running:
        active.status = TunnelSessionStatus.STOPPED
        active.stopped_at = _utcnow()
        active.error_summary = active.error_summary or "Marked stopped before new tunnel start because local manager was not running"

    try:
        local_port = await start_tunnel(str(profile_id), mgr, password=body.password)
    except Exception as exc:
        failed = TunnelSession(
            profile_id=profile.id,
            mode=ConnectivityMode.MANAGED_SSH_SOCKS,
            jumpbox_host=str(cfg.get("jumpbox_host", "")),
            jumpbox_port=int(cfg.get("jumpbox_port", 22)),
            jumpbox_username=str(cfg.get("jumpbox_username", "")),
            local_host="127.0.0.1",
            local_port=int(mgr.local_port or 0),
            process_pid=mgr.pid,
            status=TunnelSessionStatus.FAILED,
            started_by=user.id,
            stopped_at=_utcnow(),
            error_summary=str(exc)[:2000],
            sanitized_command_preview=mgr.sanitized_command_preview(),
            metadata_json={"auth_method": str(cfg.get("auth_method", "ssh_key"))},
        )
        db.add(failed)
        await _audit(db, user, "connectivity.managed_ssh.start_failed", str(profile_id), {"error": str(exc)[:500]})
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Managed SSH tunnel failed: {exc}") from exc

    session = TunnelSession(
        profile_id=profile.id,
        mode=ConnectivityMode.MANAGED_SSH_SOCKS,
        jumpbox_host=str(cfg.get("jumpbox_host", "")),
        jumpbox_port=int(cfg.get("jumpbox_port", 22)),
        jumpbox_username=str(cfg.get("jumpbox_username", "")),
        local_host="127.0.0.1",
        local_port=int(local_port),
        process_pid=mgr.pid,
        status=TunnelSessionStatus.ACTIVE,
        started_by=user.id,
        last_healthcheck_at=_utcnow(),
        sanitized_command_preview=mgr.sanitized_command_preview(),
        metadata_json={"auth_method": str(cfg.get("auth_method", "ssh_key"))},
    )
    db.add(session)
    profile.status = ConnectivityProfileStatus.ONLINE
    await _audit(db, user, "connectivity.managed_ssh.start", str(profile_id), {"local_port": local_port, "pid": mgr.pid})
    await db.commit()
    await db.refresh(session)
    return _tunnel_session_payload(session)


@router.post("/profiles/{profile_id}/tunnel/stop", response_model=TunnelSessionOut)
async def managed_ssh_tunnel_stop(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "MANAGED_SSH_SOCKS":
        raise HTTPException(status_code=400, detail="Profile is not MANAGED_SSH_SOCKS mode")

    latest = await _latest_tunnel_session(db, profile_id, active_only=True)
    if not latest:
        latest = await _latest_tunnel_session(db, profile_id)
    if not latest:
        raise HTTPException(status_code=404, detail="No tunnel session found")

    mgr = get_ssh_manager(str(profile_id))
    if mgr.running:
        await mgr.stop()
    active_rows = (await db.execute(
        select(TunnelSession).where(
            TunnelSession.profile_id == profile_id,
            TunnelSession.status == TunnelSessionStatus.ACTIVE,
        )
    )).scalars().all()
    for row in active_rows:
        row.status = TunnelSessionStatus.STOPPED
        row.stopped_at = _utcnow()
        row.process_pid = mgr.pid
    profile.status = ConnectivityProfileStatus.UNKNOWN
    await _audit(db, user, "connectivity.managed_ssh.stop", str(profile_id), {})
    await db.commit()
    await db.refresh(latest)
    return _tunnel_session_payload(latest)


@router.get("/profiles/{profile_id}/tunnel/status", response_model=TunnelSessionOut)
async def managed_ssh_tunnel_status(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "MANAGED_SSH_SOCKS":
        raise HTTPException(status_code=400, detail="Profile is not MANAGED_SSH_SOCKS mode")

    session = await _latest_tunnel_session(db, profile_id)
    if not session:
        raise HTTPException(status_code=404, detail="No tunnel session found")
    if session.status == TunnelSessionStatus.ACTIVE:
        alive = await is_local_tcp_listener(session.local_host, int(session.local_port))
        if alive:
            session.last_healthcheck_at = _utcnow()
        else:
            session.status = TunnelSessionStatus.FAILED
            session.stopped_at = _utcnow()
            session.error_summary = session.error_summary or "Local SOCKS listener is no longer reachable"
            profile.status = ConnectivityProfileStatus.OFFLINE
        await db.commit()
        await db.refresh(session)
    return _tunnel_session_payload(session)


@router.get("/profiles/{profile_id}/tunnel/logs")
async def managed_ssh_tunnel_logs(
    profile_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: PlatformUser = Depends(get_current_user),
):
    _require_tunnel_management(user)
    profile = await _require_profile_access(profile_id, db, user)
    if profile.mode.value != "MANAGED_SSH_SOCKS":
        raise HTTPException(status_code=400, detail="Profile is not MANAGED_SSH_SOCKS mode")
    mgr = _managed_ssh_manager_from_profile(profile)
    return {"lines": await mgr.log_lines()}
