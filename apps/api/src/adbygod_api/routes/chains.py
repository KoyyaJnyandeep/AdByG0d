from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
import re as _re

from pydantic import BaseModel, field_validator
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.config import settings
from adbygod_api.core.chains.path_resolver import resolve_path_to_steps
from adbygod_api.core.security.authorization import (
    require_assessment_access,
    require_assessment_write_access,
    require_superadmin,
)
from adbygod_api.core.streaming import publish_line
from adbygod_api.core.workers.impacket_worker import ImpacketWorker
from adbygod_api.core.workers.pool import get_pool
from adbygod_api.database import AsyncSessionLocal, get_db
from adbygod_api.models import (
    AttackChain, ChainStatus, Entity, GraphEdge,
    JobOutput, OffensiveJob, OffensiveJobStatus, OpsecProfile, PlatformUser,
)
from adbygod_api.routes.auth import get_current_user

log = logging.getLogger(__name__)

_background_tasks: set[asyncio.Task] = set()

def _fire_task(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _background_tasks.add(t)
    t.add_done_callback(_background_tasks.discard)
    return t


def require_chain_builder_enabled() -> None:
    if not settings.ENABLE_CHAIN_BUILDER:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Under development")


router = APIRouter(
    prefix="/chains",
    tags=["chains"],
    dependencies=[Depends(require_chain_builder_enabled)],
    include_in_schema=settings.ENABLE_CHAIN_BUILDER,
)

_chain_locks: dict[str, asyncio.Lock] = {}


def _get_chain_lock(chain_id: str) -> asyncio.Lock:
    """Return (or create) the per-chain asyncio.Lock for serialising loot writes."""
    return _chain_locks.setdefault(chain_id, asyncio.Lock())


_SAFE_HOST_RE = _re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')
_SAFE_USER_RE = _re.compile(r'^[a-zA-Z0-9._\-@$\\]{0,256}$')
_NTLM_HASH_RE = _re.compile(r'^([a-fA-F0-9]{32}:[a-fA-F0-9]{32})?$')


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _get_redis():
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


def _chain_channel(chain_id: str) -> str:
    return f"chain:{chain_id}:progress"


async def _publish_chain_event(redis, chain_id: str, event: str, data: dict):
    payload = {"chain_id": chain_id, "event": event, **data}
    await redis.publish(_chain_channel(chain_id), json.dumps(payload))


class ChainRequest(BaseModel):
    assessment_id: UUID | None = None
    target: str
    domain: str
    username: str = ""
    password: str = ""
    hashes: str = ""
    dc_ip: str = ""
    opsec_profile: OpsecProfile = OpsecProfile.BALANCED
    situation: str = "DOMAIN_USER"
    path_id: str | None = None

    @field_validator("target", "dc_ip")
    @classmethod
    def _validate_host(cls, v: str) -> str:
        if v and not _SAFE_HOST_RE.match(v):
            raise ValueError(f"Invalid host/IP format: {v!r}")
        return v

    @field_validator("username")
    @classmethod
    def _validate_username(cls, v: str) -> str:
        if v and not _SAFE_USER_RE.match(v):
            raise ValueError(f"Invalid username format: {v!r}")
        return v

    @field_validator("hashes")
    @classmethod
    def _validate_hashes(cls, v: str) -> str:
        if v and not _NTLM_HASH_RE.match(v.strip()):
            raise ValueError("hashes must be empty or NTLM format LM:NT (two 32-hex strings separated by ':')")
        return v

    @field_validator("password")
    @classmethod
    def _validate_password(cls, v: str) -> str:
        if len(v) > 512:
            raise ValueError("password too long (max 512 chars)")
        if '\x00' in v:
            raise ValueError("password must not contain null bytes")
        return v


class ChainPreflightRequest(BaseModel):
    target: str
    domain: str = ""
    username: str = ""
    password: str = ""
    hashes: str = ""
    dc_ip: str = ""
    ldap_url: str = ""
    base_dn: str = ""
    ports: list[int] | None = None


class ChainPreflightOut(BaseModel):
    ok: bool
    target: str
    dc_ip: str
    ports: dict[str, bool]
    ldap_bind: dict[str, Any]
    errors: list[str]
    warnings: list[str]


class ChainOut(BaseModel):
    id: UUID
    name: str
    status: str
    steps: list[dict]
    path_nodes: list[str]
    current_step: int
    job_ids: list[str]
    loot: dict
    target: str | None
    domain: str | None
    target_label: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


def _chain_to_out(c: AttackChain) -> ChainOut:
    return ChainOut(
        id=c.id,
        name=c.name,
        status=c.status,
        steps=c.steps or [],
        path_nodes=c.path_nodes or [],
        current_step=c.current_step or 0,
        job_ids=[str(j) for j in (c.job_ids or [])],
        loot=c.loot or {},
        target=c.target,
        domain=c.domain,
        target_label=c.target_label,
        created_at=c.created_at,
        started_at=c.started_at,
        completed_at=c.completed_at,
    )


async def _load_graph_analyzer(assessment_id: UUID | None):
    if not assessment_id:
        return None
    try:
        from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
        async with AsyncSessionLocal() as db:
            entities = (await db.execute(select(Entity).where(Entity.assessment_id == assessment_id))).scalars().all()
            edges = (await db.execute(select(GraphEdge).where(GraphEdge.assessment_id == assessment_id))).scalars().all()
        analyzer = ADGraphAnalyzer()
        analyzer.load_from_db(entities, edges)
        return analyzer
    except Exception as exc:
        log.warning("Could not load graph for chain resolution: %s", exc)
        return None


def _domain_to_base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split(".") if part)


async def _check_tcp(host: str, port: int, timeout: float = 2.0) -> tuple[int, bool, str | None]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, True, None
    except Exception as exc:
        return port, False, str(exc) or exc.__class__.__name__


def _ldap_bind_sync(ldap_url: str, username: str, password: str, base_dn: str) -> dict[str, Any]:
    try:
        from ldap3 import ALL, Connection, Server
    except Exception as exc:
        return {"ok": False, "error": f"ldap3 unavailable: {exc}"}

    try:
        server = Server(ldap_url, get_info=ALL, connect_timeout=3)
        conn = Connection(server, user=username, password=password, auto_bind=True, receive_timeout=5)
        try:
            search_base = base_dn or ""
            entries_seen = 0
            if search_base:
                conn.search(search_base, "(objectClass=*)", search_scope="BASE", attributes=["objectClass"], size_limit=1)
                entries_seen = len(conn.entries)
            return {"ok": True, "user": username, "base_dn": base_dn, "entries_seen": entries_seen}
        finally:
            conn.unbind()
    except Exception as exc:
        return {"ok": False, "user": username, "base_dn": base_dn, "error": str(exc) or exc.__class__.__name__}


SITUATION_META = [
    {
        "id": "ANON",
        "label": "Anonymous / No Creds",
        "description": "No credentials at all. Only target IP/domain required. Exploits unauthenticated attack vectors: NTLM relay, AS-REP roasting, null-session enumeration.",
        "example": "Network access only. OSINT or physical breach.",
        "color": "#94a3b8",
        "icon": "wifi",
        "credential_required": False,
    },
    {
        "id": "DOMAIN_USER",
        "label": "Domain User",
        "description": "Valid domain credentials (any low-priv user). Unlocks Kerberoasting, ACL abuse, ADCS ESC1, shadow credentials, RBCD, noPac, and more.",
        "example": "jsmith:Password123 or any domain account.",
        "color": "#818cf8",
        "icon": "user",
        "credential_required": True,
    },
    {
        "id": "HASH_ONLY",
        "label": "NT Hash / Ticket",
        "description": "NTLM hash or Kerberos ticket (CCACHE) with no cleartext password. PTH directly to admin hosts, delegation abuse, or trust escalation.",
        "example": "aad3b435:31d6cfe0d16ae931b73c59d7e0c089c0",
        "color": "#f97316",
        "icon": "key",
        "credential_required": True,
    },
    {
        "id": "LOCAL_ADMIN",
        "label": "Local Administrator",
        "description": "Local admin on one or more domain-joined machines. Dump cached creds, SAM, LSA secrets, pivot to domain assets.",
        "example": "Local admin via default creds, CVE, or physical access.",
        "color": "#fb923c",
        "icon": "shield",
        "credential_required": True,
    },
    {
        "id": "SVC_ACCT",
        "label": "Service Account",
        "description": "Domain service account — especially one with delegation rights (constrained/unconstrained). High confidence paths via S4U2Proxy impersonation.",
        "example": "svc_sql, svc_backup with delegation set.",
        "color": "#a855f7",
        "icon": "server",
        "credential_required": True,
    },
    {
        "id": "TRUST",
        "label": "Child Domain DA",
        "description": "Domain Admin in a child domain within a forest. ExtraSID Golden Ticket to escalate to Enterprise Admin / parent forest DA.",
        "example": "child\\Administrator with child domain krbtgt hash.",
        "color": "#ec4899",
        "icon": "git-branch",
        "credential_required": True,
    },
]


@router.post("/preflight", response_model=ChainPreflightOut)
async def preflight_chain_target(
    req: ChainPreflightRequest,
    current_user: PlatformUser = Depends(get_current_user),
):
    """Check target reachability and optional LDAP bind before creating a chain."""
    # This endpoint performs server-side outbound network probes and optional LDAP
    # authentication attempts. Keep it out of ordinary analyst sessions.
    await require_superadmin(current_user)
    dc_ip = req.dc_ip or req.target
    ports = req.ports or [389, 88, 445]
    warnings: list[str] = []
    errors: list[str] = []

    checked = await asyncio.gather(*[_check_tcp(dc_ip, port) for port in ports])
    port_status = {str(port): ok for port, ok, _err in checked}
    for port, ok, err in checked:
        if not ok:
            errors.append(f"{dc_ip}:{port} unreachable ({err})")

    ldap_result: dict[str, Any] = {"ok": False, "skipped": True}
    if req.username and req.password:
        bind_user = req.username
        if req.domain and "@" not in bind_user and "\\" not in bind_user:
            bind_user = f"{bind_user}@{req.domain}"
        ldap_url = req.ldap_url or f"ldap://{dc_ip}:389"
        base_dn = req.base_dn or _domain_to_base_dn(req.domain)
        ldap_result = await asyncio.to_thread(_ldap_bind_sync, ldap_url, bind_user, req.password, base_dn)
        if not ldap_result.get("ok"):
            errors.append(f"LDAP bind failed: {ldap_result.get('error', 'unknown error')}")
    elif req.username and req.hashes:
        warnings.append("LDAP simple bind skipped because only NTLM hashes were supplied")
    else:
        warnings.append("LDAP bind skipped because no username/password was supplied")

    return ChainPreflightOut(
        ok=not errors,
        target=req.target,
        dc_ip=dc_ip,
        ports=port_status,
        ldap_bind=ldap_result,
        errors=errors,
        warnings=warnings,
    )


@router.get("/situations")
async def list_situations(
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return all available starting situations with descriptions."""
    return {"situations": SITUATION_META}


@router.get("/library")
async def get_path_library(
    situation: str = "DOMAIN_USER",
    current_user: PlatformUser = Depends(get_current_user),
):
    """Return all attack paths available for a given starting situation, with step previews."""
    from adbygod_api.core.chains.path_resolver import get_paths_for_situation

    paths = get_paths_for_situation(situation)
    result = []
    for p in paths:
        result.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "confidence": p.confidence,
            "step_count": len(p.steps),
            "tags": p.tags,
            "situations": p.situations,
            "steps_preview": [
                {
                    "technique_id": s.technique_id,
                    "label": s.label,
                    "mitre": s.mitre,
                    "description": s.description,
                    "edge_type": s.edge_type,
                    "src_label": s.src_label,
                    "tgt_label": s.tgt_label,
                    "is_manual": s.is_manual,
                    "manual_prompt": s.manual_prompt,
                    "loot_produces": s.loot_produces,
                    "loot_requires": s.loot_requires,
                }
                for s in p.steps
            ],
        })
    return {"situation": situation, "paths": result, "total": len(result)}


@router.post("/resolve")
async def resolve_chain(
    req: ChainRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Dry-run: compute the attack path and return planned steps without persisting."""
    from adbygod_api.core.chains.path_resolver import get_path_steps

    if req.assessment_id is not None:
        await require_assessment_access(req.assessment_id, db, current_user)

    analyzer = await _load_graph_analyzer(req.assessment_id)
    auth = {"username": req.username, "password": req.password, "hashes": req.hashes, "dc_ip": req.dc_ip or req.target}

    if req.path_id:
        steps, nodes = await asyncio.to_thread(get_path_steps, req.path_id, req.target, req.domain, auth)
        all_paths_meta: list[dict] = []
        graph_paths: list[dict] = []
    else:
        steps, nodes, all_paths_meta, graph_paths = await asyncio.to_thread(
            resolve_path_to_steps, analyzer, req.target, req.domain, auth, req.situation
        )

    return {
        "steps": steps,
        "path_nodes": nodes,
        "step_count": len(steps),
        "solvable": len(steps) > 0,
        "found_paths": len(all_paths_meta) if all_paths_meta else (1 if steps else 0),
        "all_paths": all_paths_meta,
        "graph_paths": graph_paths,
    }


@router.post("", response_model=ChainOut, status_code=status.HTTP_201_CREATED)
async def create_chain(
    req: ChainRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Create and persist a chain (does not start execution)."""
    if req.assessment_id is not None:
        await require_assessment_write_access(req.assessment_id, db, current_user)

    analyzer = await _load_graph_analyzer(req.assessment_id)
    auth = {"username": req.username, "password": req.password, "hashes": req.hashes, "dc_ip": req.dc_ip or req.target}
    if req.path_id:
        from adbygod_api.core.chains.path_resolver import get_path_steps
        steps, nodes = await asyncio.to_thread(get_path_steps, req.path_id, req.target, req.domain, auth)
    else:
        steps, nodes, *_ = await asyncio.to_thread(
            resolve_path_to_steps, analyzer, req.target, req.domain, auth, req.situation
        )

    chain = AttackChain(
        id=uuid.uuid4(),
        assessment_id=req.assessment_id,
        owner_user_id=current_user.id,
        name=f"Path to DA — {req.domain or req.target}",
        status=ChainStatus.PENDING,
        target=req.target,
        domain=req.domain,
        target_label=nodes[-1] if nodes else "Domain Controller",
        path_nodes=nodes,
        steps=steps,
        current_step=0,
        loot={},
        job_ids=[],
        params={"opsec_profile": req.opsec_profile.value, **auth},
        created_at=_utcnow(),
    )
    db.add(chain)
    await db.commit()
    await db.refresh(chain)
    return _chain_to_out(chain)



def _blocked_chain_techniques(steps: list[dict]) -> list[str]:
    allowlist = settings.command_execution_allowlist
    return sorted({
        str(step.get("technique_id", "")).strip()
        for step in steps
        if not str(step.get("technique_id", "")).strip()
        or str(step.get("technique_id", "")).strip() not in allowlist
    })


async def _require_chain_execution_allowed(
    chain: AttackChain,
    db: AsyncSession,
    current_user: PlatformUser,
) -> None:
    await require_superadmin(current_user)
    if not settings.ENABLE_COMMAND_EXECUTION:
        raise HTTPException(status_code=403, detail="Command execution is disabled by default")
    blocked = _blocked_chain_techniques(list(chain.steps or []))
    if blocked:
        visible = ", ".join(item or "<missing-technique>" for item in blocked)
        raise HTTPException(
            status_code=403,
            detail=f"Techniques are not allowlisted for execution: {visible}",
        )
    if chain.assessment_id is not None:
        await require_assessment_write_access(chain.assessment_id, db, current_user)


@router.post("/{chain_id}/start", response_model=ChainOut)
async def start_chain(
    chain_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    chain = await db.get(AttackChain, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    if not current_user.is_superadmin and chain.owner_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    await _require_chain_execution_allowed(chain, db, current_user)
    if chain.status == ChainStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Chain already running")
    if chain.status == ChainStatus.COMPLETED:
        raise HTTPException(status_code=409, detail="Chain already completed")
    if not chain.steps:
        raise HTTPException(status_code=400, detail="Chain has no steps")

    chain.status = ChainStatus.RUNNING
    chain.started_at = _utcnow()
    chain.current_step = 0
    chain.job_ids = []
    await db.commit()
    await db.refresh(chain)

    _fire_task(_run_chain(str(chain_id)))
    return _chain_to_out(chain)


@router.post("/{chain_id}/stop", status_code=status.HTTP_204_NO_CONTENT)
async def stop_chain(
    chain_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    chain = await db.get(AttackChain, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    if not current_user.is_superadmin and chain.owner_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")

    pool = get_pool()
    for jid in (chain.job_ids or []):
        await pool.kill(str(jid))

    chain.status = ChainStatus.STOPPED
    chain.completed_at = _utcnow()
    await db.commit()


@router.get("", response_model=list[ChainOut])
async def list_chains(
    limit: int = Query(20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    q = select(AttackChain).order_by(desc(AttackChain.created_at)).limit(limit)
    if not current_user.is_superadmin:
        q = q.where(AttackChain.owner_user_id == current_user.id)
    rows = (await db.execute(q)).scalars().all()
    return [_chain_to_out(c) for c in rows]


@router.get("/{chain_id}", response_model=ChainOut)
async def get_chain(
    chain_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
):
    chain = await db.get(AttackChain, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    if not current_user.is_superadmin and chain.owner_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return _chain_to_out(chain)


@router.websocket("/ws/{chain_id}")
async def chain_ws(websocket: WebSocket, chain_id: str):
    """Stream chain progress events in real-time.

    Auth uses the HttpOnly session cookie.
    """
    if not settings.ENABLE_CHAIN_BUILDER:
        await websocket.accept()
        await websocket.send_json({"error": "Under development", "code": 503})
        await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER)
        return

    await websocket.accept()
    origin = websocket.headers.get("origin")
    if origin:
        from adbygod_api.routes.auth import _origin_allowed
        if not _origin_allowed(origin):
            await websocket.send_json({"error": "Origin not allowed", "code": 403})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    from adbygod_api.routes.auth import _get_user_cached
    from adbygod_api.database import AsyncSessionLocal as _ASL
    final_token = websocket.cookies.get(settings.AUTH_COOKIE_NAME)
    if not final_token:
        await websocket.send_json({"error": "Unauthorized", "code": 401})
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    async with _ASL() as _db:
        try:
            user = await _get_user_cached(final_token, _db)
        except Exception:
            await websocket.send_json({"error": "Invalid token", "code": 401})
            await websocket.close()
            return
        try:
            chain_uuid = UUID(chain_id)
        except ValueError:
            await websocket.send_json({"error": "Invalid chain ID", "code": 400})
            await websocket.close()
            return
        chain_obj = await _db.get(AttackChain, chain_uuid)
        if not chain_obj:
            await websocket.send_json({"error": "Chain not found", "code": 404})
            await websocket.close()
            return
        if not user.is_superadmin and chain_obj.owner_user_id != user.id:
            await websocket.send_json({"error": "Forbidden", "code": 403})
            await websocket.close()
            return
    redis = _get_redis()
    channel = _chain_channel(chain_id)
    pubsub = redis.pubsub()
    await pubsub.subscribe(channel)
    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                data = json.loads(message["data"])
            except (json.JSONDecodeError, TypeError):
                continue
            await websocket.send_json(data)
            if data.get("event") in ("chain_completed", "chain_failed", "chain_stopped"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await redis.aclose()
        try:
            await websocket.close()
        except Exception:
            pass


async def _run_chain(chain_id: str):
    """Background coroutine: execute chain steps sequentially."""
    redis = _get_redis()
    try:
        async with AsyncSessionLocal() as db:
            chain = await db.get(AttackChain, uuid.UUID(chain_id))
            if not chain:
                return
            steps: list[dict] = list(chain.steps or [])
            owner_id = chain.owner_user_id
            block_reason: str | None = None
            if not settings.ENABLE_COMMAND_EXECUTION:
                block_reason = "Command execution is disabled by default"
            else:
                blocked = _blocked_chain_techniques(steps)
                if blocked:
                    visible = ", ".join(item or "<missing-technique>" for item in blocked)
                    block_reason = f"Techniques are not allowlisted for execution: {visible}"
            if block_reason:
                chain.status = ChainStatus.FAILED
                chain.completed_at = _utcnow()
                await db.commit()
            opsec_val = chain.params.get("opsec_profile", "BALANCED")
            try:
                opsec = OpsecProfile(opsec_val)
            except ValueError:
                opsec = OpsecProfile.BALANCED

        if block_reason:
            await _publish_chain_event(redis, chain_id, "chain_failed", {"error": block_reason})
            return

        await _publish_chain_event(redis, chain_id, "chain_started", {"total_steps": len(steps)})

        for idx, step in enumerate(steps):
            technique_id = step["technique_id"]
            target = step.get("target", "")
            params = dict(step.get("params", {}))
            params["technique"] = technique_id
            params["target"] = target

            # Inject accumulated loot from prior steps into current step params
            async with AsyncSessionLocal() as loot_db:
                chain_row = await loot_db.get(AttackChain, uuid.UUID(chain_id))
                loot = dict(chain_row.loot or {}) if chain_row else {}
            if loot:
                # krbtgt_hash → nthash for ticketer / golden ticket steps
                if not params.get("nthash") and not params.get("krbtgt_hash"):
                    kh = loot.get("krbtgt_hash", [])
                    if kh:
                        params["nthash"] = kh[-1]
                        params["krbtgt_hash"] = kh[-1]
                # domain_sid passthrough
                if not params.get("domain_sid"):
                    ds = loot.get("domain_sid", [])
                    if ds:
                        params["domain_sid"] = ds[-1]
                # ccache → KRB5CCNAME env hint
                if not params.get("ccache"):
                    cc = loot.get("ccache", [])
                    if cc:
                        params["ccache"] = cc[-1]
                # DA hash from Certipy auth / pass-the-cert flows
                if not params.get("hashes"):
                    for hash_key in ("da_hashes", "nt_hashes"):
                        hashes = loot.get(hash_key, [])
                        if hashes:
                            params["hashes"] = str(hashes[-1]).splitlines()[0]
                            if hash_key == "da_hashes":
                                params["username"] = params.get("target_user") or "Administrator"
                            break
                # certificate artifacts from Certipy request / shadow creds
                if not params.get("pfx_file"):
                    for cert_key in ("da_certificate", "dc_certificate", "shadow_cert"):
                        certs = loot.get(cert_key, [])
                        if certs:
                            params["pfx_file"] = certs[-1]
                            break
                if not params.get("ca"):
                    cas = loot.get("ca_name", [])
                    if cas:
                        params["ca"] = cas[-1]
                if not params.get("template") or params.get("template") == "User":
                    templates = loot.get("vulnerable_template", [])
                    if templates:
                        params["template"] = templates[-1]

            # Pre-generate job_id and subscribe to output channel BEFORE starting
            # the worker task — avoids race where fast tasks publish done before
            # _await_job subscribes.
            job_id = uuid.uuid4()
            job_channel = f"job:{job_id}:output"
            job_pubsub = redis.pubsub()
            await job_pubsub.subscribe(job_channel)

            try:
                await _run_step(
                    chain_id=chain_id,
                    step_index=idx,
                    step=step,
                    params=params,
                    owner_id=owner_id,
                    opsec=opsec,
                    redis=redis,
                    job_id=job_id,
                )
            except Exception:
                await job_pubsub.unsubscribe(job_channel)
                await job_pubsub.aclose()
                raise

            async with AsyncSessionLocal() as db:
                chain = await db.get(AttackChain, uuid.UUID(chain_id))
                if not chain:
                    await job_pubsub.unsubscribe(job_channel)
                    await job_pubsub.aclose()
                    return
                if chain.status == ChainStatus.STOPPED:
                    await _publish_chain_event(redis, chain_id, "chain_stopped", {"step": idx})
                    await job_pubsub.unsubscribe(job_channel)
                    await job_pubsub.aclose()
                    return

                job_ids = list(chain.job_ids or [])
                job_ids.append(str(job_id))
                chain.job_ids = job_ids
                chain.current_step = idx + 1
                await db.commit()

            # wait for job to complete using pre-subscribed pubsub
            exit_code = await _await_job(job_id, redis, chain_id, idx, pubsub=job_pubsub)

            # exit_code 2 = manual_crack sentinel: human action required.
            # Treat as a soft pass — the chain continues; cracked material
            # is expected to be injected into loot by the operator later.
            if exit_code == 2:
                await _publish_chain_event(redis, chain_id, "step_waiting", {
                    "step": idx, "technique": technique_id,
                    "message": "Awaiting manual action (e.g. hash cracking). Chain continues.",
                })
            elif exit_code != 0:
                async with AsyncSessionLocal() as db:
                    chain = await db.get(AttackChain, uuid.UUID(chain_id))
                    if chain and chain.status != ChainStatus.STOPPED:
                        chain.status = ChainStatus.FAILED
                        chain.completed_at = _utcnow()
                        await db.commit()
                if chain and chain.status == ChainStatus.STOPPED:
                    return
                await _publish_chain_event(redis, chain_id, "chain_failed", {
                    "step": idx, "exit_code": exit_code,
                    "technique": technique_id,
                })
                return

            await _publish_chain_event(redis, chain_id, "step_completed", {
                "step": idx, "technique": technique_id, "exit_code": exit_code,
            })

        async with AsyncSessionLocal() as db:
            chain = await db.get(AttackChain, uuid.UUID(chain_id))
            if chain and chain.status == ChainStatus.RUNNING:
                chain.status = ChainStatus.COMPLETED
                chain.completed_at = _utcnow()
                await db.commit()

        await _publish_chain_event(redis, chain_id, "chain_completed", {
            "total_steps": len(steps), "message": "Domain compromise complete",
        })

    except Exception as exc:
        log.exception("Chain %s runner error: %s", chain_id, exc)
        try:
            async with AsyncSessionLocal() as db:
                chain = await db.get(AttackChain, uuid.UUID(chain_id))
                if chain:
                    chain.status = ChainStatus.FAILED
                    chain.completed_at = _utcnow()
                    await db.commit()
            await _publish_chain_event(redis, chain_id, "chain_failed", {"error": str(exc)})
        except Exception:
            pass
    finally:
        await redis.aclose()


async def _run_step(
    chain_id: str,
    step_index: int,
    step: dict,
    params: dict,
    owner_id: UUID,
    opsec: OpsecProfile,
    redis,
    job_id: UUID | None = None,
) -> UUID:
    technique_id = step["technique_id"]
    target = step.get("target", "")

    async with AsyncSessionLocal() as db:
        job = OffensiveJob(
            id=job_id or uuid.uuid4(),
            technique_id=technique_id,
            target=target,
            params=params,
            executor="impacket",
            opsec_profile=opsec,
            status=OffensiveJobStatus.PENDING,
            owner_user_id=owner_id,
            created_at=_utcnow(),
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        job_id = job.id
        job_id_str = str(job_id)

    await _publish_chain_event(redis, chain_id, "step_started", {
        "step": step_index,
        "technique": technique_id,
        "label": step.get("label", technique_id),
        "job_id": job_id_str,
        "target": target,
    })

    step_redis = _get_redis()
    _step_redis_closed = False
    pool = get_pool()
    worker = ImpacketWorker()

    async def _close_step_redis():
        nonlocal _step_redis_closed
        if not _step_redis_closed:
            _step_redis_closed = True
            try:
                await step_redis.aclose()
            except Exception:
                pass

    async def emit(data: dict):
        data["job_id"] = job_id_str
        await publish_line(step_redis, job_id_str, data)
        if data.get("stream") == "loot":
            loot_type = data.get("loot_type", "unknown")
            loot_data = data.get("data", "")
            async with _get_chain_lock(chain_id):
                async with AsyncSessionLocal() as loot_db:
                    c = await loot_db.get(AttackChain, uuid.UUID(chain_id))
                    if c:
                        merged = dict(c.loot or {})
                        bucket = list(merged.get(loot_type, []))
                        bucket.append(loot_data)
                        merged[loot_type] = bucket
                        c.loot = merged
                        await loot_db.commit()
            await _publish_chain_event(redis, chain_id, "loot_captured", {
                "loot_type": loot_type, "value": loot_data, "step": step_index,
            })
        line = data.get("line")
        if line:
            async with AsyncSessionLocal() as emit_db:
                emit_db.add(JobOutput(
                    id=uuid.uuid4(),
                    job_id=job_id,
                    stream=data.get("stream", "stdout"),
                    line=line,
                    ts=_utcnow(),
                ))
                await emit_db.commit()
        if data.get("done"):
            exit_code = data.get("exit_code", 1 if data.get("error") else 0)
            new_status = (
                OffensiveJobStatus.COMPLETED
                if not data.get("killed") and exit_code == 0
                else OffensiveJobStatus.FAILED
            )
            async with AsyncSessionLocal() as finish_db:
                j = await finish_db.get(OffensiveJob, job_id)
                if j and j.status == OffensiveJobStatus.RUNNING:
                    j.status = new_status
                    j.completed_at = _utcnow()
                    j.exit_code = exit_code
                    await finish_db.commit()
            await _close_step_redis()

    async with AsyncSessionLocal() as db:
        j = await db.get(OffensiveJob, job_id)
        if j:
            j.status = OffensiveJobStatus.RUNNING
            j.started_at = _utcnow()
            await db.commit()

    try:
        await pool.submit(job_id_str, worker, params, emit)
    except Exception:
        async with AsyncSessionLocal() as failed_db:
            failed_job = await failed_db.get(OffensiveJob, job_id)
            if failed_job and failed_job.status == OffensiveJobStatus.RUNNING:
                failed_job.status = OffensiveJobStatus.FAILED
                failed_job.completed_at = _utcnow()
                failed_job.exit_code = -1
                await failed_db.commit()
        await _close_step_redis()  # close if submit fails
        raise
    return job_id


async def _await_job(
    job_id: UUID,
    redis,
    chain_id: str,
    step_index: int,
    timeout: float = 300.0,
    pubsub=None,
) -> int:
    """Wait for job completion, forwarding output to chain channel. Returns exit_code.

    Accepts a pre-subscribed pubsub to avoid the race condition where a fast-completing
    job publishes done before we can subscribe.
    """
    job_id_str = str(job_id)
    channel = f"job:{job_id_str}:output"
    owns_pubsub = pubsub is None
    if owns_pubsub:
        pubsub = redis.pubsub()
        await pubsub.subscribe(channel)

    exit_code = 0
    try:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                exit_code = 1
                await get_pool().kill(job_id_str)
                async with AsyncSessionLocal() as timeout_db:
                    timed_out = await timeout_db.get(OffensiveJob, job_id)
                    if timed_out and timed_out.status == OffensiveJobStatus.RUNNING:
                        timed_out.status = OffensiveJobStatus.FAILED
                        timed_out.completed_at = _utcnow()
                        timed_out.exit_code = 1
                        await timeout_db.commit()
                break

            message = await pubsub.get_message(
                ignore_subscribe_messages=True,
                timeout=min(1.0, max(remaining, 0.0)),
            )
            if not message:
                continue
            if message["type"] != "message":
                continue
            try:
                data = json.loads(message["data"])
            except (json.JSONDecodeError, TypeError):
                continue

            if data.get("line"):
                await _publish_chain_event(redis, chain_id, "step_output", {
                    "step": step_index,
                    "job_id": job_id_str,
                    "stream": data.get("stream", "stdout"),
                    "line": data["line"],
                    "ts": data.get("ts", ""),
                })

            if data.get("done"):
                exit_code = data.get("exit_code", 1 if data.get("error") else 0)
                break
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()

    return exit_code
