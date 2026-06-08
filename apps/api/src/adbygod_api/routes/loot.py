from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

import asyncio
import uuid as _uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.database import get_db
from adbygod_api.core.loot.hash_intel import CRACK_JOBS, HASHCAT_TO_JOHN, analyze_loot, classify_hash, is_allowed_wordlist_path, start_crack_job
from adbygod_api.core.workers.impacket_worker import ImpacketWorker
from adbygod_api.database import AsyncSessionLocal
from adbygod_api.models import AttackChain, ChainStatus, PlatformUser
from adbygod_api.routes.auth import get_current_user

log = logging.getLogger(__name__)
router = APIRouter(prefix="/loot", tags=["loot"])


_MAX_CRACK_HASHES = 5000
_MAX_CRACK_HASH_CHARS = 4096
_ALLOWED_CRACK_TOOLS = {"hashcat", "john", "auto"}


class CrackRequest(BaseModel):
    hashes: list[str] = Field(default_factory=list, max_length=_MAX_CRACK_HASHES)
    hashcat_mode: int
    wordlist: str | None = None
    tool: str | None = Field(default=None, description="hashcat | john | auto")
    acknowledge_authorized: bool = False

    @field_validator("hashes")
    @classmethod
    def validate_hashes(cls, hashes: list[str]) -> list[str]:
        cleaned = [str(item).strip() for item in hashes if str(item).strip()]
        if len(cleaned) > _MAX_CRACK_HASHES:
            raise ValueError(f"At most {_MAX_CRACK_HASHES} hashes can be submitted at once")
        if any(len(item) > _MAX_CRACK_HASH_CHARS for item in cleaned):
            raise ValueError(f"Each hash must be at most {_MAX_CRACK_HASH_CHARS} characters")
        return cleaned

    @field_validator("hashcat_mode")
    @classmethod
    def validate_hashcat_mode(cls, mode: int) -> int:
        if mode not in HASHCAT_TO_JOHN:
            raise ValueError("Unsupported hashcat mode")
        return mode

    @field_validator("tool")
    @classmethod
    def validate_tool(cls, tool: str | None) -> str | None:
        if tool is None:
            return None
        normalized = tool.strip().lower()
        if normalized not in _ALLOWED_CRACK_TOOLS:
            raise ValueError("tool must be one of: hashcat, john, auto")
        return normalized

    @field_validator("wordlist")
    @classmethod
    def validate_wordlist(cls, wordlist: str | None) -> str | None:
        if wordlist in (None, ""):
            return None
        cleaned = str(wordlist).strip()
        if not is_allowed_wordlist_path(cleaned):
            raise ValueError("wordlist must be under an approved wordlist directory")
        return cleaned


def _flatten_chain_loot(chain: AttackChain) -> list[dict[str, Any]]:
    """Convert a chain's loot dict to a flat list of typed entries."""
    entries: list[dict[str, Any]] = []
    loot: dict[str, Any] = chain.loot or {}
    for loot_type, items in loot.items():
        item_list = items if isinstance(items, list) else [str(items)]
        if not item_list:
            continue
        entries.append({
            "chain_id": str(chain.id),
            "chain_name": chain.name,
            "domain": chain.domain,
            "target": chain.target,
            "loot_type": loot_type,
            "items": item_list,
            "item_count": len(item_list),
            "created_at": chain.created_at.isoformat() if chain.created_at else None,
            "completed_at": chain.completed_at.isoformat() if chain.completed_at else None,
        })
    return entries


@router.get("")
async def list_loot(
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Return all loot entries from attack chains visible to the current user."""
    q = select(AttackChain).order_by(desc(AttackChain.created_at)).limit(limit)
    if not current_user.is_superadmin:
        q = q.where(AttackChain.owner_user_id == current_user.id)
    chains = (await db.execute(q)).scalars().all()

    all_entries: list[dict[str, Any]] = []
    for chain in chains:
        all_entries.extend(_flatten_chain_loot(chain))
    return all_entries


@router.get("/summary")
async def loot_summary(
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Return aggregated loot statistics."""
    q = select(AttackChain).order_by(desc(AttackChain.created_at)).limit(200)
    if not current_user.is_superadmin:
        q = q.where(AttackChain.owner_user_id == current_user.id)
    chains = (await db.execute(q)).scalars().all()

    all_entries: list[dict[str, Any]] = []
    for chain in chains:
        all_entries.extend(_flatten_chain_loot(chain))

    by_type: dict[str, int] = {}
    for entry in all_entries:
        loot_type = entry["loot_type"]
        by_type[loot_type] = by_type.get(loot_type, 0) + entry["item_count"]

    return {
        "total_entries": len(all_entries),
        "total_items": sum(e["item_count"] for e in all_entries),
        "chains_with_loot": len({e["chain_id"] for e in all_entries}),
        "by_type": by_type,
    }


@router.get("/hash-intel")
async def hash_intel(
    limit: int = Query(200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Classify loot hashes and report local cracking tool readiness."""
    q = select(AttackChain).order_by(desc(AttackChain.created_at)).limit(limit)
    if not current_user.is_superadmin:
        q = q.where(AttackChain.owner_user_id == current_user.id)
    chains = (await db.execute(q)).scalars().all()

    # Collect manual-hash metadata for principal/source overrides
    manual_meta: dict[str, dict[str, Any]] = {}
    for chain in chains:
        if chain.loot and "manual_meta" in chain.loot:
            manual_meta.update(chain.loot["manual_meta"])

    entries: list[dict[str, Any]] = []
    for chain in chains:
        entries.extend(_flatten_chain_loot(chain))

    result = analyze_loot(entries)

    # Apply per-hash principal/source overrides from manual vault metadata
    if manual_meta:
        for h in result.get("hash_items", []):
            meta = manual_meta.get(h.get("hash", ""))
            if meta:
                if meta.get("principal"):
                    h["principal"] = meta["principal"]
                if meta.get("source"):
                    h["source"] = meta["source"]
        # Mirror overrides into the nested hashes section
        hashes_section = result.get("hashes")
        if isinstance(hashes_section, dict):
            for h in hashes_section.get("items", []):
                meta = manual_meta.get(h.get("hash", ""))
                if meta:
                    if meta.get("principal"):
                        h["principal"] = meta["principal"]
                    if meta.get("source"):
                        h["source"] = meta["source"]

    return result


@router.post("/crack/start", status_code=status.HTTP_202_ACCEPTED)
async def start_hash_crack(
    req: CrackRequest,
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Start an explicit local cracking job for selected hashes."""
    from adbygod_api.core.privileged_operations import require_dangerous_action_allowed, DangerousAction
    await require_dangerous_action_allowed(DangerousAction.CREDENTIAL_HANDLING, current_user)
    if not req.acknowledge_authorized:
        raise HTTPException(status_code=400, detail="Explicit authorized-use acknowledgement is required")
    intel = analyze_loot([])
    wordlist = req.wordlist or intel["tools"].get("default_wordlist")
    if not wordlist:
        raise HTTPException(status_code=400, detail="No wordlist provided and rockyou.txt was not found")
    try:
        job = await start_crack_job(
            owner_user_id=str(current_user.id),
            hashes=req.hashes,
            mode=req.hashcat_mode,
            wordlist=wordlist,
            tool=None if req.tool in (None, "auto") else req.tool,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "job_id": job.id,
        "status": job.status,
        "tool": job.tool,
        "mode": job.mode,
        "wordlist": job.wordlist,
    }


@router.get("/crack/{job_id}")
async def get_hash_crack_job(
    job_id: str,
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    job = CRACK_JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Crack job not found")
    if not current_user.is_superadmin and job.owner_user_id != str(current_user.id):
        raise HTTPException(status_code=403, detail="Forbidden")
    return {
        "job_id": job.id,
        "status": job.status,
        "tool": job.tool,
        "mode": job.mode,
        "wordlist": job.wordlist,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "error": job.error,
        "output": job.output[-200:],
        "cracked": job.cracked,
    }


@router.get("/export")
async def export_loot(
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> Response:
    """Export all loot as a JSON download."""
    q = select(AttackChain).order_by(desc(AttackChain.created_at)).limit(200)
    if not current_user.is_superadmin:
        q = q.where(AttackChain.owner_user_id == current_user.id)
    chains = (await db.execute(q)).scalars().all()

    all_entries: list[dict[str, Any]] = []
    for chain in chains:
        all_entries.extend(_flatten_chain_loot(chain))

    content = json.dumps(all_entries, indent=2, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=adbygod-loot-export.json"},
    )


_MANUAL_VAULT_NAME = "__manual_hash_vault__"


class ManualHashRequest(BaseModel):
    hash: str = Field(..., min_length=1, max_length=4096)
    principal: str | None = Field(default=None, max_length=255)
    source: str = Field(default="Manual Entry", max_length=128)


@router.post("/hash/manual", status_code=201)
async def add_manual_hash(
    req: ManualHashRequest,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Add a single hash manually to the vault for analysis and cracking."""
    value = req.hash.strip()
    classified = classify_hash(value, {"principal": req.principal})
    if not classified:
        raise HTTPException(status_code=400, detail="Could not classify hash. Supported: NT (32-hex or LM:NT), Net-NTLMv2 (::), Kerberoast ($krb5tgs$), AS-REP ($krb5asrep$), DCC2 ($dcc2$).")

    # Find or create the manual vault chain for this user
    q = (
        select(AttackChain)
        .where(AttackChain.owner_user_id == current_user.id)
        .where(AttackChain.name == _MANUAL_VAULT_NAME)
        .limit(1)
    )
    chain = (await db.execute(q)).scalar_one_or_none()
    if chain is None:
        chain = AttackChain(
            name=_MANUAL_VAULT_NAME,
            owner_user_id=current_user.id,
            status=ChainStatus.COMPLETED,
            target="Manual Hash Vault",
            domain=req.principal.split("\\")[0] if req.principal and "\\" in req.principal else None,
        )
        db.add(chain)
        await db.flush()

    loot: dict[str, Any] = dict(chain.loot or {})
    # Hashes stored as strings; metadata stored separately keyed by hash
    existing: list[str] = [str(i) for i in loot.get("manual_hashes", []) if i]
    metadata: dict[str, Any] = dict(loot.get("manual_meta", {}))

    # Deduplicate
    if classified["hash"] in existing:
        raise HTTPException(status_code=409, detail="Hash already exists in the vault.")

    existing.append(classified["hash"])
    metadata[classified["hash"]] = {
        "principal": req.principal or None,
        "source": req.source or "Manual Entry",
    }
    loot["manual_hashes"] = existing
    loot["manual_meta"] = metadata
    chain.loot = loot
    await db.commit()

    classified.update({
        "source": req.source or classified["source"],
        "principal": req.principal or classified.get("principal"),
        "chain_name": req.source or "Manual Hash Vault",
    })
    return {
        "added": True,
        "hash": classified,
        "chain_id": str(chain.id),
    }


_COLLECT_CHAIN_NAME = "__hash_collector__"
_COLLECT_TECHNIQUES = {"dcsync", "secretsdump", "kerberoast", "asreproast", "laps_dump", "gmsa_dump"}

# Maps loot_type emitted by worker → human label for SSE events
_LOOT_LABELS: dict[str, str] = {
    "nt_hashes":      "NT Hash",
    "krbtgt_hash":    "krbtgt NT",
    "da_hashes":      "DA NT Hash",
    "kerberos_hash":  "Kerberoast TGS",
    "asrep_hash":     "AS-REP Hash",
    "cleartext_creds":"Cleartext",
}


class CollectRequest(BaseModel):
    techniques: list[str] = Field(..., min_length=1)
    target: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(..., min_length=1, max_length=255)
    username: str = Field(default="", max_length=255)
    password: str = Field(default="", max_length=512)
    hashes: str = Field(default="", max_length=512)       # LM:NT or :NT
    dc_ip: str = Field(default="", max_length=255)

    @field_validator("techniques")
    @classmethod
    def validate_techniques(cls, v: list[str]) -> list[str]:
        bad = [t for t in v if t not in _COLLECT_TECHNIQUES]
        if bad:
            raise ValueError(f"Unknown technique(s): {bad}. Allowed: {sorted(_COLLECT_TECHNIQUES)}")
        return v


@router.post("/collect")
async def collect_hashes(
    req: CollectRequest,
    current_user: PlatformUser = Depends(get_current_user),
) -> StreamingResponse:
    """SSE stream — run one or more hash-collection techniques against a live AD target."""
    from adbygod_api.core.privileged_operations import require_dangerous_action_allowed, DangerousAction
    await require_dangerous_action_allowed(DangerousAction.CREDENTIAL_HANDLING, current_user)

    user_id = current_user.id

    async def event_generator():
        total_captured = 0

        # Resolve or create the collector vault chain
        async with AsyncSessionLocal() as db:
            q = (
                select(AttackChain)
                .where(AttackChain.owner_user_id == user_id)
                .where(AttackChain.name == _COLLECT_CHAIN_NAME)
                .limit(1)
            )
            chain = (await db.execute(q)).scalar_one_or_none()
            if chain is None:
                chain = AttackChain(
                    name=_COLLECT_CHAIN_NAME,
                    owner_user_id=user_id,
                    status=ChainStatus.COMPLETED,
                    target=req.target,
                    domain=req.domain,
                )
                db.add(chain)
                await db.flush()
                await db.refresh(chain)
            chain_id = str(chain.id)
            await db.commit()

        yield f"data: {json.dumps({'type': 'session_start', 'chain_id': chain_id, 'techniques': req.techniques})}\n\n"

        for technique in req.techniques:
            job_id = str(_uuid.uuid4())
            params = {
                "technique": technique,
                "target": req.target,
                "domain": req.domain,
                "username": req.username,
                "password": req.password,
                "hashes": req.hashes,
                "dc_ip": req.dc_ip or req.target,
            }

            yield f"data: {json.dumps({'type': 'technique_start', 'technique': technique, 'job_id': job_id})}\n\n"

            # Queue bridges worker emit() → generator yield
            queue: asyncio.Queue = asyncio.Queue()

            async def emit(data: dict, _q: asyncio.Queue = queue) -> None:
                await _q.put(data)

            worker = ImpacketWorker()

            async def run_worker(t=technique, p=params, j=job_id, _w=worker, _emit=emit):
                try:
                    await _w.execute(j, p, _emit)
                except Exception as exc:
                    await _emit({"stream": "stderr", "line": f"[!] Worker error: {exc}", "ts": ""})
                finally:
                    await _emit({"__done__": True})

            task = asyncio.create_task(run_worker())
            captured_this_run: list[dict] = []

            try:
                while True:
                    try:
                        data = await asyncio.wait_for(queue.get(), timeout=300.0)
                    except asyncio.TimeoutError:
                        yield f"data: {json.dumps({'type': 'error', 'message': 'Technique timed out after 5 minutes'})}\n\n"
                        task.cancel()
                        break

                    if data.get("__done__"):
                        break

                    # Forward output line to client
                    if data.get("line"):
                        yield f"data: {json.dumps({'type': 'output', 'stream': data.get('stream', 'stdout'), 'line': data['line']})}\n\n"

                    # Capture and store loot
                    if data.get("stream") == "loot":
                        loot_type: str = data.get("loot_type", "unknown")
                        loot_data: str = str(data.get("data", ""))

                        # Store to collector chain
                        try:
                            async with AsyncSessionLocal() as db:
                                c = await db.get(AttackChain, _uuid.UUID(chain_id))
                                if c:
                                    merged = dict(c.loot or {})
                                    bucket = list(merged.get(loot_type, []))
                                    bucket.append(loot_data)
                                    merged[loot_type] = bucket
                                    # Also store in manual_hashes so hash-intel picks them up
                                    if loot_type in ("nt_hashes", "krbtgt_hash", "da_hashes"):
                                        lines = [ln.strip() for ln in loot_data.splitlines() if ln.strip()]
                                        for ln in lines:
                                            # Extract bare NT hash (last 32-hex field from secretsdump line)
                                            import re as _re
                                            m = _re.match(r"[^:]+:\d+:[a-fA-F0-9]{32}:([a-fA-F0-9]{32}):::", ln)
                                            if m:
                                                lm_nt = f"aad3b435b51404eeaad3b435b51404ee:{m.group(1)}"
                                                existing = list(merged.get("manual_hashes", []))
                                                if lm_nt not in existing:
                                                    existing.append(lm_nt)
                                                    merged["manual_hashes"] = existing
                                                    meta = dict(merged.get("manual_meta", {}))
                                                    # Extract username from secretsdump line: user:RID:...
                                                    parts = ln.split(":")
                                                    username_from = parts[0] if parts else ""
                                                    meta[lm_nt] = {
                                                        "principal": f"{req.domain}\\{username_from}" if username_from else None,
                                                        "source": f"Collector — {technique}",
                                                    }
                                                    merged["manual_meta"] = meta
                                            elif _re.fullmatch(r"[a-fA-F0-9]{32}", ln):
                                                # bare NT hash
                                                lm_nt = f"aad3b435b51404eeaad3b435b51404ee:{ln}"
                                                existing = list(merged.get("manual_hashes", []))
                                                if lm_nt not in existing:
                                                    existing.append(lm_nt)
                                                    merged["manual_hashes"] = existing
                                                    meta = dict(merged.get("manual_meta", {}))
                                                    meta[lm_nt] = {"principal": None, "source": f"Collector — {technique}"}
                                                    merged["manual_meta"] = meta
                                    elif loot_type in ("kerberos_hash", "asrep_hash"):
                                        # Store Kerberoast/AS-REP hashes directly as manual hashes
                                        lines = [ln.strip() for ln in loot_data.splitlines() if ln.strip() and "$krb5" in ln.lower()]
                                        for ln in lines:
                                            existing = list(merged.get("manual_hashes", []))
                                            if ln not in existing:
                                                existing.append(ln)
                                                merged["manual_hashes"] = existing
                                                meta = dict(merged.get("manual_meta", {}))
                                                meta[ln] = {"principal": None, "source": f"Collector — {technique}"}
                                                merged["manual_meta"] = meta
                                    c.loot = merged
                                    await db.commit()
                        except Exception as _loot_exc:
                            log.warning("Loot capture DB write failed: %s", _loot_exc)
                            yield f"data: {json.dumps({'type': 'error', 'message': f'Loot storage failed: {_loot_exc}', 'loot_type': loot_type})}\n\n"

                        label = _LOOT_LABELS.get(loot_type, loot_type)
                        count = len([ln for ln in loot_data.splitlines() if ln.strip()])
                        captured_this_run.append({"loot_type": loot_type, "label": label, "count": count})
                        total_captured += count
                        yield f"data: {json.dumps({'type': 'loot_captured', 'loot_type': loot_type, 'label': label, 'count': count, 'total': total_captured})}\n\n"

            finally:
                if not task.done():
                    task.cancel()
                    try:
                        await asyncio.wait_for(task, timeout=5.0)
                    except (asyncio.CancelledError, asyncio.TimeoutError):
                        pass

            yield f"data: {json.dumps({'type': 'technique_done', 'technique': technique, 'captured': captured_this_run})}\n\n"

        yield f"data: {json.dumps({'type': 'session_done', 'total_captured': total_captured, 'chain_id': chain_id})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.delete("/{chain_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def clear_chain_loot(
    chain_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: PlatformUser = Depends(get_current_user),
) -> None:
    """Clear loot from a specific attack chain."""
    chain = await db.get(AttackChain, chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Chain not found")
    if not current_user.is_superadmin and chain.owner_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    chain.loot = {}
    await db.commit()
