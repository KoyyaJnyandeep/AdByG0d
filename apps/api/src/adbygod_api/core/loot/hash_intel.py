"""Hash inventory and local cracking helpers for Loot Locker."""

from __future__ import annotations

import asyncio
import hashlib
import json as _json
import logging
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

log = logging.getLogger(__name__)

_background_tasks: set[asyncio.Task] = set()

def _fire_task(coro) -> asyncio.Task:
    t = asyncio.create_task(coro)
    _background_tasks.add(t)
    t.add_done_callback(_background_tasks.discard)
    return t

_CRACK_JOB_TTL = 86_400  # 24 h


EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"

def _app_tools_dir() -> Path:
    """Return the tools/ directory next to the frozen EXE (or empty Path on dev)."""
    import sys
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent / "tools"
    return Path()


ROCKYOU_PATHS = [
    # Linux / Kali
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt",
    # Windows bundled (resolved at import time — safe because Path("") / x == Path(x))
    str(_app_tools_dir() / "wordlists" / "rockyou.txt"),
    # Windows common user-supplied locations
    r"C:\tools\wordlists\rockyou.txt",
    r"C:\wordlists\rockyou.txt",
]

HASHCAT_TO_JOHN = {
    1000: "NT",
    3000: "LM",
    5500: "netntlm",
    5600: "netntlmv2",
    13100: "krb5tgs",
    18200: "krb5asrep",
    19700: "krb5tgs",
    2100: "mscash2",
    1100: "mscash",
}


@dataclass
class CrackJob:
    id: str
    owner_user_id: str
    status: str = "QUEUED"
    tool: str | None = None
    mode: int | None = None
    wordlist: str | None = None
    started_at: float | None = None
    completed_at: float | None = None
    error: str | None = None
    output: list[str] = field(default_factory=list)
    cracked: list[dict[str, str]] = field(default_factory=list)


CRACK_JOBS: dict[str, CrackJob] = {}


# ─── Redis persistence helpers ─────────────────────────────────────────────────

def _job_to_dict(job: CrackJob) -> dict[str, Any]:
    return {
        "id": job.id,
        "owner_user_id": job.owner_user_id,
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


def _dict_to_job(data: dict[str, Any]) -> CrackJob:
    job = CrackJob(
        id=data["id"],
        owner_user_id=data["owner_user_id"],
        status=data.get("status", "COMPLETED"),
        tool=data.get("tool"),
        mode=data.get("mode"),
        wordlist=data.get("wordlist"),
        started_at=data.get("started_at"),
        completed_at=data.get("completed_at"),
        error=data.get("error"),
        output=data.get("output") or [],
        cracked=data.get("cracked") or [],
    )
    # A job in a live-execution state can't survive a restart
    if job.status in ("RUNNING", "QUEUED"):
        job.status = "FAILED"
        job.error = "Server restarted while job was in progress"
        job.completed_at = job.completed_at or time.time()
    return job


async def _redis_save(job: CrackJob) -> None:
    try:
        import redis.asyncio as aioredis
        from adbygod_api.config import settings
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            await r.setex(f"crack_job:{job.id}", _CRACK_JOB_TTL, _json.dumps(_job_to_dict(job)))
        finally:
            await r.aclose()
    except Exception:
        pass  # Redis unavailable — in-memory dict is still the primary store


async def recover_crack_jobs() -> None:
    """Load crack jobs persisted in Redis into CRACK_JOBS. Called at startup."""
    try:
        import redis.asyncio as aioredis
        from adbygod_api.config import settings
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            keys = await r.keys("crack_job:*")
            recovered = 0
            for key in keys:
                raw = await r.get(key)
                if not raw:
                    continue
                try:
                    job = _dict_to_job(_json.loads(raw))
                    if job.id not in CRACK_JOBS:
                        CRACK_JOBS[job.id] = job
                        recovered += 1
                except Exception:
                    pass
            if recovered:
                log.info("Recovered %d crack job(s) from Redis", recovered)
        finally:
            await r.aclose()
    except Exception:
        log.debug("Could not recover crack jobs from Redis (Redis unavailable?)")


def _which_tool(name: str) -> str | None:
    """Find tool binary — checks PATH first, then EXE-sibling tools/ dir."""
    found = shutil.which(name)
    if found:
        return found
    # Windows frozen EXE: check tools/ subdir next to the executable
    candidate = _app_tools_dir() / (name + (".exe" if os.name == "nt" else ""))
    if candidate.exists():
        return str(candidate)
    return None


def _safe_resolve(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def is_allowed_wordlist_path(path: str) -> bool:
    """Limit user-supplied wordlists to expected wordlist locations.

    This prevents the API from being used as a local-file existence oracle or
    from feeding arbitrary server files into cracking subprocesses.
    """
    if not path or "\x00" in str(path):
        return False
    candidate = _safe_resolve(path)
    allowed_exact = {_safe_resolve(p) for p in ROCKYOU_PATHS if p}
    allowed_dirs = [
        _safe_resolve("/usr/share/wordlists"),
        _safe_resolve("/usr/share/seclists"),
        _safe_resolve("/opt/SecLists"),
    ]
    app_tools = _app_tools_dir()
    if str(app_tools):
        allowed_dirs.append(_safe_resolve(app_tools / "wordlists"))
    if candidate in allowed_exact:
        return True
    return any(candidate == base or base in candidate.parents for base in allowed_dirs)


def detect_tools() -> dict[str, Any]:
    hashcat = _which_tool("hashcat")
    john = _which_tool("john")
    default_wordlist = next((path for path in ROCKYOU_PATHS if Path(path).exists()), None)
    wordlist_candidates = [path for path in ROCKYOU_PATHS if Path(path).exists()]

    # Keep both API shapes:
    # - nested: current frontend/API shape, e.g. tools.hashcat.present
    # - flat: legacy/report/test shape, e.g. tools.hashcat_available
    return {
        "hashcat": {"present": bool(hashcat), "path": hashcat},
        "john": {"present": bool(john), "path": john},
        "hashcat_available": bool(hashcat),
        "hashcat_path": hashcat,
        "john_available": bool(john),
        "john_path": john,
        "default_wordlist": default_wordlist,
        "wordlist_candidates": wordlist_candidates,
    }


def _iter_loot_items(entry: dict[str, Any]):
    for item in entry.get("items", []) or []:
        if isinstance(item, dict):
            yield item
            for key in ("hash", "value", "secret", "credential", "password_hash"):
                value = item.get(key)
                if isinstance(value, str):
                    yield value
        elif isinstance(item, str):
            yield item


def _hash_id(value: str) -> str:
    # Use SHA-256 for deterministic IDs across Python sessions (hash() is randomized).
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def classify_hash(value: Any, context: dict[str, Any] | None = None) -> dict[str, Any] | None:
    context = context or {}
    if isinstance(value, dict):
        if value.get("nt") and re.fullmatch(r"[0-9a-fA-F]{32}", str(value["nt"])):
            lm = str(value.get("lm") or EMPTY_LM)
            nt = str(value["nt"])
            return {
                "id": _hash_id(f"{lm}:{nt}"),
                "hash": f"{lm}:{nt}",
                "principal": f"{value.get('domain', context.get('domain') or '')}\\{value.get('user', '')}".strip("\\"),
                "source": "SAM/NTDS/DCSync",
                "hash_type": "NT Hash",
                "hashcat_mode": 1000,
                "john_format": HASHCAT_TO_JOHN[1000],
                "crackable": nt.lower() != EMPTY_NT,
                "pass_the_hash_ready": True,
                "severity": "CRITICAL" if str(value.get("user", "")).lower() in {"administrator", "krbtgt"} else "HIGH",
                "notes": "NT hash from SAM, NTDS.dit, LSASS, or DCSync. It can be used directly for pass-the-hash in authorized labs.",
            }
        return None

    text = str(value).strip()
    if not text:
        return None

    if "$krb5asrep$" in text.lower():
        return _typed(text, "AS-REP (Kerberos)", 18200, "AS-REP Roasting", "HIGH", "Pre-auth disabled account material; RC4 is usually faster to crack.")
    if "$krb5tgs$17$" in text.lower() or "$krb5tgs$18$" in text.lower():
        return _typed(text, "TGS-REP AES", 19700, "Kerberoasting", "MEDIUM", "AES Kerberoast hash; slower than RC4.")
    if "$krb5tgs$" in text.lower():
        return _typed(text, "TGS-REP RC4", 13100, "Kerberoasting", "HIGH", "RC4 Kerberoast hash; good wordlist/rules candidate.")
    if "$dcc2$" in text.lower() or text.lower().startswith("$dcc2$"):
        return _typed(text, "DCC2 / MSCACHEV2", 2100, "Domain Cached Credentials", "MEDIUM", "Slow PBKDF2 cached domain credential; cannot pass-the-hash.")
    if "::" in text and re.search(r":[0-9a-fA-F]{32}:[0-9a-fA-F]{32,}", text):
        return _typed(text, "Net-NTLMv2", 5600, "Responder/coercion capture", "HIGH", "Offline crackable challenge-response material; cannot pass-the-hash directly.")
    if re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", text):
        lm, nt = text.split(":", 1)
        return _typed(text, "NT Hash", 1000, "SAM/NTDS/LSASS/DCSync", "HIGH", "NT hash pair. Pass-the-hash ready if in scope.", principal=context.get("principal"), pth=nt.lower() != EMPTY_NT)
    if re.fullmatch(r"[0-9a-fA-F]{32}", text):
        return _typed(f"{EMPTY_LM}:{text}", "NT Hash", 1000, "SAM/NTDS/LSASS/DCSync", "HIGH", "Single NT hash normalized with empty LM half.", principal=context.get("principal"), pth=text.lower() != EMPTY_NT)
    return None


def _typed(value: str, hash_type: str, mode: int, source: str, severity: str, notes: str, principal: str | None = None, pth: bool = False) -> dict[str, Any]:
    return {
        "id": _hash_id(value),
        "hash": value,
        "principal": principal,
        "source": source,
        "hash_type": hash_type,
        "hashcat_mode": mode,
        "john_format": HASHCAT_TO_JOHN.get(mode),
        "crackable": True,
        "pass_the_hash_ready": pth,
        "severity": severity,
        "notes": notes,
    }


def analyze_loot(entries: list[dict[str, Any]]) -> dict[str, Any]:
    hashes: list[dict[str, Any]] = []
    seen: set[str] = set()
    source_counts: dict[str, int] = {}
    mode_counts: dict[str, int] = {}
    for entry in entries:
        context = {"domain": entry.get("domain"), "principal": entry.get("target")}
        for raw in _iter_loot_items(entry):
            classified = classify_hash(raw, context)
            if not classified or classified["id"] in seen:
                continue
            seen.add(classified["id"])
            classified.update({
                "chain_id": entry.get("chain_id"),
                "chain_name": entry.get("chain_name"),
                "loot_type": entry.get("loot_type"),
            })
            hashes.append(classified)
            source_counts[classified["source"]] = source_counts.get(classified["source"], 0) + 1
            mode_key = str(classified["hashcat_mode"])
            mode_counts[mode_key] = mode_counts.get(mode_key, 0) + 1

    crackable = [h for h in hashes if h.get("crackable")]
    pth_ready = [h for h in hashes if h.get("pass_the_hash_ready")]
    hashes_section = {
        "items": hashes,
        "total": len(hashes),
        "total_hashes": len(hashes),
        "crackable": len(crackable),
        "crackable_hashes": len(crackable),
        "pass_the_hash_ready": len(pth_ready),
        "by_source": source_counts,
        "by_hashcat_mode": mode_counts,
    }
    return {
        # Section-style shape expected by comprehensive/reporting tests.
        "hashes": hashes_section,
        # Explicit row-list alias for frontend/API consumers.
        "hash_items": hashes,
        # Backwards-compatible top-level counters used by the existing UI.
        "total_hashes": len(hashes),
        "crackable_hashes": len(crackable),
        "pass_the_hash_ready": len(pth_ready),
        "by_source": source_counts,
        "by_hashcat_mode": mode_counts,
        "tools": detect_tools(),
        "deep_dive": [
            {"name": "LSASS Memory", "signals": ["NT hashes", "Kerberos tickets", "WDigest plaintext"], "risk": "CRITICAL"},
            {"name": "SAM Database", "signals": ["local NT hashes", "local admin reuse"], "risk": "HIGH"},
            {"name": "NTDS.dit / DCSync", "signals": ["domain NT hashes", "Kerberos AES keys", "password history"], "risk": "CRITICAL"},
            {"name": "DCC2 Cached Credentials", "signals": ["MSCACHEV2 mode 2100"], "risk": "MEDIUM"},
            {"name": "All-in-one App Secrets", "signals": ["browser", "Wi-Fi", "RDP", "Credential Manager"], "risk": "HIGH"},
            {"name": "RemoteMonologue", "signals": ["Net-NTLMv1/v2"], "risk": "HIGH"},
            {"name": "SCCMDecryptor / goLAPS", "signals": ["NAA", "task sequence", "LAPS"], "risk": "HIGH"},
        ],
    }


async def start_crack_job(owner_user_id: str, hashes: list[str], mode: int, wordlist: str, tool: str | None = None) -> CrackJob:
    if tool is not None:
        tool = str(tool).strip().lower()
        if tool == "auto":
            tool = None
        elif tool not in {"hashcat", "john"}:
            raise ValueError("tool must be one of: hashcat, john, auto")
    if mode not in HASHCAT_TO_JOHN:
        raise ValueError("Unsupported hashcat mode")
    if len(hashes) > 5000:
        raise ValueError("Too many hashes selected")
    if any(len(str(item)) > 4096 for item in hashes):
        raise ValueError("Hash value too long")

    tools = detect_tools()
    selected_tool = tool or ("hashcat" if tools["hashcat"]["present"] else "john" if tools["john"]["present"] else None)
    if not selected_tool:
        raise ValueError("Neither hashcat nor john is installed or available in PATH")
    if selected_tool == "hashcat" and not tools["hashcat"]["present"]:
        raise ValueError("hashcat is not installed or available in PATH")
    if selected_tool == "john" and not tools["john"]["present"]:
        raise ValueError("john is not installed or available in PATH")
    if not wordlist:
        wordlist = tools.get("default_wordlist")
    if not wordlist or not Path(wordlist).exists():
        raise ValueError("Wordlist path does not exist — provide one or install rockyou.txt")
    if not is_allowed_wordlist_path(wordlist):
        raise ValueError("Wordlist path is not in an approved wordlist directory")
    if not hashes:
        raise ValueError("No hashes selected")

    job = CrackJob(id=str(uuid4()), owner_user_id=owner_user_id, status="QUEUED", tool=selected_tool, mode=mode, wordlist=wordlist)
    CRACK_JOBS[job.id] = job
    await _redis_save(job)
    _fire_task(_run_crack_job(job, hashes))
    return job


def _normalize_hashes_for_mode(hashes: list[str], mode: int) -> list[str]:
    """Strip LM prefix from LM:NT pairs for hashcat mode 1000 (NT only)."""
    if mode == 1000:
        normalized = []
        for h in hashes:
            if re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", h):
                normalized.append(h.split(":", 1)[1])  # keep NT half only
            else:
                normalized.append(h)
        return normalized
    return hashes


async def _run_crack_job(job: CrackJob, hashes: list[str]) -> None:
    job.status = "RUNNING"
    job.started_at = time.time()
    await _redis_save(job)
    normalized = _normalize_hashes_for_mode(hashes, job.mode or 0)
    with tempfile.TemporaryDirectory(prefix="adbygod-crack-") as tmp:
        hash_file = Path(tmp) / "hashes.txt"
        hash_file.write_text("\n".join(normalized) + "\n", encoding="utf-8")
        hashcat_bin = _which_tool("hashcat") or "hashcat"
        john_bin = _which_tool("john") or "john"
        if job.tool == "hashcat":
            cmd = [hashcat_bin, "-m", str(job.mode), str(hash_file), str(job.wordlist), "--quiet", "--potfile-disable"]
        else:
            fmt = HASHCAT_TO_JOHN.get(int(job.mode or 0))
            cmd = [john_bin, str(hash_file), f"--wordlist={job.wordlist}"]
            if fmt:
                cmd.insert(1, f"--format={fmt}")
        job.output.append(" ".join(cmd))
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        stdout, _ = await proc.communicate()
        output = stdout.decode(errors="replace")
        job.output.extend(output.splitlines()[-200:])
        if proc.returncode not in (0, 1):
            job.status = "FAILED"
            job.error = f"{job.tool} exited with {proc.returncode}"
        else:
            job.status = "COMPLETED"
            job.cracked = _parse_cracked(output)
    job.completed_at = time.time()
    await _redis_save(job)


def _parse_cracked(output: str) -> list[dict[str, str]]:
    cracked = []
    for line in output.splitlines():
        if ":" not in line or line.lower().startswith(("session.", "status.", "started:", "stopped:")):
            continue
        left, right = line.rsplit(":", 1)
        if left and right:
            cracked.append({"hash": left, "plaintext": right})
    return cracked[-200:]
