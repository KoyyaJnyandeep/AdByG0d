"""Async CVE checker — runs detection commands and streams output lines."""
from __future__ import annotations

import asyncio
import logging
import re
import shlex
from typing import Callable, Any

log = logging.getLogger(__name__)

VERDICT_PATTERNS = {
    "VULNERABLE": [r"VULNERABLE", r"is vulnerable", r"vulnerable to", r"\[!\]", r"\[+\].*vuln", r"success.*exploit"],
    "NOT_VULNERABLE": [r"NOT VULNERABLE", r"not vulnerable", r"patched", r"mitigated", r"\[-\]"],
    "ERROR": [r"error", r"exception", r"connection refused", r"timed out", r"no route to host"],
}

_SECRET_FLAGS = {"-p", "--password", "-password", "-hashes", "--hashes", "-w", "--bind-password"}


def _redact_token(token: str) -> str:
    if not token:
        return token
    if "@" in token and ":" in token.rsplit("@", 1)[0]:
        principal, host = token.rsplit("@", 1)
        user, _secret = principal.split(":", 1)
        return f"{user}:<redacted>@{host}"
    if token.startswith(":") and re.fullmatch(r":[A-Fa-f0-9]{32,}", token):
        return ":<redacted>"
    if re.fullmatch(r"[A-Fa-f0-9]{32}(:[A-Fa-f0-9]{32})?", token):
        return "<redacted-hash>"
    return token


def _display_cmd(cmd: list[str]) -> str:
    safe: list[str] = []
    redact_next = False
    for token in cmd:
        if redact_next:
            safe.append("<redacted>")
            redact_next = False
            continue
        safe.append(_redact_token(token))
        if token in _SECRET_FLAGS:
            redact_next = True
    return " ".join(shlex.quote(part) for part in safe)

def _detect_verdict(output: str) -> str:
    out_lower = output.lower()
    for verdict, patterns in VERDICT_PATTERNS.items():
        for p in patterns:
            if re.search(p, out_lower, re.IGNORECASE):
                return verdict
    return "UNKNOWN"


async def run_check(
    cve: dict[str, Any],
    params: dict[str, str],
    emit: Callable[[str, str], None],  # (line, type)
    timeout: int = 60,
) -> str:
    """Render the check command, run it, stream output, return verdict."""
    try:
        raw_cmd = cve.get("check_cmd", "")
        cmd = raw_cmd
        for k, v in params.items():
            cmd = cmd.replace(f"{{{k}}}", v)

        # Check for unfilled placeholders
        unfilled = re.findall(r"\{[^}]+\}", cmd)
        if unfilled:
            emit(f"[!] Missing parameters: {', '.join(unfilled)}", "warn")
            return "SKIPPED"

        args = shlex.split(cmd)
        emit(f"[*] Running: {_display_cmd(args)}", "info")
        emit("", "separator")
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        collected: list[str] = []
        try:
            async with asyncio.timeout(timeout):
                assert proc.stdout is not None
                async for raw in proc.stdout:
                    line = raw.decode(errors="replace").rstrip()
                    collected.append(line)
                    emit(line, "output")
            await proc.wait()
        except TimeoutError:
            proc.kill()
            await proc.wait()
            emit("[!] Check timed out", "warn")
            return "TIMEOUT"

        full_output = "\n".join(collected)
        verdict = _detect_verdict(full_output)
        emit("", "separator")
        emit(f"[*] Verdict: {verdict}", "verdict")
        return verdict

    except FileNotFoundError as exc:
        tool = str(exc).split("'")[1] if "'" in str(exc) else "tool"
        emit(f"[!] Tool not found: {tool} — install required tool or use manual check", "error")
        return "TOOL_MISSING"
    except Exception as exc:
        log.exception("CVE check error for %s", cve.get("id"))
        emit(f"[!] Error: {exc}", "error")
        return "ERROR"
