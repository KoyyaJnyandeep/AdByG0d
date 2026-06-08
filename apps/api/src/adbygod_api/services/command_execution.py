"""Shared command execution service — used by both AI exec tools and /ad-commands route."""
from __future__ import annotations
import asyncio
import logging
import re
import shlex
import shutil
from dataclasses import dataclass
from typing import Any

from adbygod_api.config import settings
from adbygod_api.data.ad_commands import AD_COMMANDS

log = logging.getLogger(__name__)

# Output caps
_STDOUT_CAP = 8000
_STDERR_CAP = 2000
_TIMEOUT_SECONDS = 120
_MAX_PARAMS = 100
_MAX_PARAM_NAME_CHARS = 128
_MAX_PARAM_VALUE_CHARS = 4096

_MANUAL_TEMPLATE_SYNTAX_RE = re.compile(r"(\|\||&&|[|;<>`$]|\r|\n)")
_MANUAL_WORD_RE = re.compile(r"\b(powershell|pwsh|cmd\.exe|cmd|forfiles|wmic)\b", re.IGNORECASE)


def _command_execution_mode(command: str) -> str:
    """Return argv only for commands safe to run without a shell."""
    if _MANUAL_TEMPLATE_SYNTAX_RE.search(command) or _MANUAL_WORD_RE.search(command):
        return "manual"
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return "manual"
    return "argv" if argv else "manual"


def _validate_params(params: dict[str, Any] | None) -> dict[str, str]:
    """Normalize and bound command template params for every execution caller."""
    raw_params = params or {}
    if not isinstance(raw_params, dict):
        raise ValueError("Command parameters must be an object")
    if len(raw_params) > _MAX_PARAMS:
        raise ValueError("Too many command parameters")
    cleaned: dict[str, str] = {}
    for key, raw in raw_params.items():
        key_text = str(key)
        value_text = str(raw)
        if len(key_text) > _MAX_PARAM_NAME_CHARS:
            raise ValueError("Command parameter name is too long")
        if len(value_text) > _MAX_PARAM_VALUE_CHARS:
            raise ValueError(f"Command parameter {key_text!r} is too long")
        cleaned[key_text] = value_text
    return cleaned

# Redaction patterns — ordered most-specific to least-specific
_REDACT_PATTERNS = [
    re.compile(r'(?i)(password|passwd|secret|token|key)\s*[:=]\s*\S+'),
    re.compile(r'sk-[A-Za-z0-9]{20,}'),
]


def _redact(text: str) -> str:
    """Replace sensitive patterns with [REDACTED]."""
    for pat in _REDACT_PATTERNS:
        text = pat.sub('[REDACTED]', text)
    return text


@dataclass
class ExecutionResult:
    technique_id: str | None = None
    command: str | None = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    error: str | None = None
    blocked: bool = False
    audit_event: str = "unknown"


async def execute_technique(
    *,
    technique_id: str,
    command_index: int = 0,
    params: dict[str, str] | None = None,
    current_user: Any,
    audit_fn=None,
    allowlist: list[str] | None = None,
    _rendered_command: str | None = None,
) -> ExecutionResult:
    """
    Optional _rendered_command: if the caller has already rendered the command
    (e.g. using route-level shlex.quote-based rendering for injection safety),
    pass it here to skip the service's own template substitution.
    The service will still enforce all policy checks (flags, superadmin, allowlist,
    execution_mode) and run the output caps + redaction pipeline.
    """
    """
    Shared execution entry point.

    Policy:
    1. ENABLE_COMMAND_EXECUTION must be True
    2. current_user must be superadmin
    3. technique_id must be in AD_COMMANDS
    4. If COMMAND_EXECUTION_ALLOWLIST is set, technique_id must be in it
    5. Command must have execution_mode != 'manual'/'shell-only'
    6. Executable must exist on system
    7. Timeout: _TIMEOUT_SECONDS
    8. Output capped at _STDOUT_CAP / _STDERR_CAP
    9. Output redacted
    10. Audit logged
    """
    try:
        params = _validate_params(params)
    except ValueError as exc:
        result = ExecutionResult(
            technique_id=technique_id,
            error=str(exc),
            blocked=True,
            audit_event="execution.blocked.invalid_params",
        )
        if audit_fn:
            await _audit(audit_fn, result, current_user)
        return result

    try:
        command_index = int(command_index)
    except (TypeError, ValueError):
        result = ExecutionResult(
            technique_id=technique_id,
            error="Command index must be an integer.",
            blocked=True,
            audit_event="execution.blocked.invalid_index",
        )
        if audit_fn:
            await _audit(audit_fn, result, current_user)
        return result

    # Check feature flag
    if not settings.ENABLE_COMMAND_EXECUTION:
        result = ExecutionResult(
            technique_id=technique_id,
            error="Command execution is disabled. Set ENABLE_COMMAND_EXECUTION=true to enable.",
            blocked=True,
            audit_event="execution.blocked.flag_disabled",
        )
        if audit_fn:
            await _audit(audit_fn, result, current_user)
        return result

    # Check superadmin
    if not getattr(current_user, 'is_superadmin', False):
        result = ExecutionResult(
            technique_id=technique_id,
            error="Command execution requires superadmin privileges.",
            blocked=True,
            audit_event="execution.blocked.not_superadmin",
        )
        if audit_fn:
            await _audit(audit_fn, result, current_user)
        return result

    # Resolve allowlist from settings if not overridden
    effective_allowlist = allowlist
    if effective_allowlist is None:
        effective_allowlist = list(settings.command_execution_allowlist)

    if not effective_allowlist:
        result = ExecutionResult(
            technique_id=technique_id,
            error="No techniques are allowlisted for execution.",
            blocked=True,
            audit_event="execution.blocked.empty_allowlist",
        )
        if audit_fn:
            await _audit(audit_fn, result, current_user)
        return result

    if "*" not in effective_allowlist and technique_id not in effective_allowlist:
        result = ExecutionResult(
            technique_id=technique_id,
            error=f"Technique {technique_id!r} is not in the execution allowlist.",
            blocked=True,
            audit_event="execution.blocked.not_in_allowlist",
        )
        if audit_fn:
            await _audit(audit_fn, result, current_user)
        return result

    # Find technique
    technique = next((t for t in AD_COMMANDS if t["id"] == technique_id), None)
    if not technique:
        return ExecutionResult(
            technique_id=technique_id,
            error=f"Technique {technique_id!r} not found in catalog.",
            blocked=True,
            audit_event="execution.blocked.technique_not_found",
        )

    # Check execution mode
    commands = technique.get("commands", [])
    if not commands or command_index < 0 or command_index >= len(commands):
        return ExecutionResult(
            technique_id=technique_id,
            error=f"Command index {command_index} out of range.",
            blocked=True,
            audit_event="execution.blocked.invalid_index",
        )

    cmd_def = commands[command_index]
    command_template = cmd_def.get("command", "")
    exec_mode = cmd_def.get("execution_mode", technique.get("execution_mode", ""))
    if exec_mode in ("manual", "shell-only") or _command_execution_mode(command_template) != "argv":
        return ExecutionResult(
            technique_id=technique_id,
            error=f"Technique {technique_id!r} command {command_index} is manual/shell-only and cannot be auto-executed.",
            blocked=True,
            audit_event="execution.blocked.manual_only",
        )

    cmd_platform = cmd_def.get("platform", technique.get("platform", "both"))
    if cmd_platform == "windows":
        return ExecutionResult(
            technique_id=technique_id,
            error="Selected command is Windows-only and cannot be executed here.",
            blocked=True,
            audit_event="execution.blocked.windows_only",
        )

    # Render command — use caller-supplied rendering if provided (preserves caller's quoting policy)
    rendered = _rendered_command if _rendered_command is not None else _render_command(command_template, params)
    unfilled = re.findall(r"\{(\w+)\}", rendered)
    if unfilled:
        return ExecutionResult(
            technique_id=technique_id,
            command=rendered,
            error=f"Missing required parameters: {unfilled}",
            blocked=True,
            audit_event="execution.blocked.missing_params",
        )

    try:
        argv = shlex.split(rendered)
    except ValueError as e:
        return ExecutionResult(
            technique_id=technique_id,
            error=f"Cannot parse command: {e}",
            blocked=True,
            audit_event="execution.blocked.parse_error",
        )

    if not argv:
        return ExecutionResult(
            technique_id=technique_id,
            error="Empty command after rendering.",
            blocked=True,
            audit_event="execution.blocked.empty_command",
        )

    # Check executable exists
    executable = argv[0]
    if not shutil.which(executable):
        result = ExecutionResult(
            technique_id=technique_id,
            command=rendered,
            error=f"Executable not found: {executable}",
            blocked=True,
            audit_event="execution.blocked.executable_not_found",
        )
        if audit_fn:
            await _audit(audit_fn, result, current_user)
        return result

    # Audit: about to execute
    if audit_fn:
        try:
            await audit_fn("execution.started", {
                "technique_id": technique_id,
                "command_index": command_index,
                "user_id": str(getattr(current_user, 'id', '')),
            })
        except Exception:
            pass

    # Execute
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=_TIMEOUT_SECONDS
        )

        stdout = _redact(stdout_bytes.decode("utf-8", errors="replace")[:_STDOUT_CAP])
        stderr = _redact(stderr_bytes.decode("utf-8", errors="replace")[:_STDERR_CAP])

        result = ExecutionResult(
            technique_id=technique_id,
            command=rendered,
            stdout=stdout,
            stderr=stderr,
            exit_code=proc.returncode,
            audit_event="execution.completed",
        )

    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.communicate()
        except ProcessLookupError:
            pass
        except Exception:
            log.exception("Failed to kill timed-out command process")
        result = ExecutionResult(
            technique_id=technique_id,
            command=rendered,
            error=f"Command timed out after {_TIMEOUT_SECONDS} seconds.",
            blocked=False,
            audit_event="execution.timeout",
        )
    except Exception as e:
        result = ExecutionResult(
            technique_id=technique_id,
            command=rendered,
            error=f"Execution error: {type(e).__name__}: {e}",
            blocked=False,
            audit_event="execution.error",
        )

    if audit_fn:
        await _audit(audit_fn, result, current_user)

    return result


def _render_command(template: str, params: dict[str, str]) -> str:
    def replace(m: re.Match[str]) -> str:
        key = m.group(1)
        if key not in params:
            return m.group(0)
        return shlex.quote(str(params[key]))
    return re.sub(r"\{(\w+)\}", replace, template)


async def _audit(audit_fn, result: ExecutionResult, current_user) -> None:
    try:
        await audit_fn(result.audit_event, {
            "technique_id": result.technique_id,
            "exit_code": result.exit_code,
            "blocked": result.blocked,
            "user_id": str(getattr(current_user, 'id', '')),
        })
    except Exception:
        pass
