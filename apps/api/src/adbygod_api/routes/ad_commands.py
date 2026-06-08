from __future__ import annotations

import logging
import re
import shlex
import shutil

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from adbygod_api.data.ad_commands import (
    AD_CATEGORIES,
    AD_CATEGORY_DESCRIPTIONS,
    AD_COMMANDS,
)
from adbygod_api.config import settings
from adbygod_api.models import PlatformUser
from adbygod_api.core.security.authorization import require_superadmin
from adbygod_api.routes.auth import get_current_user
from adbygod_api.services.command_execution import execute_technique as _svc_execute_technique

log = logging.getLogger(__name__)
router = APIRouter(prefix="/ad-commands", tags=["ad-commands"])


class CommandOut(BaseModel):
    label: str
    command: str
    params: list[str] = Field(default_factory=list)
    platform: str = "both"
    execution_mode: str = "manual"


class TechniqueOut(BaseModel):
    id: str
    category: str
    title: str
    tool: str
    platform: str
    executable_on_linux: bool
    description: str
    risk_level: str
    requires_opt_in: bool
    execution_supported: bool
    execution_disabled_reason: str | None = None
    commands: list[CommandOut]


class CategoryOut(BaseModel):
    name: str
    description: str
    technique_count: int
    linux_executable_count: int


class ExecuteRequest(BaseModel):
    params: dict[str, str] = Field(default_factory=dict)
    command_index: int = 0

    @field_validator("params")
    @classmethod
    def _validate_params(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 100:
            raise ValueError("Too many command parameters")
        cleaned: dict[str, str] = {}
        for key, raw in value.items():
            key_text = str(key)
            value_text = str(raw)
            if len(key_text) > 128:
                raise ValueError("Command parameter name is too long")
            if len(value_text) > 4096:
                raise ValueError(f"Command parameter {key_text!r} is too long")
            cleaned[key_text] = value_text
        return cleaned


class ExecuteResult(BaseModel):
    technique_id: str
    command_label: str
    rendered_command: str
    stdout: str
    stderr: str
    exit_code: int
    tool_available: bool
    execution_mode: str = "argv"


LINUX_TOOL_MAP: dict[str, str] = {
    "bloodhound-python": "bloodhound-python",
    "adalanche": "adalanche",
    "python3": "python3",
    "ldapsearch": "ldapsearch",
    "windapsearch": "windapsearch",
    "adidnsdump": "adidnsdump",
    "smbclient": "smbclient",
    "smbmap": "smbmap",
    "rpcclient": "rpcclient",
    "net": "net",
    "nmap": "nmap",
    "xfreerdp": "xfreerdp",
    "evil-winrm": "evil-winrm",
    "crackmapexec": "crackmapexec",
    "netexec": "nxc",
    "impacket-GetUserSPNs": "GetUserSPNs.py",
    "impacket-GetNPUsers": "GetNPUsers.py",
    "impacket-secretsdump": "secretsdump.py",
    "impacket-wmiexec": "wmiexec.py",
    "impacket-smbexec": "smbexec.py",
    "impacket-psexec": "psexec.py",
    "impacket-ntlmrelayx": "ntlmrelayx.py",
    "impacket-ticketer": "ticketer.py",
    "impacket-getST": "getST.py",
    "impacket-addcomputer": "addcomputer.py",
    "impacket-dacledit": "dacledit.py",
    "impacket-owneredit": "owneredit.py",
    "impacket-rbcd": "rbcd.py",
    "impacket-mssqlclient": "mssqlclient.py",
    "impacket-rpcdump": "rpcdump.py",
    "certipy": "certipy",
    "kerbrute": "kerbrute",
    "hashcat": "hashcat",
    "openssl": "openssl",
}
LINUX_TOOL_MAP_LOWER = {tool.lower(): binary for tool, binary in LINUX_TOOL_MAP.items()}


def _tool_available(tool: str) -> bool:
    normalized_tool = tool.strip().lower()
    binary = LINUX_TOOL_MAP_LOWER.get(normalized_tool, tool.strip())
    return shutil.which(binary) is not None


def _resolve_executable(executable: str) -> str | None:
    normalized = executable.strip().lower()
    binary = LINUX_TOOL_MAP_LOWER.get(normalized, executable.strip())
    return shutil.which(binary)


def _render(template: str, params: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in params:
            return match.group(0)
        return shlex.quote(str(params[key]))

    return re.sub(r"\{(\w+)\}", replace, template)


def _redacted_render(template: str, params: dict[str, str]) -> str:
    _SENSITIVE = {"password", "secret", "token", "hash"}
    return _render(template, {
        k: "[REDACTED]" if any(m in k.lower() for m in _SENSITIVE) else v
        for k, v in params.items()
    })


def _is_linux_executable(technique: dict) -> bool:
    return bool(
        technique.get("executable_on_linux")
        or technique.get("platform") in ("linux", "both")
    )


def _coerce(t: dict) -> dict:
    exe = _execution_supported(t["id"])
    return {
        "id": t["id"], "category": t["category"], "title": t["title"],
        "tool": t.get("tool", ""), "platform": t.get("platform", "both"),
        "executable_on_linux": t.get("executable_on_linux", False),
        "description": t.get("description", ""), "risk_level": _risk_level(t),
        "requires_opt_in": True, "execution_supported": exe,
        "execution_disabled_reason": None if exe else _execution_disabled_reason(t["id"]),
        "commands": [
            {
                "label": c.get("label", ""),
                "command": c.get("command", ""),
                "params": c.get("params", []),
                "platform": c.get("platform", t.get("platform", "both")),
                "execution_mode": _command_execution_mode(c.get("command", "")),
            }
            for c in t.get("commands", [])
        ],
    }


def _execution_supported(technique_id: str) -> bool:
    if not settings.ENABLE_COMMAND_EXECUTION:
        return False
    allowlist = settings.command_execution_allowlist
    return technique_id in allowlist


def _execution_disabled_reason(technique_id: str) -> str:
    if not settings.ENABLE_COMMAND_EXECUTION:
        return "Set ENABLE_COMMAND_EXECUTION=true to enable live execution."
    allowlist = settings.command_execution_allowlist
    if technique_id not in allowlist:
        return "Technique not in COMMAND_EXECUTION_ALLOWLIST."
    return "Execution unavailable."


_HIGH_MARKERS = frozenset(["privilege escalation","lateral movement","persistence","relay","dcsync","spray","dump","ticket","mimikatz","secretsdump","psexec","wmiexec","smbexec"])

def _risk_level(technique: dict) -> str:
    haystack = " ".join(str(technique.get(k, "")).lower() for k in ("category","title","description","tool"))
    return "HIGH" if any(m in haystack for m in _HIGH_MARKERS) else "LOW"


_MANUAL_TEMPLATE_SYNTAX_RE = re.compile(r"(\|\||&&|[|;<>`$]|\r|\n)")
_MANUAL_WORD_RE = re.compile(r"\b(powershell|pwsh|cmd\.exe|cmd|forfiles|wmic)\b", re.IGNORECASE)


def _command_execution_mode(command: str) -> str:
    if _MANUAL_TEMPLATE_SYNTAX_RE.search(command) or _MANUAL_WORD_RE.search(command):
        return "manual"
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return "manual"
    return "argv" if argv else "manual"


def _structured_argv(rendered: str) -> list[str]:
    if "$(" in rendered or "`" in rendered or "\n" in rendered or "\r" in rendered:
        raise HTTPException(
            status_code=400,
            detail="This command is manual-only because it contains shell/PowerShell/pipeline/redirection syntax.",
        )
    argv = shlex.split(rendered, posix=True)
    if not argv:
        raise HTTPException(status_code=400, detail="Rendered command is empty")
    if any(arg in {"|", "||", "&&", ";", "<", ">", "&"} for arg in argv):
        raise HTTPException(status_code=400, detail="Shell operators are not allowed for structured execution")
    return argv


@router.get("/categories", response_model=list[CategoryOut])
async def list_categories(current_user: PlatformUser = Depends(get_current_user)):
    return [
        CategoryOut(name=cat, description=AD_CATEGORY_DESCRIPTIONS.get(cat, ""),
                    technique_count=len(tc := [t for t in AD_COMMANDS if t["category"] == cat]),
                    linux_executable_count=sum(1 for t in tc if _is_linux_executable(t)))
        for cat in AD_CATEGORIES
    ]


@router.get("/techniques", response_model=list[TechniqueOut])
async def list_techniques(
    category: str | None = Query(None, max_length=100),
    search: str | None = Query(None, max_length=100),
    linux_only: bool = Query(False),
    current_user: PlatformUser = Depends(get_current_user),
):
    results = AD_COMMANDS

    if category:
        results = [t for t in results if t["category"].lower() == category.lower()]

    if linux_only:
        results = [t for t in results if _is_linux_executable(t)]

    if search:
        q = search.lower()
        results = [
            t for t in results
            if q in t["title"].lower()
            or q in t.get("description", "").lower()
            or q in t["category"].lower()
            or q in t.get("tool", "").lower()
        ]

    return [TechniqueOut(**_coerce(t)) for t in results]


@router.get("/list", response_model=list[TechniqueOut])
async def list_techniques_by_id(
    ids: str = Query("", max_length=10000),
    current_user: PlatformUser = Depends(get_current_user),
):
    """Compatibility endpoint for older command-deck pages.

    New clients should use `/ad-commands/techniques`; this keeps pages that
    request a specific ordered ID list from returning 404 after catalog updates.
    """
    requested = [item.strip() for item in ids.split(",") if item.strip()]
    if not requested:
        return []
    index = {technique["id"]: technique for technique in AD_COMMANDS}
    return [TechniqueOut(**_coerce(index[technique_id])) for technique_id in requested if technique_id in index]


@router.get("/techniques/{technique_id}", response_model=TechniqueOut)
async def get_technique(
    technique_id: str,
    current_user: PlatformUser = Depends(get_current_user),
):
    t = next((t for t in AD_COMMANDS if t["id"] == technique_id), None)
    if not t:
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")
    return TechniqueOut(**_coerce(t))


@router.get("/tools/available")
async def check_tools(current_user: PlatformUser = Depends(get_current_user)):
    await require_superadmin(current_user)
    return {tool: _tool_available(tool) for tool in LINUX_TOOL_MAP}


@router.post("/execute/{technique_id}", response_model=ExecuteResult)
async def execute_command(
    technique_id: str,
    body: ExecuteRequest,
    current_user: PlatformUser = Depends(get_current_user),
):
    await require_superadmin(current_user)
    technique = next((t for t in AD_COMMANDS if t["id"] == technique_id), None)
    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique '{technique_id}' not found")
    if not settings.ENABLE_COMMAND_EXECUTION:
        raise HTTPException(status_code=403, detail="Command execution is disabled by default")
    allowlist = settings.command_execution_allowlist
    if technique_id not in allowlist:
        raise HTTPException(status_code=403, detail="Technique is not allowlisted for execution")

    if not _is_linux_executable(technique):
        raise HTTPException(
            status_code=400,
            detail="Technique not marked linux-executable. Windows-only techniques can be viewed and copied but not run here.",
        )

    commands = technique.get("commands", [])
    if body.command_index < 0 or body.command_index >= len(commands):
        raise HTTPException(status_code=400, detail=f"Command index {body.command_index} out of range (max {len(commands)-1})")

    cmd_def = commands[body.command_index]
    if _command_execution_mode(cmd_def.get("command", "")) != "argv":
        raise HTTPException(
            status_code=400,
            detail="This command is manual-only because it contains shell/PowerShell/pipeline/redirection syntax.",
        )

    # For mixed-platform techniques, skip windows-only commands
    cmd_platform = cmd_def.get("platform", technique.get("platform", "both"))
    if cmd_platform == "windows":
        raise HTTPException(status_code=400, detail="Selected command is Windows-only and cannot be executed here.")

    rendered = _render(cmd_def["command"], body.params)
    rendered_redacted = _redacted_render(cmd_def["command"], body.params)

    unfilled = re.findall(r"\{(\w+)\}", rendered)
    if unfilled:
        raise HTTPException(status_code=422, detail=f"Missing required parameters: {unfilled}")

    argv = _structured_argv(rendered)
    executable_path = _resolve_executable(argv[0])
    if not executable_path:
        raise HTTPException(status_code=409, detail=f"Required executable is not installed: {argv[0]}")

    log.warning(
        "Structured AD command execution requested",
        extra={"technique_id": technique_id, "command_index": body.command_index, "user_id": str(current_user.id)},
    )

    try:
        svc_result = await _svc_execute_technique(
            technique_id=technique_id,
            command_index=body.command_index,
            params=body.params,
            current_user=current_user,
            _rendered_command=rendered,
        )
    except Exception as exc:
        log.error("AD command execution error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Command execution failed") from exc

    if svc_result.blocked:
        raise HTTPException(status_code=403, detail=svc_result.error or "Execution blocked by policy")
    if svc_result.error:
        # Log the internal error but surface a generic message to avoid info leakage
        log.error("AD command execution error: %s", svc_result.error)
        raise HTTPException(status_code=500, detail="Command execution failed")

    return ExecuteResult(
        technique_id=technique_id,
        command_label=cmd_def["label"],
        rendered_command=rendered_redacted,
        stdout=svc_result.stdout,
        stderr=svc_result.stderr,
        exit_code=svc_result.exit_code if svc_result.exit_code is not None else 0,
        tool_available=True,
    )
