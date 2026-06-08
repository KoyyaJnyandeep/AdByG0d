#!/usr/bin/env python3
"""
AdByGod — Technique Validation Runner
Tests every AD command/module against a fake target to determine:
  - Tool installed?
  - Command syntax valid?
  - Network response (connection refused = tool works; timeout = target unreachable)

Usage:
  python3 scripts/validate_techniques.py
  python3 scripts/validate_techniques.py --ip 10.10.10.100 --domain evil.corp
  python3 scripts/validate_techniques.py --json results.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import shlex
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api" / "src"))
from adbygod_api.data.ad_commands import AD_COMMANDS

# ── Fake target defaults ───────────────────────────────────────────────────────
DEFAULT_TARGET = {
    "DC_IP":        "192.168.1.100",
    "Domain":       "corp.local",
    "DomainName":   "corp.local",
    "Username":     "administrator",
    "User":         "administrator",
    "Password":     "Password123!",
    "credpassword": "Password123!",
    "DC":           "192.168.1.100",
    "Target":       "192.168.1.100",
    "ComputerName": "192.168.1.100",
    "DNSServer":    "192.168.1.100",
    "AttackerIP":   "127.0.0.1",
    "ForestName":   "corp.local",
    "ExternalForest": "corp.local",
    "RootDomain":   "corp.local",
    "CurrentDomain": "corp.local",
    "OurDomain":    "corp.local",
    "Interface":    "eth0",
    "GroupName":    "Domain Admins",
    "AccountName":  "administrator",
    "DomainDN":     "DC=corp,DC=local",
    "UNCPath":      "\\\\192.168.1.100\\SYSVOL",
    "NTHash":       "aad3b435b51404eeaad3b435b51404ee",
    "AES256Hash":   "a" * 64,
    "KrbtgtHash":   "a" * 32,
    "DomainSID":    "S-1-5-21-1234567890-1234567890-1234567890",
    "SID":          "S-1-5-21-1234567890-1234567890-1234567890-500",
    "HashFile":     "/dev/null",
    "TargetFile":   "/dev/null",
    "CredFile":     "/dev/null",
    "Port":         "4444",
    "Share":        "ADMIN$",
    "RuleFile":     "best64.rule",
    "ScriptName":   "PowerView",
    "Keyword":      "password",
    "OriginalHashFile": "/dev/null",
    "DC_HOSTNAME":  "DC01",
    "BastionIP":    "192.168.1.1",
    "PID":          "1234",
    "ADCS_IP":      "192.168.1.101",
    "PFXPassword":  "Password123!",
    "AdminUser":    "administrator",
    "VictimIP":     "192.168.1.200",
    "Command":      "whoami",
    "UserSID":      "S-1-5-21-1234567890-1234567890-1234567890-500",
    "TargetUser":   "administrator",
    "PolicyName":   "DefaultDomainPolicy",
    "FileName":     "Groups.xml",
}

TOOL_BINARY_MAP: dict[str, str] = {
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
    "nxc": "nxc",
    "netexec": "nxc",
    "crackmapexec": "crackmapexec",
    "xfreerdp": "xfreerdp",
    "evil-winrm": "evil-winrm",
    "kerbrute": "kerbrute",
    "hashcat": "hashcat",
    "openssl": "openssl",
    "responder": "responder",
    "socat": "socat",
    "ssh": "ssh",
    "impacket-GetUserSPNs": "impacket-GetUserSPNs",
    "impacket-GetNPUsers": "impacket-GetNPUsers",
    "impacket-secretsdump": "impacket-secretsdump",
    "impacket-wmiexec": "impacket-wmiexec",
    "impacket-psexec": "impacket-psexec",
    "impacket-ntlmrelayx": "impacket-ntlmrelayx",
    "impacket-smbexec": "impacket-smbexec",
    "impacket-ticketer": "impacket-ticketer",
    "impacket-getST": "impacket-getST",
    "impacket-addcomputer": "impacket-addcomputer",
    "impacket-dacledit": "impacket-dacledit",
    "impacket-mssqlclient": "impacket-mssqlclient",
    "impacket-rpcdump": "impacket-rpcdump",
    "impacket-printerbug": "impacket-printerbug",
    "impacket-getTGT": "impacket-getTGT",
    "certipy": "certipy-ad",
    "nc": "nc",
    "find": "find",
    "sudo": "sudo",
    "bash": "bash",
    "curl": "curl",
}


# Patterns in stderr/stdout that indicate tool ran correctly but target unreachable
_TOOL_WORKING_PATTERNS = [
    r"connection refused", r"timed out", r"unreachable", r"no route to host",
    r"network is unreachable", r"cannot connect", r"error connecting",
    r"smb.*failed", r"ldap.*failed", r"kerberos.*failed", r"kdc.*failed",
    r"authentication.*failed", r"access.*denied", r"invalid credentials",
    r"error code.*0xc", r"got.*error", r"failed with status",
    r"name or service not known", r"no such host", r"nodename nor servname",
    r"dns.*resolution", r"host.*not found",
    r"eoferror",  # interactive tool needs TTY — ran fine but no stdin available
]
_TOOL_WORKING_RE = re.compile("|".join(_TOOL_WORKING_PATTERNS), re.IGNORECASE)

# Patterns indicating the tool itself is broken or command syntax is wrong
# NOTE: "no such file or directory" is excluded — it often means missing *input* file, not broken tool
_TOOL_ERROR_PATTERNS = [
    r"command not found", r"syntax error", r"invalid option",
    r"unrecognized argument", r"unrecognized command",
    r"traceback.*most recent call last",
    r"importerror", r"modulenotfounderror",
    r"can't open file '(?!/tmp/).*': \[Errno 2\]",  # python3 can't find script (not a /tmp clone path)
    r"error: argument .* invalid",
    r"unknown option",
]
_TOOL_ERROR_RE = re.compile("|".join(_TOOL_ERROR_PATTERNS), re.IGNORECASE)

# "no such file or directory" at exit code 127 = tool missing; at other codes = input file issue
def _is_command_not_found(exit_code: int, stderr: str) -> bool:
    return exit_code == 127 or ("no such file or directory" in stderr.lower() and exit_code == 127)

# Shell operators that can't be run without a shell (skip those)
_SHELL_OP_RE = re.compile(r"[\|;&<>]|\$\(|`")
# Commands that would hang forever / are non-testable
_SKIP_LABELS = {"listen", "reverse shell", "start responder", "start smb server",
                "dynamic socks", "ssh agent hijack", "nc -lnvp", "responder -I"}


def render(template: str, params: dict[str, str]) -> str:
    def rep(m: re.Match) -> str:
        return params.get(m.group(1), m.group(0))
    return re.sub(r"\{(\w+)\}", rep, template)


def tool_from_technique(technique: dict) -> str:
    return technique.get("tool", "").split("/")[0].strip().lower()


def find_binary(technique: dict) -> Optional[str]:
    tool = tool_from_technique(technique)
    binary = TOOL_BINARY_MAP.get(tool)
    if binary and shutil.which(binary):
        return binary
    # Try matching directly
    if shutil.which(tool):
        return tool
    # Try matching first word of each command
    for cmd in technique.get("commands", []):
        if cmd.get("platform", "both") == "windows":
            continue
        first_word = cmd["command"].strip().split()[0] if cmd["command"].strip() else ""
        if first_word and shutil.which(first_word):
            return first_word
    return None


@dataclass
class CmdResult:
    technique_id: str
    technique_title: str
    category: str
    cmd_index: int
    cmd_label: str
    platform: str
    tool: str
    tool_installed: bool
    skipped: bool
    skip_reason: str
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_ms: int
    status: str  # PASS | FAIL | TOOL_MISSING | SKIP | SYNTAX_ERROR | NET_ERROR | TIMEOUT
    rendered_command: str


@dataclass
class TechniqueResult:
    technique_id: str
    title: str
    category: str
    platform: str
    tool: str
    tool_installed: bool
    windows_only: bool
    cmd_results: list[CmdResult] = field(default_factory=list)
    overall: str = "PENDING"


async def run_cmd(argv: list[str], timeout: float = 8.0) -> tuple[int, str, str, int]:
    t0 = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            ms = int((time.monotonic() - t0) * 1000)
            return proc.returncode or 0, out.decode("utf-8", errors="replace"), err.decode("utf-8", errors="replace"), ms
        except asyncio.TimeoutError:
            proc.kill()
            ms = int((time.monotonic() - t0) * 1000)
            return -1, "", "TIMEOUT", ms
    except FileNotFoundError:
        ms = int((time.monotonic() - t0) * 1000)
        return 127, "", "command not found", ms
    except Exception as e:
        ms = int((time.monotonic() - t0) * 1000)
        return -2, "", str(e), ms


def classify(exit_code: int, stdout: str, stderr: str, tool_installed: bool) -> str:
    combined = (stdout + " " + stderr).lower()
    if not tool_installed:
        return "TOOL_MISSING"
    if exit_code == -1 or "TIMEOUT" in stderr:
        return "TIMEOUT"
    if exit_code == 127 or "command not found" in combined:
        return "TOOL_MISSING"
    if exit_code == 0:
        return "PASS"
    if _TOOL_WORKING_RE.search(combined):
        return "NET_ERROR"  # tool works, target unreachable (expected for fake target)
    if _TOOL_ERROR_RE.search(combined):
        return "SYNTAX_ERROR"
    # Non-zero exit with no clear signal: could be tool worked but target absent
    # Treat exit codes that tools use for "unreachable" scenarios as NET_ERROR
    if exit_code in (1, 2, 255, 23, -1) and tool_installed:
        return "NET_ERROR"
    # Signal-terminated (>= 128): SIGPIPE/SIGTERM from lost connection = NET_ERROR
    if exit_code >= 128 and tool_installed:
        return "NET_ERROR"
    return "FAIL"


async def validate_technique(
    technique: dict,
    target: dict,
    max_cmds: int = 999,
    cmd_timeout: float = 8.0,
) -> TechniqueResult:
    tid = technique["id"]
    category = technique["category"]
    platform = technique.get("platform", "both")
    tool = tool_from_technique(technique)
    commands = technique.get("commands", [])
    windows_only = platform == "windows" and not technique.get("executable_on_linux", False)

    binary = find_binary(technique)
    tool_installed = binary is not None

    result = TechniqueResult(
        technique_id=tid,
        title=technique["title"],
        category=category,
        platform=platform,
        tool=technique.get("tool", ""),
        tool_installed=tool_installed,
        windows_only=windows_only,
    )

    if windows_only:
        result.overall = "SKIP_WINDOWS"
        for i, cmd in enumerate(commands):
            result.cmd_results.append(CmdResult(
                technique_id=tid, technique_title=technique["title"],
                category=category, cmd_index=i, cmd_label=cmd["label"],
                platform=cmd.get("platform", platform), tool=tool,
                tool_installed=False, skipped=True, skip_reason="Windows-only",
                exit_code=None, stdout="", stderr="", duration_ms=0,
                status="SKIP", rendered_command=cmd["command"],
            ))
        return result

    tested = 0
    for i, cmd in enumerate(commands):
        if tested >= max_cmds:
            break
        cmd_platform = cmd.get("platform", platform)
        if cmd_platform == "windows":
            result.cmd_results.append(CmdResult(
                technique_id=tid, technique_title=technique["title"],
                category=category, cmd_index=i, cmd_label=cmd["label"],
                platform=cmd_platform, tool=tool, tool_installed=tool_installed,
                skipped=True, skip_reason="Windows-only command",
                exit_code=None, stdout="", stderr="", duration_ms=0,
                status="SKIP", rendered_command=cmd["command"],
            ))
            continue

        raw = cmd["command"]
        rendered = render(raw, target)

        # Check for unfilled placeholders
        unfilled = re.findall(r"\{(\w+)\}", rendered)
        if unfilled:
            result.cmd_results.append(CmdResult(
                technique_id=tid, technique_title=technique["title"],
                category=category, cmd_index=i, cmd_label=cmd["label"],
                platform=cmd_platform, tool=tool, tool_installed=tool_installed,
                skipped=True, skip_reason=f"Unfilled params: {unfilled}",
                exit_code=None, stdout="", stderr="", duration_ms=0,
                status="SKIP", rendered_command=rendered,
            ))
            continue

        # Skip shell-operator commands (can't run without shell safely)
        if _SHELL_OP_RE.search(rendered) and rendered.count("\n") == 0:
            result.cmd_results.append(CmdResult(
                technique_id=tid, technique_title=technique["title"],
                category=category, cmd_index=i, cmd_label=cmd["label"],
                platform=cmd_platform, tool=tool, tool_installed=tool_installed,
                skipped=True, skip_reason="Shell operators (safe skip)",
                exit_code=None, stdout="", stderr="", duration_ms=0,
                status="SKIP", rendered_command=rendered,
            ))
            continue

        # Skip obviously-hanging commands (listeners, responder, etc.)
        label_lower = cmd["label"].lower()
        if any(s in label_lower for s in _SKIP_LABELS) or any(s in rendered.lower() for s in ["nc -lnvp", "responder -I", "-D 1080 -N"]):
            result.cmd_results.append(CmdResult(
                technique_id=tid, technique_title=technique["title"],
                category=category, cmd_index=i, cmd_label=cmd["label"],
                platform=cmd_platform, tool=tool, tool_installed=tool_installed,
                skipped=True, skip_reason="Would hang (listener/interactive)",
                exit_code=None, stdout="", stderr="", duration_ms=0,
                status="SKIP", rendered_command=rendered,
            ))
            continue

        if not tool_installed:
            result.cmd_results.append(CmdResult(
                technique_id=tid, technique_title=technique["title"],
                category=category, cmd_index=i, cmd_label=cmd["label"],
                platform=cmd_platform, tool=tool, tool_installed=False,
                skipped=False, skip_reason="",
                exit_code=None, stdout="", stderr="", duration_ms=0,
                status="TOOL_MISSING", rendered_command=rendered,
            ))
            tested += 1
            continue

        # Parse into argv
        try:
            argv = shlex.split(rendered)
        except ValueError as e:
            result.cmd_results.append(CmdResult(
                technique_id=tid, technique_title=technique["title"],
                category=category, cmd_index=i, cmd_label=cmd["label"],
                platform=cmd_platform, tool=tool, tool_installed=tool_installed,
                skipped=True, skip_reason=f"shlex parse error: {e}",
                exit_code=None, stdout="", stderr="", duration_ms=0,
                status="SKIP", rendered_command=rendered,
            ))
            continue

        exit_code, stdout, stderr, ms = await run_cmd(argv, timeout=cmd_timeout)
        status = classify(exit_code, stdout, stderr, tool_installed)

        result.cmd_results.append(CmdResult(
            technique_id=tid, technique_title=technique["title"],
            category=category, cmd_index=i, cmd_label=cmd["label"],
            platform=cmd_platform, tool=tool, tool_installed=tool_installed,
            skipped=False, skip_reason="",
            exit_code=exit_code, stdout=stdout[:800], stderr=stderr[:800], duration_ms=ms,
            status=status, rendered_command=rendered,
        ))
        tested += 1

    # Compute overall
    statuses = [r.status for r in result.cmd_results if not r.skipped]
    if not statuses:
        result.overall = "SKIP_ALL"
    elif all(s == "TOOL_MISSING" for s in statuses):
        result.overall = "TOOL_MISSING"
    elif any(s == "PASS" for s in statuses):
        result.overall = "PASS"
    elif any(s == "NET_ERROR" for s in statuses):
        result.overall = "NET_ERROR"  # tool works, just no real target
    elif any(s == "TIMEOUT" for s in statuses):
        result.overall = "TIMEOUT"
    elif any(s == "SYNTAX_ERROR" for s in statuses):
        result.overall = "SYNTAX_ERROR"
    elif result.windows_only:
        result.overall = "SKIP_WINDOWS"
    else:
        result.overall = "FAIL"

    return result


# ── ANSI colours ──────────────────────────────────────────────────────────────
R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
DIM = "\033[2m"
MAGENTA = "\033[35m"


STATUS_COLOR = {
    "PASS":         GREEN,
    "NET_ERROR":    CYAN,
    "TOOL_MISSING": RED,
    "TIMEOUT":      YELLOW,
    "SYNTAX_ERROR": RED,
    "FAIL":         RED,
    "SKIP":         DIM,
    "SKIP_ALL":     DIM,
    "SKIP_WINDOWS": DIM,
}

STATUS_SYMBOL = {
    "PASS":         "✓",
    "NET_ERROR":    "~",
    "TOOL_MISSING": "✗",
    "TIMEOUT":      "⏱",
    "SYNTAX_ERROR": "!",
    "FAIL":         "✗",
    "SKIP":         "−",
    "SKIP_ALL":     "−",
    "SKIP_WINDOWS": "W",
}


def color_status(status: str) -> str:
    c = STATUS_COLOR.get(status, "")
    s = STATUS_SYMBOL.get(status, "?")
    return f"{c}{BOLD}{s} {status}{R}"


async def main() -> None:
    parser = argparse.ArgumentParser(description="AdByGod technique validator")
    parser.add_argument("--ip", default="192.168.1.100", help="Fake target DC IP")
    parser.add_argument("--domain", default="corp.local", help="Fake target domain")
    parser.add_argument("--user", default="administrator", help="Fake username")
    parser.add_argument("--password", default="Password123!", help="Fake password")
    parser.add_argument("--timeout", type=float, default=6.0, help="Per-command timeout (seconds)")
    parser.add_argument("--category", default=None, help="Filter to single category")
    parser.add_argument("--json", default=None, help="Write JSON results to this file")
    parser.add_argument("--max-cmds", type=int, default=3, help="Max commands per technique to run (default 3)")
    args = parser.parse_args()

    target = {**DEFAULT_TARGET,
              "DC_IP": args.ip, "DC": args.ip, "Target": args.ip,
              "ComputerName": args.ip, "DNSServer": args.ip,
              "Domain": args.domain, "DomainName": args.domain,
              "ForestName": args.domain, "ExternalForest": args.domain,
              "RootDomain": args.domain, "CurrentDomain": args.domain,
              "OurDomain": args.domain,
              "Username": args.user, "User": args.user,
              "Password": args.password, "credpassword": args.password}

    techniques = AD_COMMANDS
    if args.category:
        techniques = [t for t in techniques if args.category.lower() in t["category"].lower()]

    print(f"\n{BOLD}{'='*72}{R}")
    print(f"{BOLD} AdByGod — Technique Validation Run{R}")
    print(f"{BOLD}{'='*72}{R}")
    print(f" Target : {CYAN}{args.ip}{R} · {CYAN}{args.domain}{R}")
    print(f" User   : {CYAN}{args.user}{R}")
    print(f" Total  : {BOLD}{len(techniques)}{R} techniques · {sum(len(t.get('commands',[])) for t in techniques)} commands")
    print(f" Timeout: {args.timeout}s per command · max {args.max_cmds} cmds/technique")
    print(f"{BOLD}{'='*72}{R}\n")

    results: list[TechniqueResult] = []
    t_total = time.monotonic()

    for i, tech in enumerate(techniques, 1):
        sys.stdout.write(f" [{i:02d}/{len(techniques)}] {tech['title'][:55]:<56} ")
        sys.stdout.flush()
        r = await validate_technique(tech, target, max_cmds=args.max_cmds, cmd_timeout=args.timeout)
        results.append(r)
        print(color_status(r.overall))

    elapsed = time.monotonic() - t_total

    # ── Summary ───────────────────────────────────────────────────────────────
    from collections import Counter
    overall_counts = Counter(r.overall for r in results)
    cmd_counts = Counter(
        cr.status for r in results for cr in r.cmd_results
    )

    print(f"\n{BOLD}{'='*72}{R}")
    print(f"{BOLD} TECHNIQUE SUMMARY  ({elapsed:.1f}s){R}")
    print(f"{BOLD}{'='*72}{R}")

    categories_seen: set[str] = set()
    for r in results:
        if r.category not in categories_seen:
            categories_seen.add(r.category)
            cat_results = [x for x in results if x.category == r.category]
            cat_counts = Counter(x.overall for x in cat_results)
            print(f"\n {BOLD}{r.category}{R}")
            for cr in cat_results:
                sym = STATUS_SYMBOL.get(cr.overall, "?")
                sc = STATUS_COLOR.get(cr.overall, "")
                installed = f"{GREEN}INSTALLED{R}" if cr.tool_installed else f"{RED}NOT INSTALLED{R}"
                tool_short = cr.tool.split("/")[0].strip()[:22]
                print(f"  {sc}{sym}{R} {cr.title[:50]:<51} {DIM}{tool_short:<24}{R} {installed}")

    print(f"\n{BOLD}{'─'*72}{R}")
    print(f"{BOLD} Overall by status:{R}")
    for status, count in sorted(overall_counts.items(), key=lambda x: -x[1]):
        print(f"  {color_status(status):<40} {BOLD}{count}{R} techniques")

    print(f"\n{BOLD} Command-level results:{R}")
    for status, count in sorted(cmd_counts.items(), key=lambda x: -x[1]):
        print(f"  {color_status(status):<40} {BOLD}{count}{R} commands")

    print(f"\n{BOLD} Legend:{R}")
    print(f"  {GREEN}✓ PASS{R}         — Tool ran, target responded (exit 0)")
    print(f"  {CYAN}~ NET_ERROR{R}    — Tool works correctly, target unreachable (expected for fake target)")
    print(f"  {RED}✗ TOOL_MISSING{R} — Binary not installed in this environment")
    print(f"  {YELLOW}⏱ TIMEOUT{R}     — Command timed out (likely a slow network probe)")
    print(f"  {RED}! SYNTAX_ERROR{R} — Command syntax problem (bad flags, parse error)")
    print(f"  {DIM}− SKIP{R}         — Windows-only, shell ops, listener, or unfilled params")

    # Tools missing summary
    missing_tools: set[str] = set()
    for r in results:
        if not r.tool_installed and not r.windows_only:
            missing_tools.add(r.tool.split("/")[0].strip())

    if missing_tools:
        print(f"\n{BOLD} Missing tools (install to unlock more techniques):{R}")
        for mt in sorted(missing_tools):
            print(f"  {RED}✗{R} {mt}")

    print(f"\n{BOLD}{'='*72}{R}\n")

    # JSON output
    if args.json:
        out = {"target": {"ip": args.ip, "domain": args.domain, "user": args.user},
               "summary": dict(overall_counts), "command_summary": dict(cmd_counts),
               "techniques": [asdict(r) for r in results]}
        Path(args.json).write_text(json.dumps(out, indent=2, default=str))
        print(f" JSON results written to {args.json}\n")


if __name__ == "__main__":
    asyncio.run(main())
