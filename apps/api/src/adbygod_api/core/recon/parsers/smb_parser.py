from __future__ import annotations
import re


def parse_smb_output(stdout: str, exit_code: int) -> dict:
    result: dict = {"null_session": False, "shares": [], "error": None}
    if "ACCESS_DENIED" in stdout or "LOGON_FAILURE" in stdout or exit_code != 0:
        result["error"] = stdout.strip()[:200]
        return result
    share_pattern = re.compile(r"^\s+(\S+)\s+(Disk|IPC|Printer)", re.MULTILINE)
    shares = [m.group(1) for m in share_pattern.finditer(stdout)]
    if shares:
        result["null_session"] = True
        result["shares"] = shares
    return result
