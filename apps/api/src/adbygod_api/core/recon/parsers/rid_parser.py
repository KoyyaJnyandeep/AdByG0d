from __future__ import annotations
import re


def parse_rid_output(stdout: str, exit_code: int) -> dict:
    result: dict = {"users": [], "groups": [], "error": None}
    if not stdout.strip():
        result["error"] = "RID cycling returned no output"
        return result
    user_pat  = re.compile(r"\\(\S+)\s+\(SidTypeUser\)")
    group_pat = re.compile(r"\\(.+?)\s+\(SidTypeGroup\)")
    result["users"]  = list(dict.fromkeys(m.group(1) for m in user_pat.finditer(stdout)))
    result["groups"] = list(dict.fromkeys(m.group(1) for m in group_pat.finditer(stdout)))
    return result
