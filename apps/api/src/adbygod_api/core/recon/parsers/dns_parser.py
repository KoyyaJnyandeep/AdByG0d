from __future__ import annotations
import re


def parse_dns_output(stdout: str, exit_code: int) -> dict:
    result: dict = {"zone_transfer": False, "record_types": [], "records": [], "error": None}
    if not stdout.strip():
        result["error"] = "No DNS output"
        return result
    record_pat = re.compile(r"\s+IN\s+([A-Z]+)\s+")
    types = list(dict.fromkeys(m.group(1) for m in record_pat.finditer(stdout)))
    result["record_types"] = types
    if "SOA" in types or "NS" in types:
        result["zone_transfer"] = True
    return result
