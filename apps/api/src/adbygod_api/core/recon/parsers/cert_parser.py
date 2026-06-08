from __future__ import annotations
import json


def parse_cert_json(json_str: str) -> dict:
    result: dict = {"domains": [], "error": None}
    try:
        data = json.loads(json_str)
        domains: set[str] = set()
        for entry in data:
            name = entry.get("name_value", "")
            for d in name.split("\n"):
                d = d.strip()
                if d.startswith("*."):
                    domains.add(d[2:])
                elif d:
                    domains.add(d)
        result["domains"] = sorted(domains)
    except (json.JSONDecodeError, AttributeError) as exc:
        result["error"] = str(exc)
    return result
