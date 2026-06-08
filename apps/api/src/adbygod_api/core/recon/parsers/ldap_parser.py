from __future__ import annotations


def parse_ldap_output(stdout: str, exit_code: int) -> dict:
    result: dict = {"anon_bind": False, "error": None}
    if not stdout.strip() or exit_code != 0:
        result["error"] = stdout.strip()[:200]
        return result
    if "Invalid credentials" in stdout or "ldap_bind" in stdout:
        return result
    result["anon_bind"] = True
    for line in stdout.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k, v = k.strip(), v.strip()
            if k and v and k not in ("dn", ""):
                result[k] = v
    return result
