from __future__ import annotations


def scan_for_critical(tool_name: str, result) -> list[dict]:
    """Scan a tool result for critical indicators. Returns list of alert dicts."""
    alerts: list[dict] = []

    if tool_name == "get_credential_intel" and isinstance(result, list):
        for item in result:
            h_type = item.get("hash_type", "")
            if h_type == "NTLM" and item.get("pth_ready"):
                alerts.append({
                    "severity": "CRITICAL",
                    "title": "PTH-Ready NTLM Hash Captured",
                    "detail": f"NTLM hash is Pass-the-Hash ready. {item.get('note', '')}",
                    "recommended_action": "Immediately attempt DCSync or PTH to DC",
                })

    elif tool_name == "list_findings" and isinstance(result, list):
        for finding in result:
            title = finding.get("title", "")
            module = finding.get("module", finding.get("module_name", ""))
            combined = f"{title} {module}".upper()

            for esc in ["ESC1", "ESC2", "ESC4", "ESC6", "ESC8"]:
                if esc in combined:
                    alerts.append({
                        "severity": "CRITICAL",
                        "title": f"ADCS {esc} — Certificate Template Exploitation",
                        "detail": title,
                        "recommended_action": f"Run certipy to exploit {esc} immediately",
                    })
                    break

            if "UNCONSTRAINED" in combined and "DELEGATION" in combined:
                alerts.append({
                    "severity": "CRITICAL",
                    "title": "Unconstrained Delegation — DA Hash Capture Possible",
                    "detail": title,
                    "recommended_action": "Use PrinterBug or PetitPotam to force DC authentication",
                })

    return alerts
