from __future__ import annotations

import logging
from typing import Any

from ldap3 import SUBTREE

log = logging.getLogger(__name__)

TRUST_DIRECTION = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE      = {1: "Downlevel (NT4)", 2: "Uplevel (AD)", 3: "MIT (Kerberos)", 4: "DCE"}

TRUST_ATTR_FLAGS = {
    0x001: "NON_TRANSITIVE",
    0x002: "UPLEVEL_ONLY",
    0x004: "QUARANTINED (SID Filtering)",
    0x008: "FOREST_TRANSITIVE",
    0x010: "CROSS_ORGANIZATION",
    0x020: "WITHIN_FOREST",
    0x040: "TREAT_AS_EXTERNAL",
    0x080: "USES_RC4_ENCRYPTION",
}


class TrustAnalyzer:
    """
    Map domain trusts and flag dangerous configurations such as
    missing SID filtering on inbound trusts.
    """

    def __init__(self, conn, base_dn: str):
        self.conn = conn
        self.base_dn = base_dn

    def enumerate_trusts(self) -> list[dict[str, Any]]:
        system_dn = f"CN=System,{self.base_dn}"
        self.conn.search(
            system_dn,
            "(objectClass=trustedDomain)",
            search_scope=SUBTREE,
            attributes=[
                "name", "flatName", "trustDirection", "trustType",
                "trustAttributes", "securityIdentifier",
                "whenCreated", "whenChanged",
            ],
        )
        trusts = []
        for e in self.conn.entries:
            direction_val = int(e["trustDirection"].value or 0)
            type_val      = int(e["trustType"].value or 0)
            attrs_raw     = int(e["trustAttributes"].value or 0)
            attr_flags    = [label for bit, label in TRUST_ATTR_FLAGS.items() if attrs_raw & bit]
            sid_filtering = bool(attrs_raw & 0x004)
            transitive    = not bool(attrs_raw & 0x001)
            forest_trust  = bool(attrs_raw & 0x008)
            direction_str = TRUST_DIRECTION.get(direction_val, str(direction_val))

            trusts.append({
                "dn": e.entry_dn,
                "name": str(e["name"].value),
                "flat_name": str(e["flatName"].value) if "flatName" in e else "",
                "direction": direction_str,
                "direction_val": direction_val,
                "trust_type": TRUST_TYPE.get(type_val, str(type_val)),
                "transitive": transitive,
                "forest_trust": forest_trust,
                "sid_filtering": sid_filtering,
                "attribute_flags": attr_flags,
                "attributes_raw": attrs_raw,
            })
        return trusts

    def analyze(self) -> dict[str, Any]:
        trusts = self.enumerate_trusts()
        findings = []

        for t in trusts:
            if not t["sid_filtering"] and t["direction_val"] in (1, 3):
                findings.append({
                    "type": "TRUST_NO_SID_FILTERING",
                    "severity": "HIGH",
                    "target": t["name"],
                    "description": (
                        f"Inbound/bidirectional trust with {t['name']} has no SID filtering. "
                        "Allows SID history injection attacks from the trusted domain."
                    ),
                })
            if t["forest_trust"] and t["transitive"]:
                findings.append({
                    "type": "TRANSITIVE_FOREST_TRUST",
                    "severity": "MEDIUM",
                    "target": t["name"],
                    "description": (
                        f"Transitive forest trust with {t['name']}. "
                        "Compromise of either forest can affect the other."
                    ),
                })

        log.info("[Trust] trusts=%d findings=%d", len(trusts), len(findings))
        return {"trusts": trusts, "findings": findings}
