from __future__ import annotations

import logging
from typing import Any

from ldap3 import SUBTREE

log = logging.getLogger(__name__)

UAC_UNCONSTRAINED   = 0x80000
UAC_PROTO_TRANSITION = 0x1000000
UAC_ACCOUNTDISABLE  = 0x0002


class DelegationAnalyzer:
    """
    Analyze delegation configurations — unconstrained, constrained,
    protocol-transition (S4U2Self), and resource-based constrained (RBCD).
    Operates on an already-connected ldap3 Connection.
    """

    def __init__(self, conn, base_dn: str):
        self.conn = conn
        self.base_dn = base_dn

    def _search(self, filt: str, attrs: list[str]) -> list[dict[str, Any]]:
        self.conn.search(self.base_dn, filt, search_scope=SUBTREE, attributes=attrs)
        results = []
        for e in self.conn.entries:
            obj: dict[str, Any] = {"dn": e.entry_dn}
            for a in attrs:
                try:
                    val = e[a].value
                    if val is not None:
                        obj[a] = str(val) if not isinstance(val, list) else [str(x) for x in val]
                except Exception:
                    pass
            results.append(obj)
        return results

    def unconstrained(self) -> list[dict[str, Any]]:
        """Accounts with TrustedForDelegation (excludes DCs — they legitimately have it)."""
        entries = self._search(
            "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "distinguishedName", "objectClass",
             "dNSHostName", "userAccountControl"],
        )
        results = []
        for e in entries:
            is_dc = "OU=Domain Controllers" in e["dn"]
            results.append({**e, "is_dc": is_dc, "high_risk": not is_dc})
        return results

    def constrained(self) -> list[dict[str, Any]]:
        """Accounts with msDS-AllowedToDelegateTo set."""
        entries = self._search(
            "(&(msDS-AllowedToDelegateTo=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo",
             "userAccountControl"],
        )
        results = []
        for e in entries:
            uac = int(e.get("userAccountControl") or 0)
            proto_transition = bool(uac & UAC_PROTO_TRANSITION)
            spns = e.get("msDS-AllowedToDelegateTo") or []
            if isinstance(spns, str):
                spns = [spns]
            results.append({
                **e,
                "protocol_transition": proto_transition,
                "allowed_to_delegate": spns,
                "high_risk": proto_transition,
            })
        return results

    def rbcd(self) -> list[dict[str, Any]]:
        """Accounts with msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD targets)."""
        return self._search(
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            ["sAMAccountName", "distinguishedName",
             "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        )

    def analyze(self) -> dict[str, Any]:
        unc = self.unconstrained()
        con = self.constrained()
        rbc = self.rbcd()
        proto = [x for x in con if x.get("protocol_transition")]
        high_risk_unc = [x for x in unc if not x.get("is_dc")]

        findings = []
        if high_risk_unc:
            findings.append({
                "type": "UNCONSTRAINED_DELEGATION",
                "severity": "CRITICAL",
                "count": len(high_risk_unc),
                "objects": [x["sAMAccountName"] for x in high_risk_unc if "sAMAccountName" in x],
                "description": "Non-DC accounts with unconstrained delegation can capture TGTs of any authenticating user.",
            })
        if proto:
            findings.append({
                "type": "PROTOCOL_TRANSITION_DELEGATION",
                "severity": "HIGH",
                "count": len(proto),
                "objects": [x.get("sAMAccountName", x["dn"]) for x in proto],
                "description": "Accounts with S4U2Self (TrustedToAuthForDelegation) can impersonate any domain user.",
            })
        if rbc:
            findings.append({
                "type": "RBCD_TARGETS",
                "severity": "HIGH",
                "count": len(rbc),
                "objects": [x.get("sAMAccountName", x["dn"]) for x in rbc],
                "description": "Objects with msDS-AllowedToActOnBehalfOfOtherIdentity set — potential RBCD attack surface.",
            })

        log.info(
            "[Delegation] unconstrained=%d constrained=%d rbcd=%d proto_transition=%d",
            len(unc), len(con), len(rbc), len(proto),
        )
        return {
            "unconstrained": unc,
            "constrained": con,
            "rbcd": rbc,
            "protocol_transition": proto,
            "findings": findings,
        }
