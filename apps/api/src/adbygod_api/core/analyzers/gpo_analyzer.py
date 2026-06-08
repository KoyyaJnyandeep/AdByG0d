from __future__ import annotations

import logging
import re
from typing import Any

from ldap3 import SUBTREE

log = logging.getLogger(__name__)

_GPO_LINK_RE = re.compile(r"\[LDAP://([^;]+);(\d+)\]")


class GPOAnalyzer:
    """
    Enumerate Group Policy Objects and their OU linkage.
    Flags disabled GPOs, block inheritance, and enforced links.
    """

    def __init__(self, conn, base_dn: str):
        self.conn = conn
        self.base_dn = base_dn

    def _search(self, filt: str, attrs: list[str], base: str | None = None) -> list[dict[str, Any]]:
        self.conn.search(base or self.base_dn, filt, search_scope=SUBTREE, attributes=attrs)
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

    def enumerate_gpos(self) -> list[dict[str, Any]]:
        raw = self._search(
            "(objectClass=groupPolicyContainer)",
            ["displayName", "distinguishedName", "gPCFileSysPath",
             "flags", "versionNumber", "whenCreated", "whenChanged"],
        )
        gpos = []
        for r in raw:
            flags = int(r.get("flags") or 0)
            gpos.append({
                **r,
                "name": r.get("displayName", r["dn"]),
                "sysvol_path": r.get("gPCFileSysPath", ""),
                "disabled": bool(flags & 3),
                "flags_raw": flags,
            })
        return gpos

    def enumerate_ou_links(self) -> list[dict[str, Any]]:
        raw = self._search(
            "(gPLink=*)",
            ["distinguishedName", "gPLink", "gPOptions"],
        )
        links = []
        for r in raw:
            raw_link = r.get("gPLink") or ""
            gpo_options = int(r.get("gPOptions") or 0)
            linked = [
                {
                    "gpo_dn": dn,
                    "link_options": int(opt),
                    "enforced": int(opt) & 2 == 2,
                    "disabled": int(opt) & 1 == 1,
                }
                for dn, opt in _GPO_LINK_RE.findall(raw_link)
            ]
            links.append({
                "ou": r["dn"],
                "block_inheritance": bool(gpo_options & 1),
                "linked_gpos": linked,
            })
        return links

    def analyze(self) -> dict[str, Any]:
        gpos = self.enumerate_gpos()
        ou_links = self.enumerate_ou_links()

        disabled_gpos = [g for g in gpos if g["disabled"]]
        findings = []
        if disabled_gpos:
            findings.append({
                "type": "DISABLED_GPOS",
                "severity": "INFO",
                "count": len(disabled_gpos),
                "objects": [g["name"] for g in disabled_gpos],
                "description": "GPOs that are fully disabled — may indicate stale policy objects.",
            })

        log.info("[GPO] gpos=%d ou_links=%d disabled=%d", len(gpos), len(ou_links), len(disabled_gpos))
        return {
            "gpos": gpos,
            "ou_links": ou_links,
            "gpo_count": len(gpos),
            "findings": findings,
        }
