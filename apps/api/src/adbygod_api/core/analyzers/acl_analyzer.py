from __future__ import annotations

import logging
import subprocess
from typing import Any

from ldap3 import SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control

log = logging.getLogger(__name__)

DANGEROUS_RIGHTS_MAP = {
    0x10000000: "GenericAll",
    0x000F01FF: "FullControl",
    0x00020000: "WriteDACL",
    0x00040000: "WriteOwner",
    0x00000008: "WriteProperty",
    0x00000100: "ExtendedRight",
    0x00080000: "Delete",
}

HIGH_VALUE_FILTERS = [
    "(&(objectClass=group)(sAMAccountName=Domain Admins))",
    "(&(objectClass=group)(sAMAccountName=Enterprise Admins))",
    "(&(objectClass=group)(sAMAccountName=Schema Admins))",
    "(&(objectClass=group)(sAMAccountName=Administrators))",
    "(&(objectClass=user)(sAMAccountName=Administrator))",
    "(&(objectClass=user)(sAMAccountName=krbtgt))",
]


def _describe_mask(mask: int) -> str:
    parts = [label for bit, label in DANGEROUS_RIGHTS_MAP.items() if mask & bit]
    return ",".join(parts) if parts else hex(mask)


class ACLAnalyzer:
    """
    Enumerate dangerous ACEs on high-value AD objects and check for
    privilege escalation paths via WriteDACL / WriteOwner / GenericAll.
    """

    def __init__(self, conn, base_dn: str, domain: str, username: str, password: str,
                 dc_ip: str, hashes: str = ""):
        self.conn = conn
        self.base_dn = base_dn
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.hashes = hashes

    def _high_value_dns(self) -> list[str]:
        dns = []
        for filt in HIGH_VALUE_FILTERS:
            self.conn.search(self.base_dn, filt, search_scope=SUBTREE,
                             attributes=["distinguishedName"])
            for e in self.conn.entries:
                dns.append(e.entry_dn)
        return dns

    def enumerate_security_descriptors(self) -> list[dict[str, Any]]:
        """Pull nTSecurityDescriptor from all user/group/computer objects."""
        self.conn.search(
            self.base_dn,
            "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "sAMAccountName", "nTSecurityDescriptor"],
            controls=security_descriptor_control(sdflags=0x04),
        )
        objects = []
        for e in self.conn.entries:
            try:
                sd = e["nTSecurityDescriptor"].raw_values
                if sd:
                    objects.append({
                        "dn": e.entry_dn,
                        "sam": str(e["sAMAccountName"].value) if "sAMAccountName" in e else "?",
                        "sd_size_bytes": len(sd[0]),
                    })
            except Exception:
                log.debug("[ACL] Skipped nTSecurityDescriptor for entry %s", getattr(e, 'entry_dn', '?'), exc_info=True)
        log.info("[ACL] Pulled nTSecurityDescriptor from %d objects", len(objects))
        return objects

    def dacledit_read(self, target_dn: str) -> dict[str, Any]:
        """Run impacket-dacledit read for a specific target DN."""
        if self.hashes:
            creds = f"{self.domain}/{self.username}"
            auth_extra = ["-hashes", self.hashes]
        else:
            creds = f"{self.domain}/{self.username}:{self.password}"
            auth_extra = []
        cmd = [
            "impacket-dacledit",
            "-action", "read",
            "-dc-ip", self.dc_ip,
            "-principal", self.username,
            "-target-dn", target_dn,
            *auth_extra,
            creds,
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {"target_dn": target_dn, "output": (r.stdout + r.stderr)}
        except subprocess.TimeoutExpired:
            return {"target_dn": target_dn, "output": "[!] timed out"}
        except Exception as exc:
            return {"target_dn": target_dn, "output": f"[!] {exc}"}

    def analyze(self) -> dict[str, Any]:
        log.info("[ACL] Starting ACL analysis")
        sd_objects = self.enumerate_security_descriptors()
        high_value = self._high_value_dns()
        dacledit_results = [self.dacledit_read(dn) for dn in high_value[:6]]

        findings = []
        for r in dacledit_results:
            out = r.get("output", "")
            if any(kw in out for kw in ("WriteDACL", "WriteOwner", "GenericAll", "FullControl")):
                findings.append({
                    "type": "DANGEROUS_ACE",
                    "severity": "HIGH",
                    "target_dn": r["target_dn"],
                    "description": "Dangerous ACE detected on high-value object",
                })

        return {
            "sd_objects_count": len(sd_objects),
            "high_value_targets": high_value,
            "dacledit_results": dacledit_results,
            "findings": findings,
        }
