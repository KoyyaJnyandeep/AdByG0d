from __future__ import annotations
from dataclasses import dataclass


@dataclass
class OpsecRating:
    level: str           # QUIET | MEDIUM | LOUD | CRITICAL
    event_ids: list[str]  # Windows Event IDs triggered
    note: str            # Human-readable warning


_RATINGS: dict[str, OpsecRating] = {
    "ldap-full-enum":       OpsecRating("QUIET", [], "LDAP query — baseline noise, often not logged"),
    "ldap-user-enum":       OpsecRating("QUIET", [], "LDAP user enumeration — low signal"),
    "dns-enum":             OpsecRating("QUIET", ["4662"], "DNS queries — rarely alerted"),
    "smb-share-enum":       OpsecRating("MEDIUM", ["5140"], "SMB share access — may trigger DLP"),
    "kerberoast-spns":      OpsecRating("MEDIUM", ["4769"], "Kerberoast — Event 4769 on DC for each SPN"),
    "asrep-roast":          OpsecRating("MEDIUM", ["4768"], "AS-REP Roast — Event 4768 for each account"),
    "ldap-password-spray":  OpsecRating("MEDIUM", ["4625", "4771"], "Password spray — lockout risk"),
    "bloodhound-collection":OpsecRating("MEDIUM", ["4662", "5136"], "BH collection — abnormal LDAP volume"),
    "pth-wmiexec":          OpsecRating("LOUD", ["4624", "4648"], "PTH via WMI — lateral movement event"),
    "pth-smbexec":          OpsecRating("LOUD", ["4624", "4776"], "PTH via SMB — service creation logged"),
    "secretsdump-remote":   OpsecRating("LOUD", ["4624", "4656"], "Remote secretsdump — heavy LSASS access"),
    "dcsync-domain":        OpsecRating("CRITICAL", ["4662"], "DCSync — replication event, very high signal"),
    "golden-ticket":        OpsecRating("CRITICAL", ["4769"], "Golden ticket — anomalous TGT"),
    "mimikatz-lsass":       OpsecRating("CRITICAL", ["4656", "10"], "LSASS dump — Defender/EDR almost certain"),
}

_DEFAULT = OpsecRating("MEDIUM", [], "Unknown technique — assume medium noise")


def get_opsec_rating(technique_id: str) -> OpsecRating:
    if technique_id in _RATINGS:
        return _RATINGS[technique_id]
    # Try prefix match (e.g. "dcsync-custom" matches "dcsync-domain" prefix group)
    for key, rating in _RATINGS.items():
        prefix = key.split("-")[0]
        if technique_id.startswith(prefix):
            return rating
    return _DEFAULT
