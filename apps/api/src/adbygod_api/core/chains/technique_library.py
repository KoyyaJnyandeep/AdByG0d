"""
Complete offensive technique definitions.
Each technique knows: what it needs, what it produces, how to fall back.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TechniqueSpec:
    id: str
    label: str
    description: str
    mitre: str
    loot_produces: str | None   # loot_type key this technique writes
    loot_requires: str | None   # loot_type key this technique reads
    prerequisites: list[str]    # human-readable requirements
    fallbacks: list[str]        # technique IDs to try if this fails
    is_manual: bool = False     # requires human interaction (e.g. offline crack)
    manual_prompt: str = ""     # instruction shown to user when paused
    edge_types: list[str] = field(default_factory=list)  # graph edge types this covers


TECHNIQUES: dict[str, TechniqueSpec] = {
    # ── No-cred techniques ─────────────────────────────────────────────────
    "asreproast": TechniqueSpec(
        id="asreproast",
        label="AS-REP Roast",
        description="Request AS-REP for users with pre-auth disabled — no credentials needed",
        mitre="T1558.004",
        loot_produces="asrep_hashes",
        loot_requires=None,
        prerequisites=["Network access to DC port 88"],
        fallbacks=["kerberoast", "lookupsid"],
        edge_types=["NO_PREAUTH"],
    ),
    "lookupsid": TechniqueSpec(
        id="lookupsid",
        label="SID Enumeration",
        description="Enumerate domain users and groups via SMB null session or low-priv creds",
        mitre="T1087.002",
        loot_produces="user_list",
        loot_requires=None,
        prerequisites=["Network access to SMB port 445"],
        fallbacks=["samrdump"],
        edge_types=["MEMBER_OF", "CONTAINS"],
    ),
    "samrdump": TechniqueSpec(
        id="samrdump",
        label="SAMR Dump",
        description="Enumerate users, groups, and password policy via SAMR protocol",
        mitre="T1069.002",
        loot_produces="user_list",
        loot_requires=None,
        prerequisites=["Network access to SMB/SAMR"],
        fallbacks=["lookupsid"],
        edge_types=["MEMBER_OF"],
    ),

    # ── Domain-user techniques ─────────────────────────────────────────────
    "kerberoast": TechniqueSpec(
        id="kerberoast",
        label="Kerberoast",
        description="Request TGS tickets for SPN-bearing accounts — crack offline with hashcat",
        mitre="T1558.003",
        loot_produces="kerberos_hashes",
        loot_requires=None,
        prerequisites=["Domain user credentials or valid ticket"],
        fallbacks=["asreproast", "getuserspns"],
        edge_types=["HAS_SPN", "MEMBER_OF"],
    ),
    "getuserspns": TechniqueSpec(
        id="getuserspns",
        label="GetUserSPNs",
        description="Enumerate and roast all SPN-bearing users in the domain",
        mitre="T1558.003",
        loot_produces="kerberos_hashes",
        loot_requires=None,
        prerequisites=["Domain user credentials"],
        fallbacks=["kerberoast"],
        edge_types=["HAS_SPN"],
    ),
    "getnpusers": TechniqueSpec(
        id="getnpusers",
        label="GetNPUsers",
        description="Enumerate all users with Kerberos pre-auth disabled",
        mitre="T1558.004",
        loot_produces="asrep_hashes",
        loot_requires=None,
        prerequisites=["Domain user credentials (or none for targeted)"],
        fallbacks=["asreproast"],
        edge_types=["NO_PREAUTH"],
    ),

    # ── Credential-required techniques ────────────────────────────────────
    "secretsdump": TechniqueSpec(
        id="secretsdump",
        label="Secrets Dump",
        description="Dump SAM, LSA secrets, cached credentials from a target host",
        mitre="T1003.002",
        loot_produces="nt_hashes",
        loot_requires=None,
        prerequisites=["Admin access to target (local or domain)", "SMB reachable"],
        fallbacks=["wmiexec", "smbexec"],
        edge_types=["ADMIN_TO", "LOCAL_ADMIN", "DCSYNC"],
    ),
    "dcsync": TechniqueSpec(
        id="dcsync",
        label="DCSync",
        description="Replicate all domain credentials via MS-DRSR — requires DCSync rights",
        mitre="T1003.006",
        loot_produces="da_hashes",
        loot_requires=None,
        prerequisites=["DCSync rights (Domain Admin, Replicator, or WriteDACL abuse)"],
        fallbacks=["secretsdump"],
        edge_types=["DCSYNC", "GET_CHANGES", "GET_CHANGES_ALL", "WRITE_DACL", "GENERIC_ALL"],
    ),
    "wmiexec": TechniqueSpec(
        id="wmiexec",
        label="WMI Exec",
        description="Remote command execution via WMI — fileless, leaves fewer artifacts",
        mitre="T1047",
        loot_produces="command_output",
        loot_requires=None,
        prerequisites=["Admin credentials (plaintext or hash)", "WMI/RPC reachable"],
        fallbacks=["smbexec", "atexec", "psexec"],
        edge_types=["ADMIN_TO", "CAN_RDP", "CAN_WINRM", "LOCAL_ADMIN"],
    ),
    "smbexec": TechniqueSpec(
        id="smbexec",
        label="SMB Exec",
        description="Remote execution via SMB service creation — noisier but reliable",
        mitre="T1021.002",
        loot_produces="command_output",
        loot_requires=None,
        prerequisites=["Admin credentials (plaintext or hash)", "SMB reachable"],
        fallbacks=["wmiexec", "atexec", "psexec"],
        edge_types=["ADMIN_TO", "LOCAL_ADMIN"],
    ),
    "psexec": TechniqueSpec(
        id="psexec",
        label="PSExec",
        description="Remote execution via named pipe — classic lateral movement",
        mitre="T1569.002",
        loot_produces="command_output",
        loot_requires=None,
        prerequisites=["Admin credentials", "SMB + IPC$ reachable"],
        fallbacks=["wmiexec", "smbexec"],
        edge_types=["ADMIN_TO", "LOCAL_ADMIN"],
    ),
    "atexec": TechniqueSpec(
        id="atexec",
        label="AT Exec",
        description="Remote execution via Task Scheduler (AT service)",
        mitre="T1053.005",
        loot_produces="command_output",
        loot_requires=None,
        prerequisites=["Admin credentials", "Task Scheduler service reachable"],
        fallbacks=["wmiexec", "smbexec"],
        edge_types=["ADMIN_TO"],
    ),

    # ── Delegation / ticket techniques ────────────────────────────────────
    "getst": TechniqueSpec(
        id="getst",
        label="Silver / Service Ticket",
        description="Request a service ticket impersonating a target user (constrained delegation)",
        mitre="T1558.001",
        loot_produces="ccache_ticket",
        loot_requires=None,
        prerequisites=["SPN account with constrained delegation rights", "DC reachable"],
        fallbacks=["kerberoast"],
        edge_types=["ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT"],
    ),
    "getTGT": TechniqueSpec(
        id="getTGT",
        label="Get TGT",
        description="Obtain a TGT from domain credentials or hash — enables PTT attacks",
        mitre="T1558.003",
        loot_produces="ccache_ticket",
        loot_requires=None,
        prerequisites=["Domain credentials or NT hash"],
        fallbacks=["getst"],
        edge_types=["MEMBER_OF"],
    ),
    "ticketer": TechniqueSpec(
        id="ticketer",
        label="Golden Ticket",
        description="Forge a Golden Ticket using the krbtgt hash — unlimited domain access",
        mitre="T1558.001",
        loot_produces="golden_ticket",
        loot_requires="krbtgt_hash",
        prerequisites=["krbtgt NT hash", "Domain SID"],
        fallbacks=["dcsync"],
        edge_types=["DCSYNC"],
    ),

    # ── Manual steps ──────────────────────────────────────────────────────
    "manual_crack": TechniqueSpec(
        id="manual_crack",
        label="Offline Hash Cracking",
        description="Crack captured Kerberos/NTLM hashes with hashcat or john offline",
        mitre="T1110.002",
        loot_produces="cleartext_creds",
        loot_requires="kerberos_hashes",
        prerequisites=["GPU/CPU cracking rig", "Captured hash file"],
        fallbacks=[],
        is_manual=True,
        manual_prompt=(
            "Run hashcat against the captured hashes:\n"
            "  hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt\n"
            "  hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt\n\n"
            "Enter the cracked password below to continue the chain:"
        ),
        edge_types=[],
    ),
    "manual_crack_ntlm": TechniqueSpec(
        id="manual_crack_ntlm",
        label="NTLM Hash Cracking",
        description="Crack NT hashes extracted from secretsdump",
        mitre="T1110.002",
        loot_produces="cleartext_creds",
        loot_requires="nt_hashes",
        prerequisites=["Captured NT hashes"],
        fallbacks=[],
        is_manual=True,
        manual_prompt=(
            "Run hashcat against NTLM hashes:\n"
            "  hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt\n\n"
            "Or use Pass-the-Hash directly (enter 'pth' to skip cracking).\n"
            "Enter cracked password or 'pth' to use hash directly:"
        ),
        edge_types=[],
    ),

    # ── Demo / echo ───────────────────────────────────────────────────────
    "echo_test": TechniqueSpec(
        id="echo_test",
        label="Echo Test",
        description="Simulate technique execution — used for pipeline testing",
        mitre="T1087",
        loot_produces=None,
        loot_requires=None,
        prerequisites=["None — simulation only"],
        fallbacks=[],
        edge_types=[],
    ),
}


def get_technique(tid: str) -> TechniqueSpec | None:
    return TECHNIQUES.get(tid)
