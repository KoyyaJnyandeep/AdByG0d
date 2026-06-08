"""Static attack-flow chains mapped from the AD Attack Architecture reference."""

from __future__ import annotations

from typing import Any


def _chain(
    chain_id: str,
    name: str,
    category: str,
    risk: str,
    score: float,
    source: str,
    target: str,
    steps: list[str],
    edge_types: list[str],
    explanation: str,
    mitre_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": chain_id,
        "source_id": f"playbook:{chain_id}:source",
        "target_id": f"playbook:{chain_id}:target",
        "source_label": source,
        "target_label": target,
        "hop_count": max(1, len(steps) - 1),
        "path_score": score,
        "risk_level": risk,
        "explanation": explanation,
        "steps": [
            {
                "entity_id": f"playbook:{chain_id}:{index}",
                "entity_label": step,
                "entity_type": "UNKNOWN",
                "edge_type": edge_types[min(index, len(edge_types) - 1)] if edge_types else None,
                "provenance": "AD Attack Architecture / Attack Flow Chains",
                "explanation": step,
            }
            for index, step in enumerate(steps)
        ],
        "edge_types": edge_types,
        "category": category,
        "mitre_attack_ids": mitre_ids or [],
        "origin": "architecture_playbook",
    }


ATTACK_FLOW_CHAINS: list[dict[str, Any]] = [
    _chain("rbcd_to_nt_hash", "RBCD to NT Hash", "rbcd", "CRITICAL", 92, "GenericWrite on target computer", "NT hash / shell", ["GenericWrite on target$", "write RBCD", "msDS-AllowedToAct", "S4U2Self", "Forwardable TGS", "S4U2Proxy", "TGS as admin", "impersonate", "NT hash / shell"], ["GENERIC_WRITE", "ALLOWED_TO_ACT"], "Resource-Based Constrained Delegation chain from writable computer object to admin impersonation.", ["T1558.001"]),
    _chain("unconstrained_delegation_dcsync", "Unconstrained Delegation to DCSync", "delegation", "CRITICAL", 96, "Unconstrained host", "DCSync", ["Find unconstrained host", "Coercer", "Coerce DC to target", "Rubeus dump", "Extract DC TGT", "Pass the Ticket", "DCSync"], ["ALLOWED_TO_DELEGATE", "COERCION", "DCSYNC"], "Coerce a DC to authenticate to an unconstrained host, extract the DC TGT, then replicate secrets.", ["T1558.001", "T1003.006"]),
    _chain("acl_abuse_chain", "ACL Abuse Chain", "acl_abuse", "CRITICAL", 90, "Weak ACE", "Domain control", ["ForceChangePwd", "GenericWrite", "WriteDACL", "AddMember", "WriteOwner", "GenericAll", "DC GenericAll"], ["FORCE_CHANGE_PASSWORD", "GENERIC_WRITE", "WRITE_DACL", "ADD_MEMBER", "WRITE_OWNER", "GENERIC_ALL"], "Classic escalation ladder where one directory right is chained into broader object or domain control.", ["T1098", "T1222"]),
    _chain("esc15_ekuwu_da", "ADCS ESC15 EKUwu to Domain Admin", "adcs", "CRITICAL", 94, "Schema v1 template", "Domain Admin", ["Find Schema v1 template", "certipy req", "Inject App Policy EKU", "SAN admin", "Rogue cert issued", "PKINIT", "DA / NT hash"], ["CAN_ENROLL", "ADCS_ESC15", "PASS_THE_CERT"], "ESC15/EKU injection path from vulnerable template to certificate authentication as admin.", ["T1649"]),
    _chain("child_parent_trust_escalation", "Child to Parent Trust Escalation", "trust_escalation", "CRITICAL", 98, "Owned child domain", "Forest owned", ["Own child domain", "secretsdump", "Dump child krbtgt", "get SIDs", "Parent + Child SID", "ticketer -519", "Golden + EA SID", "DCSync parent", "Forest owned"], ["TRUSTS", "EXTRASID", "GOLDEN_TICKET", "DCSYNC"], "Child-domain compromise can become forest compromise through ExtraSID and parent-domain replication.", ["T1558.001", "T1003.006"]),
    _chain("sccm_domain_compromise", "SCCM to Domain Compromise", "sccm", "CRITICAL", 90, "SCCM site", "Domain compromise", ["sccmhunter find", "NAA creds", "Harvest secrets", "push coerce", "NTLM relay to LDAP", "TAKEOVER", "Site takeover"], ["SCCM_MANAGES", "CREDENTIAL_ACCESS", "NTLM_RELAY"], "SCCM management-plane exposure chained through credentials, relay, and site takeover.", ["T1078", "T1021"]),
    _chain("kerberoast_da", "Kerberoasting to Domain Admin", "kerberoast", "HIGH", 82, "SPN service account", "Domain Admin", ["Enumerate SPNs", "GetUserSPNs", "Request TGS RC4", "hashcat 13100", "Crack offline", "PtH / auth", "Service account access"], ["HAS_SPN", "KERBEROAST", "PASS_THE_HASH"], "SPN exposure plus crackable service-account password can produce privileged access.", ["T1558.003", "T1078"]),
    _chain("shadow_credentials_nt_hash", "Shadow Credentials to NT Hash", "shadow_credentials", "CRITICAL", 91, "GenericWrite on user", "NT hash / TGT", ["GenericWrite on user", "write key", "msDS-KeyCredentialLink", "certipy shadow", "Get certificate", "PKINIT", "NT hash / TGT"], ["GENERIC_WRITE", "ADD_KEY_CREDENTIAL_LINK", "PASS_THE_CERT"], "Write msDS-KeyCredentialLink to authenticate as the target without changing their password.", ["T1558.004"]),
    _chain("petitpotam_esc8_dcsync", "PetitPotam to ESC8 to DCSync", "adcs", "CRITICAL", 97, "Coerced DC", "All domain hashes", ["Coerce DC with PetitPotam", "relay NTLM", "ntlmrelayx to ADCS HTTP", "enroll as DC", "DC certificate", "PKINIT", "DC TGT + NT hash", "DCSync", "All domain hashes"], ["COERCION", "NTLM_RELAY", "ADCS_ESC8", "DCSYNC"], "Coerce DC authentication and relay to AD CS web enrollment for a DC certificate and replication rights.", ["T1187", "T1649", "T1003.006"]),
    _chain("llmnr_relay_rbcd", "LLMNR Poisoning to Relay to RBCD", "relay", "HIGH", 84, "Responder poisoning", "NT hash / shell", ["Responder poisoning", "capture auth", "ntlmrelayx to LDAP", "set RBCD", "RBCD on target", "S4U chain", "TGS as admin", "secretsdump", "NT hash / shell"], ["POISONING", "NTLM_RELAY", "ALLOWED_TO_ACT"], "Name-resolution poisoning can feed LDAP relay and RBCD setup when mitigations are missing.", ["T1557.001", "T1558.001"]),
    _chain("writedacl_dcsync_golden", "WriteDACL to DCSync to Golden Ticket", "dcsync", "CRITICAL", 99, "WriteDACL on domain", "Golden Ticket", ["WriteDACL on domain", "dacledit", "Grant DCSync rights", "secretsdump", "Dump krbtgt hash", "ticketer", "Golden Ticket"], ["WRITE_DACL", "DCSYNC", "GOLDEN_TICKET"], "Domain-root DACL control can grant replication rights and lead directly to krbtgt-backed ticket persistence.", ["T1222", "T1003.006", "T1558.001"]),
    _chain("nopac_da", "noPac to Domain Admin", "cve", "CRITICAL", 96, "Machine account", "Domain Admin", ["Create machine account", "rename to DC", "SAMAccountName = DC", "request TGT", "TGT as DC name", "rename back", "Request TGS to DC$", "DCSync", "Domain Admin"], ["CVE_CHAIN", "MACHINE_ACCOUNT", "DCSYNC"], "CVE-2021-42278/42287 chain using machine-account rename confusion to obtain DC-equivalent access.", ["T1136.002", "T1003.006"]),
    _chain("zerologon_da", "ZeroLogon to Instant DA", "cve", "CRITICAL", 100, "Netlogon zero challenge", "Domain owned", ["Netlogon zero challenge", "~256 tries", "DC password to empty", "auth as DC$", "DCSync all hashes", "restore password", "Domain owned"], ["CVE_CHAIN", "DCSYNC"], "CVE-2020-1472 can reset a DC machine password and expose all domain secrets; extremely disruptive.", ["T1003.006"]),
    _chain("gmsa_lateral_movement", "gMSA Read to Lateral Movement", "credential_access", "HIGH", 78, "gMSA reader", "Service access / DA", ["Find gMSA readers", "gMSADumper", "Read msDS-ManagedPwd", "extract hash", "gMSA NT hash", "PtH / TGT", "Service access / DA"], ["READ_GMSA_PASSWORD", "PASS_THE_HASH", "PASS_THE_TICKET"], "Over-broad gMSA password-read permissions can expose reusable service identity material.", ["T1552.006", "T1078"]),
    _chain("mssql_linked_servers_exec", "MSSQL Linked Servers to Code Execution", "mssql", "HIGH", 76, "SQL SPN", "SYSTEM on SQL host", ["Find MSSQL via SPN enum", "mssqlclient", "Enum linked servers", "EXEC AT", "Crawl link chain", "xp_cmdshell", "SYSTEM on SQL host"], ["HAS_SPN", "SQL_ADMIN", "REMOTE_EXEC"], "SQL linked-server trust can bridge service access into OS command execution.", ["T1505.001", "T1021"]),
    _chain("mitm6_wpad_relay_da", "mitm6 WPAD Relay to DA", "relay", "CRITICAL", 88, "DHCPv6 poison", "DA / RBCD / Shadow Creds", ["mitm6 DHCPv6 poison", "WPAD proxy", "Victims auth via NTLM", "ntlmrelayx", "Relay to LDAP(S)", "delegate / add user", "DA / RBCD / Shadow Creds"], ["POISONING", "NTLM_RELAY", "ALLOWED_TO_ACT", "ADD_MEMBER"], "IPv6/WPAD poisoning can create relay opportunities into LDAP when signing/channel binding are weak.", ["T1557.001", "T1098"]),
    _chain("webdav_relay_rbcd", "WebDAV Coercion to HTTP Relay to RBCD", "relay", "HIGH", 84, "WebClient enabled", "Admin on target", ["Find WebClient enabled", "coerce HTTP", "PetitPotam @80", "relay LDAP", "ntlmrelayx set RBCD", "S4U chain", "Admin on target"], ["WEBDAV", "COERCION", "NTLM_RELAY", "ALLOWED_TO_ACT"], "HTTP coercion through WebDAV avoids SMB signing constraints and can land RBCD.", ["T1187", "T1558.001"]),
    _chain("certifried_da", "Certifried to DA", "cve", "CRITICAL", 93, "Machine account", "DCSync / DA", ["Create machine account", "set dNSHostName", "dNSHostName = DC FQDN", "certipy req", "Cert issued as DC$", "PKINIT", "DCSync / DA"], ["CVE_CHAIN", "CAN_ENROLL", "PASS_THE_CERT", "DCSYNC"], "CVE-2022-26923 abuses machine certificate mapping through dNSHostName manipulation.", ["T1649", "T1003.006"]),
    _chain("printnightmare_system", "PrintNightmare to SYSTEM", "cve", "CRITICAL", 91, "SMB DLL share", "SYSTEM / DA if DC", ["Host SMB share + DLL", "AddPrinterDriverEx", "Target loads malicious DLL", "Spooler SYSTEM", "Code exec as SYSTEM", "if DC", "DCSync / DA"], ["CVE_CHAIN", "REMOTE_EXEC", "DCSYNC"], "CVE-2021-34527 can turn print spooler exposure into SYSTEM execution; on DCs it becomes domain-impacting.", ["T1068", "T1003.006"]),
    _chain("esc1_direct_da", "ESC1 Direct to Domain Admin", "adcs", "CRITICAL", 95, "SAN template", "DA NT hash", ["certipy find vulnerable", "SAN template", "certipy req -upn DA", "cert issued", "certipy auth -pfx", "PKINIT", "DA NT hash"], ["CAN_ENROLL", "ADCS_ESC1", "PASS_THE_CERT"], "User-supplied SAN plus client authentication enables direct certificate auth as a privileged user.", ["T1649"]),
    _chain("constrained_delegation_no_pt", "Constrained Delegation without Protocol Transition", "delegation", "HIGH", 80, "Delegated service", "Admin access", ["Find msDS-AllowedToDelegateTo", "no T2A4D", "Need victim auth to svc", "coerce / RBCD trick", "Forwardable TGS obtained", "S4U2Proxy", "TGS for allowed SPN", "alt service", "Admin access"], ["ALLOWED_TO_DELEGATE", "COERCION", "S4U"], "Constrained delegation without protocol transition still becomes exploitable when a forwardable victim ticket is obtained.", ["T1558.001"]),
    _chain("dnsadmins_dll_system", "DnsAdmins DLL Load to SYSTEM on DC", "acl_abuse", "CRITICAL", 89, "DnsAdmins member", "SYSTEM on DC / DA", ["Member of DnsAdmins", "dnscmd", "Set ServerLevelPlugin DLL", "restart DNS", "DLL loaded as SYSTEM", "on DC", "SYSTEM on DC to DA"], ["DNS_ADMINS", "REMOTE_EXEC", "DCSYNC"], "DnsAdmins membership can load a DLL into the DNS service running as SYSTEM on a DC.", ["T1546.008"]),
    _chain("file_drop_hash_capture", "LNK SCF URL File Drop to Hash Capture", "credential_access", "MEDIUM", 64, "Writable share", "Credentials / shell", ["Write access to share", "drop LNK/SCF/URL", "User browses share", "auto-auth", "NTLMv2 to Responder", "crack or relay", "Credentials / shell"], ["FILE_DROP", "NTLM_CAPTURE", "NTLM_RELAY"], "Explorer-triggered UNC resolution can leak Net-NTLM material from file drops in writable shares.", ["T1187"]),
    _chain("krbrelayup_local_admin", "KrbRelayUp to Local Admin", "delegation", "HIGH", 82, "Low-priv domain user", "Local Admin", ["Low-priv domain user", "create machine$", "Coerce local SYSTEM", "relay Kerberos", "Set RBCD on local host", "S4U chain", "Local Admin"], ["MACHINE_ACCOUNT", "KERBEROS_RELAY", "ALLOWED_TO_ACT"], "Machine-account creation plus local Kerberos relay can establish local admin through RBCD.", ["T1558.001"]),
    _chain("cross_forest_sid_history", "Cross-Forest via Golden and SID History", "trust_escalation", "CRITICAL", 90, "Owned trusted forest", "Cross-forest resources", ["Own trusted forest", "dump krbtgt", "Craft Golden Ticket", "SID History RID > 1000", "Inject cross-forest SID", "access resources", "Groups with RID > 1000"], ["TRUSTS", "GOLDEN_TICKET", "SID_HISTORY"], "Trusted-forest compromise can cross boundaries when SID filtering and resource SIDs allow it.", ["T1558.001"]),
    _chain("pre2k_machine_compromise", "Pre-Windows 2000 Computer Account to Domain Compromise", "credential_access", "HIGH", 79, "Pre2k machine account", "Lateral movement / DA", ["Enum pre2k accounts", "pre2k tool", "Auth with machine name password", "lowercase name", "Machine account TGT", "S4U / RBCD / Silver", "Lateral movement / DA"], ["MACHINE_ACCOUNT", "PRE2K", "S4U"], "Legacy compatible machine-account passwords can produce valid machine auth and delegation paths.", ["T1078.002"]),
    _chain("remotemonologue_lateral", "RemoteMonologue to DCOM NTLMv2 to Lateral Movement", "credential_access", "HIGH", 72, "DCOM trigger", "Lateral movement / DA", ["DCOM trigger on target", "Internal-Monologue", "NTLMv2 hash captured", "crack or relay", "Crack / Relay hash", "PtH / auth", "Lateral Movement / DA"], ["DCOM", "NTLM_CAPTURE", "PASS_THE_HASH"], "Remote DCOM-triggered NTLM material can be cracked or relayed into lateral movement.", ["T1187", "T1021"]),
    _chain("kerberos_cname_relay", "Kerberos Relay via CNAME to DNS Abuse", "relay", "HIGH", 81, "Registered CNAME", "Privilege escalation", ["Register CNAME record", "victim resolves", "Kerberos auth redirected", "relay to LDAP", "Relay to LDAP / service", "escalate", "Privilege Escalation"], ["ADIDNS_CAN_WRITE", "KERBEROS_RELAY"], "DNS CNAME control can redirect Kerberos authentication into relay paths.", ["T1557"]),
    _chain("cve_2025_24071_hash_leak", "CVE-2025-24071 Library-ms Archive Hash Leak", "cve", "HIGH", 74, ".library-ms archive", "Credentials / shell", ["Craft .library-ms file", "package in archive", "RAR / ZIP with payload", "victim extracts", "Explorer resolves UNC", "auto-auth", "NTLMv2 hash leaked", "crack or relay", "Credentials / shell"], ["CVE_CHAIN", "NTLM_CAPTURE", "NTLM_RELAY"], "Crafted archive handling can trigger outbound SMB auth and leak NTLMv2 material.", ["T1187"]),
    _chain("walking_dead_disabled_account", "Walking Dead Disabled Account Privesc", "acl_abuse", "HIGH", 73, "Disabled account", "Privilege escalation", ["Enum disabled accounts", "LazarusWakeUp", "Find ACL GenericAll", "re-enable", "Account alive + privs", "auth as user", "Privilege Escalation"], ["GENERIC_ALL", "ACCOUNT_ENABLE"], "Disabled privileged accounts can revive if another principal has rights to re-enable them.", ["T1098"]),
    _chain("ad_recycle_bin_restore", "AD Recycle Bin Restore Deleted Object Privesc", "acl_abuse", "HIGH", 75, "Deleted object", "Domain Admin", ["Enum deleted objects", "bloodyAD", "Find writable deleted object", "restore", "Object + group memberships", "auth / SID History", "Domain Admin"], ["AD_RECYCLE_BIN", "GENERIC_WRITE", "SID_HISTORY"], "Deleted objects can retain group/SID context and become dangerous if restorable by weak ACLs.", ["T1098"]),
]


def list_attack_flow_chains() -> list[dict[str, Any]]:
    return ATTACK_FLOW_CHAINS


def attack_flow_categories() -> dict[str, dict[str, Any]]:
    meta = {
        "rbcd": ("RBCD Chains", "#22d3ee", "network"),
        "delegation": ("Delegation Chains", "#06b6d4", "repeat"),
        "acl_abuse": ("ACL Abuse Chains", "#ef4444", "shield-x"),
        "adcs": ("AD CS Chains", "#10b981", "certificate"),
        "trust_escalation": ("Trust Escalation", "#a855f7", "git-branch"),
        "sccm": ("SCCM Chains", "#f59e0b", "braces"),
        "kerberoast": ("Kerberoast Chains", "#f97316", "key"),
        "shadow_credentials": ("Shadow Credential Chains", "#c084fc", "eye"),
        "relay": ("Relay Chains", "#38bdf8", "radio"),
        "dcsync": ("DCSync Chains", "#ef4444", "database"),
        "cve": ("CVE Chains", "#fb7185", "alert-triangle"),
        "credential_access": ("Credential Access Chains", "#f472b6", "database"),
        "mssql": ("MSSQL Chains", "#eab308", "database"),
    }
    categories: dict[str, dict[str, Any]] = {}
    for chain in ATTACK_FLOW_CHAINS:
        key = chain["category"]
        name, color, icon = meta.get(key, (key.replace("_", " ").title(), "#818cf8", "route"))
        category = categories.setdefault(key, {"name": name, "icon": icon, "color": color, "count": 0, "paths": []})
        category["count"] += 1
        category["paths"].append(chain)
    return categories
