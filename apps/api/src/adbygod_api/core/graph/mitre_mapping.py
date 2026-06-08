"""MITRE ATT&CK technique mappings for AD graph edge types."""
from __future__ import annotations
from typing import Optional

EDGE_TO_TECHNIQUE: dict[str, dict] = {
    "HAS_SPN":                 {"technique_id": "T1558.003", "technique_name": "Kerberoasting", "tactic": "Credential Access"},
    "DCSYNC":                  {"technique_id": "T1003.006", "technique_name": "DCSync", "tactic": "Credential Access"},
    "ALLOWED_TO_DELEGATE":     {"technique_id": "T1558.001", "technique_name": "Golden Ticket via Delegation", "tactic": "Credential Access"},
    "ALLOWED_TO_ACT":          {"technique_id": "T1134.001", "technique_name": "RBCD Token Impersonation", "tactic": "Privilege Escalation"},
    "GENERIC_ALL":             {"technique_id": "T1484.001", "technique_name": "ACL Modification — GenericAll", "tactic": "Defense Evasion"},
    "WRITE_DACL":              {"technique_id": "T1484.001", "technique_name": "ACL Modification — WriteDACL", "tactic": "Defense Evasion"},
    "WRITE_OWNER":             {"technique_id": "T1484.001", "technique_name": "ACL Modification — WriteOwner", "tactic": "Defense Evasion"},
    "OWNS":                    {"technique_id": "T1484.001", "technique_name": "ACL Modification — Owns", "tactic": "Defense Evasion"},
    "FORCE_CHANGE_PASSWORD":   {"technique_id": "T1098.001", "technique_name": "Account Manipulation", "tactic": "Persistence"},
    "ADD_MEMBER":              {"technique_id": "T1098.001", "technique_name": "Account Manipulation — AddMember", "tactic": "Persistence"},
    "CAN_ENROLL":              {"technique_id": "T1649",     "technique_name": "Steal or Forge Auth Certificates", "tactic": "Credential Access"},
    "ADCS_RELAY":              {"technique_id": "T1557.001", "technique_name": "NTLM Relay to ADCS", "tactic": "Credential Access"},
    "ADCS_ESC1":               {"technique_id": "T1649",     "technique_name": "ESC1 Certificate Abuse", "tactic": "Credential Access"},
    "ADCS_ESC8":               {"technique_id": "T1649",     "technique_name": "ESC8 Web Enrollment Relay", "tactic": "Credential Access"},
    "ADCS_ESC15":              {"technique_id": "T1649",     "technique_name": "ESC15 CES Abuse", "tactic": "Credential Access"},
    "PASS_THE_HASH":           {"technique_id": "T1550.002", "technique_name": "Pass the Hash", "tactic": "Lateral Movement"},
    "PASS_THE_TICKET":         {"technique_id": "T1550.003", "technique_name": "Pass the Ticket", "tactic": "Lateral Movement"},
    "PASS_THE_CERT":           {"technique_id": "T1550.003", "technique_name": "Pass the Certificate", "tactic": "Lateral Movement"},
    "OVERPASS_THE_HASH":       {"technique_id": "T1550.002", "technique_name": "Overpass-the-Hash", "tactic": "Lateral Movement"},
    "ADMIN_TO":                {"technique_id": "T1021.002", "technique_name": "Remote Services — SMB/Admin Share", "tactic": "Lateral Movement"},
    "LOCAL_ADMIN":             {"technique_id": "T1021.002", "technique_name": "Local Admin Access", "tactic": "Lateral Movement"},
    "DCOM_EXEC":               {"technique_id": "T1021.003", "technique_name": "Distributed Component Object Model", "tactic": "Lateral Movement"},
    "WMI_EXEC":                {"technique_id": "T1047",     "technique_name": "Windows Management Instrumentation", "tactic": "Execution"},
    "SCM_EXEC":                {"technique_id": "T1569.002", "technique_name": "Service Control Manager Execution", "tactic": "Execution"},
    "REMOTE_EXEC":             {"technique_id": "T1021",     "technique_name": "Remote Services", "tactic": "Lateral Movement"},
    "GPO_EXEC":                {"technique_id": "T1484.001", "technique_name": "GPO Modification for Code Execution", "tactic": "Defense Evasion"},
    "COERCION":                {"technique_id": "T1187",     "technique_name": "Forced Authentication", "tactic": "Credential Access"},
    "PETITPOTAM":              {"technique_id": "T1187",     "technique_name": "PetitPotam NTLM Coercion", "tactic": "Credential Access"},
    "PRINTSPOOLER":            {"technique_id": "T1187",     "technique_name": "PrintSpooler Coercion", "tactic": "Credential Access"},
    "SHADOWCOERCE":            {"technique_id": "T1187",     "technique_name": "ShadowCoerce", "tactic": "Credential Access"},
    "NTLM_RELAY":              {"technique_id": "T1557.001", "technique_name": "NTLM Relay", "tactic": "Credential Access"},
    "KERBEROS_RELAY":          {"technique_id": "T1558",     "technique_name": "Kerberos Relay", "tactic": "Credential Access"},
    "READ_LAPS_PASSWORD":      {"technique_id": "T1552.004", "technique_name": "LAPS Password Read", "tactic": "Credential Access"},
    "READ_GMSA_PASSWORD":      {"technique_id": "T1552.004", "technique_name": "gMSA Password Read", "tactic": "Credential Access"},
    "ADD_KEY_CREDENTIAL_LINK": {"technique_id": "T1098.004", "technique_name": "Shadow Credentials", "tactic": "Persistence"},
    "GOLDEN_TICKET":           {"technique_id": "T1558.001", "technique_name": "Golden Ticket", "tactic": "Credential Access"},
    "SID_HISTORY":             {"technique_id": "T1134.005", "technique_name": "SID-History Injection", "tactic": "Privilege Escalation"},
    "AADCONNECT_SYNC":         {"technique_id": "T1484.002", "technique_name": "Domain Trust Modification via AADConnect", "tactic": "Defense Evasion"},
    "DNS_ADMIN_EXEC":          {"technique_id": "T1071.004", "technique_name": "DNS Admin Code Execution", "tactic": "Execution"},
    "SEIMPERSONATE":           {"technique_id": "T1134.002", "technique_name": "SeImpersonatePrivilege Abuse", "tactic": "Privilege Escalation"},
    "MSSQL_LINKED":            {"technique_id": "T1021.002", "technique_name": "MSSQL Linked Server Pivot", "tactic": "Lateral Movement"},
    "MSSQL_CLR":               {"technique_id": "T1059",     "technique_name": "MSSQL CLR Code Execution", "tactic": "Execution"},
    "MEMBER_OF":               {"technique_id": "T1069",     "technique_name": "Permission Groups Discovery", "tactic": "Discovery"},
    "CONTAINS":                {"technique_id": "T1069",     "technique_name": "OU/Container Enumeration", "tactic": "Discovery"},
    "TRUSTS":                  {"technique_id": "T1482",     "technique_name": "Domain Trust Discovery", "tactic": "Discovery"},
    "CVE_CHAIN":               {"technique_id": "T1203",     "technique_name": "Exploitation for Client Execution", "tactic": "Execution"},
}

TOOL_SUGGESTIONS: dict[str, str] = {
    "T1558.003": "Rubeus.exe kerberoast /outfile:hashes.txt  |  impacket-GetUserSPNs -request",
    "T1003.006": "impacket-secretsdump -just-dc DOMAIN/user:pass@DC  |  mimikatz lsadump::dcsync",
    "T1558.001": "Rubeus.exe golden /domain:DOMAIN /sid:S-1-5-... /rc4:HASH /user:Administrator",
    "T1484.001": "Add-DomainObjectAcl / Set-DomainObjectOwner (PowerView)  |  bloodyAD",
    "T1649":     "Certipy req -ca CA -template Template -upn admin@domain  |  Certify.exe request",
    "T1557.001": "Responder -I eth0  |  ntlmrelayx.py -t ldaps://DC --delegate-access",
    "T1550.002": "impacket-psexec -hashes :NTLM domain/user@target  |  mimikatz sekurlsa::pth",
    "T1550.003": "Rubeus.exe ptt /ticket:base64  |  impacket-ticketer",
    "T1021.002": "impacket-psexec / impacket-smbexec / CrackMapExec smb",
    "T1047":     "impacket-wmiexec domain/user:pass@target  |  CrackMapExec wmi",
    "T1187":     "impacket-ntlmrelayx --remove-mic  |  PetitPotam.py attacker target",
    "T1098.004": "pywhisker  |  Whisker.exe add /target:USER",
    "T1552.004": "crackmapexec ldap DC -u user -p pass --gmsa  |  LAPSToolkit",
    "T1134.002": "PrintSpoofer.exe -i -c cmd  |  RoguePotato",
}

SIGMA_SNIPPETS: dict[str, str] = {
    "T1558.003": "EventID: 4769 | ServiceName: not ends with '$' | TicketEncryptionType: 0x17",
    "T1003.006": "EventID: 4662 | Properties: contains '1131f6aa' or '1131f6ab'",
    "T1484.001": "EventID: 5136 | AttributeLDAPDisplayName: nTSecurityDescriptor",
    "T1557.001": "Network: SMBv1 | Destination: DC | Source: != Domain Member",
    "T1558.001": "EventID: 4769 | ServiceName: krbtgt | TicketOptions: 0x40810000",
    "T1098.004": "EventID: 5136 | AttributeLDAPDisplayName: msDS-KeyCredentialLink",
    "T1187":     "EventID: 4624 | LogonType: 3 | AuthPackage: NTLM | Source: unusual",
}


def edge_to_mitre(edge_type: str) -> Optional[dict]:
    return EDGE_TO_TECHNIQUE.get(edge_type.upper())


def path_to_techniques(steps: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result = []
    for step in steps:
        etype = (step.get("edge_type") or "").upper()
        if not etype:
            continue
        mapping = EDGE_TO_TECHNIQUE.get(etype)
        if mapping and mapping["technique_id"] not in seen:
            seen.add(mapping["technique_id"])
            tool = TOOL_SUGGESTIONS.get(mapping["technique_id"], "")
            sigma = SIGMA_SNIPPETS.get(mapping["technique_id"], "")
            result.append({
                **mapping,
                "edge_type": etype,
                "tool_suggestion": tool,
                "sigma_snippet": sigma,
            })
    return result
