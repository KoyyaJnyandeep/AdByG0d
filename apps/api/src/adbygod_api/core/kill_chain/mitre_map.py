from __future__ import annotations

from typing import TypedDict


class MitreEntry(TypedDict):
    technique_id: str
    mitre_id: str
    mitre_name: str
    tactic: str
    severity: str
    cvss: float


_MAP: dict[str, MitreEntry] = {
    # ── Phase 0: Reconnaissance ───────────────────────────────────────────
    "recon-dns-enum":        {"technique_id": "recon-dns-enum",        "mitre_id": "T1590.002", "mitre_name": "Gather Victim Network Info: DNS",             "tactic": "reconnaissance",    "severity": "MEDIUM", "cvss": 4.3},
    "recon-subdomain-brute": {"technique_id": "recon-subdomain-brute", "mitre_id": "T1590.001", "mitre_name": "Gather Victim Network Info: IP Addresses",    "tactic": "reconnaissance",    "severity": "MEDIUM", "cvss": 4.3},
    "recon-whois-asn":       {"technique_id": "recon-whois-asn",       "mitre_id": "T1590.005", "mitre_name": "Gather Victim Network Info: Scan Databases",  "tactic": "reconnaissance",    "severity": "LOW",    "cvss": 3.1},
    "recon-cert-transparency":{"technique_id":"recon-cert-transparency","mitre_id": "T1596.003", "mitre_name": "Search Open Technical Databases: Digital Certificates", "tactic": "reconnaissance", "severity": "LOW", "cvss": 3.7},
    "recon-email-harvest":   {"technique_id": "recon-email-harvest",   "mitre_id": "T1589.002", "mitre_name": "Gather Victim Identity Info: Email Addresses", "tactic": "reconnaissance",   "severity": "LOW",    "cvss": 3.1},
    "recon-o365-enum":       {"technique_id": "recon-o365-enum",       "mitre_id": "T1589.003", "mitre_name": "Gather Victim Identity Info: Employee Names",  "tactic": "reconnaissance",    "severity": "MEDIUM", "cvss": 4.3},
    "recon-rid-cycling":     {"technique_id": "recon-rid-cycling",     "mitre_id": "T1087.002", "mitre_name": "Account Discovery: Domain Account",            "tactic": "reconnaissance",    "severity": "HIGH",   "cvss": 6.5},
    "recon-ldap-anon":       {"technique_id": "recon-ldap-anon",       "mitre_id": "T1087.002", "mitre_name": "Account Discovery: Domain Account",            "tactic": "reconnaissance",    "severity": "HIGH",   "cvss": 7.5},
    "recon-network-sweep":   {"technique_id": "recon-network-sweep",   "mitre_id": "T1046",     "mitre_name": "Network Service Discovery",                    "tactic": "discovery",         "severity": "MEDIUM", "cvss": 4.3},
    "recon-nbtscan":         {"technique_id": "recon-nbtscan",         "mitre_id": "T1046",     "mitre_name": "Network Service Discovery",                    "tactic": "discovery",         "severity": "LOW",    "cvss": 3.1},
    "recon-ipv6-discover":   {"technique_id": "recon-ipv6-discover",   "mitre_id": "T1590.005", "mitre_name": "Gather Victim Network Info: Scan Databases",   "tactic": "reconnaissance",    "severity": "LOW",    "cvss": 3.1},
    "recon-spf-dmarc":       {"technique_id": "recon-spf-dmarc",       "mitre_id": "T1590.002", "mitre_name": "Gather Victim Network Info: DNS",              "tactic": "reconnaissance",    "severity": "LOW",    "cvss": 2.5},
    "recon-smb-null":        {"technique_id": "recon-smb-null",        "mitre_id": "T1135",     "mitre_name": "Network Share Discovery",                      "tactic": "discovery",         "severity": "HIGH",   "cvss": 6.5},
    "recon-dc-fingerprint":  {"technique_id": "recon-dc-fingerprint",  "mitre_id": "T1590.001", "mitre_name": "Gather Victim Network Info: IP Addresses",     "tactic": "reconnaissance",    "severity": "MEDIUM", "cvss": 4.3},
    "recon-nmap-vuln":       {"technique_id": "recon-nmap-vuln",       "mitre_id": "T1210",     "mitre_name": "Exploitation of Remote Services",              "tactic": "lateral_movement",  "severity": "CRITICAL","cvss": 9.8},
    # ── Phase 1: Initial Access & Evasion ────────────────────────────────
    "ia-responder-capture":  {"technique_id": "ia-responder-capture",  "mitre_id": "T1557.001", "mitre_name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "tactic": "credential_access", "severity": "HIGH",   "cvss": 8.8},
    "ia-ntlm-relay":         {"technique_id": "ia-ntlm-relay",         "mitre_id": "T1557.001", "mitre_name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "tactic": "credential_access", "severity": "CRITICAL","cvss": 9.0},
    "ia-dhcpv6-mitm6":       {"technique_id": "ia-dhcpv6-mitm6",       "mitre_id": "T1557.001", "mitre_name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "tactic": "credential_access", "severity": "CRITICAL","cvss": 9.0},
    "ia-arp-poison":         {"technique_id": "ia-arp-poison",         "mitre_id": "T1557.002", "mitre_name": "Adversary-in-the-Middle: ARP Cache Poisoning",  "tactic": "credential_access", "severity": "HIGH",   "cvss": 8.1},
    "ia-rid-hijack":         {"technique_id": "ia-rid-hijack",         "mitre_id": "T1078.002", "mitre_name": "Valid Accounts: Domain Accounts",               "tactic": "initial_access",    "severity": "CRITICAL","cvss": 9.1},
    "ia-amsi-bypass":        {"technique_id": "ia-amsi-bypass",        "mitre_id": "T1562.001", "mitre_name": "Impair Defenses: Disable or Modify Tools",      "tactic": "defense_evasion",   "severity": "HIGH",   "cvss": 7.8},
    "ia-etw-bypass":         {"technique_id": "ia-etw-bypass",         "mitre_id": "T1562.006", "mitre_name": "Impair Defenses: Indicator Blocking",           "tactic": "defense_evasion",   "severity": "HIGH",   "cvss": 7.8},
    "ia-download-cradles":   {"technique_id": "ia-download-cradles",   "mitre_id": "T1059.001", "mitre_name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution",         "severity": "HIGH",   "cvss": 7.2},
    "ia-clm-bypass":         {"technique_id": "ia-clm-bypass",         "mitre_id": "T1059.001", "mitre_name": "Command and Scripting Interpreter: PowerShell", "tactic": "defense_evasion",   "severity": "HIGH",   "cvss": 7.8},
    "ia-applocker-bypass":   {"technique_id": "ia-applocker-bypass",   "mitre_id": "T1218",     "mitre_name": "System Binary Proxy Execution",                 "tactic": "defense_evasion",   "severity": "HIGH",   "cvss": 7.8},
    "ia-codecepticon":       {"technique_id": "ia-codecepticon",       "mitre_id": "T1027.002", "mitre_name": "Obfuscated Files or Information: Software Packing", "tactic": "defense_evasion", "severity": "MEDIUM","cvss": 5.5},
    "ia-edr-nanodump":       {"technique_id": "ia-edr-nanodump",       "mitre_id": "T1003.001", "mitre_name": "OS Credential Dumping: LSASS Memory",           "tactic": "credential_access", "severity": "CRITICAL","cvss": 9.0},
    "ia-edr-rwxfinder":      {"technique_id": "ia-edr-rwxfinder",      "mitre_id": "T1574",     "mitre_name": "Hijack Execution Flow",                         "tactic": "defense_evasion",   "severity": "HIGH",   "cvss": 7.8},
    "ia-edr-bof":            {"technique_id": "ia-edr-bof",            "mitre_id": "T1055",     "mitre_name": "Process Injection",                             "tactic": "defense_evasion",   "severity": "HIGH",   "cvss": 7.8},
    "ia-uac-fodhelper":      {"technique_id": "ia-uac-fodhelper",      "mitre_id": "T1548.002", "mitre_name": "Abuse Elevation Control Mechanism: Bypass UAC", "tactic": "privilege_escalation","severity": "HIGH",  "cvss": 7.8},
    "ia-uac-eventvwr":       {"technique_id": "ia-uac-eventvwr",       "mitre_id": "T1548.002", "mitre_name": "Abuse Elevation Control Mechanism: Bypass UAC", "tactic": "privilege_escalation","severity": "HIGH",  "cvss": 7.8},
    "ia-uac-cmstplua":       {"technique_id": "ia-uac-cmstplua",       "mitre_id": "T1548.002", "mitre_name": "Abuse Elevation Control Mechanism: Bypass UAC", "tactic": "privilege_escalation","severity": "HIGH",  "cvss": 7.8},
    "ia-uac-silentcleanup":  {"technique_id": "ia-uac-silentcleanup",  "mitre_id": "T1548.002", "mitre_name": "Abuse Elevation Control Mechanism: Bypass UAC", "tactic": "privilege_escalation","severity": "HIGH",  "cvss": 7.8},
    "ia-uac-sharpbypass":    {"technique_id": "ia-uac-sharpbypass",    "mitre_id": "T1548.002", "mitre_name": "Abuse Elevation Control Mechanism: Bypass UAC", "tactic": "privilege_escalation","severity": "HIGH",  "cvss": 7.8},
    "ia-pre2k-detect":       {"technique_id": "ia-pre2k-detect",       "mitre_id": "T1078.002", "mitre_name": "Valid Accounts: Domain Accounts",               "tactic": "initial_access",    "severity": "CRITICAL","cvss": 9.1},
    "ia-pre2k-auth":         {"technique_id": "ia-pre2k-auth",         "mitre_id": "T1110.003", "mitre_name": "Brute Force: Password Spraying",                "tactic": "credential_access", "severity": "HIGH",   "cvss": 7.5},
    "ia-timeroast":          {"technique_id": "ia-timeroast",          "mitre_id": "T1558",     "mitre_name": "Steal or Forge Kerberos Tickets",               "tactic": "credential_access", "severity": "HIGH",   "cvss": 8.1},
    "ia-maq-abuse":          {"technique_id": "ia-maq-abuse",          "mitre_id": "T1136.001", "mitre_name": "Create Account: Local Account",                 "tactic": "persistence",       "severity": "HIGH",   "cvss": 7.5},
    "ia-wsus-spoof":         {"technique_id": "ia-wsus-spoof",         "mitre_id": "T1072",     "mitre_name": "Software Deployment Tools",                     "tactic": "execution",         "severity": "CRITICAL","cvss": 9.0},
    "ia-wsus-exec":          {"technique_id": "ia-wsus-exec",          "mitre_id": "T1072",     "mitre_name": "Software Deployment Tools",                     "tactic": "execution",         "severity": "CRITICAL","cvss": 9.8},
    # ── Existing techniques ───────────────────────────────────────────────
    "privesc-kerberoast-impacket": {"technique_id": "privesc-kerberoast-impacket", "mitre_id": "T1558.003", "mitre_name": "Steal or Forge Kerberos Tickets: Kerberoasting", "tactic": "credential_access", "severity": "HIGH", "cvss": 8.1},
    "privesc-asreproast":          {"technique_id": "privesc-asreproast",           "mitre_id": "T1558.004", "mitre_name": "Steal or Forge Kerberos Tickets: AS-REP Roasting", "tactic": "credential_access", "severity": "HIGH", "cvss": 7.5},
    "privesc-shadow-copies":       {"technique_id": "privesc-shadow-copies",        "mitre_id": "T1003.003", "mitre_name": "OS Credential Dumping: NTDS", "tactic": "credential_access", "severity": "CRITICAL", "cvss": 9.1},
    "persist-golden-ticket":       {"technique_id": "persist-golden-ticket",        "mitre_id": "T1558.001", "mitre_name": "Steal or Forge Kerberos Tickets: Golden Ticket", "tactic": "persistence", "severity": "CRITICAL", "cvss": 10.0},
    "persist-dcsync":              {"technique_id": "persist-dcsync",               "mitre_id": "T1003.006", "mitre_name": "OS Credential Dumping: DCSync", "tactic": "credential_access", "severity": "CRITICAL", "cvss": 9.8},
    "latmov-ntlmrelay":            {"technique_id": "latmov-ntlmrelay",             "mitre_id": "T1557.001", "mitre_name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "tactic": "credential_access", "severity": "HIGH", "cvss": 8.8},
    "attack-shadow-creds":         {"technique_id": "attack-shadow-creds",          "mitre_id": "T1556.006", "mitre_name": "Modify Authentication Process", "tactic": "credential_access", "severity": "CRITICAL", "cvss": 9.1},
    "privesc-zerologon":           {"technique_id": "privesc-zerologon",             "mitre_id": "T1190",     "mitre_name": "Exploit Public-Facing Application", "tactic": "initial_access", "severity": "CRITICAL", "cvss": 10.0},
    "privesc-printnightmare":      {"technique_id": "privesc-printnightmare",        "mitre_id": "T1068",     "mitre_name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation", "severity": "CRITICAL", "cvss": 8.8},
    "privesc-nopac":               {"technique_id": "privesc-nopac",                 "mitre_id": "T1078.002", "mitre_name": "Valid Accounts: Domain Accounts", "tactic": "privilege_escalation", "severity": "CRITICAL", "cvss": 9.8},
}

_SEVERITY_CVSS: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 3.0,
    "INFO": 1.0,
}

ALL_TECHNIQUE_IDS: list[str] = list(_MAP.keys())


def get_mitre(technique_id: str) -> MitreEntry | None:
    return _MAP.get(technique_id)


def suggest_cvss(severity: str) -> float:
    return _SEVERITY_CVSS.get(severity.upper(), 5.0)


def enrich_technique(technique_id: str, finding_dict: dict) -> dict:
    """Merge MITRE data into a finding dict. Returns finding_dict unchanged if no entry found."""
    entry = _MAP.get(technique_id)
    if not entry:
        return finding_dict
    return {
        **finding_dict,
        "mitre_id": entry["mitre_id"],
        "mitre_name": entry["mitre_name"],
        "tactic": entry["tactic"],
        "cvss": finding_dict.get("cvss") or entry["cvss"],
    }
