from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class ValidationModuleDefinition:
    id: str
    name: str
    description: str
    version: str
    expert_count: int
    mitre_techniques: list[str]
    severity_range: tuple[str, str]
    risk_category: str


VALIDATION_MODULE_INDEX = {
    "kerberos": ValidationModuleDefinition(
        id="kerberos",
        name="Kerberos Attack Surface",
        description="AS-REP roasting, Kerberoasting, delegation abuse, golden ticket risk, encryption downgrade",
        version="1.0",
        expert_count=4,
        mitre_techniques=["T1558.001", "T1558.003", "T1558.004", "T1550.003"],
        severity_range=("MEDIUM", "CRITICAL"),
        risk_category="credential_access",
    ),
    "acl": ValidationModuleDefinition(
        id="acl",
        name="ACL / Permission Abuse",
        description="GenericAll/WriteDACL/WriteOwner edges to privileged objects, AdminSDHolder, ownership abuse",
        version="1.0",
        expert_count=3,
        mitre_techniques=["T1222.001", "T1078.002"],
        severity_range=("MEDIUM", "CRITICAL"),
        risk_category="privilege_escalation",
    ),
    "dcsync": ValidationModuleDefinition(
        id="dcsync",
        name="DCSync Reachability",
        description="Replication rights on domain objects enabling credential dumping via GetNCChanges",
        version="1.0",
        expert_count=1,
        mitre_techniques=["T1003.006"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="credential_access",
    ),
    "ntlm_relay": ValidationModuleDefinition(
        id="ntlm_relay",
        name="NTLM Relay & Coercion",
        description="NTLM relay attack surface, WebClient service, PetitPotam, coercion vectors",
        version="1.0",
        expert_count=2,
        mitre_techniques=["T1557.001"],
        severity_range=("MEDIUM", "CRITICAL"),
        risk_category="lateral_movement",
    ),
    "trust": ValidationModuleDefinition(
        id="trust",
        name="Trust Abuse & Forest Pivoting",
        description="Cross-domain/forest trust abuse, SID filtering gaps, forest trust exploitation",
        version="1.0",
        expert_count=3,
        mitre_techniques=["T1482", "T1134.005"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="lateral_movement",
    ),
    "adcs": ValidationModuleDefinition(
        id="adcs",
        name="ADCS Certificate Abuse",
        description="ESC1-ESC8 certificate template vulnerabilities, CA misconfiguration, CVE-2022-26923",
        version="1.0",
        expert_count=5,
        mitre_techniques=["T1649", "T1557.001"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="credential_access",
    ),
    "shadow_credentials": ValidationModuleDefinition(
        id="shadow_credentials",
        name="Shadow Credentials",
        description="msDS-KeyCredentialLink write abuse, Whisker/pywhisker attack surface, PKINIT chains",
        version="1.0",
        expert_count=3,
        mitre_techniques=["T1098.004", "T1558"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="persistence",
    ),
    "gpo_abuse": ValidationModuleDefinition(
        id="gpo_abuse",
        name="GPO Write Abuse",
        description="GPO write access by non-admins, scope blast radius, scheduled task injection, delegation",
        version="1.0",
        expert_count=4,
        mitre_techniques=["T1484.001", "T1053.005"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="persistence",
    ),
    "laps_exposure": ValidationModuleDefinition(
        id="laps_exposure",
        name="LAPS Password Exposure",
        description="LAPS read rights, coverage gaps, password expiry analysis",
        version="1.0",
        expert_count=3,
        mitre_techniques=["T1552.001", "T1078.002"],
        severity_range=("MEDIUM", "HIGH"),
        risk_category="credential_access",
    ),
    "delegation": ValidationModuleDefinition(
        id="delegation",
        name="Delegation Deep Dive",
        description="Unconstrained/constrained delegation, RBCD chains, S4U2Proxy, TGT capture vectors",
        version="1.0",
        expert_count=5,
        mitre_techniques=["T1558.001", "T1550.003"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="credential_access",
    ),
    "password_policy": ValidationModuleDefinition(
        id="password_policy",
        name="Password Policy & Spray Surface",
        description="Weak default/FGPP policies, spray candidate identification, passwordNeverExpires",
        version="1.0",
        expert_count=4,
        mitre_techniques=["T1110.003", "T1110"],
        severity_range=("LOW", "HIGH"),
        risk_category="initial_access",
    ),
    "sid_history": ValidationModuleDefinition(
        id="sid_history",
        name="SID History Abuse",
        description="sIDHistory attribute abuse, implicit privilege via historical SIDs, trust SID filtering",
        version="1.0",
        expert_count=3,
        mitre_techniques=["T1134.005", "T1482"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="privilege_escalation",
    ),
    "maq_rbcd": ValidationModuleDefinition(
        id="maq_rbcd",
        name="MAQ / RBCD / Computer Takeover",
        description="ms-DS-MachineAccountQuota abuse, RBCD via MAQ, CreateChild computer, full takeover chain",
        version="1.0",
        expert_count=4,
        mitre_techniques=["T1550.003"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="lateral_movement",
    ),
    "network_posture": ValidationModuleDefinition(
        id="network_posture",
        name="Network Posture & Exposure",
        description="SMB signing, LDAP signing/channel binding, IPv6 rogue RA, WPAD/mDNS poisoning, PrintSpooler, WebClient exposure",
        version="1.0",
        expert_count=4,
        mitre_techniques=["T1557.001", "T1557", "T1171"],
        severity_range=("MEDIUM", "CRITICAL"),
        risk_category="lateral_movement",
    ),
    "user_accounts": ValidationModuleDefinition(
        id="user_accounts",
        name="User Account Hygiene",
        description="Stale/dormant accounts, passwordNeverExpires, no-preauth users, admin account hygiene, spray candidates",
        version="1.0",
        expert_count=3,
        mitre_techniques=["T1078.002", "T1110.003", "T1558.004"],
        severity_range=("LOW", "HIGH"),
        risk_category="initial_access",
    ),
    "service_accounts": ValidationModuleDefinition(
        id="service_accounts",
        name="Service Account Hygiene",
        description="Kerberoastable SPNs, gMSA adoption gaps, service accounts with excessive privileges",
        version="1.0",
        expert_count=2,
        mitre_techniques=["T1558.003", "T1078.002"],
        severity_range=("MEDIUM", "HIGH"),
        risk_category="credential_access",
    ),
    "domain_config": ValidationModuleDefinition(
        id="domain_config",
        name="Domain Configuration",
        description="Domain functional level, krbtgt password age, MAQ policy, AdminSDHolder propagation gaps",
        version="1.0",
        expert_count=3,
        mitre_techniques=["T1558", "T1550.003"],
        severity_range=("LOW", "CRITICAL"),
        risk_category="configuration",
    ),
    "pre2k_exposure": ValidationModuleDefinition(
        id="pre2k_exposure",
        name="Pre-Windows 2000 Compatibility Exposure",
        description="Pre-2000 compatible access group membership, null-session exposure, legacy authentication risks",
        version="1.0",
        expert_count=1,
        mitre_techniques=["T1110", "T1078.002"],
        severity_range=("MEDIUM", "HIGH"),
        risk_category="initial_access",
    ),
    "recon_exposure": ValidationModuleDefinition(
        id="recon_exposure",
        name="Reconnaissance Exposure",
        description="Unauthenticated LDAP enumeration, null session exposure, excessive AD object visibility to low-priv users",
        version="1.0",
        expert_count=1,
        mitre_techniques=["T1087.002", "T1069.002"],
        severity_range=("LOW", "MEDIUM"),
        risk_category="discovery",
    ),
    "timeroast_exposure": ValidationModuleDefinition(
        id="timeroast_exposure",
        name="Timeroasting Exposure",
        description="Computer accounts with weak/predictable passwords exposed via NTP MD5 hash extraction",
        version="1.0",
        expert_count=1,
        mitre_techniques=["T1558"],
        severity_range=("MEDIUM", "HIGH"),
        risk_category="credential_access",
    ),
    "wsus_exposure": ValidationModuleDefinition(
        id="wsus_exposure",
        name="WSUS Attack Surface",
        description="HTTP WSUS delivery, WSUS server ACL weaknesses, update hijacking for lateral movement",
        version="1.0",
        expert_count=1,
        mitre_techniques=["T1072"],
        severity_range=("HIGH", "CRITICAL"),
        risk_category="lateral_movement",
    ),
}


def list_validation_modules() -> list[dict[str, str]]:
    try:
        import adbygod_api.core.validation.experts  # noqa: F401
        from adbygod_api.core.validation.registry import expert_count
    except Exception:
        expert_count = None

    modules = []
    for module in VALIDATION_MODULE_INDEX.values():
        payload = asdict(module)
        if expert_count is not None:
            payload["expert_count"] = expert_count(module.id)
        modules.append(payload)
    return modules
