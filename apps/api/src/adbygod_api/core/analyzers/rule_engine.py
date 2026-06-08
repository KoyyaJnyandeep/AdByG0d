from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
import logging

from adbygod_api.core.dcsync_principals import classify_dcsync_principal

log = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    finding_type: str
    module: str
    title: str
    description: str
    severity: str           # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: float       # 0-1
    affected_objects: List[Any]
    affected_count: int
    root_cause: str
    causal_chain: List[str]
    remediation: str
    remediation_steps: List[str]
    fix_complexity: str
    references: List[str]
    evidence_refs: List[str] = field(default_factory=list)
    technical_severity: float = 5.0
    reachability: float = 0.5
    on_crown_jewel_path: bool = False
    is_tier0_direct: bool = False
    mitre_attack_ids: List[str] = field(default_factory=list)


@dataclass
class Rule:
    id: str
    name: str
    module: str
    description: str
    evaluate: Callable


def _adcs_object(t: dict) -> dict:
    attrs = t.get("attributes", {}) or {}
    return {
        "template_name": t.get("name"),
        "template_dn": t.get("distinguished_name") or attrs.get("distinguishedName"),
        "ca_name": t.get("ca_name") or ", ".join(attrs.get("published_by", []) or []),
        "ekus": t.get("ekus", []),
        "enrollment_principals": t.get("enrollment_rights", []),
        "write_rights": t.get("write_rights", []),
        "published": bool(attrs.get("published_by") or t.get("ca_name")),
        "collection_method": attrs.get("collection_method", "ldap/adcs"),
    }


def _entity_name_map(entities: list) -> dict:
    """Map entity_id → display name (SAM account name with display_name fallback).

    ACL edges store entity IDs (SIDs or SAM names) in source_id/target_id.
    This map lets rules resolve those IDs to human-readable names for affected_objects.
    """
    return {
        e.get("id", ""): (
            e.get("sam_account_name") or e.get("display_name") or e.get("id") or ""
        )
        for e in entities
        if e.get("id")
    }


class RuleEngine:
    def __init__(self):
        self.rules: List[Rule] = []
        self._register_builtin_rules()

    def evaluate_all(self, data: Dict[str, Any]) -> List[RuleMatch]:
        results = []
        for rule in self.rules:
            try:
                matches = rule.evaluate(data)
                results.extend(matches)
            except Exception as e:
                log.warning(f"Rule {rule.id} failed: {e}")
        return results

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        return next((r for r in self.rules if r.id == rule_id), None)

    def _reg(self, rule: Rule):
        self.rules.append(rule)

    def _register_builtin_rules(self):

        def rule_no_lockout(data):
            policy = data.get("password_policy", {})
            if "lockout_threshold" not in policy:
                return []
            try:
                lockout_threshold = int(policy.get("lockout_threshold"))
            except (TypeError, ValueError):
                return []
            if lockout_threshold == 0:
                return [RuleMatch(
                    rule_id="PWD-001", rule_name="No Account Lockout Policy",
                    finding_type="NO_LOCKOUT_POLICY", module="Password Policy",
                    title="No account lockout policy configured",
                    description=(
                        "The domain has no account lockout threshold. Attackers can "
                        "perform unlimited password guessing (spray or brute force) "
                        "against any account without triggering a lockout."
                    ),
                    severity="CRITICAL", confidence=1.0,
                    affected_objects=["Default Domain Policy"], affected_count=1,
                    root_cause="lockoutThreshold = 0 on the domain object",
                    causal_chain=[
                        "Domain-level password policy has lockoutThreshold set to 0",
                        "This means Active Directory never locks out accounts",
                        "Any attacker with network access can try unlimited passwords",
                    ],
                    remediation="Set account lockout threshold to 5-10 attempts via Default Domain Policy",
                    remediation_steps=[
                        "Open Group Policy Management Console (gpmc.msc)",
                        "Edit Default Domain Policy",
                        "Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Account Lockout Policy",
                        "Set 'Account lockout threshold' to 5 or 10",
                        "Set 'Account lockout duration' to 30 minutes or more",
                        "Set 'Reset account lockout counter after' to 30 minutes",
                    ],
                    fix_complexity="trivial",
                    references=["https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"],
                    technical_severity=9.0, reachability=1.0,
                    mitre_attack_ids=["T1110.003"],
                )]
            return []

        self._reg(Rule("PWD-001", "No Account Lockout Policy", "Password Policy",
                       "Detects missing lockout threshold", rule_no_lockout))

        def rule_weak_min_length(data):
            policy = data.get("password_policy", {})
            if "min_password_length" not in policy:
                return []
            try:
                min_len = int(policy.get("min_password_length"))
            except (TypeError, ValueError):
                return []
            if min_len < 12:
                sev = "CRITICAL" if min_len < 8 else "HIGH"
                return [RuleMatch(
                    rule_id="PWD-002", rule_name="Weak Minimum Password Length",
                    finding_type="WEAK_PASSWORD_LENGTH", module="Password Policy",
                    title=f"Minimum password length is {min_len} characters (recommended: 14+)",
                    description=f"The domain minimum password length of {min_len} characters enables short passwords that can be cracked quickly with modern hardware.",
                    severity=sev, confidence=1.0,
                    affected_objects=["Default Domain Policy"], affected_count=1,
                    root_cause=f"minPwdLength = {min_len}",
                    causal_chain=[
                        f"Domain policy enforces minimum of only {min_len} characters",
                        "Short passwords dramatically reduce brute-force search space",
                        f"An 8-character password can be cracked in hours; {min_len} is even weaker",
                    ],
                    remediation=f"Increase minimum password length from {min_len} to at least 14 characters. Consider passphrases.",
                    remediation_steps=[
                        "Edit Default Domain Policy in GPMC",
                        "Navigate to Account Policies → Password Policy",
                        "Set 'Minimum password length' to 14 or higher",
                        "Consider implementing Microsoft's password guidance: no complexity + longer length",
                    ],
                    fix_complexity="low",
                    references=["https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length"],
                    technical_severity=7.5 if min_len < 8 else 6.0, reachability=0.8,
                )]
            return []

        self._reg(Rule("PWD-002", "Weak Password Length", "Password Policy",
                       "Minimum password length below 12", rule_weak_min_length))

        def rule_passwd_notreqd(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("entity_type") == "USER"
                    and e.get("attributes", {}).get("uac_passwd_notreqd")
                    and e.get("is_enabled")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="USR-001", rule_name="PASSWD_NOTREQD Flag Set",
                finding_type="PASSWD_NOTREQD", module="User Accounts",
                title=f"{len(vuln)} enabled accounts have PASSWD_NOTREQD flag set",
                description="The PASSWD_NOTREQD flag allows accounts to authenticate with an empty password, bypassing all password policy enforcement.",
                severity="CRITICAL", confidence=1.0,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="userAccountControl has PASSWD_NOTREQD (0x20) bit set",
                causal_chain=[
                    "PASSWD_NOTREQD (UAC bit 0x20) is set on user accounts",
                    "Windows will allow login with an empty password for these accounts",
                    "Attacker can authenticate with blank password if account is misconfigured",
                ],
                remediation="Clear PASSWD_NOTREQD flag from all affected accounts and set strong passwords",
                remediation_steps=[
                    "Identify all affected accounts via: Get-ADUser -Filter {PasswordNotRequired -eq $True}",
                    "For each account: Set-ADUser <account> -PasswordNotRequired $False",
                    "Force a password reset on all affected accounts",
                    "Audit how these flags were set (provisioning issue?)",
                ],
                fix_complexity="low",
                references=["https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol"],
                mitre_attack_ids=["T1078"],
            )]

        self._reg(Rule("USR-001", "PASSWD_NOTREQD", "User Accounts",
                       "Accounts with PASSWD_NOTREQD flag", rule_passwd_notreqd))

        def rule_asrep_roastable(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("entity_type") in ("USER", "SERVICE_ACCOUNT")
                    and e.get("attributes", {}).get("uac_dont_require_preauth")
                    and e.get("is_enabled")]
            if not vuln:
                return []
            has_admin = any(e.get("is_admin_count") for e in vuln)
            sev = "CRITICAL" if has_admin else "HIGH"
            return [RuleMatch(
                rule_id="KRB-001", rule_name="AS-REP Roastable Accounts",
                finding_type="ASREP_ROASTABLE", module="Kerberos",
                title=f"{len(vuln)} accounts vulnerable to AS-REP roasting",
                description="Accounts with Kerberos pre-authentication disabled return an AS-REP containing an encrypted blob crackable offline without network access.",
                severity=sev, confidence=1.0,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="DONT_REQUIRE_PREAUTH (UAC 0x400000) set — Kerberos pre-auth disabled",
                causal_chain=[
                    "Kerberos pre-authentication is disabled (DONT_REQUIRE_PREAUTH flag)",
                    "The KDC responds to AS-REQ without requiring proof of identity first",
                    "The AS-REP contains a session key encrypted with the account's password hash",
                    "This encrypted blob can be extracted and cracked offline with hashcat",
                ],
                remediation="Enable Kerberos pre-authentication on all affected accounts",
                remediation_steps=[
                    "For each affected account: Set-ADUser <account> -DoesNotRequirePreAuth $False",
                    "Or via ADUC: Account tab → uncheck 'Do not require Kerberos preauthentication'",
                    "If pre-auth must be disabled for a legacy service, isolate that service account",
                ],
                fix_complexity="low",
                references=[
                    "https://attack.mitre.org/techniques/T1558/004/",
                    "https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/",
                ],
                technical_severity=8.0, reachability=0.7,
                is_tier0_direct=has_admin,
                mitre_attack_ids=["T1558.004"],
            )]

        self._reg(Rule("KRB-001", "AS-REP Roastable", "Kerberos",
                       "Accounts with pre-auth disabled", rule_asrep_roastable))

        def rule_kerberoastable_admins(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("entity_type") in ("USER", "SERVICE_ACCOUNT")
                    and e.get("attributes", {}).get("has_spn")
                    and e.get("is_admin_count")
                    and e.get("is_enabled")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="KRB-002", rule_name="Kerberoastable AdminCount Accounts",
                finding_type="KERBEROASTABLE_ADMIN", module="Kerberos",
                title=f"{len(vuln)} admin-level accounts are Kerberoastable",
                description="High-privilege accounts (adminCount=1) with SPNs can be Kerberoasted, providing crackable TGS tickets for domain admin or equivalent accounts.",
                severity="CRITICAL", confidence=1.0,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="Admin accounts have SPNs set, making them Kerberoastable with existing credentials",
                causal_chain=[
                    "Account has adminCount=1 (protected by AdminSDHolder)",
                    "Account also has a servicePrincipalName registered",
                    "Any authenticated user can request a TGS for this SPN",
                    "The TGS is encrypted with the service account's NTLM hash",
                    "This hash can be cracked offline to recover the plaintext password",
                    "Password = Domain Admin or equivalent access",
                ],
                remediation="Remove SPNs from admin accounts and use dedicated service accounts for services",
                remediation_steps=[
                    "Identify SPNs: Get-ADUser <account> -Properties ServicePrincipalName",
                    "Remove SPN: Set-ADUser <account> -ServicePrincipalNames @{Remove='SPN/value'}",
                    "Create a dedicated non-admin service account for the service if SPN is needed",
                    "Migrate to gMSA for automatic password management",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1558/003/"],
                technical_severity=9.5, reachability=0.9,
                is_tier0_direct=True,
                mitre_attack_ids=["T1558.003"],
            )]

        self._reg(Rule("KRB-002", "Kerberoastable Admins", "Kerberos",
                       "Admin accounts with SPNs", rule_kerberoastable_admins))

        def rule_unconstrained_delegation(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("entity_type") == "COMPUTER"
                    and e.get("attributes", {}).get("uac_trusted_for_delegation")
                    and not e.get("attributes", {}).get("uac_is_dc")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="DEL-001", rule_name="Unconstrained Delegation",
                finding_type="UNCONSTRAINED_DELEGATION", module="Kerberos",
                title=f"{len(vuln)} non-DC computers configured with unconstrained delegation",
                description="Computers with unconstrained delegation cache TGTs of any user who authenticates to them, including Domain Admins. Combined with coercion, this enables full domain compromise.",
                severity="CRITICAL", confidence=1.0,
                affected_objects=[e.get("sam_account_name") or e.get("dns_hostname") for e in vuln],
                affected_count=len(vuln),
                root_cause="TRUSTED_FOR_DELEGATION (UAC 0x80000) set on computer accounts",
                causal_chain=[
                    "Computer has TRUSTED_FOR_DELEGATION flag set",
                    "Any user who authenticates to this computer has their full TGT forwarded",
                    "The computer can use that TGT to impersonate the user to any service",
                    "Combined with coercion (PetitPotam, PrinterBug), attacker can coerce DC authentication",
                    "DC's TGT is cached → attacker extracts it → DCSync → Domain Admin",
                ],
                remediation="Replace unconstrained delegation with constrained delegation or RBCD",
                remediation_steps=[
                    "Identify which services require delegation",
                    "Replace with constrained delegation (KCD): Set-ADComputer <computer> -TrustedForDelegation $False",
                    "Configure specific service delegation instead",
                    "Or implement RBCD if constrained delegation is not feasible",
                    "Enable Protected Users group for all privileged accounts (blocks TGT forwarding)",
                ],
                fix_complexity="medium",
                references=[
                    "https://attack.mitre.org/techniques/T1558/",
                    "https://blog.harmj0y.net/activedirectory/s4u2pwnage/",
                ],
                technical_severity=9.0, reachability=0.8,
                is_tier0_direct=True,
                mitre_attack_ids=["T1558"],
            )]

        self._reg(Rule("DEL-001", "Unconstrained Delegation", "Kerberos",
                       "Non-DC with unconstrained delegation", rule_unconstrained_delegation))

        def rule_no_laps(data):
            domain_info = data.get("domain_info", {})
            if "laps_deployed" not in domain_info or "total_computers" not in domain_info:
                return []
            try:
                total = int(domain_info.get("total_computers") or 0)
            except (TypeError, ValueError):
                return []
            if total <= 0:
                return []
            if not bool(domain_info.get("laps_deployed")):
                return [RuleMatch(
                    rule_id="LAPS-001", rule_name="LAPS Not Deployed",
                    finding_type="NO_LAPS", module="Local Admin",
                    title="LAPS not deployed — local admin passwords likely reused across domain",
                    description="Without LAPS, the built-in local Administrator password is likely identical across all workstations, enabling lateral movement after a single endpoint compromise.",
                    severity="HIGH", confidence=1.0,
                    affected_objects=[f"{total} computers at risk"], affected_count=total,
                    root_cause="ms-Mcs-AdmPwdExpirationTime schema attribute not present",
                    causal_chain=[
                        "LAPS schema attributes are not present in the directory",
                        "Local admin passwords are set manually and rarely rotated",
                        "A single compromised machine exposes all machines sharing the same password",
                        "Pass-the-hash with the local admin hash enables unrestricted lateral movement",
                    ],
                    remediation="Deploy Microsoft LAPS or Windows LAPS to manage local admin passwords",
                    remediation_steps=[
                        "For Windows LAPS (built-in): Enable via GPMC (available since April 2023 update)",
                        "Or deploy legacy LAPS: https://www.microsoft.com/en-us/download/details.aspx?id=46899",
                        "Extend the schema: Update-LapsADSchema (legacy) or via GPMC (Windows LAPS)",
                        "Create GPO to configure LAPS for all OUs",
                        "Set retrieval permissions to Tier 1 admins only",
                    ],
                    fix_complexity="medium",
                    references=["https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"],
                    technical_severity=8.0, reachability=0.7,
                    mitre_attack_ids=["T1021.001"],
                )]
            return []

        self._reg(Rule("LAPS-001", "LAPS Not Deployed", "Local Admin",
                       "LAPS deployment check", rule_no_laps))

        def rule_maq(data):
            domain_info = data.get("domain_info", {})
            if "machine_account_quota" not in domain_info:
                return []
            try:
                maq = int(domain_info.get("machine_account_quota"))
            except (TypeError, ValueError):
                return []
            if maq > 0:
                return [RuleMatch(
                    rule_id="MAQ-001", rule_name="Non-Zero MachineAccountQuota",
                    finding_type="MACHINE_ACCOUNT_QUOTA", module="Domain Config",
                    title=f"MachineAccountQuota is {maq} — any user can create computer accounts",
                    description=f"Any authenticated user can create up to {maq} machine accounts, enabling RBCD-based privilege escalation attacks.",
                    severity="MEDIUM", confidence=1.0,
                    affected_objects=["Domain object"], affected_count=1,
                    root_cause=f"ms-DS-MachineAccountQuota = {maq}",
                    causal_chain=[
                        f"ms-DS-MachineAccountQuota is set to {maq}",
                        "Any domain user can create machine accounts without admin rights",
                        "Attacker creates a machine account they control",
                        "Modifies msDS-AllowedToActOnBehalfOfOtherIdentity on target computer",
                        "Uses S4U2self + S4U2proxy to impersonate any user to target",
                    ],
                    remediation="Set ms-DS-MachineAccountQuota to 0 and use delegated join accounts",
                    remediation_steps=[
                        "Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0}",
                        "Create dedicated computer join accounts with scoped OU permissions",
                        "Audit existing machine accounts created by non-admins",
                    ],
                    fix_complexity="low",
                    references=["https://www.netspi.com/blog/technical/network-penetration-testing/machineaccountquota-is-useful-sometimes/"],
                    technical_severity=6.5, reachability=0.6,
                    mitre_attack_ids=["T1098"],
                )]
            return []

        self._reg(Rule("MAQ-001", "MachineAccountQuota", "Domain Config",
                       "Non-zero MAQ enables RBCD abuse", rule_maq))

        def rule_trust_no_sid_filtering(data):
            trusts = data.get("trusts", [])
            vuln = [t for t in trusts if t.get("sid_filtering_enabled") is False]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="TRUST-001", rule_name="Trust Without SID Filtering",
                finding_type="TRUST_NO_SID_FILTERING", module="Trusts",
                title=f"{len(vuln)} domain trust(s) have SID filtering disabled",
                description="Trusts without SID filtering allow SID History injection. An attacker who compromises a trusted domain can forge SIDs to gain elevated access in this domain.",
                severity="HIGH", confidence=1.0,
                affected_objects=[t.get("partner") or t.get("name") for t in vuln],
                affected_count=len(vuln),
                root_cause="TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x4) not set on trustAttributes",
                causal_chain=[
                    "Trust telemetry explicitly reports SID filtering disabled",
                    "Accounts in the trusted domain can have SID History attributes",
                    "SID History allows an account to act as if it has additional SIDs",
                    "Attacker adds high-privilege SIDs (e.g., Domain Admins) to SID History",
                    "Authentication to this domain honors those SIDs — cross-domain escalation",
                ],
                remediation="Enable SID filtering (quarantine) on all external/forest trusts",
                remediation_steps=[
                    "netdom trust <this-domain> /domain:<trusted-domain> /quarantine:yes",
                    "Verify: (Get-ADTrust -Filter *).TrustAttributes",
                    "Test applications rely on cross-domain group membership before enforcing",
                ],
                fix_complexity="medium",
                references=["https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321(v=ws.10)"],
                technical_severity=8.5, reachability=0.6,
                mitre_attack_ids=["T1484.002"],
            )]

        self._reg(Rule("TRUST-001", "Trust SID Filtering", "Trusts",
                       "Trusts without SID filtering", rule_trust_no_sid_filtering))

        def rule_esc1(data):
            templates = data.get("cert_templates", [])
            vuln = [t for t in templates if t.get("esc1_vulnerable")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="ADCS-001", rule_name="ESC1 — Subject Alternative Name Misconfig",
                finding_type="ESC1", module="AD CS",
                title=f"{len(vuln)} certificate template(s) vulnerable to ESC1",
                description="These templates allow the enrollee to supply a Subject Alternative Name (SAN) and have Client Authentication EKU, enabling impersonation of any user including Domain Admins.",
                severity="CRITICAL", confidence=1.0,
                affected_objects=[_adcs_object(t) for t in vuln],
                affected_count=len(vuln),
                root_cause="CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + Client Auth EKU + low enrollment ACL",
                causal_chain=[
                    "Template has CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set (enrollee controls SAN)",
                    "Template has Client Authentication EKU (or equivalents)",
                    "Low-privileged users have Enroll or AutoEnroll rights",
                    "Attacker requests certificate specifying Domain Admin as the SAN",
                    "Uses that certificate for PKINIT Kerberos authentication as Domain Admin",
                ],
                remediation="Disable enrollee-supplied SAN or restrict enrollment to privileged users",
                remediation_steps=[
                    "Open Certificate Templates console (certtmpl.msc)",
                    "For each vulnerable template: Properties → Subject Name tab",
                    "Uncheck 'Supply in the request'",
                    "Or restrict enrollment rights to only authorized service accounts",
                    "Review and tighten the template ACL",
                ],
                fix_complexity="low",
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                technical_severity=10.0, reachability=0.9,
                is_tier0_direct=True,
                mitre_attack_ids=["T1649"],
            )]

        self._reg(Rule("ADCS-001", "ESC1", "AD CS",
                       "ESC1 certificate template misconfig", rule_esc1))

        def rule_esc4(data):
            templates = data.get("cert_templates", [])
            vuln = [t for t in templates if t.get("esc4_vulnerable")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="ADCS-004", rule_name="ESC4 — Template ACL Write Rights",
                finding_type="ESC4", module="AD CS",
                title=f"{len(vuln)} certificate template(s) have dangerous write ACLs",
                description="Low-privileged users have write rights over these templates, allowing them to modify template configuration to introduce ESC1 or other vulnerabilities.",
                severity="HIGH", confidence=0.9,
                affected_objects=[_adcs_object(t) for t in vuln],
                affected_count=len(vuln),
                root_cause="WriteDacl, WriteOwner, or GenericAll on certificate template object",
                causal_chain=[
                    "Low-privileged principal has write rights over the template AD object",
                    "Attacker modifies template to add CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT",
                    "Template now becomes vulnerable to ESC1",
                    "Attacker requests a Domain Admin certificate",
                ],
                remediation="Remove write rights from non-privileged accounts on all certificate templates",
                remediation_steps=[
                    "Review template ACLs: Get-ADObject -LDAPFilter '(objectClass=pKICertificateTemplate)'",
                    "Remove WriteDacl/WriteOwner/GenericAll from non-CA-admins",
                    "Only CA Admins and Enterprise Admins should have write rights to templates",
                ],
                fix_complexity="medium",
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                technical_severity=8.5, reachability=0.7,
                mitre_attack_ids=["T1649"],
            )]

        self._reg(Rule("ADCS-004", "ESC4", "AD CS",
                       "Template with dangerous write ACLs", rule_esc4))

        def rule_esc2(data):
            templates = data.get("cert_templates", [])
            vuln = [t for t in templates if t.get("esc2_vulnerable")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="ADCS-002", rule_name="ESC2 — Any Purpose EKU",
                finding_type="ESC2", module="AD CS",
                title=f"{len(vuln)} certificate template(s) vulnerable to ESC2",
                description="Templates with the Any Purpose EKU or no EKU restrictions can be used for client authentication, enabling Kerberos login as any user.",
                severity="HIGH", confidence=0.9,
                affected_objects=[_adcs_object(t) for t in vuln],
                affected_count=len(vuln),
                root_cause="Any Purpose EKU (2.5.29.37.0) or SubCA EKU set on template",
                causal_chain=[
                    "Template has Any Purpose EKU or no EKU constraints",
                    "Low-privileged users have enrollment rights",
                    "Certificate can be used for client authentication via PKINIT",
                    "Attacker authenticates as any principal in the domain",
                ],
                remediation="Replace Any Purpose EKU with specific EKUs and restrict enrollment",
                remediation_steps=[
                    "In certtmpl.msc, edit the vulnerable template",
                    "Remove 'Any Purpose' from Application Policies",
                    "Add only the required specific EKU (e.g. Server Authentication)",
                    "Restrict enrollment rights to the minimum required principals",
                ],
                fix_complexity="low",
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                technical_severity=8.0, reachability=0.8,
                mitre_attack_ids=["T1649"],
            )]

        self._reg(Rule("ADCS-002", "ESC2", "AD CS", "Any Purpose EKU template", rule_esc2))

        def rule_esc3(data):
            templates = data.get("cert_templates", [])
            vuln = [t for t in templates if t.get("esc3_vulnerable")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="ADCS-003", rule_name="ESC3 — Certificate Request Agent",
                finding_type="ESC3", module="AD CS",
                title=f"{len(vuln)} certificate template(s) vulnerable to ESC3",
                description="Templates with the Certificate Request Agent EKU let enrollees request certificates on behalf of other users, enabling impersonation of any domain principal.",
                severity="HIGH", confidence=0.9,
                affected_objects=[_adcs_object(t) for t in vuln],
                affected_count=len(vuln),
                root_cause="Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1) set with low-priv enrollment",
                causal_chain=[
                    "Template grants Certificate Request Agent capability",
                    "Low-privileged user requests agent certificate",
                    "Agent certificate used to enroll on behalf of a Domain Admin",
                    "New certificate used for PKINIT as Domain Admin",
                ],
                remediation="Restrict Certificate Request Agent templates to PKI admins only",
                remediation_steps=[
                    "Remove enrollment rights from standard users on agent-capable templates",
                    "If enrollment agents are required, use dedicated privileged accounts",
                    "Enable CA manager approval on agent certificate issuance",
                ],
                fix_complexity="medium",
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                technical_severity=8.5, reachability=0.7,
                mitre_attack_ids=["T1649"],
            )]

        self._reg(Rule("ADCS-003", "ESC3", "AD CS", "Certificate Request Agent template", rule_esc3))

        def rule_constrained_delegation_any_protocol(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            delegate_sources = {
                edge.get("source_id")
                for edge in edges
                if edge.get("edge_type") == "ALLOWED_TO_DELEGATE"
            }
            vuln = []
            for entity in entities:
                if not entity.get("is_enabled"):
                    continue
                attrs = entity.get("attributes", {}) or {}
                has_targets = bool(attrs.get("allowed_to_delegate_to")) or entity.get("id") in delegate_sources
                any_protocol = bool(
                    attrs.get("constrained_delegation_any_protocol")
                    or attrs.get("uac_trusted_to_auth_for_delegation")
                )
                if has_targets and any_protocol:
                    vuln.append(entity)
            if not vuln:
                return []
            has_admin = any(e.get("is_admin_count") for e in vuln)
            sev = "CRITICAL" if has_admin else "HIGH"
            return [RuleMatch(
                rule_id="DEL-002", rule_name="Protocol Transition Constrained Delegation",
                finding_type="CONSTRAINED_DELEGATION_ANY_PROTOCOL", module="Kerberos",
                title=f"{len(vuln)} account(s) with constrained delegation + protocol transition",
                description="Accounts with 'Use any authentication protocol' constrained delegation can impersonate any user (including Domain Admins) to specific services without requiring a Kerberos TGT from the target.",
                severity=sev, confidence=1.0,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="msDS-AllowedToDelegateTo set with TrustedToAuthForDelegation (S4U2Self enabled)",
                causal_chain=[
                    "Account has TrustedToAuthForDelegation flag (protocol transition)",
                    "Account also has AllowedToDelegateTo configured for specific SPNs",
                    "Attacker can use S4U2Self to obtain a TGS for any user to itself",
                    "Then use S4U2Proxy to forward that ticket to the target SPN",
                    "Effective impersonation of any user without their credentials",
                ],
                remediation="Replace protocol-transition delegation with standard KCD; use RBCD where possible",
                remediation_steps=[
                    "Identify constrained delegation targets: Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'}",
                    "Remove TrustedToAuthForDelegation where protocol transition is not strictly needed",
                    "Consider migrating to Resource-Based Constrained Delegation (RBCD)",
                    "Add constrained delegation targets to Protected Users if impersonation is required",
                ],
                fix_complexity="high",
                references=["https://attack.mitre.org/techniques/T1134/001/"],
                technical_severity=9.0, reachability=0.75,
                is_tier0_direct=has_admin,
                mitre_attack_ids=["T1134.001"],
            )]

        self._reg(Rule("DEL-002", "Protocol Transition Delegation", "Kerberos",
                       "Constrained delegation with protocol transition", rule_constrained_delegation_any_protocol))

        def rule_pwd_never_expires_admin(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("is_admin_count")
                    and e.get("is_enabled")
                    and e.get("attributes", {}).get("pwd_never_expires")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="USR-002", rule_name="Admin Account — Password Never Expires",
                finding_type="ADMIN_PWD_NEVER_EXPIRES", module="User Accounts",
                title=f"{len(vuln)} admin account(s) have passwords that never expire",
                description="AdminCount accounts with passwords that never expire dramatically increase the window for credential compromise and reuse after a breach.",
                severity="HIGH", confidence=1.0,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="DONT_EXPIRE_PASSWORD (UAC 0x10000) on adminCount accounts",
                causal_chain=[
                    "Password never expires means credentials can be valid indefinitely",
                    "Admin account with an old, compromised, or weak password is never forced to rotate",
                    "If password is breached (spray, phish, crack), it remains valid forever",
                ],
                remediation="Enable password expiration for all admin accounts and enforce regular rotation",
                remediation_steps=[
                    "Get-ADUser -Filter {AdminCount -eq 1 -and PasswordNeverExpires -eq $True}",
                    "For each: Set-ADUser <account> -PasswordNeverExpires $False",
                    "Configure a Fine-Grained Password Policy (PSO) for admin accounts with 90-day max age",
                    "Consider PAM solutions for just-in-time privileged access",
                ],
                fix_complexity="low",
                references=["https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"],
                technical_severity=7.0, reachability=0.6,
                mitre_attack_ids=["T1078.002"],
            )]

        self._reg(Rule("USR-002", "Admin PWD Never Expires", "User Accounts",
                       "Admin accounts with non-expiring passwords", rule_pwd_never_expires_admin))

        def rule_stale_admin_accounts(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("is_admin_count")
                    and e.get("is_enabled")
                    and e.get("attributes", {}).get("days_since_last_logon", 0) > 90]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="USR-003", rule_name="Stale Admin Accounts",
                finding_type="STALE_ADMIN_ACCOUNT", module="User Accounts",
                title=f"{len(vuln)} enabled admin account(s) unused for 90+ days",
                description="Enabled admin accounts that haven't logged in for 90+ days are likely orphaned service/contractor accounts with persistent privileged access that won't be detected if compromised.",
                severity="HIGH", confidence=0.85,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="adminCount=1 accounts with lastLogonTimestamp > 90 days",
                causal_chain=[
                    "Account was privileged but is no longer actively used",
                    "Disabling/deleting was skipped during offboarding or role change",
                    "Attacker can compromise via credential spraying or phishing without detection",
                    "No login baseline means anomalous logon won't trigger alerts",
                ],
                remediation="Disable or delete stale admin accounts; implement regular access reviews",
                remediation_steps=[
                    "Disable accounts: Disable-ADAccount -Identity <account>",
                    "Move to a 'Quarantine' OU and monitor for 30 days before deletion",
                    "Implement automated stale account reports using Search-ADAccount",
                    "Establish quarterly access reviews for all privileged accounts",
                ],
                fix_complexity="low",
                references=["https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts"],
                technical_severity=7.5, reachability=0.5,
                mitre_attack_ids=["T1078.002"],
            )]

        self._reg(Rule("USR-003", "Stale Admin Accounts", "User Accounts",
                       "Enabled admin accounts inactive for 90+ days", rule_stale_admin_accounts))

        def rule_default_admin_enabled(data):
            entities = data.get("entities", [])
            admin_accounts = [e for e in entities
                              if e.get("entity_type") == "USER"
                              and e.get("sam_account_name", "").lower() in ("administrator", "admin")
                              and e.get("is_enabled")]
            if not admin_accounts:
                return []
            return [RuleMatch(
                rule_id="USR-004", rule_name="Default Administrator Account Enabled",
                finding_type="DEFAULT_ADMIN_ENABLED", module="User Accounts",
                title="Default 'Administrator' account is enabled and active",
                description="The built-in Administrator account (RID 500) is enabled. This account cannot be locked out and is a prime target for brute force and credential reuse attacks.",
                severity="MEDIUM", confidence=0.9,
                affected_objects=[e.get("sam_account_name") for e in admin_accounts],
                affected_count=len(admin_accounts),
                root_cause="Built-in RID-500 Administrator account not disabled or renamed",
                causal_chain=[
                    "Built-in Administrator account is enabled",
                    "This account is immune to account lockout by design",
                    "Attackers specifically target this account with credential stuffing and spray",
                    "Account name 'Administrator' is predictable — no guessing needed",
                ],
                remediation="Disable the built-in Administrator account and create a named admin account",
                remediation_steps=[
                    "Create a new privileged account with a non-obvious name",
                    "Migrate any services using Administrator to a dedicated service account",
                    "Disable the built-in account: Disable-ADAccount -Identity Administrator",
                    "Optionally rename it first as an additional deterrent",
                ],
                fix_complexity="medium",
                references=["https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts"],
                technical_severity=6.0, reachability=0.7,
                mitre_attack_ids=["T1078.002"],
            )]

        self._reg(Rule("USR-004", "Default Admin Enabled", "User Accounts",
                       "Built-in Administrator account is active", rule_default_admin_enabled))

        def rule_kerberoastable_all_users(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("entity_type") in ("USER", "SERVICE_ACCOUNT")
                    and e.get("attributes", {}).get("has_spn")
                    and not e.get("is_admin_count")
                    and e.get("is_enabled")]
            if len(vuln) < 3:
                return []
            return [RuleMatch(
                rule_id="KRB-003", rule_name="Kerberoastable Service Accounts",
                finding_type="KERBEROASTABLE_SERVICES", module="Kerberos",
                title=f"{len(vuln)} service account(s) are Kerberoastable",
                description="Standard user accounts with SPNs allow any authenticated user to request TGS tickets, which can be cracked offline. Even non-admin service accounts often have broad access.",
                severity="MEDIUM", confidence=1.0,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="servicePrincipalName set on user accounts",
                causal_chain=[
                    "Accounts have SPNs making them Kerberoastable",
                    "Any authenticated domain user can request TGS tickets for these SPNs",
                    "Tickets encrypted with account NTLM hash can be cracked offline",
                    "Compromised service account may allow lateral movement or data access",
                ],
                remediation="Migrate service accounts to gMSA; enforce strong passwords; audit SPN assignments",
                remediation_steps=[
                    "Migrate to Group Managed Service Accounts (gMSA): New-ADServiceAccount",
                    "For accounts that cannot migrate: enforce 25+ character random passwords",
                    "Audit why each SPN exists; remove unused SPNs",
                    "Enable AES-only Kerberos encryption for service accounts",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1558/003/"],
                technical_severity=6.5, reachability=0.65,
                mitre_attack_ids=["T1558.003"],
            )]

        self._reg(Rule("KRB-003", "Kerberoastable Service Accounts", "Kerberos",
                       "Non-admin accounts with SPNs", rule_kerberoastable_all_users))

        def rule_domain_functional_level(data):
            domain_info = data.get("domain_info", {})
            level = domain_info.get("domain_functional_level", 7)
            try:
                level = int(level)
            except (TypeError, ValueError):
                return []
            if level < 6:  # Below 2012 R2
                level_map = {0: "2000", 1: "2003 Interim", 2: "2003", 3: "2008", 4: "2008 R2", 5: "2012", 6: "2012 R2", 7: "2016"}
                level_name = level_map.get(level, str(level))
                return [RuleMatch(
                    rule_id="DOM-001", rule_name="Low Domain Functional Level",
                    finding_type="LOW_DOMAIN_FUNCTIONAL_LEVEL", module="Domain Config",
                    title=f"Domain functional level is Windows Server {level_name}",
                    description=f"Domain functional level {level_name} lacks modern security features including Protected Users group support, Kerberos armoring, and compound authentication.",
                    severity="MEDIUM", confidence=0.9,
                    affected_objects=["Domain"], affected_count=1,
                    root_cause=f"domainFunctionality = {level}",
                    causal_chain=[
                        f"Domain functional level is {level_name}",
                        "Protected Users security group is not enforced (requires 2012 R2+)",
                        "Kerberos armoring (FAST) not available",
                        "Compound authentication not available",
                    ],
                    remediation="Raise domain functional level to Windows Server 2016 (level 7)",
                    remediation_steps=[
                        "Verify all DCs are running Windows Server 2016 or later",
                        "Set-ADDomainMode -Identity <domain> -DomainMode Windows2016Domain",
                        "Test application compatibility before raising level",
                    ],
                    fix_complexity="high",
                    references=["https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"],
                    technical_severity=5.5, reachability=0.4,
                    mitre_attack_ids=["T1558"],
                )]
            return []

        self._reg(Rule("DOM-001", "Domain Functional Level", "Domain Config",
                       "Domain functional level below 2012 R2", rule_domain_functional_level))

        def rule_krbtgt_not_rotated(data):
            domain_info = data.get("domain_info", {})
            krbtgt_age = domain_info.get("krbtgt_password_age_days", 0)
            if krbtgt_age and krbtgt_age > 180:
                sev = "CRITICAL" if krbtgt_age > 365 else "HIGH"
                return [RuleMatch(
                    rule_id="DOM-002", rule_name="KRBTGT Password Not Rotated",
                    finding_type="KRBTGT_STALE", module="Domain Config",
                    title=f"KRBTGT password not rotated in {krbtgt_age} days",
                    description=f"The KRBTGT account password is {krbtgt_age} days old. A previously compromised KRBTGT allows forging Golden Tickets that persist indefinitely and bypass all normal authentication controls.",
                    severity=sev, confidence=1.0,
                    affected_objects=["krbtgt"], affected_count=1,
                    root_cause=f"krbtgt pwdLastSet = {krbtgt_age} days ago",
                    causal_chain=[
                        "The KRBTGT key is the secret used to sign all Kerberos tickets",
                        f"It has not been rotated in {krbtgt_age} days",
                        "If KRBTGT was previously compromised (e.g., DCSync), attacker still has a valid key",
                        "Attacker can forge Golden Tickets that bypass all authentication",
                        "These tickets remain valid until KRBTGT is rotated TWICE",
                    ],
                    remediation="Rotate the KRBTGT password twice (24h apart) using Microsoft's KRBTGT reset script",
                    remediation_steps=[
                        "Download: New-KrbtgtKeys.ps1 from Microsoft GitHub",
                        "Run in 'Mode 1' (simulation) first to verify impact",
                        "Execute Mode 2 first rotation — wait minimum 10 hours (max ticket lifetime)",
                        "Execute Mode 2 second rotation to invalidate all previously-forged tickets",
                        "Schedule quarterly rotation via automation",
                    ],
                    fix_complexity="medium",
                    references=[
                        "https://github.com/microsoft/New-KrbtgtKeys.ps1",
                        "https://attack.mitre.org/techniques/T1558/001/",
                    ],
                    technical_severity=10.0 if krbtgt_age > 365 else 8.5, reachability=0.3,
                    is_tier0_direct=True,
                    mitre_attack_ids=["T1558.001"],
                )]
            return []

        self._reg(Rule("DOM-002", "KRBTGT Stale", "Domain Config",
                       "KRBTGT password not rotated in 180+ days", rule_krbtgt_not_rotated))

        def rule_dcsync_non_dcs(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            entity_by_id = {
                str(entity.get("id")): entity
                for entity in entities
                if entity.get("id")
            }

            # Only unexpected principals should produce the critical DCSync finding.
            # Built-in replication trustees and sync-like service accounts are
            # handled separately by the validation expert, where they can be
            # downgraded to operational context or review-required telemetry.
            dcsync_edges = []
            for edge in edges:
                if edge.get("edge_type") != "DCSYNC":
                    continue
                source_id = str(edge.get("source_id") or "")
                classification = classify_dcsync_principal(entity_by_id.get(source_id, {}))
                if classification == "suspicious":
                    dcsync_edges.append(edge)

            if not dcsync_edges:
                return []

            name_map = _entity_name_map(entities)
            affected = list({
                name_map.get(e.get("source_id"), e.get("source_id"))
                for e in dcsync_edges
            })
            return [RuleMatch(
                rule_id="ACL-001", rule_name="Unexpected Principals Have DCSync Rights",
                finding_type="DCSYNC_RIGHTS", module="ACL Abuse",
                title=f"{len(affected)} unexpected principal(s) have DCSync replication rights",
                description="Unexpected principals with DS-Replication-Get-Changes-All permission can replicate all AD secrets (hashes, Kerberos keys) just like a Domain Controller — effectively a DCSync backdoor.",
                severity="CRITICAL", confidence=1.0,
                affected_objects=affected[:20], affected_count=len(affected),
                root_cause="DS-Replication-Get-Changes-All ACE granted to a non-default principal",
                causal_chain=[
                    "Principal has DS-Replication-Get-Changes and DS-Replication-Get-Changes-All",
                    "These are the exact permissions used by domain controllers to replicate",
                    "Attacker uses Mimikatz/Impacket secretsdump to pull all NTLM hashes",
                    "Including krbtgt — enabling Golden Ticket attacks",
                ],
                remediation="Remove replication rights from all non-default principals immediately",
                remediation_steps=[
                    "(Get-Acl 'AD:\\DC=<domain>').Access | Where-Object {$_.ActiveDirectoryRights -like '*Replication*'}",
                    "Remove the ACEs: dsacls '<domain DN>' /R <account>",
                    "Verify only Domain Controllers and explicitly approved sync accounts have replication rights",
                    "If Azure AD Connect is used, verify its account permissions are minimal",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1003.006/"],
                technical_severity=10.0, reachability=0.9,
                is_tier0_direct=True, on_crown_jewel_path=True,
                mitre_attack_ids=["T1003.006"],
            )]

        self._reg(Rule("ACL-001", "DCSync Rights", "ACL Abuse",
                       "Non-DC accounts with DCSync replication rights", rule_dcsync_non_dcs))

        def rule_genericall_on_tier0(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            tier0_ids = {e.get("id") for e in entities
                         if e.get("tier") == 0 or e.get("is_crown_jewel")}
            if not tier0_ids:
                return []
            non_admin_ids = {e.get("id") for e in entities
                             if not e.get("is_admin_count")
                             and not e.get("attributes", {}).get("uac_is_dc")}
            abuse_edges = [
                edge for edge in edges
                if edge.get("edge_type") in ("GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS")
                and edge.get("target_id") in tier0_ids
                and edge.get("source_id") in non_admin_ids
            ]
            if not abuse_edges:
                return []
            name_map = _entity_name_map(entities)
            affected = list({name_map.get(e.get("source_id"), e.get("source_id")) for e in abuse_edges})
            return [RuleMatch(
                rule_id="ACL-002", rule_name="GenericAll/WriteDACL on Tier-0 Objects",
                finding_type="GENERIC_ALL_TIER0", module="ACL Abuse",
                title=f"{len(affected)} non-admin account(s) have GenericAll/WriteDACL over Tier-0 objects",
                description="Non-privileged accounts with GenericAll or WriteDACL over Tier-0 objects (Domain Admins, Domain, DC) can escalate to full domain compromise without any additional exploits.",
                severity="CRITICAL", confidence=0.95,
                affected_objects=affected[:20], affected_count=len(affected),
                root_cause="GenericAll or WriteDACL ACE on critical AD objects for non-admin principals",
                causal_chain=[
                    "Non-admin has GenericAll or WriteDACL over a Tier-0 group/object",
                    "GenericAll: can modify membership, reset passwords, configure delegation",
                    "WriteDACL: can grant themselves any additional rights on the object",
                    "Direct path to Domain Admin without privilege escalation",
                ],
                remediation="Remove dangerous ACEs from Tier-0 objects and audit the ACL creation",
                remediation_steps=[
                    "For each Tier-0 object, run: (Get-Acl 'AD:\\<object DN>').Access",
                    "Remove GenericAll / WriteDACL ACEs for non-admin principals",
                    "Enable AdminSDHolder replication for Group Policy protection",
                    "Set up continuous ACL auditing with event ID 5136",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1484/"],
                technical_severity=10.0, reachability=0.85,
                is_tier0_direct=True, on_crown_jewel_path=True,
                mitre_attack_ids=["T1484"],
            )]

        self._reg(Rule("ACL-002", "GenericAll on Tier-0", "ACL Abuse",
                       "Non-admin accounts with full control over Tier-0 objects", rule_genericall_on_tier0))

        def rule_admins_not_in_protected_users(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("is_admin_count")
                    and e.get("is_enabled")
                    and e.get("entity_type") == "USER"
                    and not e.get("is_protected_user")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="KRB-004", rule_name="Admin Accounts Not in Protected Users",
                finding_type="ADMIN_NOT_PROTECTED_USERS", module="Kerberos",
                title=f"{len(vuln)} admin accounts not in the Protected Users group",
                description="Admin accounts outside Protected Users can have their TGTs delegated, use NTLM authentication, and use RC4/DES encryption — all blocked by Protected Users membership.",
                severity="HIGH", confidence=0.9,
                affected_objects=[e.get("sam_account_name") for e in vuln[:20]],
                affected_count=len(vuln),
                root_cause="adminCount=1 accounts not members of Protected Users (S-1-5-21-*-525)",
                causal_chain=[
                    "Admin accounts outside Protected Users can use NTLM",
                    "NTLM credentials can be relayed (NTLM relay attacks)",
                    "TGTs can be delegated to unconstrained/constrained delegation targets",
                    "Protected Users forces Kerberos-only + AES + no delegation",
                ],
                remediation="Add all admin accounts to the Protected Users security group",
                remediation_steps=[
                    "Test impact first — Protected Users blocks NTLM, so ensure services don't depend on NTLM for these accounts",
                    "Add accounts: Add-ADGroupMember -Identity 'Protected Users' -Members @(<accounts>)",
                    "Monitor for authentication failures after adding",
                    "Create a procedure to add all new admin accounts to Protected Users on creation",
                ],
                fix_complexity="medium",
                references=["https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"],
                technical_severity=6.5, reachability=0.6,
                mitre_attack_ids=["T1557.001"],
            )]

        self._reg(Rule("KRB-004", "Admins Not in Protected Users", "Kerberos",
                       "Admin accounts not in Protected Users group", rule_admins_not_in_protected_users))

        def rule_no_password_complexity(data):
            policy = data.get("password_policy", {})
            if not policy.get("complexity_enabled", True):
                return [RuleMatch(
                    rule_id="PWD-003", rule_name="Password Complexity Disabled",
                    finding_type="NO_PASSWORD_COMPLEXITY", module="Password Policy",
                    title="Password complexity requirement is disabled",
                    description="Password complexity enforcement is disabled, allowing trivial dictionary words and single-character-class passwords that are quickly cracked.",
                    severity="HIGH", confidence=1.0,
                    affected_objects=["Default Domain Policy"], affected_count=1,
                    root_cause="pwdProperties has DOMAIN_PASSWORD_COMPLEX (0x1) bit unset",
                    causal_chain=[
                        "Password complexity is disabled",
                        "Users can set passwords like 'password123' or 'Summer2024'",
                        "These patterns are trivially cracked with rule-based hashcat attacks",
                    ],
                    remediation="Enable password complexity in Default Domain Policy",
                    remediation_steps=[
                        "Group Policy: Computer Configuration → Security Settings → Account Policies → Password Policy",
                        "Set 'Password must meet complexity requirements' to Enabled",
                        "Consider Microsoft's NIST-aligned guidance: longer passwords over complexity rules",
                    ],
                    fix_complexity="trivial",
                    references=["https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements"],
                    technical_severity=7.0, reachability=0.8,
                    mitre_attack_ids=["T1110"],
                )]
            return []

        self._reg(Rule("PWD-003", "No Password Complexity", "Password Policy",
                       "Complexity requirement disabled", rule_no_password_complexity))

        def rule_password_reuse_history(data):
            policy = data.get("password_policy", {})
            history = policy.get("password_history_count", 24)
            if history < 10:
                sev = "HIGH" if history < 5 else "MEDIUM"
                return [RuleMatch(
                    rule_id="PWD-004", rule_name="Insufficient Password History",
                    finding_type="WEAK_PASSWORD_HISTORY", module="Password Policy",
                    title=f"Password history only retains {history} previous passwords",
                    description=f"With only {history} passwords in history, users can cycle through a small set of passwords, effectively negating periodic rotation requirements.",
                    severity=sev, confidence=1.0,
                    affected_objects=["Default Domain Policy"], affected_count=1,
                    root_cause=f"pwdHistoryLength = {history}",
                    causal_chain=[
                        f"History of {history} passwords allows rapid rotation back to preferred password",
                        "Users change password N times to reuse their original compromised password",
                        "Previously compromised credentials become valid again quickly",
                    ],
                    remediation=f"Increase password history from {history} to at least 24",
                    remediation_steps=[
                        "Edit Default Domain Policy → Account Policies → Password Policy",
                        "Set 'Enforce password history' to 24",
                        "Combine with minimum password age (1 day) to prevent rapid cycling",
                    ],
                    fix_complexity="trivial",
                    references=["https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history"],
                    technical_severity=4.5, reachability=0.5,
                    mitre_attack_ids=["T1110"],
                )]
            return []

        self._reg(Rule("PWD-004", "Weak Password History", "Password Policy",
                       "Password history count below 10", rule_password_reuse_history))

        def rule_bidirectional_trust(data):
            trusts = data.get("trusts", [])
            vuln = [t for t in trusts
                    if t.get("trust_direction", "").lower() in ("bidirectional", "both")
                    and t.get("trust_type", "").lower() == "external"]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="TRUST-002", rule_name="Bidirectional External Trust",
                finding_type="BIDIRECTIONAL_EXTERNAL_TRUST", module="Trusts",
                title=f"{len(vuln)} bidirectional external trust(s) detected",
                description="Bidirectional external trusts allow mutual authentication between domains. If the trusted domain is compromised, its compromise immediately extends to this domain.",
                severity="MEDIUM", confidence=0.8,
                affected_objects=[t.get("partner") or t.get("name") for t in vuln],
                affected_count=len(vuln),
                root_cause="trustDirection=Bidirectional on external (non-forest) trusts",
                causal_chain=[
                    "Bidirectional trust means both domains trust each other",
                    "If the partner domain is compromised, its users can authenticate here",
                    "External trusts do not inherit transitive trust — but direct access remains",
                    "Compromise of partner DA = access to resources in this domain",
                ],
                remediation="Evaluate whether bidirectional trust is necessary; consider reducing to one-way",
                remediation_steps=[
                    "Audit what cross-domain access actually requires bidirectionality",
                    "If one-way access is sufficient, convert the trust",
                    "Enable selective authentication to restrict which resources are accessible",
                    "Enforce SID filtering on all external trusts",
                ],
                fix_complexity="high",
                references=["https://docs.microsoft.com/en-us/azure/active-directory-domain-services/concepts-forest-trust"],
                technical_severity=6.0, reachability=0.5,
                mitre_attack_ids=["T1484.002"],
            )]

        self._reg(Rule("TRUST-002", "Bidirectional External Trust", "Trusts",
                       "Bidirectional external trusts", rule_bidirectional_trust))

        def rule_no_laps_computers(data):
            entities = data.get("entities", [])
            laps_telemetry = [
                e for e in entities
                if e.get("entity_type") == "COMPUTER"
                and e.get("is_enabled")
                and "laps_installed" in (e.get("attributes", {}) or {})
            ]
            if not laps_telemetry:
                return []
            no_laps = [
                e for e in laps_telemetry
                if not (e.get("attributes", {}) or {}).get("laps_installed")
            ]
            if len(no_laps) < 5:
                return []
            count = len(no_laps)
            return [RuleMatch(
                rule_id="LAPS-002", rule_name="Computers Without LAPS",
                finding_type="COMPUTERS_NO_LAPS", module="Local Admin",
                title=f"{count} enabled computers do not have LAPS installed",
                description=f"{count} active computers are not managed by LAPS, meaning their local administrator passwords are likely shared or static across the fleet.",
                severity="HIGH", confidence=0.95,
                affected_objects=[e.get("sam_account_name") or e.get("dns_hostname") for e in no_laps[:20]],
                affected_count=count,
                root_cause="LAPS telemetry explicitly reports no password-expiration state on computer objects",
                causal_chain=[
                    f"{count} computers without LAPS have unmanaged local admin passwords",
                    "Single compromised machine leaks a shared local admin hash",
                    "Pass-the-hash enables lateral movement to all machines sharing the password",
                ],
                remediation="Deploy LAPS to all managed computers",
                remediation_steps=[
                    "Identify computers without LAPS: Get-ADComputer -Filter {ms-Mcs-AdmPwdExpirationTime -notlike '*'}",
                    "Push LAPS agent via GPO or SCCM to all workstations and servers",
                    "Enable Extended Protection for Authentication (EPA) on LAPS client",
                ],
                fix_complexity="medium",
                references=["https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"],
                technical_severity=7.5, reachability=0.7,
                mitre_attack_ids=["T1021.002"],
            )]

        self._reg(Rule("LAPS-002", "Computers Without LAPS", "Local Admin",
                       "Individual computers lacking LAPS", rule_no_laps_computers))

        def rule_rbcd_on_computers(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            rbcd_targets = {
                edge.get("target_id")
                for edge in edges
                if edge.get("edge_type") == "ALLOWED_TO_ACT"
            }
            vuln = [
                e for e in entities
                if e.get("entity_type") == "COMPUTER"
                and e.get("is_enabled")
                and not (e.get("attributes", {}) or {}).get("uac_is_dc")
                and (
                    (e.get("attributes", {}) or {}).get("rbcd_configured")
                    or e.get("id") in rbcd_targets
                )
            ]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="DEL-003", rule_name="RBCD Configured on Computers",
                finding_type="RBCD_CONFIGURED", module="Kerberos",
                title=f"{len(vuln)} computer(s) have Resource-Based Constrained Delegation configured",
                description=(
                    "msDS-AllowedToActOnBehalfOfOtherIdentity is set on these computers, meaning "
                    "a specific principal can impersonate any user to the computer via S4U2Proxy. "
                    "If the trusted principal is attacker-controlled, this is a direct privilege escalation path."
                ),
                severity="HIGH", confidence=0.9,
                affected_objects=[e.get("sam_account_name") or e.get("dns_hostname") for e in vuln],
                affected_count=len(vuln),
                root_cause="msDS-AllowedToActOnBehalfOfOtherIdentity set on computer accounts",
                causal_chain=[
                    "Computer has RBCD configured (msDS-AllowedToActOnBehalfOfOtherIdentity)",
                    "The trusted principal can use S4U2Self to get a TGS for any user",
                    "Then S4U2Proxy to impersonate that user to this computer",
                    "If trusted principal is attacker-controlled → immediate privilege escalation",
                ],
                remediation="Audit and remove RBCD delegations unless explicitly required by applications",
                remediation_steps=[
                    "Identify: Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne '$null'}",
                    "Clear if unneeded: Set-ADComputer <computer> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity",
                    "Document all legitimate RBCD configurations and restrict who can modify them",
                    "Monitor for changes to this attribute via Event ID 5136",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1134/001/"],
                technical_severity=8.0, reachability=0.7,
                mitre_attack_ids=["T1134.001"],
            )]

        self._reg(Rule("DEL-003", "RBCD Configured", "Kerberos",
                       "RBCD set on computer accounts", rule_rbcd_on_computers))

        def rule_shadow_credentials(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("attributes", {}).get("shadow_credentials")
                    and e.get("is_enabled")]
            if not vuln:
                return []
            has_admin = any(e.get("is_admin_count") for e in vuln)
            sev = "CRITICAL" if has_admin else "HIGH"
            return [RuleMatch(
                rule_id="PER-001", rule_name="Shadow Credentials Detected",
                finding_type="SHADOW_CREDENTIALS", module="Persistence",
                title=f"{len(vuln)} account(s) have msDS-KeyCredentialLink populated",
                description=(
                    "Shadow Credentials allow PKINIT authentication using a key pair stored in "
                    "msDS-KeyCredentialLink. An attacker who adds their key to this attribute gains "
                    "persistent, password-independent access to the account."
                ),
                severity=sev, confidence=0.85,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="msDS-KeyCredentialLink contains key credentials (possibly attacker-added)",
                causal_chain=[
                    "Attacker with WriteProperty over the account writes their public key to msDS-KeyCredentialLink",
                    "Uses PKINIT Kerberos to authenticate as the target using that key",
                    "Obtains a TGT without knowing the account's password",
                    "Persists even after password resets",
                ],
                remediation="Audit msDS-KeyCredentialLink values; remove unauthorized entries",
                remediation_steps=[
                    "Enumerate: Get-ADUser -Filter * -Properties 'msDS-KeyCredentialLink' | Where {$_.'msDS-KeyCredentialLink'}",
                    "For each account, verify all key entries are legitimate (e.g. Windows Hello for Business)",
                    "Remove unauthorized entries using dsacls or Active Directory module",
                    "Enable auditing on msDS-KeyCredentialLink attribute changes (Event ID 5136)",
                    "Restrict who can write to msDS-KeyCredentialLink via ACL hardening",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1556/006/"],
                technical_severity=9.0, reachability=0.6,
                is_tier0_direct=has_admin,
                mitre_attack_ids=["T1556.006"],
            )]

        self._reg(Rule("PER-001", "Shadow Credentials", "Persistence",
                       "msDS-KeyCredentialLink populated on accounts", rule_shadow_credentials))

        def rule_sid_history_populated(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("attributes", {}).get("has_sid_history")
                    and e.get("is_enabled")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="TRUST-003", rule_name="SID History Populated on Accounts",
                finding_type="SID_HISTORY_POPULATED", module="Trusts",
                title=f"{len(vuln)} account(s) have sIDHistory populated",
                description=(
                    "Accounts with sIDHistory carry additional SIDs that are honored in access tokens. "
                    "Attackers inject high-privilege SIDs to gain elevated access, bypassing normal group membership checks."
                ),
                severity="HIGH", confidence=0.9,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="sIDHistory attribute populated — could be legitimate migration artifact or injected SID",
                causal_chain=[
                    "Account has sIDHistory with one or more SIDs",
                    "All SIDs in sIDHistory are included in the user's access token",
                    "If a high-privilege SID (e.g., Domain Admins S-1-5-21-*-512) is present, account has DA-level access",
                    "This is invisible in normal group membership views",
                ],
                remediation="Audit sIDHistory entries; remove stale or unauthorized SIDs",
                remediation_steps=[
                    "Enumerate: Get-ADUser -Filter * -Properties sIDHistory | Where {$_.sIDHistory}",
                    "Cross-reference SIDs with legitimate migration records",
                    "Remove unauthorized SIDs: use AD PowerShell or LDP.exe to clear sIDHistory",
                    "Enable SID filtering on all domain trusts to prevent cross-domain SID injection",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1134.005/"],
                technical_severity=8.5, reachability=0.5,
                mitre_attack_ids=["T1134.005"],
            )]

        self._reg(Rule("TRUST-003", "SID History Populated", "Trusts",
                       "Accounts with sIDHistory attribute set", rule_sid_history_populated))

        def rule_rc4_kerberoastable(data):
            entities = data.get("entities", [])
            vuln = [e for e in entities
                    if e.get("attributes", {}).get("has_spn")
                    and e.get("is_enabled")
                    and e.get("attributes", {}).get("rc4_only")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="KRB-005", rule_name="Kerberoastable Accounts with RC4-Only Encryption",
                finding_type="KERBEROAST_RC4_ONLY", module="Kerberos",
                title=f"{len(vuln)} Kerberoastable account(s) support only RC4 encryption",
                description=(
                    "Service accounts with SPNs that support only RC4 Kerberos encryption produce "
                    "weaker TGS tickets (etype 23) that crack significantly faster than AES tickets. "
                    "Modern GPUs crack RC4-based Kerberos hashes ~5x faster than AES."
                ),
                severity="HIGH", confidence=0.85,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="msDS-SupportedEncryptionTypes does not include AES128/AES256 flags",
                causal_chain=[
                    "Account SPN only supports RC4 (etype 23) Kerberos tickets",
                    "Kerberoast request forces etype 23 even if AES is available domain-wide",
                    "RC4 hashes crack at 500M+ hashes/sec on a single GPU",
                    "AES hashes crack at ~100M hashes/sec — 5x slower",
                ],
                remediation="Enable AES Kerberos encryption for all service accounts with SPNs",
                remediation_steps=[
                    "Set AES encryption: Set-ADUser <account> -KerberosEncryptionType AES256",
                    "Or via ADUC: Account tab → check 'This account supports Kerberos AES 256 bit encryption'",
                    "Also enforce strong (25+ char) passwords for remaining RC4 accounts",
                    "Migrate to gMSA to eliminate the attack surface entirely",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1558/003/"],
                technical_severity=7.0, reachability=0.65,
                mitre_attack_ids=["T1558.003"],
            )]

        self._reg(Rule("KRB-005", "RC4-Only Kerberoastable", "Kerberos",
                       "Kerberoastable accounts without AES encryption", rule_rc4_kerberoastable))

        def rule_constrained_delegation_standard(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            delegate_sources = {
                edge.get("source_id")
                for edge in edges
                if edge.get("edge_type") == "ALLOWED_TO_DELEGATE"
            }
            vuln = []
            for entity in entities:
                if not entity.get("is_enabled"):
                    continue
                attrs = entity.get("attributes", {}) or {}
                if attrs.get("uac_is_dc"):
                    continue
                has_targets = bool(attrs.get("allowed_to_delegate_to")) or entity.get("id") in delegate_sources
                any_protocol = bool(
                    attrs.get("constrained_delegation_any_protocol")
                    or attrs.get("uac_trusted_to_auth_for_delegation")
                )
                if has_targets and not any_protocol:
                    vuln.append(entity)
            if not vuln:
                return []
            has_admin = any(e.get("is_admin_count") for e in vuln)
            sev = "HIGH" if has_admin else "MEDIUM"
            return [RuleMatch(
                rule_id="DEL-004", rule_name="Standard Constrained Delegation (KCD)",
                finding_type="CONSTRAINED_DELEGATION_KCD", module="Kerberos",
                title=f"{len(vuln)} account(s) configured with standard constrained delegation",
                description=(
                    "Accounts with standard KCD (msDS-AllowedToDelegateTo set, no protocol transition) "
                    "can impersonate Kerberos-authenticated users to specific target services. "
                    "Combined with coercion or existing access, this enables lateral movement."
                ),
                severity=sev, confidence=0.95,
                affected_objects=[e.get("sam_account_name") for e in vuln],
                affected_count=len(vuln),
                root_cause="msDS-AllowedToDelegateTo set without TrustedToAuthForDelegation",
                causal_chain=[
                    "Account has constrained delegation targets configured",
                    "Account can forward Kerberos tickets of authenticated users to target SPNs",
                    "If attacker compromises this account, they can impersonate any user to target services",
                ],
                remediation="Audit KCD configurations; restrict delegation targets to minimum required SPNs",
                remediation_steps=[
                    "Enumerate: Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne '$null'}",
                    "Review each delegation target — remove any that are no longer needed",
                    "Where possible, migrate to RBCD which is more granularly controlled",
                    "Ensure delegating accounts use strong, unique passwords or migrate to gMSA",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1558/"],
                technical_severity=6.5, reachability=0.6,
                is_tier0_direct=has_admin,
                mitre_attack_ids=["T1558"],
            )]

        self._reg(Rule("DEL-004", "Standard Constrained Delegation", "Kerberos",
                       "KCD without protocol transition", rule_constrained_delegation_standard))

        _EDITF_ALTSUBJECTNAME_BIT = 0x00040000

        def _esc6_flag_set(edit_flags) -> bool:
            try:
                val = edit_flags
                if isinstance(val, str):
                    val = int(val, 0)
                return bool(int(val or 0) & _EDITF_ALTSUBJECTNAME_BIT)
            except (ValueError, TypeError):
                return False

        def rule_esc6(data):
            # ESC6 is a CA policy flag — not a cert template attribute.
            # Evidence comes from ca_flags (Windows CA collector) or CA entities
            # with esc6_vulnerable set in their attributes.
            ca_flags = data.get("ca_flags", [])
            entities = data.get("entities", [])

            seen: set[str] = set()
            vuln_cas: list[dict] = []

            for ca in ca_flags:
                ca_name = str(ca.get("ca_name") or "")
                edit_flags = ca.get("edit_flags", 0)
                editf_direct = ca.get("editf_attribute_subject_alt_name_2")
                certutil_out = ca.get("certutil_output") or ""
                certutil_hit = "EDITF_ATTRIBUTESUBJECTALTNAME2" in certutil_out
                if editf_direct or _esc6_flag_set(edit_flags) or certutil_hit:
                    if ca_name not in seen:
                        seen.add(ca_name)
                        vuln_cas.append({
                            "ca_name": ca_name,
                            "host": ca.get("hostname") or ca.get("host") or "",
                            "edit_flags_decimal": int(edit_flags or 0),
                            "edit_flags_hex": ca.get("edit_flags_hex") or hex(int(edit_flags or 0)),
                            "flag_name": "EDITF_ATTRIBUTESUBJECTALTNAME2",
                            "registry_path": ca.get("registry_path") or "",
                            "collection_method": ca.get("collection_method") or "windows_ca_flags",
                        })

            # Fallback: CA entities with esc6_vulnerable attribute (e.g. from future LDAP path)
            for e in entities:
                if e.get("entity_type") != "CA":
                    continue
                attrs = e.get("attributes") or {}
                if attrs.get("esc6_vulnerable") or _esc6_flag_set(attrs.get("edit_flags")):
                    ca_name = e.get("display_name") or e.get("sam_account_name") or ""
                    if ca_name and ca_name not in seen:
                        seen.add(ca_name)
                        vuln_cas.append({
                            "ca_name": ca_name,
                            "host": attrs.get("dNSHostName") or e.get("dns_hostname") or "",
                            "edit_flags_decimal": int(attrs.get("edit_flags") or 0),
                            "edit_flags_hex": hex(int(attrs.get("edit_flags") or 0)),
                            "flag_name": "EDITF_ATTRIBUTESUBJECTALTNAME2",
                            "registry_path": "",
                            "collection_method": "entity_attribute",
                        })

            if not vuln_cas:
                return []

            title = (
                f"{vuln_cas[0]['ca_name']} allows SAN supplied in certificate requests"
                if len(vuln_cas) == 1
                else f"{len(vuln_cas)} CAs allow SAN supplied in certificate requests"
            )
            return [RuleMatch(
                rule_id="ADCS-006", rule_name="ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on CA",
                finding_type="ESC6_CA_SAN_FLAG_ENABLED", module="AD CS",
                title=title,
                description=(
                    "The EDITF_ATTRIBUTESUBJECTALTNAME2 flag is enabled on the CA policy module. "
                    "This allows any certificate request to specify an arbitrary Subject Alternative Name, "
                    "even on templates that do not grant CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT. "
                    "Every enrollable template effectively becomes ESC1-equivalent."
                ),
                severity="CRITICAL", confidence=0.95,
                affected_objects=vuln_cas,
                affected_count=len(vuln_cas),
                root_cause="EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled in CA policy module EditFlags",
                causal_chain=[
                    "CA policy module has EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) set in EditFlags",
                    "Any certificate request can include an arbitrary SAN regardless of template settings",
                    "Attacker requests certificate specifying Domain Admin UPN as SAN on any enrollable template",
                    "Certificate used for PKINIT authentication as Domain Admin → full domain compromise",
                ],
                remediation="Disable EDITF_ATTRIBUTESUBJECTALTNAME2 on all CA servers and audit enrollment controls",
                remediation_steps=[
                    "On CA server: certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2",
                    "Restart CertSvc: net stop certsvc && net start certsvc",
                    "Verify flag cleared: certutil -getreg policy\\EditFlags",
                    "Audit certificate templates with client authentication EKUs and low-privilege enrollment",
                    "Review CA policy and enrollment controls to ensure principle of least privilege",
                ],
                fix_complexity="low",
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                technical_severity=10.0, reachability=0.9,
                is_tier0_direct=True,
                mitre_attack_ids=["T1649"],
            )]

        self._reg(Rule("ADCS-006", "ESC6", "AD CS",
                       "CA with EDITF_ATTRIBUTESUBJECTALTNAME2", rule_esc6))

        def rule_esc8(data):
            templates = data.get("cert_templates", [])
            vuln = [t for t in templates if t.get("esc8_vulnerable")]
            if not vuln:
                return []
            return [RuleMatch(
                rule_id="ADCS-008", rule_name="ESC8 — NTLM Relay to AD CS HTTP Enrollment",
                finding_type="ESC8", module="AD CS",
                title=f"{len(vuln)} CA enrollment endpoint(s) vulnerable to NTLM relay",
                description=(
                    "AD CS Web Enrollment or CES/CEP endpoints that accept NTLM authentication "
                    "are vulnerable to NTLM relay attacks. An attacker can relay DC or privileged "
                    "machine authentication to obtain a certificate for that machine/user."
                ),
                severity="CRITICAL", confidence=0.8,
                affected_objects=[t.get("name") for t in vuln],
                affected_count=len(vuln),
                root_cause="CA HTTP enrollment endpoint accepts NTLM without EPA/channel binding",
                causal_chain=[
                    "CA has HTTP (not HTTPS with EPA) enrollment endpoint",
                    "NTLM authentication is accepted without Extended Protection for Authentication",
                    "Attacker coerces DC or computer authentication via PrinterBug/PetitPotam",
                    "Relays credentials to CA enrollment endpoint",
                    "Obtains certificate for the DC/computer account",
                    "Uses certificate for Kerberos auth (PKINIT) → retrieves NTLM hash → DCSync",
                ],
                remediation="Enable HTTPS with EPA on all CA enrollment endpoints; disable NTLM where possible",
                remediation_steps=[
                    "Enable Extended Protection for Authentication on IIS: set requireSSL and tokenChecking",
                    "Enforce HTTPS for all CA web enrollment interfaces",
                    "Disable NTLM on enrollment endpoints where Kerberos is available",
                    "Block NTLM relay paths with SMB signing enforcement",
                ],
                fix_complexity="medium",
                references=["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
                technical_severity=9.5, reachability=0.7,
                is_tier0_direct=True,
                mitre_attack_ids=["T1649", "T1557.001"],
            )]

        self._reg(Rule("ADCS-008", "ESC8", "AD CS",
                       "CA HTTP enrollment vulnerable to NTLM relay", rule_esc8))

        def rule_adminsdholder_orphans(data):
            entities = data.get("entities", [])
            high_value_groups = {
                "domain admins", "enterprise admins", "schema admins",
                "administrators", "account operators", "backup operators",
                "print operators", "server operators", "group policy creator owners",
            }
            # adminCount=1 but not in known admin groups — may be persistence or orphan
            orphans = []
            for e in entities:
                if (e.get("entity_type") == "USER"
                        and e.get("is_admin_count")
                        and e.get("is_enabled")):
                    sam = (e.get("sam_account_name") or "").lower()
                    if not any(marker in sam for marker in ("admin", "svc", "service", "krbtgt")):
                        member_of = [g.lower() for g in e.get("attributes", {}).get("member_of", [])]
                        in_admin_group = any(
                            any(grp in m for grp in high_value_groups)
                            for m in member_of
                        )
                        if not in_admin_group:
                            orphans.append(e)
            if not orphans:
                return []
            return [RuleMatch(
                rule_id="ACL-003", rule_name="AdminSDHolder Orphaned Accounts",
                finding_type="ADMINSDHOLDER_ORPHAN", module="ACL Abuse",
                title=f"{len(orphans)} account(s) have adminCount=1 but are not in known privileged groups",
                description=(
                    "These accounts have adminCount=1 (previously protected by AdminSDHolder) but appear "
                    "to no longer be members of privileged groups. AdminSDHolder sets restrictive ACLs "
                    "that persist even after group removal, potentially leaving hidden backdoors."
                ),
                severity="MEDIUM", confidence=0.7,
                affected_objects=[e.get("sam_account_name") for e in orphans],
                affected_count=len(orphans),
                root_cause="adminCount=1 set but account no longer in privileged group — ACL may be over-restricted",
                causal_chain=[
                    "Account was previously in a privileged group (protected by AdminSDHolder)",
                    "Account was removed from the group but adminCount was not reset to 0",
                    "AdminSDHolder-applied ACL remains — standard delegation on the account may not work",
                    "Or — the account was deliberately given adminCount=1 as a persistence mechanism",
                ],
                remediation="Audit adminCount accounts; reset adminCount to 0 for accounts no longer privileged",
                remediation_steps=[
                    "Identify: Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount,MemberOf",
                    "Compare against current privileged group membership",
                    "For orphaned accounts: Set-ADUser <account> -Clear adminCount",
                    "Re-apply proper OU-level ACL inheritance after clearing adminCount",
                ],
                fix_complexity="low",
                references=["https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"],
                technical_severity=5.0, reachability=0.4,
                mitre_attack_ids=["T1078.002"],
            )]

        self._reg(Rule("ACL-003", "AdminSDHolder Orphans", "ACL Abuse",
                       "Accounts with adminCount=1 not in privileged groups", rule_adminsdholder_orphans))

        def rule_service_accounts_no_gmsa(data):
            entities = data.get("entities", [])
            standard_svc = [e for e in entities
                            if e.get("entity_type") == "SERVICE_ACCOUNT"
                            and e.get("is_enabled")]
            gmsa_count = sum(1 for e in entities if e.get("entity_type") == "GMSA")
            if len(standard_svc) < 5 or gmsa_count >= len(standard_svc):
                return []
            return [RuleMatch(
                rule_id="SVC-001", rule_name="Service Accounts Without gMSA",
                finding_type="SERVICE_ACCOUNTS_NO_GMSA", module="Service Accounts",
                title=f"{len(standard_svc)} standard service account(s) not migrated to gMSA",
                description=(
                    "Standard user-based service accounts require manual password management, "
                    "leading to weak/static passwords that are Kerberoastable. "
                    "Group Managed Service Accounts (gMSA) use 240-char auto-rotating passwords "
                    "that eliminate Kerberoasting risk."
                ),
                severity="MEDIUM", confidence=0.85,
                affected_objects=[e.get("sam_account_name") for e in standard_svc[:20]],
                affected_count=len(standard_svc),
                root_cause="Service functions using standard user accounts instead of gMSA",
                causal_chain=[
                    "Service accounts are standard user objects with SPNs",
                    "Passwords are set manually and rarely rotated",
                    "Any authenticated user can Kerberoast these accounts",
                    "Compromised service account enables lateral movement to all systems it accesses",
                ],
                remediation="Migrate service accounts to Group Managed Service Accounts (gMSA)",
                remediation_steps=[
                    "Check KDS root key exists: Get-KDSRootKey (create if missing)",
                    "Create gMSA: New-ADServiceAccount -Name <name> -DNSHostName <host> -PrincipalsAllowedToRetrieveManagedPassword <servers>",
                    "Install on servers: Install-ADServiceAccount <gMSAName>",
                    "Update service configuration to use gMSA account",
                    "Disable and eventually delete the legacy service account",
                ],
                fix_complexity="medium",
                references=["https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"],
                technical_severity=5.5, reachability=0.6,
                mitre_attack_ids=["T1558.003"],
            )]

        self._reg(Rule("SVC-001", "Service Accounts Without gMSA", "Service Accounts",
                       "Standard service accounts not using gMSA", rule_service_accounts_no_gmsa))

        def rule_write_dacl_on_users(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            user_ids = {e.get("id") for e in entities
                        if e.get("entity_type") == "USER" and e.get("is_enabled")}
            non_admin_ids = {e.get("id") for e in entities if not e.get("is_admin_count")}
            abuse_edges = [
                edge for edge in edges
                if edge.get("edge_type") in ("WRITE_DACL", "WRITE_OWNER", "GENERIC_ALL", "FORCE_CHANGE_PASSWORD")
                and edge.get("target_id") in user_ids
                and edge.get("source_id") in non_admin_ids
            ]
            if not abuse_edges:
                return []
            affected_targets = list({e.get("target_id") for e in abuse_edges})
            return [RuleMatch(
                rule_id="ACL-004", rule_name="Dangerous ACL on User Accounts",
                finding_type="WRITE_DACL_ON_USERS", module="ACL Abuse",
                title=f"{len(affected_targets)} user account(s) have dangerous ACL rights from non-admin principals",
                description=(
                    "Non-privileged accounts have WriteDACL, WriteOwner, GenericAll, or ForceChangePassword "
                    "rights over enabled user accounts. These permissions allow direct account takeover."
                ),
                severity="HIGH", confidence=0.9,
                affected_objects=affected_targets[:20],
                affected_count=len(affected_targets),
                root_cause="Dangerous ACEs on user accounts for non-admin principals",
                causal_chain=[
                    "Non-admin principal has write/control ACE on target user account",
                    "WriteDACL: can grant themselves any additional right",
                    "WriteOwner: can take ownership → then WriteDACL",
                    "ForceChangePassword: can set a new password without knowing current",
                    "GenericAll: combined all of the above",
                ],
                remediation="Remove dangerous ACEs from user accounts via ACL cleanup",
                remediation_steps=[
                    "Enumerate: (Get-Acl 'AD:\\<user DN>').Access | Where-Object {$_.ActiveDirectoryRights -match 'WriteDacl|WriteOwner|GenericAll'}",
                    "Remove unauthorized ACEs using dsacls or Set-Acl",
                    "Verify inheritance is blocked appropriately for privileged accounts",
                    "Enable continuous ACL monitoring via Event ID 5136",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1484/"],
                technical_severity=8.0, reachability=0.7,
                mitre_attack_ids=["T1484"],
            )]

        self._reg(Rule("ACL-004", "WriteDACL on Users", "ACL Abuse",
                       "Dangerous ACL rights over enabled user accounts", rule_write_dacl_on_users))

        def rule_large_spray_surface(data):
            entities = data.get("entities", [])
            policy = data.get("password_policy", {})
            if policy.get("lockout_threshold", 1) > 0:
                return []  # Lockout policy mitigates spray risk
            enabled_users = [e for e in entities
                             if e.get("entity_type") in ("USER", "SERVICE_ACCOUNT")
                             and e.get("is_enabled")]
            if len(enabled_users) < 50:
                return []
            return [RuleMatch(
                rule_id="PWD-005", rule_name="Large Password Spray Attack Surface",
                finding_type="LARGE_SPRAY_SURFACE", module="Password Policy",
                title=f"{len(enabled_users)} enabled accounts exposed to unlimited password spraying",
                description=(
                    f"With no lockout policy and {len(enabled_users)} enabled accounts, "
                    "an attacker can spray common passwords against all accounts indefinitely "
                    "without triggering any lockout or detection."
                ),
                severity="HIGH", confidence=1.0,
                affected_objects=[f"{len(enabled_users)} enabled user accounts"],
                affected_count=len(enabled_users),
                root_cause="No lockout policy + large number of enabled accounts",
                causal_chain=[
                    "No account lockout (threshold = 0)",
                    f"{len(enabled_users)} enabled user accounts are spray targets",
                    "Common seasonal passwords ('Spring2024!', 'Company2024') likely valid for some accounts",
                    "Single valid credential enables initial foothold for further exploitation",
                ],
                remediation="Implement account lockout policy AND deploy password spray detection (e.g., Entra ID Smart Lockout)",
                remediation_steps=[
                    "Set lockout threshold: 5-10 attempts",
                    "Enable Azure AD / Entra ID Password Protection to block common passwords",
                    "Deploy SIEM alerting for distributed spray patterns (multiple accounts, low frequency)",
                    "Consider FIDO2/passwordless for all accounts",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1110.003/"],
                technical_severity=7.5, reachability=1.0,
                mitre_attack_ids=["T1110.003"],
            )]

        self._reg(Rule("PWD-005", "Large Spray Surface", "Password Policy",
                       "Many enabled accounts with no lockout policy", rule_large_spray_surface))

        def rule_write_owner_abuse(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            tier0_ids = {e.get("id") for e in entities
                         if e.get("tier") == 0 or e.get("is_crown_jewel")}
            non_admin_ids = {e.get("id") for e in entities if not e.get("is_admin_count")}
            abuse_edges = [
                edge for edge in edges
                if edge.get("edge_type") == "WRITE_OWNER"
                and edge.get("target_id") in tier0_ids
                and edge.get("source_id") in non_admin_ids
            ]
            if not abuse_edges:
                return []
            name_map = _entity_name_map(entities)
            affected = list({name_map.get(e.get("source_id"), e.get("source_id")) for e in abuse_edges})
            return [RuleMatch(
                rule_id="ACL-005", rule_name="WriteOwner on Tier-0 Objects",
                finding_type="WRITE_OWNER_TIER0", module="ACL Abuse",
                title=f"{len(affected)} non-admin account(s) can take ownership of Tier-0 objects",
                description=(
                    "Non-privileged accounts have WriteOwner rights on Tier-0 objects. "
                    "Ownership grants the ability to modify the DACL, enabling any further privilege escalation. "
                    "The attack chain: WriteOwner → take ownership → grant GenericAll → compromise."
                ),
                severity="CRITICAL", confidence=0.95,
                affected_objects=affected[:20], affected_count=len(affected),
                root_cause="WriteOwner ACE on Tier-0 object granted to non-admin principals",
                causal_chain=[
                    "Non-admin has WriteOwner ACE on a Tier-0 object",
                    "Attacker takes ownership of the object",
                    "As owner, attacker can modify the DACL unconditionally",
                    "Attacker grants themselves GenericAll",
                    "Full control of Tier-0 object (group, domain, DC)",
                ],
                remediation="Remove WriteOwner ACEs from Tier-0 objects for non-admin principals",
                remediation_steps=[
                    "Identify: (Get-Acl 'AD:\\<object>').Access | Where ActiveDirectoryRights -match 'WriteOwner'",
                    "Remove the ACEs using dsacls or PowerShell Set-Acl",
                    "Audit AdminSDHolder template to ensure it does not grant WriteOwner to low-priv accounts",
                    "Enable Event ID 5136 monitoring for ownership changes",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1484/"],
                technical_severity=9.5, reachability=0.8,
                is_tier0_direct=True, on_crown_jewel_path=True,
                mitre_attack_ids=["T1484"],
            )]

        self._reg(Rule("ACL-005", "WriteOwner on Tier-0", "ACL Abuse",
                       "Non-admin accounts with WriteOwner on Tier-0 objects", rule_write_owner_abuse))

        _PRIV_GROUP_MARKERS = {
            "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
            "ADMINISTRATORS", "DOMAIN CONTROLLERS", "READ-ONLY DOMAIN CONTROLLERS",
            "GROUP POLICY CREATOR OWNERS", "ACCOUNT OPERATORS",
            "BACKUP OPERATORS", "PRINT OPERATORS", "SERVER OPERATORS",
        }

        def _is_priv_group(name: str) -> bool:
            n = name.upper()
            return any(m in n for m in _PRIV_GROUP_MARKERS)

        def rule_add_member_group_takeover(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            label_by_id = {
                e.get("id"): (e.get("sam_account_name") or e.get("display_name") or e.get("id"))
                for e in entities
            }
            group_ids = {e.get("id") for e in entities if e.get("entity_type") == "GROUP"}
            priv_group_ids = {
                e.get("id") for e in entities
                if e.get("entity_type") == "GROUP"
                and _is_priv_group(e.get("sam_account_name") or e.get("display_name") or "")
            }
            if not group_ids:
                return []
            non_admin_ids = {e.get("id") for e in entities if not e.get("is_admin_count")}
            abuse_edges = [
                edge for edge in edges
                if edge.get("edge_type") == "ADD_MEMBER"
                and edge.get("target_id") in group_ids
                and edge.get("source_id") in non_admin_ids
            ]
            if not abuse_edges:
                return []
            affected_sources = list({label_by_id.get(e.get("source_id"), e.get("source_id")) for e in abuse_edges})
            affected_groups = list({e.get("target_id") for e in abuse_edges})
            has_privileged_target = any(group_id in priv_group_ids for group_id in affected_groups)
            affected_pairs = [
                f"{label_by_id.get(edge.get('source_id'), edge.get('source_id'))} -> "
                f"{label_by_id.get(edge.get('target_id'), edge.get('target_id'))}"
                for edge in abuse_edges[:20]
            ]
            sample_pair = affected_pairs[0] if affected_pairs else "non-admin principal -> privileged group"
            return [RuleMatch(
                rule_id="ACL-006", rule_name="AddMember Group Takeover",
                finding_type="ADD_MEMBER_GROUP_TAKEOVER", module="ACL Abuse",
                title=f"Non-admin principal can modify group membership: {sample_pair}",
                description=(
                    f"{len(affected_sources)} non-admin account(s) can perform AddMember / group takeover. "
                    "Non-privileged accounts have WriteProperty on the member attribute of groups, enabling "
                    "direct group membership manipulation. If the target group is privileged, this can grant "
                    f"full domain admin rights. Observed paths: {', '.join(affected_pairs[:10])}."
                ),
                severity="CRITICAL" if has_privileged_target else "HIGH", confidence=0.95,
                affected_objects=affected_pairs, affected_count=len(affected_sources),
                root_cause=(
                    "WriteProperty (member attribute) ACE granted to non-admin principals on groups; "
                    f"AddMember group takeover path includes {sample_pair}"
                ),
                causal_chain=[
                    "Non-admin has WriteProperty on the 'member' attribute of a group",
                    "Attacker adds themselves (or another controlled account) to the target group",
                    "Privileges or downstream access assigned to the group become available to the attacker",
                ],
                remediation="Remove AddMember (WriteProperty on member) from groups for non-admin principals unless explicitly delegated",
                remediation_steps=[
                    "(Get-Acl 'AD:\\<group DN>').Access | Where {$_.ActiveDirectoryRights -match 'WriteProperty' -and $_.ObjectType -eq 'bf9679c0-...'}",
                    "Remove the ACE using dsacls: dsacls '<group DN>' /R <account>",
                    "Verify AdminSDHolder template is protecting all privileged groups",
                    "Audit for delegated group management — use task-specific delegated accounts, not broad write ACLs",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1484/"],
                technical_severity=10.0 if has_privileged_target else 8.0, reachability=0.9,
                is_tier0_direct=has_privileged_target, on_crown_jewel_path=has_privileged_target,
                mitre_attack_ids=["T1484"],
            )]

        self._reg(Rule("ACL-006", "AddMember Group Takeover", "ACL Abuse",
                       "Non-admin accounts that can add members to groups", rule_add_member_group_takeover))

        def rule_dangerous_gpo_delegation(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            gpo_ids = {e.get("id") for e in entities if e.get("entity_type") == "GPO"}
            if not gpo_ids:
                return []
            non_admin_ids = {e.get("id") for e in entities if not e.get("is_admin_count")}
            abuse_edges = [
                edge for edge in edges
                if edge.get("edge_type") in ("GENERIC_ALL", "WRITE_DACL", "HAS_CONTROL")
                and edge.get("target_id") in gpo_ids
                and edge.get("source_id") in non_admin_ids
            ]
            if not abuse_edges:
                return []
            name_map = _entity_name_map(entities)
            affected = list({name_map.get(e.get("source_id"), e.get("source_id")) for e in abuse_edges})
            affected_gpos = list({name_map.get(e.get("target_id"), e.get("target_id")) for e in abuse_edges})
            return [RuleMatch(
                rule_id="ACL-007", rule_name="Dangerous GPO Delegation",
                finding_type="DANGEROUS_GPO_DELEGATION", module="ACL Abuse",
                title=f"{len(affected)} non-admin account(s) have write control over {len(affected_gpos)} GPO(s)",
                description=(
                    "Non-privileged accounts have GenericAll or WriteDACL over Group Policy Objects "
                    "linked to OUs containing computers. An attacker can modify GPO content to "
                    "execute arbitrary code on all affected machines — including Domain Controllers."
                ),
                severity="CRITICAL", confidence=0.9,
                affected_objects=affected[:20], affected_count=len(affected),
                root_cause="GenericAll/WriteDACL ACE on GPO objects for non-admin principals",
                causal_chain=[
                    "Non-admin has write control over a linked GPO",
                    "Attacker modifies the GPO's Computer Configuration startup script or software install",
                    "GPO applies to target computers (including possibly DCs) at next refresh",
                    "Arbitrary code executes as SYSTEM on all affected machines",
                ],
                remediation="Remove GenericAll/WriteDACL from GPOs for non-admin accounts; restrict GPO edit rights to GPMC-only accounts",
                remediation_steps=[
                    "Open GPMC → right-click GPO → Delegation → review all accounts with Edit rights",
                    "Remove non-admin accounts from Edit/Modify Security permissions",
                    "Restrict SYSVOL write access to match GPMC delegation",
                    "Enable GPO change auditing and monitor for unauthorized policy modifications",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1484.001/"],
                technical_severity=9.5, reachability=0.8,
                is_tier0_direct=True,
                mitre_attack_ids=["T1484.001"],
            )]

        self._reg(Rule("ACL-007", "Dangerous GPO Delegation", "ACL Abuse",
                       "Non-admin write control over GPOs", rule_dangerous_gpo_delegation))

        def rule_sysvol_gpp_cpassword(data):
            evidence = data.get("evidence", [])
            sysvol_ev = next(
                (ev for ev in evidence
                 if ev.get("collection_method") == "sysvol/gpp"
                 and ev.get("raw_data", {}).get("cpassword_files", 0) > 0),
                None,
            )
            if not sysvol_ev:
                return []
            count = sysvol_ev["raw_data"]["cpassword_files"]
            findings = sysvol_ev["raw_data"].get("findings", [])
            affected = [f.get("file_path", f.get("filename", "")) for f in findings[:20]]
            affected_preview = ", ".join([item for item in affected[:10] if item]) or "SYSVOL Group Policy Preference XML"
            return [RuleMatch(
                rule_id="ACL-008", rule_name="SYSVOL GPP cpassword Exposure",
                finding_type="SYSVOL_GPP_CPASSWORD", module="GPO / SYSVOL",
                title=f"GPP cpassword found in {count} SYSVOL XML file(s)",
                description=(
                    "Group Policy Preferences password (cpassword) XML files were found in SYSVOL. "
                    "The encryption key for these passwords was publicly disclosed by Microsoft in 2012 (MS14-025). "
                    "Any authenticated domain user can read SYSVOL and decrypt these credentials. "
                    f"Legacy password exposure evidence includes: {affected_preview}."
                ),
                severity="CRITICAL", confidence=1.0,
                affected_objects=affected, affected_count=count,
                root_cause="cpassword attribute present in GPP XML files in SYSVOL",
                causal_chain=[
                    "Legacy Group Policy Preferences stored passwords in XML files in SYSVOL",
                    "Microsoft published the static AES key used for 'encryption' (KB2962486)",
                    "Any authenticated domain user can read SYSVOL share",
                    "Tools like Get-GPPPassword or Metasploit post/windows/gather/credentials/gpp instantly decrypt",
                    "Credentials are often local admin or service account passwords — immediate lateral movement",
                ],
                remediation="Delete all GPP password XML files from SYSVOL; rotate all exposed credentials; use LAPS or gMSA instead",
                remediation_steps=[
                    "Delete affected XML files from SYSVOL (paths listed in affected objects)",
                    "Rotate every credential that was stored in GPP — assume they are compromised",
                    "Install Microsoft patch KB2962486 on all DCs if not already applied (MS14-025)",
                    "Deploy LAPS for local admin passwords; gMSA for service accounts",
                    "Search for additional GPP XML files: Get-ChildItem -Path \\\\<domain>\\SYSVOL -Recurse -Include Groups.xml,Services.xml,ScheduledTasks.xml",
                ],
                fix_complexity="medium",
                references=[
                    "https://attack.mitre.org/techniques/T1552.006/",
                    "https://support.microsoft.com/kb/2962486",
                ],
                technical_severity=10.0, reachability=1.0,
                is_tier0_direct=False, on_crown_jewel_path=True,
                mitre_attack_ids=["T1552.006"],
            )]

        self._reg(Rule("ACL-008", "SYSVOL GPP cpassword", "GPO / SYSVOL",
                       "GPP cpassword XML files found in SYSVOL", rule_sysvol_gpp_cpassword))

        def rule_adminsdholder_acl_drift(data):
            entities = data.get("entities", [])
            edges = data.get("edges", [])
            # Look for GenericAll/WRITE_DACL edges where the target is an AdminSDHolder-protected
            # account but the source is a non-admin principal — indicates SDHolder drift
            admin_ids = {e.get("id") for e in entities
                         if e.get("is_admin_count") and e.get("is_enabled")}
            if not admin_ids:
                return []
            non_admin_ids = {e.get("id") for e in entities if not e.get("is_admin_count")}
            # Edges: non-admin → admin with dangerous ACE type
            drift_edges = [
                edge for edge in edges
                if edge.get("edge_type") in ("GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "HAS_CONTROL")
                and edge.get("target_id") in admin_ids
                and edge.get("source_id") in non_admin_ids
                and not edge.get("attributes", {}).get("inherited")
            ]
            if not drift_edges:
                return []
            name_map = _entity_name_map(entities)
            affected_targets = list({name_map.get(e.get("target_id"), e.get("target_id")) for e in drift_edges})
            return [RuleMatch(
                rule_id="ACL-009", rule_name="AdminSDHolder ACL Drift",
                finding_type="ADMINSDHOLDER_DRIFT", module="ACL Abuse",
                title=f"Non-admin accounts have dangerous direct ACEs on {len(affected_targets)} admin account(s)",
                description=(
                    "Non-privileged accounts have non-inherited GenericAll, WriteDACL, WriteOwner, or HAS_CONTROL "
                    "ACEs directly on protected (adminCount=1) accounts. AdminSDHolder should prevent this — "
                    "these explicit ACEs may indicate an ACL-based backdoor planted by an attacker."
                ),
                severity="HIGH", confidence=0.8,
                affected_objects=affected_targets[:20], affected_count=len(affected_targets),
                root_cause="Explicit non-inherited dangerous ACEs on AdminSDHolder-protected accounts for non-admin principals",
                causal_chain=[
                    "AdminSDHolder propagates restrictive ACLs to protected accounts hourly",
                    "An explicit (non-inherited) ACE can override AdminSDHolder propagation",
                    "Non-admin with write control over a protected admin account is a persistent backdoor",
                    "Attacker can reset DA password or add themselves to DA group at any time",
                ],
                remediation="Remove explicit dangerous ACEs on admin accounts; investigate how they were added",
                remediation_steps=[
                    "Identify explicit ACEs: (Get-Acl 'AD:\\<account>').Access | Where IsInherited -eq $false",
                    "Remove unauthorized explicit ACEs",
                    "Check AdminSDHolder template ACL for unauthorized entries",
                    "Enable Event ID 5136 auditing for changes to admin account ACLs",
                    "Investigate the account that set these ACEs — it may be compromised",
                ],
                fix_complexity="medium",
                references=["https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"],
                technical_severity=8.5, reachability=0.7,
                is_tier0_direct=True,
                mitre_attack_ids=["T1484"],
            )]

        self._reg(Rule("ACL-009", "AdminSDHolder ACL Drift", "ACL Abuse",
                       "Non-inherited dangerous ACEs on admin accounts", rule_adminsdholder_acl_drift))

        def rule_reversible_encryption(data):
            policy = data.get("password_policy", {})
            if not policy.get("reversible_encryption_enabled", False):
                return []
            entities = data.get("entities", [])
            affected_users = [
                e.get("sam_account_name") or e.get("display_name") or e.get("id", "")
                for e in entities
                if e.get("entity_type") in ("USER", "SERVICE_ACCOUNT")
                and e.get("is_enabled")
            ]
            return [RuleMatch(
                rule_id="PWD-006", rule_name="Reversible Encryption Enabled",
                finding_type="REVERSIBLE_ENCRYPTION_ENABLED", module="Password Policy",
                title="Domain password policy stores passwords with reversible encryption",
                description=(
                    "The domain policy has DOMAIN_PASSWORD_STORE_CLEARTEXT (pwdProperties 0x10) "
                    "enabled. Passwords are stored in a reversibly encrypted form, equivalent to "
                    "plaintext storage. Any process or account with read access to the "
                    "userPassword or supplementalCredentials attributes can recover plaintext passwords."
                ),
                severity="CRITICAL", confidence=1.0,
                affected_objects=["Default Domain Policy"] + affected_users[:10],
                affected_count=1 + len(affected_users),
                root_cause="pwdProperties has DOMAIN_PASSWORD_STORE_CLEARTEXT (0x10) bit set",
                causal_chain=[
                    "Reversible encryption stores the plaintext-equivalent of each user password",
                    "Any privileged process (LSA, replication) can retrieve plaintext passwords",
                    "Equivalent to storing plaintext passwords in Active Directory",
                    "Affects all user accounts subject to this policy",
                ],
                remediation="Disable reversible encryption in Default Domain Policy immediately",
                remediation_steps=[
                    "Open Group Policy Management Console (gpmc.msc)",
                    "Edit Default Domain Policy",
                    "Navigate to: Computer Configuration → Policies → Windows Settings → "
                    "Security Settings → Account Policies → Password Policy",
                    "Set 'Store passwords using reversible encryption' to Disabled",
                    "Force users to reset passwords so the reversibly-encrypted copies are overwritten",
                    "Run: 'gpupdate /force' on all domain controllers",
                ],
                fix_complexity="medium",
                references=[
                    "https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption",
                    "https://attack.mitre.org/techniques/T1003/",
                ],
                technical_severity=10.0, reachability=0.9,
                is_tier0_direct=True, on_crown_jewel_path=True,
                mitre_attack_ids=["T1003"],
            )]

        self._reg(Rule("PWD-006", "Reversible Encryption Enabled", "Password Policy",
                       "Domain policy stores passwords with reversible encryption",
                       rule_reversible_encryption))

        # ── Network Posture Rules ─────────────────────────────────────────────

        def rule_smb_signing_disabled(data):
            nc = data.get("network_config", {})
            if nc.get("smb_signing_required") is not False:
                return []
            hosts = nc.get("smb_signing_disabled_hosts", [])
            return [RuleMatch(
                rule_id="NET-001", rule_name="SMB Signing Disabled",
                finding_type="SMB_SIGNING_DISABLED", module="Network Posture",
                title="SMB signing not required — relay attacks possible",
                description=(
                    "SMB signing is not enforced on one or more hosts. An attacker with network "
                    "access can relay NTLM authentication (NTLM relay / NTLMRelayx) to authenticate "
                    "as the victim against other services without knowing the password."
                ),
                severity="CRITICAL", confidence=1.0,
                affected_objects=hosts or ["target host"], affected_count=len(hosts) or 1,
                root_cause="RequireSecuritySignature=0 on SMB server",
                causal_chain=[
                    "Unauthenticated SMB connections allowed without signing",
                    "Attacker intercepts NTLM authentication (via LLMNR/NBT-NS or ARP poisoning)",
                    "Relays captured hash to SMB/LDAP/HTTP service as victim",
                    "Full domain compromise possible if relayed account is privileged",
                ],
                remediation="Enforce SMB signing via GPO: Microsoft network server/client: Digitally sign communications (always)",
                remediation_steps=[
                    "GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options",
                    "Enable 'Microsoft network server: Digitally sign communications (always)'",
                    "Enable 'Microsoft network client: Digitally sign communications (always)'",
                    "Validate with: nmap -p445 --script smb2-security-mode <target>",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1557/001/"],
                technical_severity=9.5, reachability=0.9,
                mitre_attack_ids=["T1557", "T1557.001"],
            )]

        self._reg(Rule("NET-001", "SMB Signing Disabled", "Network Posture",
                       "SMB signing not required", rule_smb_signing_disabled))

        def rule_llmnr_enabled(data):
            nc = data.get("network_config", {})
            if not nc.get("llmnr_enabled"):
                return []
            return [RuleMatch(
                rule_id="NET-002", rule_name="LLMNR Enabled",
                finding_type="LLMNR_ENABLED", module="Network Posture",
                title="LLMNR active — credential capture via poisoning possible",
                description=(
                    "Link-Local Multicast Name Resolution (LLMNR) is active. Attackers on the same "
                    "broadcast segment can respond to LLMNR queries with a rogue IP, capturing "
                    "NTLMv2 hashes for offline cracking or relay attacks."
                ),
                severity="HIGH", confidence=0.9,
                affected_objects=nc.get("llmnr_hosts", ["network segment"]),
                affected_count=len(nc.get("llmnr_hosts", [])) or 1,
                root_cause="LLMNR enabled (port 5355/UDP reachable)",
                causal_chain=[
                    "Host broadcasts LLMNR query for unresolvable name",
                    "Attacker responds with rogue IP (Responder)",
                    "Victim authenticates to attacker, leaking NTLMv2 hash",
                    "Hash cracked offline or relayed to capture access",
                ],
                remediation="Disable LLMNR via GPO: Computer Configuration → Administrative Templates → Network → DNS Client → Turn off multicast name resolution",
                remediation_steps=[
                    "GPO path: Computer Configuration → Admin Templates → Network → DNS Client",
                    "Set 'Turn off multicast name resolution' to Enabled",
                    "Verify: reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient /v EnableMulticast",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1557/001/"],
                technical_severity=7.5, reachability=0.8,
                mitre_attack_ids=["T1557.001"],
            )]

        self._reg(Rule("NET-002", "LLMNR Enabled", "Network Posture",
                       "LLMNR multicast name resolution active", rule_llmnr_enabled))

        def rule_nbtns_enabled(data):
            nc = data.get("network_config", {})
            if not nc.get("nbtns_enabled"):
                return []
            return [RuleMatch(
                rule_id="NET-003", rule_name="NBT-NS Enabled",
                finding_type="NBTNS_ENABLED", module="Network Posture",
                title="NBT-NS active — legacy name resolution poisoning vector",
                description=(
                    "NetBIOS Name Service (NBT-NS) is active on the network. Like LLMNR, it can be "
                    "poisoned by an attacker to capture NTLMv2 credentials from hosts attempting "
                    "name resolution."
                ),
                severity="HIGH", confidence=0.9,
                affected_objects=nc.get("nbtns_hosts", ["network segment"]),
                affected_count=len(nc.get("nbtns_hosts", [])) or 1,
                root_cause="NBT-NS enabled (port 137/UDP reachable)",
                causal_chain=[
                    "Host broadcasts NBT-NS query for unresolvable name",
                    "Attacker poisons response with rogue IP",
                    "NTLMv2 hash captured for cracking or relay",
                ],
                remediation="Disable NBT-NS on all network adapters via DHCP option 001 or registry",
                remediation_steps=[
                    "Via DHCP: set option 001 (Microsoft disable NetBIOS) = 0x2",
                    "Via registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces\\<GUID> → NetbiosOptions = 2",
                    "Via PowerShell: Set-ItemProperty ... -Name NetbiosOptions -Value 2",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1557/001/"],
                technical_severity=7.0, reachability=0.8,
                mitre_attack_ids=["T1557.001"],
            )]

        self._reg(Rule("NET-003", "NBT-NS Enabled", "Network Posture",
                       "NetBIOS Name Service active", rule_nbtns_enabled))

        def rule_ntlm_downgrade(data):
            nc = data.get("network_config", {})
            ntlm_level = nc.get("ntlm_lm_compat_level")
            try:
                ntlm_int = int(ntlm_level)
            except (TypeError, ValueError):
                return []
            if ntlm_int >= 5:
                return []
            sev = "CRITICAL" if ntlm_int <= 2 else "HIGH"
            return [RuleMatch(
                rule_id="NET-004", rule_name="NTLM Downgrade Allowed",
                finding_type="NTLM_DOWNGRADE", module="Network Posture",
                title=f"LmCompatibilityLevel={ntlm_int} — NTLMv1/LM downgrade possible",
                description=(
                    f"LmCompatibilityLevel is set to {ntlm_int} (recommended: 5). "
                    "This permits NTLMv1 or LM authentication, which are trivially crackable "
                    "and enable pass-the-hash attacks. Level 5 enforces NTLMv2 only."
                ),
                severity=sev, confidence=1.0,
                affected_objects=[f"LmCompatibilityLevel={ntlm_int}"], affected_count=1,
                root_cause=f"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa LmCompatibilityLevel={ntlm_int}",
                causal_chain=[
                    f"LmCompatibilityLevel={ntlm_int} allows NTLMv1/LM responses",
                    "NTLMv1 hashes can be cracked with rainbow tables in seconds",
                    "Compromised hash enables pass-the-hash lateral movement",
                ],
                remediation="Set LmCompatibilityLevel=5 via GPO: Network security: LAN Manager authentication level → Send NTLMv2 response only/refuse LM & NTLM",
                remediation_steps=[
                    "GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options",
                    "Set 'Network security: LAN Manager authentication level' to 'Send NTLMv2 response only. Refuse LM & NTLM'",
                    "Verify: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1557/"],
                technical_severity=9.0 if ntlm_int <= 2 else 7.5,
                reachability=0.85,
                mitre_attack_ids=["T1557", "T1110"],
            )]

        self._reg(Rule("NET-004", "NTLM Downgrade Allowed", "Network Posture",
                       "LmCompatibilityLevel permits NTLMv1/LM", rule_ntlm_downgrade))

        def rule_ldap_signing_disabled(data):
            nc = data.get("network_config", {})
            ldap_sign = nc.get("ldap_signing")
            if ldap_sign not in ("none", "disabled", 0, "0"):
                return []
            return [RuleMatch(
                rule_id="NET-005", rule_name="LDAP Signing Disabled",
                finding_type="LDAP_SIGNING_DISABLED", module="Network Posture",
                title="LDAP signing not required on DC — LDAP relay possible",
                description=(
                    "LDAP signing is not enforced. Attackers can relay NTLM authentication "
                    "to LDAP on the domain controller to modify AD objects (add users to groups, "
                    "set RBCD, reset passwords) without SMB signing defenses applying."
                ),
                severity="HIGH", confidence=1.0,
                affected_objects=["Domain Controller LDAP"], affected_count=1,
                root_cause="LDAPServerIntegrity < 2 on domain controller",
                causal_chain=[
                    "NTLM auth relayed from victim to DC LDAP port 389",
                    "Attacker modifies AD objects as victim principal",
                    "Can add themselves to privileged groups or configure RBCD",
                ],
                remediation="Set LDAPServerIntegrity=2 on all DCs and enable LDAP channel binding",
                remediation_steps=[
                    "GPO: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options",
                    "Set 'Domain controller: LDAP server signing requirements' to 'Require signing'",
                    "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters LDAPServerIntegrity=2",
                    "Also enable LDAP Channel Binding via KB4520412",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1557/"],
                technical_severity=8.5, reachability=0.85,
                mitre_attack_ids=["T1557"],
            )]

        self._reg(Rule("NET-005", "LDAP Signing Disabled", "Network Posture",
                       "LDAP signing not required on DC", rule_ldap_signing_disabled))

        def rule_ldap_channel_binding_disabled(data):
            nc = data.get("network_config", {})
            if nc.get("ldap_channel_binding") is not False:
                return []
            return [RuleMatch(
                rule_id="NET-006", rule_name="LDAP Channel Binding Disabled",
                finding_type="LDAP_CHANNEL_BINDING_DISABLED", module="Network Posture",
                title="LDAP channel binding not enforced — cross-protocol relay risk",
                description=(
                    "LDAP channel binding (EPA) is not enforced. Combined with LDAPS, "
                    "channel binding prevents relay attacks from other protocols to LDAPS. "
                    "Without it, attackers can relay credentials from HTTP/SMB to LDAPS."
                ),
                severity="MEDIUM", confidence=0.9,
                affected_objects=["Domain Controller LDAPS"], affected_count=1,
                root_cause="LdapEnforceChannelBinding=0 or not configured",
                causal_chain=[
                    "NTLM auth from HTTP/SMB relayed to LDAPS without binding verification",
                    "Attacker modifies AD objects without physical channel validation",
                ],
                remediation="Enable LDAP channel binding via registry LdapEnforceChannelBinding=2 and apply KB4520412",
                remediation_steps=[
                    "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters LdapEnforceChannelBinding=2",
                    "Apply Microsoft KB4520412 / security update",
                    "Test client compatibility before enforcing",
                ],
                fix_complexity="low",
                references=["https://support.microsoft.com/en-us/topic/kb4520412"],
                technical_severity=6.5, reachability=0.7,
                mitre_attack_ids=["T1557"],
            )]

        self._reg(Rule("NET-006", "LDAP Channel Binding Disabled", "Network Posture",
                       "LDAP channel binding not enforced", rule_ldap_channel_binding_disabled))

        def rule_winrm_exposed(data):
            nc = data.get("network_config", {})
            if not nc.get("winrm_open"):
                return []
            hosts = nc.get("winrm_hosts", [])
            return [RuleMatch(
                rule_id="NET-007", rule_name="WinRM Exposed",
                finding_type="WINRM_EXPOSED", module="Network Posture",
                title="WinRM (5985/5986) reachable from network — remote management attack surface",
                description=(
                    "Windows Remote Management is accessible from the network. With valid credentials "
                    "(captured via phishing, spray, or relay), attackers gain interactive PowerShell "
                    "on the host via Evil-WinRM or Invoke-Command."
                ),
                severity="MEDIUM", confidence=1.0,
                affected_objects=hosts or ["target host"], affected_count=len(hosts) or 1,
                root_cause="WinRM service listening on 5985/5986 with no network restriction",
                causal_chain=[
                    "Attacker obtains valid credentials (spray/relay/phish)",
                    "Connects via WinRM to target — full PowerShell shell",
                    "Lateral movement and privilege escalation from shell",
                ],
                remediation="Restrict WinRM access via Windows Firewall to jump host IPs only; require HTTPS (5986)",
                remediation_steps=[
                    "Limit WinRM via firewall: New-NetFirewallRule -RemoteAddress <JumpHostIP>",
                    "Enforce HTTPS: winrm set winrm/config/listener?Address=*+Transport=HTTPS @{...}",
                    "Consider disabling WinRM on workstations if not needed",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1021/006/"],
                technical_severity=6.0, reachability=0.75,
                mitre_attack_ids=["T1021.006"],
            )]

        self._reg(Rule("NET-007", "WinRM Exposed", "Network Posture",
                       "WinRM reachable from network", rule_winrm_exposed))

        def rule_open_smb_shares(data):
            nc = data.get("network_config", {})
            shares = nc.get("open_shares", [])
            if not shares:
                return []
            return [RuleMatch(
                rule_id="NET-008", rule_name="Open SMB Shares",
                finding_type="OPEN_SMB_SHARES", module="Network Posture",
                title=f"{len(shares)} SMB share(s) accessible via null/guest session",
                description=(
                    "One or more SMB shares are readable by unauthenticated (null session) or "
                    "guest accounts. These may expose sensitive files, scripts, or credential "
                    "material to any host on the network."
                ),
                severity="HIGH", confidence=1.0,
                affected_objects=shares, affected_count=len(shares),
                root_cause="SMB share with null/guest read ACE",
                causal_chain=[
                    "Unauthenticated SMB client connects to share",
                    "Reads scripts, configs, or files containing credentials/hashes",
                    "Escalates using found material",
                ],
                remediation="Remove null/Everyone/Guest ACEs from all non-public SMB shares",
                remediation_steps=[
                    "Audit share permissions: Get-SmbShareAccess -Name <share>",
                    "Remove guest/everyone: Revoke-SmbShareAccess -Name <share> -AccountName Everyone",
                    "Disable null sessions: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa RestrictAnonymous=2",
                ],
                fix_complexity="low",
                references=["https://attack.mitre.org/techniques/T1135/"],
                technical_severity=7.0, reachability=0.9,
                mitre_attack_ids=["T1135"],
            )]

        self._reg(Rule("NET-008", "Open SMB Shares", "Network Posture",
                       "SMB shares accessible unauthenticated", rule_open_smb_shares))

        def rule_cred_manager_secrets(data):
            nc = data.get("network_config", {})
            entries = nc.get("cred_manager_entries", [])
            if not entries:
                return []
            return [RuleMatch(
                rule_id="NET-009", rule_name="Credential Manager Secrets",
                finding_type="CRED_MANAGER_SECRETS", module="Network Posture",
                title=f"Credential Manager contains {len(entries)} stored credential(s)",
                description=(
                    "Windows Credential Manager contains stored credentials. These can be dumped "
                    "by any process running as the user (DPAPI), or by attackers who gain local "
                    "admin access. Autologon entries in Winlogon may contain plaintext passwords."
                ),
                severity="HIGH", confidence=0.85,
                affected_objects=entries, affected_count=len(entries),
                root_cause="Credentials persisted in Windows Credential Manager or Winlogon registry keys",
                causal_chain=[
                    "User/service stored credentials in Credential Manager or Autologon",
                    "Local admin or SYSTEM can dump via cmdkey /list or DPAPI",
                    "Plaintext passwords retrievable from Winlogon AutoAdminLogon keys",
                ],
                remediation="Audit and purge Credential Manager entries; disable Autologon; use service accounts with gMSA",
                remediation_steps=[
                    "Audit: cmdkey /list",
                    "Remove entries: cmdkey /delete:<target>",
                    "Clear Winlogon autologon: reg delete HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v DefaultPassword",
                    "Replace stored service credentials with gMSA accounts",
                ],
                fix_complexity="medium",
                references=["https://attack.mitre.org/techniques/T1555/004/"],
                technical_severity=7.5, reachability=0.7,
                mitre_attack_ids=["T1555.004"],
            )]

        self._reg(Rule("NET-009", "Credential Manager Secrets", "Network Posture",
                       "Credentials stored in Windows Credential Manager", rule_cred_manager_secrets))
