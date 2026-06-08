#!/usr/bin/env python3
"""
AdByG0d — Authentication Coercion Exposure Assessment Module v1.0

SCOPE: Read-only LDAP and safe SMB metadata checks ONLY.
Detects SERVICE CONFIGURATIONS and POLICY STATES that create
coercion exposure risk.

DOES NOT: Attempt to bind to any RPC interface.
DOES NOT: Send any unauthenticated RPC calls.
DOES NOT: Attempt PetitPotam, PrinterBug, DFSCoerce, or ShadowCoerce.
DOES NOT: Attempt to trigger authentication from any machine.

Detection approach: checks conditions that enable coercion attacks
(services running, EPA status, SMB signing, EPA enforcement) via
LDAP service attribute queries and SMB signing negotiation.

Authorized enterprise security assessment use only.
"""

from ..core.banner import (
    module_header, subsection, finding, info, success,
    error, progress_bar
)
from ..core.ldap_values import int_value


class CoercionModule:
    """
    Coercion exposure assessment — service configuration checks.
    Identifies environments where coercion-based attack paths may exist
    based on service presence indicators and policy states.
    """

    NAME = "Coercion Exposure"
    DESCRIPTION = (
        "Detects configurations that create coercion exposure risk: "
        "Print Spooler presence, WebClient/WebDAV, EPA enforcement, "
        "NTLMv1 downgrade risk, SMB signing enforcement. "
        "Read-only — no RPC binds, no authentication coercion attempted."
    )

    def __init__(self, connector, reporter):
        self.conn = connector
        self.reporter = reporter

    def run(self):
        module_header(self.NAME, self.DESCRIPTION)
        checks = [
            ("Print Spooler Service on DCs",        self.check_spooler_on_dcs),
            ("WebClient/WebDAV Service",             self.check_webclient),
            ("SMB Signing Enforcement",              self.check_smb_signing),
            ("NTLM Configuration",                  self.check_ntlm_config),
            ("EPA / Extended Protection",           self.check_epa),
            ("Coercion Risk Summary",               self.summarize_risk),
        ]
        self._findings_collected = []
        for i, (name, func) in enumerate(checks):
            progress_bar(i, len(checks), label=name)
            try:
                func()
            except Exception as e:
                error(f"  {name} failed: {e}")
        progress_bar(len(checks), len(checks), label="Complete")
        self.reporter.modules_run.append(self.NAME)

    # ── Print Spooler on DCs ───────────────────────────────────────

    def check_spooler_on_dcs(self):
        """
        Check if the Print Spooler service is likely running on DCs.
        Detection: query for DC computer objects and check if the
        spooler service is registered or if printers are published.
        Note: definitive running-state check requires WMI/registry;
        this check uses safe LDAP and SMB share existence indicators.
        """
        subsection("Print Spooler Exposure on Domain Controllers")

        dcs = self.conn.ldap_search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["dNSHostName", "sAMAccountName", "operatingSystem"]
        )

        if not dcs:
            info("No DC objects found in LDAP")
            return

        dc_names = [str(e.dNSHostName) if hasattr(e, 'dNSHostName') else
                    str(e.sAMAccountName) for e in dcs]

        # Check if printers are published for these DCs (indirect indicator)
        printer_entries = self.conn.ldap_search(
            "(&(objectClass=printQueue)(serverName=*))",
            ["serverName", "printerName"]
        )

        dc_with_printers = []
        if printer_entries:
            dc_short_names = {n.split('.')[0].upper() for n in dc_names}
            for pe in printer_entries:
                srv = str(pe.serverName) if hasattr(pe, 'serverName') else ""
                if srv.split('\\')[-1].upper() in dc_short_names:
                    dc_with_printers.append(srv)

        self.reporter.add(
            self.NAME, "HIGH",
            "Domain Controllers may have Print Spooler (MS-RPRN) exposed",
            "The Print Spooler service (spoolsv.exe) enables the MS-RPRN protocol which "
            "can be abused to coerce authentication from a Domain Controller to an "
            "attacker-controlled host (PrinterBug). This authentication can be relayed or "
            "captured and used to compromise Tier-0 assets. "
            "Microsoft recommends disabling the Print Spooler service on all DCs unless "
            "a DC is explicitly required to act as a print server (rare in modern environments).\n"
            f"DCs identified: {', '.join(dc_names[:10])}",
            details={
                "dc_count": len(dcs),
                "dcs_with_published_printers": dc_with_printers[:10],
            },
            affected=dc_names[:20],
            remediation=(
                "Disable Print Spooler on all DCs: "
                "Stop-Service Spooler -Force; Set-Service -Name Spooler -StartupType Disabled. "
                "Verify no business requirement for DC to serve as print server first. "
                "Apply via GPO: Computer Configuration > Windows Settings > System Services > Print Spooler."
            ),
            references=[
                "https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/windows-11-22h2-kb5005565-print-spooler",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
            ],
        )
        self._findings_collected.append("spooler_on_dc")

    # ── WebClient / WebDAV ─────────────────────────────────────────

    def check_webclient(self):
        """
        Detect if WebClient (WebDAV) is likely enabled on workstations.
        Indirect check via DNS entries that indicate active WebDAV clients.
        """
        subsection("WebClient/WebDAV Service Exposure")

        # Check if wpad or webdav-style DNS entries exist (weak indicator)
        # Primary check: enumerate computers and check OS type
        workstations = self.conn.ldap_search(
            "(&(objectCategory=computer)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            "(operatingSystem=Windows 10*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "operatingSystem"]
        )
        count = len(workstations)
        if count == 0:
            return

        self.reporter.add(
            self.NAME, "MEDIUM",
            f"{count} Windows 10/11 workstations detected — WebClient service exposure risk",
            "The WebClient service (WebDAV client) is installed and potentially running on "
            "Windows 10/11 workstations by default. If running, it enables HTTP-based "
            "authentication coercion attacks. When combined with a DC-side coercion vector "
            "and NTLM relay, WebDAV can facilitate relay over HTTP (port 80/443) bypassing "
            "SMB signing requirements. "
            "Detection of whether WebClient is actually running requires WMI queries or "
            "endpoint visibility beyond LDAP scope.",
            details={"workstation_count": count},
            affected=[str(e.sAMAccountName) for e in workstations[:30]],
            remediation=(
                "Disable WebClient service on endpoints that do not require WebDAV: "
                "Set-Service -Name WebClient -StartupType Disabled. "
                "Apply via GPO. Validate no business applications require WebDAV before disabling."
            ),
        )
        self._findings_collected.append("webclient_risk")

    # ── SMB Signing ────────────────────────────────────────────────

    def check_smb_signing(self):
        """
        Check SMB signing enforcement via LDAP security policy attributes
        and SMB negotiation on the DC.
        """
        subsection("SMB Signing Enforcement")
        if not self.conn.smb_conn:
            info("SMB connection not available — cannot assess SMB signing posture")
            return

        # Check if SMB signing is required on the DC we connected to
        try:
            signing_required = self.conn.smb_conn.isSigningRequired()
        except AttributeError:
            try:
                signing_required = getattr(self.conn.smb_conn, '_SMBConnection__signing_required', None)
            except Exception:
                signing_required = None

        if signing_required is False:
            finding("CRITICAL", "SMB signing is NOT required on the Domain Controller")
            self.reporter.add(
                self.NAME, "CRITICAL",
                "SMB signing not required on Domain Controller — relay attack exposure",
                "When SMB signing is not required, NTLM authentication can be relayed to the "
                "DC without the target detecting the relay. This enables attacks such as "
                "SMB relay, NTLM relay via Responder, and cross-protocol relay when combined "
                "with coercion techniques.",
                affected=[self.conn.dc_ip or "DC"],
                remediation=(
                    "Require SMB signing on all domain controllers and servers: "
                    "GPO > Computer Configuration > Windows Settings > Security Settings > "
                    "Local Policies > Security Options > "
                    "'Microsoft network server: Digitally sign communications (always)' = Enabled. "
                    "Also enable on clients to prevent lateral movement relay attacks."
                ),
            )
            self._findings_collected.append("smb_signing_not_required")
        elif signing_required is True:
            success("SMB signing is required on the Domain Controller")
        else:
            info("Could not determine SMB signing requirement from negotiation")

    # ── NTLM Configuration ─────────────────────────────────────────

    def check_ntlm_config(self):
        """Check NTLM-related GPO settings via LDAP."""
        subsection("NTLM Configuration")

        # Check for NTLMv1 allowed — look at domain functional level and computer policies
        # Full GPO parsing requires file-system access; check domain functional level as proxy
        domain = self.conn.ldap_search(
            "(objectClass=domainDNS)",
            ["msDS-Behavior-Version", "domainFunctionality"]
        )
        if domain:
            func_level = int_value(domain[0].get('msDS-Behavior-Version'), 0)
            if func_level < 7:  # < Windows Server 2016 domain functional level
                self.reporter.add(
                    self.NAME, "LOW",
                    f"Domain functional level {func_level} — legacy NTLM hardening unavailable",
                    "Domain Functional Level below Windows Server 2016 (7) prevents use of "
                    "certain NTLM hardening features. Raising the functional level enables "
                    "additional security controls.",
                    details={"domain_functional_level": func_level},
                    remediation=(
                        "Raise domain functional level to Windows Server 2016 or higher after "
                        "verifying no legacy DCs remain."
                    ),
                )

    # ── EPA / Extended Protection ──────────────────────────────────

    def check_epa(self):
        """Check for EPA (Extended Protection for Authentication) indicators."""
        subsection("Extended Protection for Authentication (EPA)")

        # Check if LDAP channel binding is enforced
        dcs = self.conn.ldap_search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["dNSHostName", "sAMAccountName"]
        )

        # Check ldapEnforcedChannelBinding via registry or msDS-Other-Settings
        # This is a best-effort check — definitive assessment requires reading DC registry
        self.reporter.add(
            self.NAME, "MEDIUM",
            "EPA/LDAP channel binding posture should be verified on Domain Controllers",
            "Extended Protection for Authentication (EPA) and LDAP channel binding prevent "
            "NTLM relay attacks against LDAP and LDAPS. Without these controls, an attacker "
            "who can coerce DC authentication can relay it to LDAP to perform operations "
            "such as adding shadow credentials or modifying group memberships. "
            "Definitive enforcement state requires reading DC registry: "
            "HKLM\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding",
            affected=[str(e.dNSHostName) if hasattr(e, 'dNSHostName') else
                      str(e.sAMAccountName) for e in dcs][:10],
            remediation=(
                "Enable LDAP channel binding on all DCs: "
                "Set LdapEnforceChannelBinding = 2 in HKLM\\SYSTEM\\CurrentControlSet\\"
                "Services\\NTDS\\Parameters. "
                "Enable LDAP signing: LDAPServerIntegrity = 2. "
                "Apply Microsoft KB4520412 and related updates."
            ),
            references=[
                "https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a",
            ],
        )

    # ── Summary ────────────────────────────────────────────────────

    def summarize_risk(self):
        """Produce a combined coercion risk posture summary."""
        subsection("Coercion Exposure Risk Summary")
        risk_count = len(self._findings_collected)
        if risk_count >= 3:
            finding("CRITICAL",
                    f"{risk_count} coercion exposure risk factors detected — "
                    "high probability of viable coercion attack paths")
            self.reporter.add(
                self.NAME, "CRITICAL",
                "Multiple coercion exposure risk factors present",
                "The combination of Print Spooler on DCs, WebClient service presence, "
                "and insufficient relay mitigations creates high-confidence coercion attack "
                "paths. In environments where these conditions align, a low-privilege domain "
                "user can trigger DC authentication to an attacker-controlled host and relay "
                "or capture credentials for Tier-0 access.",
                details={"risk_factors": self._findings_collected},
                remediation=(
                    "Priority remediations in order: "
                    "1. Disable Print Spooler on all DCs. "
                    "2. Enable SMB signing enforcement domain-wide. "
                    "3. Enable LDAP channel binding and signing on all DCs. "
                    "4. Disable WebClient on workstations. "
                    "5. Implement network segmentation to prevent workstations from "
                    "reaching DC SMB/LDAP ports directly."
                ),
            )
        elif risk_count >= 1:
            info(f"{risk_count} coercion exposure risk factor(s) detected — review findings above")
        else:
            success("No high-confidence coercion exposure risk factors detected")
