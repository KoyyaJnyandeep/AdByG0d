#!/usr/bin/env python3
"""
AdByG0d — Password Posture Assessment Module v1.0

SCOPE: Read-only configuration and metadata analysis only.
This module detects password hygiene RISK INDICATORS using LDAP attribute
inspection and SYSVOL file metadata scanning.

DOES NOT: decrypt or display any credentials, passwords, or hashes.
DOES NOT: extract GPP plaintext passwords.
DOES NOT: read LAPS password values.
DOES NOT: perform password spraying or brute force of any kind.

If GPP XML files containing cpassword attributes are detected, the finding
reports their PRESENCE (a misconfiguration) — not the decrypted content.
Remediation is to delete the files and rotate affected accounts.

Authorized enterprise security assessment use only.
"""

import re
from datetime import datetime, timezone
from ..core.banner import (
    module_header, subsection, finding, info, success,
    warning, error, progress_bar
)
from ..core.ldap_values import int_value


class PasswordModule:
    """Password posture assessment — read-only hygiene analysis."""

    NAME = "Password Hygiene"
    DESCRIPTION = (
        "Read-only password posture: policy gaps, stale accounts, "
        "credential exposure indicators, reversible encryption, pre-auth gaps. "
        "No credentials are extracted, decrypted, or displayed."
    )

    def __init__(self, connector, reporter):
        self.conn = connector
        self.reporter = reporter

    def run(self):
        module_header(self.NAME, self.DESCRIPTION)
        checks = [
            ("Password Policy Analysis",            self.check_password_policy),
            ("GPP Credential File Presence",        self.check_gpp_file_presence),
            ("Credentials in Description Fields",   self.check_description_creds),
            ("Accounts with Password Not Required", self.check_passwd_not_required),
            ("Password Age Distribution",           self.check_password_age),
            ("Never-Expiring Privileged Passwords", self.check_nonexpiring_privileged),
            ("Reversible Encryption Enabled",       self.check_reversible_encryption),
            ("LAPS Deployment Coverage",            self.check_laps_coverage),
        ]
        for i, (name, func) in enumerate(checks):
            progress_bar(i, len(checks), label=name)
            try:
                func()
            except Exception as e:
                error(f"  {name} failed: {e}")
        progress_bar(len(checks), len(checks), label="Complete")
        self.reporter.modules_run.append(self.NAME)

    # ── Password Policy ────────────────────────────────────────────

    def check_password_policy(self):
        subsection("Domain Password Policy")
        entries = self.conn.ldap_search(
            "(objectClass=domainDNS)",
            ["minPwdLength", "lockoutThreshold", "lockoutDuration",
             "maxPwdAge", "pwdHistoryLength", "pwdProperties"]
        )
        if not entries:
            warning("Could not retrieve domain password policy")
            return

        entry = entries[0]
        min_len       = int_value(entry.get('minPwdLength'), 7)
        lockout_thr   = int_value(entry.get('lockoutThreshold'), 0)
        history_count = int_value(entry.get('pwdHistoryLength'), 0)
        pwd_props     = int_value(entry.get('pwdProperties'), 0)
        reversible    = bool(pwd_props & 0x10)

        policy = {
            "min_length": min_len,
            "lockout_threshold": lockout_thr,
            "history_count": history_count,
            "complexity_required": bool(pwd_props & 0x1),
            "reversible_encryption": reversible,
        }

        info(f"Min length: {min_len}  Lockout threshold: {lockout_thr}  "
             f"History: {history_count}  Complexity: {bool(pwd_props & 0x1)}")

        if lockout_thr == 0:
            finding("CRITICAL", "Account lockout is NOT configured (lockoutThreshold = 0)")
            self.reporter.add(
                self.NAME, "CRITICAL",
                "No account lockout policy configured",
                "With lockoutThreshold = 0, accounts are never locked regardless of failed "
                "authentication attempts. This permits unlimited password spraying and brute "
                "force attacks against all domain accounts without generating lockout events. "
                "Combined with common password reuse patterns, this typically leads to "
                "widespread credential compromise within hours of an attack.",
                details=policy,
                affected=["Default Domain Policy"],
                remediation=(
                    "Set Account Lockout Threshold to ≤ 10 invalid attempts. "
                    "Set Account Lockout Duration to ≥ 15 minutes. "
                    "Set Reset lockout counter after ≥ 15 minutes. "
                    "Consider Fine-Grained Password Policies (PSO) for service accounts "
                    "that cannot tolerate lockout."
                ),
            )

        if min_len < 12:
            sev = "HIGH" if min_len < 8 else "MEDIUM"
            self.reporter.add(
                self.NAME, sev,
                f"Minimum password length is only {min_len} characters",
                f"NIST SP 800-63B and CIS Benchmark recommend a minimum of 14 characters. "
                f"At {min_len} characters, accounts are susceptible to fast offline cracking "
                "if NTLM hashes are obtained.",
                details={"min_length": min_len, "recommended": 14},
                affected=["Default Domain Policy"],
                remediation="Increase minimum password length to 14 characters.",
            )

        if reversible:
            self.reporter.add(
                self.NAME, "HIGH",
                "Reversible password encryption is enabled in domain policy",
                "Reversible encryption stores passwords in a form recoverable by domain admins, "
                "effectively storing cleartext passwords in the directory. This is equivalent to "
                "storing plaintext and should only be used when required by specific applications.",
                affected=["Default Domain Policy"],
                remediation=(
                    "Disable reversible encryption in domain password policy. "
                    "Reset passwords of all affected accounts after the policy change."
                ),
            )

    # ── GPP File Presence ──────────────────────────────────────────

    def check_gpp_file_presence(self):
        """
        Detect PRESENCE of GPP XML files that may contain cpassword attributes.
        Reports the misconfiguration (files should not exist) WITHOUT reading
        or decrypting any credential values.
        """
        subsection("GPP Credential File Presence (MS14-025 Indicator)")
        if not self.conn.smb_conn:
            info("SMB connection not available — skipping GPP file presence check")
            return

        gpp_filenames = [
            "Groups.xml", "Services.xml", "ScheduledTasks.xml",
            "DataSources.xml", "Printers.xml", "Drives.xml"
        ]

        gpp_paths_found = []

        try:
            base_path = f"\\{self.conn.domain}\\Policies\\"
            try:
                policies = self.conn.smb_conn.listPath("SYSVOL", base_path + "*")
            except Exception:
                info("Could not enumerate SYSVOL — skipping GPP file check")
                return

            for policy in policies:
                pol_name = policy.get_longname()
                if pol_name in ('.', '..') or not policy.is_directory():
                    continue

                for context in ["Machine", "User"]:
                    for fname in gpp_filenames:
                        for pref_dir in ["Groups", "Services", "ScheduledTasks",
                                         "DataSources", "Printers", "Drives"]:
                            path = (f"{base_path}{pol_name}\\{context}\\"
                                    f"Preferences\\{pref_dir}\\{fname}")
                            try:
                                files = self.conn.smb_conn.listPath(
                                    "SYSVOL", path.rsplit("\\", 1)[0] + "\\*"
                                )
                                for f in files:
                                    if f.get_longname().lower() == fname.lower():
                                        # File exists — check if it contains cpassword
                                        # by looking at file size (empty files have no creds)
                                        size = f.get_filesize()
                                        if size > 100:  # Non-trivial file
                                            gpp_paths_found.append(
                                                f"{pol_name}\\{context}\\{fname} ({size} bytes)"
                                            )
                            except Exception:
                                continue
        except Exception as e:
            error(f"GPP scan error: {e}")
            return

        if gpp_paths_found:
            finding("HIGH",
                    f"Found {len(gpp_paths_found)} GPP preference file(s) in SYSVOL "
                    "(may contain encrypted credentials — MS14-025)")
            self.reporter.add(
                self.NAME, "HIGH",
                f"{len(gpp_paths_found)} Group Policy Preference files detected in SYSVOL",
                "Group Policy Preferences XML files (Groups.xml, Services.xml, etc.) "
                "sometimes contain 'cpassword' attributes — passwords encrypted with a "
                "publicly known AES key (MS14-025, published by Microsoft in 2014). "
                "Any domain user can read SYSVOL and any tool aware of the key can recover "
                "the plaintext password. These files should be removed and affected accounts rotated.\n"
                f"Files found: {', '.join(gpp_paths_found[:10])}",
                affected=gpp_paths_found[:50],
                remediation=(
                    "1. Identify all GPP files with cpassword: Get-GPPPassword (PowerSploit) or "
                    "manual SYSVOL review. "
                    "2. Remove all GPP files containing cpassword. "
                    "3. Rotate credentials for any accounts referenced in those files. "
                    "4. Use LAPS for local admin password management going forward. "
                    "5. GPP password functionality was removed in MS14-025 — do not re-create."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025",
                ],
            )
        else:
            success("No GPP preference files detected in SYSVOL")

    # ── Credentials in description fields ─────────────────────────

    def check_description_creds(self):
        subsection("Credentials in Description/Info Fields")
        # Look for common password keyword patterns in description fields
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)"
            "(description=*))",
            ["sAMAccountName", "description"]
        )

        suspicious_patterns = re.compile(
            r'(password|passwd|pwd|pass|secret|cred|login|p@ss|temp)',
            re.IGNORECASE
        )

        suspicious = []
        for entry in entries:
            desc = str(entry.description) if hasattr(entry, 'description') else ''
            if suspicious_patterns.search(desc):
                sam = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "?"
                # Redact: report the account name, not the description content
                suspicious.append(sam)

        if suspicious:
            finding("HIGH", f"{len(suspicious)} accounts have password-related keywords "
                    "in description/info fields")
            self.reporter.add(
                self.NAME, "HIGH",
                f"{len(suspicious)} accounts have credential keywords in description fields",
                "Account description or info attributes contain keywords suggesting passwords "
                "are stored in plaintext in the directory. Description fields are readable by "
                "all authenticated domain users and are a common source of credential exposure.",
                affected=suspicious[:50],
                remediation=(
                    "Review description fields for the listed accounts and remove any credentials. "
                    "Rotate any passwords that may have been exposed. "
                    "Implement a policy prohibiting storage of credentials in directory attributes."
                ),
            )
        else:
            success("No credential keywords found in description fields")

    # ── Password Not Required ──────────────────────────────────────

    def check_passwd_not_required(self):
        subsection("Accounts with PASSWD_NOTREQD Flag")
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=32)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "adminCount"]
        )
        if not entries:
            success("No accounts with PASSWD_NOTREQD flag found")
            return
        affected = [str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')]
        privileged = [n for n in affected
                      if any(hasattr(e, 'adminCount') and str(e.adminCount) == '1'
                             and str(e.sAMAccountName) == n for e in entries)]
        sev = "CRITICAL" if privileged else "HIGH"
        self.reporter.add(
            self.NAME, sev,
            f"{len(entries)} accounts have PASSWD_NOTREQD flag set",
            "The PASSWD_NOTREQD UAC flag allows accounts to have empty or trivial passwords "
            "regardless of the domain password policy. This can result in accounts authenticating "
            "with empty passwords, bypassing complexity requirements.",
            details={"total": len(entries), "privileged": len(privileged)},
            affected=affected,
            remediation=(
                "Clear the flag: Set-ADUser <user> -PasswordNotRequired $false. "
                "Force password reset for all affected accounts. "
                "Audit: Get-ADUser -Filter {PasswordNotRequired -eq $true}"
            ),
        )

    # ── Password Age ───────────────────────────────────────────────

    def check_password_age(self):
        subsection("Password Age Distribution")
        # Privileged accounts with passwords older than 180 days
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(adminCount=1)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "pwdLastSet"]
        )
        stale_180, stale_365 = [], []
        for entry in entries:
            age = self._pwd_age_days(entry.get('pwdLastSet'))
            sam = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "?"
            if age > 365:
                stale_365.append(sam)
            elif age > 180:
                stale_180.append(sam)

        if stale_365:
            self.reporter.add(
                self.NAME, "HIGH",
                f"{len(stale_365)} privileged accounts have passwords older than 365 days",
                "Privileged accounts with stale passwords present elevated risk — a password "
                "that has been in use for over a year is more likely to have been exposed "
                "through phishing, breach correlation, or offline cracking.",
                affected=stale_365[:50],
                remediation="Enforce maximum password age of 180 days for privileged accounts.",
            )
        if stale_180:
            self.reporter.add(
                self.NAME, "MEDIUM",
                f"{len(stale_180)} privileged accounts have passwords between 180–365 days old",
                "Privileged account passwords should be rotated at least every 180 days.",
                affected=stale_180[:50],
                remediation="Implement a password rotation schedule for all privileged accounts.",
            )

    # ── Never-expiring privileged passwords ───────────────────────

    def check_nonexpiring_privileged(self):
        subsection("Non-Expiring Passwords on Privileged Accounts")
        # DONT_EXPIRE_PASSWORD = 0x10000
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(adminCount=1)"
            "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"]
        )
        if not entries:
            return
        affected = [str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')]
        self.reporter.add(
            self.NAME, "HIGH",
            f"{len(affected)} privileged accounts have passwords set to never expire",
            "Privileged accounts with non-expiring passwords may carry the same password "
            "for years, increasing the window of opportunity if the password is ever exposed. "
            "This is commonly seen on legacy service accounts and break-glass accounts.",
            affected=affected,
            remediation=(
                "Remove DONT_EXPIRE_PASSWORD from privileged accounts and enforce password age policy. "
                "For break-glass accounts, use a documented manual rotation process."
            ),
        )

    # ── Reversible encryption ──────────────────────────────────────

    def check_reversible_encryption(self):
        """Check for accounts with reversible encryption enabled at account level."""
        subsection("Reversible Encryption — Account Level")
        # ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=128)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"]
        )
        if not entries:
            return
        affected = [str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')]
        self.reporter.add(
            self.NAME, "HIGH",
            f"{len(affected)} accounts have reversible password encryption enabled",
            "Reversible encryption stores a form of the cleartext password. "
            "A privileged attacker or DCSync access can recover these passwords.",
            affected=affected,
            remediation=(
                "Disable reversible encryption per-account and via policy. "
                "Reset passwords for all affected accounts after the change."
            ),
        )

    # ── LAPS coverage ──────────────────────────────────────────────

    def check_laps_coverage(self):
        subsection("LAPS Deployment Coverage")
        # Coverage can be measured from expiration metadata; do not request password values.
        computers = self.conn.ldap_search(
            "(&(objectCategory=computer)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))"  # not DCs
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"]
        )
        total = len(computers)
        if total == 0:
            return

        laps_managed = sum(
            1 for e in computers
            if (hasattr(e, 'ms-Mcs-AdmPwdExpirationTime')
                and str(e['ms-Mcs-AdmPwdExpirationTime']) not in ('', '[]', 'None'))
            or (hasattr(e, 'msLAPS-PasswordExpirationTime')
                and str(e['msLAPS-PasswordExpirationTime']) not in ('', '[]', 'None'))
        )
        coverage_pct = round((laps_managed / total) * 100, 1) if total else 0

        info(f"LAPS coverage: {laps_managed}/{total} computers ({coverage_pct}%)")

        if coverage_pct < 50:
            sev = "HIGH"
        elif coverage_pct < 90:
            sev = "MEDIUM"
        else:
            success(f"LAPS coverage is {coverage_pct}% — good posture")
            return

        self.reporter.add(
            self.NAME, sev,
            f"LAPS covers only {coverage_pct}% of non-DC computers ({laps_managed}/{total})",
            "Without LAPS, workstations and servers likely share the same local administrator "
            "password. Compromising one machine exposes the credential that unlocks all others, "
            "enabling rapid lateral movement across the environment.",
            details={"total_computers": total, "laps_managed": laps_managed,
                     "coverage_pct": coverage_pct},
            affected=[str(e.sAMAccountName) for e in computers
                      if not ((hasattr(e, 'ms-Mcs-AdmPwdExpirationTime')
                               and str(e['ms-Mcs-AdmPwdExpirationTime']) not in ('', '[]', 'None'))
                              or (hasattr(e, 'msLAPS-PasswordExpirationTime')
                                  and str(e['msLAPS-PasswordExpirationTime']) not in ('', '[]', 'None')))][:50],
            remediation=(
                "Deploy Windows LAPS (native in Windows 2022/11 22H2+): Update-LapsADSchema. "
                "Configure via GPO: Computer Configuration > Administrative Templates > LAPS. "
                "Recommended: 20-character passwords, 30-day rotation."
            ),
        )

    # ── Helpers ────────────────────────────────────────────────────

    def _pwd_age_days(self, raw_val) -> int:
        if not raw_val or str(raw_val) in ('0', '[]', 'None'):
            return 0
        try:
            ts = int_value(raw_val, 0)
            if ts <= 0:
                return 0
            epoch = (ts / 10_000_000) - 11_644_473_600
            return int((datetime.now(timezone.utc).timestamp() - epoch) / 86400)
        except (ValueError, OverflowError):
            return 0
