#!/usr/bin/env python3
"""
AdByG0d — Kerberos Posture Assessment Module v1.0

SCOPE: Read-only LDAP attribute analysis only.
Detects Kerberos misconfiguration risk — does NOT request tickets,
extract hashes, perform AS-REQ/TGS-REQ operations, or write any files.

Authorized enterprise security assessment use only.
"""

from datetime import datetime, timezone
from ..core.banner import (
    module_header, subsection, finding, info, success,
    error, print_table, progress_bar
)
from ..core.ldap_values import first_value, int_value


class KerberosModule:
    """Kerberos posture assessment — read-only configuration analysis."""

    NAME = "Kerberos"
    DESCRIPTION = (
        "Read-only posture checks: roastable account configurations, "
        "delegation exposure, encryption weaknesses, pre-auth gaps, "
        "Protected Users coverage, krbtgt hygiene."
    )

    def __init__(self, connector, reporter):
        self.conn = connector
        self.reporter = reporter

    def run(self):
        module_header(self.NAME, self.DESCRIPTION)
        checks = [
            ("Kerberoastable Account Posture",       self.assess_kerberoastable),
            ("AS-REP Roastable Account Posture",      self.assess_asrep_roastable),
            ("Kerberos Encryption Posture",           self.assess_encryption),
            ("Unconstrained Delegation",              self.assess_unconstrained_delegation),
            ("Constrained Delegation",                self.assess_constrained_delegation),
            ("Resource-Based Constrained Delegation", self.assess_rbcd),
            ("Protected Users Group Coverage",        self.assess_protected_users),
            ("krbtgt Account Hygiene",                self.assess_krbtgt),
        ]
        for i, (name, func) in enumerate(checks):
            progress_bar(i, len(checks), label=name)
            try:
                func()
            except Exception as e:
                error(f"  {name} failed: {e}")
        progress_bar(len(checks), len(checks), label="Complete")
        self.reporter.modules_run.append(self.NAME)

    # ── Kerberoastable detection ───────────────────────────────────

    def assess_kerberoastable(self):
        subsection("Kerberoastable Account Posture")
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)"
            "(servicePrincipalName=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(!(objectCategory=computer)))",
            ["sAMAccountName", "servicePrincipalName", "adminCount",
             "pwdLastSet", "msDS-SupportedEncryptionTypes"]
        )
        if not entries:
            success("No Kerberoastable user accounts found")
            return

        rows, high_value, rc4_accounts, stale_passwords = [], [], [], []
        for entry in entries:
            sam  = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "N/A"
            spns = list(entry.servicePrincipalName) if hasattr(entry, 'servicePrincipalName') else []
            is_admin = hasattr(entry, 'adminCount') and str(entry.adminCount) == '1'
            enc_raw = entry.get('msDS-SupportedEncryptionTypes')
            enc_val = int_value(enc_raw, 0)
            uses_rc4 = (enc_val == 0) or bool(enc_val & 0x4)
            pwd_age_label = self._pwd_age_label(entry.get('pwdLastSet'))
            if ">" in pwd_age_label and "365" in pwd_age_label or self._pwd_age_days(entry.get('pwdLastSet')) > 365:
                stale_passwords.append(sam)
            if is_admin:
                high_value.append(sam)
            if uses_rc4:
                rc4_accounts.append(sam)
            rows.append([sam, str(spns[0])[:50] if spns else "N/A",
                         "Yes" if is_admin else "No",
                         "RC4 (weak)" if uses_rc4 else "AES",
                         pwd_age_label])

        print_table(["Account", "Primary SPN", "AdminCount", "Encryption", "Pwd Age"],
                    rows[:30], f"Kerberoastable Accounts ({len(entries)} total)")

        affected = [str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')]
        sev = "CRITICAL" if high_value else "HIGH"

        self.reporter.add(
            self.NAME, sev,
            f"{len(entries)} Kerberoastable service accounts detected",
            "Service accounts with registered SPNs expose Kerberos service tickets to any "
            "authenticated domain user. An attacker can request these tickets and perform "
            "offline password attacks at full GPU speed without generating authentication "
            f"failure events. RC4 encryption ({len(rc4_accounts)} accounts) significantly "
            f"accelerates cracking. Stale passwords ({len(stale_passwords)} accounts over 1 year) "
            "increase the probability of successful compromise.",
            details={
                "total_kerberoastable": len(entries),
                "admincount_1": len(high_value),
                "rc4_encryption": len(rc4_accounts),
                "password_stale_365d": len(stale_passwords),
            },
            affected=affected,
            remediation=(
                "Migrate service accounts to Group Managed Service Accounts (gMSA). "
                "For accounts that cannot use gMSA, set passwords to 25+ random characters. "
                "Enforce AES-only: Set-ADUser <sam> -KerberosEncryptionType AES128,AES256. "
                "Remove unnecessary SPNs. Audit SPN assignments quarterly."
            ),
            references=[
                "https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/",
            ],
        )
        if high_value:
            self.reporter.add(
                self.NAME, "CRITICAL",
                "Privileged accounts are Kerberoastable (AdminCount=1)",
                "These accounts held or hold high-privilege group memberships. "
                "Offline password guessing on their service tickets yields privileged access.",
                affected=high_value,
                remediation="Immediately migrate to gMSA or set 25+ character random passwords.",
            )

    # ── AS-REP Roastable ───────────────────────────────────────────

    def assess_asrep_roastable(self):
        subsection("AS-REP Roastable Account Posture")
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "adminCount"]
        )
        if not entries:
            success("No AS-REP Roastable accounts found")
            return
        affected = [str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')]
        high_value = [n for n in affected
                      if any(hasattr(e, 'adminCount') and str(e.adminCount) == '1'
                             and str(e.sAMAccountName) == n for e in entries)]
        sev = "CRITICAL" if high_value else "HIGH"
        finding(sev, f"{len(entries)} accounts have Kerberos pre-authentication disabled")
        self.reporter.add(
            self.NAME, sev,
            f"{len(entries)} accounts vulnerable to AS-REP Roasting (pre-auth disabled)",
            "Accounts with DONT_REQUIRE_PREAUTH allow unauthenticated parties to request "
            "an AS-REP response encrypted with the account's password hash. "
            "This enables offline password guessing with zero domain credentials required — "
            "the attack is undetectable without specific AS-REP monitoring.",
            details={"total": len(entries), "with_admincount": len(high_value)},
            affected=affected,
            remediation=(
                "Enable pre-authentication for all affected accounts: "
                "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | "
                "Set-ADAccountControl -DoesNotRequirePreAuth $false"
            ),
        )

    # ── Encryption posture ─────────────────────────────────────────

    def assess_encryption(self):
        subsection("Kerberos Encryption Posture")
        # DES-only accounts (USE_DES_KEY_ONLY = 0x200000)
        des_entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=2097152)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"]
        )
        if des_entries:
            affected = [str(e.sAMAccountName) for e in des_entries
                        if hasattr(e, 'sAMAccountName')]
            self.reporter.add(
                self.NAME, "HIGH",
                f"{len(des_entries)} accounts configured with DES Kerberos encryption",
                "DES was deprecated in 2005 and broken long before that. Accounts with "
                "USE_DES_KEY_ONLY will negotiate DES when possible, making their Kerberos "
                "exchanges trivially decryptable by a passive observer.",
                affected=affected,
                remediation=(
                    "Clear USE_DES_KEY_ONLY UAC flag: "
                    "Set-ADUser <user> -KerberosEncryptionType AES128,AES256"
                ),
            )

        # krbtgt RC4 check
        krbtgt = self.conn.ldap_search("(sAMAccountName=krbtgt)",
                                       ["msDS-SupportedEncryptionTypes"])
        if krbtgt:
            enc_raw = krbtgt[0].get('msDS-SupportedEncryptionTypes')
            enc_val = int_value(enc_raw, 0)
            if enc_val == 0 or bool(enc_val & 0x4):
                self.reporter.add(
                    self.NAME, "MEDIUM",
                    "krbtgt account permits RC4 Kerberos encryption",
                    "The krbtgt key signs all Kerberos tickets. RC4 support enables downgrade "
                    "attacks. AES-only enforcement is a defence-in-depth measure.",
                    affected=["krbtgt"],
                    remediation=(
                        "Set-ADUser krbtgt -KerberosEncryptionType AES256, then rotate "
                        "the krbtgt password twice to invalidate outstanding RC4 tickets."
                    ),
                )

    # ── Delegation ─────────────────────────────────────────────────

    def assess_unconstrained_delegation(self):
        subsection("Unconstrained Kerberos Delegation")
        entries = self.conn.ldap_search(
            "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "objectClass", "dNSHostName"]
        )
        if not entries:
            success("No non-DC accounts with unconstrained delegation found")
            return
        affected = [str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')]
        finding("CRITICAL", f"{len(entries)} non-DC objects with unconstrained delegation")
        self.reporter.add(
            self.NAME, "CRITICAL",
            f"{len(entries)} accounts/computers configured with unconstrained Kerberos delegation",
            "Unconstrained delegation (TRUSTED_FOR_DELEGATION) causes the KDC to include "
            "authenticating users' TGTs in service tickets sent to this account. "
            "Any service compromised on this host accumulates TGTs for every user who "
            "authenticates — including domain controllers if coerced. "
            "This is a direct path to full domain compromise.",
            affected=affected,
            remediation=(
                "Remove TRUSTED_FOR_DELEGATION from all non-DC accounts. "
                "Replace with constrained or Resource-Based Constrained Delegation. "
                "Add Tier-0 accounts to Protected Users — their TGTs will never be forwarded."
            ),
        )

    def assess_constrained_delegation(self):
        subsection("Constrained Kerberos Delegation")
        entries = self.conn.ldap_search(
            "(&(msDS-AllowedToDelegateTo=*)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl"]
        )
        if not entries:
            return
        protocol_transition = []
        for entry in entries:
            uac = int_value(entry.get('userAccountControl'), 0)
            if uac & 0x1000000:  # TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
                protocol_transition.append(
                    str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "?")
        affected = [str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')]
        sev = "HIGH" if protocol_transition else "MEDIUM"
        self.reporter.add(
            self.NAME, sev,
            f"{len(entries)} accounts with constrained delegation; "
            f"{len(protocol_transition)} with protocol transition",
            "Constrained delegation with protocol transition allows impersonating any user "
            "to the specified services without requiring that user's TGT — authentication bypass "
            "if the delegating account is compromised.",
            affected=affected,
            remediation=(
                "Audit each delegation entry. Remove protocol transition where not required. "
                "Prefer RBCD. Monitor msDS-AllowedToDelegateTo for unauthorized changes."
            ),
        )

    def assess_rbcd(self):
        subsection("Resource-Based Constrained Delegation (RBCD)")
        entries = self.conn.ldap_search(
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            ["sAMAccountName", "dNSHostName"]
        )
        if not entries:
            return
        affected = [str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')]
        self.reporter.add(
            self.NAME, "MEDIUM",
            f"{len(entries)} objects have RBCD configured",
            "RBCD entries should be reviewed for legitimacy. Unexpected entries may indicate "
            "an attacker exploited WriteProperty access on a computer object to add RBCD.",
            affected=affected,
            remediation=(
                "Review each RBCD entry for business justification. "
                "Audit who has WriteProperty/GenericAll on computer objects."
            ),
        )

    # ── Protected Users ────────────────────────────────────────────

    def assess_protected_users(self):
        subsection("Protected Users Group Coverage")
        domain_dn = self._get_domain_dn()
        protected = self.conn.ldap_search(
            f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:="
            f"CN=Protected Users,CN=Users,{domain_dn}))",
            ["sAMAccountName"]
        )
        protected_names = {str(e.sAMAccountName) for e in protected
                           if hasattr(e, 'sAMAccountName')}
        privileged = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(adminCount=1)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"]
        )
        priv_names = [str(e.sAMAccountName) for e in privileged
                      if hasattr(e, 'sAMAccountName')]
        not_protected = [n for n in priv_names
                         if n not in protected_names and n != 'krbtgt']
        if not_protected:
            self.reporter.add(
                self.NAME, "MEDIUM",
                f"{len(not_protected)} privileged accounts not in Protected Users group",
                "Protected Users members cannot authenticate with NTLM, use DES/RC4 Kerberos, "
                "be subjected to unconstrained delegation, or have credentials cached. "
                "Privileged accounts outside this group retain weaker protections.",
                details={"privileged_total": len(priv_names),
                         "in_protected_users": len(protected_names)},
                affected=not_protected[:50],
                remediation=(
                    "Add Tier-0 and Tier-1 accounts to Protected Users. "
                    "Validate service accounts for NTLM/delegation compatibility first."
                ),
            )

    # ── krbtgt ─────────────────────────────────────────────────────

    def assess_krbtgt(self):
        subsection("krbtgt Account Hygiene")
        entries = self.conn.ldap_search("(sAMAccountName=krbtgt)", ["pwdLastSet"])
        if not entries:
            return
        age = self._pwd_age_days(first_value(entries[0].get('pwdLastSet')))
        if age > 0:
            info(f"krbtgt password last changed: {age} days ago")
            if age > 365:
                sev = "CRITICAL"
            elif age > 180:
                sev = "HIGH"
            else:
                return
            self.reporter.add(
                self.NAME, sev,
                f"krbtgt password is {age} days old",
                "The krbtgt password is the KDC signing key. If an attacker has ever obtained "
                "this hash, they can forge Kerberos tickets (Golden Tickets) indefinitely until "
                "the password is rotated twice. Recommended rotation: every 180 days.",
                affected=["krbtgt"],
                remediation=(
                    "Rotate krbtgt password twice with at least 10 hours between rotations "
                    "(ticket lifetime). Use Microsoft's New-KrbtgtKeys.ps1 script."
                ),
            )

    # ── Helpers ────────────────────────────────────────────────────

    def _get_domain_dn(self):
        if self.conn.domain:
            return ','.join(f"DC={p}" for p in self.conn.domain.split('.'))
        return ""

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

    def _pwd_age_label(self, raw_val) -> str:
        days = self._pwd_age_days(raw_val)
        return f"{days}d" if days > 0 else "?"
