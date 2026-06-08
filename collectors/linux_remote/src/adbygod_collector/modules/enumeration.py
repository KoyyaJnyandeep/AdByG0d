#!/usr/bin/env python3
"""
AdByG0d - Domain Enumeration Module
Full domain reconnaissance: users, groups, computers, OUs, GPOs, trusts, DCs, LAPS, DNS.
"""

from datetime import datetime, timedelta
from ..core.banner import (
    C, module_header, subsection, finding, status, info, error, print_table, progress_bar
)
from ..core.ldap_values import int_value


class EnumerationModule:
    """Comprehensive AD enumeration."""

    NAME = "Domain Enumeration"
    DESCRIPTION = "Full domain recon — users, groups, computers, policies, trusts, and more"

    def __init__(self, connector, reporter):
        self.conn = connector
        self.reporter = reporter
        self.domain_info = {}

    def run(self):
        module_header(self.NAME, self.DESCRIPTION)

        checks = [
            ("Domain Controllers", self.enum_domain_controllers),
            ("Password Policy", self.enum_password_policy),
            ("Users", self.enum_users),
            ("Privileged Groups", self.enum_privileged_groups),
            ("Computers", self.enum_computers),
            ("Organizational Units", self.enum_ous),
            ("Group Policy Objects", self.enum_gpos),
            ("Domain Trusts", self.enum_trusts),
            ("LAPS Deployment", self.enum_laps),
            ("Fine-Grained Password Policies", self.enum_fgpp),
            ("Service Accounts", self.enum_service_accounts),
            ("Stale Objects", self.enum_stale_objects),
            ("MachineAccountQuota", self.enum_maq),
        ]

        for i, (name, func) in enumerate(checks):
            progress_bar(i, len(checks), label=name)
            try:
                func()
            except Exception as e:
                error(f"  {name} failed: {str(e)}")
        progress_bar(len(checks), len(checks), label="Complete")

        self.reporter.modules_run.append(self.NAME)
        return self.domain_info

    def enum_domain_controllers(self):
        subsection("Domain Controllers")
        entries = self.conn.ldap_search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion", "whenCreated"]
        )

        rows = []
        for entry in entries:
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"
            dns = str(entry.dNSHostName) if hasattr(entry, 'dNSHostName') else "N/A"
            os_name = str(entry.operatingSystem) if hasattr(entry, 'operatingSystem') else "N/A"
            rows.append([name, dns, os_name])

        if rows:
            print_table(["Name", "DNS Hostname", "Operating System"], rows, "Domain Controllers")
            self.domain_info["dc_count"] = len(rows)

            # Check for old OS
            for row in rows:
                if any(old in row[2] for old in ["2008", "2003", "2000"]):
                    finding("HIGH", f"Legacy OS on DC: {row[0]}", f"Running: {row[2]}")
                    self.reporter.add(
                        "Enumeration", "HIGH",
                        f"Domain Controller running legacy OS: {row[0]}",
                        f"DC {row[0]} is running {row[2]}, which is end-of-life and lacks modern security features.",
                        remediation="Upgrade to Windows Server 2019 or later."
                    )
        else:
            info("No domain controllers found via LDAP (may need elevated privileges)")

    def enum_password_policy(self):
        subsection("Password Policy")
        entries = self.conn.ldap_search(
            "(objectClass=domain)",
            ["minPwdLength", "maxPwdAge", "minPwdAge", "pwdHistoryLength",
             "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
             "pwdProperties"],
            search_base=self.conn.base_dn,
            size_limit=1
        )

        if entries:
            entry = entries[0]
            min_len = int_value(entry.minPwdLength, 0) if hasattr(entry, 'minPwdLength') else 0
            lockout = int_value(entry.lockoutThreshold, 0) if hasattr(entry, 'lockoutThreshold') else 0
            pwd_hist = int_value(entry.pwdHistoryLength, 0) if hasattr(entry, 'pwdHistoryLength') else 0
            pwd_props = int_value(entry.pwdProperties, 0) if hasattr(entry, 'pwdProperties') else 0
            complexity = bool(pwd_props & 1)

            rows = [
                ["Minimum Password Length", str(min_len)],
                ["Password History", str(pwd_hist)],
                ["Lockout Threshold", str(lockout) if lockout else "None (No Lockout!)"],
                ["Complexity Required", str(complexity)],
            ]
            print_table(["Policy", "Value"], rows, "Default Domain Password Policy")

            if min_len < 12:
                finding("HIGH", f"Weak minimum password length: {min_len}",
                        "Recommended: 12+ characters minimum")
                self.reporter.add(
                    "Enumeration", "HIGH",
                    f"Weak minimum password length: {min_len} characters",
                    "Short passwords are easily brute-forced. Industry standard is 12+ characters.",
                    details={"Current Length": min_len, "Recommended": "12+"},
                    remediation="Increase minimum password length to 12+ characters. Consider using passphrases."
                )

            if lockout == 0:
                finding("CRITICAL", "No account lockout policy!",
                        "Accounts can be brute-forced without lockout")
                self.reporter.add(
                    "Enumeration", "CRITICAL",
                    "No account lockout policy configured",
                    "Without an account lockout threshold, attackers can perform unlimited password guessing attacks.",
                    remediation="Configure account lockout threshold (recommended: 5-10 attempts)."
                )
            elif lockout > 10:
                finding("MEDIUM", f"High lockout threshold: {lockout}",
                        "Allows many password guessing attempts")
                self.reporter.add(
                    "Enumeration", "MEDIUM",
                    f"High account lockout threshold: {lockout} attempts",
                    "A high lockout threshold allows attackers to make many guessing attempts.",
                    remediation="Lower lockout threshold to 5-10 attempts."
                )

            if not complexity:
                finding("HIGH", "Password complexity not required")
                self.reporter.add(
                    "Enumeration", "HIGH",
                    "Password complexity requirements disabled",
                    "Without complexity requirements, users can set simple, easily guessed passwords.",
                    remediation="Enable password complexity requirements in Default Domain Policy."
                )

    def enum_users(self):
        subsection("User Enumeration")
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user))",
            ["sAMAccountName", "userAccountControl", "adminCount", "memberOf",
             "lastLogonTimestamp", "pwdLastSet", "description", "servicePrincipalName"]
        )

        total_users = len(entries)
        enabled = 0
        disabled = 0
        admin_count = 0
        no_preauth = 0
        no_password = 0
        pwd_never_expires = 0
        des_only = 0
        interesting_desc = []
        kerberoastable = 0

        for entry in entries:
            uac = int_value(entry.userAccountControl, 0) if hasattr(entry, 'userAccountControl') else 0
            if uac & 0x2:
                disabled += 1
            else:
                enabled += 1

            if hasattr(entry, 'adminCount') and str(entry.adminCount) == '1':
                admin_count += 1

            if uac & 0x400000:  # DONT_REQUIRE_PREAUTH
                no_preauth += 1
            if uac & 0x20:  # PASSWD_NOTREQD
                no_password += 1
            if uac & 0x10000:  # DONT_EXPIRE_PASSWORD
                pwd_never_expires += 1
            if uac & 0x200000:  # USE_DES_KEY_ONLY
                des_only += 1

            if hasattr(entry, 'servicePrincipalName') and entry.servicePrincipalName:
                if not (uac & 0x2):  # Not disabled
                    kerberoastable += 1

            if hasattr(entry, 'description') and entry.description:
                desc = str(entry.description)
                keywords = ['pass', 'pwd', 'cred', 'secret', 'key', 'token']
                if any(kw in desc.lower() for kw in keywords):
                    name = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "?"
                    interesting_desc.append((name, desc))

        rows = [
            ["Total Users", str(total_users)],
            ["Enabled", str(enabled)],
            ["Disabled", str(disabled)],
            ["AdminCount=1", str(admin_count)],
            ["Kerberoastable", str(kerberoastable)],
            ["AS-REP Roastable", str(no_preauth)],
            ["Password Not Required", str(no_password)],
            ["Password Never Expires", str(pwd_never_expires)],
            ["DES-Only Encryption", str(des_only)],
        ]
        print_table(["Property", "Count"], rows, "User Statistics")

        self.domain_info["total_users"] = total_users
        self.domain_info["enabled_users"] = enabled

        if no_preauth > 0:
            finding("HIGH", f"{no_preauth} accounts with Kerberos pre-auth disabled (AS-REP Roastable)")
            self.reporter.add(
                "Enumeration", "HIGH",
                f"{no_preauth} accounts vulnerable to AS-REP Roasting",
                "Accounts with Kerberos pre-authentication disabled can be AS-REP roasted offline.",
                remediation="Enable Kerberos pre-authentication on all accounts unless absolutely necessary."
            )

        if no_password > 0:
            finding("CRITICAL", f"{no_password} accounts with PASSWD_NOTREQD flag")
            self.reporter.add(
                "Enumeration", "CRITICAL",
                f"{no_password} accounts with PASSWD_NOTREQD flag set",
                "These accounts can have empty passwords. Attackers can authenticate with blank credentials.",
                remediation="Remove the PASSWD_NOTREQD flag from all accounts."
            )

        if des_only > 0:
            finding("HIGH", f"{des_only} accounts restricted to DES encryption",
                    "DES is broken and trivially crackable")
            self.reporter.add(
                "Enumeration", "HIGH",
                f"{des_only} accounts using DES-only Kerberos encryption",
                "DES encryption is cryptographically broken. Tickets can be cracked instantly.",
                remediation="Remove USE_DES_KEY_ONLY flag and migrate to AES encryption."
            )

        if interesting_desc:
            finding("HIGH", f"{len(interesting_desc)} accounts with potential credentials in description")
            for name, desc in interesting_desc[:10]:
                status("!", f"  {C.BYELLOW}{name}{C.RST}: {desc}", C.BYELLOW)
            self.reporter.add(
                "Enumeration", "HIGH",
                "Credentials potentially stored in user description fields",
                "User description fields may contain passwords or sensitive information.",
                affected=[f"{n}: {d}" for n, d in interesting_desc],
                remediation="Remove sensitive information from description fields. Rotate exposed credentials."
            )

        if pwd_never_expires > (total_users * 0.1) and total_users > 10:
            finding("MEDIUM", f"{pwd_never_expires} accounts ({pwd_never_expires*100//total_users}%) with non-expiring passwords")
            self.reporter.add(
                "Enumeration", "MEDIUM",
                f"{pwd_never_expires} accounts with non-expiring passwords",
                "A large number of accounts have passwords that never expire, increasing credential theft risk.",
                remediation="Implement password expiration policies. Consider using managed service accounts for services."
            )

    def enum_privileged_groups(self):
        subsection("Privileged Groups")
        privileged_groups = [
            ("Domain Admins", "HIGH"),
            ("Enterprise Admins", "HIGH"),
            ("Schema Admins", "HIGH"),
            ("Administrators", "HIGH"),
            ("Account Operators", "MEDIUM"),
            ("Backup Operators", "MEDIUM"),
            ("Server Operators", "MEDIUM"),
            ("Print Operators", "LOW"),
            ("DnsAdmins", "MEDIUM"),
            ("Group Policy Creator Owners", "MEDIUM"),
            ("Remote Desktop Users", "LOW"),
        ]

        rows = []
        for group_name, sev in privileged_groups:
            entries = self.conn.ldap_search(
                f"(&(objectClass=group)(cn={group_name}))",
                ["member", "cn"]
            )
            if entries:
                entry = entries[0]
                members = entry.member if hasattr(entry, 'member') else []
                member_count = len(members) if members else 0
                rows.append([group_name, str(member_count), sev])

                if group_name == "Domain Admins" and member_count > 5:
                    finding("HIGH", f"Domain Admins has {member_count} members (recommended: <5)")
                    self.reporter.add(
                        "Enumeration", "HIGH",
                        f"Excessive Domain Admins: {member_count} members",
                        "Having too many Domain Admins increases the attack surface.",
                        remediation="Reduce Domain Admins to essential accounts only. Use delegation instead."
                    )

                if group_name in ("Enterprise Admins", "Schema Admins") and member_count > 1:
                    finding("MEDIUM", f"{group_name} has {member_count} members (recommended: 0-1)")
                    self.reporter.add(
                        "Enumeration", "MEDIUM",
                        f"{group_name} has {member_count} members",
                        f"{group_name} should ideally be empty or have at most 1 member.",
                        remediation=f"Remove unnecessary members from {group_name}."
                    )

                if group_name == "DnsAdmins" and member_count > 0:
                    finding("MEDIUM", f"DnsAdmins has {member_count} members (potential DLL injection path)")
                    self.reporter.add(
                        "Enumeration", "MEDIUM",
                        f"DnsAdmins group has {member_count} members — potential privilege escalation",
                        "Members of DnsAdmins can load arbitrary DLLs on the DNS server, "
                        "which is often the DC itself, leading to SYSTEM-level code execution.",
                        remediation="Minimize DnsAdmins membership. Monitor DNS service configuration changes."
                    )

        if rows:
            print_table(["Group", "Members", "Risk"], rows, "Privileged Groups")

    def enum_computers(self):
        subsection("Computer Objects")
        entries = self.conn.ldap_search(
            "(objectCategory=computer)",
            ["cn", "operatingSystem", "operatingSystemVersion", "userAccountControl",
             "lastLogonTimestamp", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"]
        )

        total = len(entries)
        os_counts = {}
        legacy_os = []
        laps_enabled = 0
        unconstrained = 0

        for entry in entries:
            os_name = str(entry.operatingSystem) if hasattr(entry, 'operatingSystem') else "Unknown"
            os_counts[os_name] = os_counts.get(os_name, 0) + 1

            if any(old in os_name for old in ["2003", "2008", "XP", "Vista", "Windows 7", "2000"]):
                legacy_os.append((str(entry.cn), os_name))

            if ((hasattr(entry, 'ms-Mcs-AdmPwdExpirationTime')
                 and str(entry['ms-Mcs-AdmPwdExpirationTime']) not in ('', '[]', 'None'))
                or (hasattr(entry, 'msLAPS-PasswordExpirationTime')
                    and str(entry['msLAPS-PasswordExpirationTime']) not in ('', '[]', 'None'))):
                laps_enabled += 1

            uac = int_value(entry.userAccountControl, 0) if hasattr(entry, 'userAccountControl') else 0
            if uac & 0x80000:  # TRUSTED_FOR_DELEGATION
                unconstrained += 1

        rows = [[os_name, str(count)] for os_name, count in sorted(os_counts.items(), key=lambda x: x[1], reverse=True)]
        if rows:
            print_table(["Operating System", "Count"], rows, f"Computer Objects ({total} total)")

        if legacy_os:
            finding("HIGH", f"{len(legacy_os)} computers running legacy/EOL operating systems")
            affected = [f"{name} ({os})" for name, os in legacy_os]
            self.reporter.add(
                "Enumeration", "HIGH",
                f"{len(legacy_os)} computers running end-of-life operating systems",
                "Legacy OS systems lack modern security controls and receive no patches.",
                affected=affected,
                remediation="Decommission or upgrade all end-of-life systems."
            )

        self.domain_info["total_computers"] = total
        self.domain_info["laps_computers"] = laps_enabled

    def enum_ous(self):
        subsection("Organizational Units")
        entries = self.conn.ldap_search(
            "(objectClass=organizationalUnit)",
            ["ou", "description", "gPLink"]
        )

        ou_count = len(entries)
        linked_gpos = 0
        for entry in entries:
            if hasattr(entry, 'gPLink') and entry.gPLink:
                linked_gpos += 1

        info(f"Found {ou_count} Organizational Units ({linked_gpos} with GPO links)")

    def enum_gpos(self):
        subsection("Group Policy Objects")
        entries = self.conn.ldap_search(
            "(objectClass=groupPolicyContainer)",
            ["displayName", "gPCFileSysPath", "versionNumber", "flags"]
        )

        rows = []
        for entry in entries:
            name = str(entry.displayName) if hasattr(entry, 'displayName') else "N/A"
            path = str(entry.gPCFileSysPath) if hasattr(entry, 'gPCFileSysPath') else "N/A"
            flags = int_value(entry.flags, 0) if hasattr(entry, 'flags') else 0
            state = "Enabled" if flags == 0 else "Disabled" if flags == 3 else "Partial"
            rows.append([name, state, path])

        if rows:
            print_table(["GPO Name", "Status", "SYSVOL Path"], rows[:15], f"Group Policy Objects ({len(rows)} total)")
            self.domain_info["gpo_count"] = len(rows)

    def enum_trusts(self):
        subsection("Domain Trusts")
        entries = self.conn.ldap_search(
            "(objectClass=trustedDomain)",
            ["cn", "trustDirection", "trustType", "trustAttributes", "securityIdentifier",
             "flatName", "trustPartner"]
        )

        if not entries:
            info("No domain trusts found")
            return

        dir_map = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        type_map = {1: "Downlevel", 2: "Uplevel", 3: "MIT", 4: "DCE"}

        rows = []
        for entry in entries:
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"
            direction = dir_map.get(int_value(entry.trustDirection, 0) if hasattr(entry, 'trustDirection') else 0, "Unknown")
            trust_type = type_map.get(int_value(entry.trustType, 0) if hasattr(entry, 'trustType') else 0, "Unknown")
            attrs = int_value(entry.trustAttributes, 0) if hasattr(entry, 'trustAttributes') else 0

            sid_filtering = "Yes" if (attrs & 0x4) else "No"
            if sid_filtering == "No":
                finding("HIGH", f"SID Filtering disabled on trust: {name}",
                        "Allows SID History injection attacks across trusts")
                self.reporter.add(
                    "Enumeration", "HIGH",
                    f"SID Filtering disabled on trust to {name}",
                    "Without SID filtering, an attacker who compromises the trusted domain can forge "
                    "SID History to gain elevated access in this domain.",
                    remediation="Enable SID filtering (quarantine) on the trust."
                )

            rows.append([name, direction, trust_type, sid_filtering])

        print_table(["Trust Partner", "Direction", "Type", "SID Filtering"], rows, "Domain Trusts")

    def enum_laps(self):
        subsection("LAPS Deployment")
        # Check for either legacy Microsoft LAPS or modern Windows LAPS schema attributes.
        entries = self.conn.ldap_search(
            "(|(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)(lDAPDisplayName=msLAPS-PasswordExpirationTime))",
            ["cn", "lDAPDisplayName"],
            search_base=f"CN=Schema,CN=Configuration,{self.conn.base_dn}"
        )

        if entries:
            info("LAPS schema attributes detected")

            # Count computers with LAPS
            laps_computers = self.conn.ldap_search(
                "(&(objectCategory=computer)(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*)))",
                ["cn", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"]
            )
            total_computers = self.domain_info.get("total_computers", 0)
            laps_count = len(laps_computers)

            if total_computers > 0:
                pct = (laps_count / total_computers) * 100
                info(f"LAPS deployed on {laps_count}/{total_computers} computers ({pct:.0f}%)")

                if pct < 80:
                    finding("MEDIUM", f"LAPS only deployed on {pct:.0f}% of computers")
                    self.reporter.add(
                        "Enumeration", "MEDIUM",
                        f"Incomplete LAPS deployment ({pct:.0f}%)",
                        "LAPS is not deployed on all domain computers, leaving local admin passwords potentially reused.",
                        details={"LAPS Deployed": laps_count, "Total Computers": total_computers},
                        remediation="Deploy LAPS to all domain-joined computers."
                    )
        else:
            finding("HIGH", "LAPS not deployed in this domain")
            self.reporter.add(
                "Enumeration", "HIGH",
                "LAPS (Local Administrator Password Solution) not deployed",
                "Without LAPS, local admin passwords may be identical across machines, "
                "enabling lateral movement after a single compromise.",
                remediation="Deploy Microsoft LAPS or Windows LAPS to randomize local admin passwords."
            )

    def enum_fgpp(self):
        subsection("Fine-Grained Password Policies")
        entries = self.conn.ldap_search(
            "(objectClass=msDS-PasswordSettings)",
            ["cn", "msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength",
             "msDS-LockoutThreshold", "msDS-PasswordComplexityEnabled",
             "msDS-PasswordSettingsPrecedence", "msDS-PSOAppliesTo"]
        )

        if entries:
            rows = []
            for entry in entries:
                name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"
                min_len = str(entry['msDS-MinimumPasswordLength']) if hasattr(entry, 'msDS-MinimumPasswordLength') else "N/A"
                rows.append([name, min_len])
            print_table(["Policy Name", "Min Length"], rows, "Fine-Grained Password Policies")
        else:
            info("No Fine-Grained Password Policies configured")

    def enum_service_accounts(self):
        subsection("Service Accounts")

        # gMSA
        gmsa = self.conn.ldap_search(
            "(objectClass=msDS-GroupManagedServiceAccount)",
            ["sAMAccountName", "msDS-ManagedPasswordInterval", "msDS-GroupMSAMembership"]
        )
        info(f"Group Managed Service Accounts (gMSA): {len(gmsa)}")

        # Regular service accounts (by naming convention + SPN)
        svc = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "servicePrincipalName", "pwdLastSet", "adminCount"]
        )
        info(f"User accounts with SPNs (Kerberoastable): {len(svc)}")

        if svc:
            rows = []
            for entry in svc:
                name = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "N/A"
                spns = entry.servicePrincipalName if hasattr(entry, 'servicePrincipalName') else []
                spn_str = str(spns[0]) if spns else "N/A"
                admin = "Yes" if (hasattr(entry, 'adminCount') and str(entry.adminCount) == '1') else "No"
                rows.append([name, spn_str, admin])

            print_table(["Account", "SPN (first)", "AdminCount"], rows[:20],
                        "Kerberoastable Service Accounts")

    def enum_stale_objects(self):
        subsection("Stale Objects")

        # Accounts not logged in for 90+ days
        threshold = datetime.now() - timedelta(days=90)
        # Convert to Windows FileTime
        epoch = datetime(1601, 1, 1)
        ft = int((threshold - epoch).total_seconds() * 10000000)

        stale_users = self.conn.ldap_search(
            f"(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<={ft})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName"]
        )

        stale_computers = self.conn.ldap_search(
            f"(&(objectCategory=computer)(lastLogonTimestamp<={ft}))",
            ["cn"]
        )

        if stale_users:
            info(f"Stale user accounts (90+ days inactive): {len(stale_users)}")
            if len(stale_users) > 50:
                finding("MEDIUM", f"{len(stale_users)} stale user accounts detected",
                        "Inactive accounts increase the attack surface")
                self.reporter.add(
                    "Enumeration", "MEDIUM",
                    f"{len(stale_users)} stale user accounts (inactive 90+ days)",
                    "Stale accounts are prime targets for credential attacks as they're less likely to be monitored.",
                    remediation="Disable or delete inactive user accounts on a regular basis."
                )

        if stale_computers:
            info(f"Stale computer accounts (90+ days inactive): {len(stale_computers)}")

    def enum_maq(self):
        subsection("MachineAccountQuota")
        entries = self.conn.ldap_search(
            "(objectClass=domain)",
            ["ms-DS-MachineAccountQuota"],
            search_base=self.conn.base_dn,
            size_limit=1
        )

        if entries:
            entry = entries[0]
            maq = int_value(entry['ms-DS-MachineAccountQuota'], 10) if hasattr(entry, 'ms-DS-MachineAccountQuota') else 10

            info(f"MachineAccountQuota: {maq}")

            if maq > 0:
                finding("MEDIUM", f"MachineAccountQuota is {maq} (allows RBCD attacks)",
                        "Any authenticated user can create up to {maq} computer accounts")
                self.reporter.add(
                    "Enumeration", "MEDIUM",
                    f"MachineAccountQuota set to {maq}",
                    "Any authenticated user can create machine accounts, enabling Resource-Based "
                    "Constrained Delegation (RBCD) attacks for privilege escalation.",
                    details={"Current Value": maq, "Recommended": 0},
                    remediation="Set ms-DS-MachineAccountQuota to 0 in the domain object."
                )
