#!/usr/bin/env python3
"""
AdByG0d - Persistence & Backdoor Detection Module
Detects existing persistence: Golden Ticket prereqs, Skeleton Key, DCShadow, SID History, etc.
"""

from datetime import datetime, timedelta
from ..core.banner import (
    C, module_header, subsection, finding, info, error, print_table, progress_bar
)
from ..core.ldap_values import int_value, list_values


class PersistenceModule:
    """Detect persistence mechanisms and backdoor indicators."""

    NAME = "Persistence Detection"
    DESCRIPTION = "Golden/Silver Ticket prereqs, Skeleton Key, DCShadow, SID History, backdoors"

    def __init__(self, connector, reporter):
        self.conn = connector
        self.reporter = reporter

    def run(self):
        module_header(self.NAME, self.DESCRIPTION)

        checks = [
            ("krbtgt Account Analysis", self.check_krbtgt),
            ("SID History Injection", self.check_sid_history),
            ("AdminSDHolder Modifications", self.check_adminsdholder_mods),
            ("Shadow Credentials", self.check_shadow_credentials),
            ("Rogue Domain Controllers", self.check_rogue_dcs),
            ("Primary Group ID Manipulation", self.check_primary_group),
            ("Suspicious Account Patterns", self.check_suspicious_accounts),
            ("Trust Account Anomalies", self.check_trust_anomalies),
            ("Certificate Persistence", self.check_cert_persistence),
            ("GPO Persistence", self.check_gpo_persistence),
        ]

        for i, (name, func) in enumerate(checks):
            progress_bar(i, len(checks), label=name)
            try:
                func()
            except Exception as e:
                error(f"  {name} failed: {str(e)}")
        progress_bar(len(checks), len(checks), label="Complete")

        self.reporter.modules_run.append(self.NAME)

    def check_krbtgt(self):
        subsection("krbtgt Account Analysis")

        entries = self.conn.ldap_search(
            "(sAMAccountName=krbtgt)",
            ["pwdLastSet", "msDS-KeyVersionNumber", "whenChanged", "adminCount"]
        )

        if entries:
            entry = entries[0]
            pwd_last_set = str(entry.pwdLastSet) if hasattr(entry, 'pwdLastSet') else "N/A"
            kvno = str(entry['msDS-KeyVersionNumber']) if hasattr(entry, 'msDS-KeyVersionNumber') else "N/A"

            rows = [
                ["Password Last Set", pwd_last_set],
                ["Key Version Number", kvno],
            ]
            print_table(["Property", "Value"], rows, "krbtgt Account")

            # Check if krbtgt password is old
            try:
                pwd_ts = entry.pwdLastSet.value
                if pwd_ts:
                    age = datetime.now(pwd_ts.tzinfo) - pwd_ts if pwd_ts.tzinfo else datetime.now() - pwd_ts
                    if age > timedelta(days=180):
                        finding("HIGH", f"krbtgt password is {age.days} days old!",
                                "Old krbtgt key = long Golden Ticket validity window")
                        self.reporter.add(
                            "Persistence", "HIGH",
                            f"krbtgt password not rotated in {age.days} days",
                            "The krbtgt account password should be rotated regularly. An old password "
                            "means any previously generated Golden Tickets remain valid. "
                            "Note: krbtgt password must be changed TWICE to fully invalidate old tickets.",
                            details={"Password Age (days)": age.days, "Key Version": kvno},
                            remediation="Rotate krbtgt password twice (with replication in between). "
                                        "Use the krbtgt reset script from Microsoft."
                        )
                    else:
                        info(f"krbtgt password age: {age.days} days")
            except Exception:
                pass

            # Golden Ticket prerequisites info
            info("Golden Ticket requires: krbtgt NTLM hash + domain SID + domain name")
            info("Silver Ticket requires: service account NTLM hash + domain SID + SPN")

    def check_sid_history(self):
        subsection("SID History Injection")

        entries = self.conn.ldap_search(
            "(sIDHistory=*)",
            ["sAMAccountName", "sIDHistory", "objectClass", "adminCount"]
        )

        if not entries:
            info("No accounts with SID History found")
            return

        rows = []
        suspicious = []

        for entry in entries:
            name = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "N/A"
            sid_history = list(entry.sIDHistory) if hasattr(entry, 'sIDHistory') else []
            object_classes = list_values(entry.objectClass) if hasattr(entry, 'objectClass') else []
            obj_class = str(object_classes[-1]) if object_classes else "N/A"

            for sid in sid_history:
                sid_str = str(sid)
                rows.append([name, obj_class, sid_str[:50]])

                # Check for privileged SID in history (e.g., -500, -512, -519)
                if any(sid_str.endswith(s) for s in ["-500", "-512", "-516", "-518", "-519", "-544"]):
                    suspicious.append((name, sid_str))

        print_table(["Account", "Type", "SID History"], rows[:20],
                    f"Accounts with SID History ({len(entries)} total)")

        if suspicious:
            finding("CRITICAL", f"Privileged SIDs in SID History: {len(suspicious)} accounts!")
            for name, sid in suspicious:
                info(f"  {C.BRED}{name}{C.RST} has privileged SID: {sid}")

            self.reporter.add(
                "Persistence", "CRITICAL",
                f"Privileged SIDs found in SID History on {len(suspicious)} accounts",
                "SID History containing privileged SIDs (e.g., Domain Admins) grants those privileges "
                "without being a member of the group. This is a common persistence technique.",
                affected=[f"{n} has SID {s}" for n, s in suspicious],
                remediation="Remove SID History from affected accounts unless from a legitimate migration. "
                            "Enable SID Filtering on trusts."
            )
        elif entries:
            finding("LOW", f"{len(entries)} accounts with SID History — verify legitimacy")

    def check_adminsdholder_mods(self):
        subsection("AdminSDHolder Permission Backdoors")

        # Check for non-default permissions on AdminSDHolder
        raw_entries = self.conn.ldap_search_raw(
            f"(distinguishedName=CN=AdminSDHolder,CN=System,{self.conn.base_dn})",
            ["nTSecurityDescriptor", "whenChanged"]
        )

        if raw_entries:
            info("AdminSDHolder object exists — permissions propagate to all protected objects")
            info("Any custom ACE on AdminSDHolder = persistent backdoor on all admin accounts")

            # Check whenChanged
            for entry in raw_entries:
                if 'attributes' in entry:
                    changed = entry['attributes'].get('whenChanged', 'Unknown')
                    info(f"AdminSDHolder last modified: {changed}")

            self.reporter.add(
                "Persistence", "INFO",
                "AdminSDHolder audit recommended",
                "The AdminSDHolder object's DACL is propagated to all protected accounts (Domain Admins, etc.) "
                "every 60 minutes by SDProp. Custom ACEs = persistent backdoor that survives permission cleanup.",
                remediation="Audit AdminSDHolder DACL for non-default entries. "
                            "Compare with a clean AD installation."
            )

    def check_shadow_credentials(self):
        subsection("Shadow Credentials (msDS-KeyCredentialLink)")

        entries = self.conn.ldap_search(
            "(&(objectClass=user)(msDS-KeyCredentialLink=*))",
            ["sAMAccountName", "msDS-KeyCredentialLink", "adminCount"]
        )

        if entries:
            finding("MEDIUM", f"{len(entries)} accounts with Shadow Credentials (KeyCredentialLink)")

            rows = []
            for entry in entries:
                name = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "N/A"
                admin = "Yes" if (hasattr(entry, 'adminCount') and str(entry.adminCount) == '1') else "No"
                rows.append([name, admin, "Key Credential Present"])

            print_table(["Account", "Admin", "Status"], rows[:20])

            admin_shadows = [
                str(e.sAMAccountName) for e in entries
                if hasattr(e, 'adminCount') and str(e.adminCount) == '1'
            ]

            if admin_shadows:
                finding("HIGH", f"Admin accounts with Shadow Credentials: {', '.join(admin_shadows)}")

            self.reporter.add(
                "Persistence", "MEDIUM",
                f"{len(entries)} accounts with Shadow Credentials configured",
                "msDS-KeyCredentialLink allows certificate-based authentication. "
                "Attackers can add shadow credentials for persistent access without passwords.",
                affected=[str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')],
                remediation="Audit all msDS-KeyCredentialLink values. Remove unauthorized entries. "
                            "Monitor changes to this attribute via event ID 5136."
            )
        else:
            info("No Shadow Credentials found")

    def check_rogue_dcs(self):
        subsection("Rogue Domain Controller Detection")

        # Find all objects with DC UAC flags
        dcs = self.conn.ldap_search(
            "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
            ["sAMAccountName", "dNSHostName", "operatingSystem", "whenCreated",
             "userAccountControl", "lastLogonTimestamp"]
        )

        # Find DC objects in Sites
        site_dcs = self.conn.ldap_search(
            "(objectClass=nTDSDSA)",
            ["distinguishedName"],
            search_base=f"CN=Sites,CN=Configuration,{self.conn.base_dn}"
        )

        site_dc_count = len(site_dcs)
        dc_count = len(dcs)

        info(f"Domain Controllers (UAC flag): {dc_count}")
        info(f"NTDS DSA objects (Sites): {site_dc_count}")

        if dc_count != site_dc_count:
            finding("HIGH", f"DC count mismatch! UAC={dc_count} vs Sites={site_dc_count}",
                    "May indicate rogue DC or DCShadow attack")
            self.reporter.add(
                "Persistence", "HIGH",
                "Domain Controller count mismatch",
                "The number of DC objects doesn't match NTDS DSA entries in Sites. "
                "This could indicate a rogue Domain Controller or DCShadow attack.",
                details={"DCs by UAC": dc_count, "DCs in Sites": site_dc_count},
                remediation="Investigate the discrepancy. Check for unauthorized DC objects."
            )

        # Check for recently created DCs
        for dc in dcs:
            try:
                created = dc.whenCreated.value if hasattr(dc, 'whenCreated') else None
                if created:
                    age = datetime.now(created.tzinfo) - created if hasattr(created, 'tzinfo') and created.tzinfo else datetime.now() - created
                    if age < timedelta(days=30):
                        name = str(dc.sAMAccountName)
                        finding("HIGH", f"Recently created DC: {name} (created {age.days} days ago)")
                        self.reporter.add(
                            "Persistence", "HIGH",
                            f"Recently created Domain Controller: {name}",
                            "This DC was created within the last 30 days. Verify it was authorized.",
                            affected=[name],
                            remediation="Verify DC was authorized. Check for DCShadow indicators."
                        )
            except Exception:
                pass

    def check_primary_group(self):
        subsection("Primary Group ID Manipulation")

        # Users with non-default primary group (not 513 = Domain Users)
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)"
            "(!(primaryGroupID=513))(!(primaryGroupID=514))(!(primaryGroupID=516))"
            "(!(primaryGroupID=521)))",
            ["sAMAccountName", "primaryGroupID", "adminCount"]
        )

        if entries:
            rows = []
            suspicious = []
            priv_groups = {512: "Domain Admins", 516: "Domain Controllers",
                          518: "Schema Admins", 519: "Enterprise Admins", 544: "Administrators"}

            for entry in entries:
                name = str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else "N/A"
                pgid = int_value(entry.primaryGroupID, 0) if hasattr(entry, 'primaryGroupID') else 0
                group_name = priv_groups.get(pgid, f"RID {pgid}")
                rows.append([name, str(pgid), group_name])

                if pgid in priv_groups:
                    suspicious.append((name, group_name))

            print_table(["Account", "Primary Group ID", "Group"], rows[:20])

            if suspicious:
                finding("HIGH", "Users with privileged primary groups (hidden membership!)")
                self.reporter.add(
                    "Persistence", "HIGH",
                    "Users with privileged primary groups",
                    "Changing the primary group ID is a stealth technique — the user won't appear "
                    "as a member of the group in standard enumeration tools.",
                    affected=[f"{n} -> {g}" for n, g in suspicious],
                    remediation="Reset primary group to Domain Users (513) and add explicit membership if needed."
                )

    def check_suspicious_accounts(self):
        subsection("Suspicious Account Patterns")

        # Accounts with adminCount=1 but not in any known admin groups
        # Accounts created recently with high privileges
        # Accounts with $ in name (machine accounts) that aren't computers

        # Machine account names that aren't actual computers
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(sAMAccountName=*$))",
            ["sAMAccountName", "adminCount", "whenCreated"]
        )

        if entries:
            finding("MEDIUM", f"{len(entries)} user accounts with '$' suffix (mimicking machine accounts)")
            self.reporter.add(
                "Persistence", "MEDIUM",
                f"{len(entries)} user accounts disguised as machine accounts",
                "User accounts with $ suffix blend in with legitimate computer accounts, "
                "making them harder to detect during audits.",
                affected=[str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')],
                remediation="Investigate these accounts. Remove if unauthorized."
            )

        # Accounts with adminCount=1 (protected accounts beyond the default set)
        admin_count_entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            ["sAMAccountName", "memberOf"]
        )

        if admin_count_entries:
            info(f"Total accounts with adminCount=1: {len(admin_count_entries)}")
            # Flag if unusually high
            if len(admin_count_entries) > 20:
                finding("MEDIUM", f"Unusually high number of adminCount=1 accounts: {len(admin_count_entries)}")

    def check_trust_anomalies(self):
        subsection("Trust Account Anomalies")

        entries = self.conn.ldap_search(
            "(objectClass=trustedDomain)",
            ["cn", "trustDirection", "trustAttributes", "whenCreated", "whenChanged"]
        )

        for entry in entries:
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"
            attrs = int_value(entry.trustAttributes, 0) if hasattr(entry, 'trustAttributes') else 0

            # Check for TREAT_AS_EXTERNAL
            if attrs & 0x40:
                finding("MEDIUM", f"Trust '{name}' has TREAT_AS_EXTERNAL flag",
                        "May bypass SID filtering")
                self.reporter.add(
                    "Persistence", "MEDIUM",
                    f"Trust to {name} has TREAT_AS_EXTERNAL flag",
                    "This flag can affect SID filtering behavior.",
                    remediation="Review trust configuration and SID filtering settings."
                )

    def check_cert_persistence(self):
        subsection("Certificate-Based Persistence")

        # Check for user certificates that could be used for persistence
        entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(userCertificate=*)(adminCount=1))",
            ["sAMAccountName", "userCertificate"],
            size_limit=20
        )

        if entries:
            info(f"{len(entries)} admin accounts have certificates stored in AD")
            self.reporter.add(
                "Persistence", "INFO",
                f"{len(entries)} admin accounts with stored certificates",
                "Certificates stored on admin accounts could be used for persistent authentication.",
                affected=[str(e.sAMAccountName) for e in entries if hasattr(e, 'sAMAccountName')],
                remediation="Audit certificates on admin accounts. Remove unused certificates."
            )

    def check_gpo_persistence(self):
        subsection("GPO-Based Persistence Indicators")

        # Check for GPOs that run scripts
        entries = self.conn.ldap_search(
            "(objectClass=groupPolicyContainer)",
            ["displayName", "gPCFileSysPath"],
            size_limit=50
        )

        if entries and self.conn.smb_conn:
            info(f"Checking {len(entries)} GPOs for script-based persistence...")

            for entry in entries[:20]:
                gpo_name = str(entry.displayName) if hasattr(entry, 'displayName') else "Unknown"
                path = str(entry.gPCFileSysPath) if hasattr(entry, 'gPCFileSysPath') else ""

                if not path or path == "[]":
                    continue

                # Check for startup/logon scripts in GPO
                for script_type in ["Scripts\\Startup", "Scripts\\Logon", "Scripts\\Shutdown"]:
                    for context in ["Machine", "User"]:
                        script_path = f"{path}\\{context}\\{script_type}"
                        try:
                            # Normalize UNC to share path
                            share_path = script_path.replace(f"\\\\{self.conn.domain}", "")
                            parts = share_path.lstrip("\\").split("\\", 1)
                            if len(parts) == 2:
                                share = parts[0]
                                rel_path = "\\" + parts[1] + "\\*"
                                files = self.conn.smb_conn.listPath(share, rel_path)
                                scripts = [f.get_longname() for f in files
                                          if f.get_longname() not in ('.', '..')]
                                if scripts:
                                    finding("MEDIUM", f"GPO '{gpo_name}' has {script_type} scripts: "
                                            f"{', '.join(scripts[:3])}")
                        except Exception:
                            pass
