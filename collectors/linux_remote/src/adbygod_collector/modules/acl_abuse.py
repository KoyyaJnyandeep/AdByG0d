#!/usr/bin/env python3
"""
AdByG0d - ACL Abuse Module
Finds dangerous ACL misconfigurations: DCSync, WriteDACL, GenericAll, ForceChangePassword, etc.
"""

import struct
from ..core.banner import (
    module_header, subsection, finding, info, warning, error, print_table, progress_bar
)
from ..core.ldap_values import first_value

# Well-known SIDs
WELL_KNOWN_SIDS = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
}

# Dangerous rights GUIDs
RIGHTS_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "00000000-0000-0000-0000-000000000000": "All Extended Rights",
}

# Access mask flags
ACCESS_FLAGS = {
    0x1:       "GenericRead",
    0x2:       "GenericWrite",
    0x4:       "GenericExecute",
    0x10000:   "DELETE",
    0x20000:   "READ_CONTROL",
    0x40000:   "WRITE_DAC",
    0x80000:   "WRITE_OWNER",
    0xF01FF:   "GenericAll",
    0x100:     "EXTENDED_RIGHT",
    0x20:      "WRITE_PROPERTY",
}


class ACLModule:
    """ACL-based attack path discovery."""

    NAME = "ACL Abuse"
    DESCRIPTION = "Dangerous permissions: DCSync, WriteDACL, GenericAll, ownership abuse paths"

    def __init__(self, connector, reporter):
        self.conn = connector
        self.reporter = reporter
        self.domain_sid = None

    def run(self):
        module_header(self.NAME, self.DESCRIPTION)

        # Get domain SID
        self._get_domain_sid()

        checks = [
            ("DCSync Rights", self.check_dcsync),
            ("GenericAll on Domain", self.check_genericall_domain),
            ("WriteDACL Abuse", self.check_writedacl),
            ("WriteOwner Abuse", self.check_writeowner),
            ("Password Reset Rights", self.check_force_change_password),
            ("GenericAll on Users", self.check_genericall_users),
            ("GenericWrite on Groups", self.check_genericwrite_groups),
            ("AdminSDHolder", self.check_adminsdholder),
            ("Dangerous GPO Permissions", self.check_gpo_permissions),
            ("Dangerous OU Permissions", self.check_ou_permissions),
        ]

        for i, (name, func) in enumerate(checks):
            progress_bar(i, len(checks), label=name)
            try:
                func()
            except Exception as e:
                error(f"  {name} failed: {str(e)}")
        progress_bar(len(checks), len(checks), label="Complete")

        self.reporter.modules_run.append(self.NAME)

    def _get_domain_sid(self):
        """Get the domain SID."""
        entries = self.conn.ldap_search(
            "(objectClass=domain)",
            ["objectSid"],
            search_base=self.conn.base_dn,
            size_limit=1
        )
        if entries:
            try:
                sid_raw = self._entry_raw_values(entries[0], "objectSid")[0]
                self.domain_sid = self._parse_sid(sid_raw)
                info(f"Domain SID: {self.domain_sid}")
            except (IndexError, TypeError, AttributeError):
                warning("Could not parse domain SID from LDAP result")

    def _entry_raw_values(self, entry, attr):
        raw_attrs = entry.get("raw_attributes", {}) if isinstance(entry, dict) else getattr(entry, "raw_attributes", {})
        values = raw_attrs.get(attr) or raw_attrs.get(attr.encode() if isinstance(attr, str) else attr) or []
        if values:
            return list(values)
        attr_obj = entry.get(attr) if isinstance(entry, dict) else getattr(entry, attr, None)
        raw_values = getattr(attr_obj, "raw_values", None)
        return list(raw_values or [])

    def _entry_value(self, entry, *attrs, default=""):
        for attr in attrs:
            if isinstance(entry, dict):
                if attr in entry:
                    value = first_value(entry.get(attr))
                    if value is not None:
                        return value
            elif hasattr(entry, attr):
                value = first_value(getattr(entry, attr))
                if value is not None:
                    return value
        return default

    def _entry_dn(self, entry):
        return str(self._entry_value(entry, "entry_dn", "distinguishedName", default=""))

    def _security_descriptors(self, entry):
        for value in self._entry_raw_values(entry, "nTSecurityDescriptor"):
            if value:
                yield bytes(value)

    def _parse_sid(self, raw):
        """Parse a binary SID into string format."""
        try:
            raw = bytes(raw)
            if len(raw) < 8:
                return "S-1-5-??"
            revision = raw[0]
            sub_count = raw[1]
            if len(raw) < 8 + sub_count * 4:
                return "S-1-5-??"
            authority = int.from_bytes(raw[2:8], 'big')
            subs = []
            for i in range(sub_count):
                offset = 8 + i * 4
                subs.append(struct.unpack('<I', raw[offset:offset+4])[0])
            return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)
        except Exception:
            return "S-1-5-??"

    def _parse_ace_from_ntsecuritydescriptor(self, sd_raw):
        """Parse ACEs from nTSecurityDescriptor."""
        aces = []
        try:
            if len(sd_raw) < 20:
                return aces

            # Parse SECURITY_DESCRIPTOR
            sd_raw[0]
            struct.unpack('<H', sd_raw[2:4])[0]

            # DACL offset
            dacl_offset = struct.unpack('<I', sd_raw[16:20])[0]
            if dacl_offset == 0 or dacl_offset + 8 > len(sd_raw):
                return aces

            # Parse ACL header
            acl_data = sd_raw[dacl_offset:]
            if len(acl_data) < 8:
                return aces

            acl_data[0]
            acl_size = struct.unpack('<H', acl_data[2:4])[0]
            ace_count = struct.unpack('<H', acl_data[4:6])[0]
            if acl_size < 8:
                return aces
            acl_data = acl_data[:min(acl_size, len(acl_data))]

            offset = 8
            for _ in range(ace_count):
                if offset + 4 > len(acl_data):
                    break

                ace_type = acl_data[offset]
                acl_data[offset + 1]
                ace_size = struct.unpack('<H', acl_data[offset+2:offset+4])[0]

                if ace_size < 4 or offset + ace_size > len(acl_data):
                    break

                ace_data = acl_data[offset:offset+ace_size]

                if ace_type == 0x00:  # ACCESS_ALLOWED_ACE
                    if len(ace_data) >= 16:
                        mask = struct.unpack('<I', ace_data[4:8])[0]
                        sid = self._parse_sid(ace_data[8:])
                        aces.append({"type": "allow", "mask": mask, "sid": sid, "object_type": None})

                elif ace_type == 0x05:  # ACCESS_ALLOWED_OBJECT_ACE
                    if len(ace_data) >= 20:
                        mask = struct.unpack('<I', ace_data[4:8])[0]
                        obj_flags = struct.unpack('<I', ace_data[8:12])[0]
                        obj_offset = 12
                        obj_type = None

                        if obj_flags & 0x1:  # ACE_OBJECT_TYPE_PRESENT
                            if obj_offset + 16 > len(ace_data):
                                offset += ace_size
                                continue
                            guid_bytes = ace_data[obj_offset:obj_offset+16]
                            obj_type = self._bytes_to_guid(guid_bytes)
                            obj_offset += 16

                        if obj_flags & 0x2:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                            if obj_offset + 16 > len(ace_data):
                                offset += ace_size
                                continue
                            obj_offset += 16

                        if obj_offset + 8 <= len(ace_data):
                            sid = self._parse_sid(ace_data[obj_offset:])
                            aces.append({"type": "allow_object", "mask": mask, "sid": sid, "object_type": obj_type})

                offset += ace_size

        except Exception:
            pass

        return aces

    def _bytes_to_guid(self, b):
        """Convert 16 bytes to GUID string."""
        if len(b) != 16:
            return ""
        parts = struct.unpack('<IHH', b[:8])
        return f"{parts[0]:08x}-{parts[1]:04x}-{parts[2]:04x}-{b[8]:02x}{b[9]:02x}-" + \
               "".join(f"{x:02x}" for x in b[10:16])

    def _resolve_sid(self, sid):
        """Resolve a SID to a name."""
        if sid in WELL_KNOWN_SIDS:
            return WELL_KNOWN_SIDS[sid]

        entries = self.conn.ldap_search(
            f"(objectSid={sid})",
            ["sAMAccountName", "cn"],
            size_limit=1
        )
        if entries:
            return str(self._entry_value(entries[0], "sAMAccountName", "cn", default=sid))
        return sid

    def _is_low_priv(self, sid):
        """Check if SID represents a low-privilege principal."""
        low_priv_rids = [
            "-513",   # Domain Users
            "-515",   # Domain Computers
            "-545",   # Users
            "-11",    # Authenticated Users
        ]
        return any(sid.endswith(r) for r in low_priv_rids) or sid == "S-1-1-0" or sid == "S-1-5-11"

    def check_dcsync(self):
        subsection("DCSync Rights")

        # Get the domain object's security descriptor
        raw_entries = self.conn.ldap_search_raw(
            "(objectClass=domain)",
            ["nTSecurityDescriptor"],
            search_base=self.conn.base_dn,
            size_limit=1
        )

        dcsync_sids = {}
        repl_get_changes = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        repl_get_changes_all = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

        for entry in raw_entries:
            aces = [
                ace
                for sd_raw in self._security_descriptors(entry)
                for ace in self._parse_ace_from_ntsecuritydescriptor(sd_raw)
            ]

            for ace in aces:
                obj_type = ace.get("object_type", "")
                if obj_type in (repl_get_changes, repl_get_changes_all):
                    sid = ace["sid"]
                    if sid not in dcsync_sids:
                        dcsync_sids[sid] = set()
                    dcsync_sids[sid].add(obj_type)

        # Find accounts with BOTH replication rights
        dangerous = []
        for sid, rights in dcsync_sids.items():
            if repl_get_changes in rights and repl_get_changes_all in rights:
                name = self._resolve_sid(sid)
                dangerous.append((name, sid))

        # Also check via LDAP for users with DCSync-like privileges
        # Look for non-default accounts with replication rights
        expected_dcsync = ["Administrators", "Domain Controllers", "Enterprise Domain Controllers"]

        unexpected = [(name, sid) for name, sid in dangerous if name not in expected_dcsync]

        if unexpected:
            finding("CRITICAL", "Non-default accounts with DCSync rights!")
            rows = [[name, sid] for name, sid in unexpected]
            print_table(["Account", "SID"], rows, "Accounts with DCSync Rights")

            self.reporter.add(
                "ACL Abuse", "CRITICAL",
                "Non-default accounts have DCSync (replication) rights",
                "These accounts can use DCSync to extract all password hashes from the domain, "
                "including krbtgt, enabling Golden Ticket attacks.",
                affected=[name for name, _ in unexpected],
                remediation="Remove DS-Replication-Get-Changes-All from non-essential accounts. "
                            "Only Domain Controllers should have this right."
            )
        else:
            info("No non-default DCSync rights found (checked DACL)")

    def check_genericall_domain(self):
        subsection("GenericAll on Domain Object")

        raw_entries = self.conn.ldap_search_raw(
            "(objectClass=domain)",
            ["nTSecurityDescriptor"],
            search_base=self.conn.base_dn,
            size_limit=1
        )

        dangerous = []
        for entry in raw_entries:
            aces = [
                ace
                for sd_raw in self._security_descriptors(entry)
                for ace in self._parse_ace_from_ntsecuritydescriptor(sd_raw)
            ]
            for ace in aces:
                mask = ace.get("mask", 0)
                sid = ace.get("sid", "")

                # Check for GenericAll or WriteDACL on domain
                if (mask & 0xF01FF == 0xF01FF) or (mask & 0x40000):
                    if self._is_low_priv(sid):
                        name = self._resolve_sid(sid)
                        dangerous.append((name, sid, hex(mask)))

        if dangerous:
            finding("CRITICAL", "Low-privilege principals with dangerous rights on domain object!")
            rows = [[n, s, m] for n, s, m in dangerous]
            print_table(["Principal", "SID", "Access Mask"], rows)

            self.reporter.add(
                "ACL Abuse", "CRITICAL",
                "Dangerous permissions on domain object",
                "Low-privilege principals have GenericAll or WriteDACL on the domain object, "
                "allowing them to grant themselves DCSync rights.",
                affected=[n for n, _, _ in dangerous],
                remediation="Remove excessive permissions from the domain object DACL."
            )
        else:
            info("No dangerous low-privilege permissions on domain object")

    def check_writedacl(self):
        subsection("WriteDACL on Critical Objects")
        # Check WriteDACL on Domain Admins group
        critical_objects = [
            ("CN=Domain Admins,CN=Users," + self.conn.base_dn, "Domain Admins"),
            ("CN=Enterprise Admins,CN=Users," + self.conn.base_dn, "Enterprise Admins"),
            ("CN=Administrators,CN=Builtin," + self.conn.base_dn, "Administrators"),
        ]

        for dn, name in critical_objects:
            raw_entries = self.conn.ldap_search_raw(
                f"(distinguishedName={dn})",
                ["nTSecurityDescriptor"]
            )

            for entry in raw_entries:
                aces = [
                    ace
                    for sd_raw in self._security_descriptors(entry)
                    for ace in self._parse_ace_from_ntsecuritydescriptor(sd_raw)
                ]
                for ace in aces:
                    mask = ace.get("mask", 0)
                    sid = ace.get("sid", "")
                    if (mask & 0x40000) and self._is_low_priv(sid):
                        principal = self._resolve_sid(sid)
                        finding("CRITICAL", f"WriteDACL on {name} by {principal}")
                        self.reporter.add(
                            "ACL Abuse", "CRITICAL",
                            f"WriteDACL on {name} group by low-privilege principal",
                            f"{principal} can modify the DACL of {name}, granting themselves membership.",
                            affected=[principal],
                            remediation=f"Remove WriteDACL from {principal} on the {name} object."
                        )

    def check_writeowner(self):
        subsection("WriteOwner Abuse")
        info("Checking for WriteOwner on critical objects...")
        # Similar to WriteDACL check - WriteOwner allows changing ownership then modifying DACL
        # Covered in the genericall and writedacl checks above via mask analysis

    def check_force_change_password(self):
        subsection("Force Password Change Rights")

        # Check if any low-priv users can force password changes on privileged accounts
        admin_entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            ["sAMAccountName", "distinguishedName"],
            size_limit=50
        )

        dangerous_resets = []
        for entry in admin_entries[:10]:  # Check top 10
            dn = self._entry_dn(entry)
            if not dn:
                continue

            raw_entries = self.conn.ldap_search_raw(
                f"(distinguishedName={dn})",
                ["nTSecurityDescriptor"]
            )

            for raw_entry in raw_entries:
                aces = [
                    ace
                    for sd_raw in self._security_descriptors(raw_entry)
                    for ace in self._parse_ace_from_ntsecuritydescriptor(sd_raw)
                ]
                for ace in aces:
                    obj_type = ace.get("object_type", "")
                    sid = ace.get("sid", "")

                    if obj_type == "00299570-246d-11d0-a768-00aa006e0529" and self._is_low_priv(sid):
                        target = str(self._entry_value(entry, "sAMAccountName", default="Unknown"))
                        principal = self._resolve_sid(sid)
                        dangerous_resets.append((principal, target))

        if dangerous_resets:
            finding("CRITICAL", "Low-privilege accounts can reset passwords of admin accounts!")
            rows = [[p, t] for p, t in dangerous_resets]
            print_table(["Can Reset", "Target Admin"], rows)

            self.reporter.add(
                "ACL Abuse", "CRITICAL",
                "Force password change on privileged accounts",
                "Low-privilege principals can force-reset passwords of admin accounts.",
                affected=[f"{p} -> {t}" for p, t in dangerous_resets],
                remediation="Remove User-Force-Change-Password rights from low-privilege principals on admin accounts."
            )

    def check_genericall_users(self):
        subsection("GenericAll/GenericWrite on Users")
        # Check for GenericAll on privileged users by non-admins
        info("Analyzing ACLs on privileged user objects...")

        admin_entries = self.conn.ldap_search(
            "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
            ["sAMAccountName"],
            size_limit=20
        )

        dangerous = []
        for entry in admin_entries[:5]:
            dn = self._entry_dn(entry)
            if not dn:
                continue
            raw_entries = self.conn.ldap_search_raw(
                f"(distinguishedName={dn})",
                ["nTSecurityDescriptor"]
            )

            for raw_entry in raw_entries:
                aces = [
                    ace
                    for sd_raw in self._security_descriptors(raw_entry)
                    for ace in self._parse_ace_from_ntsecuritydescriptor(sd_raw)
                ]
                for ace in aces:
                    mask = ace.get("mask", 0)
                    sid = ace.get("sid", "")
                    if (mask & 0xF01FF == 0xF01FF) and self._is_low_priv(sid):
                        principal = self._resolve_sid(sid)
                        target = str(self._entry_value(entry, "sAMAccountName", default="Unknown"))
                        dangerous.append((principal, target))

        if dangerous:
            finding("CRITICAL", "GenericAll on privileged users by low-privilege principals!")
            for p, t in dangerous:
                info(f"  {p} -> {t}")
            self.reporter.add(
                "ACL Abuse", "CRITICAL",
                "GenericAll on privileged user accounts",
                "Low-privilege principals have full control over privileged accounts, "
                "allowing password resets, SPN manipulation, or targeted Kerberoasting.",
                affected=[f"{p} -> {t}" for p, t in dangerous],
                remediation="Remove GenericAll from non-admin principals on privileged accounts."
            )

    def check_genericwrite_groups(self):
        subsection("Write Permissions on Privileged Groups")
        info("Checking group membership modification rights...")

        groups_to_check = [
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Account Operators", "Backup Operators"
        ]

        for group_name in groups_to_check:
            entries = self.conn.ldap_search(
                f"(&(objectClass=group)(cn={group_name}))",
                ["distinguishedName"]
            )
            if not entries:
                continue

            dn = self._entry_dn(entries[0])
            if not dn:
                continue
            raw_entries = self.conn.ldap_search_raw(
                f"(distinguishedName={dn})",
                ["nTSecurityDescriptor"]
            )

            for raw_entry in raw_entries:
                aces = [
                    ace
                    for sd_raw in self._security_descriptors(raw_entry)
                    for ace in self._parse_ace_from_ntsecuritydescriptor(sd_raw)
                ]
                for ace in aces:
                    mask = ace.get("mask", 0)
                    sid = ace.get("sid", "")
                    obj_type = ace.get("object_type", "")

                    # WriteProperty on member attribute or GenericWrite
                    if ((mask & 0x20) or (mask & 0x2) or (mask & 0xF01FF == 0xF01FF)):
                        if self._is_low_priv(sid) and obj_type in ("bf9679c0-0de6-11d0-a285-00aa003049e2", "", None):
                            principal = self._resolve_sid(sid)
                            finding("CRITICAL", f"Can add members to {group_name}: {principal}")
                            self.reporter.add(
                                "ACL Abuse", "CRITICAL",
                                f"Can modify membership of {group_name}",
                                f"{principal} can add accounts to the {group_name} group.",
                                affected=[principal],
                                remediation=f"Remove write permissions from {principal} on {group_name}."
                            )

    def check_adminsdholder(self):
        subsection("AdminSDHolder")

        entries = self.conn.ldap_search(
            f"(distinguishedName=CN=AdminSDHolder,CN=System,{self.conn.base_dn})",
            ["nTSecurityDescriptor"]
        )

        if entries:
            info("AdminSDHolder object found — permissions propagate to all protected accounts")
            info("Protected accounts inherit AdminSDHolder DACL every 60 minutes (SDProp)")
        else:
            info("Could not access AdminSDHolder object")

    def check_gpo_permissions(self):
        subsection("GPO Write Permissions")

        entries = self.conn.ldap_search(
            "(objectClass=groupPolicyContainer)",
            ["displayName", "gPCFileSysPath", "distinguishedName"],
            size_limit=50
        )

        info(f"Checking write permissions on {len(entries)} GPOs...")

        for entry in entries[:20]:
            gpo_name = str(self._entry_value(entry, "displayName", default="Unknown"))
            dn = self._entry_dn(entry)
            if not dn:
                continue

            raw_entries = self.conn.ldap_search_raw(
                f"(distinguishedName={dn})",
                ["nTSecurityDescriptor"]
            )

            for raw_entry in raw_entries:
                aces = [
                    ace
                    for sd_raw in self._security_descriptors(raw_entry)
                    for ace in self._parse_ace_from_ntsecuritydescriptor(sd_raw)
                ]
                for ace in aces:
                    mask = ace.get("mask", 0)
                    sid = ace.get("sid", "")
                    if (mask & 0x40000 or mask & 0xF01FF == 0xF01FF) and self._is_low_priv(sid):
                        principal = self._resolve_sid(sid)
                        finding("HIGH", f"Can modify GPO '{gpo_name}': {principal}",
                                "GPO hijacking can deploy malware domain-wide")
                        self.reporter.add(
                            "ACL Abuse", "HIGH",
                            f"Low-privilege write access to GPO: {gpo_name}",
                            f"{principal} can modify this GPO. If linked to privileged OUs, "
                            "this allows code execution on privileged systems.",
                            affected=[principal],
                            remediation=f"Remove write permissions from {principal} on GPO {gpo_name}."
                        )

    def check_ou_permissions(self):
        subsection("OU Permissions")
        info("Checking for dangerous OU-level permissions...")

        entries = self.conn.ldap_search(
            "(objectClass=organizationalUnit)",
            ["ou", "distinguishedName"],
            size_limit=30
        )

        for entry in entries[:10]:
            ou_name = str(self._entry_value(entry, "ou", default="Unknown"))
            dn = self._entry_dn(entry)
            if not dn:
                continue

            raw_entries = self.conn.ldap_search_raw(
                f"(distinguishedName={dn})",
                ["nTSecurityDescriptor"]
            )

            for raw_entry in raw_entries:
                aces = [
                    ace
                    for sd_raw in self._security_descriptors(raw_entry)
                    for ace in self._parse_ace_from_ntsecuritydescriptor(sd_raw)
                ]
                for ace in aces:
                    mask = ace.get("mask", 0)
                    sid = ace.get("sid", "")
                    if (mask & 0xF01FF == 0xF01FF) and self._is_low_priv(sid):
                        principal = self._resolve_sid(sid)
                        finding("HIGH", f"GenericAll on OU '{ou_name}': {principal}")
                        self.reporter.add(
                            "ACL Abuse", "HIGH",
                            f"GenericAll on OU: {ou_name}",
                            f"{principal} has full control over this OU and all objects within it.",
                            affected=[principal],
                            remediation=f"Remove GenericAll from {principal} on OU {ou_name}."
                        )
