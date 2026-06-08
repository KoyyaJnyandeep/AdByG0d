#!/usr/bin/env python3
"""
AdByG0d — SMB Posture Assessment Module v1.0

SCOPE: Read-only SMB metadata and LDAP-backed posture checks ONLY.
Detects SERVICE CONFIGURATIONS and POLICY STATES that create SMB
attack surface risk.

DOES NOT: Create, modify, or delete any files on any share.
DOES NOT: Bind to any RPC interface (no spooler, no scmr, no rrp).
DOES NOT: Send unauthenticated probes or craft raw SMB frames.
DOES NOT: Attempt to exploit any vulnerability.

Detection approach: uses the existing authenticated SMB connection
(established by the connector) to query share metadata and signing
state. SYSVOL checks enumerate file names only — no content is read.

Authorized enterprise security assessment use only.
"""

from ..core.banner import (
    module_header, subsection, finding, info, success,
    error, print_table, progress_bar
)

try:
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


# GPP XML filenames whose mere presence indicates a historical
# credential-exposure risk (MS14-025). We check existence only —
# no content is read, no cpassword values are extracted.
_GPP_SENSITIVE_NAMES = frozenset({
    'groups.xml', 'services.xml', 'scheduledtasks.xml',
    'datasources.xml', 'printers.xml', 'drives.xml',
})

# SMB dialect identifiers (from SMB2/3 negotiation)
_DIALECT_MAP = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}


def _share_field(share, key, default=""):
    try:
        value = share.get(key, default)
    except AttributeError:
        value = getattr(share, key, default)
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    value = str(value or default)
    return value.rstrip("\x00")


class SMBModule:
    """
    SMB posture assessment — read-only configuration checks.
    Uses the authenticated connection established by the connector;
    no additional SMB connections are opened.
    """

    NAME = "SMB Posture"
    DESCRIPTION = (
        "Read-only SMB security posture assessment: signing enforcement, "
        "null session exposure, share enumeration (no write testing), "
        "SYSVOL GPP file presence (no content read), SMB dialect version. "
        "No RPC binds, no file creation, no active probing."
    )

    def __init__(self, connector, reporter):
        self.conn = connector
        self.reporter = reporter

    def run(self):
        module_header(self.NAME, self.DESCRIPTION)

        checks = [
            ("SMB Signing Enforcement",   self.check_smb_signing),
            ("Null Session Access",        self.check_null_sessions),
            ("Share Enumeration",          self.enum_shares),
            ("SMB Protocol Version",       self.check_smb_versions),
            ("SYSVOL GPP File Presence",   self.check_sysvol_gpp),
        ]

        for i, (name, func) in enumerate(checks):
            progress_bar(i, len(checks), label=name)
            try:
                func()
            except Exception as e:
                error(f"  {name} failed: {e}")
        progress_bar(len(checks), len(checks), label="Complete")

        self.reporter.modules_run.append(self.NAME)

    # ── SMB Signing ────────────────────────────────────────────────

    def check_smb_signing(self):
        """
        Check SMB signing requirement using the existing authenticated
        connection. No new SMB connections are opened.
        """
        subsection("SMB Signing Enforcement")

        if not self.conn.smb_conn:
            info("SMB connection not available — skipping signing check")
            return

        try:
            signing_required = self.conn.smb_conn.isSigningRequired()
        except AttributeError:
            signing_required = getattr(
                self.conn.smb_conn, '_SMBConnection__signing_required', None
            )

        dc_label = self.conn.dc_ip or "DC"

        if signing_required is True:
            success(f"SMB signing is required on {dc_label}")
        elif signing_required is False:
            finding("HIGH", f"SMB signing NOT required on {dc_label}")
            self.reporter.add(
                self.NAME, "HIGH",
                f"SMB signing not required on Domain Controller ({dc_label})",
                "When SMB signing is not required on a Domain Controller, NTLM "
                "authentication captured or coerced from any domain machine can be "
                "relayed to SMB on that DC, enabling operations under the relayed "
                "identity without cracking the credential. Combined with NTLM coercion "
                "techniques this can result in Tier-0 compromise.",
                affected=[dc_label],
                remediation=(
                    "Require SMB signing on all DCs and member servers via GPO: "
                    "Computer Configuration > Windows Settings > Security Settings > "
                    "Local Policies > Security Options > "
                    "'Microsoft network server: Digitally sign communications (always)' = Enabled. "
                    "Also set the client-side policy to prevent relay from workstations."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/"
                    "microsoft-network-server-digitally-sign-communications-always",
                ],
            )
        else:
            info("Could not determine SMB signing state from existing connection")

    # ── Null Sessions ──────────────────────────────────────────────

    def check_null_sessions(self):
        """
        Attempt an unauthenticated (null session) SMB login to check
        if anonymous enumeration is permitted. Uses a transient
        connection that performs no share access — only tests whether
        the anonymous bind itself succeeds.
        """
        subsection("Null Session Access")

        if not HAS_IMPACKET:
            info("impacket not available — skipping null session check")
            return

        dc_ip = self.conn.dc_ip
        if not dc_ip:
            info("DC IP not known — skipping null session check")
            return

        null_session_ok = False
        smb = None
        try:
            smb = SMBConnection(dc_ip, dc_ip, timeout=5)
            smb.login('', '')  # empty username + password = null session
            null_session_ok = True
        except Exception:
            pass  # login failure = null session blocked (good)
        finally:
            if smb is not None:
                try:
                    smb.close()
                except Exception:
                    pass

        if null_session_ok:
            finding("MEDIUM", f"Null session login succeeded on {dc_ip}")
            self.reporter.add(
                self.NAME, "MEDIUM",
                f"Anonymous (null session) SMB access permitted on {dc_ip}",
                "The Domain Controller accepted an anonymous SMB bind. "
                "Null sessions can be used to enumerate user accounts, groups, "
                "and policy settings without credentials, providing reconnaissance "
                "data to an attacker inside the network.",
                affected=[dc_ip],
                remediation=(
                    "Set RestrictAnonymous = 1 (or 2) in HKLM\\SYSTEM\\CurrentControlSet\\"
                    "Control\\Lsa via GPO: "
                    "Computer Configuration > Windows Settings > Security Settings > "
                    "Local Policies > Security Options > "
                    "'Network access: Do not allow anonymous enumeration of SAM accounts and shares'."
                ),
            )
        else:
            success(f"Null session rejected on {dc_ip} (good)")

    # ── Share Enumeration ──────────────────────────────────────────

    def enum_shares(self):
        """
        List shares visible to the authenticated user. Read access is
        confirmed via listPath. Write access is NOT tested — no files
        are created or deleted.
        """
        subsection("Share Enumeration (Read Access Only)")

        if not self.conn.smb_conn:
            info("SMB connection not available — skipping share enumeration")
            return

        try:
            shares = self.conn.smb_conn.listShares()
        except Exception as e:
            error(f"Could not list shares: {e}")
            return

        rows = []
        readable_non_default = []

        default_shares = frozenset({"SYSVOL", "NETLOGON", "IPC$", "ADMIN$", "C$"})

        for share in shares:
            share_name = _share_field(share, "shi1_netname")
            if not share_name:
                continue
            remark = _share_field(share, "shi1_remark")

            can_read = False
            try:
                self.conn.smb_conn.listPath(share_name, '*')
                can_read = True
            except Exception:
                pass

            access = "READ" if can_read else "DENIED"
            rows.append([share_name, remark, access])

            if can_read and share_name.upper() not in default_shares:
                readable_non_default.append(share_name)

        if rows:
            print_table(["Share", "Remark", "Access"], rows, "SMB Shares")

        if readable_non_default:
            finding("LOW", f"Non-default readable shares: {', '.join(readable_non_default)}")
            self.reporter.add(
                self.NAME, "LOW",
                f"Non-default SMB shares readable by assessed account: "
                f"{', '.join(readable_non_default)}",
                "Non-default shares accessible to the current user should be reviewed "
                "for sensitive data exposure. Review share permissions and confirm that "
                "only authorized users have read access.",
                affected=readable_non_default,
                remediation=(
                    "Audit share ACLs and remove unnecessary read access. "
                    "Apply least-privilege share permissions. "
                    "Enable access-based enumeration (ABE) to hide shares users cannot access."
                ),
            )

    # ── SMB Version ────────────────────────────────────────────────

    def check_smb_versions(self):
        """
        Read the negotiated SMB dialect from the existing connection.
        No new connections are opened.
        """
        subsection("SMB Protocol Version")

        if not self.conn.smb_conn:
            info("SMB connection not available — cannot read dialect")
            return

        try:
            dialect = self.conn.smb_conn.getDialect()
        except Exception as e:
            info(f"Could not read SMB dialect: {e}")
            return

        try:
            dialect_int = int(dialect)
        except (TypeError, ValueError):
            dialect_int = 0
        version = _DIALECT_MAP.get(dialect_int, f"Unknown ({hex(dialect_int)})")
        dc_label = self.conn.dc_ip or "DC"
        info(f"  Negotiated dialect on {dc_label}: {version}")

        if dialect_int < 0x0300:
            finding("MEDIUM", f"SMB dialect below 3.0 on {dc_label}: {version}")
            self.reporter.add(
                self.NAME, "MEDIUM",
                f"Outdated SMB dialect negotiated on {dc_label}: {version}",
                f"SMB {version} lacks SMB 3.x encryption, pre-authentication integrity, "
                "and cluster dialect improvements. Allowing legacy dialects increases "
                "exposure to downgrade and relay attacks.",
                details={"dialect_hex": hex(dialect_int), "dialect_name": version},
                affected=[dc_label],
                remediation=(
                    "Set the minimum SMB dialect to 3.0 via Group Policy or registry: "
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\"
                    "SMB2 (enable), and configure SMBv1 disabled. "
                    "Audit clients for legacy OS versions that require older dialects."
                ),
            )
        else:
            success(f"Modern SMB dialect in use: {version}")

    # ── SYSVOL GPP File Presence ───────────────────────────────────

    def check_sysvol_gpp(self):
        """
        Walk SYSVOL (max depth 6) and report the PRESENCE of Group
        Policy Preferences XML files by name. File content is NOT
        read — this only detects whether the files exist, which is
        sufficient to flag the MS14-025 misconfiguration.
        """
        subsection("SYSVOL GPP File Presence (MS14-025)")

        if not self.conn.smb_conn:
            info("SMB connection not available — skipping SYSVOL check")
            return

        found_gpp = []
        try:
            self._walk_sysvol("SYSVOL", "\\", depth=0, max_depth=6,
                              found=found_gpp)
        except Exception as e:
            error(f"SYSVOL walk failed: {e}")
            return

        if found_gpp:
            finding("HIGH", f"GPP credential files found in SYSVOL: {len(found_gpp)} file(s)")
            self.reporter.add(
                self.NAME, "HIGH",
                f"Group Policy Preferences XML files present in SYSVOL ({len(found_gpp)} file(s))",
                "GPP XML files (groups.xml, services.xml, etc.) may contain a 'cpassword' "
                "attribute — an AES-encrypted password whose static key was published by "
                "Microsoft (MS14-025 / CVE-2014-1812). The mere presence of these files in "
                "SYSVOL means they are accessible to any authenticated domain user and should "
                "be treated as a credential exposure risk until verified clean. "
                "Note: this check reports file existence only — no content was read.",
                affected=found_gpp[:30],
                remediation=(
                    "1. Delete all GPP XML files from SYSVOL that contain cpassword values. "
                    "2. Rotate every password that was stored in GPP. "
                    "3. Remove the corresponding GPO preferences that produced these files. "
                    "4. Install MS14-025 on all Domain Controllers (included in later rollup patches). "
                    "Reference: https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-"
                    "group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-"
                    "60734e15-af79-26ca-ea53-8cd617073c30"
                ),
                references=[
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2014-1812",
                ],
            )
        else:
            success("No GPP credential files found in SYSVOL")

    def _walk_sysvol(self, share, path, depth, max_depth, found):
        """
        Enumerate SYSVOL by listing directory entries recursively.
        Records matching filenames into `found`. Does NOT read file
        content. Stops at max_depth to bound execution time.
        """
        if depth > max_depth:
            return

        try:
            entries = self.conn.smb_conn.listPath(share, path + "*")
        except Exception:
            return

        for entry in entries:
            name = entry.get_longname()
            if name in ('.', '..'):
                continue

            full_path = path + name

            if entry.is_directory():
                self._walk_sysvol(share, full_path + "\\",
                                  depth + 1, max_depth, found)
            elif name.lower() in _GPP_SENSITIVE_NAMES:
                found.append(f"{share}{full_path}")
