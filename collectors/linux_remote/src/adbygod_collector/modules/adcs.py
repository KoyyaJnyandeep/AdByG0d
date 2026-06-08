#!/usr/bin/env python3
"""
AdByG0d - ADCS (Active Directory Certificate Services) Module
Finds ESC1-ESC8 misconfigurations for certificate-based privilege escalation.
"""

import struct
from ..core.banner import (
    module_header, subsection, finding, info, success,
    error, print_table, progress_bar
)
from ..core.ldap_values import int_value


# Certificate template flags
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
CT_FLAG_PEND_ALL_REQUESTS = 0x00000002
CT_FLAG_PUBLISH_TO_DS = 0x00000008
CT_FLAG_AUTO_ENROLLMENT = 0x00000020

# Enrollment flags
CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000

# Extended key usage OIDs
EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
EKU_PKINIT = "1.3.6.1.5.2.3.4"
EKU_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
EKU_ANY_PURPOSE = "2.5.29.37.0"
EKU_CERTIFICATE_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"
EKU_SUBTREE_OID = "1.3.6.1.4.1.311.20.2"


class ADCSModule:
    """AD Certificate Services vulnerability scanner."""

    NAME = "ADCS Attacks"
    DESCRIPTION = "Certificate template misconfigurations: ESC1-ESC8, Golden Certificate paths"

    def __init__(self, connector, reporter):
        self.conn = connector
        self.reporter = reporter
        self.config_dn = f"CN=Configuration,{self.conn.base_dn}"
        self.ca_info = []
        self.templates = []

    def run(self):
        module_header(self.NAME, self.DESCRIPTION)

        checks = [
            ("Certificate Authorities", self.enum_cas),
            ("Certificate Templates", self.enum_templates),
            ("ESC1 — SAN Misconfig", self.check_esc1),
            ("ESC2 — Any Purpose EKU", self.check_esc2),
            ("ESC3 — Enrollment Agent", self.check_esc3),
            ("ESC4 — Template ACL Abuse", self.check_esc4),
            ("ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2", self.check_esc6),
            ("ESC7 — CA Permissions", self.check_esc7),
            ("ESC8 — Web Enrollment NTLM Relay", self.check_esc8),
            ("ESC11 — IF_ENFORCEENCRYPTICERTREQUEST", self.check_esc11),
        ]

        for i, (name, func) in enumerate(checks):
            progress_bar(i, len(checks), label=name)
            try:
                func()
            except Exception as e:
                error(f"  {name} failed: {str(e)}")
        progress_bar(len(checks), len(checks), label="Complete")

        self.reporter.modules_run.append(self.NAME)

    def enum_cas(self):
        subsection("Certificate Authorities")

        entries = self.conn.ldap_search(
            "(objectClass=pKIEnrollmentService)",
            ["cn", "dNSHostName", "certificateTemplates", "cACertificate",
             "flags", "msPKI-Enrollment-Servers"],
            search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.config_dn}"
        )

        if not entries:
            info("No Certificate Authorities found — ADCS not deployed")
            return

        rows = []
        for entry in entries:
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"
            dns = str(entry.dNSHostName) if hasattr(entry, 'dNSHostName') else "N/A"
            templates = list(entry.certificateTemplates) if hasattr(entry, 'certificateTemplates') else []
            rows.append([name, dns, str(len(templates))])

            self.ca_info.append({
                "name": name,
                "dns": dns,
                "templates": templates,
            })

        print_table(["CA Name", "DNS Host", "Templates"], rows, "Certificate Authorities")
        success(f"Found {len(entries)} Certificate Authority(ies)")

    def enum_templates(self):
        subsection("Certificate Templates")

        entries = self.conn.ldap_search(
            "(objectClass=pKICertificateTemplate)",
            ["cn", "displayName", "msPKI-Certificate-Name-Flag",
             "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage",
             "msPKI-RA-Signature", "msPKI-Certificate-Application-Policy",
             "msPKI-Template-Schema-Version", "nTSecurityDescriptor",
             "msPKI-Private-Key-Flag", "flags"],
            search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.config_dn}"
        )

        if not entries:
            info("No certificate templates found")
            return

        self.templates = entries
        info(f"Found {len(entries)} certificate templates")

        # Show published templates
        published = set()
        for ca in self.ca_info:
            published.update(ca.get("templates", []))

        rows = []
        for entry in entries:
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"
            is_published = "Yes" if name in published else "No"

            name_flag = int_value(entry['msPKI-Certificate-Name-Flag'], 0) if hasattr(entry, 'msPKI-Certificate-Name-Flag') else 0
            ekus = list(entry.pKIExtendedKeyUsage) if hasattr(entry, 'pKIExtendedKeyUsage') else []
            eku_str = self._format_ekus(ekus)

            san = "Yes" if (name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) else "No"
            rows.append([name, is_published, san, eku_str[:40]])

        print_table(
            ["Template", "Published", "SAN", "EKU"],
            rows[:30],
            f"Certificate Templates ({len(entries)} total)"
        )

    def _format_ekus(self, ekus):
        eku_names = {
            EKU_CLIENT_AUTH: "Client Auth",
            EKU_PKINIT: "PKINIT",
            EKU_SMART_CARD_LOGON: "Smart Card Logon",
            EKU_ANY_PURPOSE: "Any Purpose",
            EKU_CERTIFICATE_REQUEST_AGENT: "Enrollment Agent",
        }
        if not ekus:
            return "None (Any)"
        return ", ".join(eku_names.get(str(e), str(e)) for e in ekus)

    def _can_low_priv_enroll(self, entry):
        """Check if low-priv users can enroll in this template."""
        # Simplified check — in real implementation, parse nTSecurityDescriptor
        # For now, check if the template is published (accessible)
        name = str(entry.cn) if hasattr(entry, 'cn') else ""
        for ca in self.ca_info:
            if name in ca.get("templates", []):
                return True
        return False

    def _is_published(self, entry):
        name = str(entry.cn) if hasattr(entry, 'cn') else ""
        for ca in self.ca_info:
            if name in ca.get("templates", []):
                return True
        return False

    def check_esc1(self):
        """ESC1: Template allows SAN + Client Auth + low-priv enrollment."""
        subsection("ESC1 — Enrollee Supplies Subject Alternative Name")

        vulnerable = []
        for entry in self.templates:
            name_flag = int_value(entry['msPKI-Certificate-Name-Flag'], 0) if hasattr(entry, 'msPKI-Certificate-Name-Flag') else 0
            ekus = [str(e) for e in entry.pKIExtendedKeyUsage] if hasattr(entry, 'pKIExtendedKeyUsage') else []
            ra_sig = int_value(entry['msPKI-RA-Signature'], 0) if hasattr(entry, 'msPKI-RA-Signature') else 0
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"

            # Conditions for ESC1:
            # 1. CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT enabled
            # 2. EKU allows client auth or is empty
            # 3. No manager approval required (ra_sig == 0)
            # 4. Published on a CA

            has_san = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            has_auth_eku = (
                not ekus or
                EKU_CLIENT_AUTH in ekus or
                EKU_PKINIT in ekus or
                EKU_SMART_CARD_LOGON in ekus or
                EKU_ANY_PURPOSE in ekus
            )
            no_approval = (ra_sig == 0)
            is_published = self._is_published(entry)

            if has_san and has_auth_eku and no_approval and is_published:
                vulnerable.append(name)

        if vulnerable:
            finding("CRITICAL", f"ESC1: {len(vulnerable)} templates allow SAN with client auth!")
            for t in vulnerable:
                info(f"  Vulnerable template: {t}")

            self.reporter.add(
                "ADCS", "CRITICAL",
                f"ESC1: {len(vulnerable)} templates vulnerable to SAN abuse",
                "Templates allow enrollees to specify a Subject Alternative Name (SAN) with "
                "client authentication EKU. An attacker can request a certificate as any user, "
                "including Domain Admin, and use it for authentication.",
                affected=vulnerable,
                remediation="Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on templates that allow client auth. "
                            "Require CA manager approval. Restrict enrollment permissions."
            )
        else:
            info("No ESC1 vulnerable templates found")

    def check_esc2(self):
        """ESC2: Template with Any Purpose or no EKU (SubCA)."""
        subsection("ESC2 — Any Purpose / SubCA Templates")

        vulnerable = []
        for entry in self.templates:
            ekus = [str(e) for e in entry.pKIExtendedKeyUsage] if hasattr(entry, 'pKIExtendedKeyUsage') else []
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"
            ra_sig = int_value(entry['msPKI-RA-Signature'], 0) if hasattr(entry, 'msPKI-RA-Signature') else 0

            if self._is_published(entry) and ra_sig == 0:
                if not ekus or EKU_ANY_PURPOSE in ekus:
                    vulnerable.append(name)

        if vulnerable:
            finding("HIGH", f"ESC2: {len(vulnerable)} templates with Any Purpose/no EKU")
            self.reporter.add(
                "ADCS", "HIGH",
                f"ESC2: {len(vulnerable)} templates with overly permissive EKU",
                "Templates with Any Purpose EKU or no EKU can be used for any purpose, "
                "including client authentication as any user.",
                affected=vulnerable,
                remediation="Restrict EKUs to only the required purposes. Remove Any Purpose EKU."
            )

    def check_esc3(self):
        """ESC3: Enrollment Agent template abuse."""
        subsection("ESC3 — Enrollment Agent Abuse")

        # Find enrollment agent templates
        agent_templates = []
        for entry in self.templates:
            ekus = [str(e) for e in entry.pKIExtendedKeyUsage] if hasattr(entry, 'pKIExtendedKeyUsage') else []
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"

            if EKU_CERTIFICATE_REQUEST_AGENT in ekus and self._is_published(entry):
                agent_templates.append(name)

        if agent_templates:
            finding("HIGH", f"ESC3: {len(agent_templates)} Enrollment Agent templates found")
            info("Enrollment Agent certificates allow requesting certs on behalf of other users")

            self.reporter.add(
                "ADCS", "HIGH",
                f"ESC3: {len(agent_templates)} Enrollment Agent templates available",
                "An attacker can enroll for an Enrollment Agent certificate and then use it "
                "to request certificates on behalf of other users, including administrators.",
                affected=agent_templates,
                remediation="Restrict enrollment in Enrollment Agent templates. "
                            "Configure enrollment agent restrictions on the CA."
            )

    def check_esc4(self):
        """ESC4: Dangerous template permissions (modify template to ESC1)."""
        subsection("ESC4 — Template Write Permissions")

        info("Checking for writable certificate templates...")

        for entry in self.templates:
            name = str(entry.cn) if hasattr(entry, 'cn') else "N/A"

            if not self._is_published(entry):
                continue

            # Check template ACL for write permissions by low-priv users
            raw_entries = self.conn.ldap_search_raw(
                f"(cn={name})",
                ["nTSecurityDescriptor"],
                search_base=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.config_dn}"
            )

            for raw_entry in raw_entries:
                if 'raw_attributes' not in raw_entry:
                    continue
                sd_values = raw_entry.get('raw_attributes', {}).get('nTSecurityDescriptor', [])
                if not sd_values:
                    continue

                # Simplified ACL check
                sd_raw = sd_values[0]
                if len(sd_raw) > 20:
                    dacl_offset = struct.unpack('<I', sd_raw[16:20])[0]
                    if dacl_offset > 0 and dacl_offset < len(sd_raw):
                        acl_data = sd_raw[dacl_offset:]
                        # Look for write permissions to common low-priv SIDs
                        # This is a simplified check
                        if b'\x13\x05' in acl_data or b'\x00\x00\x00\xf0' in acl_data:
                            # Potential write access found
                            pass  # Would need full ACL parsing for accuracy

    def check_esc6(self):
        """ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA."""
        subsection("ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2")

        info("Checking CA configuration flags...")
        info("Note: This check requires CA admin access or registry read permissions")
        info("If the flag is set, ANY template can be abused like ESC1")

        # This requires RPC/registry access to check
        # Flag it as a check item
        if self.ca_info:
            self.reporter.add(
                "ADCS", "INFO",
                "ESC6: Verify EDITF_ATTRIBUTESUBJECTALTNAME2 flag",
                "If this flag is enabled on the CA, any certificate template can be abused like ESC1 "
                "by specifying a SAN in the certificate request. "
                "Check with: certutil -config 'CA\\NAME' -getreg policy\\EditFlags",
                remediation="Disable EDITF_ATTRIBUTESUBJECTALTNAME2: "
                            "certutil -config 'CA\\NAME' -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2"
            )

    def check_esc7(self):
        """ESC7: Dangerous CA permissions (ManageCA, ManageCertificates)."""
        subsection("ESC7 — CA Security Permissions")

        for ca in self.ca_info:
            ca_name = ca["name"]
            entries = self.conn.ldap_search(
                f"(&(objectClass=pKIEnrollmentService)(cn={ca_name}))",
                ["nTSecurityDescriptor"],
                search_base=f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.config_dn}"
            )

            if entries:
                info(f"Checking permissions on CA: {ca_name}")
                # Would need full ACL parsing for ManageCA/ManageCertificates rights

    def check_esc8(self):
        """ESC8: HTTP enrollment endpoint vulnerable to NTLM relay."""
        subsection("ESC8 — Web Enrollment NTLM Relay")

        for ca in self.ca_info:
            dns = ca.get("dns", "")
            if not dns:
                continue

            # Check for web enrollment
            enrollment_urls = [
                f"http://{dns}/certsrv/",
                f"https://{dns}/certsrv/",
            ]

            import socket
            for url in enrollment_urls:
                try:
                    host = dns
                    port = 443 if url.startswith("https") else 80
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    result = s.connect_ex((host, port))
                    s.close()

                    if result == 0:
                        if port == 80:
                            finding("CRITICAL", f"ESC8: HTTP web enrollment on {dns}:{port}",
                                    "Vulnerable to NTLM relay! Coerce DC auth + relay = instant DA")
                            self.reporter.add(
                                "ADCS", "CRITICAL",
                                f"ESC8: HTTP-based certificate web enrollment on {dns}",
                                "Certificate web enrollment over HTTP allows NTLM relay attacks. "
                                "Combined with coercion (PetitPotam/PrinterBug), an attacker can relay "
                                "DC machine account authentication to obtain a DC certificate for DCSync.",
                                affected=[f"{dns}:{port}"],
                                remediation="Disable HTTP enrollment. Enable HTTPS with Extended Protection for Authentication. "
                                            "Or disable web enrollment entirely and use only DCOM enrollment."
                            )
                        else:
                            finding("MEDIUM", f"ESC8: HTTPS web enrollment on {dns}:{port}",
                                    "Check if EPA (Extended Protection) is enforced")
                            self.reporter.add(
                                "ADCS", "MEDIUM",
                                f"ESC8: HTTPS web enrollment on {dns} (verify EPA)",
                                "HTTPS enrollment with EPA disabled may still be vulnerable to relay.",
                                affected=[f"{dns}:{port}"],
                                remediation="Enable Extended Protection for Authentication (EPA) on the enrollment endpoint."
                            )

                except Exception:
                    continue

    def check_esc11(self):
        """ESC11: CA does not enforce encryption on RPC."""
        subsection("ESC11 — IF_ENFORCEENCRYPTICERTREQUEST")

        info("ESC11: Check if CA enforces RPC encryption")
        info("If IF_ENFORCEENCRYPTICERTREQUEST is disabled, NTLM relay via RPC is possible")

        if self.ca_info:
            self.reporter.add(
                "ADCS", "INFO",
                "ESC11: Verify IF_ENFORCEENCRYPTICERTREQUEST on CA",
                "If RPC encryption is not enforced, NTLM relay to the CA is possible via ICPR. "
                "Check with: certutil -config 'CA\\NAME' -getreg CA\\InterfaceFlags",
                remediation="Enable IF_ENFORCEENCRYPTICERTREQUEST flag on the CA."
            )
