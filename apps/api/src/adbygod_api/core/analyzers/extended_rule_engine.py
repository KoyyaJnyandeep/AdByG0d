from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Any


_ORIGINAL_PATH = Path(__file__).with_name("rule_engine.py")
_SPEC = importlib.util.spec_from_file_location("_adbygod_original_rule_engine", _ORIGINAL_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError(f"Cannot load original rule engine from {_ORIGINAL_PATH}")
_original = importlib.util.module_from_spec(_SPEC)
sys.modules.setdefault("_adbygod_original_rule_engine", _original)
_SPEC.loader.exec_module(_original)

Rule = _original.Rule
RuleMatch = _original.RuleMatch
_BaseRuleEngine = _original.RuleEngine
_entity_name_map = _original._entity_name_map
_adcs_object = _original._adcs_object


LOW_PRIV_MARKERS = (
    "everyone", "authenticated users", "domain users", "domain computers",
    "builtin\\users", "users", "helpdesk", "workstation admins",
)
PRIV_MARKERS = (
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "domain controllers", "enterprise domain controllers", "system",
    "cert publishers", "ca admins", "certificate service",
)
PKI_ADMIN_MARKERS = (
    "pki admins", "pki administrators", "certificate admins",
    "certificate administrators", "cert admins", "ca managers",
)
PRIV_RIDS = {"512", "516", "518", "519", "520", "544"}
SECRET_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|apikey|api[_ -]?key)\s*[:=]\s*\S+")


def _label(entity: dict[str, Any] | None) -> str:
    if not entity:
        return ""
    return (
        entity.get("sam_account_name")
        or entity.get("display_name")
        or entity.get("dns_hostname")
        or entity.get("id")
        or ""
    )


def _is_privileged(entity: dict[str, Any] | None) -> bool:
    if not entity:
        return False
    name = _label(entity).lower()
    rid = str(entity.get("object_sid") or entity.get("id") or "").rsplit("-", 1)[-1]
    return bool(
        entity.get("is_admin_count")
        or entity.get("tier") == 0
        or entity.get("is_crown_jewel")
        or rid in PRIV_RIDS
        or any(marker in name for marker in PRIV_MARKERS)
    )


def _principal_is_privileged(*, name: Any = "", sid: Any = "", entity: dict[str, Any] | None = None) -> bool:
    if entity is not None and _is_privileged(entity):
        return True
    name_text = str(name or "").strip().lower()
    sid_text = str(sid or "").strip()
    rid = sid_text.rsplit("-", 1)[-1] if "-" in sid_text else ""
    return bool(
        rid in PRIV_RIDS
        or sid_text in {"S-1-5-18", "S-1-5-9", "S-1-5-32-544"}
        or any(marker in name_text for marker in PRIV_MARKERS)
    )


def _principal_matches_identity(principal: dict[str, Any], *, name: Any = "", sid: Any = "") -> bool:
    name_text = str(name or "").strip().lower()
    sid_text = str(sid or "").strip().lower()
    candidates = {
        str(principal.get("id") or "").strip().lower(),
        str(principal.get("object_sid") or "").strip().lower(),
        str(principal.get("sid") or "").strip().lower(),
        str(principal.get("sam_account_name") or "").strip().lower(),
        str(principal.get("display_name") or "").strip().lower(),
        str(principal.get("name") or "").strip().lower(),
        str(principal.get("distinguished_name") or "").strip().lower(),
    }
    return bool((sid_text and sid_text in candidates) or (name_text and name_text in candidates))


def _principal_is_pki_authorized(data: dict[str, Any], ca: dict[str, Any], perm: dict[str, Any], *, name: Any = "", sid: Any = "") -> bool:
    if _principal_is_privileged(name=name, sid=sid):
        return True
    if any(perm.get(k) for k in ("is_authorized_pki_admin", "is_pki_admin", "approved_pki_admin", "is_ca_admin")):
        return True

    name_text = str(name or "").strip().lower()
    if any(marker in name_text for marker in PKI_ADMIN_MARKERS):
        return True

    approved = []
    for key in ("approved_pki_admins", "authorized_pki_admins", "pki_admin_principals", "ca_admin_principals"):
        approved.extend(ca.get(key, []) or [])
        approved.extend(data.get(key, []) or [])
    metadata = data.get("metadata") or {}
    for key in ("approved_pki_admins", "authorized_pki_admins", "pki_admin_principals", "ca_admin_principals"):
        approved.extend(metadata.get(key, []) or [])

    for principal in approved:
        if isinstance(principal, dict):
            if _principal_matches_identity(principal, name=name, sid=sid):
                return True
        else:
            text = str(principal or "").strip().lower()
            if text and text in {name_text, str(sid or "").strip().lower()}:
                return True
    return False


def _linked_group_is_privileged(value: Any, data: dict[str, Any] | None = None) -> bool:
    if isinstance(value, dict):
        if any(value.get(k) for k in ("is_privileged", "is_admin_count", "is_crown_jewel")):
            return True
        if value.get("tier") == 0:
            return True
        if any(value.get(k) is False for k in ("is_privileged", "is_admin_count", "is_crown_jewel")) and value.get("tier") not in (0, "0"):
            # Explicit custom metadata saying the linked group is not privileged
            # wins over ambiguous names such as department-admin labels.
            return False
        return _principal_is_privileged(
            name=value.get("name") or value.get("group") or value.get("display_name") or value.get("sam_account_name"),
            sid=value.get("sid") or value.get("object_sid") or value.get("group_sid"),
        )
    if _principal_is_privileged(name=value):
        return True
    if not data:
        return False

    name_text = str(value or "").strip().lower()
    for entity in data.get("entities", []) or []:
        if _principal_matches_identity(entity, name=name_text) and _is_privileged(entity):
            return True

    metadata = data.get("metadata") or {}
    privileged_groups = []
    for key in ("privileged_groups", "tier0_groups", "crown_jewel_groups"):
        privileged_groups.extend(data.get(key, []) or [])
        privileged_groups.extend(metadata.get(key, []) or [])
    for group in privileged_groups:
        if isinstance(group, dict):
            if _principal_matches_identity(group, name=name_text):
                return True
        elif str(group or "").strip().lower() == name_text:
            return True
    return False


def _is_low_priv_source(entity: dict[str, Any] | None) -> bool:
    if entity is None:
        return True
    if _is_privileged(entity):
        return False
    name = _label(entity).lower()
    rid = str(entity.get("object_sid") or entity.get("id") or "").rsplit("-", 1)[-1]
    return rid in {"513", "515"} or any(marker in name for marker in LOW_PRIV_MARKERS) or True


def _by_id(entities: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entity in entities:
        for key in (
            entity.get("id"),
            entity.get("object_sid"),
            entity.get("sam_account_name"),
            entity.get("display_name"),
            entity.get("distinguished_name"),
        ):
            if key:
                out[str(key)] = entity
    return out


def _edge_pairs(edges: list[dict[str, Any]], entities: list[dict[str, Any]], edge_types: set[str]) -> list[dict[str, Any]]:
    byid = _by_id(entities)
    pairs = []
    for edge in edges:
        if str(edge.get("edge_type") or "") not in edge_types:
            continue
        src = byid.get(str(edge.get("source_ref") or "")) or byid.get(str(edge.get("source_id") or ""))
        tgt = byid.get(str(edge.get("target_ref") or "")) or byid.get(str(edge.get("target_id") or ""))
        if not _is_low_priv_source(src):
            continue
        pairs.append({
            "source_principal": _label(src) or edge.get("source_ref") or edge.get("source_id"),
            "target_object": _label(tgt) or edge.get("target_ref") or edge.get("target_id"),
            "source_id": edge.get("source_ref") or edge.get("source_id"),
            "target_id": edge.get("target_ref") or edge.get("target_id"),
            "edge_type": edge.get("edge_type"),
            "provenance": edge.get("provenance"),
            "attributes": edge.get("attributes") or {},
        })
    return pairs


def _is_cert_template_object(entity: dict[str, Any] | None, target_dn: str) -> bool:
    if entity and entity.get("entity_type") == "CERT_TEMPLATE":
        return True
    dn = str(target_dn or "").lower()
    # Actual template objects live under CN=Certificate Templates. The
    # container itself is still an ESC5 PKI infrastructure object and should
    # remain in scope.
    return ",cn=certificate templates," in dn and not dn.startswith("cn=certificate templates,")


def _low_priv_enrollment(template: dict[str, Any]) -> bool:
    rights = template.get("enrollment_rights") or []
    for right in rights:
        if isinstance(right, dict):
            if right.get("is_low_privileged"):
                return True
            name = str(right.get("principal_name") or right.get("name") or right.get("trustee") or "").lower()
            sid = str(right.get("principal_sid") or right.get("trustee_sid") or "")
            if sid.endswith("-513") or sid in {"S-1-1-0", "S-1-5-11"} or any(m in name for m in LOW_PRIV_MARKERS):
                return True
        elif any(m in str(right).lower() for m in LOW_PRIV_MARKERS):
            return True
    return False


def _ca_configs(data: dict[str, Any]) -> list[dict[str, Any]]:
    configs: list[dict[str, Any]] = []
    for key in ("ca_flags", "adcs_ca_configs", "ca_configs"):
        for item in data.get(key, []) or []:
            if isinstance(item, dict):
                configs.append(item)
    for entity in data.get("entities", []) or []:
        if entity.get("entity_type") == "CA":
            attrs = dict(entity.get("attributes") or {})
            attrs.setdefault("ca_name", entity.get("display_name") or entity.get("sam_account_name"))
            attrs.setdefault("hostname", entity.get("dns_hostname"))
            configs.append(attrs)
    return configs


def _control_match(
    *,
    rule_id: str,
    rule_name: str,
    finding_type: str,
    module: str,
    title: str,
    description: str,
    severity: str,
    affected: list[Any],
    root_cause: str,
    remediation: str,
    technical_severity: float,
    references: list[str] | None = None,
    confidence: float = 0.95,
    mitre: list[str] | None = None,
) -> list[Any]:
    if not affected:
        return []
    return [RuleMatch(
        rule_id=rule_id, rule_name=rule_name, finding_type=finding_type,
        module=module, title=title, description=description,
        severity=severity, confidence=confidence,
        affected_objects=affected[:50], affected_count=len(affected),
        root_cause=root_cause,
        causal_chain=[
            "Normalized telemetry identifies a non-admin principal or weak posture condition",
            "The condition creates a credential, delegation, ACL, PKI, or lateral-movement attack path",
            "An attacker with the source access can convert the path into privilege escalation or persistence",
        ],
        remediation=remediation,
        remediation_steps=[
            "Validate the listed source and target objects against the source evidence",
            "Remove the excessive permission or harden the referenced configuration",
            "Add monitoring for future changes to the same attribute, ACL, or CA setting",
        ],
        fix_complexity="medium",
        references=references or ["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
        technical_severity=technical_severity, reachability=0.75,
        is_tier0_direct=severity == "CRITICAL",
        on_crown_jewel_path=severity == "CRITICAL",
        mitre_attack_ids=mitre or [],
    )]


class RuleEngine(_BaseRuleEngine):
    def _register_builtin_rules(self):
        super()._register_builtin_rules()
        self._register_coverage_expansion_rules()

    def _register_coverage_expansion_rules(self):
        def rule_esc5(data):
            entities = data.get("entities", [])
            byid = _by_id(entities)
            pki_targets = {
                e.get("id") for e in entities
                if e.get("entity_type") in {"CA", "CERT_TEMPLATE"}
                or "public key services" in str(e.get("distinguished_name") or "").lower()
                or "enrollment services" in str(e.get("distinguished_name") or "").lower()
                or "ntauthcertificates" in str(e.get("display_name") or e.get("sam_account_name") or "").lower()
            }
            affected = []
            for edge in data.get("edges", []) or []:
                if edge.get("edge_type") not in {"GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "HAS_CONTROL", "CA_PRIVATE_KEY_CONTROL", "GOLDEN_CERT"}:
                    continue
                target_key = edge.get("target_ref") or edge.get("target_id")
                target = byid.get(str(target_key))
                target_dn = str((target or {}).get("distinguished_name") or target_key or "")
                if _is_cert_template_object(target, target_dn):
                    continue
                target_name = _label(target) or str(target_key)
                is_pki = (
                    edge.get("target_id") in pki_targets
                    or edge.get("target_ref") in pki_targets
                    or "public key services" in target_dn.lower()
                    or (target or {}).get("entity_type") in {"CA", "CERT_TEMPLATE"}
                )
                source = byid.get(str(edge.get("source_ref") or edge.get("source_id") or ""))
                if is_pki and _is_low_priv_source(source):
                    affected.append({
                        "source_principal": _label(source) or edge.get("source_ref") or edge.get("source_id"),
                        "target_pki_object": target_name,
                        "target_dn": target_dn,
                        "right": edge.get("edge_type"),
                        "provenance": edge.get("provenance"),
                    })
            return _control_match(
                rule_id="ADCS-005", rule_name="ESC5 - PKI Object Control",
                finding_type="ESC5_PKI_OBJECT_CONTROL", module="AD CS",
                title=f"{len(affected)} non-admin PKI object control path(s)",
                description="Non-admin principals have dangerous control over AD CS / PKI infrastructure objects such as CA, enrollment service, NTAuth, or certificate-template objects.",
                severity="CRITICAL", affected=affected,
                root_cause="GenericAll, WriteDACL, WriteOwner, or equivalent control over PKI infrastructure objects",
                remediation="Remove non-admin control rights from AD CS / PKI objects and delegate certificate administration through dedicated PKI admin groups only.",
                technical_severity=10.0, mitre=["T1649"],
            )

        self._reg(Rule("ADCS-005", "ESC5", "AD CS", "PKI object control", rule_esc5))

        def rule_esc7(data):
            affected = _edge_pairs(data.get("edges", []) or [], data.get("entities", []) or [], {"MANAGE_CA", "MANAGE_CERTIFICATES"})
            for ca in _ca_configs(data):
                for perm in ca.get("dangerous_permissions", []) or ca.get("ca_permissions", []) or []:
                    if not isinstance(perm, dict):
                        continue
                    ptype = str(perm.get("permission") or perm.get("right") or "")
                    principal_name = perm.get("principal") or perm.get("principal_name") or perm.get("name")
                    principal_sid = perm.get("principal_sid") or perm.get("sid") or perm.get("object_sid")
                    if (
                        ptype in {"ManageCA", "ManageCertificates", "MANAGE_CA", "MANAGE_CERTIFICATES"}
                        and not _principal_is_pki_authorized(data, ca, perm, name=principal_name, sid=principal_sid)
                    ):
                        affected.append({
                            "source_principal": principal_name or principal_sid,
                            "target_object": ca.get("ca_name") or ca.get("name"),
                            "edge_type": ptype,
                            "provenance": ca.get("collection_method") or "ca_config",
                        })
            return _control_match(
                rule_id="ADCS-007", rule_name="ESC7 - CA Permission Abuse",
                finding_type="ESC7_CA_PERMISSION_ABUSE", module="AD CS",
                title=f"{len(affected)} dangerous CA management permission path(s)",
                description="Low-privileged or excessive principals have ManageCA or ManageCertificates influence over an Enterprise CA.",
                severity="CRITICAL", affected=affected,
                root_cause="CA security descriptor grants ManageCA or ManageCertificates to non-PKI-admin principals",
                remediation="Restrict ManageCA and ManageCertificates to dedicated PKI administrators and review CA officer assignments.",
                technical_severity=9.5, mitre=["T1649"],
            )

        self._reg(Rule("ADCS-007", "ESC7", "AD CS", "Dangerous CA permissions", rule_esc7))

        def rule_esc9(data):
            affected = []
            weak_ca = any(c.get("sid_security_extension_disabled") or c.get("strong_certificate_binding_enforcement") in (0, "0", False) for c in _ca_configs(data))
            for t in data.get("cert_templates", []) or []:
                attrs = t.get("attributes") or {}
                if _low_priv_enrollment(t) and (attrs.get("no_security_extension") or attrs.get("ct_flag_no_security_extension") or (weak_ca and attrs.get("subject_alt_require_upn"))):
                    affected.append(_adcs_object(t) | {"weak_attribute": "no_security_extension / weak identity mapping context"})
            return _control_match(
                rule_id="ADCS-009", rule_name="ESC9 - Weak Security Extension Mapping",
                finding_type="ESC9_WEAK_SECURITY_EXTENSION_MAPPING", module="AD CS",
                title=f"{len(affected)} template(s) expose weak SID-extension mapping risk",
                description="Templates are enrollable by low-privileged principals and suppress or weaken SID security extension identity binding in a weak mapping context.",
                severity="HIGH", affected=affected,
                root_cause="Template/CA telemetry indicates weak or absent SID security extension binding",
                remediation="Require the SID security extension, enable strong certificate binding enforcement, and restrict enrollment.",
                technical_severity=8.0, confidence=0.85, mitre=["T1649"],
            )

        self._reg(Rule("ADCS-009", "ESC9", "AD CS", "Weak security extension mapping", rule_esc9))

        def rule_esc10(data):
            affected = []
            for ca in _ca_configs(data):
                value = ca.get("strong_certificate_binding_enforcement", ca.get("certificate_mapping_enforcement"))
                weak = value in (0, 1, "0", "1", False) or ca.get("weak_certificate_mapping")
                if weak:
                    affected.append({
                        "ca_name": ca.get("ca_name") or ca.get("name"),
                        "host": ca.get("hostname") or ca.get("host"),
                        "mapping_enforcement": value,
                        "source": ca.get("collection_method") or "ca_config",
                    })
            return _control_match(
                rule_id="ADCS-010", rule_name="ESC10 - Weak Certificate Mapping",
                finding_type="ESC10_WEAK_CERTIFICATE_MAPPING", module="AD CS",
                title=f"{len(affected)} CA(s) have weak certificate mapping enforcement",
                description="CA or domain certificate mapping posture allows weak subject/UPN mapping instead of strong SID-bound certificate mapping.",
                severity="HIGH", affected=affected,
                root_cause="StrongCertificateBindingEnforcement is disabled/compatibility mode or equivalent weak mapping telemetry is present",
                remediation="Set strong certificate binding enforcement to full enforcement and remediate templates that rely on weak UPN/subject mapping.",
                technical_severity=8.5, confidence=0.9, mitre=["T1649"],
            )

        self._reg(Rule("ADCS-010", "ESC10", "AD CS", "Weak certificate mapping", rule_esc10))

        def rule_esc11(data):
            affected = []
            for ca in _ca_configs(data):
                rpc_enabled = ca.get("rpc_enrollment_enabled", True)
                encrypted = ca.get("enforce_encrypt_icertrequest", ca.get("if_enforce_encrypt_icertrequest"))
                if rpc_enabled and encrypted in (False, 0, "0"):
                    affected.append({
                        "ca_name": ca.get("ca_name") or ca.get("name"),
                        "host": ca.get("hostname") or ca.get("host"),
                        "enforce_encrypt_icertrequest": encrypted,
                        "source": ca.get("collection_method") or "ca_config",
                    })
            return _control_match(
                rule_id="ADCS-011", rule_name="ESC11 - RPC Enrollment Relay Exposure",
                finding_type="ESC11_RPC_ENROLLMENT_RELAY", module="AD CS",
                title=f"{len(affected)} CA(s) expose unencrypted RPC enrollment relay posture",
                description="CA RPC enrollment is enabled while IF_ENFORCEENCRYPTICERTREQUEST is not enforced, making relay-style certificate enrollment abuse more practical.",
                severity="HIGH", affected=affected,
                root_cause="RPC enrollment encryption enforcement is disabled",
                remediation="Enable IF_ENFORCEENCRYPTICERTREQUEST and reduce NTLM relay exposure to CA enrollment services.",
                technical_severity=8.0, confidence=0.85, mitre=["T1649", "T1557.001"],
            )

        self._reg(Rule("ADCS-011", "ESC11", "AD CS", "RPC enrollment relay exposure", rule_esc11))

        def rule_esc13(data):
            affected = []
            for t in data.get("cert_templates", []) or []:
                attrs = t.get("attributes") or {}
                policies = attrs.get("issuance_policies") or attrs.get("certificate_policies") or []
                for policy in policies:
                    if (
                        isinstance(policy, dict)
                        and policy.get("linked_group")
                        and _linked_group_is_privileged(policy.get("linked_group"), data)
                        and _low_priv_enrollment(t)
                    ):
                        affected.append(_adcs_object(t) | {
                            "issuance_policy": policy.get("oid") or policy.get("name"),
                            "linked_group": policy.get("linked_group"),
                        })
            return _control_match(
                rule_id="ADCS-013", rule_name="ESC13 - Issuance Policy Group Link Abuse",
                finding_type="ESC13_ISSUANCE_POLICY_GROUP_LINK", module="AD CS",
                title=f"{len(affected)} issuance policy group-link abuse path(s)",
                description="Low-privileged enrollment can obtain certificates containing issuance policy OIDs linked to privileged groups.",
                severity="CRITICAL", affected=affected,
                root_cause="Issuance policy/OID is linked to a privileged group and exposed through low-privileged template enrollment",
                remediation="Remove privileged group links from issuance policies or restrict enrollment on templates that issue those policies.",
                technical_severity=9.5, mitre=["T1649"],
            )

        self._reg(Rule("ADCS-013", "ESC13", "AD CS", "Issuance policy group-link abuse", rule_esc13))

        def rule_esc16(data):
            affected = []
            for ca in _ca_configs(data):
                disabled = ca.get("sid_security_extension_disabled") or ca.get("disable_sid_security_extension")
                disabled = disabled or "1.3.6.1.4.1.311.25.2" in str(ca.get("disabled_extensions") or ca.get("policy_disable_extension_list") or "")
                if disabled:
                    affected.append({
                        "ca_name": ca.get("ca_name") or ca.get("name"),
                        "host": ca.get("hostname") or ca.get("host"),
                        "disabled_extension": "1.3.6.1.4.1.311.25.2",
                        "source": ca.get("collection_method") or "ca_config",
                    })
            return _control_match(
                rule_id="ADCS-016", rule_name="ESC16 - CA Disables SID Security Extension",
                finding_type="ESC16_CA_DISables_SID_EXTENSION".upper(),
                module="AD CS",
                title=f"{len(affected)} CA(s) disable the SID security extension",
                description="CA policy disables the SID security extension, weakening strong identity binding for issued certificates.",
                severity="CRITICAL", affected=affected,
                root_cause="CA disabled extension list includes the SID security extension or equivalent telemetry",
                remediation="Remove the SID security extension from disabled extension lists and enforce strong certificate mapping.",
                technical_severity=9.5, mitre=["T1649"],
            )

        self._reg(Rule("ADCS-016", "ESC16", "AD CS", "CA disables SID security extension", rule_esc16))

        edge_rule_specs = [
            ("ACL-010", "READ_LAPS_PASSWORD", "LAPS_PASSWORD_READABLE", "Local Admin", "can read LAPS passwords", "HIGH", 8.0),
            ("SVC-002", "READ_GMSA_PASSWORD", "GMSA_PASSWORD_READABLE", "Service Accounts", "can read gMSA managed passwords", "HIGH", 8.0),
            ("ACL-011", "WRITE_SPN", "WRITE_SPN_ABUSE_PATH", "ACL Abuse", "can write SPNs on accounts", "HIGH", 8.0),
            ("PER-002", "ADD_KEY_CREDENTIAL_LINK", "ADD_KEY_CREDENTIAL_LINK_ABUSE_PATH", "Persistence", "can add shadow credentials", "CRITICAL", 9.5),
            ("ACL-012", "WRITE_GP_LINK", "WRITE_GP_LINK_ABUSE_PATH", "GPO / SYSVOL", "can alter GP links", "HIGH", 8.5),
            ("DEL-005", "WRITE_ACCOUNT_RESTRICTIONS", "WRITE_ACCOUNT_RESTRICTIONS_ABUSE_PATH", "Kerberos", "can write account restriction attributes", "HIGH", 8.0),
            ("SQL-001", "SQL_ADMIN", "SQL_ADMIN_ATTACK_PATH", "Network Posture", "has SQL admin lateral movement path", "MEDIUM", 6.5),
            ("ADCS-017", "CA_PRIVATE_KEY_CONTROL", "CA_PRIVATE_KEY_CONTROL", "AD CS", "controls CA private key material", "CRITICAL", 10.0),
            ("ADCS-018", "GOLDEN_CERT", "GOLDEN_CERTIFICATE_RISK", "AD CS", "has Golden Certificate capability", "CRITICAL", 10.0),
        ]
        for rid, edge_type, ftype, module, phrase, severity, tech in edge_rule_specs:
            def _make_rule(rid=rid, edge_type=edge_type, ftype=ftype, module=module, phrase=phrase, severity=severity, tech=tech):
                def rule(data):
                    affected = _edge_pairs(data.get("edges", []) or [], data.get("entities", []) or [], {edge_type})
                    return _control_match(
                        rule_id=rid, rule_name=edge_type.replace("_", " ").title(),
                        finding_type=ftype, module=module,
                        title=f"{len(affected)} principal(s) {phrase}",
                        description=f"Normalized graph telemetry shows low-privileged or excessive principals {phrase}.",
                        severity=severity, affected=affected,
                        root_cause=f"{edge_type} graph edge from non-admin source to target object",
                        remediation=f"Remove or scope the delegated right represented by {edge_type}.",
                        technical_severity=tech,
                        references=["https://attack.mitre.org/"],
                        mitre=["T1098"] if "KEY_CREDENTIAL" in edge_type else [],
                    )
                return rule
            self._reg(Rule(rid, edge_type, module, f"{edge_type} abuse path", _make_rule()))

        def rule_dnsadmins(data):
            entities = data.get("entities", [])
            byid = _by_id(entities)
            affected = []
            for edge in data.get("edges", []) or []:
                if edge.get("edge_type") != "MEMBER_OF":
                    continue
                tgt = byid.get(str(edge.get("target_ref") or edge.get("target_id") or ""))
                src = byid.get(str(edge.get("source_ref") or edge.get("source_id") or ""))
                if "dnsadmins" in _label(tgt).lower() and _is_low_priv_source(src):
                    affected.append({"member": _label(src), "group": _label(tgt), "edge_type": "MEMBER_OF"})
            return _control_match(
                rule_id="DNS-001", rule_name="DNSAdmins Risky Membership",
                finding_type="DNSADMINS_RISKY_MEMBERSHIP", module="DNS",
                title=f"{len(affected)} non-admin DNSAdmins member(s)",
                description="DNSAdmins membership can often be converted into code execution on DNS servers through server-level plugin configuration.",
                severity="HIGH", affected=affected,
                root_cause="Non-admin principal is member of DNSAdmins",
                remediation="Remove unnecessary DNSAdmins members and use just-in-time DNS administration.",
                technical_severity=8.0, references=["https://attack.mitre.org/techniques/T1543/"],
            )
        self._reg(Rule("DNS-001", "DNSAdmins Membership", "DNS", "Risky DNSAdmins membership", rule_dnsadmins))

        def rule_collector_centralized(data):
            findings = []
            entities = data.get("entities", []) or []
            nc = data.get("network_config", {}) or {}
            trusts = data.get("trusts", []) or []
            if nc.get("null_session_hosts"):
                findings.extend(_control_match(
                    rule_id="NET-010", rule_name="Null Session SMB Exposure",
                    finding_type="NULL_SESSION_SMB_EXPOSURE", module="Network Posture",
                    title=f"{len(nc.get('null_session_hosts') or [])} host(s) allow null-session SMB access",
                    description="SMB null-session access permits unauthenticated enumeration of shares, users, groups, or named pipes.",
                    severity="HIGH", affected=list(nc.get("null_session_hosts") or []),
                    root_cause="SMB server permits anonymous/null-session access",
                    remediation="Disable anonymous SMB access and restrict NullSessionPipes/NullSessionShares.",
                    technical_severity=8.0, references=["https://attack.mitre.org/techniques/T1087/"],
                ))
            legacy = [e for e in entities if e.get("entity_type") in {"COMPUTER", "DC"} and any(x in str((e.get("attributes") or {}).get("os") or (e.get("attributes") or {}).get("operating_system") or "").lower() for x in ("2000", "2003", "2008", "windows xp", "windows 7"))]
            findings.extend(_control_match(
                rule_id="HOST-001", rule_name="Legacy Operating Systems",
                finding_type="LEGACY_EOL_OPERATING_SYSTEMS", module="Network Posture",
                title=f"{len(legacy)} legacy/EOL host(s) detected",
                description="Legacy Windows operating systems lack modern hardening and security update support.",
                severity="HIGH", affected=[_label(e) for e in legacy],
                root_cause="OperatingSystem attribute indicates EOL Windows release",
                remediation="Retire or isolate legacy hosts and migrate supported workloads.",
                technical_severity=7.5, references=["https://learn.microsoft.com/lifecycle/"],
            ))
            des = [e for e in entities if e.get("is_enabled") and ((e.get("attributes") or {}).get("use_des_key_only") or (e.get("attributes") or {}).get("des_only") or (e.get("attributes") or {}).get("uac_use_des_key_only"))]
            findings.extend(_control_match(
                rule_id="KRB-006", rule_name="DES-only Kerberos Accounts",
                finding_type="DES_ONLY_KERBEROS_ACCOUNT", module="Kerberos",
                title=f"{len(des)} enabled account(s) restricted to DES Kerberos",
                description="DES-only Kerberos is cryptographically broken and should not be accepted for enabled accounts.",
                severity="HIGH", affected=[_label(e) for e in des],
                root_cause="USE_DES_KEY_ONLY or equivalent encryption telemetry is set",
                remediation="Clear USE_DES_KEY_ONLY and require AES Kerberos encryption.",
                technical_severity=8.0, references=["https://attack.mitre.org/techniques/T1558/"],
            ))
            secrets = [e for e in entities if e.get("is_enabled") and SECRET_RE.search(str((e.get("attributes") or {}).get("description") or ""))]
            findings.extend(_control_match(
                rule_id="USR-005", rule_name="Secrets in Account Descriptions",
                finding_type="ACCOUNT_DESCRIPTION_SECRET", module="User Accounts",
                title=f"{len(secrets)} account description(s) contain secret-like strings",
                description="Account descriptions contain password/secret/token-like material visible to authenticated users.",
                severity="HIGH", affected=[_label(e) for e in secrets],
                root_cause="description attribute contains credential-like text",
                remediation="Remove secrets from descriptions and rotate any exposed credentials.",
                technical_severity=8.5, references=["https://attack.mitre.org/techniques/T1552/"],
            ))
            pgid = [e for e in entities if e.get("entity_type") == "USER" and str((e.get("attributes") or {}).get("primary_group_id") or (e.get("attributes") or {}).get("primaryGroupID") or "") in {"512", "518", "519", "520"}]
            findings.extend(_control_match(
                rule_id="PER-003", rule_name="Privileged primaryGroupID Abuse",
                finding_type="PRIVILEGED_PRIMARY_GROUP_ID", module="Persistence",
                title=f"{len(pgid)} user(s) have privileged primaryGroupID",
                description="A privileged primaryGroupID can hide effective privilege outside normal group membership review.",
                severity="HIGH", affected=[_label(e) for e in pgid],
                root_cause="primaryGroupID points to a privileged RID",
                remediation="Reset primaryGroupID to Domain Users unless explicitly required and investigate the change.",
                technical_severity=8.0, references=["https://attack.mitre.org/techniques/T1098/"],
            ))
            dollar_users = [e for e in entities if e.get("entity_type") == "USER" and e.get("is_enabled", True) and str(e.get("sam_account_name") or "").endswith("$")]
            findings.extend(_control_match(
                rule_id="USR-006", rule_name="User Accounts Mimic Computers",
                finding_type="USER_ACCOUNT_DOLLAR_SUFFIX", module="User Accounts",
                title=f"{len(dollar_users)} user account(s) end with '$'",
                description="Enabled user accounts with computer-like names can hide in host inventory and confuse reviews.",
                severity="MEDIUM", affected=[_label(e) for e in dollar_users],
                root_cause="User sAMAccountName ends with '$'",
                remediation="Rename or disable deceptive user accounts after validation.",
                technical_severity=5.5, confidence=0.8, references=["https://attack.mitre.org/techniques/T1036/"],
            ))
            tae = [t for t in trusts if bool(t.get("treat_as_external")) or (str(t.get("trust_attributes") or "").isdigit() and int(str(t.get("trust_attributes"))) & 0x40)]
            findings.extend(_control_match(
                rule_id="TRUST-004", rule_name="TREAT_AS_EXTERNAL Trust Flag",
                finding_type="TREAT_AS_EXTERNAL_TRUST", module="Trusts",
                title=f"{len(tae)} trust(s) have TREAT_AS_EXTERNAL posture",
                description="TREAT_AS_EXTERNAL changes forest trust behavior and can weaken expected cross-forest SID filtering posture.",
                severity="MEDIUM", affected=[t.get("partner") or t.get("name") or t.get("target_domain") for t in tae],
                root_cause="TrustAttributes includes TREAT_AS_EXTERNAL",
                remediation="Validate why the trust requires TREAT_AS_EXTERNAL and remove it unless explicitly needed.",
                technical_severity=6.0, confidence=0.85, references=["https://learn.microsoft.com/windows/win32/api/ntsecapi/ns-ntsecapi-lsa_trust_information"],
            ))
            return findings
        self._reg(Rule("COLLECTOR-001", "Centralized Collector Signals", "Network Posture", "Collector-only signal normalization", rule_collector_centralized))
