from __future__ import annotations

import json
import re
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


def _parse_ps_list(output: str) -> list[dict]:
    """Parse PS list-format output (Prop : Value blocks) into list of dicts."""
    records: list[dict] = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        if " : " in line:
            key, _, val = line.partition(" : ")
            current[key.strip()] = val.strip()
        elif not line.strip() and current:
            records.append(current)
            current = {}
    if current:
        records.append(current)
    return records


def _bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in ("true", "yes", "1", "$true")


def _int_value(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    raw = str(value).strip()
    try:
        return int(raw, 0)
    except ValueError:
        return default


def _first(rec: dict, *keys: str, default: str = "") -> str:
    lowered = {str(k).lower(): v for k, v in rec.items()}
    for key in keys:
        if key in rec:
            return rec[key]
        if key.lower() in lowered:
            return lowered[key.lower()]
    return default


def _has_value(value: Any) -> bool:
    raw = str(value or "").strip()
    return raw not in ("", "{}", "[]", "@{}")


def _parse_datetime_text(value: Any) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    for candidate in (raw, raw.replace("Z", "+00:00")):
        try:
            dt = datetime.fromisoformat(candidate)
            return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            pass
    for fmt in ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _parse_json_or_text(output: Any) -> list[dict]:
    """Try JSON parse first (ConvertTo-Json commands), fall back to PS-list text."""
    stripped = str(output or "").strip()
    if not stripped:
        return []
    if stripped[0] in ("[", "{"):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return [r for r in parsed if isinstance(r, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except (json.JSONDecodeError, ValueError):
            pass
    return _parse_ps_list(stripped)


_HIGH_VALUE_GROUPS = frozenset({
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "protected users", "account operators", "backup operators", "print operators",
    "server operators", "group policy creator owners", "dnsadmins",
})


def _sid_value(sid_raw: Any) -> str:
    """Extract SID string from either a plain string or a PS {'Value': '...'} object."""
    if isinstance(sid_raw, dict):
        return str(sid_raw.get("Value") or sid_raw.get("value") or "")
    return str(sid_raw or "")


def _parse_groups(output: Any, domain: str = "") -> tuple[list[dict], list[dict]]:
    """Parse JSON or PS-list group output into (GROUP entities, MEMBER_OF edges)."""
    records = _parse_json_or_text(output)
    entities: list[dict] = []
    edges: list[dict] = []
    for r in records:
        sam = str(r.get("SamAccountName") or r.get("samaccountname") or "")
        sid = _sid_value(r.get("objectSid") or r.get("objectsid") or "")
        dn = str(r.get("DistinguishedName") or r.get("distinguishedname") or "")
        name = str(r.get("Name") or r.get("name") or sam)
        is_admin = bool(r.get("adminCount") or r.get("admincount"))
        is_high = sam.lower() in _HIGH_VALUE_GROUPS
        entity_id = sid or sam
        if not entity_id:
            continue
        entities.append({
            "id": entity_id,
            "entity_type": "GROUP",
            "object_sid": sid,
            "sam_account_name": sam,
            "display_name": name,
            "distinguished_name": dn,
            "domain": domain,
            "is_enabled": True,
            "is_admin_count": is_admin,
            "is_sensitive": False,
            "is_protected_user": False,
            "is_crown_jewel": is_high,
            "tier": 0 if (is_high or is_admin) else None,
            "attributes": {"object_sid": sid},
            "business_tags": [],
        })
        members_raw = r.get("member") or r.get("Member") or []
        if isinstance(members_raw, str):
            members_raw = [members_raw]
        for member_dn in (members_raw or []):
            if not member_dn:
                continue
            edges.append({
                "source_id": str(member_dn),
                "target_id": entity_id,
                "edge_type": "MEMBER_OF",
                "risk_weight": 0.4,
                "provenance": "PowerShell group membership",
                "attributes": {"member_dn": str(member_dn)},
            })
    return entities, edges


_GPO_LINK_PATTERN = re.compile(r'\[LDAP://([^;]+);(\d+)\]', re.I)


def _parse_ous(output: Any, domain: str = "") -> list[dict]:
    """Parse JSON/text OU output into OU entities preserving gPLink for edge resolution."""
    records = _parse_json_or_text(output)
    entities: list[dict] = []
    for r in records:
        dn = str(r.get("DistinguishedName") or r.get("distinguishedname") or "")
        if not dn:
            continue
        name = str(r.get("Name") or r.get("name") or "")
        sid = _sid_value(r.get("objectSid") or r.get("objectsid") or "")
        gp_link = str(r.get("gPLink") or r.get("gplink") or "")
        gp_opts = _int_value(r.get("gPOptions") or r.get("gpoptions"), 0)
        entities.append({
            "id": dn,
            "entity_type": "OU",
            "object_sid": sid,
            "sam_account_name": name,
            "display_name": name,
            "distinguished_name": dn,
            "domain": domain,
            "is_enabled": True,
            "is_admin_count": False,
            "is_sensitive": False,
            "is_protected_user": False,
            "is_crown_jewel": False,
            "tier": None,
            "attributes": {"gp_link": gp_link, "gp_options": gp_opts},
            "business_tags": [],
        })
    return entities


def _parse_gpos(output: Any, domain: str = "") -> list[dict]:
    """Parse JSON/text GPO output into GPO entities."""
    records = _parse_json_or_text(output)
    entities: list[dict] = []
    for r in records:
        name = str(r.get("DisplayName") or r.get("displayname") or r.get("Name") or r.get("name") or "")
        dn = str(r.get("DistinguishedName") or r.get("distinguishedname") or "")
        guid = str(r.get("Id") or r.get("id") or r.get("cn") or "")
        if not (name or dn):
            continue
        entity_id = dn or f"GPO:{name}"
        entities.append({
            "id": entity_id,
            "entity_type": "GPO",
            "sam_account_name": name,
            "display_name": name,
            "distinguished_name": dn,
            "domain": domain,
            "is_enabled": True,
            "is_admin_count": False,
            "is_sensitive": False,
            "is_protected_user": False,
            "is_crown_jewel": False,
            "tier": None,
            "attributes": {"gpo_guid": guid},
            "business_tags": [],
        })
    return entities


def _parse_gpo_links_from_containers(
    containers: list[dict],
    gpos: list[dict],
) -> list[dict]:
    """
    Resolve APPLIES_GPO edges from container gPLink attributes.
    containers: list of dicts with keys DistinguishedName and gPLink.
    gpos: list of GPO entities as built by _parse_gpos (used for id lookup by DN).
    """
    gpo_map: dict[str, str] = {}
    for gpo in gpos:
        dn = str(gpo.get("distinguished_name") or gpo.get("id") or "").lower()
        if dn:
            gpo_map[dn] = str(gpo.get("id") or dn)

    edges: list[dict] = []
    for c in containers:
        container_dn = str(c.get("DistinguishedName") or c.get("distinguished_name") or "")
        gp_link = str(c.get("gPLink") or c.get("attributes", {}).get("gp_link") or "")
        if not gp_link:
            continue
        for m in _GPO_LINK_PATTERN.finditer(gp_link):
            gpo_dn_raw = m.group(1).strip()
            link_opts = _int_value(m.group(2), 0)
            disabled = bool(link_opts & 0x01)
            enforced = bool(link_opts & 0x02)
            if disabled:
                continue
            gpo_id = gpo_map.get(gpo_dn_raw.lower(), gpo_dn_raw)
            edges.append({
                "source_id": gpo_id,
                "target_id": container_dn,
                "edge_type": "APPLIES_GPO",
                "risk_weight": 0.6 if enforced else 0.3,
                "provenance": f"GPO linked {'(enforced) ' if enforced else ''}to {container_dn}",
                "attributes": {
                    "enforced": enforced,
                    "gpo_dn": gpo_dn_raw,
                    "target_dn": container_dn,
                },
            })
    return edges


def _parse_delegation_edges(output: Any, domain: str = "") -> list[dict]:
    """
    Parse JSON/text delegation output into ALLOWED_TO_DELEGATE and ALLOWED_TO_ACT edges.
    Handles unconstrained (TrustedForDelegation), constrained (msDS-AllowedToDelegateTo),
    and RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity).
    """
    records = _parse_json_or_text(output)
    edges: list[dict] = []
    for r in records:
        sid = _sid_value(r.get("objectSid") or r.get("objectsid") or "")
        sam = str(r.get("SamAccountName") or r.get("samaccountname") or "")
        dn = str(r.get("DistinguishedName") or r.get("distinguishedname") or "")
        src = sid or sam
        if not src:
            continue

        # Unconstrained delegation (TrustedForDelegation=True, non-DC)
        trusted = r.get("TrustedForDelegation") or r.get("trustedfordelegation")
        if _bool_value(trusted):
            edges.append({
                "source_id": src,
                "target_id": f"domain:{domain}" if domain else "domain:unknown",
                "edge_type": "ALLOWED_TO_DELEGATE",
                "risk_weight": 0.9,
                "provenance": f"Unconstrained delegation on {sam or dn}",
                "attributes": {"delegation_type": "unconstrained"},
            })

        # Constrained delegation (msDS-AllowedToDelegateTo)
        spns_raw = r.get("msDS-AllowedToDelegateTo") or r.get("msdsdelegation") or []
        if isinstance(spns_raw, str):
            spns_raw = [spns_raw]
        for spn in (spns_raw or []):
            spn = str(spn).strip()
            if not spn:
                continue
            edges.append({
                "source_id": src,
                "target_id": spn,
                "edge_type": "ALLOWED_TO_DELEGATE",
                "risk_weight": 0.7,
                "provenance": f"Constrained delegation to {spn}",
                "attributes": {"delegation_type": "constrained", "target_spn": spn},
            })

        # RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity present)
        rbcd_raw = r.get("msDS-AllowedToActOnBehalfOfOtherIdentity") or r.get("rbcd")
        if rbcd_raw and str(rbcd_raw).strip() not in ("", "None", "{}"):
            edges.append({
                "source_id": "RBCD_TRUSTEE_PENDING",
                "target_id": src,
                "edge_type": "ALLOWED_TO_ACT",
                "risk_weight": 0.8,
                "provenance": f"RBCD configured on {sam or dn}",
                "attributes": {
                    "delegation_type": "rbcd",
                    "target_dn": dn,
                    "target_sam": sam,
                },
            })
    return edges


def _parse_shadow_credential_edges(output: Any) -> list[dict]:
    """Parse JSON/text shadow credential output into ADD_KEY_CREDENTIAL_LINK edges."""
    records = _parse_json_or_text(output)
    edges: list[dict] = []
    for r in records:
        sid = _sid_value(r.get("objectSid") or r.get("objectsid") or "")
        sam = str(r.get("SamAccountName") or r.get("samaccountname") or "")
        dn = str(r.get("DistinguishedName") or r.get("distinguishedname") or "")
        target = sid or sam
        if not target:
            continue
        keys_raw = r.get("msDS-KeyCredentialLink") or r.get("keycredentiallink") or []
        if isinstance(keys_raw, str):
            keys_raw = [keys_raw]
        key_count = len(keys_raw) if isinstance(keys_raw, list) else 1
        edges.append({
            "source_id": "SHADOW_CRED_ATTACKER_PENDING",
            "target_id": target,
            "edge_type": "ADD_KEY_CREDENTIAL_LINK",
            "risk_weight": 0.95,
            "provenance": f"Shadow credential configured on {sam or dn}",
            "attributes": {
                "target_dn": dn,
                "target_sam": sam,
                "key_count": key_count,
            },
        })
    return edges


_EKU_CLIENT_AUTH        = "1.3.6.1.5.5.7.3.2"
_EKU_ANY_PURPOSE        = "2.5.29.37.0"
_EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"

_MS_NAME_FLAG_ENROLLEE_SUPPLIES  = 0x00000001
_MS_ENROLL_FLAG_REQUIRES_APPROVAL = 0x00000002


def _ekus_from_record(r: dict) -> list[str]:
    ekus_raw = r.get("pKIExtendedKeyUsage") or r.get("pkiextendedkeyusage") or []
    app_raw  = r.get("msPKI-Certificate-Application-Policy") or r.get("mspki-certificate-application-policy") or []
    if isinstance(ekus_raw, str):
        ekus_raw = [ekus_raw]
    if isinstance(app_raw, str):
        app_raw = [app_raw]
    return list({str(e) for e in (ekus_raw or []) + (app_raw or []) if e})


def _parse_cert_templates_ps(output: Any) -> list[dict]:
    """Parse JSON cert template LDAP output into cert_template dicts with ESC1-3 detection."""
    records = _parse_json_or_text(output)
    templates: list[dict] = []
    for r in records:
        name = str(r.get("cn") or r.get("name") or r.get("displayName") or "")
        dn   = str(r.get("DistinguishedName") or r.get("distinguishedname") or "")
        if not name:
            continue
        name_flag   = _int_value(r.get("msPKI-Certificate-Name-Flag") or r.get("mspki-certificate-name-flag"), 0)
        enroll_flag = _int_value(r.get("msPKI-Enrollment-Flag")       or r.get("mspki-enrollment-flag"), 0)
        ra_sig      = _int_value(r.get("msPKI-RA-Signature")          or r.get("mspki-ra-signature"), 0)
        ekus        = _ekus_from_record(r)

        enrollee_supplies_subject = bool(name_flag  & _MS_NAME_FLAG_ENROLLEE_SUPPLIES)
        requires_manager_approval = bool(enroll_flag & _MS_ENROLL_FLAG_REQUIRES_APPROVAL)

        esc1 = (
            enrollee_supplies_subject
            and ra_sig == 0
            and not requires_manager_approval
            and (
                not ekus
                or _EKU_CLIENT_AUTH in ekus
                or _EKU_ANY_PURPOSE in ekus
            )
        )
        esc2 = (
            ra_sig == 0
            and not requires_manager_approval
            and (not ekus or _EKU_ANY_PURPOSE in ekus)
        )
        esc3 = (
            not requires_manager_approval
            and _EKU_CERT_REQUEST_AGENT in ekus
        )
        templates.append({
            "name": name,
            "ca_name": "",
            "distinguished_name": dn,
            "enrollee_supplies_subject": enrollee_supplies_subject,
            "requires_manager_approval": requires_manager_approval,
            "authorized_signatures_required": ra_sig,
            "ekus": ekus,
            "enrollment_rights": [],
            "write_rights": [],
            "esc1_vulnerable": esc1,
            "esc2_vulnerable": esc2,
            "esc3_vulnerable": esc3,
            "esc4_vulnerable": False,
        })
    return templates


def _parse_cas_ps(output: Any, domain: str = "") -> list[dict]:
    """Parse JSON CA enrollment service output into CA entities."""
    records = _parse_json_or_text(output)
    entities: list[dict] = []
    for r in records:
        name = str(r.get("cn") or r.get("name") or r.get("displayName") or "")
        dn   = str(r.get("DistinguishedName") or r.get("distinguishedname") or "")
        host = str(r.get("dNSHostName") or r.get("dnshostname") or "")
        if not name:
            continue
        entities.append({
            "id": dn or f"CA:{name}",
            "entity_type": "CA",
            "sam_account_name": name,
            "display_name": name,
            "distinguished_name": dn,
            "domain": domain,
            "is_enabled": True,
            "is_admin_count": False,
            "is_sensitive": True,
            "is_protected_user": False,
            "is_crown_jewel": True,
            "tier": 0,
            "attributes": {
                "dns_hostname": host,
                "published_templates": list(r.get("certificateTemplates") or []),
            },
            "business_tags": ["Certificate Authority"],
        })
    return entities


def _build_domain_entity(output: Any, domain: str = "") -> dict | None:
    """Parse JSON Get-ADDomain output into a DOMAIN entity."""
    stripped = str(output or "").strip()
    if not stripped:
        return None
    records = _parse_json_or_text(stripped)
    if not records:
        return None
    r = records[0]
    sid = _sid_value(r.get("DomainSID") or r.get("domainsid") or "")
    dns = str(r.get("DNSRoot") or r.get("dnsroot") or domain or "")
    dn  = str(r.get("DistinguishedName") or r.get("distinguishedname") or "")
    if not (sid or dns):
        return None
    return {
        "id": sid or dns,
        "entity_type": "DOMAIN",
        "object_sid": sid,
        "sam_account_name": dns,
        "display_name": dns,
        "distinguished_name": dn,
        "domain": dns or domain,
        "is_enabled": True,
        "is_admin_count": False,
        "is_sensitive": True,
        "is_protected_user": False,
        "is_crown_jewel": True,
        "tier": 0,
        "attributes": {"object_sid": sid},
        "business_tags": ["Domain Root"],
    }


def _enrich_domain_info(
    domain_info: dict,
    domain_output: Any = None,
    krbtgt_output: Any = None,
) -> None:
    """Enrich domain_info dict in-place with MAQ, functional level, and krbtgt age."""
    if domain_output:
        records = _parse_json_or_text(domain_output)
        if records:
            r = records[0]
            maq = r.get("ms-DS-MachineAccountQuota") or r.get("machineaccountquota")
            if maq is not None:
                try:
                    domain_info["machine_account_quota"] = int(maq)
                except (TypeError, ValueError):
                    pass
            mode = r.get("DomainMode") or r.get("domainmode") or r.get("msDS-Behavior-Version")
            if mode is not None:
                try:
                    domain_info["functional_level"] = int(mode)
                    domain_info["domain_functional_level"] = int(mode)
                except (TypeError, ValueError):
                    pass

    if krbtgt_output:
        records = _parse_json_or_text(krbtgt_output)
        if records:
            r = records[0]
            pwd_set = r.get("PasswordLastSet") or r.get("passwordlastset") or r.get("pwdLastSet")
            if pwd_set:
                dt = _parse_datetime_text(pwd_set)
                if dt:
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    try:
                        age = (now - dt).days
                        domain_info["krbtgt_password_age_days"] = max(0, age)
                    except Exception:
                        pass


def _days_since_datetime_text(value: Any) -> int | None:
    parsed = _parse_datetime_text(value)
    if not parsed:
        return None
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - parsed
    return max(0, delta.days)


def _parse_net_accounts(output: str) -> dict:
    """Parse `net accounts /domain` output → password_policy dict without fabricated defaults."""
    policy: dict[str, Any] = {}
    for line in output.splitlines():
        line = line.strip()
        if "Minimum password length" in line:
            val = line.split(":")[-1].strip()
            if val.isdigit():
                policy["min_password_length"] = int(val)
        elif "Lockout threshold" in line:
            val = line.split(":")[-1].strip().lower()
            if "never" in val:
                policy["lockout_threshold"] = 0
            elif val.isdigit():
                policy["lockout_threshold"] = int(val)
        elif "Maximum password age" in line:
            val = line.split(":")[-1].strip()
            if val.isdigit():
                policy["max_password_age"] = int(val)
        elif "Password history" in line or "password history" in line:
            val = line.split(":")[-1].strip().lower()
            if "none" in val:
                policy["password_history_count"] = 0
            elif val.isdigit():
                policy["password_history_count"] = int(val)
    return policy

def _parse_users(output: str, default_admin_count: bool = False) -> list[dict]:
    """Parse Get-ADUser JSON (ConvertTo-Json) or PS list output into entity dicts."""
    entities = []
    for rec in _parse_json_or_text(output):
        sam = _first(rec, "SamAccountName", "SAMAccountName")
        if not sam:
            continue
        uac_val = _int_value(_first(rec, "UserAccountControl"))
        admin_count = _int_value(_first(rec, "AdminCount", "adminCount"))
        _sid_raw = rec.get("objectSid") or rec.get("SID") or rec.get("ObjectSID")
        sid = _sid_value(_sid_raw) if _sid_raw is not None else ""
        if not sid:
            sid = sam
        dn = _first(rec, "DistinguishedName")
        spn_raw = _first(rec, "ServicePrincipalName", "servicePrincipalName")
        has_spn = _has_value(spn_raw)
        preauth_disabled = _bool_value(_first(rec, "DoesNotRequirePreAuth")) or bool(uac_val & 0x400000)
        passwd_notreqd = bool(uac_val & 0x20)
        pwd_never_expires = _bool_value(_first(rec, "PasswordNeverExpires")) or bool(uac_val & 0x10000)
        trusted_for_delegation = _bool_value(_first(rec, "TrustedForDelegation")) or bool(uac_val & 0x80000)
        trusted_to_auth = _bool_value(_first(rec, "TrustedToAuthForDelegation")) or bool(uac_val & 0x1000000)
        is_admin = default_admin_count or admin_count == 1 or sam.lower() in ("administrator", "krbtgt")
        last_logon_raw = _first(rec, "LastLogonDate", "LastLogon")
        days_since_last_logon = _days_since_datetime_text(last_logon_raw)
        enc_types = _int_value(_first(rec, "msDS-SupportedEncryptionTypes"), default=-1)
        allowed_to_delegate = _first(rec, "msDS-AllowedToDelegateTo", "AllowedToDelegateTo")
        attrs: dict[str, Any] = {
            "pwd_never_expires": pwd_never_expires,
            "uac_passwd_notreqd": passwd_notreqd,
            "uac_dont_require_preauth": preauth_disabled,
            "uac_trusted_for_delegation": trusted_for_delegation,
            "uac_trusted_to_auth_for_delegation": trusted_to_auth,
            "constrained_delegation_any_protocol": trusted_to_auth,
            "uac_not_delegated": _bool_value(_first(rec, "AccountNotDelegated")) or bool(uac_val & 0x100000),
            "has_spn": has_spn,
            "uac": uac_val,
            "msds_supported_encryption_types": enc_types,
            "rc4_only": enc_types not in (-1, 0) and not bool(enc_types & 0x18),
            "last_logon": last_logon_raw,
            "password_last_set": _first(rec, "PasswordLastSet", "pwdLastSet"),
        }
        if allowed_to_delegate:
            attrs["allowed_to_delegate_to"] = allowed_to_delegate if isinstance(allowed_to_delegate, list) else [allowed_to_delegate]
        if days_since_last_logon is not None:
            attrs["days_since_last_logon"] = days_since_last_logon

        entities.append({
            "id": sid,
            "entity_type": "SERVICE_ACCOUNT" if has_spn else "USER",
            "sam_account_name": sam,
            "display_name": _first(rec, "Name", default=sam),
            "distinguished_name": dn,
            "is_enabled": _bool_value(_first(rec, "Enabled", default="True"), default=True) and not bool(uac_val & 0x2),
            "is_admin_count": is_admin,
            "is_crown_jewel": sam.lower() in ("administrator", "krbtgt"),
            "tier": 0 if is_admin else 2,
            "last_logon": last_logon_raw or None,
            "password_last_set": _first(rec, "PasswordLastSet", "pwdLastSet") or None,
            "attributes": attrs,
        })
    return entities

def _parse_computers(output: str) -> list[dict]:
    """Parse Get-ADComputer JSON (ConvertTo-Json) or PS list output into entity dicts."""
    entities = []
    for rec in _parse_json_or_text(output):
        name = _first(rec, "Name")
        if not name:
            continue
        uac_val = _int_value(_first(rec, "UserAccountControl"))
        dn = _first(rec, "DistinguishedName")
        is_dc = bool(uac_val & 0x2000) or "Domain Controllers" in dn
        has_laps = _has_value(_first(rec, "ms-Mcs-AdmPwdExpirationTime", "msLAPS-PasswordExpirationTime"))
        trusted_to_auth = _bool_value(_first(rec, "TrustedToAuthForDelegation")) or bool(uac_val & 0x1000000)
        allowed_to_delegate = _first(rec, "msDS-AllowedToDelegateTo", "AllowedToDelegateTo")
        attrs = {
            "uac_trusted_for_delegation": _bool_value(_first(rec, "TrustedForDelegation")) or bool(uac_val & 0x80000),
            "uac_trusted_to_auth_for_delegation": trusted_to_auth,
            "constrained_delegation_any_protocol": trusted_to_auth,
            "uac_is_dc": is_dc,
            "dns_hostname": _first(rec, "DNSHostName", "DNSHostname"),
            "operating_system": _first(rec, "OperatingSystem"),
            "has_spn": _has_value(_first(rec, "ServicePrincipalName", "servicePrincipalName")),
            "has_laps": has_laps,
            "laps_installed": has_laps,
            "uac": uac_val,
        }
        if allowed_to_delegate:
            attrs["allowed_to_delegate_to"] = allowed_to_delegate if isinstance(allowed_to_delegate, list) else [allowed_to_delegate]
        _sid_raw = rec.get("objectSid") or rec.get("SID") or rec.get("ObjectSID")
        comp_sid = _sid_value(_sid_raw) if _sid_raw is not None else ""
        entities.append({
            "id": comp_sid or name,
            "entity_type": "DC" if is_dc else "COMPUTER",
            "sam_account_name": _first(rec, "SamAccountName", default=name + "$"),
            "display_name": name,
            "distinguished_name": dn,
            "is_enabled": _bool_value(_first(rec, "Enabled", default="True"), default=True) and not bool(uac_val & 0x2),
            "is_admin_count": False,
            "is_crown_jewel": is_dc,
            "tier": 0 if is_dc else 2,
            "attributes": attrs,
        })
    return entities

def _parse_trusts(output: str) -> list[dict]:
    """Parse Get-ADTrust PS list output into trust dicts."""
    trusts = []
    for rec in _parse_ps_list(output):
        name = _first(rec, "Name")
        if not name:
            continue
        direction_raw = rec.get("Direction", "").strip().lower()
        attrs = _int_value(_first(rec, "TrustAttributes"), default=-1)
        sid_filtering_raw = _first(rec, "SIDFilteringQuarantined", "SIDFilteringForestAware")
        trusts.append({
            "name": name,
            "trust_type": _first(rec, "TrustType").strip(),
            "trust_direction": direction_raw,
            "bidirectional": direction_raw == "bidirectional",
            "sid_filtering_enabled": _bool_value(sid_filtering_raw, default=(attrs & 4) == 4 if attrs >= 0 else True),
        })
    return trusts


def _parse_domain_info(output: str) -> dict:
    """Parse Get-ADDomain JSON or PS list output into domain_info dict."""
    info: dict[str, Any] = {}
    records = _parse_json_or_text(output)
    if records:
        r = records[0]
        dns = r.get("DNSRoot") or r.get("dnsroot") or r.get("DNSRoot")
        if dns:
            info["dns_root"] = str(dns)
        netbios = r.get("NetBIOSName") or r.get("netbiosname")
        if netbios:
            info["netbios_name"] = str(netbios)
        mode = r.get("DomainMode") or r.get("domainmode")
        if mode is not None:
            try:
                info["domain_functional_level"] = int(mode)
            except (TypeError, ValueError):
                pass
        maq = r.get("ms-DS-MachineAccountQuota") or r.get("machineaccountquota")
        if maq is not None:
            try:
                info["machine_account_quota"] = int(maq)
            except (TypeError, ValueError):
                pass
        return info
    # Fall back to line-by-line for plain PS list output
    for line in output.splitlines():
        if "DomainMode" in line and " : " in line:
            val = line.split(" : ", 1)[-1].strip()
            if val.isdigit():
                info["domain_functional_level"] = int(val)
        elif "DNSRoot" in line and " : " in line:
            info["dns_root"] = line.split(" : ", 1)[-1].strip()
        elif "NetBIOSName" in line and " : " in line:
            info["netbios_name"] = line.split(" : ", 1)[-1].strip()
        elif "ms-DS-MachineAccountQuota" in line and " : " in line:
            val = line.split(" : ", 1)[-1].strip()
            if val.isdigit():
                info["machine_account_quota"] = int(val)
    return info

def _parse_reg_dword(output: str, value_name: str) -> int | None:
    """Parse `reg query` REG_DWORD output for a named value."""
    if not output or "unable to find" in output.lower() or "error:" in output.lower():
        return None
    pattern = re.compile(rf"\b{re.escape(value_name)}\b\s+REG_DWORD\s+([^\s]+)", re.I)
    match = pattern.search(output)
    if not match:
        return None
    raw = match.group(1).strip()
    try:
        return int(raw, 16 if raw.lower().startswith("0x") else 10)
    except ValueError:
        return None


def _merge_entity(existing: dict, incoming: dict) -> dict:
    merged = {**existing, **{k: v for k, v in incoming.items() if v not in (None, "", [])}}
    merged_attrs = dict(existing.get("attributes") or {})
    merged_attrs.update({k: v for k, v in (incoming.get("attributes") or {}).items() if v not in (None, "", [])})
    merged["attributes"] = merged_attrs
    merged["is_admin_count"] = bool(existing.get("is_admin_count") or incoming.get("is_admin_count"))
    merged["is_crown_jewel"] = bool(existing.get("is_crown_jewel") or incoming.get("is_crown_jewel"))
    merged["is_enabled"] = bool(existing.get("is_enabled", True) and incoming.get("is_enabled", True))
    if existing.get("tier") == 0 or incoming.get("tier") == 0:
        merged["tier"] = 0
    return merged


# ── Main builder ───────────────────────────────────────────────────────────────

def _get_cmd_output(module_data: dict, module_id: str, cmd_id: str) -> str:
    mod = module_data.get(module_id, {})
    for cmd in mod.get("commands", []):
        if cmd.get("id") == cmd_id:
            return cmd.get("output") or ""
    return ""


def _get_all_outputs(module_data: dict, module_id: str) -> dict[str, str]:
    mod = module_data.get(module_id, {})
    return {c["id"]: (c.get("output") or "") for c in mod.get("commands", [])}


def build_rule_data_from_collector(module_data: dict) -> dict:
    """Convert native collector module_data dict into rule_engine data dict."""
    rule_data: dict[str, Any] = {
        "password_policy": {},
        "entities": [],
        "trusts": [],
        "domain_info": {},
        "smb_signing_required": True,
        "smb_signing_disabled_hosts": [],
        "cpassword_files": [],
        "edges": [],
        "cert_templates": [],
        "ca_flags": [],
        "network_config": {
            "smb_signing_required": True,
            "smb_signing_disabled_hosts": [],
            "llmnr_enabled": False,
            "nbtns_enabled": False,
            "winrm_open": False,
            "winrm_hosts": [],
            "open_shares": [],
            "cred_manager_entries": [],
        },
    }

    # ── Password policy ────────────────────────────────────────────────────────
    for mod_id in ("enum", "passwords"):
        for cmd_id in ("net-accounts-domain", "net-accounts-domain-passwords"):
            out = _get_cmd_output(module_data, mod_id, cmd_id)
            if out:
                rule_data["password_policy"].update(_parse_net_accounts(out))
                break
        if rule_data["password_policy"]:
            break

    entity_by_key: dict[str, dict] = {}

    def add_entity(entity: dict) -> None:
        key = (
            str(entity.get("id") or "").lower()
            or str(entity.get("distinguished_name") or "").lower()
            or str(entity.get("sam_account_name") or "").lower()
        )
        if not key:
            return
        existing = entity_by_key.get(key)
        if existing:
            entity_by_key[key] = _merge_entity(existing, entity)
        else:
            entity_by_key[key] = entity

    # ── Users ─────────────────────────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("passwords", "get-aduser-password-hygiene"),
        ("enum", "get-aduser-all"),
        ("exposure_quick_checks", "quick-get-aduser-risk"),
        ("service_accounts", "get-aduser-spn"),
        ("network_posture", "get-aduser-spn"),
        ("kerberos", "get-aduser-kerberos-props"),
        ("delegation_abuse_architecture", "delegation_abuse_architecture-2"),
    ]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            for e in _parse_users(out):
                add_entity(e)

    # ── Computers ────────────────────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("enum", "get-adcomputer-all"),
        ("exposure_quick_checks", "quick-get-adcomputer-risk"),
        ("service_accounts", "get-adcomputer-spn"),
        ("kerberos", "get-adcomputer-kerberos-props"),
    ]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            for e in _parse_computers(out):
                add_entity(e)

    # ── Domain entity ─────────────────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("enum", "get-addomain"),
        ("exposure_quick_checks", "quick-get-domain-policy"),
    ]:
        domain_out = _get_cmd_output(module_data, mod_id, cmd_id)
        if domain_out:
            dom_entity = _build_domain_entity(domain_out)
            if dom_entity:
                add_entity(dom_entity)
            _enrich_domain_info(rule_data["domain_info"], domain_output=domain_out)
            break

    # ── krbtgt password age ───────────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("enum", "get-krbtgt-age"),
        ("exposure_quick_checks", "quick-krbtgt-age"),
    ]:
        krbtgt_out = _get_cmd_output(module_data, mod_id, cmd_id)
        if krbtgt_out:
            _enrich_domain_info(rule_data["domain_info"], krbtgt_output=krbtgt_out)
            break

    # ── Groups ────────────────────────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("enum", "get-adgroup-all"),
        ("exposure_quick_checks", "quick-get-tier0-groups"),
    ]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            grp_entities, grp_edges = _parse_groups(out, domain=rule_data.get("domain_info", {}).get("domain", ""))
            for e in grp_entities:
                add_entity(e)
            rule_data["edges"].extend(grp_edges)

    # ── OUs ───────────────────────────────────────────────────────────────────
    ou_list: list[dict] = []
    for mod_id, cmd_id in [("enum", "get-adou-all"), ("topology", "get-adou-all")]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            ou_list = _parse_ous(out, domain=rule_data.get("domain_info", {}).get("domain", ""))
            for e in ou_list:
                add_entity(e)
            break

    # ── GPOs ──────────────────────────────────────────────────────────────────
    gpo_list: list[dict] = []
    for mod_id, cmd_id in [("enum", "get-adgpo-all"), ("topology", "get-adgpo-all")]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            gpo_list = _parse_gpos(out, domain=rule_data.get("domain_info", {}).get("domain", ""))
            for e in gpo_list:
                add_entity(e)
            break

    # ── APPLIES_GPO edges ─────────────────────────────────────────────────────
    if gpo_list:
        containers: list[dict] = list(ou_list)
        domain_entities = [e for e in entity_by_key.values() if e.get("entity_type") == "DOMAIN"]
        containers.extend([
            {
                "DistinguishedName": e.get("distinguished_name", ""),
                "gPLink": e.get("attributes", {}).get("gp_link", ""),
            }
            for e in domain_entities
        ])
        rule_data["edges"].extend(_parse_gpo_links_from_containers(containers, gpo_list))

    # ── Delegation edges ──────────────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("kerberos", "get-delegation-unconstrained"),
        ("kerberos", "get-delegation-constrained"),
        ("kerberos", "get-delegation-rbcd"),
        ("delegation_abuse_architecture", "get-delegation-unconstrained"),
        ("delegation_abuse_architecture", "get-delegation-constrained"),
    ]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            rule_data["edges"].extend(
                _parse_delegation_edges(out, domain=rule_data.get("domain_info", {}).get("domain", ""))
            )

    # ── Shadow credentials ────────────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("shadow_credentials", "get-shadow-credentials"),
        ("enum", "get-shadow-credentials"),
    ]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            rule_data["edges"].extend(_parse_shadow_credential_edges(out))

    # ── Cert templates (JSON path) ────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("adcs", "get-cert-templates"),
        ("pki", "get-cert-templates"),
        ("enum", "get-cert-templates"),
    ]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            rule_data["cert_templates"].extend(_parse_cert_templates_ps(out))

    # ── CA entities (JSON path) ───────────────────────────────────────────────
    for mod_id, cmd_id in [
        ("adcs", "get-ca-info"),
        ("pki", "get-ca-info"),
    ]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            for ca_entity in _parse_cas_ps(out, domain=rule_data.get("domain_info", {}).get("domain", "")):
                add_entity(ca_entity)

    # ── Trusts ────────────────────────────────────────────────────────────────
    for mod_id, cmd_id in [("enum", "get-adtrust"), ("topology", "get-adtrust-topology")]:
        out = _get_cmd_output(module_data, mod_id, cmd_id)
        if out:
            rule_data["trusts"].extend(_parse_trusts(out))

    # ── Domain info ───────────────────────────────────────────────────────────
    # Use update() not assignment so krbtgt_password_age_days from _enrich_domain_info is preserved
    out = _get_cmd_output(module_data, "enum", "get-addomain")
    if out:
        rule_data["domain_info"].update(_parse_domain_info(out))
    out = _get_cmd_output(module_data, "exposure_quick_checks", "quick-get-domain-policy")
    if out:
        rule_data["domain_info"].update(_parse_domain_info(out))

    # ── LAPS coverage ─────────────────────────────────────────────────────────
    laps_hosts: set[str] = set()
    for cmd_id in ("get-adcomputer-laps-legacy", "get-adcomputer-windows-laps"):
        out = _get_cmd_output(module_data, "laps", cmd_id)
        for rec in _parse_ps_list(out):
            name = _first(rec, "Name", "DNSHostName")
            if name and any(_has_value(v) for k, v in rec.items() if "laps" in k.lower() or "admpwd" in k.lower()):
                laps_hosts.add(name.lower())

    # ── SMB signing ───────────────────────────────────────────────────────────
    smb_out = _get_cmd_output(module_data, "smb", "get-smb-server-config")
    if smb_out:
        if re.search(r"RequireSecuritySignature\s*:\s*False", smb_out, re.I):
            rule_data["network_config"]["smb_signing_required"] = False
        if re.search(r"EnableSecuritySignature\s*:\s*False", smb_out, re.I):
            rule_data["network_config"]["smb_signing_disabled_hosts"].append("local-host")

    for mod_id, cmd_id in [
        ("exposure_quick_checks", "quick-reg-smb-signing"),
        ("network_posture", "reg-smb-signing"),
        ("legacy_protocols", "reg-smb-signing-server"),
    ]:
        val = _parse_reg_dword(_get_cmd_output(module_data, mod_id, cmd_id), "RequireSecuritySignature")
        if val is None:
            continue
        rule_data["network_config"]["smb_signing_required"] = val != 0
        if val == 0 and "local-host" not in rule_data["network_config"]["smb_signing_disabled_hosts"]:
            rule_data["network_config"]["smb_signing_disabled_hosts"].append("local-host")

    ldap_signing = _parse_reg_dword(
        _get_cmd_output(module_data, "exposure_quick_checks", "quick-reg-ldap-signing")
        or _get_cmd_output(module_data, "network_posture", "reg-ldap-signing")
        or _get_cmd_output(module_data, "legacy_protocols", "reg-ldap-signing"),
        "LDAPServerIntegrity",
    )
    if ldap_signing is not None:
        rule_data["network_config"]["ldap_signing"] = "required" if ldap_signing >= 2 else "disabled"

    ldap_channel_binding = _parse_reg_dword(
        _get_cmd_output(module_data, "exposure_quick_checks", "quick-reg-ldap-channel-binding")
        or _get_cmd_output(module_data, "network_posture", "reg-ldap-channel-binding"),
        "LdapEnforceChannelBinding",
    )
    if ldap_channel_binding is not None:
        rule_data["network_config"]["ldap_channel_binding"] = ldap_channel_binding >= 2

    lm_compat = _parse_reg_dword(
        _get_cmd_output(module_data, "exposure_quick_checks", "quick-reg-lmcompat")
        or _get_cmd_output(module_data, "network_posture", "reg-lm-compat"),
        "LmCompatibilityLevel",
    )
    if lm_compat is not None:
        rule_data["network_config"]["ntlm_lm_compat_level"] = lm_compat

    winrm_out = (
        _get_cmd_output(module_data, "exposure_quick_checks", "quick-winrm-service")
        or _get_cmd_output(module_data, "network_posture", "winrm-config")
        or _get_cmd_output(module_data, "network_posture", "winrm-listeners")
    )
    if winrm_out and not re.search(r"(error|not recognized|cannot find|access is denied)", winrm_out, re.I):
        rule_data["network_config"]["winrm_open"] = True
        rule_data["network_config"]["winrm_hosts"] = ["local-host"]

    rule_data["entities"] = list(entity_by_key.values())
    computers = [
        e for e in rule_data["entities"]
        if e.get("entity_type") in ("COMPUTER", "DC")
    ]
    if computers:
        laps_count = sum(1 for e in computers if (e.get("attributes") or {}).get("has_laps"))
        if laps_hosts:
            laps_count = max(laps_count, len(laps_hosts))
        rule_data["domain_info"]["total_computers"] = len(computers)
        rule_data["domain_info"]["laps_deployed"] = laps_count > 0
        rule_data["domain_info"]["laps_coverage_pct"] = int((laps_count / len(computers)) * 100)

    # Backward-compatible aliases for older callers that read these fields at top level.
    rule_data["smb_signing_required"] = rule_data["network_config"]["smb_signing_required"]
    rule_data["smb_signing_disabled_hosts"] = rule_data["network_config"]["smb_signing_disabled_hosts"]

    # Synthetic/native validation packs may include a tightly gated canonical
    # overlay. Keep this constrained so arbitrary collector modules cannot
    # smuggle central telemetry around the normal parser contracts.
    for module_id, module in module_data.items():
        overlay = module.get("canonical") if isinstance(module, dict) else None
        if not isinstance(overlay, dict):
            continue
        overlay_schema = str(module.get("canonical_overlay_schema") or "")
        if module_id != "coverage_expansion" or overlay_schema != "adbygod.coverage_expansion.v1":
            log.warning(
                "Ignoring unauthorized native collector canonical overlay in module %s",
                module_id,
            )
            continue
        for key in ("entities", "edges", "cert_templates", "ca_flags", "findings", "evidence"):
            if isinstance(overlay.get(key), list):
                rule_data.setdefault(key, [])
                rule_data[key].extend(overlay[key])
        for key in ("domain_info", "password_policy", "network_config"):
            if isinstance(overlay.get(key), dict):
                rule_data.setdefault(key, {})
                rule_data[key].update(overlay[key])
        if isinstance(overlay.get("trusts"), list):
            rule_data["trusts"].extend(overlay["trusts"])
        metadata = overlay.get("metadata") if isinstance(overlay.get("metadata"), dict) else {}
        for key in ("domain_info", "password_policy", "network_config"):
            if isinstance(metadata.get(key), dict):
                rule_data.setdefault(key, {})
                rule_data[key].update(metadata[key])
        if isinstance(metadata.get("trusts"), list):
            rule_data["trusts"].extend(metadata["trusts"])

    log.info(
        "Collector rule_data built: %d entities, policy=%s, trusts=%d",
        len(rule_data["entities"]),
        rule_data["password_policy"],
        len(rule_data["trusts"]),
    )
    return rule_data
