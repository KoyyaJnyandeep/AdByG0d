from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from adbygod_api.core.collection.acl_collector import (
    ACE_ALLOW,
    ACE_ALLOW_OBJECT,
    INHERITED_ACE,
    MASK_EXT_RIGHT,
    MASK_FULL_CONTROL,
    MASK_GENERIC_ALL,
    MASK_GENERIC_WRITE,
    MASK_WRITE_DACL,
    MASK_WRITE_OWNER,
    OBJ_TYPE_PRESENT,
    parse_sd_aces,
    _bytes_to_guid,
)

CLIENT_AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2",
    "1.3.6.1.4.1.311.20.2.2",
    "1.3.6.1.5.2.3.4",
    "2.5.29.37.0",
}
ANY_PURPOSE_EKU = "2.5.29.37.0"
CERT_REQUEST_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"
ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
PEND_ALL_REQUESTS = 0x00000002
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
ENROLL_EXTENDED_RIGHT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
AUTOENROLL_EXTENDED_RIGHT = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
ESC5_PRIVILEGED_DOMAIN_RIDS = {
    "512",  # Domain Admins
    "516",  # Domain Controllers
    "518",  # Schema Admins
    "519",  # Enterprise Admins
    "520",  # Group Policy Creator Owners
}

LOW_PRIV_WELL_KNOWN = {
    "S-1-1-0": "Everyone",
    "S-1-5-11": "Authenticated Users",
}
PRIVILEGED_WELL_KNOWN = {
    "S-1-5-18": "SYSTEM",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-32-544": "BUILTIN\\Administrators",
}
PRIVILEGED_NAME_MARKERS = (
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "system",
    "domain controllers",
    "enterprise domain controllers",
    "cert publishers",
    "ca admins",
    "certificate service",
)


@dataclass(frozen=True)
class Trustee:
    sid: str
    name: str
    is_privileged: bool = False


def coerce_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if hasattr(value, "values"):
        return list(value.values)
    if hasattr(value, "value"):
        value = value.value
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if str(value) in ("", "[]", "None"):
        return []
    return [value]


def parse_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    if hasattr(value, "values"):
        values = value.values
        value = values[0] if values else default
    elif hasattr(value, "value"):
        value = value.value
    if isinstance(value, (list, tuple)):
        value = value[0] if value else default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except ValueError:
        return default


def parse_ekus(*values: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        for item in coerce_list(value):
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    return out


def manager_approval_required(enrollment_flag: Any) -> bool:
    return bool(parse_int(enrollment_flag) & PEND_ALL_REQUESTS)


def ra_signature_count(value: Any) -> int:
    return parse_int(value)


def enrollee_supplies_subject(name_flag: Any) -> bool:
    return bool(parse_int(name_flag) & ENROLLEE_SUPPLIES_SUBJECT)


def esc6_enabled(edit_flags: Any) -> bool:
    return bool(parse_int(edit_flags) & EDITF_ATTRIBUTESUBJECTALTNAME2)


def parse_certutil_edit_flags(certutil_output: str) -> int | None:
    """Extract EditFlags integer from `certutil -getreg policy\\EditFlags` output."""
    import re
    if not certutil_output:
        return None
    m = re.search(r'EditFlags\s+REG_DWORD\s*=\s*(0x[0-9a-fA-F]+)', certutil_output, re.IGNORECASE)
    if m:
        return int(m.group(1), 16)
    m = re.search(r'EditFlags\s+REG_DWORD\s*=\s*(\d+)', certutil_output, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def certutil_has_editf_altsubjectname(certutil_output: str) -> bool:
    return "EDITF_ATTRIBUTESUBJECTALTNAME2" in (certutil_output or "")


def _is_privileged_name(name: str) -> bool:
    low = name.lower()
    return any(marker in low for marker in PRIVILEGED_NAME_MARKERS)


def is_low_priv_trustee(trustee: Trustee) -> bool:
    if trustee.sid in LOW_PRIV_WELL_KNOWN:
        return True
    if trustee.sid in PRIVILEGED_WELL_KNOWN:
        return False
    if trustee.is_privileged:
        return False
    return not _is_privileged_name(trustee.name or trustee.sid)


def sid_is_domain_users(sid: str) -> bool:
    return sid.endswith("-513")


def _esc5_sid_is_privileged(sid: str) -> bool:
    return bool(sid) and (
        sid in PRIVILEGED_WELL_KNOWN
        or sid.rsplit("-", 1)[-1] in ESC5_PRIVILEGED_DOMAIN_RIDS
    )


def _esc5_trustee_for_sid(sid: str, trustee_map: dict[str, Trustee]) -> Trustee:
    return trustee_map.get(sid) or Trustee(
        sid=sid,
        name=LOW_PRIV_WELL_KNOWN.get(
            sid,
            PRIVILEGED_WELL_KNOWN.get(sid, "Domain Users" if sid_is_domain_users(sid) else sid),
        ),
        is_privileged=_esc5_sid_is_privileged(sid),
    )


def _esc5_is_low_priv_trustee(trustee: Trustee) -> bool:
    name = trustee.name or trustee.sid
    low_name = name.lower()
    if trustee.sid in LOW_PRIV_WELL_KNOWN or sid_is_domain_users(trustee.sid):
        return True
    if _esc5_sid_is_privileged(trustee.sid) or trustee.is_privileged:
        return False
    if low_name.startswith("adg0d") or low_name.startswith("adg0d2"):
        return True
    return not _is_privileged_name(name)


def analyse_pki_object_acl(
    *,
    sd_raw: bytes | None,
    trustee_map: dict[str, Trustee],
    target_name: str,
    target_dn: str,
    object_class: str,
    include_inherited: bool = True,
) -> list[dict[str, Any]]:
    controls: list[dict[str, Any]] = []
    if not sd_raw:
        return controls

    for ace in parse_sd_aces(sd_raw):
        try:
            ace_type = ace["AceType"]
            if ace_type not in (ACE_ALLOW, ACE_ALLOW_OBJECT):
                continue
            is_inherited = bool(ace["AceFlags"] & INHERITED_ACE)
            if is_inherited and not include_inherited:
                continue
            inner = ace["Ace"]
            mask = inner["Mask"]["Mask"]
            sid = inner["Sid"].formatCanonical()
        except Exception:
            continue

        trustee = _esc5_trustee_for_sid(sid, trustee_map)
        if not _esc5_is_low_priv_trustee(trustee):
            continue

        rights: list[str] = []
        if mask & MASK_GENERIC_ALL:
            rights.append("GenericAll")
        elif (mask & MASK_FULL_CONTROL) == MASK_FULL_CONTROL:
            rights.append("FullControl")
        else:
            if mask & MASK_GENERIC_WRITE:
                rights.append("GenericWrite")
            if mask & MASK_WRITE_DACL:
                rights.append("WriteDacl")
            if mask & MASK_WRITE_OWNER:
                rights.append("WriteOwner")

        for right in rights:
            controls.append({
                "trustee": trustee.name,
                "trustee_sid": sid,
                "source_principal": trustee.name,
                "source_sid": sid,
                "target_name": target_name,
                "target_dn": target_dn,
                "object_class": object_class,
                "right": right,
                "is_inherited": is_inherited,
                "inheritance": "inherited" if is_inherited else "explicit",
                "raw_mask": hex(mask),
                "collection_method": "LDAP ACL",
                "why_esc5": "Dangerous non-admin control over an AD CS / PKI infrastructure object can compromise CA administration or certificate trust.",
            })
    return controls


def analyse_template_acl(
    sd_raw: bytes | None,
    trustee_map: dict[str, Trustee],
    include_inherited: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    enrollment: list[dict[str, Any]] = []
    write_rights: list[dict[str, Any]] = []
    if not sd_raw:
        return enrollment, write_rights

    for ace in parse_sd_aces(sd_raw):
        try:
            ace_type = ace["AceType"]
            if ace_type not in (ACE_ALLOW, ACE_ALLOW_OBJECT):
                continue
            is_inherited = bool(ace["AceFlags"] & INHERITED_ACE)
            if is_inherited and not include_inherited:
                continue
            inner = ace["Ace"]
            mask = inner["Mask"]["Mask"]
            sid = inner["Sid"].formatCanonical()
        except Exception:
            continue

        trustee = trustee_map.get(sid) or Trustee(
            sid=sid,
            name=LOW_PRIV_WELL_KNOWN.get(sid, PRIVILEGED_WELL_KNOWN.get(sid, "Domain Users" if sid_is_domain_users(sid) else sid)),
            is_privileged=sid in PRIVILEGED_WELL_KNOWN,
        )
        base = {
            "trustee_sid": sid,
            "trustee": trustee.name,
            "is_inherited": is_inherited,
            "is_low_privileged": is_low_priv_trustee(trustee) or sid_is_domain_users(sid),
        }

        object_guid = ""
        if ace_type == ACE_ALLOW_OBJECT:
            try:
                if inner["Flags"] & OBJ_TYPE_PRESENT:
                    object_guid = _bytes_to_guid(bytes(inner["ObjectType"]))
            except Exception:
                object_guid = ""

        if object_guid in {ENROLL_EXTENDED_RIGHT, AUTOENROLL_EXTENDED_RIGHT} and (mask & MASK_EXT_RIGHT):
            enrollment.append({
                **base,
                "right": "AutoEnroll" if object_guid == AUTOENROLL_EXTENDED_RIGHT else "Enroll",
                "guid": object_guid,
            })

        if (mask & MASK_GENERIC_ALL) or ((mask & MASK_FULL_CONTROL) == MASK_FULL_CONTROL):
            write_rights.append({**base, "right": "GenericAll", "raw_mask": hex(mask)})
            continue
        if mask & MASK_GENERIC_WRITE:
            write_rights.append({**base, "right": "GenericWrite", "raw_mask": hex(mask)})
        if mask & MASK_WRITE_DACL:
            write_rights.append({**base, "right": "WriteDacl", "raw_mask": hex(mask)})
        if mask & MASK_WRITE_OWNER:
            write_rights.append({**base, "right": "WriteOwner", "raw_mask": hex(mask)})

    return enrollment, write_rights


def has_low_priv_enrollment(enrollment_rights: list[dict[str, Any]]) -> bool:
    return any(r.get("is_low_privileged") for r in enrollment_rights)


def evaluate_template(template: dict[str, Any], published_ca_names: list[str]) -> dict[str, bool]:
    ekus = set(parse_ekus(template.get("ekus")))
    published = bool(published_ca_names)
    low_priv = has_low_priv_enrollment(template.get("enrollment_rights", []))
    approval_ok = not template.get("requires_manager_approval")
    ra_ok = ra_signature_count(template.get("authorized_signatures_required")) == 0
    return {
        "esc1_vulnerable": (
            published
            and enrollee_supplies_subject(template.get("msPKI-Certificate-Name-Flag"))
            and bool(ekus & CLIENT_AUTH_EKUS)
            and approval_ok
            and ra_ok
            and low_priv
        ),
        "esc2_vulnerable": (
            published
            and (ANY_PURPOSE_EKU in ekus or not ekus)
            and approval_ok
            and ra_ok
            and low_priv
        ),
        "esc3_vulnerable": (
            published
            and CERT_REQUEST_AGENT_EKU in ekus
            and approval_ok
            and ra_ok
            and low_priv
        ),
        "esc4_vulnerable": any(r.get("is_low_privileged") for r in template.get("write_rights", [])),
    }


def check_web_enrollment(
    url: str,
    timeout: float = 3.0,
    *,
    connect_url: str | None = None,
    host_header: str | None = None,
) -> dict[str, Any]:
    request_url = connect_url or url
    parsed = urlparse(request_url)
    if parsed.scheme not in {"http", "https"}:
        return {"url": url, "status_code": None, "exists": False, "error": "unsupported URL scheme"}

    request_url = connect_url or url
    parsed = urlparse(request_url)
    if parsed.scheme not in {"http", "https"}:
        return {"url": url, "status_code": None, "exists": False, "error": "unsupported URL scheme"}

    request_url = connect_url or url
    parsed = urlparse(request_url)
    if parsed.scheme not in {"http", "https"}:
        return {"url": url, "status_code": None, "exists": False, "error": "unsupported URL scheme"}

    request_url = connect_url or url
    parsed = urlparse(request_url)
    if parsed.scheme not in {"http", "https"}:
        return {"url": url, "status_code": None, "exists": False, "error": "unsupported URL scheme"}

    headers = {"User-Agent": "AdByG0d-readonly-adcs-check"}
    if host_header:
        headers["Host"] = host_header
    req = Request(request_url, headers=headers)
    try:
        # request_url is restricted to http(s) immediately above this call.
        with urlopen(req, timeout=timeout) as resp:  # nosec B310
            status = int(resp.status)
            return {"url": url, "status_code": status, "exists": status in {200, 401, 403}, "error": ""}
    except HTTPError as exc:
        status = int(exc.code)
        return {"url": url, "status_code": status, "exists": status in {200, 401, 403}, "error": ""}
    except (TimeoutError, socket.timeout):
        return {"url": url, "status_code": None, "exists": False, "error": "timeout"}
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, socket.timeout):
            return {"url": url, "status_code": None, "exists": False, "error": "timeout"}
        return {"url": url, "status_code": None, "exists": False, "error": str(reason)}
    except Exception as exc:
        return {"url": url, "status_code": None, "exists": False, "error": str(exc)}


def build_trustee_map(entities: list[dict]) -> dict[str, Trustee]:
    trustees: dict[str, Trustee] = {}
    for entity in entities:
        sid = str(entity.get("object_sid") or "")
        if not sid:
            continue
        name = str(entity.get("display_name") or entity.get("sam_account_name") or sid)
        trustees[sid] = Trustee(
            sid=sid,
            name=name,
            is_privileged=bool(entity.get("is_admin_count") or entity.get("tier") == 0 or entity.get("is_crown_jewel")),
        )
    return trustees


def adcs_finding(finding_type: str, title: str, severity: str, affected: list[dict], description: str, remediation: str) -> dict:
    return {
        "finding_type": finding_type,
        "module": "AD CS",
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": 0.95,
        "affected_count": len(affected),
        "affected_objects": affected,
        "root_cause": "Read-only LDAP/HTTP AD CS collection evidence",
        "causal_chain": [],
        "remediation": remediation,
        "remediation_steps": [],
        "fix_complexity": "medium",
        "references": ["https://posts.specterops.io/certified-pre-owned-d95910965cd2"],
        "technical_severity": 9.0 if severity == "CRITICAL" else 8.0,
        "reachability": 0.8,
        "evidence_refs": ["ldap-adcs"],
        "origin": "COLLECTED",
    }


def build_adcs_result(
    *,
    domain: str,
    dc_ip: str,
    entities: list[dict],
    template_rows: list[dict],
    ca_rows: list[dict],
    include_inherited: bool,
    check_adcs_web: bool,
    check_esc6: bool,
    pki_object_rows: list[dict] | None = None,
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict], dict]:
    ca_by_template: dict[str, list[str]] = {}
    ca_entities: list[dict] = []
    web_checks: list[dict] = []
    for row in ca_rows:
        name = str(row.get("cn") or row.get("name") or "")
        dn = str(row.get("distinguishedName", ""))
        host = str(row.get("dNSHostName") or "")
        published = [str(v) for v in coerce_list(row.get("certificateTemplates")) if str(v)]
        for template_name in published:
            ca_by_template.setdefault(template_name.lower(), []).append(name)
        attrs = {k: str(v) for k, v in row.items() if k != "nTSecurityDescriptor"}
        attrs["certificateTemplates"] = published
        attrs["esc6_checked"] = False
        attrs["esc6_reason"] = "CA EditFlags require Windows collector or remote registry; Linux LDAP collection does not expose policy\\EditFlags"
        if check_adcs_web and host:
            for scheme in ("http", "https"):
                url = f"{scheme}://{host}/certsrv"
                result = check_web_enrollment(url)
                if (not result["exists"]) and dc_ip and result.get("error") and "Name or service not known" in result.get("error", ""):
                    result = check_web_enrollment(url, connect_url=f"{scheme}://{dc_ip}/certsrv", host_header=host)
                result["ca_name"] = name
                web_checks.append(result)
                if result["exists"] or scheme == "http":
                    break
        ca_entities.append({
            "id": dn or name,
            "entity_type": "CA",
            "sam_account_name": name,
            "display_name": name,
            "dns_hostname": host,
            "distinguished_name": dn,
            "domain": domain,
            "is_enabled": True,
            "is_admin_count": False,
            "is_sensitive": True,
            "is_protected_user": False,
            "is_crown_jewel": True,
            "tier": 0,
            "attributes": attrs,
            "business_tags": ["Certificate Authority"],
        })

    trustees = build_trustee_map(entities)
    templates: list[dict] = []
    template_entities: list[dict] = []
    esc5_controls: list[dict[str, Any]] = []

    pki_rows = list(pki_object_rows or [])
    seen_pki_dns = {str(row.get("distinguishedName", "")).lower() for row in pki_rows}
    for ca_row in ca_rows:
        ca_dn = str(ca_row.get("distinguishedName", ""))
        if ca_dn and ca_dn.lower() not in seen_pki_dns:
            pki_rows.append({**ca_row, "objectClass": "pKIEnrollmentService"})
            seen_pki_dns.add(ca_dn.lower())
    for row in pki_rows:
        target_dn = str(row.get("distinguishedName", ""))
        target_name = str(row.get("cn") or row.get("name") or target_dn.split(",", 1)[0].replace("CN=", "") or "PKI object")
        object_class = ",".join(str(item) for item in coerce_list(row.get("objectClass"))) or "pkiObject"
        esc5_controls.extend(analyse_pki_object_acl(
            sd_raw=row.get("nTSecurityDescriptor"),
            trustee_map=trustees,
            target_name=target_name,
            target_dn=target_dn,
            object_class=object_class,
            include_inherited=include_inherited,
        ))

    for row in template_rows:
        name = str(row.get("cn") or row.get("name") or row.get("displayName") or "")
        display = str(row.get("displayName") or name)
        dn = str(row.get("distinguishedName", ""))
        name_flag = parse_int(row.get("msPKI-Certificate-Name-Flag"))
        enroll_flag = parse_int(row.get("msPKI-Enrollment-Flag"))
        ra_sigs = ra_signature_count(row.get("msPKI-RA-Signature"))
        ekus = parse_ekus(row.get("pKIExtendedKeyUsage"), row.get("msPKI-Certificate-Application-Policy"))
        enrollment_rights, write_rights = analyse_template_acl(
            row.get("nTSecurityDescriptor"),
            trustees,
            include_inherited=include_inherited,
        )
        ca_names = ca_by_template.get(name.lower(), [])
        template = {
            "name": name,
            "display_name": display,
            "distinguished_name": dn,
            "ca_name": ", ".join(ca_names),
            "ca_names": ca_names,
            "published": bool(ca_names),
            "enrollee_supplies_subject": enrollee_supplies_subject(name_flag),
            "requires_manager_approval": manager_approval_required(enroll_flag),
            "authorized_signatures_required": ra_sigs,
            "ekus": ekus,
            "enrollment_rights": enrollment_rights,
            "write_rights": write_rights,
            "msPKI-Certificate-Name-Flag": name_flag,
            "msPKI-Enrollment-Flag": enroll_flag,
            "attributes": {
                **{k: str(v) for k, v in row.items() if k != "nTSecurityDescriptor"},
                "published_by": ca_names,
                "collection_method": "ldap/adcs",
            },
        }
        template.update(evaluate_template(template, ca_names))
        templates.append(template)
        is_vulnerable = any(template.get(k) for k in ("esc1_vulnerable", "esc2_vulnerable", "esc3_vulnerable", "esc4_vulnerable"))
        template_entities.append({
            "id": dn or f"cert-template:{name}",
            "entity_type": "CERT_TEMPLATE",
            "sam_account_name": name,
            "display_name": display,
            "distinguished_name": dn,
            "domain": domain,
            "is_enabled": bool(ca_names),
            "is_admin_count": False,
            "is_sensitive": is_vulnerable,
            "is_protected_user": False,
            "is_crown_jewel": False,
            "tier": 0 if is_vulnerable else None,
            "attributes": template["attributes"],
            "business_tags": ["Certificate Template"],
        })

    findings: list[dict] = []
    esc8_affected = [
        {"ca_name": check["ca_name"], "url": check["url"], "status_code": check["status_code"]}
        for check in web_checks
        if check.get("exists")
    ]
    if esc8_affected:
        findings.append(adcs_finding(
            "ESC8_ADCS_WEB_ENROLLMENT_EXPOSED",
            f"{len(esc8_affected)} AD CS Web Enrollment endpoint(s) exposed",
            "CRITICAL",
            esc8_affected,
            "AD CS Web Enrollment endpoint exists and is reachable. This is exposure evidence only; no relay or authentication coercion was attempted.",
            "Disable legacy Web Enrollment if unused, or require HTTPS with Extended Protection for Authentication and reduce NTLM exposure.",
        ))
    if esc5_controls:
        findings.append(adcs_finding(
            "ESC5_PKI_OBJECT_CONTROL",
            "Non-admin principal controls AD CS / PKI infrastructure object",
            "CRITICAL",
            esc5_controls,
            "Dangerous ACLs on AD CS / PKI infrastructure objects give non-admin principals control over CA administration or certificate trust configuration.",
            "Remove GenericAll, GenericWrite, WriteDacl, WriteOwner, and FullControl from non-admin principals on AD CS / PKI infrastructure objects.",
        ))
    if check_esc6:
        for ca in ca_entities:
            attrs = ca.get("attributes", {})
            if esc6_enabled(attrs.get("edit_flags")):
                findings.append(adcs_finding(
                    "ESC6_CA_SAN_FLAG_ENABLED",
                    f"CA {ca['display_name']} has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
                    "CRITICAL",
                    [{"ca_name": ca["display_name"], "edit_flags": attrs.get("edit_flags")}],
                    "CA policy module allows request-supplied SAN globally.",
                    "Disable EDITF_ATTRIBUTESUBJECTALTNAME2 and restart CertSvc after change control.",
                ))

    published_count = sum(1 for t in templates if t.get("published"))
    esc_counts = {
        "esc1": sum(1 for t in templates if t.get("esc1_vulnerable")),
        "esc2": sum(1 for t in templates if t.get("esc2_vulnerable")),
        "esc3": sum(1 for t in templates if t.get("esc3_vulnerable")),
        "esc4": sum(1 for t in templates if t.get("esc4_vulnerable")),
    }
    coverage = {
        "templates_collected": len(templates),
        "ca_objects_collected": len(ca_entities),
        "published_templates_resolved": published_count,
        "esc_counts": esc_counts,
        "esc5_findings": len(esc5_controls),
        "esc6_checked": False,
        "esc6_reason": "Linux LDAP collector cannot safely read CA policy EditFlags; use Windows collector or remote registry support",
        "esc8_endpoints_checked": len(web_checks),
        "esc8_endpoints": web_checks,
    }
    evidence = [{
        "id": "ldap-adcs",
        "source_type": "ldap",
        "source_host": dc_ip,
        "collection_method": "ldap/adcs",
        "origin": "COLLECTED",
        "raw_data": coverage,
        "confidence": 1.0,
    }]
    return ca_entities, template_entities, templates, findings, evidence, coverage
