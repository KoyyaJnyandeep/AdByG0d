from __future__ import annotations

import struct
from unittest.mock import MagicMock


def _make_guid_bytes(guid_str: str) -> bytes:
    parts = guid_str.replace("-", "")
    return (
        struct.pack("<IHH", int(parts[0:8], 16), int(parts[8:12], 16), int(parts[12:16], 16))
        + bytes.fromhex(parts[16:20])
        + bytes.fromhex(parts[20:32])
    )


def _sid_mock(sid_str: str) -> MagicMock:
    sid = MagicMock()
    sid.formatCanonical.return_value = sid_str
    return sid


def _object_ace(mask: int, sid_str: str, object_type_guid: str) -> MagicMock:
    inner = MagicMock()
    inner.__getitem__.side_effect = lambda k: {
        "Mask": MagicMock(**{"__getitem__.return_value": mask}),
        "Sid": _sid_mock(sid_str),
        "Flags": 0x01,
        "ObjectType": _make_guid_bytes(object_type_guid),
    }[k]
    ace = MagicMock()
    ace.__getitem__.side_effect = lambda k: {"AceType": 5, "AceFlags": 0, "Ace": inner}[k]
    return ace


def _allow_ace(mask: int, sid_str: str) -> MagicMock:
    inner = MagicMock()
    inner.__getitem__.side_effect = lambda k: {
        "Mask": MagicMock(**{"__getitem__.return_value": mask}),
        "Sid": _sid_mock(sid_str),
    }[k]
    ace = MagicMock()
    ace.__getitem__.side_effect = lambda k: {"AceType": 0, "AceFlags": 0, "Ace": inner}[k]
    return ace


def test_adcs_parses_eku_flags_and_approval():
    from adbygod_api.core.collection import adcs

    assert adcs.parse_ekus("1.3.6.1.5.5.7.3.2", ["2.5.29.37.0"]) == [
        "1.3.6.1.5.5.7.3.2",
        "2.5.29.37.0",
    ]
    assert adcs.enrollee_supplies_subject(0x1) is True
    assert adcs.manager_approval_required(0x2) is True
    assert adcs.ra_signature_count(None) == 0
    assert adcs.esc6_enabled(0x00040000) is True


def test_low_priv_enrollment_and_esc1_esc2_esc3_positive(monkeypatch):
    from adbygod_api.core.collection import adcs

    monkeypatch.setattr(adcs, "parse_sd_aces", lambda _raw: [
        _object_ace(adcs.MASK_EXT_RIGHT, "S-1-5-11", adcs.ENROLL_EXTENDED_RIGHT),
    ])
    enrollment, writes = adcs.analyse_template_acl(b"sd", {})
    assert writes == []
    assert enrollment[0]["trustee"] == "Authenticated Users"
    assert adcs.has_low_priv_enrollment(enrollment)

    base = {
        "published": True,
        "ca_name": "LAB-DC01-CA",
        "enrollment_rights": enrollment,
        "requires_manager_approval": False,
        "authorized_signatures_required": 0,
    }
    esc1 = {**base, "name": "ADG0D-ESC1-SupplySAN", "msPKI-Certificate-Name-Flag": 1, "ekus": ["1.3.6.1.5.5.7.3.2"]}
    esc2 = {**base, "name": "ADG0D-ESC2-AnyPurpose", "msPKI-Certificate-Name-Flag": 0, "ekus": ["2.5.29.37.0"]}
    esc3 = {**base, "name": "ADG0D-ESC3-EnrollmentAgent", "msPKI-Certificate-Name-Flag": 0, "ekus": ["1.3.6.1.4.1.311.20.2.1"]}

    assert adcs.evaluate_template(esc1, ["LAB-DC01-CA"])["esc1_vulnerable"] is True
    assert adcs.evaluate_template(esc2, ["LAB-DC01-CA"])["esc2_vulnerable"] is True
    assert adcs.evaluate_template(esc3, ["LAB-DC01-CA"])["esc3_vulnerable"] is True


def test_esc4_positive_and_safe_negative(monkeypatch):
    from adbygod_api.core.collection import adcs

    monkeypatch.setattr(adcs, "parse_sd_aces", lambda _raw: [
        _allow_ace(adcs.MASK_GENERIC_ALL, "S-1-5-21-1-2-3-1108"),
    ])
    trustees = {
        "S-1-5-21-1-2-3-1108": adcs.Trustee(
            sid="S-1-5-21-1-2-3-1108",
            name="ADG0D-ESC4-Template-Admins",
            is_privileged=False,
        )
    }
    enrollment, writes = adcs.analyse_template_acl(b"sd", trustees)
    assert enrollment == []
    assert writes[0]["right"] == "GenericAll"
    assert writes[0]["is_low_privileged"] is True

    vulnerable = {
        "name": "ADG0D-ESC4-WeakTemplateACL",
        "enrollment_rights": [],
        "write_rights": writes,
        "requires_manager_approval": True,
        "authorized_signatures_required": 1,
        "ekus": [],
        "msPKI-Certificate-Name-Flag": 0,
    }
    assert adcs.evaluate_template(vulnerable, ["LAB-DC01-CA"])["esc4_vulnerable"] is True

    safe = {**vulnerable, "write_rights": []}
    assert not any(adcs.evaluate_template(safe, ["LAB-DC01-CA"]).values())
    assert not any(adcs.evaluate_template({**vulnerable, "write_rights": []}, []).values())


def _esc5_entities():
    return [{
        "object_sid": "S-1-5-21-1-2-3-5501",
        "display_name": "ADG0D-ESC5-PKI-Admins",
        "sam_account_name": "ADG0D-ESC5-PKI-Admins",
        "entity_type": "GROUP",
        "is_admin_count": False,
        "tier": None,
        "is_crown_jewel": False,
    }]


def _esc5_findings(result):
    return [f for f in result[3] if f.get("finding_type") == "ESC5_PKI_OBJECT_CONTROL"]


def test_esc5_genericall_on_ca_enrollment_service_triggers(monkeypatch):
    from adbygod_api.core.collection import adcs

    monkeypatch.setattr(adcs, "parse_sd_aces", lambda _raw: [
        _allow_ace(adcs.MASK_GENERIC_ALL, "S-1-5-21-1-2-3-5501"),
    ])
    result = adcs.build_adcs_result(
        domain="lab.local",
        dc_ip="192.168.56.10",
        entities=_esc5_entities(),
        template_rows=[],
        ca_rows=[{
            "cn": "LAB-DC01-CA",
            "distinguishedName": "CN=LAB-DC01-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
            "dNSHostName": "dc01.lab.local",
            "certificateTemplates": [],
            "nTSecurityDescriptor": b"sd",
        }],
        include_inherited=True,
        check_adcs_web=False,
        check_esc6=False,
    )
    finding = _esc5_findings(result)[0]
    affected = finding["affected_objects"][0]
    assert affected["trustee"] == "ADG0D-ESC5-PKI-Admins"
    assert affected["target_name"] == "LAB-DC01-CA"
    assert affected["target_dn"].startswith("CN=LAB-DC01-CA")
    assert affected["object_class"] == "pKIEnrollmentService"
    assert affected["right"] == "GenericAll"
    assert affected["inheritance"] == "explicit"
    assert affected["collection_method"] == "LDAP ACL"
    assert result[5]["esc5_findings"] == 1


def test_esc5_writedacl_on_ntauthcertificates_triggers(monkeypatch):
    from adbygod_api.core.collection import adcs

    monkeypatch.setattr(adcs, "parse_sd_aces", lambda _raw: [
        _allow_ace(adcs.MASK_WRITE_DACL, "S-1-5-21-1-2-3-5501"),
    ])
    result = adcs.build_adcs_result(
        domain="lab.local",
        dc_ip="192.168.56.10",
        entities=_esc5_entities(),
        template_rows=[],
        ca_rows=[],
        pki_object_rows=[{
            "cn": "NTAuthCertificates",
            "distinguishedName": "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
            "objectClass": "certificationAuthority",
            "nTSecurityDescriptor": b"sd",
        }],
        include_inherited=True,
        check_adcs_web=False,
        check_esc6=False,
    )
    affected = _esc5_findings(result)[0]["affected_objects"][0]
    assert affected["target_name"] == "NTAuthCertificates"
    assert affected["right"] == "WriteDacl"


def test_esc5_writeowner_on_certificate_templates_container_triggers(monkeypatch):
    from adbygod_api.core.collection import adcs

    monkeypatch.setattr(adcs, "parse_sd_aces", lambda _raw: [
        _allow_ace(adcs.MASK_WRITE_OWNER, "S-1-5-21-1-2-3-5501"),
    ])
    result = adcs.build_adcs_result(
        domain="lab.local",
        dc_ip="192.168.56.10",
        entities=_esc5_entities(),
        template_rows=[],
        ca_rows=[],
        pki_object_rows=[{
            "cn": "Certificate Templates",
            "distinguishedName": "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
            "objectClass": "container",
            "nTSecurityDescriptor": b"sd",
        }],
        include_inherited=True,
        check_adcs_web=False,
        check_esc6=False,
    )
    affected = _esc5_findings(result)[0]["affected_objects"][0]
    assert affected["target_name"] == "Certificate Templates"
    assert affected["right"] == "WriteOwner"


def test_esc5_domain_admins_and_safe_right_do_not_trigger(monkeypatch):
    from adbygod_api.core.collection import adcs

    domain_admins_sid = "S-1-5-21-1-2-3-512"
    monkeypatch.setattr(adcs, "parse_sd_aces", lambda _raw: [
        _allow_ace(adcs.MASK_GENERIC_ALL, domain_admins_sid),
        _allow_ace(0x00020000, "S-1-5-21-1-2-3-5501"),
    ])
    result = adcs.build_adcs_result(
        domain="lab.local",
        dc_ip="192.168.56.10",
        entities=[
            *_esc5_entities(),
            {
                "object_sid": domain_admins_sid,
                "display_name": "Domain Admins",
                "sam_account_name": "Domain Admins",
                "entity_type": "GROUP",
                "is_admin_count": True,
                "tier": 0,
                "is_crown_jewel": True,
            },
        ],
        template_rows=[],
        ca_rows=[],
        pki_object_rows=[{
            "cn": "Public Key Services",
            "distinguishedName": "CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
            "objectClass": "container",
            "nTSecurityDescriptor": b"sd",
        }],
        include_inherited=True,
        check_adcs_web=False,
        check_esc6=False,
    )
    assert _esc5_findings(result) == []


def test_esc8_http_status_and_timeout(monkeypatch):
    from urllib.error import HTTPError, URLError
    import socket

    from adbygod_api.core.collection import adcs

    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    monkeypatch.setattr(adcs, "urlopen", lambda *_args, **_kwargs: Response())
    assert adcs.check_web_enrollment("http://dc01.lab.local/certsrv")["exists"] is True

    monkeypatch.setattr(adcs, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        HTTPError("http://dc01.lab.local/certsrv", 401, "Unauthorized", {}, None)
    ))
    assert adcs.check_web_enrollment("http://dc01.lab.local/certsrv")["exists"] is True

    monkeypatch.setattr(adcs, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(
        URLError(socket.timeout("timed out"))
    ))
    timed_out = adcs.check_web_enrollment("http://dc01.lab.local/certsrv")
    assert timed_out["exists"] is False
    assert timed_out["error"] == "timeout"


def test_ldap_adcs_collector_resolves_lab_objects(monkeypatch):
    from adbygod_api.core.collection import adcs
    from adbygod_api.core.collection.ldap_collector import LDAPCollector

    collector = LDAPCollector(
        dc_ip="192.168.56.10",
        domain="lab.local",
        username="scanner@lab.local",
        password="secret",
        auth_method="SIMPLE",
        enum_adcs=True,
    )
    collector._base_dn = "DC=lab,DC=local"
    collector._conn = MagicMock()
    collector._emit = lambda *_args, **_kwargs: None

    monkeypatch.setattr(adcs, "parse_sd_aces", lambda _raw: [
        _object_ace(adcs.MASK_EXT_RIGHT, "S-1-5-11", adcs.ENROLL_EXTENDED_RIGHT),
        _allow_ace(adcs.MASK_GENERIC_ALL, "S-1-5-21-1-2-3-1108"),
    ])
    monkeypatch.setattr(adcs, "check_web_enrollment", lambda url, **_kwargs: {
        "url": url,
        "status_code": 200,
        "exists": url == "http://dc01.lab.local/certsrv",
        "error": "",
    })

    def fake_search_with_sd(search_filter, _attributes, search_base, **_kwargs):
        if search_filter == "(objectClass=*)":
            return []
        if search_filter == "(objectClass=pKIEnrollmentService)":
            return [{
                "cn": "LAB-DC01-CA",
                "distinguishedName": "CN=LAB-DC01-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
                "dNSHostName": "dc01.lab.local",
                "certificateTemplates": [
                    "ADG0D-ESC1-SupplySAN",
                    "ADG0D-ESC2-AnyPurpose",
                    "ADG0D-ESC3-EnrollmentAgent",
                    "ADG0D-ESC4-WeakTemplateACL",
                ],
            }]
        return [
            {
                "cn": "ADG0D-ESC1-SupplySAN",
                "distinguishedName": "CN=ADG0D-ESC1-SupplySAN,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
                "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
                "msPKI-Certificate-Name-Flag": 1,
                "nTSecurityDescriptor": b"sd",
            },
            {
                "cn": "ADG0D-ESC2-AnyPurpose",
                "distinguishedName": "CN=ADG0D-ESC2-AnyPurpose,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
                "pKIExtendedKeyUsage": ["2.5.29.37.0"],
                "nTSecurityDescriptor": b"sd",
            },
            {
                "cn": "ADG0D-ESC3-EnrollmentAgent",
                "distinguishedName": "CN=ADG0D-ESC3-EnrollmentAgent,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
                "pKIExtendedKeyUsage": ["1.3.6.1.4.1.311.20.2.1"],
                "nTSecurityDescriptor": b"sd",
            },
            {
                "cn": "ADG0D-ESC4-WeakTemplateACL",
                "distinguishedName": "CN=ADG0D-ESC4-WeakTemplateACL,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=local",
                "pKIExtendedKeyUsage": [],
                "nTSecurityDescriptor": b"sd",
            },
        ]

    monkeypatch.setattr(collector, "_search_with_sd", fake_search_with_sd)
    ca_entities, template_entities, templates, findings, evidence, coverage = collector._enum_adcs([])

    assert ca_entities[0]["display_name"] == "LAB-DC01-CA"
    assert len(template_entities) == 4
    by_name = {t["name"]: t for t in templates}
    assert by_name["ADG0D-ESC1-SupplySAN"]["esc1_vulnerable"] is True
    assert by_name["ADG0D-ESC2-AnyPurpose"]["esc2_vulnerable"] is True
    assert by_name["ADG0D-ESC3-EnrollmentAgent"]["esc3_vulnerable"] is True
    assert by_name["ADG0D-ESC4-WeakTemplateACL"]["esc4_vulnerable"] is True
    assert coverage["published_templates_resolved"] == 4
    assert coverage["esc8_endpoints_checked"] == 1
    assert coverage["esc6_checked"] is False
    assert any(f["finding_type"] == "ESC8_ADCS_WEB_ENROLLMENT_EXPOSED" for f in findings)
    assert evidence[0]["raw_data"]["templates_collected"] == 4


# ── ESC6 bit-parsing unit tests ───────────────────────────────────────────────

def test_esc6_bit_parse_vulnerable():
    from adbygod_api.core.collection.adcs import esc6_enabled
    assert esc6_enabled(0x00040000) is True
    assert esc6_enabled(0x00160004 | 0x00040000) is True   # multiple flags set
    assert esc6_enabled("0x00040000") is True               # hex string
    assert esc6_enabled(262144) is True                     # decimal integer


def test_esc6_bit_parse_not_vulnerable():
    from adbygod_api.core.collection.adcs import esc6_enabled
    assert esc6_enabled(0) is False
    assert esc6_enabled(0x00120004) is False  # common default, ESC6 bit absent
    assert esc6_enabled(None) is False
    assert esc6_enabled("0") is False


# ── certutil output parsing tests ────────────────────────────────────────────

def test_parse_certutil_edit_flags_hex():
    from adbygod_api.core.collection.adcs import parse_certutil_edit_flags
    out = "  EditFlags REG_DWORD = 0x00120004 (1179652)\n"
    assert parse_certutil_edit_flags(out) == 0x00120004


def test_parse_certutil_edit_flags_none():
    from adbygod_api.core.collection.adcs import parse_certutil_edit_flags
    assert parse_certutil_edit_flags("") is None
    assert parse_certutil_edit_flags("no flags here") is None
    assert parse_certutil_edit_flags(None) is None


def test_certutil_has_editf_altsubjectname_positive():
    from adbygod_api.core.collection.adcs import certutil_has_editf_altsubjectname
    out = (
        "  EditFlags REG_DWORD = 0x00160004 (1441796)\n"
        "    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 262144 (0x40000)\n"
    )
    assert certutil_has_editf_altsubjectname(out) is True


def test_certutil_has_editf_altsubjectname_negative():
    from adbygod_api.core.collection.adcs import certutil_has_editf_altsubjectname
    assert certutil_has_editf_altsubjectname("EditFlags REG_DWORD = 0x00120004") is False
    assert certutil_has_editf_altsubjectname("") is False
    assert certutil_has_editf_altsubjectname(None) is False


# ── rule_engine ESC6 rule tests ───────────────────────────────────────────────

def test_rule_esc6_fires_from_ca_flags():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine
    engine = RuleEngine()
    data = {
        "ca_flags": [{
            "ca_name": "LAB-DC01-CA",
            "hostname": "dc01.lab.local",
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\LAB-DC01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy",
            "edit_flags": 0x00040000,
            "edit_flags_hex": "0x00040000",
            "editf_attribute_subject_alt_name_2": True,
            "certutil_output": "",
            "collection_method": "windows_ca_flags",
        }],
        "entities": [],
        "cert_templates": [],
    }
    matches = engine.evaluate_all(data)
    esc6 = [m for m in matches if m.finding_type == "ESC6_CA_SAN_FLAG_ENABLED"]
    assert len(esc6) == 1
    assert esc6[0].severity == "CRITICAL"
    assert esc6[0].is_tier0_direct is True
    assert esc6[0].affected_objects[0]["ca_name"] == "LAB-DC01-CA"
    assert esc6[0].affected_objects[0]["flag_name"] == "EDITF_ATTRIBUTESUBJECTALTNAME2"
    assert "SAN" in esc6[0].title


def test_rule_esc6_fires_from_bit_flag():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine
    engine = RuleEngine()
    data = {
        "ca_flags": [{
            "ca_name": "LAB-DC01-CA",
            "hostname": "dc01.lab.local",
            "edit_flags": 0x00040000,
            "editf_attribute_subject_alt_name_2": False,  # direct bool not set
            "certutil_output": "",
            "collection_method": "windows_ca_flags",
        }],
        "entities": [],
        "cert_templates": [],
    }
    matches = engine.evaluate_all(data)
    esc6 = [m for m in matches if m.finding_type == "ESC6_CA_SAN_FLAG_ENABLED"]
    assert len(esc6) == 1  # bit check should catch it


def test_rule_esc6_fires_from_certutil_text():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine
    engine = RuleEngine()
    data = {
        "ca_flags": [{
            "ca_name": "LAB-DC01-CA",
            "hostname": "dc01.lab.local",
            "edit_flags": 0,
            "editf_attribute_subject_alt_name_2": False,
            "certutil_output": "  EDITF_ATTRIBUTESUBJECTALTNAME2 -- 262144 (0x40000)\n",
            "collection_method": "windows_ca_flags",
        }],
        "entities": [],
        "cert_templates": [],
    }
    matches = engine.evaluate_all(data)
    esc6 = [m for m in matches if m.finding_type == "ESC6_CA_SAN_FLAG_ENABLED"]
    assert len(esc6) == 1


def test_rule_esc6_no_finding_when_flag_not_set():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine
    engine = RuleEngine()
    data = {
        "ca_flags": [{
            "ca_name": "LAB-DC01-CA",
            "hostname": "dc01.lab.local",
            "edit_flags": 0x00120004,  # common default, no ESC6 bit
            "editf_attribute_subject_alt_name_2": False,
            "certutil_output": "EditFlags REG_DWORD = 0x00120004",
            "collection_method": "windows_ca_flags",
        }],
        "entities": [],
        "cert_templates": [],
    }
    matches = engine.evaluate_all(data)
    esc6 = [m for m in matches if m.finding_type == "ESC6_CA_SAN_FLAG_ENABLED"]
    assert len(esc6) == 0


def test_rule_esc6_no_finding_when_no_ca_flags():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine
    engine = RuleEngine()
    data = {"ca_flags": [], "entities": [], "cert_templates": []}
    matches = engine.evaluate_all(data)
    esc6 = [m for m in matches if m.finding_type == "ESC6_CA_SAN_FLAG_ENABLED"]
    assert len(esc6) == 0


# ── Coverage skip test ────────────────────────────────────────────────────────

def test_esc6_coverage_false_for_linux_ldap(monkeypatch):
    from adbygod_api.core.collection import adcs

    monkeypatch.setattr(adcs, "parse_sd_aces", lambda _raw: [])

    ca_entities, template_entities, templates, findings, evidence, coverage = adcs.build_adcs_result(
        domain="lab.local",
        dc_ip="192.168.56.10",
        entities=[],
        template_rows=[],
        ca_rows=[{
            "cn": "LAB-DC01-CA",
            "distinguishedName": "CN=LAB-DC01-CA,CN=Enrollment Services,...",
            "dNSHostName": "dc01.lab.local",
            "certificateTemplates": [],
        }],
        include_inherited=True,
        check_adcs_web=False,
        check_esc6=False,
    )
    assert coverage["esc6_checked"] is False
    assert "EditFlags" in coverage["esc6_reason"] or "CA" in coverage["esc6_reason"]
    esc6_findings = [f for f in findings if f.get("finding_type") == "ESC6_CA_SAN_FLAG_ENABLED"]
    assert len(esc6_findings) == 0


# ── Import JSON → ESC6 finding integration test ───────────────────────────────

def test_ca_flags_json_import_produces_esc6_finding():
    """Simulate the output of Collect-AdByG0d-ADCS-CAFlags.ps1 going through the rule engine."""
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    # Represents the ca_flags array from the PS1 script JSON output
    ps1_ca_flags = [
        {
            "ca_name": "LAB-DC01-CA",
            "hostname": "DC01.lab.local",
            "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\LAB-DC01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy",
            "edit_flags": 262144,
            "edit_flags_hex": "0x00040000",
            "editf_attribute_subject_alt_name_2": True,
            "certutil_output": (
                "  EditFlags REG_DWORD = 0x00040000 (262144)\n"
                "    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 262144 (0x40000)\n"
                "CertUtil: -getreg command completed successfully."
            ),
            "collection_method": "windows_ca_flags",
            "collected_at": "2026-05-02T10:00:00Z",
        }
    ]

    engine = RuleEngine()
    matches = engine.evaluate_all({
        "ca_flags": ps1_ca_flags,
        "entities": [],
        "cert_templates": [],
    })

    esc6 = [m for m in matches if m.finding_type == "ESC6_CA_SAN_FLAG_ENABLED"]
    assert len(esc6) == 1

    m = esc6[0]
    assert m.severity == "CRITICAL"
    assert m.is_tier0_direct is True
    assert m.technical_severity == 10.0
    assert m.affected_objects[0]["ca_name"] == "LAB-DC01-CA"
    assert m.affected_objects[0]["host"] == "DC01.lab.local"
    assert m.affected_objects[0]["flag_name"] == "EDITF_ATTRIBUTESUBJECTALTNAME2"
    assert m.affected_objects[0]["collection_method"] == "windows_ca_flags"
    assert "LAB-DC01-CA" in m.title
    assert "SAN" in m.title
    assert "T1649" in m.mitre_attack_ids


def test_esc1_expert_fires_on_esc1_vulnerable_flag_without_low_priv_enrollment():
    """ESC1 expert must fire on esc1_vulnerable=True even without low_priv_enrollment key."""
    import asyncio
    from adbygod_api.core.validation.experts.adcs import ESC1Expert
    from dataclasses import dataclass, field

    @dataclass
    class FakeCtx:
        certificate_templates: list = field(default_factory=list)
        findings: list = field(default_factory=list)

    # Template as it comes from DB: has esc1_vulnerable, no low_priv_enrollment
    ctx = FakeCtx(certificate_templates=[{
        "esc1_vulnerable": True,
        "name": "DB-Template",
    }])

    expert = ESC1Expert()
    decision = asyncio.run(expert.analyze(ctx))

    assert decision.verdict.name == "SUPPORTS_EXPOSURE", (
        f"Expected SUPPORTS_EXPOSURE, got {decision.verdict.name}"
    )
    assert decision.score_delta > 0
