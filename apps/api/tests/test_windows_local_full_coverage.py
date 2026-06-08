from __future__ import annotations

import json
from adbygod_api.core.analyzers.collector_analyzer import (
    _parse_json_or_text,
    _parse_groups,
    _parse_ous,
    _parse_gpos,
    _parse_gpo_links_from_containers,
    _parse_delegation_edges,
    _parse_shadow_credential_edges,
    _parse_cert_templates_ps,
    _parse_cas_ps,
    _build_domain_entity,
    _enrich_domain_info,
    build_rule_data_from_collector,
)


def test_parse_json_or_text_handles_json_array():
    data = [{"SamAccountName": "alice", "objectSid": "S-1-5-21-1"}]
    result = _parse_json_or_text(json.dumps(data))
    assert result == data


def test_parse_json_or_text_handles_json_object():
    data = {"SamAccountName": "alice"}
    result = _parse_json_or_text(json.dumps(data))
    assert result == [data]


def test_parse_json_or_text_falls_back_to_ps_list_on_plain_text():
    text = "SamAccountName : alice\nDistinguishedName : CN=alice,DC=corp,DC=local\n"
    result = _parse_json_or_text(text)
    assert result == [{"SamAccountName": "alice", "DistinguishedName": "CN=alice,DC=corp,DC=local"}]


def test_parse_json_or_text_returns_empty_list_on_empty_input():
    assert _parse_json_or_text("") == []
    assert _parse_json_or_text(None) == []


def test_parse_groups_produces_group_entity():
    data = json.dumps([{
        "SamAccountName": "Domain Admins",
        "objectSid": {"Value": "S-1-5-21-1-512"},
        "DistinguishedName": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "Name": "Domain Admins",
        "adminCount": 1,
        "member": ["CN=alice,DC=corp,DC=local"],
    }])
    entities, edges = _parse_groups(data, domain="corp.local")
    assert len(entities) == 1
    g = entities[0]
    assert g["entity_type"] == "GROUP"
    assert g["sam_account_name"] == "Domain Admins"
    assert g["id"] == "S-1-5-21-1-512"
    assert g["is_admin_count"] is True
    assert g["is_crown_jewel"] is True
    assert g["tier"] == 0


def test_parse_groups_produces_member_of_edges():
    data = json.dumps([{
        "SamAccountName": "Backup Operators",
        "objectSid": {"Value": "S-1-5-21-1-551"},
        "DistinguishedName": "CN=Backup Operators,CN=Builtin,DC=corp,DC=local",
        "Name": "Backup Operators",
        "adminCount": None,
        "member": [
            "CN=alice,CN=Users,DC=corp,DC=local",
            "CN=bob,CN=Users,DC=corp,DC=local",
        ],
    }])
    entities, edges = _parse_groups(data, domain="corp.local")
    assert len(edges) == 2
    assert edges[0]["edge_type"] == "MEMBER_OF"
    assert edges[0]["target_id"] == "S-1-5-21-1-551"
    assert edges[0]["source_id"] == "CN=alice,CN=Users,DC=corp,DC=local"
    assert edges[1]["source_id"] == "CN=bob,CN=Users,DC=corp,DC=local"


def test_parse_groups_handles_string_sid_value():
    """objectSid may be a plain string rather than a {Value: ...} object depending on PS version."""
    data = json.dumps([{
        "SamAccountName": "TestGroup",
        "objectSid": "S-1-5-21-1-9999",
        "DistinguishedName": "CN=TestGroup,DC=corp,DC=local",
        "Name": "TestGroup",
        "adminCount": None,
        "member": None,
    }])
    entities, edges = _parse_groups(data, domain="corp.local")
    assert entities[0]["id"] == "S-1-5-21-1-9999"
    assert edges == []


def test_parse_groups_falls_back_gracefully_on_empty():
    entities, edges = _parse_groups("", domain="corp.local")
    assert entities == []
    assert edges == []


def test_parse_ous_produces_ou_entities():
    data = json.dumps([{
        "DistinguishedName": "OU=Workstations,DC=corp,DC=local",
        "Name": "Workstations",
        "gPLink": "[LDAP://CN={31B2F340},CN=Policies,CN=System,DC=corp,DC=local;0]",
        "gPOptions": 0,
        "objectSid": None,
    }])
    entities = _parse_ous(data, domain="corp.local")
    assert len(entities) == 1
    ou = entities[0]
    assert ou["entity_type"] == "OU"
    assert ou["id"] == "OU=Workstations,DC=corp,DC=local"
    assert ou["attributes"]["gp_link"].startswith("[LDAP://")


def test_parse_gpos_produces_gpo_entities():
    data = json.dumps([{
        "DisplayName": "Default Domain Policy",
        "Id": "31B2F340-016D-11D2-945F-00C04FB984F9",
        "DistinguishedName": "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local",
    }])
    entities = _parse_gpos(data, domain="corp.local")
    assert len(entities) == 1
    gpo = entities[0]
    assert gpo["entity_type"] == "GPO"
    assert gpo["display_name"] == "Default Domain Policy"
    assert gpo["attributes"]["gpo_guid"] == "31B2F340-016D-11D2-945F-00C04FB984F9"


def test_parse_gpo_links_from_containers_resolves_applies_gpo_edges():
    gpo_dn = "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local"
    containers = [{"DistinguishedName": "DC=corp,DC=local", "gPLink": f"[LDAP://{gpo_dn};0]"}]
    gpos = [{"id": gpo_dn, "distinguished_name": gpo_dn, "entity_type": "GPO"}]
    edges = _parse_gpo_links_from_containers(containers, gpos)
    assert len(edges) == 1
    e = edges[0]
    assert e["edge_type"] == "APPLIES_GPO"
    assert e["source_id"] == gpo_dn
    assert e["target_id"] == "DC=corp,DC=local"
    assert e["attributes"]["enforced"] is False


def test_parse_gpo_links_skips_disabled_links():
    gpo_dn = "CN={AAAAAAAA},CN=Policies,CN=System,DC=corp,DC=local"
    # link_opts & 0x01 == 1 → disabled
    containers = [{"DistinguishedName": "OU=Test,DC=corp,DC=local", "gPLink": f"[LDAP://{gpo_dn};1]"}]
    gpos = [{"id": gpo_dn, "distinguished_name": gpo_dn, "entity_type": "GPO"}]
    edges = _parse_gpo_links_from_containers(containers, gpos)
    assert edges == []


def test_parse_gpo_links_marks_enforced_links():
    gpo_dn = "CN={BBBBBBBB},CN=Policies,CN=System,DC=corp,DC=local"
    # link_opts & 0x02 == 2 → enforced
    containers = [{"DistinguishedName": "OU=Test,DC=corp,DC=local", "gPLink": f"[LDAP://{gpo_dn};2]"}]
    gpos = [{"id": gpo_dn, "distinguished_name": gpo_dn, "entity_type": "GPO"}]
    edges = _parse_gpo_links_from_containers(containers, gpos)
    assert len(edges) == 1
    assert edges[0]["attributes"]["enforced"] is True
    assert edges[0]["risk_weight"] == 0.6


def test_parse_delegation_edges_unconstrained():
    data = json.dumps([{
        "SamAccountName": "WS01$",
        "objectSid": "S-1-5-21-1-1001",
        "TrustedForDelegation": True,
        "msDS-AllowedToDelegateTo": None,
        "msDS-AllowedToActOnBehalfOfOtherIdentity": None,
    }])
    edges = _parse_delegation_edges(data, domain="corp.local")
    assert len(edges) == 1
    e = edges[0]
    assert e["edge_type"] == "ALLOWED_TO_DELEGATE"
    assert e["source_id"] == "S-1-5-21-1-1001"
    assert e["target_id"] == "domain:corp.local"
    assert e["attributes"]["delegation_type"] == "unconstrained"
    assert e["risk_weight"] == 0.9


def test_parse_delegation_edges_constrained_multiple_spns():
    data = json.dumps([{
        "SamAccountName": "svc_web",
        "objectSid": "S-1-5-21-1-1100",
        "TrustedForDelegation": False,
        "msDS-AllowedToDelegateTo": ["cifs/sql.corp.local", "host/sql.corp.local"],
        "msDS-AllowedToActOnBehalfOfOtherIdentity": None,
    }])
    edges = _parse_delegation_edges(data, domain="corp.local")
    assert len(edges) == 2
    assert all(e["edge_type"] == "ALLOWED_TO_DELEGATE" for e in edges)
    assert all(e["attributes"]["delegation_type"] == "constrained" for e in edges)
    assert edges[0]["target_id"] == "cifs/sql.corp.local"
    assert edges[0]["risk_weight"] == 0.7


def test_parse_delegation_edges_rbcd_emits_allowed_to_act():
    data = json.dumps([{
        "SamAccountName": "DB01$",
        "objectSid": "S-1-5-21-1-1200",
        "DistinguishedName": "CN=DB01,OU=Servers,DC=corp,DC=local",
        "TrustedForDelegation": False,
        "msDS-AllowedToDelegateTo": None,
        "msDS-AllowedToActOnBehalfOfOtherIdentity": "01 00 ...",
    }])
    edges = _parse_delegation_edges(data, domain="corp.local")
    assert len(edges) == 1
    e = edges[0]
    assert e["edge_type"] == "ALLOWED_TO_ACT"
    assert e["target_id"] == "S-1-5-21-1-1200"
    assert e["attributes"]["delegation_type"] == "rbcd"
    assert e["risk_weight"] == 0.8


def test_parse_shadow_credential_edges():
    data = json.dumps([{
        "SamAccountName": "alice",
        "objectSid": "S-1-5-21-1-1005",
        "DistinguishedName": "CN=alice,DC=corp,DC=local",
        "msDS-KeyCredentialLink": ["<key blob 1>", "<key blob 2>"],
    }])
    edges = _parse_shadow_credential_edges(data)
    assert len(edges) == 1
    e = edges[0]
    assert e["edge_type"] == "ADD_KEY_CREDENTIAL_LINK"
    assert e["target_id"] == "S-1-5-21-1-1005"
    assert e["attributes"]["key_count"] == 2
    assert e["risk_weight"] == 0.95


def test_parse_delegation_edges_empty_returns_no_edges():
    assert _parse_delegation_edges("", domain="corp.local") == []


def test_parse_cert_templates_ps_esc1_detection():
    """msPKI-Certificate-Name-Flag & 1 = ENROLLEE_SUPPLIES_SUBJECT."""
    data = json.dumps([{
        "cn": "VulnTemplate",
        "displayName": "Vulnerable User Template",
        "DistinguishedName": "CN=VulnTemplate,CN=Certificate Templates,DC=corp,DC=local",
        "msPKI-Certificate-Name-Flag": 1,
        "msPKI-Enrollment-Flag": 0,
        "msPKI-RA-Signature": 0,
        "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
        "msPKI-Certificate-Application-Policy": None,
    }])
    templates = _parse_cert_templates_ps(data)
    assert len(templates) == 1
    t = templates[0]
    assert t["name"] == "VulnTemplate"
    assert t["enrollee_supplies_subject"] is True
    assert t["requires_manager_approval"] is False
    assert t["authorized_signatures_required"] == 0
    assert t["esc1_vulnerable"] is True
    assert t["esc2_vulnerable"] is False


def test_parse_cert_templates_ps_esc2_detection():
    """Any-purpose EKU (2.5.29.37.0) with no manager approval → ESC2."""
    data = json.dumps([{
        "cn": "AnyPurpose",
        "displayName": "Any Purpose",
        "DistinguishedName": "CN=AnyPurpose,CN=Certificate Templates,DC=corp,DC=local",
        "msPKI-Certificate-Name-Flag": 0,
        "msPKI-Enrollment-Flag": 0,
        "msPKI-RA-Signature": 0,
        "pKIExtendedKeyUsage": ["2.5.29.37.0"],
        "msPKI-Certificate-Application-Policy": None,
    }])
    templates = _parse_cert_templates_ps(data)
    assert templates[0]["esc2_vulnerable"] is True
    assert templates[0]["esc1_vulnerable"] is False


def test_parse_cert_templates_ps_esc3_detection():
    """Certificate Request Agent EKU → ESC3."""
    data = json.dumps([{
        "cn": "ReqAgent",
        "displayName": "Request Agent",
        "DistinguishedName": "CN=ReqAgent,CN=Certificate Templates,DC=corp,DC=local",
        "msPKI-Certificate-Name-Flag": 0,
        "msPKI-Enrollment-Flag": 0,
        "msPKI-RA-Signature": 0,
        "pKIExtendedKeyUsage": ["1.3.6.1.4.1.311.20.2.1"],
        "msPKI-Certificate-Application-Policy": None,
    }])
    templates = _parse_cert_templates_ps(data)
    assert templates[0]["esc3_vulnerable"] is True


def test_parse_cas_ps_produces_ca_entities():
    data = json.dumps([{
        "cn": "CORP-CA",
        "name": "CORP-CA",
        "DistinguishedName": "CN=CORP-CA,CN=Enrollment Services,DC=corp,DC=local",
        "dNSHostName": "ca01.corp.local",
        "certificateTemplates": ["User", "Computer", "VulnTemplate"],
    }])
    entities = _parse_cas_ps(data, domain="corp.local")
    assert len(entities) == 1
    ca = entities[0]
    assert ca["entity_type"] == "CA"
    assert ca["is_crown_jewel"] is True
    assert ca["tier"] == 0
    assert ca["attributes"]["dns_hostname"] == "ca01.corp.local"


def test_build_domain_entity_from_json():
    data = json.dumps({
        "DNSRoot": "corp.local",
        "DistinguishedName": "DC=corp,DC=local",
        "DomainSID": {"Value": "S-1-5-21-111-222-333"},
        "DomainMode": 7,
    })
    entity = _build_domain_entity(data, domain="corp.local")
    assert entity is not None
    assert entity["entity_type"] == "DOMAIN"
    assert entity["id"] == "S-1-5-21-111-222-333"
    assert entity["object_sid"] == "S-1-5-21-111-222-333"
    assert entity["is_crown_jewel"] is True
    assert entity["tier"] == 0


def test_build_domain_entity_returns_none_on_empty():
    assert _build_domain_entity("", domain="corp.local") is None


def test_enrich_domain_info_adds_krbtgt_age():
    krbtgt_data = json.dumps([{
        "SamAccountName": "krbtgt",
        "PasswordLastSet": "01/01/2020 00:00:00",
    }])
    domain_info: dict = {"domain": "corp.local"}
    _enrich_domain_info(domain_info, krbtgt_output=krbtgt_data)
    assert "krbtgt_password_age_days" in domain_info
    assert domain_info["krbtgt_password_age_days"] > 0


def test_enrich_domain_info_adds_maq():
    domain_data = json.dumps({
        "ms-DS-MachineAccountQuota": 10,
        "DomainMode": 7,
    })
    domain_info: dict = {}
    _enrich_domain_info(domain_info, domain_output=domain_data)
    assert domain_info.get("machine_account_quota") == 10
    assert domain_info.get("functional_level") == 7


def test_build_rule_data_produces_group_entities_and_member_of_edges():
    group_json = json.dumps([{
        "SamAccountName": "Domain Admins",
        "objectSid": {"Value": "S-1-5-21-1-512"},
        "DistinguishedName": "CN=Domain Admins,CN=Users,DC=corp,DC=local",
        "Name": "Domain Admins",
        "adminCount": 1,
        "member": ["CN=alice,DC=corp,DC=local"],
    }])
    module_data = {
        "enum": {"commands": [
            {"id": "get-adgroup-all", "output": group_json, "error": None, "duration_ms": 10},
        ]},
    }
    rd = build_rule_data_from_collector(module_data)
    group_entities = [e for e in rd["entities"] if e["entity_type"] == "GROUP"]
    member_edges   = [e for e in rd["edges"]    if e["edge_type"]  == "MEMBER_OF"]
    assert len(group_entities) >= 1
    assert any(g["sam_account_name"] == "Domain Admins" for g in group_entities)
    assert len(member_edges) >= 1


def test_build_rule_data_produces_ou_entities():
    ou_json = json.dumps([{
        "DistinguishedName": "OU=Workstations,DC=corp,DC=local",
        "Name": "Workstations",
        "gPLink": None,
        "gPOptions": 0,
    }])
    module_data = {
        "enum": {"commands": [
            {"id": "get-adou-all", "output": ou_json, "error": None, "duration_ms": 5},
        ]},
    }
    rd = build_rule_data_from_collector(module_data)
    ou_entities = [e for e in rd["entities"] if e["entity_type"] == "OU"]
    assert any(e["id"] == "OU=Workstations,DC=corp,DC=local" for e in ou_entities)


def test_build_rule_data_produces_delegation_edges():
    deleg_json = json.dumps([{
        "SamAccountName": "WS01$",
        "objectSid": "S-1-5-21-1-1001",
        "TrustedForDelegation": True,
        "msDS-AllowedToDelegateTo": None,
        "msDS-AllowedToActOnBehalfOfOtherIdentity": None,
    }])
    module_data = {
        "kerberos": {"commands": [
            {"id": "get-delegation-unconstrained", "output": deleg_json, "error": None, "duration_ms": 5},
        ]},
    }
    rd = build_rule_data_from_collector(module_data)
    deleg_edges = [e for e in rd["edges"] if e["edge_type"] == "ALLOWED_TO_DELEGATE"]
    assert len(deleg_edges) >= 1


def test_build_rule_data_produces_cert_templates():
    tmpl_json = json.dumps([{
        "cn": "VulnTemplate",
        "displayName": "Vulnerable",
        "DistinguishedName": "CN=VulnTemplate,DC=corp,DC=local",
        "msPKI-Certificate-Name-Flag": 1,
        "msPKI-Enrollment-Flag": 0,
        "msPKI-RA-Signature": 0,
        "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
        "msPKI-Certificate-Application-Policy": None,
    }])
    module_data = {
        "adcs": {"commands": [
            {"id": "get-cert-templates", "output": tmpl_json, "error": None, "duration_ms": 10},
        ]},
    }
    rd = build_rule_data_from_collector(module_data)
    assert any(t.get("esc1_vulnerable") for t in rd["cert_templates"])
