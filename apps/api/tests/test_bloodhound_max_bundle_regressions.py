from __future__ import annotations

from adbygod_api.core.parsers.bloodhound import BloodHoundParser
from adbygod_api.core.analyzers.rule_engine import RuleEngine


def _find_rule_ids(result: dict) -> set[str]:
    findings = RuleEngine().evaluate_all({
        "entities": result.get("entities", []),
        "edges": result.get("edges", []),
        "cert_templates": result.get("cert_templates", []),
        "domain_info": result.get("metadata", {}).get("domain_info", {}),
        "password_policy": result.get("metadata", {}).get("password_policy", {}),
        "trusts": result.get("metadata", {}).get("trusts", []),
        "network_config": result.get("metadata", {}).get("network_config", {}),
    })
    return {finding.rule_id for finding in findings}


def test_bloodhound_admin_password_age_and_stale_admin_rules_align() -> None:
    parser = BloodHoundParser()
    parser._parse_users([{
        "ObjectIdentifier": "S-1-5-21-1-2-3-500",
        "Properties": {
            "name": "LEGACYADMIN@LAB.LOCAL",
            "samaccountname": "legacyadmin",
            "enabled": True,
            "admincount": True,
            "passwordneverexpires": True,
            "lastlogon": 132537600000000000,
        },
    }])
    result = parser._build_result()
    ids = _find_rule_ids(result)
    assert "USR-002" in ids
    assert "USR-003" in ids


def test_asrep_roastable_spn_users_remain_detectable_after_service_account_classification() -> None:
    parser = BloodHoundParser()
    parser._parse_users([{
        "ObjectIdentifier": "S-1-5-21-1-2-3-1100",
        "Properties": {
            "name": "svc_asrep@lab.local",
            "samaccountname": "svc_asrep",
            "enabled": True,
            "dontreqpreauth": True,
            "hasspn": True,
            "serviceprincipalnames": ["MSSQLSvc/sql01.lab.local:1433"],
        },
    }])
    result = parser._build_result()
    service = next(entity for entity in result["entities"] if entity.get("sam_account_name") == "svc_asrep")
    assert service["entity_type"] == "SERVICE_ACCOUNT"
    assert "KRB-001" in _find_rule_ids(result)


def test_bloodhound_missing_laps_and_maq_telemetry_do_not_fabricate_findings() -> None:
    parser = BloodHoundParser()
    parser._parse_domains([{
        "ObjectIdentifier": "DOMAIN-SID",
        "Properties": {"name": "LAB.LOCAL", "functionallevel": 7},
    }])
    parser._parse_computers([{
        "ObjectIdentifier": "COMPUTER-01",
        "Properties": {"name": "WS01@LAB.LOCAL", "enabled": True, "isdc": False},
    } for _ in range(6)])
    result = parser._build_result()
    ids = _find_rule_ids(result)
    assert "MAQ-001" not in ids
    assert "LAPS-001" not in ids
    assert "LAPS-002" not in ids


def test_bloodhound_trust_direction_and_sid_filtering_use_explicit_telemetry() -> None:
    parser = BloodHoundParser()
    parser._parse_domains([{
        "ObjectIdentifier": "DOMAIN-SID",
        "Properties": {"name": "LAB.LOCAL", "functionallevel": 7},
        "Trusts": [
            {
                "TargetDomainName": "UNKNOWN.LOCAL",
                "TrustType": "External",
                "TrustDirection": "Bidirectional",
            },
            {
                "TargetDomainName": "LEGACY.LOCAL",
                "TrustType": "External",
                "TrustDirection": "Bidirectional",
                "SidFilteringEnabled": False,
            },
        ],
    }])
    result = parser._build_result()
    ids = _find_rule_ids(result)
    assert "TRUST-001" in ids
    assert "TRUST-002" in ids
    unknown = next(t for t in result["metadata"]["trusts"] if t["partner"] == "UNKNOWN.LOCAL")
    assert "sid_filtering_enabled" not in unknown


def test_bloodhound_delegation_rbcd_and_sid_history_drive_rules() -> None:
    parser = BloodHoundParser()
    parser._parse_users([{
        "ObjectIdentifier": "USER-DELEGATOR",
        "Properties": {
            "name": "svcweb@lab.local",
            "samaccountname": "svcweb",
            "enabled": True,
            "trustedtoauth": True,
            "sidhistory": ["S-1-5-21-9-9-9-512"],
            "hasspn": True,
            "serviceprincipalnames": ["HTTP/web.lab.local"],
        },
        "AllowedToDelegate": [{"ObjectIdentifier": "COMPUTER-WEB", "ObjectType": "Computer"}],
    }])
    parser._parse_computers([{
        "ObjectIdentifier": "COMPUTER-RBCD",
        "Properties": {"name": "WS02@LAB.LOCAL", "enabled": True, "isdc": False},
        "AllowedToAct": [{"ObjectIdentifier": "USER-DELEGATOR", "ObjectType": "User"}],
    }])
    result = parser._build_result()
    ids = _find_rule_ids(result)
    assert "DEL-002" in ids
    assert "DEL-003" in ids
    assert "TRUST-003" in ids
    user = next(entity for entity in result["entities"] if entity["id"] == "USER-DELEGATOR")
    assert user["entity_type"] == "SERVICE_ACCOUNT"


def test_bloodhound_standard_kcd_requires_targets_and_not_protocol_transition() -> None:
    parser = BloodHoundParser()
    parser._parse_users([
        {
            "ObjectIdentifier": "USER-EMPTY-FLAG",
            "Properties": {
                "name": "empty@lab.local",
                "samaccountname": "empty",
                "enabled": True,
                "trustedtoauth": True,
            },
        },
        {
            "ObjectIdentifier": "USER-KCD",
            "Properties": {"name": "kcd@lab.local", "samaccountname": "kcd", "enabled": True},
            "AllowedToDelegate": [{"ObjectIdentifier": "COMPUTER-SQL", "ObjectType": "Computer"}],
        },
    ])
    result = parser._build_result()
    ids = _find_rule_ids(result)
    assert "DEL-002" not in ids
    assert "DEL-004" in ids


def test_bloodhound_cert_template_enrollment_edges_and_esc_gating() -> None:
    parser = BloodHoundParser()
    parser._parse_groups([{
        "ObjectIdentifier": "GROUP-DOMAIN-USERS",
        "Properties": {"name": "DOMAIN USERS@LAB.LOCAL", "samaccountname": "Domain Users"},
    }])
    parser._parse_cert_templates([
        {
            "ObjectIdentifier": "TPL-ESC1",
            "Properties": {
                "name": "ESC1@LAB.LOCAL",
                "caname": "LAB-CA",
                "ekus": ["1.3.6.1.5.5.7.3.2"],
                "enrolleesuppliessubject": True,
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 0,
                "enrollmentrights": ["LAB\\Domain Users"],
            },
        },
        {
            "ObjectIdentifier": "TPL-RESTRICTED",
            "Properties": {
                "name": "RESTRICTED@LAB.LOCAL",
                "caname": "LAB-CA",
                "ekus": ["1.3.6.1.5.5.7.3.2"],
                "enrolleesuppliessubject": True,
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 0,
                "enrollmentrights": ["LAB\\PKI Enrollment Operators"],
            },
        },
        {
            "ObjectIdentifier": "TPL-UNPUBLISHED",
            "Properties": {
                "name": "UNPUBLISHED@LAB.LOCAL",
                "ekus": ["1.3.6.1.5.5.7.3.2"],
                "enrolleesuppliessubject": True,
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 0,
                "enrollmentrights": ["LAB\\Domain Users"],
            },
        },
    ])
    result = parser._build_result()
    templates = {item["object_sid"]: item for item in result["cert_templates"]}
    assert templates["TPL-ESC1"]["esc1_vulnerable"] is True
    assert templates["TPL-RESTRICTED"]["esc1_vulnerable"] is False
    assert templates["TPL-UNPUBLISHED"]["esc1_vulnerable"] is False
    edges = {(edge["source_id"], edge["target_id"], edge["edge_type"]) for edge in result["edges"]}
    assert ("GROUP-DOMAIN-USERS", "TPL-ESC1", "CAN_ENROLL") in edges
    assert result["metadata"]["domain_info"]["total_edges"] == len(result["edges"])


def test_bloodhound_domain_functional_level_alias_reaches_domain_rule() -> None:
    parser = BloodHoundParser()
    parser._parse_domains([{
        "ObjectIdentifier": "DOMAIN-SID",
        "Properties": {"name": "OLD.LAB", "functionallevel": 5},
    }])
    result = parser._build_result()
    assert "DOM-001" in _find_rule_ids(result)
