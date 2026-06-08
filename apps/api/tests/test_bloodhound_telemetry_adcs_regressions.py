from __future__ import annotations

from adbygod_api.core.analyzers.rule_engine import RuleEngine
from adbygod_api.core.parsers.bloodhound import BloodHoundParser


def _rule_data(result: dict) -> dict:
    metadata = result["metadata"]
    return {
        **result,
        "domain_info": metadata.get("domain_info", {}),
        "password_policy": metadata.get("password_policy", {}),
        "trusts": metadata.get("trusts", []),
    }


def _rule_ids(result: dict) -> set[str]:
    return {match.rule_id for match in RuleEngine().evaluate_all(_rule_data(result))}


def test_bloodhound_missing_machine_account_quota_stays_unknown() -> None:
    parser = BloodHoundParser()
    parser._parse_domains([
        {"ObjectIdentifier": "DOM", "Properties": {"name": "LAB.LOCAL"}},
    ])

    result = parser._build_result()
    assert "machine_account_quota" not in result["metadata"]["domain_info"]
    assert "MAQ-001" not in _rule_ids(result)


def test_bloodhound_missing_laps_telemetry_does_not_emit_laps_findings() -> None:
    parser = BloodHoundParser()
    parser._parse_domains([
        {"ObjectIdentifier": "DOM", "Properties": {"name": "LAB.LOCAL"}},
    ])
    parser._parse_computers([
        {"ObjectIdentifier": f"C{i}", "Properties": {"name": f"PC{i}@LAB.LOCAL", "enabled": True}}
        for i in range(5)
    ])

    result = parser._build_result()
    assert "laps_deployed" not in result["metadata"]["domain_info"]
    rule_ids = _rule_ids(result)
    assert "LAPS-001" not in rule_ids
    assert "LAPS-002" not in rule_ids


def test_bloodhound_esc1_requires_low_privileged_enrollment() -> None:
    parser = BloodHoundParser()
    parser._parse_cert_templates([
        {
            "ObjectIdentifier": "TPL-RESTRICTED",
            "Properties": {
                "name": "RESTRICTED@LAB.LOCAL",
                "caname": "LAB-CA01",
                "ekus": ["1.3.6.1.5.5.7.3.2"],
                "enrolleesuppliessubject": True,
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 0,
                "enrollmentrights": ["LAB\\PKI Enrollment Operators"],
            },
        }
    ])

    template = parser._build_result()["cert_templates"][0]
    assert template["esc1_vulnerable"] is False


def test_bloodhound_esc1_requires_published_template_marker() -> None:
    parser = BloodHoundParser()
    parser._parse_cert_templates([
        {
            "ObjectIdentifier": "TPL-UNPUBLISHED",
            "Properties": {
                "name": "UNPUBLISHED@LAB.LOCAL",
                "caname": "",
                "ekus": ["1.3.6.1.5.5.7.3.2"],
                "enrolleesuppliessubject": True,
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 0,
                "enrollmentrights": ["LAB\\Domain Users"],
            },
        }
    ])

    template = parser._build_result()["cert_templates"][0]
    assert template["esc1_vulnerable"] is False


def test_bloodhound_esc1_keeps_valid_low_privileged_published_template() -> None:
    parser = BloodHoundParser()
    parser._parse_cert_templates([
        {
            "ObjectIdentifier": "TPL-PUBLISHED",
            "Properties": {
                "name": "PUBLISHED@LAB.LOCAL",
                "caname": "LAB-CA01",
                "ekus": ["1.3.6.1.5.5.7.3.2"],
                "enrolleesuppliessubject": True,
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 0,
                "enrollmentrights": ["LAB\\Domain Users"],
            },
        }
    ])

    template = parser._build_result()["cert_templates"][0]
    assert template["esc1_vulnerable"] is True
