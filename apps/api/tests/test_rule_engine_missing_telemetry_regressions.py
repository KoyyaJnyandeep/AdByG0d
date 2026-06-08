from __future__ import annotations

from adbygod_api.core.analyzers.rule_engine import RuleEngine


def _rule_ids(data: dict) -> set[str]:
    return {match.rule_id for match in RuleEngine().evaluate_all(data)}


def test_missing_password_and_domain_posture_telemetry_does_not_create_configuration_findings() -> None:
    ids = _rule_ids({
        "entities": [],
        "edges": [],
        "password_policy": {},
        "domain_info": {},
    })

    assert "PWD-001" not in ids
    assert "PWD-002" not in ids
    assert "LAPS-001" not in ids
    assert "MAQ-001" not in ids


def test_explicit_password_policy_telemetry_still_emits_pwd_findings() -> None:
    ids = _rule_ids({
        "entities": [],
        "edges": [],
        "password_policy": {
            "lockout_threshold": 0,
            "min_password_length": 8,
        },
        "domain_info": {},
    })

    assert "PWD-001" in ids
    assert "PWD-002" in ids


def test_explicit_laps_and_maq_telemetry_still_emit_domain_configuration_findings() -> None:
    ids = _rule_ids({
        "entities": [],
        "edges": [],
        "password_policy": {},
        "domain_info": {
            "laps_deployed": False,
            "total_computers": 12,
            "machine_account_quota": 10,
        },
    })

    assert "LAPS-001" in ids
    assert "MAQ-001" in ids


def test_zero_computer_laps_telemetry_is_not_treated_as_confirmed_domain_exposure() -> None:
    ids = _rule_ids({
        "entities": [],
        "edges": [],
        "password_policy": {},
        "domain_info": {
            "laps_deployed": False,
            "total_computers": 0,
        },
    })

    assert "LAPS-001" not in ids
