from __future__ import annotations

from adbygod_api.core.analyzers.rule_engine import RuleEngine
from adbygod_api.core.parsers.bloodhound import BloodHoundParser


OLD_ADMIN_LASTLOGON_FILETIME = 133585596000000000  # 2024-04-25 23:00:00 UTC


def _rule_ids(data: dict) -> set[str]:
    return {match.rule_id for match in RuleEngine().evaluate_all(data)}


def test_bloodhound_admin_pwd_never_expires_and_stale_admin_are_rule_visible() -> None:
    parser = BloodHoundParser()
    parser._parse_users([
        {
            "ObjectIdentifier": "S-1-5-21-111-222-333-1101",
            "Properties": {
                "name": "svc_sql@lab.local",
                "samaccountname": "svc_sql",
                "admincount": True,
                "enabled": True,
                "passwordneverexpires": True,
                "lastlogon": OLD_ADMIN_LASTLOGON_FILETIME,
            },
        }
    ])
    result = parser._build_result()
    user = result["entities"][0]

    assert user["attributes"]["pwd_never_expires"] is True
    assert user["attributes"]["days_since_last_logon"] > 90

    ids = _rule_ids({"entities": result["entities"], "edges": result["edges"]})
    assert "USR-002" in ids
    assert "USR-003" in ids


def test_bloodhound_haslaps_maps_to_laps_installed_for_laps_rule() -> None:
    parser = BloodHoundParser()
    parser._parse_computers([
        {
            "ObjectIdentifier": f"S-1-5-21-111-222-333-20{i}",
            "Properties": {
                "name": f"wkst{i}.lab.local",
                "samaccountname": f"WKST{i}$",
                "enabled": True,
                "haslaps": i == 0,
            },
        }
        for i in range(5)
    ])
    result = parser._build_result()
    protected = next(entity for entity in result["entities"] if entity["sam_account_name"] == "WKST0$")

    assert protected["attributes"]["laps_installed"] is True

    ids = _rule_ids({"entities": result["entities"], "edges": result["edges"]})
    assert "LAPS-002" not in ids


def test_rbcd_edge_only_imports_trigger_del003() -> None:
    target = {
        "id": "S-1-5-21-111-222-333-3001",
        "entity_type": "COMPUTER",
        "sam_account_name": "APP01$",
        "dns_hostname": "app01.lab.local",
        "is_enabled": True,
        "attributes": {"uac_is_dc": False},
    }
    edges = [
        {
            "source_id": "S-1-5-21-111-222-333-2101",
            "target_id": target["id"],
            "edge_type": "ALLOWED_TO_ACT",
        }
    ]

    ids = _rule_ids({"entities": [target], "edges": edges})
    assert "DEL-003" in ids
