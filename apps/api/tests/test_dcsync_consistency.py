from __future__ import annotations

from adbygod_api.core.analyzers.rule_engine import RuleEngine
from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
from adbygod_api.core.parsers.bloodhound import BloodHoundParser


def _entity(
    entity_id: str,
    entity_type: str,
    sam: str,
    *,
    sid: str | None = None,
    admin_count: bool = False,
    crown_jewel: bool = False,
) -> dict:
    sid = sid or entity_id
    return {
        "id": entity_id,
        "entity_type": entity_type,
        "object_sid": sid,
        "sam_account_name": sam,
        "display_name": sam,
        "distinguished_name": "",
        "domain": "lab.local",
        "is_enabled": True,
        "is_admin_count": admin_count,
        "is_sensitive": False,
        "is_protected_user": False,
        "is_crown_jewel": crown_jewel,
        "tier": 0 if crown_jewel else None,
        "attributes": {"object_sid": sid},
        "business_tags": [],
    }


def _dcsync_edge(source_id: str, target_id: str) -> dict:
    return {
        "source_id": source_id,
        "target_id": target_id,
        "edge_type": "DCSYNC",
        "risk_weight": 1.0,
        "provenance": "test",
        "attributes": {"right": "DCSync"},
    }


def test_acl001_suppresses_expected_builtin_dcsync_principals() -> None:
    engine = RuleEngine()
    domain = _entity("domain-root", "DOMAIN", "lab.local", crown_jewel=True)
    builtin_admins = _entity(
        "builtin-admins",
        "UNKNOWN",
        "BUILTIN\\Administrators",
        sid="S-1-5-32-544",
    )
    domain_controllers = _entity(
        "domain-controllers",
        "GROUP",
        "Domain Controllers",
        sid="S-1-5-21-111-222-333-516",
    )

    matches = engine.evaluate_all({
        "entities": [domain, builtin_admins, domain_controllers],
        "edges": [
            _dcsync_edge(builtin_admins["id"], domain["id"]),
            _dcsync_edge(domain_controllers["id"], domain["id"]),
        ],
    })

    assert "ACL-001" not in {match.rule_id for match in matches}


def test_acl001_still_fires_for_unexpected_dcsync_principal() -> None:
    engine = RuleEngine()
    domain = _entity("domain-root", "DOMAIN", "lab.local", crown_jewel=True)
    rogue = _entity("rogue-sync", "GROUP", "ADG0D2-DCSync")

    matches = engine.evaluate_all({
        "entities": [domain, rogue],
        "edges": [_dcsync_edge(rogue["id"], domain["id"])],
    })

    acl001 = next((match for match in matches if match.rule_id == "ACL-001"), None)
    assert acl001 is not None
    assert "ADG0D2-DCSync" in " ".join(str(item) for item in acl001.affected_objects)


def test_graph_dcsync_summary_uses_principal_classification_and_orders_unexpected_first() -> None:
    analyzer = ADGraphAnalyzer()
    domain = _entity("domain-root", "DOMAIN", "lab.local", crown_jewel=True)
    builtin_admins = _entity(
        "builtin-admins",
        "UNKNOWN",
        "BUILTIN\\Administrators",
        sid="S-1-5-32-544",
    )
    rogue = _entity("rogue-user", "USER", "rogue.user")

    analyzer.load_from_dicts(
        [domain, builtin_admins, rogue],
        [
            _dcsync_edge(builtin_admins["id"], domain["id"]),
            _dcsync_edge(rogue["id"], domain["id"]),
        ],
    )

    principals = analyzer.detect_dcsync_principals()
    assert [principal["principal_id"] for principal in principals] == ["rogue-user", "builtin-admins"]
    assert principals[0]["classification"] == "suspicious"
    assert principals[0]["is_expected"] is False
    assert principals[1]["classification"] == "expected"
    assert principals[1]["is_expected"] is True


def test_bloodhound_parser_does_not_treat_pwdneverexpires_as_protected_users() -> None:
    parser = BloodHoundParser()
    parser._parse_users([
        {
            "ObjectIdentifier": "S-1-5-21-111-222-333-1001",
            "Properties": {
                "name": "alice@lab.local",
                "samaccountname": "alice",
                "pwdneverexpires": True,
                "enabled": True,
            },
        }
    ])

    user = parser._entities[0]
    assert user["is_protected_user"] is False
    assert user["attributes"]["protected_users"] is False


def test_bloodhound_parser_marks_direct_protected_users_group_members() -> None:
    parser = BloodHoundParser()
    user_sid = "S-1-5-21-111-222-333-1002"
    parser._parse_users([
        {
            "ObjectIdentifier": user_sid,
            "Properties": {
                "name": "bob@lab.local",
                "samaccountname": "bob",
                "enabled": True,
            },
        }
    ])
    parser._parse_groups([
        {
            "ObjectIdentifier": "S-1-5-21-111-222-333-525",
            "Properties": {
                "name": "PROTECTED USERS@LAB.LOCAL",
                "samaccountname": "Protected Users",
            },
            "Members": [{"ObjectIdentifier": user_sid}],
        }
    ])

    result = parser._build_result()
    bob = next(entity for entity in result["entities"] if entity["id"] == user_sid)
    assert bob["is_protected_user"] is True
    assert bob["attributes"]["protected_users"] is True
    assert bob["attributes"]["protected_users_source"] == "bloodhound/group_membership"
