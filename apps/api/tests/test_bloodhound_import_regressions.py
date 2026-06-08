from __future__ import annotations

from adbygod_api.core.collection.adcs import evaluate_template
from adbygod_api.core.parsers.bloodhound import BloodHoundParser


def _edge_index(result: dict) -> dict[tuple[str, str, str], dict]:
    return {
        (edge["source_id"], edge["target_id"], edge["edge_type"]): edge
        for edge in result["edges"]
    }


def test_bloodhound_domain_and_ou_import_scope_edges() -> None:
    parser = BloodHoundParser()
    parser._parse_domains([
        {
            "ObjectIdentifier": "DOMAIN-SID",
            "Properties": {"name": "LAB.LOCAL"},
            "Links": [{"GUID": "GPO-DOMAIN", "IsEnforced": True}],
            "ChildObjects": [{"ObjectIdentifier": "OU-ROOT", "ObjectType": "OU"}],
        }
    ])
    parser._parse_ous([
        {
            "ObjectIdentifier": "OU-ROOT",
            "Properties": {"name": "WORKSTATIONS@LAB.LOCAL"},
            "Links": [{"GUID": "GPO-OU", "IsEnforced": False}],
            "ChildObjects": [{"ObjectIdentifier": "COMPUTER-01", "ObjectType": "Computer"}],
        }
    ])

    result = parser._build_result()
    edges = _edge_index(result)

    domain_link = edges[("GPO-DOMAIN", "DOMAIN-SID", "APPLIES_GPO")]
    assert domain_link["attributes"]["enforced"] is True
    assert domain_link["attributes"]["scope_type"] == "DOMAIN"

    ou_link = edges[("GPO-OU", "OU-ROOT", "APPLIES_GPO")]
    assert ou_link["attributes"]["enforced"] is False
    assert ou_link["attributes"]["scope_type"] == "OU"

    assert ("DOMAIN-SID", "OU-ROOT", "CONTAINS") in edges
    assert ("OU-ROOT", "COMPUTER-01", "CONTAINS") in edges


def test_bloodhound_gpo_enforcement_does_not_disable_the_gpo_entity() -> None:
    parser = BloodHoundParser()
    parser._parse_gpos([
        {
            "ObjectIdentifier": "GPO-01",
            "Properties": {"name": "ENFORCED POLICY", "isenforced": True},
        }
    ])

    assert parser._entities[0]["is_enabled"] is True


def test_bloodhound_template_esc2_and_esc3_require_unrestricted_issuance() -> None:
    parser = BloodHoundParser()
    parser._parse_cert_templates([
        {
            "ObjectIdentifier": "TPL-NO-EKU",
            "Properties": {
                "name": "No EKU Template",
                "ekus": [],
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 0,
            },
        },
        {
            "ObjectIdentifier": "TPL-ESC2-SIGS",
            "Properties": {
                "name": "Any Purpose But Signatures Required",
                "ekus": ["2.5.29.37.0"],
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 1,
            },
        },
        {
            "ObjectIdentifier": "TPL-ESC3-SIGS",
            "Properties": {
                "name": "Enrollment Agent But Signatures Required",
                "ekus": ["1.3.6.1.4.1.311.20.2.1"],
                "requiresmanagerapproval": False,
                "authorizedsignaturesrequired": 1,
            },
        },
    ])

    templates = {template["name"]: template for template in parser._build_result()["cert_templates"]}
    assert templates["No EKU Template"]["esc2_vulnerable"] is True
    assert templates["Any Purpose But Signatures Required"]["esc2_vulnerable"] is False
    assert templates["Enrollment Agent But Signatures Required"]["esc3_vulnerable"] is False


def test_bloodhound_template_esc4_uses_low_privileged_control_aces() -> None:
    parser = BloodHoundParser()
    parser._parse_cert_templates([
        {
            "ObjectIdentifier": "TPL-LOW-PRIV",
            "Properties": {"name": "Weak Template ACL"},
            "Aces": [
                {
                    "PrincipalSID": "S-1-5-21-111-222-333-513",
                    "PrincipalType": "Group",
                    "RightName": "WriteDacl",
                    "IsInherited": False,
                }
            ],
        },
        {
            "ObjectIdentifier": "TPL-PRIV",
            "Properties": {"name": "Admin-Owned Template"},
            "Aces": [
                {
                    "PrincipalSID": "S-1-5-21-111-222-333-512",
                    "PrincipalType": "Group",
                    "RightName": "WriteDacl",
                    "IsInherited": False,
                }
            ],
        },
    ])

    templates = {template["name"]: template for template in parser._build_result()["cert_templates"]}
    weak = templates["Weak Template ACL"]
    admin_owned = templates["Admin-Owned Template"]

    assert weak["esc4_vulnerable"] is True
    assert weak["write_rights"][0]["is_low_privileged"] is True
    assert admin_owned["esc4_vulnerable"] is False
    assert admin_owned["write_rights"][0]["is_low_privileged"] is False


def test_live_adcs_esc2_flags_no_eku_templates() -> None:
    result = evaluate_template(
        {
            "ekus": [],
            "enrollment_rights": [{"is_low_privileged": True}],
            "requires_manager_approval": False,
            "authorized_signatures_required": 0,
            "msPKI-Certificate-Name-Flag": 0,
        },
        ["LAB-DC01-CA"],
    )

    assert result["esc2_vulnerable"] is True



def test_bloodhound_single_replication_right_does_not_emit_dcsync() -> None:
    parser = BloodHoundParser()
    parser._parse_domains([
        {
            "ObjectIdentifier": "DOMAIN-SID",
            "Properties": {"name": "LAB.LOCAL"},
            "Aces": [
                {
                    "PrincipalSID": "S-1-5-21-111-222-333-1101",
                    "PrincipalType": "User",
                    "RightName": "GetChangesAll",
                    "IsInherited": False,
                }
            ],
        }
    ])

    result = parser._build_result()
    assert not any(edge["edge_type"] == "DCSYNC" for edge in result["edges"])


def test_bloodhound_combined_replication_rights_emit_dcsync() -> None:
    parser = BloodHoundParser()
    principal_sid = "S-1-5-21-111-222-333-1102"
    parser._parse_domains([
        {
            "ObjectIdentifier": "DOMAIN-SID",
            "Properties": {"name": "LAB.LOCAL"},
            "Aces": [
                {
                    "PrincipalSID": principal_sid,
                    "PrincipalType": "User",
                    "RightName": "GetChanges",
                    "IsInherited": False,
                },
                {
                    "PrincipalSID": principal_sid,
                    "PrincipalType": "User",
                    "RightName": "GetChangesAll",
                    "IsInherited": False,
                },
            ],
        }
    ])

    result = parser._build_result()
    dcsync = [edge for edge in result["edges"] if edge["edge_type"] == "DCSYNC"]
    assert len(dcsync) == 1
    assert dcsync[0]["source_id"] == principal_sid
    assert dcsync[0]["target_id"] == "DOMAIN-SID"
    assert dcsync[0]["attributes"]["ace_rights"] == ["GetChanges", "GetChangesAll"]


def test_bloodhound_esc4_templates_are_visible_as_sensitive_entities() -> None:
    parser = BloodHoundParser()
    parser._parse_cert_templates([
        {
            "ObjectIdentifier": "TPL-ESC4-VISIBLE",
            "Properties": {"name": "Low Priv Template Control"},
            "Aces": [
                {
                    "PrincipalSID": "S-1-5-21-111-222-333-513",
                    "PrincipalType": "Group",
                    "RightName": "WriteDacl",
                    "IsInherited": False,
                }
            ],
        }
    ])

    result = parser._build_result()
    template_entity = next(
        entity for entity in result["entities"]
        if entity["id"] == "TPL-ESC4-VISIBLE"
    )
    assert template_entity["is_sensitive"] is True
    assert "ESC4" in template_entity["business_tags"]


def test_bloodhound_structured_delegation_fields_materialize_edges() -> None:
    parser = BloodHoundParser()
    parser._parse_users([
        {
            "ObjectIdentifier": "USER-DELEGATOR",
            "Properties": {"name": "svc_web@lab.local", "samaccountname": "svc_web"},
            "AllowedToDelegate": [{"ObjectIdentifier": "COMPUTER-WEB", "ObjectType": "Computer"}],
        }
    ])
    parser._parse_computers([
        {
            "ObjectIdentifier": "COMPUTER-RBCD-TARGET",
            "Properties": {"name": "APP01.LAB.LOCAL"},
            "AllowedToDelegate": [{"ObjectIdentifier": "COMPUTER-SQL", "ObjectType": "Computer"}],
            "AllowedToAct": [{"ObjectIdentifier": "COMPUTER-ATTACKER", "ObjectType": "Computer"}],
        }
    ])

    edges = _edge_index(parser._build_result())
    assert ("USER-DELEGATOR", "COMPUTER-WEB", "ALLOWED_TO_DELEGATE") in edges
    assert ("COMPUTER-RBCD-TARGET", "COMPUTER-SQL", "ALLOWED_TO_DELEGATE") in edges
    assert ("COMPUTER-ATTACKER", "COMPUTER-RBCD-TARGET", "ALLOWED_TO_ACT") in edges


def test_bloodhound_gpo_changes_materialize_effective_computer_edges() -> None:
    parser = BloodHoundParser()
    parser._parse_domains([
        {
            "ObjectIdentifier": "DOMAIN-SID",
            "Properties": {"name": "LAB.LOCAL"},
            "GPOChanges": {
                "AffectedComputers": [{"ObjectIdentifier": "COMPUTER-01", "ObjectType": "Computer"}],
                "LocalAdmins": [{"ObjectIdentifier": "GROUP-ADMIN", "ObjectType": "Group"}],
                "RemoteDesktopUsers": [{"ObjectIdentifier": "GROUP-RDP", "ObjectType": "Group"}],
                "DcomUsers": [{"ObjectIdentifier": "GROUP-DCOM", "ObjectType": "Group"}],
                "PSRemoteUsers": [{"ObjectIdentifier": "GROUP-PSREMOTE", "ObjectType": "Group"}],
            },
        }
    ])
    parser._parse_ous([
        {
            "ObjectIdentifier": "OU-APPS",
            "Properties": {"name": "APPS@LAB.LOCAL"},
            "GPOChanges": {
                "AffectedComputers": [{"ObjectIdentifier": "COMPUTER-02", "ObjectType": "Computer"}],
                "LocalAdmins": [{"ObjectIdentifier": "GROUP-OU-ADMIN", "ObjectType": "Group"}],
            },
        }
    ])

    edges = _edge_index(parser._build_result())
    assert ("GROUP-ADMIN", "COMPUTER-01", "ADMIN_TO") in edges
    assert ("GROUP-RDP", "COMPUTER-01", "CAN_RDP") in edges
    assert ("GROUP-DCOM", "COMPUTER-01", "HAS_CONTROL") in edges
    assert ("GROUP-PSREMOTE", "COMPUTER-01", "CAN_WINRM") in edges
    assert ("GROUP-OU-ADMIN", "COMPUTER-02", "ADMIN_TO") in edges
    assert edges[("GROUP-ADMIN", "COMPUTER-01", "ADMIN_TO")]["attributes"]["scope_type"] == "DOMAIN"
    assert edges[("GROUP-OU-ADMIN", "COMPUTER-02", "ADMIN_TO")]["attributes"]["scope_type"] == "OU"
