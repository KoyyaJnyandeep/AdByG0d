"""Unit tests for AclCollector, SysvolScanner, and new ACL rule engine rules."""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING
from unittest.mock import MagicMock


if TYPE_CHECKING:
    from adbygod_api.core.collection.acl_collector import AclCollector


# ── GUID helpers ──────────────────────────────────────────────────────────────

def _make_guid_bytes(guid_str: str) -> bytes:
    """Pack a GUID string into mixed-endian Windows binary form."""
    parts = guid_str.replace("-", "")
    p1 = int(parts[0:8], 16)
    p2 = int(parts[8:12], 16)
    p3 = int(parts[12:16], 16)
    p4 = bytes.fromhex(parts[16:20])
    p5 = bytes.fromhex(parts[20:32])
    return struct.pack("<IHH", p1, p2, p3) + p4 + p5


# ── GUID round-trip ───────────────────────────────────────────────────────────

def test_bytes_to_guid_dcsync_all():
    from adbygod_api.core.collection.acl_collector import _bytes_to_guid, DC_SYNC_GET_CHANGES_ALL

    raw = _make_guid_bytes(DC_SYNC_GET_CHANGES_ALL)
    assert _bytes_to_guid(raw) == DC_SYNC_GET_CHANGES_ALL


def test_bytes_to_guid_member_attr():
    from adbygod_api.core.collection.acl_collector import _bytes_to_guid, MEMBER_ATTR_GUID

    raw = _make_guid_bytes(MEMBER_ATTR_GUID)
    assert _bytes_to_guid(raw) == MEMBER_ATTR_GUID


# ── ACE mock builders ─────────────────────────────────────────────────────────

def _sid_mock(sid_str: str) -> MagicMock:
    sid = MagicMock()
    sid.formatCanonical.return_value = sid_str
    return sid


def _allow_ace(mask: int, sid_str: str, inherited: bool = False) -> MagicMock:
    """Build a mock ALLOW (type 0) ACE."""
    inner = MagicMock()
    inner.__getitem__.side_effect = lambda k: {
        "Mask": MagicMock(**{"__getitem__.return_value": mask}),
        "Sid": _sid_mock(sid_str),
    }[k]

    ace = MagicMock()
    ace.__getitem__.side_effect = lambda k: {
        "AceType": 0,
        "AceFlags": 0x10 if inherited else 0x00,
        "Ace": inner,
    }[k]
    return ace


def _object_ace(mask: int, sid_str: str, object_type_guid: str | None,
                inherited: bool = False) -> MagicMock:
    """Build a mock ALLOW_OBJECT (type 5) ACE."""
    flags = 0x01 if object_type_guid else 0x00
    obj_bytes = _make_guid_bytes(object_type_guid) if object_type_guid else b"\x00" * 16

    inner = MagicMock()
    inner.__getitem__.side_effect = lambda k: {
        "Mask": MagicMock(**{"__getitem__.return_value": mask}),
        "Sid": _sid_mock(sid_str),
        "Flags": flags,
        "ObjectType": obj_bytes,
        "InheritedObjectType": b"\x00" * 16,
    }[k]

    ace = MagicMock()
    ace.__getitem__.side_effect = lambda k: {
        "AceType": 5,
        "AceFlags": 0x10 if inherited else 0x00,
        "Ace": inner,
    }[k]
    return ace


# ── AclCollector factory ──────────────────────────────────────────────────────

def _make_acl(entity_map: dict | None = None) -> "AclCollector":
    from adbygod_api.core.collection.acl_collector import AclCollector

    return AclCollector(
        conn=MagicMock(),
        base_dn="DC=lab,DC=local",
        entity_map=entity_map if entity_map is not None else {"S-1-5-21-1-2-3-500": "user-id-500"},
        include_inherited=True,
        max_objects=100,
    )


# ── _process_ace tests ────────────────────────────────────────────────────────

def test_process_ace_generic_all_emits_edge():
    from adbygod_api.core.collection.acl_collector import MASK_GENERIC_ALL

    acl = _make_acl()
    ace = _allow_ace(MASK_GENERIC_ALL, "S-1-5-21-1-2-3-500")
    acl._process_ace(ace, "group-da-id", "CN=Domain Admins,CN=Users,DC=lab,DC=local", "GROUP", False)

    edges = [e for e in acl._edges if e["edge_type"] == "GENERIC_ALL"]
    assert len(edges) == 1
    assert edges[0]["source_id"] == "user-id-500"


def test_process_ace_write_dacl_emits_edge():
    from adbygod_api.core.collection.acl_collector import MASK_WRITE_DACL

    acl = _make_acl()
    ace = _allow_ace(MASK_WRITE_DACL, "S-1-5-21-1-2-3-500")
    acl._process_ace(ace, "admin-id", "CN=Administrator,CN=Users,DC=lab,DC=local", "USER", False)

    assert any(e["edge_type"] == "WRITE_DACL" for e in acl._edges)


def test_process_ace_write_owner_emits_edge():
    from adbygod_api.core.collection.acl_collector import MASK_WRITE_OWNER

    acl = _make_acl()
    ace = _allow_ace(MASK_WRITE_OWNER, "S-1-5-21-1-2-3-500")
    acl._process_ace(ace, "domain-id", "DC=lab,DC=local", "DOMAIN", False)

    assert any(e["edge_type"] == "WRITE_OWNER" for e in acl._edges)


def test_process_ace_dcsync_get_changes_all_pending():
    from adbygod_api.core.collection.acl_collector import MASK_EXT_RIGHT, DC_SYNC_GET_CHANGES_ALL

    acl = _make_acl()
    ace = _object_ace(MASK_EXT_RIGHT, "S-1-5-21-1-2-3-500", DC_SYNC_GET_CHANGES_ALL)
    acl._process_ace(ace, "domain-id", "DC=lab,DC=local", "DOMAIN", is_domain_root=True)

    assert "S-1-5-21-1-2-3-500" in acl._dcsync
    assert DC_SYNC_GET_CHANGES_ALL in acl._dcsync["S-1-5-21-1-2-3-500"]


def test_process_ace_add_member_emits_edge():
    from adbygod_api.core.collection.acl_collector import MASK_WRITE_PROP, MEMBER_ATTR_GUID

    acl = _make_acl()
    ace = _object_ace(MASK_WRITE_PROP, "S-1-5-21-1-2-3-500", MEMBER_ATTR_GUID)
    acl._process_ace(ace, "group-da-id", "CN=Domain Admins,CN=Users,DC=lab,DC=local", "GROUP", False)

    assert any(e["edge_type"] == "ADD_MEMBER" for e in acl._edges)


def test_search_sd_reads_all_ldap_pages():
    from adbygod_api.core.collection.acl_collector import AclCollector

    class FakeConnection:
        def __init__(self):
            self.calls = 0

        def search(self, **kwargs):
            self.calls += 1
            cookie = b"next" if self.calls == 1 else b""
            dn = f"CN=Group{self.calls},DC=lab,DC=local"
            return (
                True,
                {"controls": {"1.2.840.113556.1.4.319": {"value": {"cookie": cookie}}}},
                [{
                    "type": "searchResEntry",
                    "dn": dn,
                    "attributes": {"objectSid": f"S-1-5-21-{self.calls}"},
                    "raw_attributes": {"nTSecurityDescriptor": [b"sd"]},
                }],
                None,
            )

    acl = AclCollector(
        conn=FakeConnection(),
        base_dn="DC=lab,DC=local",
        entity_map={},
    )

    rows = acl._search_sd("(objectClass=group)")

    assert [row["dn"] for row in rows] == [
        "CN=Group1,DC=lab,DC=local",
        "CN=Group2,DC=lab,DC=local",
    ]


def test_unresolved_sid_creates_placeholder():
    from adbygod_api.core.collection.acl_collector import MASK_GENERIC_ALL

    acl = _make_acl(entity_map={})
    ace = _allow_ace(MASK_GENERIC_ALL, "S-1-5-21-999-999-999-1337")
    acl._process_ace(ace, "domain-id", "DC=lab,DC=local", "DOMAIN", False)

    assert any(
        e.get("object_sid") == "S-1-5-21-999-999-999-1337"
        for e in acl._placeholders
    )


def test_inherited_ace_skipped_when_disabled():
    from adbygod_api.core.collection.acl_collector import MASK_GENERIC_ALL, AclCollector

    acl = AclCollector(
        conn=MagicMock(),
        base_dn="DC=lab,DC=local",
        entity_map={"S-1-5-21-1-2-3-500": "user-id"},
        include_inherited=False,
    )
    ace = _allow_ace(MASK_GENERIC_ALL, "S-1-5-21-1-2-3-500", inherited=True)
    acl._process_ace(ace, "domain-id", "DC=lab,DC=local", "DOMAIN", False)

    assert acl._edges == []


# ── _flush_dcsync ─────────────────────────────────────────────────────────────

def test_flush_dcsync_emits_only_when_both_rights_present():
    from adbygod_api.core.collection.acl_collector import (
        AclCollector, DC_SYNC_GET_CHANGES, DC_SYNC_GET_CHANGES_ALL
    )

    acl = AclCollector(
        conn=MagicMock(),
        base_dn="DC=lab,DC=local",
        entity_map={
            "S-1-5-21-1-2-3-500": "user-id-500",
            "S-1-5-21-1-2-3-501": "user-id-501",
        },
        include_inherited=True,
    )
    # SID 500: has both Get-Changes + Get-Changes-All → should emit
    acl._dcsync["S-1-5-21-1-2-3-500"] = {DC_SYNC_GET_CHANGES, DC_SYNC_GET_CHANGES_ALL}
    # SID 501: only Get-Changes-All (no Get-Changes) → should NOT emit
    acl._dcsync["S-1-5-21-1-2-3-501"] = {DC_SYNC_GET_CHANGES_ALL}
    # SID 502: only Get-Changes (missing All) → should NOT emit
    acl._dcsync["S-1-5-21-1-2-3-502"] = {DC_SYNC_GET_CHANGES}

    acl._flush_dcsync("domain-id")

    dcsync = [e for e in acl._edges if e["edge_type"] == "DCSYNC"]
    source_ids = {e["source_id"] for e in dcsync}
    assert source_ids == {"user-id-500"}


# ── GPO link regex ────────────────────────────────────────────────────────────

def test_gpo_link_regex_parses_multiple_links():
    import re
    _GPO_LINK_RE = re.compile(r"\[LDAP://([^;]+);(\d+)\]", re.IGNORECASE)

    gp_link = (
        "[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=lab,DC=local;0]"
        "[LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=lab,DC=local;1]"
    )
    matches = list(_GPO_LINK_RE.finditer(gp_link))
    assert len(matches) == 2
    assert int(matches[1].group(2)) & 0x01 == 1  # disabled flag set


# ── SYSVOL cpassword redaction ────────────────────────────────────────────────

def test_sysvol_cpassword_redacted_not_stored():
    from adbygod_api.core.collection.sysvol_scanner import SysvolScanner

    xml_content = b'<User cpassword="VpH5KqHbgaF1rJYxPz2Q==" newName="" fullName=""/>'
    scanner = SysvolScanner(dc_ip="192.168.56.10", domain="lab.local",
                            username="scanner", password="secret")
    findings: list = []
    scanner._check_cpassword(
        xml_content,
        "\\lab.local\\Policies\\{GUID}\\Machine\\Groups.xml",
        "Groups.xml",
        findings,
    )

    assert len(findings) == 1
    assert "VpH5KqHbgaF1rJYxPz2Q==" not in findings[0]["redacted_content_preview"]
    assert "***REDACTED***" in findings[0]["redacted_content_preview"]
    assert findings[0]["cpassword_count"] == 1


def test_sysvol_no_cpassword_no_finding():
    from adbygod_api.core.collection.sysvol_scanner import SysvolScanner

    xml_content = b'<User name="LocalAdmin" newName="" fullName=""/>'
    scanner = SysvolScanner(dc_ip="192.168.56.10", domain="lab.local",
                            username="scanner", password="secret")
    findings: list = []
    scanner._check_cpassword(xml_content, "path", "Groups.xml", findings)
    assert findings == []


def test_sysvol_gpo_guid_extraction():
    from adbygod_api.core.collection.sysvol_scanner import SysvolScanner

    scanner = SysvolScanner(dc_ip="192.168.56.10", domain="lab.local",
                            username="scanner", password="secret")
    findings: list = []
    scanner._check_cpassword(
        b'<User cpassword="abc123"/>',
        "\\lab.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Groups.xml",
        "Groups.xml",
        findings,
    )
    assert findings[0]["gpo_guid"] == "{31B2F340-016D-11D2-945F-00C04FB984F9}"


# ── Rule engine: new ACL rules ────────────────────────────────────────────────

def _base_data(**kwargs) -> dict:
    return {
        "entities": [],
        "edges": [],
        "evidence": [],
        "cert_templates": [],
        "domain_info": {},
        "password_policy": {},
        "trusts": [],
        **kwargs,
    }


def test_rule_acl001_dcsync_fires():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    engine = RuleEngine()
    data = _base_data(
        entities=[{"id": "user-low", "entity_type": "USER", "is_admin_count": False,
                   "attributes": {"uac_is_dc": False}}],
        edges=[{"source_id": "user-low", "target_id": "domain-root", "edge_type": "DCSYNC"}],
    )
    rule_ids = {m.rule_id for m in engine.evaluate_all(data)}
    assert "ACL-001" in rule_ids


def test_rule_acl005_write_owner_tier0():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    engine = RuleEngine()
    data = _base_data(
        entities=[
            {"id": "da-group", "entity_type": "GROUP", "tier": 0, "is_crown_jewel": True, "is_admin_count": True},
            {"id": "user-low", "entity_type": "USER", "is_admin_count": False},
        ],
        edges=[{"source_id": "user-low", "target_id": "da-group", "edge_type": "WRITE_OWNER"}],
    )
    rule_ids = {m.rule_id for m in engine.evaluate_all(data)}
    assert "ACL-005" in rule_ids


def test_rule_acl006_add_member_priv_group():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    engine = RuleEngine()
    data = _base_data(
        entities=[
            {"id": "da-group", "entity_type": "GROUP", "is_admin_count": True,
             "sam_account_name": "Domain Admins", "display_name": "Domain Admins"},
            {"id": "user-low", "entity_type": "USER", "is_admin_count": False, "sam_account_name": "lowpriv"},
        ],
        edges=[{"source_id": "user-low", "target_id": "da-group", "edge_type": "ADD_MEMBER"}],
    )
    matches = engine.evaluate_all(data)
    rule_ids = {m.rule_id for m in matches}
    assert "ACL-006" in rule_ids
    match = next(m for m in matches if m.rule_id == "ACL-006")
    assert "Non-admin principal can modify group membership" in match.title
    assert "lowpriv -> Domain Admins" in match.title
    assert "group takeover" in match.description


def test_rule_acl006_add_member_non_priv_group_takeover():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    engine = RuleEngine()
    data = _base_data(
        entities=[
            {"id": "testers", "entity_type": "GROUP", "is_admin_count": False,
             "sam_account_name": "ADG0D-AddMember-Testers", "display_name": "ADG0D-AddMember-Testers"},
            {"id": "target", "entity_type": "GROUP", "is_admin_count": False,
             "sam_account_name": "ADG0D-Takeover-TargetGroup", "display_name": "ADG0D-Takeover-TargetGroup"},
        ],
        edges=[{"source_id": "testers", "target_id": "target", "edge_type": "ADD_MEMBER"}],
    )

    matches = engine.evaluate_all(data)
    match = next(m for m in matches if m.rule_id == "ACL-006")

    assert match.severity == "HIGH"
    assert "ADG0D-AddMember-Testers -> ADG0D-Takeover-TargetGroup" in match.title
    assert match.is_tier0_direct is False


def test_rule_acl007_gpo_delegation():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    engine = RuleEngine()
    data = _base_data(
        entities=[
            {"id": "gpo-1", "entity_type": "GPO", "is_admin_count": False},
            {"id": "user-low", "entity_type": "USER", "is_admin_count": False},
        ],
        edges=[{"source_id": "user-low", "target_id": "gpo-1", "edge_type": "GENERIC_ALL"}],
    )
    rule_ids = {m.rule_id for m in engine.evaluate_all(data)}
    assert "ACL-007" in rule_ids


def test_rule_acl008_sysvol_gpp():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    engine = RuleEngine()
    data = _base_data(
        evidence=[{
            "collection_method": "sysvol/gpp",
            "raw_data": {"cpassword_files": 2, "findings": []},
        }],
    )
    rule_ids = {m.rule_id for m in engine.evaluate_all(data)}
    assert "ACL-008" in rule_ids


def test_rule_acl009_adminsdholder_drift():
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    engine = RuleEngine()
    data = _base_data(
        entities=[
            {"id": "admin-user", "entity_type": "USER", "is_admin_count": True, "is_enabled": True},
            {"id": "user-low", "entity_type": "USER", "is_admin_count": False},
        ],
        edges=[{
            "source_id": "user-low",
            "target_id": "admin-user",
            "edge_type": "GENERIC_ALL",
            "attributes": {"inherited": False},
        }],
    )
    rule_ids = {m.rule_id for m in engine.evaluate_all(data)}
    assert "ACL-009" in rule_ids


def test_acl005_not_fires_for_admin_source():
    """Admin accounts should not trigger ACL-005 (they're supposed to own Tier-0)."""
    from adbygod_api.core.analyzers.rule_engine import RuleEngine

    engine = RuleEngine()
    data = _base_data(
        entities=[
            {"id": "da-group", "entity_type": "GROUP", "tier": 0, "is_crown_jewel": True, "is_admin_count": True},
            {"id": "admin-user", "entity_type": "USER", "is_admin_count": True},
        ],
        edges=[{"source_id": "admin-user", "target_id": "da-group", "edge_type": "WRITE_OWNER"}],
    )
    rule_ids = {m.rule_id for m in engine.evaluate_all(data)}
    assert "ACL-005" not in rule_ids


def test_sysvol_raw_dicts_not_in_collector_findings(monkeypatch):
    """Collector findings list must not contain raw sysvol file-path dicts (no finding_type)."""
    from adbygod_api.core.collection.ldap_collector import LDAPCollector

    raw_file_findings = [
        {"file_path": "\\\\lab.local\\Policies\\{A}\\Groups.xml", "filename": "Groups.xml",
         "gpo_guid": "{A}", "cpassword_count": 1, "redacted_content_preview": "..."},
    ]
    raw_evidence = [{"id": "sysvol-scan", "source_type": "smb",
                     "collection_method": "sysvol/gpp", "origin": "COLLECTED",
                     "raw_data": {"files_read": 1, "cpassword_files": 1,
                                  "policies_path": "\\\\lab.local\\Policies",
                                  "findings": [{"file_path": "test", "filename": "Groups.xml",
                                                "gpo_guid": "{A}", "cpassword_count": 1}]},
                     "confidence": 1.0}]

    monkeypatch.setattr(LDAPCollector, "_connect", lambda self: None)
    monkeypatch.setattr(LDAPCollector, "_disconnect", lambda self: None)
    monkeypatch.setattr(LDAPCollector, "_enum_domain_entity", lambda self: None)
    monkeypatch.setattr(LDAPCollector, "_enum_users", lambda self: [])
    monkeypatch.setattr(LDAPCollector, "_enum_computers", lambda self: [])
    monkeypatch.setattr(LDAPCollector, "_enum_groups", lambda self: ([], []))
    monkeypatch.setattr(LDAPCollector, "_enum_ous", lambda self: [])
    monkeypatch.setattr(LDAPCollector, "_enum_domain_policy", lambda self: {})
    monkeypatch.setattr(LDAPCollector, "_get_krbtgt_password_age", lambda self: 0)
    monkeypatch.setattr(LDAPCollector, "_run_sysvol_scan",
                        lambda self: (raw_file_findings, raw_evidence))

    col = LDAPCollector("1.2.3.4", "lab.local", scan_sysvol=True,
                        enum_adcs=False, enum_trusts=False, enum_gpos=False, enum_acls=False)
    col._base_dn = "DC=lab,DC=local"
    result = col._run_collection()

    # None of the findings should be raw file dicts (missing finding_type or type)
    for f in result["findings"]:
        assert "finding_type" in f or "type" in f, (
            f"Raw file dict leaked into findings: {f}")
    # Evidence must still contain the sysvol scan record
    ev_methods = [e.get("collection_method") for e in result["evidence"]]
    assert "sysvol/gpp" in ev_methods


def test_process_ace_broad_principals_are_not_globally_suppressed():
    from adbygod_api.core.collection.acl_collector import MASK_GENERIC_ALL

    acl = _make_acl(entity_map={})
    principals = [
        ("S-1-1-0", "Everyone"),
        ("S-1-5-11", "Authenticated Users"),
    ]

    for sid, _name in principals:
        ace = _allow_ace(MASK_GENERIC_ALL, sid)
        acl._process_ace(
            ace,
            "domain-id",
            "DC=lab,DC=local",
            "DOMAIN",
            False,
        )

    source_ids = {
        edge["source_id"]
        for edge in acl._edges
        if edge["edge_type"] == "GENERIC_ALL"
    }
    assert source_ids == {"S-1-1-0", "S-1-5-11"}

    placeholders = {
        entity["object_sid"]: entity["display_name"]
        for entity in acl._placeholders
    }
    assert placeholders["S-1-1-0"] == "Everyone"
    assert placeholders["S-1-5-11"] == "Authenticated Users"
