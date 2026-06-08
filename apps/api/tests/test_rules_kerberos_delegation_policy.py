"""
Unit tests for Kerberos, delegation, and password policy rules.
All tests use in-memory data — no LDAP connection required.
"""
from __future__ import annotations

import pytest
from adbygod_api.core.analyzers.rule_engine import RuleEngine


@pytest.fixture
def engine():
    return RuleEngine()


# ─── Helper builders ────────────────────────────────────────────────────────────

def _user(sam, *, enabled=True, is_admin=False, spn=False, spns=None, rc4_only=False,
          no_preauth=False, constrained_any=False, constrained_targets=None,
          rbcd=False, enc_types=0, sid=None):
    sid = sid or f"S-1-5-21-111-{sam}"
    return {
        "id": sid,
        "entity_type": "SERVICE_ACCOUNT" if spn and is_admin else "USER",
        "object_sid": sid,
        "sam_account_name": sam,
        "display_name": sam,
        "distinguished_name": f"CN={sam},DC=lab,DC=local",
        "domain": "lab.local",
        "is_enabled": enabled,
        "is_admin_count": is_admin,
        "is_sensitive": False,
        "is_protected_user": False,
        "is_crown_jewel": False,
        "tier": 0 if is_admin else None,
        "attributes": {
            "has_spn": bool(spn or spns),
            "spns": spns or (["MSSQLSvc/db.lab.local:1433"] if spn else []),
            "uac_dont_require_preauth": no_preauth,
            "uac_trusted_for_delegation": False,
            "uac_trusted_to_auth_for_delegation": constrained_any,
            "constrained_delegation_any_protocol": constrained_any,
            "allowed_to_delegate_to": constrained_targets or [],
            "rbcd_configured": rbcd,
            "rc4_only": rc4_only,
            "supported_encryption_types": enc_types,
            "shadow_credentials": False,
            "has_sid_history": False,
            "sid_history": [],
            "pwd_never_expires": False,
            "uac_is_dc": False,
        },
    }


def _computer(name, *, is_dc=False, unconstrained=False, constrained_any=False,
              constrained_targets=None, rbcd=False, sid=None):
    sid = sid or f"S-1-5-21-111-comp-{name}"
    return {
        "id": sid,
        "entity_type": "DC" if is_dc else "COMPUTER",
        "object_sid": sid,
        "sam_account_name": f"{name}$",
        "display_name": name,
        "distinguished_name": f"CN={name},DC=lab,DC=local",
        "domain": "lab.local",
        "is_enabled": True,
        "is_admin_count": False,
        "is_sensitive": is_dc,
        "is_protected_user": False,
        "is_crown_jewel": is_dc,
        "tier": 0 if is_dc else None,
        "attributes": {
            "uac_trusted_for_delegation": unconstrained and not is_dc,
            "uac_trusted_to_auth_for_delegation": constrained_any,
            "uac_is_dc": is_dc,
            "constrained_delegation_any_protocol": constrained_any,
            "allowed_to_delegate_to": constrained_targets or [],
            "rbcd_configured": rbcd,
            "has_laps": False,
            "laps_installed": False,
            "has_spn": False,
            "spns": [],
            "rc4_only": False,
            "supported_encryption_types": 0,
        },
    }


def _policy(**kwargs):
    defaults = {
        "min_password_length": 14,
        "lockout_threshold": 5,
        "lockout_duration": "-18000000000",
        "max_pwd_age": "-36288000000000",
        "min_pwd_age": "-864000000000",
        "pwd_history_length": 24,
        "password_history_count": 24,
        "machine_account_quota": 10,
        "functional_level": 7,
        "domain_functional_level": 7,
        "complexity_enabled": True,
        "reversible_encryption_enabled": False,
    }
    defaults.update(kwargs)
    return defaults


def _base_data(entities=None, edges=None, policy=None):
    return {
        "entities": entities or [],
        "edges": edges or [],
        "password_policy": policy or _policy(),
        "cert_templates": [],
        "trusts": [],
        "domain_info": {},
        "evidence": [],
    }


def _dcsync_edge(src_id, target_id="S-1-5-21-111-domain"):
    return {
        "source_id": src_id,
        "target_id": target_id,
        "edge_type": "DCSYNC",
        "risk_weight": 1.0,
        "provenance": "test",
        "attributes": {"right": "DCSync"},
    }


# ─── KRB-001: ASREP Roastable ────────────────────────────────────────────────

def test_krb001_asrep_roastable_fires(engine):
    user = _user("ADG0D_ASREP", no_preauth=True, enabled=True)
    matches = engine.evaluate_all(_base_data(entities=[user]))
    assert "KRB-001" in {m.rule_id for m in matches}


def test_krb001_asrep_not_fires_for_disabled(engine):
    user = _user("ADG0D_ASREP", no_preauth=True, enabled=False)
    matches = engine.evaluate_all(_base_data(entities=[user]))
    assert "KRB-001" not in {m.rule_id for m in matches}


def test_krb001_asrep_affected_objects_contain_name(engine):
    user = _user("ADG0D_ASREP2", no_preauth=True)
    matches = engine.evaluate_all(_base_data(entities=[user]))
    krb001 = next((m for m in matches if m.rule_id == "KRB-001"), None)
    assert krb001 is not None
    all_names = " ".join(str(o) for o in krb001.affected_objects)
    assert "ADG0D_ASREP2" in all_names


def test_krb001_multiple_asrep_accounts(engine):
    users = [_user(f"ASREP_{i}", no_preauth=True) for i in range(3)]
    matches = engine.evaluate_all(_base_data(entities=users))
    krb001 = next((m for m in matches if m.rule_id == "KRB-001"), None)
    assert krb001 is not None
    assert krb001.affected_count == 3


# ─── KRB-002: Kerberoastable Admins ─────────────────────────────────────────

def test_krb002_kerberoastable_admin_fires(engine):
    svc = _user("ADG0D_SVC_SQL", is_admin=True, spn=True)
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "KRB-002" in {m.rule_id for m in matches}


def test_krb002_not_fires_for_non_admin_spn(engine):
    svc = _user("ADG0D_SVC_WEB", is_admin=False, spn=True)
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "KRB-002" not in {m.rule_id for m in matches}


def test_krb002_not_fires_for_admin_without_spn(engine):
    admin = _user("DA_USER", is_admin=True, spn=False)
    matches = engine.evaluate_all(_base_data(entities=[admin]))
    assert "KRB-002" not in {m.rule_id for m in matches}


def test_krb002_disabled_admin_excluded(engine):
    svc = _user("ADG0D_SVC_DISABLED", is_admin=True, spn=True, enabled=False)
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "KRB-002" not in {m.rule_id for m in matches}


# ─── KRB-003: Kerberoastable Service Accounts ────────────────────────────────

def test_krb003_kerberoastable_services_fires_with_3plus(engine):
    svcs = [_user(f"SVC{i}", spn=True, is_admin=False) for i in range(4)]
    matches = engine.evaluate_all(_base_data(entities=svcs))
    assert "KRB-003" in {m.rule_id for m in matches}


def test_krb003_not_fires_with_fewer_than_3(engine):
    svcs = [_user("SVC_ONLY", spn=True, is_admin=False)]
    matches = engine.evaluate_all(_base_data(entities=svcs))
    assert "KRB-003" not in {m.rule_id for m in matches}


def test_krb003_lab_accounts_detected(engine):
    lab_svcs = [
        _user("ADG0D_SVC_SQL", spn=True, is_admin=False),
        _user("ADG0D_SVC_SQL2", spn=True, is_admin=False),
        _user("ADG0D_SVC_WEB2", spn=True, is_admin=False),
        _user("ADG0D_SVC_LEGACY2", spn=True, is_admin=False),
    ]
    matches = engine.evaluate_all(_base_data(entities=lab_svcs))
    krb003 = next((m for m in matches if m.rule_id == "KRB-003"), None)
    assert krb003 is not None
    affected_str = " ".join(str(o) for o in krb003.affected_objects)
    assert "ADG0D_SVC_SQL" in affected_str


# ─── KRB-005: RC4-Only Kerberoastable ────────────────────────────────────────

def test_krb005_rc4only_fires(engine):
    svc = _user("ADG0D_RC4ONLY", spn=True, rc4_only=True, enc_types=4)
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "KRB-005" in {m.rule_id for m in matches}


def test_krb005_not_fires_for_aes_account(engine):
    svc = _user("SVC_AES", spn=True, rc4_only=False, enc_types=0x18)
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "KRB-005" not in {m.rule_id for m in matches}


def test_krb005_not_fires_for_no_enc_type(engine):
    # enc_types=0 means not rc4_only (no type set = default)
    svc = _user("SVC_DEFAULT", spn=True, rc4_only=False, enc_types=0)
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "KRB-005" not in {m.rule_id for m in matches}


def test_krb005_legacy_account_detected(engine):
    legacy = _user("ADG0D_SVC_LEGACY2", spn=True, rc4_only=True, enc_types=0x07)
    matches = engine.evaluate_all(_base_data(entities=[legacy]))
    assert "KRB-005" in {m.rule_id for m in matches}


# ─── DEL-001: Unconstrained Delegation ───────────────────────────────────────

def test_del001_unconstrained_delegation_computer(engine):
    comp = _computer("ADG0D-APP02", unconstrained=True)
    matches = engine.evaluate_all(_base_data(entities=[comp]))
    assert "DEL-001" in {m.rule_id for m in matches}


def test_del001_not_fires_for_user_entity(engine):
    # DEL-001 is scoped to COMPUTER entities only; user accounts are not flagged
    user = _user("UNCONSTRAINED_SVC", spn=True)
    user["attributes"]["uac_trusted_for_delegation"] = True
    matches = engine.evaluate_all(_base_data(entities=[user]))
    assert "DEL-001" not in {m.rule_id for m in matches}


def test_del001_not_fires_for_dc(engine):
    dc = _computer("DC01", is_dc=True)
    # DCs have UAC_SERVER_TRUST, not UAC_TRUSTED_FOR_DELEGATION (excluded by rule)
    matches = engine.evaluate_all(_base_data(entities=[dc]))
    assert "DEL-001" not in {m.rule_id for m in matches}


def test_del001_not_fires_for_normal_computer(engine):
    comp = _computer("WORKSTATION01", unconstrained=False)
    matches = engine.evaluate_all(_base_data(entities=[comp]))
    assert "DEL-001" not in {m.rule_id for m in matches}


# ─── DEL-002: Protocol Transition / S4U ──────────────────────────────────────

def test_del002_protocol_transition_fires(engine):
    svc = _user("ADG0D_SVC_WEB2", constrained_any=True,
                constrained_targets=["cifs/fileserver.lab.local"])
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "DEL-002" in {m.rule_id for m in matches}


def test_del002_not_fires_for_standard_constrained(engine):
    # Standard constrained: has targets but NOT TRUSTED_TO_AUTH_FOR_DELEGATION
    svc = _user("SVC_KCD", constrained_any=False,
                constrained_targets=["cifs/server.lab.local"])
    svc["attributes"]["uac_trusted_to_auth_for_delegation"] = False
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "DEL-002" not in {m.rule_id for m in matches}


# ─── DEL-003: RBCD ────────────────────────────────────────────────────────────

def test_del003_rbcd_fires(engine):
    comp = _computer("ADG0D-FILE02", rbcd=True)
    matches = engine.evaluate_all(_base_data(entities=[comp]))
    assert "DEL-003" in {m.rule_id for m in matches}


def test_del003_not_fires_for_no_rbcd(engine):
    comp = _computer("CLEAN-SERVER", rbcd=False)
    matches = engine.evaluate_all(_base_data(entities=[comp]))
    assert "DEL-003" not in {m.rule_id for m in matches}


def test_del003_not_fires_for_user_entity(engine):
    # DEL-003 is scoped to COMPUTER entities only; user accounts are not flagged
    user = _user("SVC_RBCD", rbcd=True)
    matches = engine.evaluate_all(_base_data(entities=[user]))
    assert "DEL-003" not in {m.rule_id for m in matches}


# ─── DEL-004: Standard Constrained Delegation ────────────────────────────────

def test_del004_standard_constrained_delegation(engine):
    svc = _user("SVC_KCD", constrained_targets=["cifs/server.lab.local"])
    svc["attributes"]["uac_trusted_to_auth_for_delegation"] = False
    svc["attributes"]["constrained_delegation_any_protocol"] = False
    matches = engine.evaluate_all(_base_data(entities=[svc]))
    assert "DEL-004" in {m.rule_id for m in matches}


def test_del004_not_fires_when_no_delegation(engine):
    user = _user("PLAIN_USER")
    matches = engine.evaluate_all(_base_data(entities=[user]))
    assert "DEL-004" not in {m.rule_id for m in matches}


# ─── PWD-001: No Lockout ─────────────────────────────────────────────────────

def test_pwd001_no_lockout_fires(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(lockout_threshold=0)))
    assert "PWD-001" in {m.rule_id for m in matches}


def test_pwd001_not_fires_when_lockout_set(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(lockout_threshold=5)))
    assert "PWD-001" not in {m.rule_id for m in matches}


def test_pwd001_severity_is_critical(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(lockout_threshold=0)))
    pwd001 = next(m for m in matches if m.rule_id == "PWD-001")
    assert pwd001.severity == "CRITICAL"
    assert pwd001.finding_type == "NO_LOCKOUT_POLICY"


# ─── PWD-002: Weak Min Length ────────────────────────────────────────────────

def test_pwd002_min_length_6_fires_critical(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(min_password_length=6)))
    pwd002 = next((m for m in matches if m.rule_id == "PWD-002"), None)
    assert pwd002 is not None
    assert pwd002.severity == "CRITICAL"
    assert "6" in pwd002.title


def test_pwd002_min_length_10_fires_high(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(min_password_length=10)))
    pwd002 = next((m for m in matches if m.rule_id == "PWD-002"), None)
    assert pwd002 is not None
    assert pwd002.severity == "HIGH"


def test_pwd002_not_fires_for_strong_length(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(min_password_length=14)))
    assert "PWD-002" not in {m.rule_id for m in matches}


# ─── PWD-003: No Complexity ─────────────────────────────────────────────────

def test_pwd003_no_complexity_fires(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(complexity_enabled=False)))
    assert "PWD-003" in {m.rule_id for m in matches}


def test_pwd003_not_fires_with_complexity(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(complexity_enabled=True)))
    assert "PWD-003" not in {m.rule_id for m in matches}


# ─── PWD-004: Weak Password History ─────────────────────────────────────────

def test_pwd004_zero_history_fires_high(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(password_history_count=0)))
    pwd004 = next((m for m in matches if m.rule_id == "PWD-004"), None)
    assert pwd004 is not None
    assert pwd004.severity == "HIGH"


def test_pwd004_weak_history_5_fires_medium(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(password_history_count=5)))
    pwd004 = next((m for m in matches if m.rule_id == "PWD-004"), None)
    assert pwd004 is not None
    assert pwd004.severity == "MEDIUM"


def test_pwd004_not_fires_for_good_history(engine):
    matches = engine.evaluate_all(_base_data(policy=_policy(password_history_count=24)))
    assert "PWD-004" not in {m.rule_id for m in matches}


# ─── PWD-005: Large Spray Surface ────────────────────────────────────────────

def test_pwd005_spray_surface_fires_without_lockout(engine):
    users = [_user(f"user{i}", enabled=True) for i in range(100)]
    matches = engine.evaluate_all(_base_data(entities=users,
                                             policy=_policy(lockout_threshold=0)))
    assert "PWD-005" in {m.rule_id for m in matches}


def test_pwd005_not_fires_with_lockout(engine):
    users = [_user(f"user{i}", enabled=True) for i in range(100)]
    matches = engine.evaluate_all(_base_data(entities=users,
                                             policy=_policy(lockout_threshold=5)))
    assert "PWD-005" not in {m.rule_id for m in matches}


# ─── PWD-006: Reversible Encryption ─────────────────────────────────────────

def test_pwd006_reversible_encryption_fires(engine):
    matches = engine.evaluate_all(_base_data(
        policy=_policy(reversible_encryption_enabled=True)))
    assert "PWD-006" in {m.rule_id for m in matches}


def test_pwd006_not_fires_when_disabled(engine):
    matches = engine.evaluate_all(_base_data(
        policy=_policy(reversible_encryption_enabled=False)))
    assert "PWD-006" not in {m.rule_id for m in matches}


def test_pwd006_severity_is_critical(engine):
    matches = engine.evaluate_all(_base_data(
        policy=_policy(reversible_encryption_enabled=True)))
    pwd006 = next(m for m in matches if m.rule_id == "PWD-006")
    assert pwd006.severity == "CRITICAL"
    assert pwd006.finding_type == "REVERSIBLE_ENCRYPTION_ENABLED"
    assert pwd006.is_tier0_direct is True


def test_pwd006_affected_includes_domain_policy(engine):
    matches = engine.evaluate_all(_base_data(
        policy=_policy(reversible_encryption_enabled=True)))
    pwd006 = next(m for m in matches if m.rule_id == "PWD-006")
    assert "Default Domain Policy" in pwd006.affected_objects


def test_pwd006_affected_includes_enabled_user_names(engine):
    users = [_user("ADG0D_REVERSIBLE", enabled=True),
             _user("DISABLED_USER", enabled=False)]
    matches = engine.evaluate_all(_base_data(
        entities=users, policy=_policy(reversible_encryption_enabled=True)))
    pwd006 = next(m for m in matches if m.rule_id == "PWD-006")
    all_affected = " ".join(str(o) for o in pwd006.affected_objects)
    assert "ADG0D_REVERSIBLE" in all_affected
    assert "DISABLED_USER" not in all_affected


# ─── Entity name resolution in ACL rules ────────────────────────────────────

def test_acl001_dcsync_affected_objects_contain_display_name(engine):
    """ACL-001 affected_objects must contain SAM name, not raw SID."""
    group_sid = "S-1-5-21-111-222-333-1234"
    domain_sid = "S-1-5-21-111-222-333-domain"
    grp = {
        "id": group_sid,
        "entity_type": "GROUP",
        "object_sid": group_sid,
        "sam_account_name": "ADG0D2-DCSync",
        "display_name": "ADG0D2-DCSync",
        "distinguished_name": "CN=ADG0D2-DCSync,DC=lab,DC=local",
        "domain": "lab.local",
        "is_enabled": True,
        "is_admin_count": False,
        "is_sensitive": False,
        "is_protected_user": False,
        "is_crown_jewel": False,
        "tier": None,
        "attributes": {"object_sid": group_sid},
        "business_tags": [],
    }
    domain_ent = {
        "id": domain_sid,
        "entity_type": "DOMAIN",
        "object_sid": domain_sid,
        "sam_account_name": "lab.local",
        "display_name": "lab.local",
        "distinguished_name": "DC=lab,DC=local",
        "domain": "lab.local",
        "is_enabled": True,
        "is_admin_count": False,
        "is_sensitive": True,
        "is_protected_user": False,
        "is_crown_jewel": True,
        "tier": 0,
        "attributes": {"object_sid": domain_sid},
        "business_tags": [],
    }
    edge = _dcsync_edge(src_id=group_sid, target_id=domain_sid)
    matches = engine.evaluate_all(_base_data(
        entities=[grp, domain_ent], edges=[edge]))
    acl001 = next((m for m in matches if m.rule_id == "ACL-001"), None)
    assert acl001 is not None, "ACL-001 must fire"
    all_affected = " ".join(str(o) for o in acl001.affected_objects)
    assert "ADG0D2-DCSync" in all_affected, (
        f"SAM name expected in affected_objects, got: {acl001.affected_objects}")
    assert "S-1-5-21-111-222-333-1234" not in all_affected, (
        f"Raw SID must not appear in affected_objects: {acl001.affected_objects}")


def test_entity_name_map_resolves_sid_to_sam():
    """_entity_name_map returns SAM name when entity id is a SID."""
    from adbygod_api.core.analyzers.rule_engine import _entity_name_map

    entities = [
        {"id": "S-1-5-21-111-1001", "sam_account_name": "ADG0D2_LOWACE", "display_name": "ADG0D2_LOWACE"},
        {"id": "S-1-5-21-111-1002", "sam_account_name": None, "display_name": "Anonymous"},
        {"id": "sam_only", "sam_account_name": "PLAIN_USER", "display_name": None},
    ]
    name_map = _entity_name_map(entities)
    assert name_map["S-1-5-21-111-1001"] == "ADG0D2_LOWACE"
    assert name_map["S-1-5-21-111-1002"] == "Anonymous"
    assert name_map["sam_only"] == "PLAIN_USER"


def test_entity_name_map_falls_back_to_id():
    """_entity_name_map falls back to id when no name fields set."""
    from adbygod_api.core.analyzers.rule_engine import _entity_name_map

    entities = [{"id": "S-1-5-21-111-9999"}]
    name_map = _entity_name_map(entities)
    assert name_map["S-1-5-21-111-9999"] == "S-1-5-21-111-9999"


# ─── UAC flag parsing constants ──────────────────────────────────────────────

def test_uac_flags_parsed_correctly():
    """Verify UAC flag constants produce correct boolean results."""
    from adbygod_api.core.collection.ldap_collector import (
        UAC_ACCOUNTDISABLE, UAC_DONT_REQ_PREAUTH, UAC_TRUSTED_FOR_DELEGATION,
        UAC_DONT_EXPIRE_PASSWD, UAC_SERVER_TRUST,
    )
    # ASREP flag
    assert bool(UAC_DONT_REQ_PREAUTH & UAC_DONT_REQ_PREAUTH)
    assert not bool(UAC_DONT_REQ_PREAUTH & UAC_ACCOUNTDISABLE)

    # Unconstrained delegation
    assert bool(UAC_TRUSTED_FOR_DELEGATION & UAC_TRUSTED_FOR_DELEGATION)
    assert not bool(UAC_TRUSTED_FOR_DELEGATION & UAC_SERVER_TRUST)

    # DC flag does not overlap with unconstrained
    assert not bool(UAC_SERVER_TRUST & UAC_TRUSTED_FOR_DELEGATION)

    # Never-expire password
    assert bool(UAC_DONT_EXPIRE_PASSWD & UAC_DONT_EXPIRE_PASSWD)


def test_rc4_only_detection_logic():
    """Verify rc4_only flag logic: enc_types != 0 and no AES bits (0x18)."""
    # 0x18 = AES128 (0x8) | AES256 (0x10)
    def is_rc4_only(enc_types: int) -> bool:
        return enc_types != 0 and not bool(enc_types & 0x18)

    assert is_rc4_only(0x04)      # RC4 + DES, no AES
    assert is_rc4_only(0x07)      # Old-style all DES+RC4
    assert not is_rc4_only(0)     # No enc type = not rc4_only
    assert not is_rc4_only(0x18)  # AES only
    assert not is_rc4_only(0x1C)  # AES + RC4


def test_reversible_encryption_flag_logic():
    """Verify pwdProperties 0x10 is the correct bit for reversible encryption."""
    DOMAIN_PASSWORD_STORE_CLEARTEXT = 0x10

    assert bool(0x11 & DOMAIN_PASSWORD_STORE_CLEARTEXT)  # 0x10 + 0x01
    assert not bool(0x01 & DOMAIN_PASSWORD_STORE_CLEARTEXT)  # complexity only
    assert bool(0x10 & DOMAIN_PASSWORD_STORE_CLEARTEXT)    # reversible only
