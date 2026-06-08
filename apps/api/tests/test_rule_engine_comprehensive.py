"""Comprehensive rule engine tests — every check category with real data."""
from __future__ import annotations

import pytest

from adbygod_api.core.analyzers.rule_engine import RuleEngine


# ── helpers ───────────────────────────────────────────────────────────────────

def _ent(id_: str, etype: str, name: str, *, is_enabled: bool = True, **extra) -> dict:
    e = {
        "id": id_,
        "entity_type": etype,
        "sam_account_name": name,
        "display_name": name,
        "is_enabled": is_enabled,
        "attributes": {},
    }
    # pull attrs out separately if passed under 'attributes' key
    if "attributes" in extra:
        e["attributes"] = extra.pop("attributes")
    e.update(extra)
    return e


def _edge(src: str, tgt: str, etype: str, rw: float = 0.9) -> dict:
    return {"source_id": src, "target_id": tgt, "edge_type": etype, "risk_weight": rw}


def _run(entities=None, edges=None, password_policy=None, cert_templates=None) -> list:
    engine = RuleEngine()
    data = {
        "entities": entities or [],
        "edges": edges or [],
        "password_policy": password_policy or {},
        "cert_templates": cert_templates or [],
    }
    return engine.evaluate_all(data)


def _types(findings) -> set[str]:
    return {
        f.get("finding_type") if isinstance(f, dict) else f.finding_type
        for f in findings
    }


# ── password policy checks ────────────────────────────────────────────────────

class TestPasswordPolicyChecks:
    def test_no_lockout_policy_detected(self):
        findings = _run(password_policy={"lockout_threshold": 0})
        assert "NO_LOCKOUT_POLICY" in _types(findings)

    def test_lockout_configured_no_finding(self):
        findings = _run(password_policy={"lockout_threshold": 5})
        assert "NO_LOCKOUT_POLICY" not in _types(findings)

    def test_missing_lockout_key_no_crash(self):
        findings = _run(password_policy={})
        assert isinstance(findings, list)

    def test_password_not_required_detected(self):
        entities = [_ent("u1", "USER", "nopwd", attributes={"uac_passwd_notreqd": True})]
        findings = _run(entities=entities)
        assert "PASSWD_NOTREQD" in _types(findings)

    def test_password_not_required_disabled_account_skipped(self):
        entities = [_ent("u1", "USER", "nopwd", is_enabled=False, attributes={"uac_passwd_notreqd": True})]
        findings = _run(entities=entities)
        assert "PASSWD_NOTREQD" not in _types(findings)

    def test_multiple_notreqd_accounts(self):
        entities = [
            _ent(f"u{i}", "USER", f"user{i}", attributes={"uac_passwd_notreqd": True})
            for i in range(5)
        ]
        findings = _run(entities=entities)
        assert "PASSWD_NOTREQD" in _types(findings)
        match = next(f for f in findings if (
            f.get("finding_type") if isinstance(f, dict) else f.finding_type
        ) == "PASSWD_NOTREQD")
        affected = match.get("affected_count") if isinstance(match, dict) else match.affected_count
        assert affected == 5


# ── kerberos checks ───────────────────────────────────────────────────────────

class TestKerberosChecks:
    def test_asrep_roastable_detected(self):
        entities = [_ent("u1", "USER", "asrep_user", attributes={"uac_dont_require_preauth": True})]
        findings = _run(entities=entities)
        assert "ASREP_ROASTABLE" in _types(findings)

    def test_asrep_roastable_disabled_account_skipped(self):
        entities = [_ent("u1", "USER", "asrep_user", is_enabled=False, attributes={"uac_dont_require_preauth": True})]
        findings = _run(entities=entities)
        assert "ASREP_ROASTABLE" not in _types(findings)

    def test_kerberoastable_admin_detected(self):
        entities = [_ent("svc", "SERVICE_ACCOUNT", "svc_sql",
                        is_admin_count=True, attributes={"has_spn": True})]
        findings = _run(entities=entities)
        assert "KERBEROASTABLE_ADMIN" in _types(findings)

    def test_kerberoastable_nonadmin_no_krbadmin_finding(self):
        entities = [_ent("svc", "SERVICE_ACCOUNT", "svc_web",
                        is_admin_count=False, attributes={"has_spn": True})]
        findings = _run(entities=entities)
        assert "KERBEROASTABLE_ADMIN" not in _types(findings)

    def test_unconstrained_delegation_detected(self):
        entities = [_ent("srv", "COMPUTER", "SERVER01$",
                        attributes={"uac_trusted_for_delegation": True})]
        findings = _run(entities=entities)
        assert "UNCONSTRAINED_DELEGATION" in _types(findings)

    def test_unconstrained_delegation_dc_excluded(self):
        entities = [_ent("dc1", "COMPUTER", "DC01$",
                        attributes={"uac_trusted_for_delegation": True, "uac_is_dc": True})]
        findings = _run(entities=entities)
        assert "UNCONSTRAINED_DELEGATION" not in _types(findings)

    def test_asrep_service_account_detected(self):
        entities = [_ent("svc", "SERVICE_ACCOUNT", "svc_asrep",
                        attributes={"uac_dont_require_preauth": True})]
        findings = _run(entities=entities)
        assert "ASREP_ROASTABLE" in _types(findings)


# ── ACL / control path checks ─────────────────────────────────────────────────

class TestACLChecks:
    def test_generic_all_to_tier0_detected(self):
        entities = [
            _ent("attacker", "USER", "low_priv"),
            _ent("target", "GROUP", "Domain Admins", tier=0),
        ]
        edges = [_edge("attacker", "target", "GENERIC_ALL")]
        findings = _run(entities=entities, edges=edges)
        assert len(findings) >= 1

    def test_dcsync_non_dc_detected(self):
        entities = [
            _ent("svc", "SERVICE_ACCOUNT", "svc_sync"),
            _ent("dom", "DOMAIN", "corp.local", tier=0),
        ]
        edges = [_edge("svc", "dom", "DCSYNC")]
        findings = _run(entities=entities, edges=edges)
        types = _types(findings)
        assert any("DCSYNC" in t or "DC_SYNC" in t or "REPLICATION" in t for t in types)

    def test_write_dacl_edge_analyzed(self):
        entities = [
            _ent("u1", "USER", "attacker"),
            _ent("da", "GROUP", "Domain Admins", tier=0),
        ]
        edges = [_edge("u1", "da", "WRITE_DACL")]
        findings = _run(entities=entities, edges=edges)
        assert isinstance(findings, list)

    def test_shadow_credential_edge(self):
        entities = [
            _ent("u1", "USER", "low_user"),
            _ent("admin", "USER", "admin_user", tier=0),
        ]
        edges = [_edge("u1", "admin", "ADD_KEY_CREDENTIAL_LINK")]
        findings = _run(entities=entities, edges=edges)
        assert isinstance(findings, list)


# ── delegation checks ─────────────────────────────────────────────────────────

class TestDelegationChecks:
    def test_constrained_delegation_any_protocol(self):
        entities = [_ent("comp", "COMPUTER", "COMP01$",
                        attributes={"uac_trusted_to_auth_for_delegation": True})]
        findings = _run(entities=entities)
        assert isinstance(findings, list)

    def test_rbcd_via_allowed_to_act(self):
        entities = [
            _ent("comp", "COMPUTER", "COMP01$"),
            _ent("server", "COMPUTER", "SERVER01$"),
        ]
        edges = [_edge("comp", "server", "ALLOWED_TO_ACT")]
        findings = _run(entities=entities, edges=edges)
        assert isinstance(findings, list)


# ── network / infrastructure checks ──────────────────────────────────────────

class TestNetworkChecks:
    def test_laps_not_deployed_detected(self):
        # LAPS-001 uses domain_info dict, not entity attributes
        engine = RuleEngine()
        data = {"entities": [], "edges": [], "cert_templates": [],
                "password_policy": {},
                "domain_info": {"laps_deployed": False, "total_computers": 50}}
        findings = engine.evaluate_all(data)
        assert "NO_LAPS" in _types(findings)

    def test_laps_deployed_no_finding(self):
        engine = RuleEngine()
        data = {"entities": [], "edges": [], "cert_templates": [],
                "password_policy": {},
                "domain_info": {"laps_deployed": True, "total_computers": 50}}
        findings = engine.evaluate_all(data)
        assert "NO_LAPS" not in _types(findings)

    def test_llmnr_check_does_not_crash(self):
        entities = [_ent("host", "COMPUTER", "HOST01$", attributes={"llmnr_enabled": True})]
        findings = _run(entities=entities)
        assert isinstance(findings, list)


# ── PKI / AD CS checks ────────────────────────────────────────────────────────

class TestADCSRuleEngine:
    def _esc1_template(self) -> dict:
        # ESC1 rule checks t.get("esc1_vulnerable") directly
        return {
            "id": "tmpl1",
            "name": "UserTemplate",
            "enabled": True,
            "esc1_vulnerable": True,
            "enrollee_supplies_subject": True,
            "requires_manager_approval": False,
            "authorized_signatures_required": 0,
            "client_authentication": True,
            "authentication_enabled": True,
        }

    def test_esc1_template_triggers_finding(self):
        findings = _run(cert_templates=[self._esc1_template()])
        types = _types(findings)
        assert "ESC1" in types

    def test_no_cert_templates_no_adcs_finding(self):
        findings = _run(cert_templates=[])
        types = _types(findings)
        assert "ESC1" not in types


# ── rule engine stability ─────────────────────────────────────────────────────

class TestRuleEngineStability:
    def test_empty_input_does_not_crash(self):
        assert isinstance(_run(), list)

    def test_single_entity_no_edges(self):
        assert isinstance(_run(entities=[_ent("u1", "USER", "alice")]), list)

    def test_100_users_no_crash(self):
        entities = [_ent(f"u{i}", "USER", f"user{i}") for i in range(100)]
        assert isinstance(_run(entities=entities), list)

    def test_dense_graph_no_crash(self):
        entities = [_ent(f"u{i}", "USER", f"u{i}") for i in range(20)]
        entities += [_ent("da", "GROUP", "Domain Admins", tier=0)]
        edges = [_edge(f"u{i}", "da", "MEMBER_OF") for i in range(20)]
        edges += [_edge(f"u{i}", f"u{(i+1)%20}", "GENERIC_ALL") for i in range(20)]
        findings = _run(entities=entities, edges=edges)
        assert isinstance(findings, list)

    def test_findings_have_required_fields(self):
        entities = [_ent("u1", "USER", "asrep", attributes={"uac_dont_require_preauth": True})]
        findings = _run(entities=entities)
        for f in findings:
            if isinstance(f, dict):
                assert "finding_type" in f or "title" in f
                assert "severity" in f
            else:
                assert hasattr(f, "finding_type") or hasattr(f, "title")
                assert hasattr(f, "severity")

    def test_all_entity_types_accepted(self):
        from adbygod_api.models import EntityType
        for et in EntityType:
            entities = [_ent("e1", et.value, f"ent_{et.value}")]
            try:
                findings = _run(entities=entities)
                assert isinstance(findings, list)
            except Exception as e:
                pytest.fail(f"EntityType {et.value} crashed: {e}")

    def test_all_edge_types_accepted(self):
        from adbygod_api.models import EdgeType
        src = _ent("src", "USER", "src")
        tgt = _ent("tgt", "USER", "tgt")
        for et in EdgeType:
            try:
                findings = _run(entities=[src, tgt], edges=[_edge("src", "tgt", et.value)])
                assert isinstance(findings, list)
            except Exception as e:
                pytest.fail(f"EdgeType {et.value} crashed: {e}")

    def test_circular_membership_handled(self):
        entities = [
            _ent("g1", "GROUP", "Group1"),
            _ent("g2", "GROUP", "Group2"),
            _ent("da", "GROUP", "Domain Admins", tier=0),
        ]
        edges = [
            _edge("g1", "g2", "MEMBER_OF"),
            _edge("g2", "g1", "MEMBER_OF"),
            _edge("g1", "da", "MEMBER_OF"),
        ]
        assert isinstance(_run(entities=entities, edges=edges), list)

    def test_unicode_sam_names_handled(self):
        entities = [_ent("u1", "USER", "用户_unicode")]
        assert isinstance(_run(entities=entities), list)

    def test_very_long_sam_name(self):
        entities = [_ent("u1", "USER", "a" * 512)]
        assert isinstance(_run(entities=entities), list)

    def test_rule_count_is_nonzero(self):
        engine = RuleEngine()
        assert len(engine.rules) > 0

    def test_get_rule_by_id(self):
        engine = RuleEngine()
        rule = engine.get_rule("KRB-001")
        assert rule is not None
        assert rule.id == "KRB-001"

    def test_get_nonexistent_rule_returns_none(self):
        engine = RuleEngine()
        assert engine.get_rule("FAKE-999") is None

    def test_all_builtin_rules_have_valid_ids(self):
        engine = RuleEngine()
        for rule in engine.rules:
            assert rule.id
            assert len(rule.id) >= 3
            assert "-" in rule.id

    def test_multiple_rule_matches_same_data(self):
        entities = [
            _ent("u1", "USER", "asrep_admin",
                 is_admin_count=True,
                 attributes={"uac_dont_require_preauth": True, "has_spn": True, "uac_passwd_notreqd": True}),
        ]
        findings = _run(entities=entities)
        types = _types(findings)
        # Should trigger ASREP, KERBEROASTABLE_ADMIN (admin+spn), PASSWD_NOTREQD
        assert len(types) >= 2

    def test_password_policy_edge_cases(self):
        for threshold in [0, 1, 5, 10, 50, 999]:
            findings = _run(password_policy={"lockout_threshold": threshold})
            if threshold == 0:
                assert "NO_LOCKOUT_POLICY" in _types(findings)
            else:
                assert "NO_LOCKOUT_POLICY" not in _types(findings)
