from __future__ import annotations
import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Task 1 — Service account numeric scoring
# ──────────────────────────────────────────────────────────────────────────────

def _make_entity(**kwargs):
    """Build a minimal fake Entity-like object for scoring tests."""
    from types import SimpleNamespace
    defaults = {
        "is_admin_count": False,
        "is_sensitive": False,
        "is_crown_jewel": False,
        "is_enabled": True,
        "password_last_set": None,
        "last_logon": None,
        "attributes": {},
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_score_account_unconstrained_delegation_is_always_critical():
    from adbygod_api.routes.service_accounts import _score_account
    entity = _make_entity(attributes={"unconstrained_delegation": True})
    score, grade = _score_account(entity, 0)
    assert score == 100.0
    assert grade == "CRITICAL"


def test_score_account_admin_count_scores_critical():
    from adbygod_api.routes.service_accounts import _score_account
    entity = _make_entity(is_admin_count=True)
    score, grade = _score_account(entity, 0)
    assert score >= 85.0
    assert grade == "CRITICAL"


def test_score_account_kerberoastable_scores_high():
    from adbygod_api.routes.service_accounts import _score_account
    entity = _make_entity(attributes={"kerberoastable": True})
    score, grade = _score_account(entity, 0)
    assert score >= 65.0
    assert grade in ("HIGH", "CRITICAL")


def test_score_account_disabled_halves_score():
    from adbygod_api.routes.service_accounts import _score_account
    enabled = _make_entity(attributes={"kerberoastable": True}, is_enabled=True)
    disabled = _make_entity(attributes={"kerberoastable": True}, is_enabled=False)
    score_e, _ = _score_account(enabled, 0)
    score_d, _ = _score_account(disabled, 0)
    assert score_d == pytest.approx(score_e * 0.5, abs=1.0)


def test_score_account_stale_password_contributes():
    from adbygod_api.routes.service_accounts import _score_account
    fresh = _make_entity()
    stale = _make_entity()
    score_f, _ = _score_account(fresh, 0)
    score_s, _ = _score_account(stale, 800)  # > 730 days
    assert score_s > score_f


def test_score_account_response_includes_risk_score(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("sa-score-user", "sa-score@example.invalid"))
    ws = db.run(db.create_workspace("sa-score-ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    assessment = db.run(db.create_assessment("SA Score Test", "score.local", workspace_id=ws.id, created_by=user.id))
    headers = test_app["headers_for"](user)
    response = test_app["client"].get(
        f"/api/v1/service-accounts?assessment_id={assessment.id}",
        headers=headers,
    )
    assert response.status_code == 200
    items = response.json()
    # Empty assessment returns empty list — that's fine
    if items:
        assert "risk_score" in items[0]
        assert isinstance(items[0]["risk_score"], (int, float))


# ──────────────────────────────────────────────────────────────────────────────
# Task 2 — Trust risk comprehensive assessment
# ──────────────────────────────────────────────────────────────────────────────

def test_trust_risk_forest_no_sid_filtering_is_critical():
    from adbygod_api.routes.trusts import _trust_risk
    result = _trust_risk({"forest_trust": True, "sid_filtering": False})
    assert result == "CRITICAL"


def test_trust_risk_bidirectional_no_sid_filtering_is_critical():
    from adbygod_api.routes.trusts import _trust_risk
    result = _trust_risk({"direction_val": 3, "sid_filtering": False})
    assert result == "CRITICAL"


def test_trust_risk_any_no_sid_filtering_is_high():
    from adbygod_api.routes.trusts import _trust_risk
    # Outbound (not forest, not bidirectional) but no SID filtering
    result = _trust_risk({"direction_val": 2, "sid_filtering": False, "forest_trust": False})
    assert result == "HIGH"


def test_trust_risk_forest_with_sid_filtering_is_high():
    from adbygod_api.routes.trusts import _trust_risk
    # Forest trust with SID filtering ON but no selective auth
    result = _trust_risk({"forest_trust": True, "sid_filtering": True, "selective_auth": False})
    assert result == "HIGH"


def test_trust_risk_selective_auth_is_low():
    from adbygod_api.routes.trusts import _trust_risk
    result = _trust_risk({"selective_auth": True, "sid_filtering": True})
    assert result == "LOW"


def test_trust_risk_quarantine_is_low():
    from adbygod_api.routes.trusts import _trust_risk
    result = _trust_risk({"quarantine": True, "sid_filtering": True})
    assert result == "LOW"


def test_trust_risk_transitive_no_selective_auth_is_medium():
    from adbygod_api.routes.trusts import _trust_risk
    result = _trust_risk({"transitive": True, "selective_auth": False, "sid_filtering": True, "forest_trust": False})
    assert result == "MEDIUM"


def test_trust_entry_has_risk_factors(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("trust-score-user", "trust-score@example.invalid"))
    ws = db.run(db.create_workspace("trust-score-ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    assessment = db.run(db.create_assessment("Trust Factors Test", "trust.local", workspace_id=ws.id, created_by=user.id))
    headers = test_app["headers_for"](user)
    response = test_app["client"].get(
        f"/api/v1/trusts?assessment_id={assessment.id}",
        headers=headers,
    )
    assert response.status_code == 200
    items = response.json()
    if items:
        assert "risk_factors" in items[0]
        assert isinstance(items[0]["risk_factors"], list)


# ──────────────────────────────────────────────────────────────────────────────
# Task 3 — Remediation graph-powered simulation
# ──────────────────────────────────────────────────────────────────────────────

def test_simulate_remediation_returns_graph_powered_flag(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("remed-gp-user", "remed-gp@example.invalid"))
    ws = db.run(db.create_workspace("remed-gp-ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    assessment = db.run(db.create_assessment("Remediation Graph Test", "remed.local", workspace_id=ws.id, created_by=user.id))
    headers = test_app["headers_for"](user)

    response = test_app["client"].post(
        "/api/v1/remediation/simulate",
        headers=headers,
        json={"assessment_id": str(assessment.id), "finding_ids": []},
    )
    assert response.status_code == 200
    body = response.json()
    assert "graph_powered" in body
    assert isinstance(body["graph_powered"], bool)


def test_simulate_remediation_returns_blast_radius_reduction(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("remed-br-user", "remed-br@example.invalid"))
    ws = db.run(db.create_workspace("remed-br-ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    assessment = db.run(db.create_assessment("Blast Radius Test", "blast.local", workspace_id=ws.id, created_by=user.id))
    headers = test_app["headers_for"](user)

    response = test_app["client"].post(
        "/api/v1/remediation/simulate",
        headers=headers,
        json={"assessment_id": str(assessment.id), "finding_ids": []},
    )
    assert response.status_code == 200
    body = response.json()
    assert "blast_radius_reduction" in body
    assert isinstance(body["blast_radius_reduction"], int)


def test_simulate_remediation_falls_back_to_arithmetic_when_no_graph(test_app, monkeypatch):
    """When graph has no nodes, simulation must not raise and must return graph_powered=False."""
    db = test_app["db"]
    user = db.run(db.create_user("remed-fallback-user", "remed-fallback@example.invalid"))
    ws = db.run(db.create_workspace("remed-fallback-ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    assessment = db.run(db.create_assessment("Fallback Test", "fallback.local", workspace_id=ws.id, created_by=user.id))
    headers = test_app["headers_for"](user)

    from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
    from adbygod_api.routes import remediation as remed_mod

    async def _empty_analyzer(*_a, **_kw):
        return ADGraphAnalyzer()  # no nodes

    monkeypatch.setattr(remed_mod, "_load_graph_analyzer_for_assessment", _empty_analyzer)

    response = test_app["client"].post(
        "/api/v1/remediation/simulate",
        headers=headers,
        json={"assessment_id": str(assessment.id), "finding_ids": []},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["graph_powered"] is False


# ──────────────────────────────────────────────────────────────────────────────
# Task 4 — Path resolver hybrid selection
# ──────────────────────────────────────────────────────────────────────────────

def test_fingerprint_environment_returns_empty_for_none_analyzer():
    from adbygod_api.core.chains.path_resolver import _fingerprint_environment
    result = _fingerprint_environment(None)
    assert result == {}


def test_fingerprint_environment_returns_empty_for_empty_graph():
    from adbygod_api.core.chains.path_resolver import _fingerprint_environment
    from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
    result = _fingerprint_environment(ADGraphAnalyzer())
    assert result == {}


def test_score_path_for_environment_boosts_adcs_esc1_when_esc1_detected():
    from adbygod_api.core.chains.path_resolver import _score_path_for_environment, _PATH_LOOKUP
    path = _PATH_LOOKUP.get("adcs_esc1_cert_da")
    if path is None:
        pytest.skip("adcs_esc1_cert_da path not found")
    env_with_esc1 = {"adcs_esc1": True, "has_adcs": True}
    env_without_adcs = {"adcs_esc1": False, "has_adcs": False}
    score_with = _score_path_for_environment(path, env_with_esc1)
    score_without = _score_path_for_environment(path, env_without_adcs)
    assert score_with > path.confidence
    assert score_without < path.confidence


def test_score_path_for_environment_returns_baseline_when_env_empty():
    from adbygod_api.core.chains.path_resolver import _score_path_for_environment, ALL_PATHS
    path = ALL_PATHS[0]
    result = _score_path_for_environment(path, {})
    assert result == path.confidence


def test_resolve_path_to_steps_returns_four_tuple():
    from adbygod_api.core.chains.path_resolver import resolve_path_to_steps
    result = resolve_path_to_steps(None, "10.0.0.1", "corp.local", {}, "DOMAIN_USER")
    assert len(result) == 4, f"Expected 4-tuple, got {len(result)}-tuple"
    steps, nodes, all_paths_meta, graph_paths = result
    assert isinstance(steps, list)
    assert isinstance(graph_paths, list)


def test_get_graph_paths_returns_empty_for_none_analyzer():
    from adbygod_api.core.chains.path_resolver import _get_graph_paths
    result = _get_graph_paths(None)
    assert result == []


def test_preflight_endpoint_includes_graph_paths(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("preflight-user", "preflight@example.invalid", is_superadmin=True))
    ws = db.run(db.create_workspace("preflight-ws"))
    db.run(db.add_workspace_user(ws.id, user.id))
    headers = test_app["headers_for"](user)

    response = test_app["client"].post(
        "/api/v1/chains/resolve",
        headers=headers,
        json={
            "target": "10.0.0.1",
            "domain": "corp.local",
            "situation": "DOMAIN_USER",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert "graph_paths" in body
    assert isinstance(body["graph_paths"], list)
