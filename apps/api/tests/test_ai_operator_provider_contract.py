from __future__ import annotations

import pytest

from adbygod_api.core.ai_operator.orchestrator import Suggestion
from adbygod_api.routes import ai_operator


@pytest.fixture()
def ai_user(test_app):
    user = test_app["db"].run(
        test_app["db"].create_user("ai.contract", "ai.contract@example.test", is_superadmin=True)
    )
    return user, test_app["headers_for"](user)


def test_suggest_forwards_provider_and_model(test_app, ai_user, monkeypatch):
    _user, headers = ai_user
    captured: dict[str, str | None] = {}

    async def fake_get_next_suggestion(
        session,
        kill_chain_phases,
        recent_findings,
        phase_scope,
        excluded_ids,
        provider_id=None,
        model=None,
        api_key=None,
        base_url=None,
    ):
        captured["provider_id"] = provider_id
        captured["model"] = model
        return Suggestion(
            technique_id="kerberoast",
            title="Kerberoast",
            reason="Selected for test",
            expected_outcome="Ticket material",
            mitre_id="T1558.003",
            phase_id=2,
            prerequisites_met=True,
            auth_level_promotion=False,
            requires_human_approval=False,
        )

    monkeypatch.setattr(ai_operator, "get_next_suggestion", fake_get_next_suggestion)

    response = test_app["client"].post(
        "/api/v1/ai-operator/suggest",
        headers=headers,
        json={
            "phase_scope": [2],
            "excluded_ids": ["skip-me"],
            "provider": "openai",
            "model": "gpt-4o",
        },
    )

    assert response.status_code == 200
    assert response.json()["technique_id"] == "kerberoast"
    assert captured == {"provider_id": "openai", "model": "gpt-4o"}


def test_playbook_forwards_provider_and_model(test_app, ai_user, monkeypatch):
    _user, headers = ai_user
    captured: dict[str, str | None] = {}

    async def fake_generate_playbook(
        session,
        phase_scope,
        excluded_ids,
        provider_id=None,
        model=None,
        api_key=None,
    ):
        captured["provider_id"] = provider_id
        captured["model"] = model
        return [
            {
                "technique_id": "asrep",
                "title": "AS-REP roast",
                "phase_id": 2,
                "reason": "Selected for test",
                "mitre_id": "T1558.004",
            }
        ]

    monkeypatch.setattr(ai_operator, "generate_playbook", fake_generate_playbook)

    response = test_app["client"].post(
        "/api/v1/ai-operator/playbook",
        headers=headers,
        json={
            "phase_scope": [2, 3],
            "excluded_ids": ["skip-me"],
            "provider": "ollama",
            "model": "llama3.1",
        },
    )

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert captured == {"provider_id": "ollama", "model": "llama3.1"}


def test_test_provider_rejects_loopback_base_url(test_app):
    """POST /providers/openai/test with a loopback base_url must return 422."""
    factory = test_app["db"]
    client = test_app["client"]

    factory.run(factory.create_user("ssrf_admin", "ssrf_admin@test.com", is_superadmin=True))
    login = client.post("/api/v1/auth/login", json={"username": "ssrf_admin", "password": "password123!"})
    token = login.cookies.get("adbygod_session")

    for bad_url in [
        "http://127.0.0.1:8080",
        "http://localhost/admin",
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/latest/meta-data",
    ]:
        resp = client.post(
            "/api/v1/ai-operator/providers/openai/test",
            json={"base_url": bad_url, "api_key": "test-key"},
            cookies={"adbygod_session": token},
            headers={"x-requested-with": "XMLHttpRequest"},
        )
        assert resp.status_code == 422, f"Expected 422 for {bad_url}, got {resp.status_code}"


def test_test_provider_ollama_rejects_non_configured_base_url(test_app, monkeypatch):
    """POST /providers/ollama/test with a base_url different from configured OLLAMA_BASE_URL must return 422."""
    from adbygod_api.routes import ai_operator as ai_op_mod
    factory = test_app["db"]
    client = test_app["client"]

    # Patch get_settings in the ai_operator module to avoid Pydantic revalidation side-effects
    class _FakeSettings:
        OLLAMA_BASE_URL = "http://localhost:11434"

    monkeypatch.setattr(ai_op_mod, "get_settings", lambda: _FakeSettings())

    factory.run(factory.create_user("ssrf_ollama", "ssrf_ollama@test.com", is_superadmin=True))
    login = client.post("/api/v1/auth/login", json={"username": "ssrf_ollama", "password": "password123!"})
    token = login.cookies.get("adbygod_session")

    resp = client.post(
        "/api/v1/ai-operator/providers/ollama/test",
        json={"base_url": "http://internal-server:11434"},
        cookies={"adbygod_session": token},
        headers={"x-requested-with": "XMLHttpRequest"},
    )
    assert resp.status_code == 422
