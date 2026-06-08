from __future__ import annotations


def test_synthetic_validation_is_post_only(test_app):
    client = test_app["client"]

    response = client.get("/api/v1/validation/simulate-synthetic/kerberos/pentest_target")

    assert response.status_code == 405


def test_synthetic_validation_response_contract(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("synthetic-user", "synthetic@example.test"))

    response = client.post(
        "/api/v1/validation/simulate-synthetic/kerberos/pentest_target",
        headers=test_app["headers_for"](user),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["module_id"] == "kerberos"
    assert payload["preset"] == "pentest_target"
    assert isinstance(payload["summary"], str)
    assert isinstance(payload["risk_score"], (int, float))
    assert isinstance(payload["confidence"], (int, float))
    assert isinstance(payload["kill_chains"], int)
    assert isinstance(payload["threat_actors"], list)
    assert "final_verdict" not in payload
