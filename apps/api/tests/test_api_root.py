from __future__ import annotations


def test_api_root_is_a_helpful_landing_page(test_app):
    response = test_app["client"].get("/")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["api_docs"] == "/api/docs"
    assert body["health"] == "/api/health"
    assert body["api_prefix"] == "/api/v1"
    assert "port 3000" in body["message"]
