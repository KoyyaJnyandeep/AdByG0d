from __future__ import annotations

import adbygod_api.models as models


def test_login_sets_cookie_and_cookie_auth_works(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("cookie-user", "cookie@example.invalid", password="StrongPassword123!"))

    login = client.post(
        "/api/v1/auth/login",
        json={"username": user.username, "password": "StrongPassword123!"},
    )
    assert login.status_code == 200
    assert "adbygod_session" in login.cookies

    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == user.username

    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 200

    denied = client.get("/api/v1/auth/me")
    assert denied.status_code == 401


def test_global_search_returns_findings_and_entities_with_workspace_scoping(test_app):
    db = test_app["db"]
    client = test_app["client"]

    user_one = db.run(db.create_user("searcher", "searcher@example.invalid"))
    user_two = db.run(db.create_user("other-searcher", "other-searcher@example.invalid"))
    workspace_one = db.run(db.create_workspace("blue-search"))
    workspace_two = db.run(db.create_workspace("red-search"))
    db.run(db.add_workspace_user(workspace_one.id, user_one.id))
    db.run(db.add_workspace_user(workspace_two.id, user_two.id))

    assessment_one = db.run(db.create_assessment("Blue", "blue.local", workspace_id=workspace_one.id, created_by=user_one.id))
    assessment_two = db.run(db.create_assessment("Red", "red.local", workspace_id=workspace_two.id, created_by=user_two.id))

    db.run(db.create_entity(assessment_one.id, entity_type=models.EntityType.USER, sam_account_name="alice.search"))
    db.run(db.create_entity(assessment_two.id, entity_type=models.EntityType.USER, sam_account_name="hidden.search"))
    db.run(db.create_finding(assessment_one.id, title="Searchable Exposure"))
    db.run(db.create_finding(assessment_two.id, title="Hidden Exposure"))

    response = client.get(
        "/api/v1/search",
        headers=test_app["headers_for"](user_one),
        params={"q": "search"},
    )
    assert response.status_code == 200
    payload = response.json()

    assert any(item["title"] == "Searchable Exposure" for item in payload["findings"])
    assert all(item["title"] != "Hidden Exposure" for item in payload["findings"])
    assert any(item["label"] == "alice.search" for item in payload["entities"])
    assert all(item["label"] != "hidden.search" for item in payload["entities"])
