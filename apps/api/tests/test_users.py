"""Tests for /api/v1/users/* endpoints."""
from __future__ import annotations




def _login(client, username, password="password123!"):
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200
    return r


# ── list_users ────────────────────────────────────────────────────────────────

def test_list_users_requires_superadmin(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user = db.run(db.create_user("analyst1", "a1@example.com"))
    r = client.get("/api/v1/users", headers=headers_for(user))
    assert r.status_code == 403


def test_list_users_superadmin_gets_all(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    admin = db.run(db.create_user("admin_list", "admin_list@example.com", is_superadmin=True))
    db.run(db.create_user("userA", "ua@example.com"))
    db.run(db.create_user("userB", "ub@example.com"))
    r = client.get("/api/v1/users", headers=headers_for(admin))
    assert r.status_code == 200
    usernames = {u["username"] for u in r.json()}
    assert "userA" in usernames
    assert "userB" in usernames


def test_list_users_pagination(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    admin = db.run(db.create_user("admin_page", "admin_page@example.com", is_superadmin=True))
    for i in range(5):
        db.run(db.create_user(f"page_user_{i}", f"pu{i}@example.com"))
    r1 = client.get("/api/v1/users?limit=2&offset=0", headers=headers_for(admin))
    r2 = client.get("/api/v1/users?limit=2&offset=2", headers=headers_for(admin))
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert len(r1.json()) == 2
    ids1 = {u["id"] for u in r1.json()}
    ids2 = {u["id"] for u in r2.json()}
    assert ids1.isdisjoint(ids2), "Paginated pages must not overlap"


def test_list_users_response_schema(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    admin = db.run(db.create_user("admin_schema", "admin_schema@example.com", is_superadmin=True))
    db.run(db.create_user("schema_user", "schema_user@example.com"))
    r = client.get("/api/v1/users", headers=headers_for(admin))
    assert r.status_code == 200
    for user in r.json():
        assert set(user.keys()) >= {"id", "username", "email", "is_active", "is_superadmin"}


# ── get_me ────────────────────────────────────────────────────────────────────

def test_get_me_returns_own_profile(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user = db.run(db.create_user("me_user", "me@example.com"))
    r = client.get("/api/v1/users/me", headers=headers_for(user))
    assert r.status_code == 200
    assert r.json()["username"] == "me_user"


# ── update_user ───────────────────────────────────────────────────────────────

def test_update_user_self_allowed(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user = db.run(db.create_user("self_update", "self@example.com"))
    r = client.patch(
        f"/api/v1/users/{user.id}",
        json={"full_name": "Updated Name"},
        headers=headers_for(user),
    )
    assert r.status_code == 200
    assert r.json()["full_name"] == "Updated Name"


def test_update_other_user_forbidden_for_non_admin(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user1 = db.run(db.create_user("forbidden_u1", "fu1@example.com"))
    user2 = db.run(db.create_user("forbidden_u2", "fu2@example.com"))
    r = client.patch(
        f"/api/v1/users/{user2.id}",
        json={"full_name": "Hacked"},
        headers=headers_for(user1),
    )
    assert r.status_code == 403


def test_update_user_email_uniqueness_enforced(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    db.run(db.create_user("email_u1", "email1@example.com"))
    u2 = db.run(db.create_user("email_u2", "email2@example.com"))
    admin = db.run(db.create_user("email_admin", "email_admin@example.com", is_superadmin=True))
    r = client.patch(
        f"/api/v1/users/{u2.id}",
        json={"email": "email1@example.com"},
        headers=headers_for(admin),
    )
    assert r.status_code == 409


def test_update_user_email_uniqueness_is_case_insensitive(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    db.run(db.create_user("email_case_u1", "case@example.com"))
    u2 = db.run(db.create_user("email_case_u2", "other-case@example.com"))
    admin = db.run(db.create_user("email_case_admin", "email_case_admin@example.com", is_superadmin=True))
    r = client.patch(
        f"/api/v1/users/{u2.id}",
        json={"email": "  CASE@EXAMPLE.COM  "},
        headers=headers_for(admin),
    )
    assert r.status_code == 409


def test_update_user_password_too_short(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user = db.run(db.create_user("short_pwd", "short@example.com"))
    r = client.patch(
        f"/api/v1/users/{user.id}",
        json={"password": "abc"},
        headers=headers_for(user),
    )
    assert r.status_code == 422


def test_update_user_password_too_long(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    user = db.run(db.create_user("long_pwd", "long@example.com"))
    r = client.patch(
        f"/api/v1/users/{user.id}",
        json={"password": "x" * 129},
        headers=headers_for(user),
    )
    assert r.status_code == 422


def test_update_user_404(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    admin = db.run(db.create_user("admin_404", "admin_404@example.com", is_superadmin=True))
    import uuid
    r = client.patch(
        f"/api/v1/users/{uuid.uuid4()}",
        json={"full_name": "Ghost"},
        headers=headers_for(admin),
    )
    assert r.status_code == 404


# ── deactivate / activate ─────────────────────────────────────────────────────

def test_deactivate_requires_superadmin(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    analyst = db.run(db.create_user("deact_analyst", "da@example.com"))
    target = db.run(db.create_user("deact_target", "dt@example.com"))
    r = client.post(f"/api/v1/users/{target.id}/deactivate", headers=headers_for(analyst))
    assert r.status_code == 403


def test_deactivate_self_forbidden(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    admin = db.run(db.create_user("self_deact_admin", "sda@example.com", is_superadmin=True))
    r = client.post(f"/api/v1/users/{admin.id}/deactivate", headers=headers_for(admin))
    assert r.status_code == 400


def test_deactivate_and_activate_roundtrip(test_app):
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]
    admin = db.run(db.create_user("rt_admin", "rt_admin@example.com", is_superadmin=True))
    user = db.run(db.create_user("rt_user", "rt_user@example.com"))
    r = client.post(f"/api/v1/users/{user.id}/deactivate", headers=headers_for(admin))
    assert r.status_code == 204
    r = client.post(f"/api/v1/users/{user.id}/activate", headers=headers_for(admin))
    assert r.status_code == 204
