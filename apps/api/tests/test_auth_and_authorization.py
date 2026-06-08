from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest
from jose import jwt
from uuid import UUID

from sqlalchemy import func, select

from adbygod_api import models
from adbygod_api.models import FindingStatus
from adbygod_api.config import Settings
from adbygod_api.routes import auth as auth_routes


def test_config_validation_rejects_weak_secret():
    settings = Settings(SECRET_KEY="short-secret", DEBUG=False, ENABLE_COMMAND_EXECUTION=False, ALLOW_DEV_BOOTSTRAP=False)
    with pytest.raises(RuntimeError):
        settings.validate_runtime()


def test_config_validation_rejects_weak_secret_when_dangerous_features_enabled():
    command_settings = Settings(
        SECRET_KEY="replace-with-a-unique-32-plus-character-secret",
        DEBUG=True,
        ENABLE_COMMAND_EXECUTION=True,
        COMMAND_EXECUTION_ALLOWLIST="enum-ldapsearch-linux",
        ALLOW_DEV_BOOTSTRAP=False,
    )
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        command_settings.validate_runtime()

    bootstrap_settings = Settings(
        SECRET_KEY="short-secret",
        DEBUG=True,
        ENABLE_COMMAND_EXECUTION=False,
        ALLOW_DEV_BOOTSTRAP=True,
        DEFAULT_ADMIN_PASSWORD="StrongPassword123!",
    )
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        bootstrap_settings.validate_runtime()


def test_config_validation_rejects_weak_default_admin_password():
    settings = Settings(
        SECRET_KEY="x" * 40,
        DEBUG=True,
        ALLOW_DEV_BOOTSTRAP=True,
        DEFAULT_ADMIN_PASSWORD="password",
        ENABLE_COMMAND_EXECUTION=False,
    )
    with pytest.raises(RuntimeError, match="DEFAULT_ADMIN_PASSWORD"):
        settings.validate_runtime()


def test_command_allowlist_validation_rejects_unknown_ids():
    settings = Settings(
        SECRET_KEY="x" * 40,
        DEBUG=True,
        ALLOW_DEV_BOOTSTRAP=False,
        ENABLE_COMMAND_EXECUTION=True,
        COMMAND_EXECUTION_ALLOWLIST="enum-ldapsearch-linux,not-real",
    )
    with pytest.raises(RuntimeError, match="not-real"):
        settings.validate_runtime()


def test_command_allowlist_validation_accepts_valid_or_disabled_empty():
    valid = Settings(
        SECRET_KEY="x" * 40,
        DEBUG=True,
        ALLOW_DEV_BOOTSTRAP=False,
        ENABLE_COMMAND_EXECUTION=True,
        COMMAND_EXECUTION_ALLOWLIST="enum-ldapsearch-linux",
    )
    valid.validate_runtime()

    disabled_empty = Settings(
        SECRET_KEY="x" * 40,
        DEBUG=False,
        ALLOW_DEV_BOOTSTRAP=False,
        ENABLE_COMMAND_EXECUTION=False,
        COMMAND_EXECUTION_ALLOWLIST="",
    )
    disabled_empty.validate_runtime()


def test_config_validation_rejects_production_debug_mode():
    settings = Settings(
        SECRET_KEY="x" * 40,
        DEBUG=True,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+asyncpg://user:pass@db/adbygod",
    )
    with pytest.raises(RuntimeError, match="DEBUG"):
        settings.validate_runtime()


def test_config_validation_rejects_production_sqlite():
    settings = Settings(
        SECRET_KEY="x" * 40,
        DEBUG=False,
        ENVIRONMENT="production",
        DATABASE_URL="sqlite+aiosqlite:///tmp/adbygod.db",
    )
    with pytest.raises(RuntimeError, match="external database"):
        settings.validate_runtime()


def test_config_validation_rejects_production_wildcard_cors():
    settings = Settings(
        SECRET_KEY="x" * 40,
        DEBUG=False,
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+asyncpg://user:pass@db/adbygod",
        ALLOWED_ORIGINS="*",
    )
    with pytest.raises(RuntimeError, match="wildcard CORS"):
        settings.validate_runtime()


def test_login_does_not_auto_bootstrap_admin(test_app):
    client = test_app["client"]
    response = client.post("/api/v1/auth/login", json={"username": "admin", "password": "password"})
    assert response.status_code == 401


def test_settings_accept_release_style_debug_values():
    release = Settings(SECRET_KEY="x" * 40, DEBUG="release")
    development = Settings(SECRET_KEY="x" * 40, DEBUG="development")

    assert release.DEBUG is False
    assert development.DEBUG is True


def test_bootstrap_disabled_by_default(test_app):
    auth_routes.settings.DEBUG = False
    auth_routes.settings.ALLOW_DEV_BOOTSTRAP = False
    with pytest.raises(RuntimeError):
        test_app["db"].run(
            auth_routes.bootstrap_admin_user(
                username="bootstrap",
                email="bootstrap@example.invalid",
                password="StrongPassword123!",
            )
        )


def test_bootstrap_allowed_only_with_explicit_dev_flag(test_app):
    auth_routes.settings.DEBUG = True
    auth_routes.settings.ALLOW_DEV_BOOTSTRAP = True
    user = test_app["db"].run(
        auth_routes.bootstrap_admin_user(
            username="bootstrap",
            email="bootstrap@example.invalid",
            password="StrongPassword123!",
        )
    )
    assert user.username == "bootstrap"
    assert user.is_superadmin is True


def test_default_admin_password_rejects_default_password(test_app):
    auth_routes.settings.DEBUG = True
    auth_routes.settings.ALLOW_DEV_BOOTSTRAP = True
    auth_routes.settings.SECRET_KEY = "x" * 40
    auth_routes.settings.DEFAULT_ADMIN_USERNAME = "admin"
    auth_routes.settings.DEFAULT_ADMIN_EMAIL = "admin@example.invalid"
    auth_routes.settings.DEFAULT_ADMIN_PASSWORD = "password"
    auth_routes.settings.DEFAULT_ADMIN_FULL_NAME = "Development Administrator"

    with pytest.raises(RuntimeError, match="DEFAULT_ADMIN_PASSWORD"):
        auth_routes.settings.validate_runtime()


def test_default_admin_credentials_are_provisioned_and_loginable_with_strong_password(test_app):
    auth_routes.settings.DEBUG = True
    auth_routes.settings.ALLOW_DEV_BOOTSTRAP = True
    auth_routes.settings.DEFAULT_ADMIN_USERNAME = "strongadmin"
    auth_routes.settings.DEFAULT_ADMIN_EMAIL = "strongadmin@example.invalid"
    auth_routes.settings.DEFAULT_ADMIN_PASSWORD = "StrongPassword123!"
    auth_routes.settings.DEFAULT_ADMIN_FULL_NAME = "Development Administrator"

    test_app["db"].run(auth_routes.ensure_default_admin_user())

    response = test_app["client"].post(
        "/api/v1/auth/login",
        json={"username": "strongadmin", "password": "StrongPassword123!"},
    )

    assert response.status_code == 200
    assert response.json()["user"]["username"] == "strongadmin"


def test_login_password_verification_is_exact():
    hashed = auth_routes._hash_password("password")
    assert auth_routes._verify_login_password("password", hashed) is True
    assert auth_routes._verify_login_password(" password ", hashed) is False

    whitespace_hash = auth_routes._hash_password(" password ")
    assert auth_routes._verify_login_password(" password ", whitespace_hash) is True


def test_login_rate_limit_blocks_repeated_failed_attempts(test_app):
    client = test_app["client"]
    db = test_app["db"]
    db.run(db.create_user("ratelimit", "ratelimit@example.invalid", password="StrongPassword123!"))

    auth_routes.settings.LOGIN_RATE_LIMIT_ATTEMPTS = 2
    auth_routes.settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS = 300
    auth_routes._LOGIN_ATTEMPTS.clear()

    first = client.post("/api/v1/auth/login", json={"username": "ratelimit", "password": "wrong"})
    second = client.post("/api/v1/auth/login", json={"username": "ratelimit", "password": "wrong"})
    blocked = client.post("/api/v1/auth/login", json={"username": "ratelimit", "password": "wrong"})

    assert first.status_code == 401
    assert second.status_code == 401
    assert blocked.status_code == 429
    assert "Too many failed login attempts" in blocked.json()["detail"]


def test_login_accepts_case_insensitive_email_identifier(test_app):
    db = test_app["db"]
    client = test_app["client"]

    db.run(
        db.create_user(
            "mixedcase",
            "CaseSensitive@example.invalid",
            password="StrongPassword123!",
        )
    )

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "casesensitive@EXAMPLE.invalid", "password": "StrongPassword123!"},
    )

    assert response.status_code == 200
    assert response.json()["user"]["username"] == "mixedcase"
    assert response.json()["user"]["email"] == "CaseSensitive@example.invalid"


def test_cross_workspace_access_denied(test_app):
    db = test_app["db"]
    client = test_app["client"]

    user_one = db.run(db.create_user("alice", "alice@example.invalid"))
    user_two = db.run(db.create_user("bob", "bob@example.invalid"))
    workspace_one = db.run(db.create_workspace("blue"))
    workspace_two = db.run(db.create_workspace("red"))
    db.run(db.add_workspace_user(workspace_one.id, user_one.id))
    db.run(db.add_workspace_user(workspace_two.id, user_two.id))
    assessment = db.run(db.create_assessment("Red Assessment", "red.local", workspace_id=workspace_two.id, created_by=user_two.id))

    response = client.get(f"/api/v1/assessments/{assessment.id}", headers=test_app["headers_for"](user_one))
    assert response.status_code == 403


def test_null_workspace_assessment_is_superadmin_only(test_app):
    db = test_app["db"]
    client = test_app["client"]

    user = db.run(db.create_user("charlie", "charlie@example.invalid"))
    admin = db.run(db.create_user("root", "root@example.invalid", is_superadmin=True))
    assessment = db.run(db.create_assessment("Legacy", "legacy.local", workspace_id=None, created_by=admin.id))

    denied = client.get(f"/api/v1/assessments/{assessment.id}", headers=test_app["headers_for"](user))
    allowed = client.get(f"/api/v1/assessments/{assessment.id}", headers=test_app["headers_for"](admin))

    assert denied.status_code == 403
    assert allowed.status_code == 200


def test_create_assessment_auto_assigns_single_accessible_workspace(test_app):
    db = test_app["db"]
    client = test_app["client"]

    user = db.run(db.create_user("worker", "worker@example.invalid"))
    workspace = db.run(db.create_workspace("blue"))
    db.run(db.add_workspace_user(workspace.id, user.id))

    response = client.post(
        "/api/v1/assessments",
        headers=test_app["headers_for"](user),
        json={
            "name": "Blue Assessment",
            "domain": "blue.local",
            "collection_mode": "LINUX_REMOTE",
            "collection_config": {"modules": ["directory_inventory"]},
        },
    )

    assert response.status_code == 201
    created = response.json()
    loaded = db.run(db.get_assessment(UUID(created["id"])))
    assert loaded is not None
    assert loaded.workspace_id == workspace.id


def test_create_assessment_accepts_windows_local_mode(test_app):
    db = test_app["db"]
    client = test_app["client"]

    user = db.run(db.create_user("windows-local", "windows-local@example.invalid"))
    workspace = db.run(db.create_workspace("lab"))
    db.run(db.add_workspace_user(workspace.id, user.id))

    response = client.post(
        "/api/v1/assessments",
        headers=test_app["headers_for"](user),
        json={
            "name": "BadBlood Lab",
            "domain": "lab.local",
            "dc_ip": "192.168.56.10",
            "collection_mode": "WINDOWS_LOCAL",
            "collection_config": {"modules": ["password_hygiene"]},
        },
    )

    assert response.status_code == 201
    assert response.json()["collection_mode"] == "WINDOWS_LOCAL"


def test_delete_assessment_removes_collected_children(test_app):
    db = test_app["db"]
    client = test_app["client"]
    session_maker = test_app["session_maker"]

    user = db.run(db.create_user("deleter", "deleter@example.invalid"))
    workspace = db.run(db.create_workspace("delete-lab"))
    db.run(db.add_workspace_user(workspace.id, user.id))
    assessment = db.run(db.create_assessment("Delete Me", "delete.local", workspace_id=workspace.id, created_by=user.id))
    source = db.run(db.create_entity(assessment.id, entity_type=models.EntityType.USER, sam_account_name="alice"))
    target = db.run(db.create_entity(assessment.id, entity_type=models.EntityType.GROUP, sam_account_name="Domain Admins"))
    db.run(db.create_edge(assessment.id, source.id, target.id))
    finding = db.run(db.create_finding(assessment.id, title="Delete Finding"))

    async def _add_more_children():
        async with session_maker() as session:
            evidence = models.EvidenceRecord(
                assessment_id=assessment.id,
                source_type="ldap",
                raw_data={"ok": True},
                confidence=1.0,
                origin=models.DataOrigin.COLLECTED,
            )
            path = models.ExposurePath(
                assessment_id=assessment.id,
                source_entity_id=source.id,
                target_entity_id=target.id,
                path_steps=[],
                hop_count=1,
                path_score=1.0,
            )
            cert = models.CertTemplate(assessment_id=assessment.id, name="User")
            session.add_all([evidence, path, cert])
            await session.flush()
            session.add(models.FindingEvidence(finding_id=finding.id, evidence_id=evidence.id))
            await session.commit()

    db.run(_add_more_children())

    response = client.delete(f"/api/v1/assessments/{assessment.id}", headers=test_app["headers_for"](user))

    assert response.status_code == 204

    async def _counts():
        async with session_maker() as session:
            return {
                "assessments": await session.scalar(select(func.count(models.Assessment.id)).where(models.Assessment.id == assessment.id)),
                "entities": await session.scalar(select(func.count(models.Entity.id)).where(models.Entity.assessment_id == assessment.id)),
                "edges": await session.scalar(select(func.count(models.GraphEdge.id)).where(models.GraphEdge.assessment_id == assessment.id)),
                "findings": await session.scalar(select(func.count(models.Finding.id)).where(models.Finding.assessment_id == assessment.id)),
                "evidence": await session.scalar(select(func.count(models.EvidenceRecord.id)).where(models.EvidenceRecord.assessment_id == assessment.id)),
                "paths": await session.scalar(select(func.count(models.ExposurePath.id)).where(models.ExposurePath.assessment_id == assessment.id)),
                "certs": await session.scalar(select(func.count(models.CertTemplate.id)).where(models.CertTemplate.assessment_id == assessment.id)),
            }

    assert db.run(_counts()) == {
        "assessments": 0,
        "entities": 0,
        "edges": 0,
        "findings": 0,
        "evidence": 0,
        "paths": 0,
        "certs": 0,
    }


def test_create_assessment_auto_assigns_stable_workspace_when_multiple_accessible(test_app):
    db = test_app["db"]
    client = test_app["client"]

    user = db.run(db.create_user("multi", "multi@example.invalid"))
    workspace_one = db.run(db.create_workspace("blue"))
    workspace_two = db.run(db.create_workspace("red"))
    db.run(db.add_workspace_user(workspace_one.id, user.id))
    db.run(db.add_workspace_user(workspace_two.id, user.id))

    response = client.post(
        "/api/v1/assessments",
        headers=test_app["headers_for"](user),
        json={
            "name": "Ambiguous Assessment",
            "domain": "corp.local",
            "collection_mode": "LINUX_REMOTE",
            "collection_config": {"modules": ["directory_inventory"]},
        },
    )

    assert response.status_code == 201
    created = response.json()
    loaded = db.run(db.get_assessment(UUID(created["id"])))
    assert loaded is not None
    assert loaded.workspace_id == sorted([workspace_one.id, workspace_two.id], key=str)[0]


def test_list_accessible_workspaces_scoped_to_current_user(test_app):
    db = test_app["db"]
    client = test_app["client"]

    user = db.run(db.create_user("scoped", "scoped@example.invalid"))
    other = db.run(db.create_user("other", "other@example.invalid"))
    workspace_one = db.run(db.create_workspace("blue"))
    workspace_two = db.run(db.create_workspace("red"))
    db.run(db.add_workspace_user(workspace_one.id, user.id))
    db.run(db.add_workspace_user(workspace_two.id, other.id))

    response = client.get(
        "/api/v1/assessments/workspaces",
        headers=test_app["headers_for"](user),
    )

    assert response.status_code == 200
    payload = response.json()
    assert [item["name"] for item in payload] == ["blue"]


def test_viewer_cannot_modify_findings(test_app):
    db = test_app["db"]
    client = test_app["client"]

    viewer = db.run(db.create_user("viewer", "viewer@example.invalid"))
    creator = db.run(db.create_user("creator", "creator@example.invalid"))
    workspace = db.run(db.create_workspace("ops"))
    db.run(db.add_workspace_user(workspace.id, viewer.id, role="viewer"))
    db.run(db.add_workspace_user(workspace.id, creator.id, role="admin"))
    assessment = db.run(db.create_assessment("Scoped", "corp.local", workspace_id=workspace.id, created_by=creator.id))
    finding = db.run(db.create_finding(assessment.id, title="Viewer Block Test"))

    response = client.patch(
        f"/api/v1/findings/{finding.id}",
        headers=test_app["headers_for"](viewer),
        json={"status": FindingStatus.IN_REVIEW.value},
    )

    assert response.status_code == 403


def test_expired_access_token_is_rejected_even_when_user_cache_is_primed(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(
        db.create_user(
            "expired-cache",
            "expired-cache@example.invalid",
        )
    )

    expired_token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "type": "access",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
        },
        auth_routes.settings.SECRET_KEY,
        algorithm=auth_routes.settings.ALGORITHM,
    )

    cache_key = auth_routes._token_cache_key(expired_token)
    auth_routes._user_cache[cache_key] = (
        auth_routes.time.monotonic(),
        user.id,
    )

    try:
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
    finally:
        auth_routes._user_cache.pop(cache_key, None)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid access token"


def test_token_invalid_after_logout(test_app):
    """A token used after logout must return 401."""
    db = test_app["db"]
    client = test_app["client"]

    db.run(db.create_user("logout_user", "logout_user@test.com"))
    login_resp = client.post("/api/v1/auth/login", json={"username": "logout_user", "password": "password123!"})
    assert login_resp.status_code == 200
    token = login_resp.cookies.get("adbygod_session")

    # Confirm token works before logout
    me_resp = client.get("/api/v1/auth/me", cookies={"adbygod_session": token})
    assert me_resp.status_code == 200

    # Logout with the token
    logout_resp = client.post(
        "/api/v1/auth/logout",
        cookies={"adbygod_session": token},
        headers={"x-requested-with": "XMLHttpRequest"},
    )
    assert logout_resp.status_code == 200

    # Old token must now be rejected
    me_after = client.get("/api/v1/auth/me", cookies={"adbygod_session": token})
    assert me_after.status_code == 401


def test_new_token_works_after_logout(test_app):
    """A new login after logout must succeed and the new session must be usable."""
    db = test_app["db"]
    client = test_app["client"]

    db.run(db.create_user("logout_relogin", "logout_relogin@test.com"))

    login1 = client.post("/api/v1/auth/login", json={"username": "logout_relogin", "password": "password123!"})
    assert login1.status_code == 200
    token1 = login1.cookies.get("adbygod_session")

    client.post(
        "/api/v1/auth/logout",
        cookies={"adbygod_session": token1},
        headers={"x-requested-with": "XMLHttpRequest"},
    )

    # Verify old token is now rejected
    me_old = client.get("/api/v1/auth/me", cookies={"adbygod_session": token1})
    assert me_old.status_code == 401

    login2 = client.post("/api/v1/auth/login", json={"username": "logout_relogin", "password": "password123!"})
    assert login2.status_code == 200
    token2 = login2.cookies.get("adbygod_session")

    me = client.get("/api/v1/auth/me", cookies={"adbygod_session": token2})
    assert me.status_code == 200
