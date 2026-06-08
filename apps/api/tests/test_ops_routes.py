import pytest
from httpx import AsyncClient, ASGITransport
from adbygod_api.main import app


@pytest.mark.asyncio
async def test_ops_execute_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/api/v1/ops/execute", json={
            "technique_id": "kerberoast",
            "target": "10.0.0.1",
            "params": {"domain": "lab.local", "username": "user", "password": "pass"},
        })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ops_jobs_list_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/api/v1/ops/jobs")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ops_kill_requires_auth():
    import uuid
    jid = str(uuid.uuid4())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete(f"/api/v1/ops/jobs/{jid}")
    assert resp.status_code == 401


def _post_ops_execute(test_app, user):
    return test_app["client"].post(
        "/api/v1/ops/execute",
        headers=test_app["headers_for"](user),
        json={
            "technique_id": "kerberoast",
            "target": "10.0.0.1",
            "params": {"domain": "lab.local", "username": "user", "password": "pass"},
        },
    )


def test_ops_execute_requires_superadmin(test_app):
    user = test_app["db"].run(
        test_app["db"].create_user(
            "ops-regular-user",
            "ops-regular-user@example.test",
            is_superadmin=False,
        )
    )

    response = _post_ops_execute(test_app, user)

    assert response.status_code == 403
    assert response.json()["detail"] == "Superadmin access required"


def test_ops_execute_respects_global_kill_switch(test_app):
    user = test_app["db"].run(
        test_app["db"].create_user(
            "ops-disabled-admin",
            "ops-disabled-admin@example.test",
            is_superadmin=True,
        )
    )

    response = _post_ops_execute(test_app, user)

    assert response.status_code == 403
    assert response.json()["detail"] == "Command execution is disabled by default"


def test_ops_execute_requires_allowlisted_technique(test_app, monkeypatch):
    from adbygod_api.routes import ops as ops_routes

    monkeypatch.setattr(ops_routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(ops_routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "")

    user = test_app["db"].run(
        test_app["db"].create_user(
            "ops-allowlist-admin",
            "ops-allowlist-admin@example.test",
            is_superadmin=True,
        )
    )

    response = _post_ops_execute(test_app, user)

    assert response.status_code == 403
    assert response.json()["detail"] == "Technique is not allowlisted for execution"



def test_ops_execute_rejects_unknown_assessment_context(test_app, monkeypatch):
    import uuid
    from adbygod_api.routes import ops as ops_routes

    monkeypatch.setattr(ops_routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(ops_routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "kerberoast")

    admin = test_app["db"].run(
        test_app["db"].create_user(
            "ops-assessment-admin",
            "ops-assessment-admin@example.test",
            is_superadmin=True,
        )
    )

    response = test_app["client"].post(
        "/api/v1/ops/execute",
        headers=test_app["headers_for"](admin),
        json={
            "technique_id": "kerberoast",
            "target": "10.0.0.1",
            "assessment_id": str(uuid.uuid4()),
            "params": {"domain": "lab.local", "username": "user", "password": "pass"},
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Assessment not found"
