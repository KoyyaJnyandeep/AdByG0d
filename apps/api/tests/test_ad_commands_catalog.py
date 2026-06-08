from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from adbygod_api.routes import ad_commands as adcmd_routes
from adbygod_api.routes import jobs as job_routes


def test_ad_command_catalog_requires_authentication(test_app):
    response = test_app["client"].get("/api/v1/ad-commands/categories")
    assert response.status_code == 401


def test_ad_command_tool_inventory_requires_superadmin(test_app):
    db = test_app["db"]
    user = db.run(db.create_user("tool-regular", "tool-regular@example.invalid", is_superadmin=False))
    admin = db.run(db.create_user("tool-admin", "tool-admin@example.invalid", is_superadmin=True))

    denied = test_app["client"].get("/api/v1/ad-commands/tools/available", headers=test_app["headers_for"](user))
    allowed = test_app["client"].get("/api/v1/ad-commands/tools/available", headers=test_app["headers_for"](admin))

    assert denied.status_code == 403
    assert allowed.status_code == 200


def test_ad_command_execute_rejects_oversized_params(test_app, monkeypatch):
    monkeypatch.setattr(adcmd_routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(adcmd_routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    monkeypatch.setattr(
        adcmd_routes,
        "AD_COMMANDS",
        [
            {
                "id": "linux-tech",
                "category": "Test",
                "title": "Linux",
                "tool": "echo",
                "platform": "linux",
                "executable_on_linux": True,
                "description": "",
                "commands": [{"label": "Echo", "command": "echo {Value}", "params": ["Value"]}],
            }
        ],
    )
    admin = test_app["db"].run(test_app["db"].create_user("param-admin", "param-admin@example.invalid", is_superadmin=True))

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=test_app["headers_for"](admin),
        json={"command_index": 0, "params": {"Value": "x" * 5000}},
    )

    assert response.status_code == 422


def test_ad_command_execute_truncates_large_output(test_app, monkeypatch):
    # Execution now goes through services/command_execution.py — patch asyncio there.
    import adbygod_api.services.command_execution as cmd_svc

    _FAKE_TECHNIQUE = [
        {
            "id": "linux-tech",
            "category": "Test",
            "title": "Linux",
            "tool": "echo",
            "platform": "linux",
            "executable_on_linux": True,
            "description": "",
            "commands": [{"label": "Echo", "command": "echo ok", "params": []}],
        }
    ]

    class FakeProc:
        returncode = 0

        async def communicate(self):
            # Return more bytes than the service's _STDOUT_CAP so we can verify capping.
            return (b"A" * (cmd_svc._STDOUT_CAP + 1000)), b""

    async def fake_exec(*argv, stdout=None, stderr=None):
        return FakeProc()

    monkeypatch.setattr(adcmd_routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(adcmd_routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "linux-tech")
    # Route uses its own AD_COMMANDS for technique lookup before delegating to service.
    monkeypatch.setattr(adcmd_routes, "AD_COMMANDS", _FAKE_TECHNIQUE)
    # Service uses its own AD_COMMANDS + asyncio + shutil for actual execution.
    monkeypatch.setattr(cmd_svc, "AD_COMMANDS", _FAKE_TECHNIQUE)
    monkeypatch.setattr(cmd_svc.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(cmd_svc.shutil, "which", lambda binary: f"/usr/bin/{binary}")
    # Route calls shutil.which via _resolve_executable — also patch there.
    monkeypatch.setattr(adcmd_routes.shutil, "which", lambda binary: f"/usr/bin/{binary}")

    admin = test_app["db"].run(test_app["db"].create_user("output-admin", "output-admin@example.invalid", is_superadmin=True))

    response = test_app["client"].post(
        "/api/v1/ad-commands/execute/linux-tech",
        headers=test_app["headers_for"](admin),
        json={"command_index": 0, "params": {}},
    )

    assert response.status_code == 200, f"Unexpected {response.status_code}: {response.text}"
    # Output must be capped at the service's _STDOUT_CAP limit.
    stdout = response.json()["stdout"]
    assert len(stdout) <= cmd_svc._STDOUT_CAP, f"stdout not capped: got {len(stdout)} chars"


def test_login_rejects_oversized_identifier_before_rate_limit_key_growth(test_app):
    response = test_app["client"].post(
        "/api/v1/auth/login",
        json={"username": "u" * 300, "password": "password123!"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Username or email too long"


def test_search_and_findings_reject_oversized_search_terms(test_app):
    user = test_app["db"].run(test_app["db"].create_user("search-limit", "search-limit@example.invalid"))
    headers = test_app["headers_for"](user)

    search = test_app["client"].get("/api/v1/search", headers=headers, params={"q": "x" * 200})
    findings = test_app["client"].get("/api/v1/findings", headers=headers, params={"search": "x" * 200})

    assert search.status_code == 422
    assert findings.status_code == 422


def test_user_profile_rejects_oversized_full_name(test_app):
    user = test_app["db"].run(test_app["db"].create_user("profile-limit", "profile-limit@example.invalid"))
    response = test_app["client"].patch(
        f"/api/v1/users/{user.id}",
        headers=test_app["headers_for"](user),
        json={"full_name": "x" * 500},
    )
    assert response.status_code == 422


def test_active_job_gc_uses_last_event_activity_not_creation_age():
    owner_id = UUID("00000000-0000-0000-0000-000000000444")
    record = job_routes.create_job("job-still-active", owner_id)
    record.created_at = datetime.now(timezone.utc) - timedelta(seconds=job_routes._JOB_ACTIVE_TTL_SECONDS + 60)
    record.last_event_at = datetime.now(timezone.utc)

    job_routes._gc_stale_jobs()

    assert job_routes.get_job("job-still-active") is record
