from __future__ import annotations

from adbygod_api.core.arsenal.cve_database import CVE_DATABASE
from adbygod_api.routes import arsenal as arsenal_routes


def _make_user(test_app, username: str, *, is_superadmin: bool = False):
    return test_app["db"].run(
        test_app["db"].create_user(
            username,
            f"{username}@example.test",
            is_superadmin=is_superadmin,
        )
    )


def _assessment_pair(test_app):
    db = test_app["db"]
    owner = _make_user(test_app, "arsenal-owner")
    outsider = _make_user(test_app, "arsenal-outsider")
    owner_ws = db.run(db.create_workspace("Arsenal Owner Workspace"))
    outsider_ws = db.run(db.create_workspace("Arsenal Outsider Workspace"))
    db.run(db.add_workspace_user(owner_ws.id, owner.id, role="analyst"))
    db.run(db.add_workspace_user(outsider_ws.id, outsider.id, role="analyst"))
    owner_assessment = db.run(
        db.create_assessment(
            "Owner Assessment",
            "owner.lab",
            workspace_id=owner_ws.id,
            created_by=owner.id,
        )
    )
    outsider_assessment = db.run(
        db.create_assessment(
            "Outsider Assessment",
            "outsider.lab",
            workspace_id=outsider_ws.id,
            created_by=outsider.id,
        )
    )
    return owner, outsider, owner_assessment, outsider_assessment


def test_arsenal_assessments_list_is_workspace_scoped(test_app):
    owner, _outsider, owner_assessment, outsider_assessment = _assessment_pair(test_app)

    response = test_app["client"].get(
        "/api/v1/arsenal/assessments-list",
        headers=test_app["headers_for"](owner),
    )

    assert response.status_code == 200
    ids = {row["id"] for row in response.json()}
    assert str(owner_assessment.id) in ids
    assert str(outsider_assessment.id) not in ids


def test_arsenal_target_from_assessment_rejects_cross_workspace_access(test_app):
    owner, outsider, owner_assessment, _outsider_assessment = _assessment_pair(test_app)

    denied = test_app["client"].get(
        f"/api/v1/arsenal/target-from-assessment/{owner_assessment.id}",
        headers=test_app["headers_for"](outsider),
    )
    allowed = test_app["client"].get(
        f"/api/v1/arsenal/target-from-assessment/{owner_assessment.id}",
        headers=test_app["headers_for"](owner),
    )

    assert denied.status_code == 403
    assert denied.json()["detail"] == "Workspace access denied"
    assert allowed.status_code == 200
    assert allowed.json()["domain"] == "owner.lab"


def test_arsenal_check_requires_superadmin(test_app):
    user = _make_user(test_app, "arsenal-regular")
    response = test_app["client"].post(
        "/api/v1/arsenal/check",
        headers=test_app["headers_for"](user),
        json={"cve_id": CVE_DATABASE[0]["id"], "params": {}},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Superadmin access required"


def test_arsenal_check_respects_global_kill_switch(test_app):
    admin = _make_user(test_app, "arsenal-admin-disabled", is_superadmin=True)
    response = test_app["client"].post(
        "/api/v1/arsenal/check",
        headers=test_app["headers_for"](admin),
        json={"cve_id": CVE_DATABASE[0]["id"], "params": {}},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Command execution is disabled by default"


def test_arsenal_check_requires_allowlisted_technique(test_app, monkeypatch):
    admin = _make_user(test_app, "arsenal-admin-allowlist", is_superadmin=True)
    monkeypatch.setattr(arsenal_routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(arsenal_routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "")

    response = test_app["client"].post(
        "/api/v1/arsenal/check",
        headers=test_app["headers_for"](admin),
        json={"cve_id": CVE_DATABASE[0]["id"], "params": {}},
    )

    assert response.status_code == 403
    assert "not allowlisted" in response.json()["detail"]


def test_arsenal_job_status_is_owner_scoped(test_app):
    owner = _make_user(test_app, "arsenal-job-owner")
    outsider = _make_user(test_app, "arsenal-job-outsider")
    job_id = "arsenal-owned-job"
    arsenal_routes._runs[job_id] = {
        "status": "RUNNING",
        "results": [],
        "owner_user_id": owner.id,
    }
    try:
        denied = test_app["client"].get(
            f"/api/v1/arsenal/jobs/{job_id}",
            headers=test_app["headers_for"](outsider),
        )
        allowed = test_app["client"].get(
            f"/api/v1/arsenal/jobs/{job_id}",
            headers=test_app["headers_for"](owner),
        )
    finally:
        arsenal_routes._runs.pop(job_id, None)

    assert denied.status_code == 403
    assert denied.json()["detail"] == "Arsenal job access denied"
    assert allowed.status_code == 200
