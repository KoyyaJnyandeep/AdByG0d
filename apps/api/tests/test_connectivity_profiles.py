from __future__ import annotations

import asyncio
from uuid import UUID

import pytest

from adbygod_api import models
from adbygod_api.core.connectivity.transport import resolve_transport
from adbygod_api.routes import ops as ops_routes


def _create_direct_profile(test_app, user, *, name: str = "Owned Direct") -> dict:
    response = test_app["client"].post(
        "/api/v1/connectivity/profiles",
        headers=test_app["headers_for"](user),
        json={
            "name": name,
            "mode": "DIRECT",
            "config": {
                "dc_ip": "192.168.56.10",
                "dc_hostname": "dc01.lab.local",
                "target_subnets": ["192.168.56.0/24"],
            },
        },
    )
    assert response.status_code == 201
    return response.json()


def _chain_payload(assessment_id: UUID) -> dict:
    return {
        "assessment_id": str(assessment_id),
        "target": "192.168.56.10",
        "domain": "lab.local",
        "username": "scanner@lab.local",
        "password": "secret",
        "dc_ip": "192.168.56.10",
        "situation": "DOMAIN_USER",
    }


def test_connectivity_profiles_are_owner_scoped_for_non_superadmins(test_app):
    db = test_app["db"]
    client = test_app["client"]
    owner = db.run(db.create_user("profile-owner", "profile-owner@example.invalid"))
    outsider = db.run(db.create_user("profile-outsider", "profile-outsider@example.invalid"))

    profile = _create_direct_profile(test_app, owner)
    outsider_headers = test_app["headers_for"](outsider)

    listed = client.get("/api/v1/connectivity/profiles", headers=outsider_headers)
    fetched = client.get(f"/api/v1/connectivity/profiles/{profile['id']}", headers=outsider_headers)
    updated = client.patch(
        f"/api/v1/connectivity/profiles/{profile['id']}",
        headers=outsider_headers,
        json={"name": "hijacked"},
    )
    tested = client.post(
        f"/api/v1/connectivity/profiles/{profile['id']}/test",
        headers=outsider_headers,
        json={"target_host": "192.168.56.10"},
    )
    deleted = client.delete(f"/api/v1/connectivity/profiles/{profile['id']}", headers=outsider_headers)

    assert listed.status_code == 200
    assert listed.json() == []
    assert fetched.status_code == 403
    assert updated.status_code == 403
    assert tested.status_code == 403
    assert deleted.status_code == 403


def test_assessment_cannot_attach_another_users_connectivity_profile(test_app):
    db = test_app["db"]
    client = test_app["client"]
    owner = db.run(db.create_user("profile-attach-owner", "profile-attach-owner@example.invalid"))
    creator = db.run(db.create_user("assessment-profile-creator", "assessment-profile-creator@example.invalid"))
    workspace = db.run(db.create_workspace("profile attach scope"))
    db.run(db.add_workspace_user(workspace.id, creator.id, role="analyst"))

    profile = _create_direct_profile(test_app, owner, name="Owner Only")

    response = client.post(
        "/api/v1/assessments",
        headers=test_app["headers_for"](creator),
        json={
            "name": "Should Not Attach",
            "domain": "lab.local",
            "workspace_id": str(workspace.id),
            "connectivity_profile_id": profile["id"],
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Connectivity profile access denied"


def test_connectivity_profile_delete_is_blocked_while_assessments_reference_it(test_app):
    db = test_app["db"]
    client = test_app["client"]
    owner = db.run(db.create_user("profile-in-use-owner", "profile-in-use-owner@example.invalid"))
    workspace = db.run(db.create_workspace("profile in use"))
    db.run(db.add_workspace_user(workspace.id, owner.id, role="analyst"))
    profile = _create_direct_profile(test_app, owner, name="In Use")

    created = client.post(
        "/api/v1/assessments",
        headers=test_app["headers_for"](owner),
        json={
            "name": "Uses Connectivity",
            "domain": "lab.local",
            "workspace_id": str(workspace.id),
            "connectivity_profile_id": profile["id"],
        },
    )
    deleted = client.delete(
        f"/api/v1/connectivity/profiles/{profile['id']}",
        headers=test_app["headers_for"](owner),
    )

    assert created.status_code == 201
    assert deleted.status_code == 409
    assert "linked to" in deleted.json()["detail"]


def test_workspace_viewer_cannot_persist_chains_or_recompute_paths(test_app):
    db = test_app["db"]
    client = test_app["client"]
    viewer = db.run(db.create_user("chain-graph-viewer", "chain-graph-viewer@example.invalid"))
    admin = db.run(db.create_user("chain-graph-admin", "chain-graph-admin@example.invalid"))
    workspace = db.run(db.create_workspace("viewer readonly"))
    db.run(db.add_workspace_user(workspace.id, viewer.id, role="viewer"))
    db.run(db.add_workspace_user(workspace.id, admin.id, role="admin"))
    assessment = db.run(
        db.create_assessment(
            "Read Only Assessment",
            "lab.local",
            workspace_id=workspace.id,
            created_by=admin.id,
        )
    )

    headers = test_app["headers_for"](viewer)
    chain = client.post("/api/v1/chains", headers=headers, json=_chain_payload(assessment.id))
    paths = client.post(f"/api/v1/graph/{assessment.id}/compute-paths", headers=headers)

    assert chain.status_code == 403
    assert paths.status_code == 403


def test_managed_ssh_transport_without_live_tunnel_fails_closed(test_app):
    db = test_app["db"]

    owner = db.run(db.create_user("managed-transport-owner", "managed-transport-owner@example.invalid"))

    async def _resolve_without_session() -> None:
        async with test_app["session_maker"]() as session:
            profile = models.ConnectivityProfile(
                name="Managed Pivot",
                mode=models.ConnectivityMode.MANAGED_SSH_SOCKS,
                config={
                    "jumpbox_host": "jumpbox.lab.local",
                    "jumpbox_port": 22,
                    "jumpbox_username": "pivot",
                },
                created_by=owner.id,
            )
            session.add(profile)
            await session.commit()
            await session.refresh(profile)
            with pytest.raises(RuntimeError, match="no active session"):
                await resolve_transport(profile, session)

    asyncio.run(_resolve_without_session())


def test_ops_execute_rejects_unavailable_managed_tunnel_before_queueing(test_app, monkeypatch):
    db = test_app["db"]
    client = test_app["client"]
    admin = db.run(db.create_user("ops-managed-admin", "ops-managed-admin@example.invalid", is_superadmin=True))
    workspace = db.run(db.create_workspace("ops managed tunnel"))
    db.run(db.add_workspace_user(workspace.id, admin.id, role="admin"))

    async def _insert_assessment_with_profile():
        async with test_app["session_maker"]() as session:
            profile = models.ConnectivityProfile(
                name="Managed Pivot",
                mode=models.ConnectivityMode.MANAGED_SSH_SOCKS,
                config={
                    "jumpbox_host": "jumpbox.lab.local",
                    "jumpbox_port": 22,
                    "jumpbox_username": "pivot",
                },
                created_by=admin.id,
            )
            session.add(profile)
            await session.flush()
            assessment = models.Assessment(
                workspace_id=workspace.id,
                name="Managed Tunnel Assessment",
                domain="lab.local",
                dc_ip="192.168.56.10",
                connectivity_profile_id=profile.id,
                created_by=admin.id,
                status=models.AssessmentStatus.PENDING,
                modules_run=[],
                stats={},
                exposure_score=0.0,
            )
            session.add(assessment)
            await session.commit()
            await session.refresh(assessment)
            return assessment

    assessment = asyncio.run(_insert_assessment_with_profile())
    monkeypatch.setattr(ops_routes.settings, "ENABLE_COMMAND_EXECUTION", True)
    monkeypatch.setattr(ops_routes.settings, "COMMAND_EXECUTION_ALLOWLIST", "kerberoast")

    response = client.post(
        "/api/v1/ops/execute",
        headers=test_app["headers_for"](admin),
        json={
            "technique_id": "kerberoast",
            "target": "192.168.56.10",
            "assessment_id": str(assessment.id),
            "params": {"domain": "lab.local", "username": "scanner", "password": "secret"},
        },
    )

    assert response.status_code == 409
    assert "Connectivity transport unavailable" in response.json()["detail"]
