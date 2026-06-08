"""Authorization matrix tests for industry-grade route scoping.

Proves:
1. User A cannot read user B's assessment via AI target-card (assessment-access gate).
2. Recon list returns empty for user with no workspace access (not all scans).
3. Kill chain read is scoped to assessment access.
4. AI shell command blocked for normal user (superadmin + flag required).
5. AI execute_technique blocked when ENABLE_COMMAND_EXECUTION=False.
"""
from __future__ import annotations

import asyncio
import uuid


import adbygod_api.config as config
import adbygod_api.models as models


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _login(client, username: str, password: str = "password123!") -> dict[str, str]:
    """Return Authorization header dict for the given user credentials."""
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, f"Login failed for {username!r}: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. User A cannot read user B's assessment via AI target-card
# ---------------------------------------------------------------------------

def test_target_card_cross_user_blocked(test_app):
    """User B must not access user A's assessment target-card."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    # Create two workspaces, one user per workspace, and one assessment each.
    user_a = db.run(db.create_user("user_a_tc", "a_tc@test.local"))
    user_b = db.run(db.create_user("user_b_tc", "b_tc@test.local"))

    ws_a = db.run(db.create_workspace("ws_a_tc"))
    db.run(db.add_workspace_user(ws_a.id, user_a.id))

    assessment_a = db.run(
        db.create_assessment("Assess A", "a.local", workspace_id=ws_a.id, created_by=user_a.id)
    )

    # User B has no workspace membership at all.
    headers_b = headers_for(user_b)
    resp = client.get(f"/api/v1/ai-operator/target-card/{assessment_a.id}", headers=headers_b)

    # Must be 403 or 404 — never 200.
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 but got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# 2. Recon list returns empty for user with no workspace access
# ---------------------------------------------------------------------------

def test_recon_list_scoped_to_workspace(test_app, monkeypatch):
    """A user with no workspace membership sees an empty recon scan list."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    session_maker = test_app["session_maker"]

    # Patch the recon route module so it uses the in-memory test DB.
    from adbygod_api.routes import recon as recon_routes
    monkeypatch.setattr(recon_routes, "AsyncSessionLocal", session_maker)

    # Create a superadmin who owns all the scans.
    admin = db.run(db.create_user("admin_recon", "admin_recon@test.local", is_superadmin=True))

    ws = db.run(db.create_workspace("ws_recon"))
    db.run(db.add_workspace_user(ws.id, admin.id))

    assessment = db.run(
        db.create_assessment("Recon Assess", "recon.local", workspace_id=ws.id, created_by=admin.id)
    )

    # Directly insert a ReconScan tied to this assessment.
    async def _insert_scan():
        async with session_maker() as sess:
            scan = models.ReconScan(
                id=uuid.uuid4(),
                assessment_id=assessment.id,
                status=models.ReconScanStatus.COMPLETED,
                target_dc_ip="10.0.0.1",
                domain="recon.local",
                findings=[],
                summary={},
            )
            sess.add(scan)
            await sess.commit()

    asyncio.run(_insert_scan())

    # Create a plain user with NO workspace access.
    user_isolated = db.run(db.create_user("user_isolated_recon", "isolated_recon@test.local"))
    headers_isolated = headers_for(user_isolated)

    resp = client.get("/api/v1/recon/scans", headers=headers_isolated)
    assert resp.status_code == 200, f"Expected 200 but got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data == [], (
        f"Expected empty list for isolated user, got {len(data)} item(s)"
    )


# ---------------------------------------------------------------------------
# 3. Kill chain read is scoped to assessment access
# ---------------------------------------------------------------------------

def test_kill_chain_cross_assessment_blocked(test_app):
    """User with no workspace access cannot read kill chain for another user's assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    owner = db.run(db.create_user("kc_owner", "kc_owner@test.local"))
    ws = db.run(db.create_workspace("ws_kc"))
    db.run(db.add_workspace_user(ws.id, owner.id))
    assessment = db.run(
        db.create_assessment("KC Assess", "kc.local", workspace_id=ws.id, created_by=owner.id)
    )

    # Intruder has no workspace access.
    intruder = db.run(db.create_user("kc_intruder", "kc_intruder@test.local"))
    headers_intruder = headers_for(intruder)

    resp = client.get(
        f"/api/v1/kill-chain?assessment_id={assessment.id}",
        headers=headers_intruder,
    )
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for kill chain cross-access but got {resp.status_code}: {resp.text}"
    )


def test_kill_chain_accessible_to_workspace_member(test_app):
    """Workspace member CAN read kill chain for their own assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    member = db.run(db.create_user("kc_member", "kc_member@test.local"))
    ws = db.run(db.create_workspace("ws_kc_member"))
    db.run(db.add_workspace_user(ws.id, member.id))
    assessment = db.run(
        db.create_assessment("KC Member Assess", "kcm.local", workspace_id=ws.id, created_by=member.id)
    )

    headers = headers_for(member)
    resp = client.get(
        f"/api/v1/kill-chain?assessment_id={assessment.id}",
        headers=headers,
    )
    assert resp.status_code == 200, f"Expected 200 but got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# 4. AI shell command blocked for normal user (requires superadmin)
# ---------------------------------------------------------------------------

def test_ai_execute_blocked_for_normal_user(test_app):
    """Normal (non-superadmin) user is blocked from /ops/execute even with valid data."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    # Temporarily enable command execution so the flag is not the blocker.
    original = config.settings.ENABLE_COMMAND_EXECUTION
    config.settings.ENABLE_COMMAND_EXECUTION = True
    try:
        normal_user = db.run(db.create_user("normal_exec_user", "normal_exec@test.local"))
        headers = headers_for(normal_user)

        resp = client.post(
            "/api/v1/ops/execute",
            json={"technique_id": "kerberoast", "target": "dc01.test.local"},
            headers=headers,
        )
        # Must be rejected: superadmin required.
        assert resp.status_code == 403, (
            f"Expected 403 (superadmin required) but got {resp.status_code}: {resp.text}"
        )
    finally:
        config.settings.ENABLE_COMMAND_EXECUTION = original


# ---------------------------------------------------------------------------
# 5. execute_technique blocked when ENABLE_COMMAND_EXECUTION=False
# ---------------------------------------------------------------------------

def test_execute_technique_blocked_when_flag_disabled(test_app):
    """Even superadmin cannot execute when ENABLE_COMMAND_EXECUTION=False."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    # Ensure the flag is disabled (it's False in conftest, make explicit).
    config.settings.ENABLE_COMMAND_EXECUTION = False

    superadmin = db.run(
        db.create_user("sa_exec_flag", "sa_exec_flag@test.local", is_superadmin=True)
    )
    headers = headers_for(superadmin)

    resp = client.post(
        "/api/v1/ops/execute",
        json={"technique_id": "kerberoast", "target": "dc01.test.local"},
        headers=headers,
    )
    assert resp.status_code == 403, (
        f"Expected 403 (flag disabled) but got {resp.status_code}: {resp.text}"
    )
    body = resp.json()
    assert "disabled" in body.get("detail", "").lower(), (
        f"Expected 'disabled' in error detail, got: {body}"
    )


# ---------------------------------------------------------------------------
# 6. Cross-user finding access denied
# ---------------------------------------------------------------------------

def test_finding_cross_user_denied(test_app):
    """User B cannot read a finding belonging to user A's assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    user_a = db.run(db.create_user("find_alice", "find_alice@test.local"))
    user_b = db.run(db.create_user("find_bob", "find_bob@test.local"))

    ws_a = db.run(db.create_workspace("ws_find_a"))
    ws_b = db.run(db.create_workspace("ws_find_b"))
    db.run(db.add_workspace_user(ws_a.id, user_a.id))
    db.run(db.add_workspace_user(ws_b.id, user_b.id))

    assessment_a = db.run(
        db.create_assessment("Find Alpha", "fa.local", workspace_id=ws_a.id, created_by=user_a.id)
    )
    finding_a = db.run(
        db.create_finding(assessment_a.id, title="Test Finding Alpha")
    )

    # User B tries to read user A's finding by ID.
    resp = client.get(f"/api/v1/findings/{finding_a.id}", headers=headers_for(user_b))
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for cross-user finding GET, got {resp.status_code}: {resp.text}"
    )


def test_finding_list_cross_user_empty(test_app):
    """User B gets an empty list when requesting findings for user A's assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    user_a = db.run(db.create_user("fl_alice", "fl_alice@test.local"))
    user_b = db.run(db.create_user("fl_bob", "fl_bob@test.local"))

    ws_a = db.run(db.create_workspace("ws_fl_a"))
    ws_b = db.run(db.create_workspace("ws_fl_b"))
    db.run(db.add_workspace_user(ws_a.id, user_a.id))
    db.run(db.add_workspace_user(ws_b.id, user_b.id))

    assessment_a = db.run(
        db.create_assessment("FL Alpha", "fla.local", workspace_id=ws_a.id, created_by=user_a.id)
    )
    db.run(db.create_finding(assessment_a.id, title="Secret Finding"))

    # User B explicitly requests user A's assessment findings — must be denied.
    resp = client.get(
        f"/api/v1/findings?assessment_id={assessment_a.id}",
        headers=headers_for(user_b),
    )
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for cross-user findings list, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# 7. Cross-user report access denied
# ---------------------------------------------------------------------------

def test_report_preview_cross_user_denied(test_app):
    """User B cannot preview a report for user A's assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    user_a = db.run(db.create_user("rpt_alice", "rpt_alice@test.local"))
    user_b = db.run(db.create_user("rpt_bob", "rpt_bob@test.local"))

    ws_a = db.run(db.create_workspace("ws_rpt_a"))
    ws_b = db.run(db.create_workspace("ws_rpt_b"))
    db.run(db.add_workspace_user(ws_a.id, user_a.id))
    db.run(db.add_workspace_user(ws_b.id, user_b.id))

    assessment_a = db.run(
        db.create_assessment("Rpt Alpha", "rpta.local", workspace_id=ws_a.id, created_by=user_a.id)
    )

    resp = client.get(
        f"/api/v1/reports/preview/{assessment_a.id}",
        headers=headers_for(user_b),
    )
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for cross-user report preview, got {resp.status_code}: {resp.text}"
    )


def test_report_export_cross_user_denied(test_app):
    """User B cannot export a report for user A's assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    user_a = db.run(db.create_user("rex_alice", "rex_alice@test.local"))
    user_b = db.run(db.create_user("rex_bob", "rex_bob@test.local"))

    ws_a = db.run(db.create_workspace("ws_rex_a"))
    ws_b = db.run(db.create_workspace("ws_rex_b"))
    db.run(db.add_workspace_user(ws_a.id, user_a.id))
    db.run(db.add_workspace_user(ws_b.id, user_b.id))

    assessment_a = db.run(
        db.create_assessment("Rex Alpha", "rexa.local", workspace_id=ws_a.id, created_by=user_a.id)
    )

    resp = client.post(
        "/api/v1/reports/export",
        json={"assessment_id": str(assessment_a.id), "format": "json"},
        headers=headers_for(user_b),
    )
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for cross-user report export, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# 8. Cross-user AI memory access denied
# ---------------------------------------------------------------------------

def test_ai_memory_cross_user_denied(test_app):
    """User B cannot read AI memory for user A's assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    user_a = db.run(db.create_user("mem2_alice", "mem2_alice@test.local"))
    user_b = db.run(db.create_user("mem2_bob", "mem2_bob@test.local"))

    ws_a = db.run(db.create_workspace("ws_mem2_a"))
    ws_b = db.run(db.create_workspace("ws_mem2_b"))
    db.run(db.add_workspace_user(ws_a.id, user_a.id))
    db.run(db.add_workspace_user(ws_b.id, user_b.id))

    assessment_a = db.run(
        db.create_assessment("Mem2 Alpha", "mem2a.local", workspace_id=ws_a.id, created_by=user_a.id)
    )

    resp = client.get(
        f"/api/v1/ai-operator/memory/{assessment_a.id}",
        headers=headers_for(user_b),
    )
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for cross-user AI memory access, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# 9. Cross-user recon scan read denied (single scan by ID)
# ---------------------------------------------------------------------------

def test_recon_scan_get_cross_user_denied(test_app, monkeypatch):
    """User B cannot read a specific recon scan that belongs to user A's assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]
    session_maker = test_app["session_maker"]

    from adbygod_api.routes import recon as recon_routes
    monkeypatch.setattr(recon_routes, "AsyncSessionLocal", session_maker)

    user_a = db.run(db.create_user("rscan_alice", "rscan_alice@test.local"))
    user_b = db.run(db.create_user("rscan_bob", "rscan_bob@test.local"))

    ws_a = db.run(db.create_workspace("ws_rscan_a"))
    ws_b = db.run(db.create_workspace("ws_rscan_b"))
    db.run(db.add_workspace_user(ws_a.id, user_a.id))
    db.run(db.add_workspace_user(ws_b.id, user_b.id))

    assessment_a = db.run(
        db.create_assessment("RScan Alpha", "rscana.local", workspace_id=ws_a.id, created_by=user_a.id)
    )

    # Insert a scan owned by user_a's assessment.
    scan_id = uuid.uuid4()

    async def _insert():
        async with session_maker() as sess:
            scan = models.ReconScan(
                id=scan_id,
                assessment_id=assessment_a.id,
                status=models.ReconScanStatus.COMPLETED,
                target_dc_ip="10.0.0.5",
                domain="rscana.local",
                findings=[],
                summary={},
            )
            sess.add(scan)
            await sess.commit()

    asyncio.run(_insert())

    # User B tries to read the scan by ID — must be denied.
    resp = client.get(f"/api/v1/recon/scan/{scan_id}", headers=headers_for(user_b))
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for cross-user recon scan GET, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# 10. Cross-user job event/status denied
# ---------------------------------------------------------------------------

def test_job_status_cross_user_denied(test_app):
    """User B cannot poll status of a job owned by user A."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    from adbygod_api.routes import jobs as jobs_routes

    user_a = db.run(db.create_user("job_alice", "job_alice@test.local"))
    user_b = db.run(db.create_user("job_bob", "job_bob@test.local"))

    job_id = str(uuid.uuid4())
    jobs_routes.create_job(job_id, owner_user_id=user_a.id)

    resp = client.get(f"/api/v1/jobs/status/{job_id}", headers=headers_for(user_b))
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for cross-user job status poll, got {resp.status_code}: {resp.text}"
    )

    # Cleanup
    jobs_routes.remove_job(job_id)


# ---------------------------------------------------------------------------
# 11. Cross-user loot access denied
# ---------------------------------------------------------------------------

def test_loot_list_cross_user_isolation(test_app):
    """User B's loot list must not include chains owned by user A."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    import asyncio as _asyncio
    from adbygod_api.models import AttackChain, ChainStatus

    user_a = db.run(db.create_user("loot_alice", "loot_alice@test.local"))
    user_b = db.run(db.create_user("loot_bob", "loot_bob@test.local"))

    # Insert a chain with loot for user_a only.
    session_maker = test_app["session_maker"]

    async def _insert_chain():
        async with session_maker() as sess:
            chain = AttackChain(
                name="alice-chain",
                owner_user_id=user_a.id,
                status=ChainStatus.COMPLETED,
                target="dc01",
                domain="loot.local",
                loot={"nt_hashes": ["aad3b435:deadbeef"]},
            )
            sess.add(chain)
            await sess.commit()

    _asyncio.run(_insert_chain())

    # User B's loot list should be empty (or at least not include alice's chain).
    resp = client.get("/api/v1/loot", headers=headers_for(user_b))
    assert resp.status_code == 200, f"Expected 200 got {resp.status_code}: {resp.text}"
    data = resp.json()
    chain_names = {entry.get("chain_name") for entry in data}
    assert "alice-chain" not in chain_names, (
        f"User B must not see user A's loot; got chain names: {chain_names}"
    )


# ---------------------------------------------------------------------------
# 12. Graph routes require assessment access
# ---------------------------------------------------------------------------

def test_graph_data_cross_user_denied(test_app):
    """User B cannot retrieve graph data for user A's assessment."""
    client = test_app["client"]
    db = test_app["db"]
    headers_for = test_app["headers_for"]

    user_a = db.run(db.create_user("graph_alice", "graph_alice@test.local"))
    user_b = db.run(db.create_user("graph_bob", "graph_bob@test.local"))

    ws_a = db.run(db.create_workspace("ws_graph_a"))
    ws_b = db.run(db.create_workspace("ws_graph_b"))
    db.run(db.add_workspace_user(ws_a.id, user_a.id))
    db.run(db.add_workspace_user(ws_b.id, user_b.id))

    assessment_a = db.run(
        db.create_assessment("Graph Alpha", "grapha.local", workspace_id=ws_a.id, created_by=user_a.id)
    )

    resp = client.get(
        f"/api/v1/graph/{assessment_a.id}/data",
        headers=headers_for(user_b),
    )
    assert resp.status_code in (403, 404), (
        f"Expected 403/404 for cross-user graph data, got {resp.status_code}: {resp.text}"
    )
