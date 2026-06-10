from __future__ import annotations


def test_reproject_enqueues_and_reports_state(test_app, monkeypatch):
    from adbygod_api.routes import graph as graph_routes

    enq = {}
    monkeypatch.setattr(
        graph_routes, "_enqueue_projection", lambda aid: enq.setdefault("aid", str(aid))
    )

    db = test_app["db"]
    admin = db.run(db.create_user("admin", "a@x.io", is_superadmin=True))
    ws = db.run(db.create_workspace("ws"))
    a = db.run(
        db.create_assessment("A", "d", workspace_id=ws.id, created_by=admin.id)
    )
    headers = test_app["headers_for"](admin)

    r = test_app["client"].post(f"/api/v1/graph/{a.id}/reproject", headers=headers)
    assert r.status_code == 202, r.text
    assert enq["aid"] == str(a.id)

    s = test_app["client"].get(f"/api/v1/graph/{a.id}/projection-state", headers=headers)
    assert s.status_code == 200
    body = s.json()
    # The enqueue is mocked, so the worker never runs: state stays "projecting".
    assert body["status"] == "projecting"
    assert body["node_count"] == 0
    assert body["edge_count"] == 0
    assert body["last_projected_at"] is None


def test_projection_state_defaults_to_pending(test_app):
    """An assessment that was never projected reports pending defaults."""
    db = test_app["db"]
    admin = db.run(db.create_user("admin2", "a2@x.io", is_superadmin=True))
    ws = db.run(db.create_workspace("ws2"))
    a = db.run(db.create_assessment("B", "d", workspace_id=ws.id, created_by=admin.id))
    headers = test_app["headers_for"](admin)

    s = test_app["client"].get(f"/api/v1/graph/{a.id}/projection-state", headers=headers)
    assert s.status_code == 200
    body = s.json()
    assert body["status"] == "pending"
    assert body["node_count"] == 0
    assert body["last_projected_at"] is None
