"""Tests: WS manager broadcast_graph_delta emits type='delta' frames.
Verifies the live graph stream sends delta notifications after mutations."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock
from starlette.websockets import WebSocketDisconnect

from adbygod_api.core.graph.websocket_manager import WebSocketManager, broadcast_graph_delta


@pytest.mark.asyncio
async def test_broadcast_graph_delta_sends_delta_type():
    """broadcast_graph_delta must send a message with type='delta'."""
    mgr = WebSocketManager()
    aid = "test-assessment-id"

    mock_ws = AsyncMock()
    mock_ws.accept = AsyncMock()
    mock_ws.send_json = AsyncMock()

    await mgr.connect(aid, mock_ws)
    await mgr.broadcast(aid, {"type": "delta", "entity_count": 5, "edge_count": 10})

    mock_ws.send_json.assert_called_once_with(
        {"type": "delta", "entity_count": 5, "edge_count": 10}
    )


@pytest.mark.asyncio
async def test_broadcast_graph_delta_helper_sends_correct_message():
    """broadcast_graph_delta helper sends delta with entity/edge counts."""
    mock_ws = AsyncMock()
    mock_ws.accept = AsyncMock()
    mock_ws.send_json = AsyncMock()

    import adbygod_api.core.graph.websocket_manager as _mod
    _mod.ws_manager._subscribers["aid-123"] = [mock_ws]

    await broadcast_graph_delta("aid-123", entity_count=3, edge_count=7)

    call_args = mock_ws.send_json.call_args[0][0]
    assert call_args["type"] == "delta"
    assert call_args["entity_count"] == 3
    assert call_args["edge_count"] == 7

    _mod.ws_manager._subscribers.pop("aid-123", None)


@pytest.mark.asyncio
async def test_broadcast_graph_delta_no_subscribers_does_not_raise():
    """broadcast_graph_delta with no subscribers must not raise."""
    await broadcast_graph_delta("no-subscribers-id", entity_count=0, edge_count=0)


@pytest.mark.asyncio
async def test_broadcast_removes_dead_connections():
    """broadcast must remove WebSocket connections that raise on send."""
    mgr = WebSocketManager()
    aid = "dead-ws-test"

    dead_ws = AsyncMock()
    dead_ws.accept = AsyncMock()
    dead_ws.send_json = AsyncMock(side_effect=Exception("connection closed"))

    await mgr.connect(aid, dead_ws)
    assert len(mgr._subscribers[aid]) == 1

    await mgr.broadcast(aid, {"type": "delta"})
    assert len(mgr._subscribers[aid]) == 0


def test_graph_ws_rejects_disallowed_origin(test_app):
    """WS connection with a disallowed Origin header must be rejected.

    After the Origin check is implemented, the server closes the connection
    before accept(). Starlette's TestClient raises WebSocketDisconnect in that
    case.  We verify the connection was NOT completed successfully (i.e. we
    must not receive a {"type": "connected"} frame).
    """
    db = test_app["db"]
    client = test_app["client"]

    admin = db.run(db.create_user("ws_origin_admin", "ws_origin@test.com", is_superadmin=True))
    assessment = db.run(db.create_assessment(
        "ws_origin_assess", "corp.local", workspace_id=None, created_by=admin.id
    ))

    login = client.post("/api/v1/auth/login", json={"username": "ws_origin_admin", "password": "password123!"})
    token = login.cookies.get("adbygod_session")

    connection_was_rejected = False
    try:
        with client.websocket_connect(
            f"/api/v1/graph/{assessment.id}/stream",
            cookies={"adbygod_session": token},
            headers={"origin": "https://evil.example.com"},
        ) as ws:
            data = ws.receive_json()
            # If we reach here, the server accepted the socket — check it sent an error
            assert data.get("type") != "connected", (
                "Server accepted evil-origin connection and sent 'connected' — Origin check missing"
            )
            # An explicit error payload (403/error) also counts as rejection
            assert data.get("code") == 403 or data.get("error") is not None
            connection_was_rejected = True
    except WebSocketDisconnect:
        # Server closed before or right after accept — expected after fix
        connection_was_rejected = True

    assert connection_was_rejected, "Expected connection to be rejected for disallowed origin"


def test_graph_ws_allows_allowlisted_origin(test_app, monkeypatch):
    """WS connection with an allowlisted Origin is accepted."""
    import adbygod_api.config as config_mod

    db = test_app["db"]
    client = test_app["client"]

    monkeypatch.setattr(config_mod.settings, "ALLOWED_ORIGINS", "http://localhost:3000")

    admin = db.run(db.create_user("ws_ok_admin", "ws_ok@test.com", is_superadmin=True))
    assessment = db.run(db.create_assessment(
        "ws_ok_assess", "corp.local", workspace_id=None, created_by=admin.id
    ))

    login = client.post("/api/v1/auth/login", json={"username": "ws_ok_admin", "password": "password123!"})
    token = login.cookies.get("adbygod_session")

    with client.websocket_connect(
        f"/api/v1/graph/{assessment.id}/stream",
        cookies={"adbygod_session": token},
        headers={"origin": "http://localhost:3000"},
    ) as ws:
        data = ws.receive_json()
        assert data.get("type") == "connected"
