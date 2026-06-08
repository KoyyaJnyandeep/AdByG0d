from __future__ import annotations
from uuid import UUID
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from adbygod_api.config import settings
from adbygod_api.core.graph.websocket_manager import ws_manager

router = APIRouter(prefix="/graph", tags=["graph-ws"])


def _origin_allowed_for_ws(origin: str | None) -> bool:
    """Return True if origin is absent (native client) or in the allowlist."""
    if not origin:
        return True
    normalized = origin.rstrip("/")
    return normalized in {o.rstrip("/") for o in settings.allowed_origins_list}


@router.websocket("/{assessment_id}/stream")
async def graph_stream(
    assessment_id: UUID,
    ws: WebSocket,
):
    """Stream incremental graph deltas in real time."""
    aid = str(assessment_id)

    # Origin check — must run before accept() to avoid leaking a response body
    origin = ws.headers.get("origin")
    if not _origin_allowed_for_ws(origin):
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Auth: require valid session cookie before accepting
    token = ws.cookies.get(settings.AUTH_COOKIE_NAME)
    if not token:
        await ws.accept()
        await ws.send_json({"error": "Unauthorized", "code": 401})
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    from adbygod_api.database import AsyncSessionLocal as _ASL
    from adbygod_api.routes.auth import _get_user_cached
    from adbygod_api.core.security.authorization import require_assessment_access

    async with _ASL() as db:
        try:
            user = await _get_user_cached(token, db)
        except Exception:
            await ws.accept()
            await ws.send_json({"error": "Invalid token", "code": 401})
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        try:
            await require_assessment_access(assessment_id, db, user)
        except Exception:
            await ws.accept()
            await ws.send_json({"error": "Forbidden", "code": 403})
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    await ws_manager.connect(aid, ws)
    try:
        await ws.send_json({"type": "connected", "assessment_id": aid})
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(aid, ws)
