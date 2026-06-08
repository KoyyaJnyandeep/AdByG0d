"""In-process WebSocket subscriber registry for graph streaming."""
from __future__ import annotations
import asyncio
import logging
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import WebSocket

log = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self):
        self._subscribers: dict[str, list["WebSocket"]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def connect(self, assessment_id: str, ws: "WebSocket") -> None:
        await ws.accept()
        async with self._lock:
            self._subscribers[assessment_id].append(ws)
        log.debug("WS connected for assessment %s (total: %d)", assessment_id, len(self._subscribers[assessment_id]))

    async def disconnect(self, assessment_id: str, ws: "WebSocket") -> None:
        async with self._lock:
            subs = self._subscribers.get(assessment_id, [])
            if ws in subs:
                subs.remove(ws)

    async def broadcast(self, assessment_id: str, message: dict) -> None:
        async with self._lock:
            subs = list(self._subscribers.get(assessment_id, []))
        dead = []
        for ws in subs:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            await self.disconnect(assessment_id, ws)


ws_manager = WebSocketManager()


async def broadcast_graph_delta(
    assessment_id: str,
    entity_count: int = 0,
    edge_count: int = 0,
) -> None:
    """Broadcast a delta notification to all WS subscribers for an assessment."""
    await ws_manager.broadcast(assessment_id, {
        "type": "delta",
        "entity_count": entity_count,
        "edge_count": edge_count,
    })
