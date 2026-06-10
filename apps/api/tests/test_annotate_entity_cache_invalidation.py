"""_annotate_entity must enqueue a Neo4j re-projection after committing entity
field changes, so the derived graph read-model (and the graph UI) does not serve
stale data. (Replaces the old in-memory invalidate_graph_cache mechanism, which
was removed when the graph routes moved to Neo4j.)"""
from __future__ import annotations

import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from adbygod_api.core.ai_operator.tools.write_tools import HANDLERS
from adbygod_api.models import EntityType

_AUTHZ_WRITE = "adbygod_api.core.security.authorization.require_assessment_write_access"
_ENQUEUE = "adbygod_api.core.tasks.graph_projection.enqueue"
_BROADCAST = "adbygod_api.core.graph.websocket_manager.broadcast_graph_delta"


def _make_ctx(aid, entity):
    ctx = MagicMock()
    ctx.assessment_id = aid
    ctx.current_user = MagicMock(id=uuid.uuid4(), is_superadmin=True)
    ctx.memory_store = None

    entity_result = MagicMock()
    entity_result.scalars.return_value.first.return_value = entity

    ctx.db = AsyncMock()
    ctx.db.execute = AsyncMock(return_value=entity_result)
    ctx.db.commit = AsyncMock()
    return ctx


def _make_entity(eid, aid):
    e = MagicMock()
    e.id = eid
    e.assessment_id = aid
    e.entity_type = EntityType.COMPUTER
    e.display_name = "DC01"
    e.sam_account_name = None
    e.dns_hostname = "dc01.corp.local"
    e.is_crown_jewel = False
    e.is_sensitive = False
    e.business_tags = []
    e.attributes = {}
    return e


@pytest.mark.asyncio
async def test_annotate_entity_enqueues_projection_on_crown_jewel_change():
    """Setting is_crown_jewel must enqueue a re-projection for the assessment."""
    aid = str(uuid.uuid4())
    eid = uuid.uuid4()
    ctx = _make_ctx(aid, _make_entity(eid, aid))

    with patch(_AUTHZ_WRITE, new=AsyncMock()), \
         patch(_BROADCAST, new=AsyncMock()), \
         patch(_ENQUEUE) as mock_enqueue:
        result = await HANDLERS["annotate_entity"](
            {"entity_id": str(eid), "assessment_id": aid, "is_crown_jewel": True}, ctx,
        )

    mock_enqueue.assert_called_once_with(aid)
    assert result["is_crown_jewel"] is True


@pytest.mark.asyncio
async def test_annotate_entity_enqueues_projection_on_sensitive_change():
    """Setting is_sensitive must also enqueue a re-projection."""
    aid = str(uuid.uuid4())
    eid = uuid.uuid4()
    ctx = _make_ctx(aid, _make_entity(eid, aid))

    with patch(_AUTHZ_WRITE, new=AsyncMock()), \
         patch(_BROADCAST, new=AsyncMock()), \
         patch(_ENQUEUE) as mock_enqueue:
        await HANDLERS["annotate_entity"](
            {"entity_id": str(eid), "assessment_id": aid, "is_sensitive": True}, ctx,
        )

    mock_enqueue.assert_called_once_with(aid)


@pytest.mark.asyncio
async def test_annotate_entity_survives_projection_enqueue_error():
    """If enqueuing the projection fails, annotate_entity must not raise."""
    aid = str(uuid.uuid4())
    eid = uuid.uuid4()
    ctx = _make_ctx(aid, _make_entity(eid, aid))

    with patch(_AUTHZ_WRITE, new=AsyncMock()), \
         patch(_BROADCAST, new=AsyncMock()), \
         patch(_ENQUEUE, side_effect=RuntimeError("broker unavailable")):
        result = await HANDLERS["annotate_entity"](
            {"entity_id": str(eid), "assessment_id": aid, "is_crown_jewel": True}, ctx,
        )

    assert result.get("updated") is True
