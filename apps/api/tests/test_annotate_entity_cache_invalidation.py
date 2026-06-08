"""Unit test: _annotate_entity must invalidate the graph export cache after
committing entity field changes so the graph UI does not serve stale data."""
from __future__ import annotations

import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from adbygod_api.core.ai_operator.tools.write_tools import HANDLERS
from adbygod_api.models import EntityType

_AUTHZ_WRITE = "adbygod_api.core.security.authorization.require_assessment_write_access"
_INVALIDATE = "adbygod_api.routes.graph.invalidate_graph_cache"


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
async def test_annotate_entity_invalidates_cache_on_crown_jewel_change():
    """Setting is_crown_jewel must trigger invalidate_graph_cache for the assessment."""
    aid = str(uuid.uuid4())
    eid = uuid.uuid4()
    entity = _make_entity(eid, aid)
    ctx = _make_ctx(aid, entity)

    with patch(_AUTHZ_WRITE, new=AsyncMock()):
        with patch(_INVALIDATE) as mock_invalidate:
            result = await HANDLERS["annotate_entity"](
                {"entity_id": str(eid), "assessment_id": aid, "is_crown_jewel": True},
                ctx,
            )

    mock_invalidate.assert_called_once_with(aid)
    assert result["is_crown_jewel"] is True


@pytest.mark.asyncio
async def test_annotate_entity_invalidates_cache_on_sensitive_change():
    """Setting is_sensitive must also invalidate the cache."""
    aid = str(uuid.uuid4())
    eid = uuid.uuid4()
    entity = _make_entity(eid, aid)
    ctx = _make_ctx(aid, entity)

    with patch(_AUTHZ_WRITE, new=AsyncMock()):
        with patch(_INVALIDATE) as mock_invalidate:
            await HANDLERS["annotate_entity"](
                {"entity_id": str(eid), "assessment_id": aid, "is_sensitive": True},
                ctx,
            )

    mock_invalidate.assert_called_once_with(aid)


@pytest.mark.asyncio
async def test_annotate_entity_cache_invalidation_survives_import_error():
    """Even if routes.graph cannot be imported, annotate_entity must not raise."""
    aid = str(uuid.uuid4())
    eid = uuid.uuid4()
    entity = _make_entity(eid, aid)
    ctx = _make_ctx(aid, entity)

    with patch(_AUTHZ_WRITE, new=AsyncMock()):
        with patch(_INVALIDATE, side_effect=ImportError("routes not loaded")):
            result = await HANDLERS["annotate_entity"](
                {"entity_id": str(eid), "assessment_id": aid, "is_crown_jewel": True},
                ctx,
            )

    assert result.get("updated") is True
