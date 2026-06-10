from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from adbygod_api.core.tasks import graph_projection


class _FakeDbSession:
    """Minimal async session double that absorbs state writes."""

    def __init__(self):
        self._row = None

    async def get(self, model_cls, pk):
        return self._row

    def add(self, obj):
        self._row = obj

    async def commit(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _make_session_maker(fake_session=None):
    """Return a callable that always yields the same fake session."""
    sess = fake_session or _FakeDbSession()
    return lambda: sess


def test_task_invokes_projection(monkeypatch):
    calls = {"closed": 0}

    async def fake_connect():
        return None

    async def fake_close():
        calls["closed"] += 1

    async def fake_reproject(db, aid):
        calls["aid"] = aid
        return {"nodes": 3, "edges": 2}

    monkeypatch.setattr(graph_projection.neo4j_client, "connect", fake_connect)
    monkeypatch.setattr(graph_projection.neo4j_client, "close", fake_close)
    monkeypatch.setattr(graph_projection.projection, "reproject_assessment", fake_reproject)
    monkeypatch.setattr(graph_projection, "AsyncSessionLocal", _make_session_maker())

    result = asyncio.run(graph_projection._run("00000000-0000-0000-0000-000000000001"))
    assert result == {"nodes": 3, "edges": 2}
    assert calls["aid"] == "00000000-0000-0000-0000-000000000001"
    # The driver must be closed per task so the next task's connect() rebuilds
    # it on a fresh event loop (asyncio.run closes the current loop on return).
    assert calls["closed"] == 1


def test_task_closes_driver_even_on_error(monkeypatch):
    closed = {"n": 0}

    async def fake_connect():
        return None

    async def fake_close():
        closed["n"] += 1

    async def boom(db, aid):
        raise RuntimeError("projection failed")

    monkeypatch.setattr(graph_projection.neo4j_client, "connect", fake_connect)
    monkeypatch.setattr(graph_projection.neo4j_client, "close", fake_close)
    monkeypatch.setattr(graph_projection.projection, "reproject_assessment", boom)
    monkeypatch.setattr(graph_projection, "AsyncSessionLocal", _make_session_maker())

    with pytest.raises(RuntimeError, match="projection failed"):
        asyncio.run(graph_projection._run("00000000-0000-0000-0000-000000000001"))
    assert closed["n"] == 1  # finally-block close still runs on failure


# ---------------------------------------------------------------------------
# State-transition tests: verify _run writes GraphProjectionState correctly
# ---------------------------------------------------------------------------

def _make_sqlite_session_maker():
    """Create a throwaway in-memory SQLite DB with only the tables we need.

    SQLite does not enforce FK constraints by default, so we only need to
    create the graph_projection_state table (and assessments for the FK
    definition to resolve).  We configure a SECRET_KEY so EncryptedJSON
    columns on Assessment don't blow up if they're ever hit.
    """
    import adbygod_api.config as cfg
    import adbygod_api.models as models

    cfg.settings.SECRET_KEY = "test-secret-key-with-sufficient-length-1234567890"

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(models.Base.metadata.create_all)

    asyncio.run(_setup())
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def test_run_writes_ready_state_on_success(monkeypatch):
    """After a successful projection, GraphProjectionState must be status='ready' with counts."""
    from adbygod_api.models import GraphProjectionState

    aid = uuid.UUID("00000000-0000-0000-0000-000000000002")
    # SQLite does not enforce FK constraints by default, so no Assessment seed needed.
    session_maker = _make_sqlite_session_maker()

    async def fake_connect():
        pass

    async def fake_close():
        pass

    async def fake_reproject(db, aid_str):
        return {"nodes": 7, "edges": 5}

    monkeypatch.setattr(graph_projection.neo4j_client, "connect", fake_connect)
    monkeypatch.setattr(graph_projection.neo4j_client, "close", fake_close)
    monkeypatch.setattr(graph_projection.projection, "reproject_assessment", fake_reproject)
    monkeypatch.setattr(graph_projection, "AsyncSessionLocal", session_maker)

    result = asyncio.run(graph_projection._run(str(aid)))
    assert result == {"nodes": 7, "edges": 5}

    async def _check():
        async with session_maker() as db:
            return await db.get(GraphProjectionState, aid)

    state = asyncio.run(_check())
    assert state is not None
    assert state.status == "ready"
    assert state.node_count == 7
    assert state.edge_count == 5
    assert state.last_projected_at is not None


def test_run_writes_error_state_on_failure(monkeypatch):
    """When projection raises, GraphProjectionState must be set to status='error'."""
    from adbygod_api.models import GraphProjectionState

    aid = uuid.UUID("00000000-0000-0000-0000-000000000003")
    # SQLite does not enforce FK constraints by default, so no Assessment seed needed.
    session_maker = _make_sqlite_session_maker()

    async def fake_connect():
        pass

    async def fake_close():
        pass

    async def boom(db, aid_str):
        raise RuntimeError("neo4j exploded")

    monkeypatch.setattr(graph_projection.neo4j_client, "connect", fake_connect)
    monkeypatch.setattr(graph_projection.neo4j_client, "close", fake_close)
    monkeypatch.setattr(graph_projection.projection, "reproject_assessment", boom)
    monkeypatch.setattr(graph_projection, "AsyncSessionLocal", session_maker)

    with pytest.raises(RuntimeError, match="neo4j exploded"):
        asyncio.run(graph_projection._run(str(aid)))

    async def _check():
        async with session_maker() as db:
            return await db.get(GraphProjectionState, aid)

    state = asyncio.run(_check())
    assert state is not None
    assert state.status == "error"
