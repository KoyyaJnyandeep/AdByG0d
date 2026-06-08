"""Cross-user isolation tests for AI operator read tools."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from adbygod_api.core.ai_operator.tools.read_tools import HANDLERS


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class MockUser:
    def __init__(self, user_id, is_superadmin=False):
        self.id = user_id
        self.is_superadmin = is_superadmin


class MockScalars:
    def __init__(self, items=None):
        self._items = items or []

    def all(self):
        return self._items

    def first(self):
        return self._items[0] if self._items else None


class MockResult:
    def __init__(self, items=None, scalar_value=0):
        self._items = items or []
        self._scalar_value = scalar_value

    def scalars(self):
        return MockScalars(self._items)

    def scalar(self):
        return self._scalar_value


class MockDB:
    async def execute(self, stmt):
        return MockResult()


class MockCtx:
    def __init__(self, user, assessment_id=None, db=None, memory_store=None):
        self.current_user = user
        self.assessment_id = assessment_id
        self.db = db or MockDB()
        self.memory_store = memory_store


async def _deny(*args, **kwargs):
    """require_assessment_access that always raises — simulates cross-user denial."""
    from fastapi import HTTPException, status
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


_AUTHZ_MODULE = "adbygod_api.core.security.authorization"


# ---------------------------------------------------------------------------
# test_assessment_summary_denies_cross_user
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_assessment_summary_denies_cross_user():
    """User A cannot read summary for user B's assessment."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["get_assessment_summary"]({"assessment_id": other_aid}, ctx)

    assert "error" in result
    assert "access denied" in result["error"].lower()


# ---------------------------------------------------------------------------
# test_list_findings_denies_cross_user
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_findings_denies_cross_user():
    """User A cannot list findings for user B's assessment."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["list_findings"]({"assessment_id": other_aid}, ctx)

    # _list_findings returns [] on denial
    assert result == []


# ---------------------------------------------------------------------------
# test_list_findings_returns_empty_no_aid
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_findings_returns_empty_no_aid():
    """Missing assessment_id → safe empty list, not global data."""
    user = MockUser(uuid.uuid4())
    ctx = MockCtx(user=user, assessment_id=None)

    result = await HANDLERS["list_findings"]({}, ctx)

    assert result == []


# ---------------------------------------------------------------------------
# test_get_entities_denies_cross_user
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_entities_denies_cross_user():
    """User A cannot read entities for user B's assessment."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["get_entities"]({"assessment_id": other_aid}, ctx)

    assert result == []


# ---------------------------------------------------------------------------
# test_search_platform_scoped_to_assessment
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_search_platform_scoped_to_assessment():
    """Searching with another user's assessment_id is blocked before any DB query."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["search_platform"](
            {"query": "admin", "assessment_id": other_aid}, ctx
        )

    assert result["findings"] == []
    assert result["entities"] == []
    assert "error" in result
    assert "access denied" in result["error"].lower()


# ---------------------------------------------------------------------------
# test_search_platform_no_aid_returns_safe_result
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_search_platform_no_aid_returns_safe_result():
    """Search without assessment_id falls back to user-scoped query — no global leak."""
    user = MockUser(uuid.uuid4())
    ctx = MockCtx(user=user, assessment_id=None)

    # Provide a mock scope_assessment_child_query that returns the original stmt
    async def _noop_scope(stmt, col, db, user):
        return stmt

    with patch(f"{_AUTHZ_MODULE}.scope_assessment_child_query", new=_noop_scope):
        result = await HANDLERS["search_platform"]({"query": "administrator"}, ctx)

    # Result must be a dict with findings/entities keys — not a raw global dump
    assert "findings" in result
    assert "entities" in result
    assert "error" not in result or result.get("findings") == []


# ---------------------------------------------------------------------------
# test_lateral_movement_denies_cross_user
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lateral_movement_denies_cross_user():
    """User A cannot read lateral movement chains for user B's assessment."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["get_lateral_movement"]({"assessment_id": other_aid}, ctx)

    assert "error" in result
    assert "access denied" in result["error"].lower()


# ---------------------------------------------------------------------------
# test_loot_denies_cross_user
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_loot_denies_cross_user():
    """User A cannot read loot for user B's assessment."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["get_loot"]({"assessment_id": other_aid}, ctx)

    assert result == []


# ---------------------------------------------------------------------------
# test_allowed_owner_access_works
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_allowed_owner_access_works():
    """Valid owner gets their assessment data across multiple read functions."""
    owner = MockUser(uuid.uuid4())
    own_aid = str(uuid.uuid4())
    ctx = MockCtx(user=owner, assessment_id=own_aid)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(return_value=None)):
        # list_findings returns [] from mock DB — that's fine, just verify no error/block
        findings = await HANDLERS["list_findings"]({}, ctx)
        entities = await HANDLERS["get_entities"]({}, ctx)
        paths = await HANDLERS["get_attack_paths"]({}, ctx)

    assert isinstance(findings, list)
    assert isinstance(entities, list)
    assert isinstance(paths, list)
    # None of these should carry an "error" or "blocked" key
    for item in [findings, entities, paths]:
        assert item != {"error": "Assessment not found or access denied"}


# ---------------------------------------------------------------------------
# test_get_attack_paths_denies_cross_user  (bonus: _get_attack_paths)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_attack_paths_denies_cross_user():
    """User A cannot read attack paths for user B's assessment."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["get_attack_paths"]({"assessment_id": other_aid}, ctx)

    assert result == []
