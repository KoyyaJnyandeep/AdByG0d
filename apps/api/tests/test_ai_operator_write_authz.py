"""Cross-user isolation tests for AI operator write tools."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from adbygod_api.core.ai_operator.tools.write_tools import HANDLERS


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class MockUser:
    def __init__(self, user_id, is_superadmin=False):
        self.id = user_id
        self.is_superadmin = is_superadmin


class MockCtx:
    def __init__(self, user, assessment_id=None, db=None, memory_store=None):
        self.current_user = user
        self.assessment_id = assessment_id
        self.db = db
        self.memory_store = memory_store


def _allow(*args, **kwargs):
    """require_assessment_access that always allows (returns None / does nothing)."""
    return None


async def _deny(*args, **kwargs):
    """require_assessment_access that always raises (simulates access denied)."""
    from fastapi import HTTPException, status
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


_PATCH_TARGET = "adbygod_api.core.ai_operator.tools.write_tools.require_assessment_access"

# We patch inside the function's import scope. Because _verify_write_access
# does a local `from … import require_assessment_access`, we need to patch at
# the module path that is looked up at call time via importlib.
_AUTHZ_MODULE = "adbygod_api.core.security.authorization"


# ---------------------------------------------------------------------------
# _save_to_memory
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_save_to_memory_requires_assessment_id():
    user = MockUser(uuid.uuid4())
    ctx = MockCtx(user=user, assessment_id=None)
    result = await HANDLERS["save_to_memory"]({"key": "foo", "value": "bar"}, ctx)
    assert result.get("blocked") is True
    assert "assessment_id" in result["error"].lower()


@pytest.mark.asyncio
async def test_save_to_memory_denies_cross_user():
    """User A cannot write to an assessment that belongs to user B's workspace."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    memory_store = AsyncMock()

    ctx = MockCtx(user=user_a, assessment_id=None, db=AsyncMock(), memory_store=memory_store)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["save_to_memory"](
            {"assessment_id": other_aid, "key": "notes", "value": "pwned"}, ctx
        )

    assert result.get("blocked") is True
    assert "access denied" in result["error"].lower()
    memory_store.append.assert_not_called()


@pytest.mark.asyncio
async def test_save_to_memory_allows_owner():
    """Owner can write to their own assessment."""
    owner = MockUser(uuid.uuid4())
    own_aid = str(uuid.uuid4())
    memory_store = AsyncMock()
    memory_store.append = AsyncMock(return_value=None)

    ctx = MockCtx(user=owner, assessment_id=own_aid, db=AsyncMock(), memory_store=memory_store)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_write_access", new=AsyncMock(return_value=MagicMock())):
        result = await HANDLERS["save_to_memory"]({"key": "owned", "value": "yes"}, ctx)

    assert result.get("saved") is True
    assert result["key"] == "owned"
    memory_store.append.assert_called_once_with(own_aid, "owned", "yes")


# ---------------------------------------------------------------------------
# _write_report_section
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_write_report_section_requires_assessment_id():
    user = MockUser(uuid.uuid4())
    ctx = MockCtx(user=user, assessment_id=None)
    result = await HANDLERS["write_report_section"](
        {"section": "exec_summary", "content": "text"}, ctx
    )
    assert result.get("blocked") is True
    assert "assessment_id" in result["error"].lower()


@pytest.mark.asyncio
async def test_write_report_section_denies_cross_user():
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    memory_store = AsyncMock()

    ctx = MockCtx(user=user_a, assessment_id=None, db=AsyncMock(), memory_store=memory_store)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["write_report_section"](
            {"assessment_id": other_aid, "section": "exec", "content": "evil"}, ctx
        )

    assert result.get("blocked") is True
    assert "access denied" in result["error"].lower()
    memory_store.set_report_section.assert_not_called()


# ---------------------------------------------------------------------------
# _update_target_card
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_update_target_card_requires_assessment_id():
    user = MockUser(uuid.uuid4())
    ctx = MockCtx(user=user, assessment_id=None)
    result = await HANDLERS["update_target_card"]({"domain": "corp.local"}, ctx)
    assert result.get("blocked") is True
    assert "assessment_id" in result["error"].lower()


@pytest.mark.asyncio
async def test_update_target_card_denies_cross_user():
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    memory_store = AsyncMock()

    ctx = MockCtx(user=user_a, assessment_id=None, db=AsyncMock(), memory_store=memory_store)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["update_target_card"](
            {"assessment_id": other_aid, "domain": "evil.local"}, ctx
        )

    assert result.get("blocked") is True
    assert "access denied" in result["error"].lower()
    memory_store.append.assert_not_called()


# ---------------------------------------------------------------------------
# Superadmin allowed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_write_functions_superadmin_allowed():
    """Superadmin can write when the assessment exists (no workspace-membership check)."""
    admin = MockUser(uuid.uuid4(), is_superadmin=True)
    aid = str(uuid.uuid4())
    memory_store = AsyncMock()
    memory_store.append = AsyncMock(return_value=None)
    memory_store.set_report_section = AsyncMock(return_value=None)

    ctx = MockCtx(user=admin, assessment_id=aid, db=AsyncMock(), memory_store=memory_store)

    # Mock the actual DB-backed function to return a fake assessment
    with patch(f"{_AUTHZ_MODULE}.require_assessment_write_access", new=AsyncMock(return_value=MagicMock())):
        save_result = await HANDLERS["save_to_memory"]({"key": "admin_note", "value": "ok"}, ctx)
        report_result = await HANDLERS["write_report_section"](
            {"section": "intro", "content": "admin content"}, ctx
        )
        card_result = await HANDLERS["update_target_card"]({"domain": "root.local"}, ctx)

    assert save_result.get("saved") is True
    assert report_result.get("section") == "intro"
    assert card_result.get("updated") is True
    assert card_result["assessment_id"] == aid


# ---------------------------------------------------------------------------
# DELETE /memory/{assessment_id} — authorization tests
# ---------------------------------------------------------------------------

def test_clear_memory_viewer_forbidden(test_app):
    """A viewer-role user must not be able to clear AI memory."""
    from unittest.mock import patch

    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]

    viewer = db.run(db.create_user("viewer_mem", "viewer_mem@test.com", is_superadmin=False))
    workspace = db.run(db.create_workspace("ws_mem"))
    db.run(db.add_workspace_user(workspace.id, viewer.id, role="viewer"))
    assessment = db.run(db.create_assessment("assess_mem", "corp.local", workspace_id=workspace.id))

    with patch("adbygod_api.routes.ai_operator.get_memory_store"):
        resp = client.delete(
            f"/api/v1/ai-operator/memory/{assessment.id}",
            headers=headers_for(viewer),
        )
    assert resp.status_code == 403


def test_clear_memory_writer_allowed(test_app):
    """A writer-role user can clear AI memory."""
    from unittest.mock import patch, MagicMock

    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]

    writer = db.run(db.create_user("writer_mem", "writer_mem@test.com", is_superadmin=False))
    workspace = db.run(db.create_workspace("ws_mem2"))
    db.run(db.add_workspace_user(workspace.id, writer.id, role="analyst"))
    assessment = db.run(db.create_assessment("assess_mem2", "corp.local", workspace_id=workspace.id))

    mock_store = MagicMock()
    mock_store.load = MagicMock(return_value=None)
    with patch("adbygod_api.routes.ai_operator.get_memory_store", return_value=mock_store):
        resp = client.delete(
            f"/api/v1/ai-operator/memory/{assessment.id}",
            headers=headers_for(writer),
        )
    assert resp.status_code == 200
