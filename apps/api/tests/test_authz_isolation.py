"""
Tests proving multi-user authorization isolation.
These tests verify that user A cannot access user B's data.
"""
from __future__ import annotations

import sys
from pathlib import Path
from uuid import UUID

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from fastapi import HTTPException

from adbygod_api.config import Settings
from adbygod_api.core.ai_operator.approval_store import ApprovalStore
from adbygod_api.core.security.authorization import require_assessment_access


# ── Test 1: cross-user assessment access denied at the service layer ───────────

@pytest.mark.asyncio
async def test_cross_user_assessment_access_denied(test_app):
    """User B cannot access an assessment that belongs to user A's workspace."""
    db = test_app["db"]
    session_maker = test_app["session_maker"]

    user_a = await db.create_user("isolate-alice", "isolate-alice@example.invalid")
    user_b = await db.create_user("isolate-bob", "isolate-bob@example.invalid")
    workspace_a = await db.create_workspace("ws-alpha")
    workspace_b = await db.create_workspace("ws-beta")
    await db.add_workspace_user(workspace_a.id, user_a.id)
    await db.add_workspace_user(workspace_b.id, user_b.id)
    assessment_a = await db.create_assessment(
        "Alpha Assessment",
        "alpha.local",
        workspace_id=workspace_a.id,
        created_by=user_a.id,
    )

    async with session_maker() as session:
        with pytest.raises(HTTPException) as exc_info:
            await require_assessment_access(assessment_a.id, session, user_b)

    assert exc_info.value.status_code in (403, 404)


# ── Test 2: ApprovalStore resolves only for the owning user ───────────────────

@pytest.mark.asyncio
async def test_approval_store_user_scoping():
    """User B cannot resolve an approval created for user A."""
    store = ApprovalStore()
    request_id = store.create(
        tool_name="nmap",
        args={"target": "10.0.0.1"},
        description="Scan target",
        user_id="user-aaa",
    )

    # Wrong user — must not resolve
    ok_wrong, reason_wrong = store.resolve(request_id, approved=True, user_id="user-bbb")
    assert ok_wrong is False
    assert reason_wrong == "user_mismatch"

    # Correct user — must resolve
    ok_correct, reason_correct = store.resolve(request_id, approved=True, user_id="user-aaa")
    assert ok_correct is True
    assert reason_correct == "ok"


# ── Test 3: ApprovalStore returns full UUID request IDs ───────────────────────

@pytest.mark.asyncio
async def test_approval_store_full_uuid_request_id():
    """Request IDs must be full UUIDs (36 characters with dashes), not truncated."""
    store = ApprovalStore()
    request_id = store.create(
        tool_name="enum-shares",
        args={},
        description="Enumerate shares",
        user_id="user-zzz",
    )

    assert len(request_id) == 36, (
        f"Expected a full UUID (36 chars), got {len(request_id)} chars: {request_id!r}"
    )
    # Validate UUID format: 8-4-4-4-12
    parts = request_id.split("-")
    assert len(parts) == 5
    assert [len(p) for p in parts] == [8, 4, 4, 4, 12]
    # Must be parseable as a valid UUID
    UUID(request_id)


# ── Test 4: memory route rejects cross-user access via HTTP ───────────────────

@pytest.mark.asyncio
async def test_memory_route_requires_assessment_ownership(test_app):
    """GET /api/v1/ai-operator/memory/{id} must return 403/404 for a non-member user."""
    db = test_app["db"]
    client = test_app["client"]
    headers_for = test_app["headers_for"]

    user_a = await db.create_user("mem-alice", "mem-alice@example.invalid")
    user_b = await db.create_user("mem-bob", "mem-bob@example.invalid")
    workspace_a = await db.create_workspace("mem-ws-alpha")
    workspace_b = await db.create_workspace("mem-ws-beta")
    await db.add_workspace_user(workspace_a.id, user_a.id)
    await db.add_workspace_user(workspace_b.id, user_b.id)
    assessment_a = await db.create_assessment(
        "Memory Alpha",
        "mem-alpha.local",
        workspace_id=workspace_a.id,
        created_by=user_a.id,
    )

    response = client.get(
        f"/api/v1/ai-operator/memory/{assessment_a.id}",
        headers=headers_for(user_b),
    )

    assert response.status_code in (403, 404), (
        f"Expected 403 or 404 for cross-user memory access, got {response.status_code}"
    )


# ── Test 5: production rejects insecure cookie ────────────────────────────────

@pytest.mark.asyncio
async def test_config_production_rejects_insecure_cookie():
    """AUTH_COOKIE_SECURE=False must be rejected in production."""
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 48,
        DATABASE_URL="postgresql+asyncpg://user:pass@db/adbygod",
        ALLOWED_ORIGINS="http://example.com",
        AUTH_COOKIE_SECURE=False,
        DEBUG=False,
    )
    with pytest.raises(RuntimeError, match="AUTH_COOKIE_SECURE"):
        s.validate_runtime()


# ── Test 6: production rejects wildcard CORS ──────────────────────────────────

@pytest.mark.asyncio
async def test_config_production_rejects_wildcard_cors():
    """ALLOWED_ORIGINS='*' must be rejected in production."""
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 48,
        DATABASE_URL="postgresql+asyncpg://user:pass@db/adbygod",
        ALLOWED_ORIGINS="*",
        AUTH_COOKIE_SECURE=True,
        DEBUG=False,
    )
    with pytest.raises(RuntimeError, match="wildcard"):
        s.validate_runtime()


# ── Test 7: production rejects DEBUG mode ─────────────────────────────────────

@pytest.mark.asyncio
async def test_config_production_rejects_debug_mode():
    """DEBUG=True must be rejected when ENVIRONMENT=production."""
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 48,
        DATABASE_URL="postgresql+asyncpg://user:pass@db/adbygod",
        ALLOWED_ORIGINS="http://example.com",
        AUTH_COOKIE_SECURE=True,
        DEBUG=True,
    )
    with pytest.raises(RuntimeError):
        s.validate_runtime()


# ── Test 8: production rejects SQLite ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_config_production_rejects_sqlite():
    """SQLite database URLs must be rejected in production."""
    s = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 48,
        DATABASE_URL="sqlite:///./test.db",
        ALLOWED_ORIGINS="http://example.com",
        AUTH_COOKIE_SECURE=True,
        DEBUG=False,
    )
    with pytest.raises(RuntimeError, match="SQLite"):
        s.validate_runtime()
