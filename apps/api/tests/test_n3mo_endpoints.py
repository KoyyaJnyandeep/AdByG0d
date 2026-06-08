"""Tests for N3mo God Mode API endpoints."""
import pytest
from unittest.mock import MagicMock, patch


@pytest.mark.asyncio
async def test_approve_endpoint_not_found_returns_404():
    """Approving a nonexistent request_id returns 404."""
    from adbygod_api.routes.ai_operator import router
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    app = FastAPI()
    app.include_router(router)

    # Mock auth
    from adbygod_api.routes.auth import get_current_user
    app.dependency_overrides[get_current_user] = lambda: MagicMock(is_superadmin=True, id="user-1")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/ai-operator/approve/nonexistent-id")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_reject_endpoint_not_found_returns_404():
    from adbygod_api.routes.ai_operator import router
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    app = FastAPI()
    app.include_router(router)

    from adbygod_api.routes.auth import get_current_user
    app.dependency_overrides[get_current_user] = lambda: MagicMock(is_superadmin=True, id="user-1")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/ai-operator/reject/nonexistent-id")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_approve_resolves_pending_request():
    """Approving a real pending request returns 200 and resolves it."""
    from adbygod_api.routes.ai_operator import router
    from adbygod_api.core.ai_operator.approval_store import ApprovalStore
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    store = ApprovalStore()
    req_id = store.create("read_assessment_data", {"assessment_id": "abc"}, "desc", "LOW", "")

    app = FastAPI()
    app.include_router(router)

    from adbygod_api.routes.auth import get_current_user
    app.dependency_overrides[get_current_user] = lambda: MagicMock(is_superadmin=True, id="user-1")

    with patch("adbygod_api.routes.ai_operator.get_approval_store", return_value=store):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(f"/ai-operator/approve/{req_id}")
            assert resp.status_code == 200
            data = resp.json()
            assert data["approved"] is True


@pytest.mark.asyncio
async def test_playbooks_endpoint_returns_list():
    from adbygod_api.routes.ai_operator import router
    from fastapi import FastAPI
    from httpx import AsyncClient, ASGITransport

    app = FastAPI()
    app.include_router(router)

    from adbygod_api.routes.auth import get_current_user
    app.dependency_overrides[get_current_user] = lambda: MagicMock(is_superadmin=True, id="user-1")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/ai-operator/playbooks")
        assert resp.status_code == 200
        data = resp.json()
        assert "playbooks" in data
        assert isinstance(data["playbooks"], list)
