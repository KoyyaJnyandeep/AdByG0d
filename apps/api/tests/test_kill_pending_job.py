"""Integration test: DELETE /ops/jobs/{id} must also kill PENDING jobs.
Before the fix, only RUNNING jobs were transitioned to KILLED; PENDING stayed as-is."""
from __future__ import annotations

import uuid
import pytest
from unittest.mock import AsyncMock, patch

from adbygod_api.models import OffensiveJob, OffensiveJobStatus


def _create_job_payload():
    return {
        "technique_id": "recon-ldap-anon",
        "target": "10.0.0.1",
        "params": {},
        "opsec_profile": "BALANCED",
    }


@pytest.mark.asyncio
async def test_kill_pending_job_sets_killed_status(test_app):
    factory = test_app["db"]
    sm = test_app["session_maker"]
    client = test_app["client"]

    user = await factory.create_user("killer", "killer@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "KillTest", "corp.local", workspace_id=None, created_by=user.id
    )

    job_id = uuid.uuid4()
    async with sm() as session:
        job = OffensiveJob(
            id=job_id,
            assessment_id=assessment.id,
            technique_id="recon-ldap-anon",
            target="10.0.0.1",
            params={},
            executor="impacket",
            status=OffensiveJobStatus.PENDING,
            owner_user_id=user.id,
        )
        session.add(job)
        await session.commit()

    headers = test_app["headers_for"](user)
    with patch("adbygod_api.routes.ops._get_redis") as mock_redis_fn:
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.aclose = AsyncMock()
        mock_redis_fn.return_value = mock_redis
        resp = client.delete(f"/api/v1/ops/jobs/{job_id}", headers=headers)

    assert resp.status_code == 204

    async with sm() as session:
        updated = await session.get(OffensiveJob, job_id)
        assert updated.status == OffensiveJobStatus.KILLED
        assert updated.completed_at is not None
        assert updated.exit_code == -1


@pytest.mark.asyncio
async def test_kill_running_job_also_sets_killed_status(test_app):
    """RUNNING jobs must still be killed (regression check)."""
    factory = test_app["db"]
    sm = test_app["session_maker"]
    client = test_app["client"]

    user = await factory.create_user("killer2", "killer2@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "KillTest2", "corp.local", workspace_id=None, created_by=user.id
    )

    job_id = uuid.uuid4()
    async with sm() as session:
        job = OffensiveJob(
            id=job_id,
            assessment_id=assessment.id,
            technique_id="recon-ldap-anon",
            target="10.0.0.2",
            params={},
            executor="impacket",
            status=OffensiveJobStatus.RUNNING,
            owner_user_id=user.id,
        )
        session.add(job)
        await session.commit()

    headers = test_app["headers_for"](user)
    with patch("adbygod_api.routes.ops._get_redis") as mock_redis_fn:
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.aclose = AsyncMock()
        mock_redis_fn.return_value = mock_redis
        resp = client.delete(f"/api/v1/ops/jobs/{job_id}", headers=headers)

    assert resp.status_code == 204

    async with sm() as session:
        updated = await session.get(OffensiveJob, job_id)
        assert updated.status == OffensiveJobStatus.KILLED
        assert updated.exit_code == -1


@pytest.mark.asyncio
async def test_kill_completed_job_does_not_change_status(test_app):
    """Completed jobs must not be re-killed."""
    factory = test_app["db"]
    sm = test_app["session_maker"]
    client = test_app["client"]

    user = await factory.create_user("killer3", "killer3@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "KillTest3", "corp.local", workspace_id=None, created_by=user.id
    )

    job_id = uuid.uuid4()
    async with sm() as session:
        job = OffensiveJob(
            id=job_id,
            assessment_id=assessment.id,
            technique_id="recon-ldap-anon",
            target="10.0.0.3",
            params={},
            executor="impacket",
            status=OffensiveJobStatus.COMPLETED,
            owner_user_id=user.id,
        )
        session.add(job)
        await session.commit()

    headers = test_app["headers_for"](user)
    with patch("adbygod_api.routes.ops._get_redis") as mock_redis_fn:
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(return_value=None)
        mock_redis.aclose = AsyncMock()
        mock_redis_fn.return_value = mock_redis
        resp = client.delete(f"/api/v1/ops/jobs/{job_id}", headers=headers)

    assert resp.status_code == 204

    async with sm() as session:
        updated = await session.get(OffensiveJob, job_id)
        assert updated.status == OffensiveJobStatus.COMPLETED
