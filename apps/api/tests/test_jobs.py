from __future__ import annotations

import asyncio
import json
from uuid import UUID

from adbygod_api.routes import jobs as job_routes


def test_in_memory_job_store_interface():
    store = job_routes.InMemoryJobStore()
    record = store.create("job-1", owner_user_id=UUID("00000000-0000-0000-0000-000000000111"))
    assert store.get("job-1") is record
    store.remove("job-1")
    assert store.get("job-1") is None


def test_owner_can_stream_completed_job_from_history(test_app):
    db = test_app["db"]
    client = test_app["client"]
    owner = db.run(db.create_user("owner", "owner@example.invalid", is_superadmin=True))

    job_routes.create_job("job-owner", owner.id)
    token = job_routes.create_stream_token("job-owner", owner.id)
    asyncio.run(job_routes.emit("job-owner", {"message": "hello", "pct": 10}))
    asyncio.run(job_routes.emit("job-owner", {"message": "done", "done": True, "status": "COMPLETED"}))

    response = client.get(f"/api/v1/jobs/stream/job-owner?token={token}")
    assert response.status_code == 200
    assert "hello" in response.text
    assert job_routes.get_job("job-owner") is not None


def test_emit_fans_out_to_multiple_subscribers():
    owner_id = UUID("00000000-0000-0000-0000-000000000222")
    record = job_routes.create_job("job-fanout", owner_id)
    q1: asyncio.Queue = asyncio.Queue(maxsize=10)
    q2: asyncio.Queue = asyncio.Queue(maxsize=10)
    record.subscribers.update({q1, q2})

    asyncio.run(job_routes.emit("job-fanout", {"message": "same-event", "pct": 42}))

    assert q1.get_nowait()["message"] == "same-event"
    assert q2.get_nowait()["message"] == "same-event"
    assert record.history[-1]["message"] == "same-event"


def test_late_subscriber_receives_history_and_cleanup_removes_queue():
    owner_id = UUID("00000000-0000-0000-0000-000000000333")
    record = job_routes.create_job("job-replay", owner_id)
    asyncio.run(job_routes.emit("job-replay", {"message": "previous", "done": True, "status": "COMPLETED"}))

    async def _read_once():
        generator = job_routes._event_generator("job-replay")
        try:
            first = await generator.__anext__()
            return json.loads(first)
        finally:
            await generator.aclose()

    event = asyncio.run(_read_once())

    assert event["message"] == "previous"
    assert len(record.subscribers) == 0


def test_non_owner_cannot_stream(test_app):
    db = test_app["db"]
    client = test_app["client"]
    owner = db.run(db.create_user("owner2", "owner2@example.invalid", is_superadmin=True))
    other = db.run(db.create_user("other", "other@example.invalid", is_superadmin=True))

    job_routes.create_job("job-forbidden", owner.id)
    token = job_routes.create_stream_token("job-forbidden", other.id)

    response = client.get(f"/api/v1/jobs/stream/job-forbidden?token={token}")
    assert response.status_code == 403


def test_missing_or_invalid_stream_token_rejected(test_app):
    db = test_app["db"]
    client = test_app["client"]
    owner = db.run(db.create_user("owner3", "owner3@example.invalid", is_superadmin=True))

    job_routes.create_job("job-invalid", owner.id)

    missing = client.get("/api/v1/jobs/stream/job-invalid")
    invalid = client.get("/api/v1/jobs/stream/job-invalid?token=not-a-jwt")

    assert missing.status_code == 401
    assert invalid.status_code == 401


def test_status_endpoint_enforces_ownership(test_app):
    db = test_app["db"]
    client = test_app["client"]
    owner = db.run(db.create_user("owner4", "owner4@example.invalid"))
    other = db.run(db.create_user("other4", "other4@example.invalid"))

    job_routes.create_job("job-status", owner.id)

    denied = client.get("/api/v1/jobs/status/job-status", headers=test_app["headers_for"](other))
    allowed = client.get("/api/v1/jobs/status/job-status", headers=test_app["headers_for"](owner))

    assert denied.status_code == 403
    assert allowed.status_code == 200
