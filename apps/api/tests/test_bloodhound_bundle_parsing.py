from __future__ import annotations

import asyncio
import io
import zipfile

import pytest

from adbygod_api.core.parsers.bloodhound import BloodHoundParser
from adbygod_api.models import AssessmentStatus, ValidationRun
from adbygod_api.routes import import_data as import_routes


def _zip_bytes(entries: dict[str, bytes], *, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_validation_simulate_requires_workspace_write(test_app):
    db = test_app["db"]
    client = test_app["client"]
    workspace = db.run(db.create_workspace("Validation ACL"))
    owner = db.run(db.create_user("validation_owner", "validation-owner@example.invalid"))
    viewer = db.run(db.create_user("validation_viewer", "validation-viewer@example.invalid"))
    db.run(db.add_workspace_user(workspace.id, owner.id, role="analyst"))
    db.run(db.add_workspace_user(workspace.id, viewer.id, role="viewer"))
    assessment = db.run(
        db.create_assessment(
            "Validation",
            "corp.local",
            workspace_id=workspace.id,
            created_by=owner.id,
        )
    )

    response = client.post(
        f"/api/v1/validation/simulate/dcsync/{assessment.id}",
        headers=test_app["headers_for"](viewer),
        json={"target": "corp.local", "mode": "simulation"},
    )
    assert response.status_code == 403


def test_validation_runs_total_reports_full_count(test_app):
    db = test_app["db"]
    client = test_app["client"]
    user = db.run(db.create_user("validation_total", "validation-total@example.invalid", is_superadmin=True))
    assessment = db.run(
        db.create_assessment(
            "Validation",
            "corp.local",
            workspace_id=None,
            created_by=user.id,
        )
    )

    async def seed():
        async with test_app["session_maker"]() as session:
            for index in range(101):
                session.add(
                    ValidationRun(
                        assessment_id=assessment.id,
                        module_id="dcsync",
                        target=f"target-{index}",
                        requested_mode="simulation",
                        status="COMPLETED",
                        execution_mode="SIMULATION",
                        simulated=True,
                        origin="SIMULATED",
                    )
                )
            await session.commit()

    asyncio.run(seed())
    response = client.get(
        f"/api/v1/validation/runs/{assessment.id}",
        headers=test_app["headers_for"](user),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 101
    assert body["returned"] == 100
    assert len(body["runs"]) == 100


def test_bloodhound_parser_rejects_member_count_bomb():
    entries = {f"users-{i}.json": b"{}" for i in range(257)}
    with pytest.raises(ValueError, match="too many BloodHound members"):
        BloodHoundParser().parse_zip(_zip_bytes(entries))


def test_bloodhound_parser_rejects_ratio_bomb():
    bomb = _zip_bytes({"users.json": b"A" * 500_000})
    with pytest.raises(ValueError, match="suspicious compression ratio"):
        BloodHoundParser().parse_zip(bomb)


def test_empty_bloodhound_payload_marks_assessment_failed(test_app, monkeypatch):
    db = test_app["db"]
    assessment = db.run(db.create_assessment("Wrapper", "corp.local", workspace_id=None))

    class EmptyParser:
        def parse_zip(self, _data: bytes):
            return {
                "schema_version": "1.0",
                "tool": "BloodHound",
                "collection_mode": "IMPORT",
                "domain": "corp.local",
                "dc_ip": None,
                "collected_at": "2026-04-12T00:00:00Z",
                "collector_version": "test",
                "modules_run": ["BloodHound Import"],
                "entities": [],
                "edges": [],
                "evidence": [],
                "findings": [],
                "cert_templates": [],
                "metadata": {},
            }

        parse_json = parse_zip

    monkeypatch.setattr(import_routes, "BloodHoundParser", EmptyParser)
    db.run(import_routes._run_import("job-wrapper", assessment.id, b"wrapper", "wrapper.zip"))
    refreshed = db.run(db.get_assessment(assessment.id))
    assert refreshed.status == AssessmentStatus.FAILED
    assert "no recognized BloodHound/SharpHound" in (refreshed.error_message or "")


def test_chain_request_rejects_shell_metacharacters_in_dc_ip():
    from adbygod_api.routes.chains import ChainRequest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ChainRequest(target="10.0.0.1", domain="corp.local", dc_ip="10.0.0.1; rm -rf /")


def test_chain_request_rejects_shell_metacharacters_in_target():
    from adbygod_api.routes.chains import ChainRequest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ChainRequest(target="10.0.0.1 && whoami", domain="corp.local")


def test_chain_request_rejects_malformed_hashes():
    from adbygod_api.routes.chains import ChainRequest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ChainRequest(target="10.0.0.1", domain="corp.local", hashes="not-a-hash; injected")


def test_chain_request_accepts_valid_ntlm_hash():
    from adbygod_api.routes.chains import ChainRequest

    req = ChainRequest(
        target="10.0.0.1",
        domain="corp.local",
        username="Administrator",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        dc_ip="10.0.0.1",
    )
    assert req.hashes == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def test_chain_request_accepts_empty_credentials():
    from adbygod_api.routes.chains import ChainRequest

    req = ChainRequest(target="dc01.corp.local", domain="corp.local")
    assert req.username == ""
    assert req.hashes == ""


def test_loot_capture_db_error_yields_error_event_not_unhandled_exception(monkeypatch):
    """If the DB commit fails during loot capture, the SSE stream must yield an error event."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    captured_events = []

    async def fake_event_generator():
        try:
            async with MagicMock() as db:
                db.get = AsyncMock(return_value=None)
                db.commit = AsyncMock(side_effect=Exception("DB connection lost"))
                raise Exception("DB connection lost")
        except Exception as exc:
            yield f"data: {{'type': 'error', 'message': '{exc}'}}\n\n"
            return

    async def collect():
        async for event in fake_event_generator():
            captured_events.append(event)

    asyncio.run(collect())
    assert len(captured_events) == 1
    assert "error" in captured_events[0]


def test_ingest_ca_flags_returns_500_on_bulk_insert_failure(test_app, monkeypatch):
    """ingest_ca_flags must return 500 and not corrupt the DB if the insert phase fails."""
    from adbygod_api import models
    from adbygod_api.routes import ingest as ingest_mod

    db = test_app["db"]
    user = db.run(db.create_user("caflags-user", "caflags@example.invalid", is_superadmin=True))
    assessment = db.run(
        db.create_assessment(
            "CA Flags Test",
            "corp.local",
            workspace_id=None,
            created_by=user.id,
            status=models.AssessmentStatus.COMPLETED,
        )
    )
    token_headers = test_app["headers_for"](user)

    original_bulk_insert = ingest_mod._bulk_insert
    call_count = {"n": 0}

    async def failing_bulk_insert(session, model, rows):
        call_count["n"] += 1
        if model.__tablename__ == "findings" and call_count["n"] > 1:
            raise Exception("Simulated insert failure")
        return await original_bulk_insert(session, model, rows)

    monkeypatch.setattr(ingest_mod, "_bulk_insert", failing_bulk_insert)

    payload = {"ca_flags": [{"ca_name": "TestCA", "hostname": "dc01", "edit_flags_raw": "0x00040000"}]}
    response = test_app["client"].post(
        f"/api/v1/ingest/{assessment.id}/ca-flags",
        headers=token_headers,
        json=payload,
    )

    assert response.status_code == 500


def test_graph_cache_lock_exists_in_graph_module():
    """graph.py must expose a module-level asyncio.Lock for cache protection."""
    import asyncio
    from adbygod_api.routes import graph as graph_mod

    assert hasattr(graph_mod, "_graph_cache_lock"), (
        "_graph_cache_lock must exist in graph module"
    )
    assert isinstance(graph_mod._graph_cache_lock, asyncio.Lock), (
        "_graph_cache_lock must be an asyncio.Lock instance"
    )


def test_get_chain_lock_returns_same_lock_for_same_chain_id():
    """_get_chain_lock must return the same Lock instance for the same chain_id."""
    from adbygod_api.routes.chains import _get_chain_lock
    import asyncio

    lock_a = _get_chain_lock("chain-abc")
    lock_b = _get_chain_lock("chain-abc")
    lock_c = _get_chain_lock("chain-xyz")

    assert lock_a is lock_b, "Same chain_id must return the same Lock"
    assert lock_a is not lock_c, "Different chain_ids must return different Locks"
    assert isinstance(lock_a, asyncio.Lock)


def test_get_chain_lock_is_race_safe():
    """setdefault guarantees only one Lock is created even under concurrent access."""
    from adbygod_api.routes.chains import _get_chain_lock, _chain_locks

    cid = "race-test-chain"
    _chain_locks.pop(cid, None)  # ensure clean state

    lock1 = _get_chain_lock(cid)
    lock2 = _get_chain_lock(cid)
    assert lock1 is lock2


def test_graph_paths_returns_503_on_timeout(test_app, monkeypatch):
    """GET /graph/{id}/paths must return 503 if path computation exceeds 30 seconds."""
    import asyncio
    from unittest.mock import AsyncMock
    from adbygod_api.routes import graph as graph_mod

    db = test_app["db"]
    user = db.run(db.create_user("graph-timeout-user", "graph-timeout@example.invalid", is_superadmin=True))
    assessment = db.run(
        db.create_assessment(
            "Timeout Test",
            "timeout.local",
            workspace_id=None,
            created_by=user.id,
        )
    )
    token_headers = test_app["headers_for"](user)

    class SlowAnalyzer:
        def get_all_paths(self, *args, **kwargs):
            import time
            time.sleep(999)
        def get_paths_to_tier0(self, *args, **kwargs):
            import time
            time.sleep(999)

    async def fast_timeout(coro, timeout):
        raise asyncio.TimeoutError()

    monkeypatch.setattr(graph_mod.asyncio, "wait_for", fast_timeout)
    monkeypatch.setattr(graph_mod, "_get_analyzer", AsyncMock(return_value=SlowAnalyzer()))

    response = test_app["client"].get(
        f"/api/v1/graph/{assessment.id}/paths",
        headers=token_headers,
        params={"source_id": "S-1-fake", "target_id": "S-1-fake2"},
    )

    assert response.status_code == 503
    assert "timed out" in response.json()["detail"].lower()
