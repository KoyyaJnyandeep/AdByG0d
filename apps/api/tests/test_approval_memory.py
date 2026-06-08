import pytest
import asyncio
import tempfile
from adbygod_api.core.ai_operator.approval_store import ApprovalStore
from adbygod_api.core.ai_operator.memory_store import MemoryStore

@pytest.mark.asyncio
async def test_approval_approve_resolves():
    store = ApprovalStore()
    req_id = store.create("execute_technique", {"technique_id": "x"}, "Run x", "MEDIUM", "May trigger logs")
    async def approve():
        await asyncio.sleep(0.05)
        store.resolve(req_id, True)  # returns (ok, reason) — discard here
    asyncio.create_task(approve())
    result = await asyncio.wait_for(store.wait(req_id), timeout=2.0)
    assert result is True

@pytest.mark.asyncio
async def test_approval_reject_resolves():
    store = ApprovalStore()
    req_id = store.create("execute_technique", {}, "desc", "LOW", "")
    async def reject():
        await asyncio.sleep(0.05)
        store.resolve(req_id, False)  # returns (ok, reason) — discard here
    asyncio.create_task(reject())
    result = await asyncio.wait_for(store.wait(req_id), timeout=2.0)
    assert result is False

@pytest.mark.asyncio
async def test_approval_unknown_request_returns_none():
    store = ApprovalStore()
    result = await store.wait("nonexistent-id", timeout=0.1)
    assert result is None

@pytest.mark.asyncio
async def test_approval_as_event_dict():
    store = ApprovalStore()
    req_id = store.create("execute_technique", {"technique_id": "k"}, "Kerberoast", "MEDIUM", "Note")
    pending = store.get(req_id)
    d = pending.as_event_dict()
    assert d["type"] == "approval_required"
    assert d["request_id"] == req_id
    assert d["tool"] == "execute_technique"
    assert d["opsec_rating"] == "MEDIUM"

@pytest.mark.asyncio
async def test_memory_persist_and_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(base_dir=tmpdir)
        await store.append("assess-1", "owned_accounts", "admin@corp.local")
        await store.append("assess-1", "owned_accounts", "svc_backup")
        mem = await store.load("assess-1")
        assert "admin@corp.local" in mem.get("owned_accounts", [])
        assert "svc_backup" in mem.get("owned_accounts", [])

@pytest.mark.asyncio
async def test_memory_no_duplicates():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(base_dir=tmpdir)
        await store.append("assess-1", "owned_accounts", "admin@corp.local")
        await store.append("assess-1", "owned_accounts", "admin@corp.local")
        mem = await store.load("assess-1")
        assert mem["owned_accounts"].count("admin@corp.local") == 1

@pytest.mark.asyncio
async def test_memory_set_report_section():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(base_dir=tmpdir)
        await store.set_report_section("assess-1", "executive_summary", "# Summary\n\nCritical.")
        mem = await store.load("assess-1")
        assert "executive_summary" in mem.get("report_sections", {})
        assert "Critical." in mem["report_sections"]["executive_summary"]["content"]

@pytest.mark.asyncio
async def test_memory_empty_returns_dict():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = MemoryStore(base_dir=tmpdir)
        mem = await store.load("nonexistent-id")
        assert isinstance(mem, dict)
        assert mem == {}
