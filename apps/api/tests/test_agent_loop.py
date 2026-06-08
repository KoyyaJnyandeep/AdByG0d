import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch


def _collect_events(gen):
    """Collect all SSE events from an async generator."""
    import asyncio
    async def _collect():
        events = []
        async for line in gen:
            if line.startswith("data: "):
                try:
                    events.append(json.loads(line[6:].strip()))
                except json.JSONDecodeError:
                    pass
        return events
    return asyncio.get_event_loop().run_until_complete(_collect())


@pytest.mark.asyncio
async def test_agent_emits_done_event():
    """AgentLoop always emits a done event at the end."""
    from adbygod_api.core.ai_operator.agent import AgentLoop
    from adbygod_api.core.ai_operator.approval_store import ApprovalStore
    from adbygod_api.core.ai_operator.memory_store import MemoryStore

    loop = AgentLoop(
        approval_store=ApprovalStore(),
        memory_store=MemoryStore(base_dir="/tmp/test_agent_memory"),
    )

    events = []
    with patch.object(loop, "_auto_context", new_callable=AsyncMock, return_value=""), \
         patch.object(loop, "_call_llm", new_callable=AsyncMock,
                      return_value={"type": "text", "chunks": ["Hello N3mo"], "tool_calls": []}):
        async for line in loop.run(
            session_ctx=None, user_message="hi", history=[],
            provider_id="claude", model=None, api_key="test-key", base_url=None,
            assessment_id=None, db=AsyncMock(), current_user=MagicMock()
        ):
            if line.startswith("data: "):
                events.append(json.loads(line[6:].strip()))

    assert any(e.get("type") == "done" for e in events)
    assert any(e.get("type") == "chunk" for e in events)


@pytest.mark.asyncio
async def test_agent_emits_approval_required_for_exec_tool():
    """AgentLoop emits approval_required for execution tools and pauses."""
    from adbygod_api.core.ai_operator.agent import AgentLoop
    from adbygod_api.core.ai_operator.approval_store import ApprovalStore
    from adbygod_api.core.ai_operator.memory_store import MemoryStore

    store = ApprovalStore()
    loop = AgentLoop(
        approval_store=store,
        memory_store=MemoryStore(base_dir="/tmp/test_agent_memory2"),
    )

    tool_call = {"id": "tc_1", "name": "execute_technique", "args": {"technique_id": "kerberoast-spns"}}

    call_count = 0
    async def mock_call_llm(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"type": "tool_use", "tool_calls": [tool_call], "raw_content": [tool_call]}
        return {"type": "text", "chunks": ["Done after rejection"], "tool_calls": []}

    async def auto_reject():
        await asyncio.sleep(0.15)
        # Find and reject the pending approval
        for req_id in list(store._pending.keys()):
            store.resolve(req_id, False)

    events = []
    reject_task = asyncio.create_task(auto_reject())

    with patch.object(loop, "_auto_context", new_callable=AsyncMock, return_value=""), \
         patch.object(loop, "_call_llm", side_effect=mock_call_llm):
        async for line in loop.run(
            session_ctx=None, user_message="Kerberoast", history=[],
            provider_id="claude", model=None, api_key="test-key", base_url=None,
            assessment_id=None, db=AsyncMock(), current_user=MagicMock()
        ):
            if line.startswith("data: "):
                events.append(json.loads(line[6:].strip()))

    await reject_task
    event_types = [e.get("type") for e in events]
    assert "approval_required" in event_types
    assert "rejected" in event_types
    assert "done" in event_types


@pytest.mark.asyncio
async def test_agent_emits_tool_call_and_result_for_read_tool():
    """AgentLoop emits tool_call then tool_result for read tools without approval."""
    from adbygod_api.core.ai_operator.agent import AgentLoop
    from adbygod_api.core.ai_operator.approval_store import ApprovalStore
    from adbygod_api.core.ai_operator.memory_store import MemoryStore

    loop = AgentLoop(
        approval_store=ApprovalStore(),
        memory_store=MemoryStore(base_dir="/tmp/test_agent_memory3"),
    )

    tool_call = {"id": "tc_2", "name": "get_graph_summary", "args": {"assessment_id": "test-id"}}

    call_count = 0
    async def mock_call_llm(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"type": "tool_use", "tool_calls": [tool_call], "raw_content": [tool_call]}
        return {"type": "text", "chunks": ["Here is the graph summary."], "tool_calls": []}

    mock_dispatch = AsyncMock(return_value={"result": {"summary": "100 entities"}, "duration_ms": 50})

    events = []
    with patch.object(loop, "_auto_context", new_callable=AsyncMock, return_value=""), \
         patch.object(loop, "_call_llm", side_effect=mock_call_llm), \
         patch("adbygod_api.core.ai_operator.agent.dispatch_tool", mock_dispatch):
        async for line in loop.run(
            session_ctx=None, user_message="show graph", history=[],
            provider_id="claude", model=None, api_key="test-key", base_url=None,
            assessment_id="test-id", db=AsyncMock(), current_user=MagicMock()
        ):
            if line.startswith("data: "):
                events.append(json.loads(line[6:].strip()))

    event_types = [e.get("type") for e in events]
    assert "tool_call" in event_types
    assert "tool_result" in event_types
    assert "done" in event_types
