# apps/api/tests/test_tool_registry.py
import pytest
from adbygod_api.core.ai_operator.tools.registry import TOOL_SCHEMAS, dispatch_tool

def test_all_22_tools_defined():
    names = [t["name"] for t in TOOL_SCHEMAS]
    assert len(names) == 45

def test_dispatch_unknown_tool_raises():
    import asyncio
    with pytest.raises(ValueError, match="Unknown tool"):
        asyncio.run(dispatch_tool("does_not_exist", {}, ctx=None))

def test_read_tools_not_exec():
    from adbygod_api.core.ai_operator.tools.registry import EXEC_TOOL_NAMES, READ_TOOL_NAMES
    assert "execute_technique" in EXEC_TOOL_NAMES
    assert "list_findings" in READ_TOOL_NAMES
    assert not (set(READ_TOOL_NAMES) & set(EXEC_TOOL_NAMES))


@pytest.mark.asyncio
async def test_dispatch_known_tool_calls_handler():
    """dispatch_tool calls the registered handler and returns result + duration_ms."""
    from unittest.mock import AsyncMock, patch
    from adbygod_api.core.ai_operator.tools.registry import dispatch_tool
    from adbygod_api.core.ai_operator import tools as tools_pkg

    mock_handler = AsyncMock(return_value={"items": []})

    mock_read = type("read_tools", (), {"HANDLERS": {"list_findings": mock_handler}})()
    mock_intel = type("intel_tools", (), {"HANDLERS": {}})()
    mock_write = type("write_tools", (), {"HANDLERS": {}})()

    with (
        patch.object(tools_pkg, "read_tools", mock_read, create=True),
        patch.object(tools_pkg, "intel_tools", mock_intel, create=True),
        patch.object(tools_pkg, "write_tools", mock_write, create=True),
    ):
        result = await dispatch_tool("list_findings", {"limit": 5}, ctx=None)

    assert result["result"] == {"items": []}
    assert "duration_ms" in result
    mock_handler.assert_called_once_with({"limit": 5}, None)
