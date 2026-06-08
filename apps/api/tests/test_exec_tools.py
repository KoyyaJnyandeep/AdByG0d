import pytest
from unittest.mock import MagicMock, patch
from adbygod_api.core.ai_operator.tools.exec_tools import HANDLERS

@pytest.mark.asyncio
async def test_execute_technique_blocked_when_disabled():
    """When ENABLE_COMMAND_EXECUTION=false, returns blocked before arg validation."""
    import adbygod_api.config as config_module
    ctx = MagicMock()
    ctx.current_user = MagicMock(is_superadmin=True)
    with patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", False):
        result = await HANDLERS["execute_technique"]({}, ctx)
        assert result.get("blocked") is True

@pytest.mark.asyncio
async def test_run_shell_command_blocked_when_disabled():
    """When ENABLE_AI_ARBITRARY_SHELL=false, returns blocked regardless of args."""
    import adbygod_api.config as config_module
    ctx = MagicMock()
    ctx.current_user = MagicMock(is_superadmin=True)
    with patch.object(config_module.settings, "ENABLE_AI_ARBITRARY_SHELL", False):
        result = await HANDLERS["run_shell_command"]({}, ctx)
        assert result.get("blocked") is True

@pytest.mark.asyncio
async def test_execute_technique_blocked_for_non_superadmin():
    """Non-superadmin is blocked even if ENABLE_COMMAND_EXECUTION=true."""
    import adbygod_api.config as config_module
    ctx = MagicMock()
    ctx.current_user = MagicMock(is_superadmin=False)
    with patch.object(config_module.settings, "ENABLE_COMMAND_EXECUTION", True):
        result = await HANDLERS["execute_technique"]({"technique_id": "any"}, ctx)
        assert result.get("blocked") is True

@pytest.mark.asyncio
async def test_crack_hashes_requires_hashcat_mode():
    ctx = MagicMock()
    with pytest.raises((KeyError, ValueError)):
        await HANDLERS["crack_hashes"]({"hashes": ["abc"]}, ctx)

@pytest.mark.asyncio
async def test_execute_technique_unknown_returns_error():
    ctx = MagicMock()
    result = await HANDLERS["execute_technique"](
        {"technique_id": "nonexistent-technique-xyz"}, ctx
    )
    assert "error" in result

@pytest.mark.asyncio
async def test_all_5_exec_handlers_registered():
    expected = {
        "execute_technique", "run_shell_command", "run_campaign_step", "spawn_sub_agent",
        "crack_hashes", "plan_attack", "get_timeline", "import_tool_output",
        "run_technique_chain", "generate_playbook", "export_report",
        "get_next_best_action", "run_bloodhound_collection",
    }
    assert expected == set(HANDLERS.keys())
