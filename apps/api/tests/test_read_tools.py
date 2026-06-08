# apps/api/tests/test_read_tools.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from adbygod_api.core.ai_operator.tools.read_tools import HANDLERS

@pytest.mark.asyncio
async def test_list_findings_returns_list():
    import uuid
    aid = str(uuid.uuid4())
    ctx = MagicMock()
    ctx.assessment_id = aid
    # Superadmin bypasses workspace-scoped access check in _verify_assessment_access
    ctx.current_user = MagicMock(is_superadmin=True)
    mock_finding = MagicMock()
    mock_finding.id = str(uuid.uuid4())
    mock_finding.title = "Kerberoastable SPN"
    mock_finding.severity = MagicMock(value="CRITICAL")
    mock_finding.status = MagicMock(value="open")
    mock_finding.module = "kerberos"
    mock_finding.description = "Some description"
    ctx.db = AsyncMock()
    ctx.db.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[mock_finding])))
    ))
    result = await HANDLERS["list_findings"]({"limit": 5}, ctx)
    assert isinstance(result, list)
    assert result[0]["title"] == "Kerberoastable SPN"
    assert result[0]["severity"] == "CRITICAL"

@pytest.mark.asyncio
async def test_search_platform_requires_query():
    ctx = MagicMock()
    ctx.assessment_id = None
    ctx.db = AsyncMock()
    ctx.db.execute = AsyncMock(return_value=MagicMock(
        scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))
    ))
    with pytest.raises(ValueError, match="query"):
        await HANDLERS["search_platform"]({}, ctx)

@pytest.mark.asyncio
async def test_get_assessment_summary_no_assessment():
    ctx = MagicMock()
    ctx.assessment_id = None
    result = await HANDLERS["get_assessment_summary"]({}, ctx)
    assert "error" in result

@pytest.mark.asyncio
async def test_all_10_read_handlers_registered():
    expected = {
        "get_assessment_summary", "list_findings", "get_entities",
        "get_attack_paths", "get_kill_chain_status", "get_loot",
        "get_graph_summary", "get_validation_results", "get_lateral_movement",
        "search_platform", "get_entity_details", "get_opsec_status",
        "get_mitre_coverage", "get_domain_info", "get_technique_catalog",
        "get_acl_edges", "diff_assessments", "get_reachable_from",
    }
    assert expected == set(HANDLERS.keys())
