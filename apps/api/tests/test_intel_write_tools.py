import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from adbygod_api.core.ai_operator.tools.intel_tools import HANDLERS as INTEL
from adbygod_api.core.ai_operator.tools.write_tools import HANDLERS as WRITE

_AUTHZ_MODULE = "adbygod_api.core.security.authorization"

@pytest.mark.asyncio
async def test_get_credential_intel_classifies_ntlm():
    ctx = MagicMock()
    result = await INTEL["get_credential_intel"](
        {"hashes": ["aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"], "domain": "corp.local"},
        ctx
    )
    assert isinstance(result, list)
    assert result[0]["hash_type"] == "NTLM"
    assert result[0]["pth_ready"] is True
    assert result[0]["hashcat_mode"] == 1000

@pytest.mark.asyncio
async def test_get_credential_intel_classifies_tgs():
    ctx = MagicMock()
    result = await INTEL["get_credential_intel"](
        {"hashes": ["$krb5tgs$23$*user$REALM$spn*$abcd1234..."], "domain": "corp.local"},
        ctx
    )
    assert result[0]["hash_type"] == "Kerberos TGS"
    assert result[0]["hashcat_mode"] == 13100
    assert result[0]["pth_ready"] is False

@pytest.mark.asyncio
async def test_save_to_memory_calls_store():
    aid = str(uuid.uuid4())
    ctx = MagicMock()
    ctx.assessment_id = aid
    ctx.current_user = MagicMock(id=uuid.uuid4(), is_superadmin=False)
    ctx.db = AsyncMock()
    ctx.memory_store = AsyncMock()
    ctx.memory_store.append = AsyncMock(return_value=None)
    with patch(f"{_AUTHZ_MODULE}.require_assessment_write_access", new=AsyncMock(return_value=MagicMock())):
        result = await WRITE["save_to_memory"](
            {"key": "owned_accounts", "value": "admin@corp.local"}, ctx
        )
    ctx.memory_store.append.assert_called_once_with(aid, "owned_accounts", "admin@corp.local")
    assert result["saved"] is True

@pytest.mark.asyncio
async def test_write_report_section_saves():
    aid = str(uuid.uuid4())
    ctx = MagicMock()
    ctx.assessment_id = aid
    ctx.current_user = MagicMock(id=uuid.uuid4(), is_superadmin=False)
    ctx.db = AsyncMock()
    ctx.memory_store = AsyncMock()
    ctx.memory_store.set_report_section = AsyncMock(return_value=None)
    with patch(f"{_AUTHZ_MODULE}.require_assessment_write_access", new=AsyncMock(return_value=MagicMock())):
        result = await WRITE["write_report_section"](
            {"section": "executive_summary", "content": "# Executive Summary\n\nCritical findings."},
            ctx
        )
    assert result.get("section") == "executive_summary"
    ctx.memory_store.set_report_section.assert_called_once()

@pytest.mark.asyncio
async def test_intel_handlers_registered():
    expected = {
        "get_credential_intel", "parse_bloodhound", "get_engagement_memory",
        "simulate_attack_chain", "get_owned_graph", "get_session_intel", "get_trust_map",
    }
    assert expected == set(INTEL.keys())

@pytest.mark.asyncio
async def test_write_handlers_registered():
    expected = {
        "save_to_memory", "write_report_section", "update_target_card",
        "add_finding", "annotate_entity", "flag_finding", "set_opsec_mode",
    }
    assert expected == set(WRITE.keys())
