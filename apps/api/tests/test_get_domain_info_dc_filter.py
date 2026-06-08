"""Unit test: _get_domain_info must return entities explicitly typed DC
even when dns_hostname does not contain 'dc' and attributes.is_dc is absent."""
from __future__ import annotations

import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from adbygod_api.core.ai_operator.tools.read_tools import HANDLERS
from adbygod_api.models import EntityType

_AUTHZ = "adbygod_api.core.security.authorization.require_assessment_access"


def _make_assessment(aid):
    a = MagicMock()
    a.id = aid
    a.domain = "corp.local"
    a.dc_ip = "10.0.0.1"
    a.domain_functional_level = "2016"
    return a


def _make_entity(eid, entity_type, dns_hostname=None, attributes=None):
    e = MagicMock()
    e.id = eid
    e.entity_type = entity_type
    e.dns_hostname = dns_hostname
    e.display_name = "Primary Controller"
    e.attributes = attributes or {}
    return e


@pytest.mark.asyncio
async def test_get_domain_info_includes_explicit_dc_entity():
    """Entity with entity_type=DC and no dns_hostname hint must appear in domain_controllers."""
    aid = str(uuid.uuid4())
    eid = uuid.uuid4()

    # Entity typed DC but no "dc" in hostname and no is_dc attribute
    dc_entity = _make_entity(eid, EntityType.DC, dns_hostname="primary-controller.corp.local", attributes={})

    ctx = MagicMock()
    ctx.assessment_id = aid
    ctx.current_user = MagicMock(is_superadmin=True)

    # Sequence of execute calls:
    # 1. Assessment lookup
    # 2. DC entity lookup
    # 3-N. Privileged group lookups (one per group name)
    # N+1. Trust lookup
    assessment_result = MagicMock()
    assessment_result.scalars.return_value.first.return_value = _make_assessment(aid)

    dc_result = MagicMock()
    dc_result.scalars.return_value.all.return_value = [dc_entity]

    # Privileged group queries return empty
    empty_result = MagicMock()
    empty_result.scalars.return_value.first.return_value = None

    # Trust query returns empty list
    trust_result = MagicMock()
    trust_result.scalars.return_value.all.return_value = []

    call_count = 0

    async def mock_execute(stmt):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return assessment_result
        if call_count == 2:
            return dc_result
        if call_count <= 8:
            return empty_result
        return trust_result

    ctx.db = AsyncMock()
    ctx.db.execute = mock_execute

    with patch(_AUTHZ, new=AsyncMock()):
        result = await HANDLERS["get_domain_info"]({"assessment_id": aid}, ctx)

    assert "domain_controllers" in result
    dc_ids = [dc["id"] for dc in result["domain_controllers"]]
    assert str(eid) in dc_ids, f"Expected DC entity {eid} in domain_controllers, got: {result['domain_controllers']}"


@pytest.mark.asyncio
async def test_get_domain_info_excludes_non_dc_computer_without_hints():
    """COMPUTER entity with no 'dc' in hostname and no is_dc flag must NOT appear."""
    aid = str(uuid.uuid4())
    eid = uuid.uuid4()

    workstation = _make_entity(eid, EntityType.COMPUTER, dns_hostname="ws01.corp.local", attributes={})

    ctx = MagicMock()
    ctx.assessment_id = aid
    ctx.current_user = MagicMock(is_superadmin=True)

    assessment_result = MagicMock()
    assessment_result.scalars.return_value.first.return_value = _make_assessment(aid)

    dc_result = MagicMock()
    dc_result.scalars.return_value.all.return_value = [workstation]

    empty_result = MagicMock()
    empty_result.scalars.return_value.first.return_value = None
    empty_result.scalars.return_value.all.return_value = []

    call_count = 0

    async def mock_execute(stmt):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return assessment_result
        if call_count == 2:
            return dc_result
        return empty_result

    ctx.db = AsyncMock()
    ctx.db.execute = mock_execute

    with patch(_AUTHZ, new=AsyncMock()):
        result = await HANDLERS["get_domain_info"]({"assessment_id": aid}, ctx)

    dc_ids = [dc["id"] for dc in result.get("domain_controllers", [])]
    assert str(eid) not in dc_ids
