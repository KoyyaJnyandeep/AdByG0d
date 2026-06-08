"""Cross-user isolation tests for AI operator intel tools."""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from adbygod_api.core.ai_operator.tools.intel_tools import HANDLERS


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class MockUser:
    def __init__(self, user_id, is_superadmin=False):
        self.id = user_id
        self.is_superadmin = is_superadmin


class MockScalars:
    def all(self):
        return []


class MockResult:
    def scalars(self):
        return MockScalars()


class MockDB:
    async def execute(self, stmt):
        return MockResult()


class MockCtx:
    def __init__(self, user, assessment_id=None, db=None, memory_store=None):
        self.current_user = user
        self.assessment_id = assessment_id
        self.db = db or MockDB()
        self.memory_store = memory_store


async def _deny(*args, **kwargs):
    """require_assessment_access that always raises (simulates access denied)."""
    from fastapi import HTTPException, status
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


_AUTHZ_MODULE = "adbygod_api.core.security.authorization"


# ---------------------------------------------------------------------------
# _parse_bloodhound
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_parse_bloodhound_requires_assessment_id():
    user = MockUser(uuid.uuid4())
    ctx = MockCtx(user=user, assessment_id=None)
    result = await HANDLERS["parse_bloodhound"]({}, ctx)
    assert result.get("blocked") is True
    assert "assessment_id" in result["error"].lower()


@pytest.mark.asyncio
async def test_parse_bloodhound_denies_cross_user():
    """User A cannot read BloodHound data belonging to user B's assessment."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["parse_bloodhound"]({"assessment_id": other_aid}, ctx)

    assert result.get("blocked") is True
    assert "access denied" in result["error"].lower()


@pytest.mark.asyncio
async def test_parse_bloodhound_allows_owner():
    """Assessment owner can query BloodHound data (returns empty list from mock DB)."""
    owner = MockUser(uuid.uuid4())
    own_aid = str(uuid.uuid4())
    ctx = MockCtx(user=owner, assessment_id=own_aid)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(return_value=None)):
        result = await HANDLERS["parse_bloodhound"]({}, ctx)

    assert "blocked" not in result or result.get("blocked") is not True
    assert "paths_to_da" in result
    assert "choke_points" in result
    assert result["total_paths_analyzed"] == 0


# ---------------------------------------------------------------------------
# _get_engagement_memory
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_engagement_memory_requires_assessment_id():
    user = MockUser(uuid.uuid4())
    ctx = MockCtx(user=user, assessment_id=None)
    result = await HANDLERS["get_engagement_memory"]({}, ctx)
    assert result.get("blocked") is True
    assert "assessment_id" in result["error"].lower()


@pytest.mark.asyncio
async def test_engagement_memory_denies_cross_user():
    """User A cannot read engagement memory for user B's assessment."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    memory_store = AsyncMock()
    ctx = MockCtx(user=user_a, assessment_id=None, memory_store=memory_store)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["get_engagement_memory"]({"assessment_id": other_aid}, ctx)

    assert result.get("blocked") is True
    assert "access denied" in result["error"].lower()
    memory_store.load.assert_not_called()


@pytest.mark.asyncio
async def test_engagement_memory_allows_owner():
    """Owner can read their own engagement memory."""
    owner = MockUser(uuid.uuid4())
    own_aid = str(uuid.uuid4())
    memory_store = AsyncMock()
    memory_store.load = AsyncMock(return_value={"notes": "some intel"})
    ctx = MockCtx(user=owner, assessment_id=own_aid, memory_store=memory_store)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(return_value=None)):
        result = await HANDLERS["get_engagement_memory"]({}, ctx)

    assert result == {"notes": "some intel"}
    memory_store.load.assert_called_once_with(own_aid)


# ---------------------------------------------------------------------------
# _simulate_attack_chain
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_simulate_attack_chain_requires_assessment_id():
    user = MockUser(uuid.uuid4())
    ctx = MockCtx(user=user, assessment_id=None)
    result = await HANDLERS["simulate_attack_chain"]({}, ctx)
    assert result.get("blocked") is True
    assert "assessment_id" in result["error"].lower()


@pytest.mark.asyncio
async def test_simulate_attack_chain_denies_cross_user():
    """User A cannot simulate attack chains using user B's assessment data."""
    user_a = MockUser(uuid.uuid4())
    other_aid = str(uuid.uuid4())
    ctx = MockCtx(user=user_a, assessment_id=None)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(side_effect=_deny)):
        result = await HANDLERS["simulate_attack_chain"](
            {"assessment_id": other_aid, "owned": ["user1"], "target": "Domain Admins"}, ctx
        )

    assert result.get("blocked") is True
    assert "access denied" in result["error"].lower()


@pytest.mark.asyncio
async def test_simulate_attack_chain_allows_owner():
    """Owner can simulate attack chains against their own assessment data."""
    owner = MockUser(uuid.uuid4())
    own_aid = str(uuid.uuid4())
    ctx = MockCtx(user=owner, assessment_id=own_aid)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(return_value=None)):
        result = await HANDLERS["simulate_attack_chain"](
            {"owned": ["user1"], "target": "Domain Admins"}, ctx
        )

    # Empty DB mock returns no paths — should get verdict but no blocked flag
    assert "blocked" not in result or result.get("blocked") is not True
    assert "direct_paths_to_target" in result


# ---------------------------------------------------------------------------
# _get_credential_intel — stateless, no assessment_id needed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_credential_intel_is_stateless():
    """_get_credential_intel classifies hashes without any assessment_id or DB access."""
    # No user, no ctx, no assessment — still works
    result = await HANDLERS["get_credential_intel"](
        {
            "hashes": [
                "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",  # NTLM
                "$krb5tgs$23$*user$DOMAIN.LOCAL$spn*$deadbeef...",  # TGS
            ],
            "domain": "corp.local",
        },
        None,  # no ctx
    )

    assert isinstance(result, list)
    assert len(result) == 2
    ntlm = result[0]
    assert ntlm["hash_type"] == "NTLM"
    assert ntlm["pth_ready"] is True
    assert ntlm["severity"] == "CRITICAL"
    tgs = result[1]
    assert tgs["hash_type"] == "Kerberos TGS"
    assert "wordlist_hints" in tgs


# ---------------------------------------------------------------------------
# Superadmin allowed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_superadmin_can_access_any_assessment_intel():
    """Superadmin bypasses workspace membership — require_assessment_access passes."""
    admin = MockUser(uuid.uuid4(), is_superadmin=True)
    any_aid = str(uuid.uuid4())
    ctx = MockCtx(user=admin, assessment_id=any_aid)

    with patch(f"{_AUTHZ_MODULE}.require_assessment_access", new=AsyncMock(return_value=None)):
        bh_result = await HANDLERS["parse_bloodhound"]({}, ctx)
        sim_result = await HANDLERS["simulate_attack_chain"](
            {"owned": ["krbtgt"], "target": "Domain Admins"}, ctx
        )

    assert "paths_to_da" in bh_result
    assert bh_result.get("blocked") is not True
    assert "direct_paths_to_target" in sim_result
    assert sim_result.get("blocked") is not True
