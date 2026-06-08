"""Unit tests: _plan_attack must use numeric phase_ids to suppress completed phases,
not string phase labels, because KillChainProgress.phase_id is Integer."""
from __future__ import annotations

import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from adbygod_api.core.ai_operator.tools.exec_tools import HANDLERS, _PHASE_NAME_TO_ID

_AUTHZ = "adbygod_api.core.security.authorization.require_assessment_access"


def _make_finding(title, severity="HIGH"):
    f = MagicMock()
    f.id = uuid.uuid4()
    f.title = title
    f.severity = MagicMock(value=severity)
    return f


def _make_kc_progress(phase_id: int, status: str = "complete"):
    p = MagicMock()
    p.phase_id = phase_id
    p.status = MagicMock()
    p.status.__str__ = lambda s: status
    return p


def _ctx_with_db(assessment_id, findings, kc_phases, paths=None):
    ctx = MagicMock()
    ctx.assessment_id = assessment_id
    ctx.current_user = MagicMock(is_superadmin=True)

    findings_result = MagicMock()
    findings_result.scalars.return_value.all.return_value = findings

    paths_result = MagicMock()
    paths_result.scalars.return_value.all.return_value = paths or []

    kc_result = MagicMock()
    kc_result.scalars.return_value.all.return_value = kc_phases

    call_count = 0

    async def mock_execute(stmt):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return findings_result
        if call_count == 2:
            return paths_result
        return kc_result

    ctx.db = AsyncMock()
    ctx.db.execute = mock_execute
    return ctx


@pytest.mark.asyncio
async def test_completed_loot_phase_suppresses_loot_steps():
    """phase_id=5 (Credential Access / 'loot') complete → no loot steps returned."""
    aid = str(uuid.uuid4())
    findings = [_make_finding("LAPS passwords readable")]
    kc = [_make_kc_progress(5, "complete")]  # Credential Access = "loot"

    ctx = _ctx_with_db(aid, findings, kc)

    with patch(_AUTHZ, new=AsyncMock()):
        result = await HANDLERS["plan_attack"]({"assessment_id": aid}, ctx)

    loot_steps = [s for s in result.get("steps", []) if s["phase"] == "loot"]
    assert loot_steps == [], f"Expected no loot steps when phase 5 complete, got: {loot_steps}"


@pytest.mark.asyncio
async def test_completed_loot_not_in_phases_remaining():
    """phase_id=5 complete → 'loot' must not appear in phases_remaining."""
    aid = str(uuid.uuid4())
    findings = [_make_finding("LAPS passwords readable")]
    kc = [_make_kc_progress(5, "complete")]

    ctx = _ctx_with_db(aid, findings, kc)

    with patch(_AUTHZ, new=AsyncMock()):
        result = await HANDLERS["plan_attack"]({"assessment_id": aid}, ctx)

    assert "loot" not in result.get("phases_remaining", [])


@pytest.mark.asyncio
async def test_completed_privesc_phase_suppresses_privesc_steps():
    """phase_id=3 (Privilege Escalation / 'privesc') complete → no privesc steps."""
    aid = str(uuid.uuid4())
    findings = [_make_finding("Unconstrained Delegation configured")]
    kc = [_make_kc_progress(3, "complete")]

    ctx = _ctx_with_db(aid, findings, kc)

    with patch(_AUTHZ, new=AsyncMock()):
        result = await HANDLERS["plan_attack"]({"assessment_id": aid}, ctx)

    privesc_steps = [s for s in result.get("steps", []) if s["phase"] == "privesc"]
    assert privesc_steps == []


@pytest.mark.asyncio
async def test_incomplete_phase_keeps_steps():
    """Incomplete phase must still appear in the plan."""
    aid = str(uuid.uuid4())
    findings = [_make_finding("LAPS passwords readable")]
    kc = [_make_kc_progress(3, "complete")]  # only privesc complete, loot still open

    ctx = _ctx_with_db(aid, findings, kc)

    with patch(_AUTHZ, new=AsyncMock()):
        result = await HANDLERS["plan_attack"]({"assessment_id": aid}, ctx)

    loot_steps = [s for s in result.get("steps", []) if s["phase"] == "loot"]
    assert len(loot_steps) > 0


@pytest.mark.asyncio
async def test_phase_name_to_id_mapping_completeness():
    """All string phase labels used in technique_map must be present in _PHASE_NAME_TO_ID."""
    # These are the phase labels used in technique_map inside _plan_attack
    used_labels = {"enum", "privesc", "da", "loot"}
    for label in used_labels:
        assert label in _PHASE_NAME_TO_ID, f"Missing phase label: {label}"
