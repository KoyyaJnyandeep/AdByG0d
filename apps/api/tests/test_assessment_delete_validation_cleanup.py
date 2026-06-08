"""Integration test: DELETE /assessments/{id} must delete validation rows.
Without the fix, ValidationRun and ValidationExpertDecision rows are orphaned."""
from __future__ import annotations

import pytest
import uuid
from sqlalchemy import select

from adbygod_api.models import ValidationRun, ValidationExpertDecision


@pytest.mark.asyncio
async def test_delete_assessment_removes_validation_runs(test_app):
    factory = test_app["db"]
    sm = test_app["session_maker"]
    client = test_app["client"]

    user = await factory.create_user("va_deleter", "va_del@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "ValidationCleanupTest", "corp.local", workspace_id=None, created_by=user.id
    )
    aid = assessment.id

    # Insert ValidationRun + ValidationExpertDecision rows
    run_id = uuid.uuid4()
    async with sm() as session:
        run = ValidationRun(
            id=run_id,
            assessment_id=aid,
            module_id="kerberos",
            target="corp.local",
            requested_mode="SIMULATION",
            execution_mode="SIMULATION_CONSENSUS",
            status="COMPLETE",
        )
        session.add(run)
        dec = ValidationExpertDecision(
            id=uuid.uuid4(),
            validation_run_id=run_id,
            expert_id="expert_kerberos",
            expert_name="Kerberos Expert",
            verdict="VULNERABLE",
            score_delta=50.0,
            confidence=0.9,
        )
        session.add(dec)
        await session.commit()

    # Verify rows exist before deletion
    async with sm() as session:
        runs = (await session.execute(
            select(ValidationRun).where(ValidationRun.assessment_id == aid)
        )).scalars().all()
        assert len(runs) == 1

    # Delete the assessment via HTTP
    headers = test_app["headers_for"](user)
    resp = client.delete(f"/api/v1/assessments/{aid}", headers=headers)
    assert resp.status_code == 204

    # Assert validation rows are gone
    async with sm() as session:
        remaining_runs = (await session.execute(
            select(ValidationRun).where(ValidationRun.assessment_id == aid)
        )).scalars().all()
        assert len(remaining_runs) == 0

        remaining_decisions = (await session.execute(
            select(ValidationExpertDecision).where(ValidationExpertDecision.validation_run_id == run_id)
        )).scalars().all()
        assert len(remaining_decisions) == 0


@pytest.mark.asyncio
async def test_delete_assessment_no_validation_rows_still_succeeds(test_app):
    """Assessment with no validation rows must still delete cleanly."""
    factory = test_app["db"]
    client = test_app["client"]

    user = await factory.create_user("va_deleter2", "va_del2@corp.local", is_superadmin=True)
    assessment = await factory.create_assessment(
        "NoValidation", "corp.local", workspace_id=None, created_by=user.id
    )

    headers = test_app["headers_for"](user)
    resp = client.delete(f"/api/v1/assessments/{assessment.id}", headers=headers)
    assert resp.status_code == 204
