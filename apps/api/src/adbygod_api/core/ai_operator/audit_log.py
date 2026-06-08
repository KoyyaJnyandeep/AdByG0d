from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from adbygod_api.models import AIOperatorAction


async def log_action(
    db: AsyncSession,
    *,
    session_id: uuid.UUID | None,
    action_type: str,
    technique_id: str | None = None,
    command_executed: str | None = None,
    output_snippet: str | None = None,
    reasoning: str | None = None,
    phase_id: int | None = None,
    worker_id: int | None = None,
) -> AIOperatorAction:
    action = AIOperatorAction(
        id=uuid.uuid4(),
        session_id=session_id,
        action_type=action_type,
        technique_id=technique_id,
        command_executed=command_executed,
        output_snippet=(output_snippet or "")[:2000],
        reasoning=reasoning,
        phase_id=phase_id,
        worker_id=worker_id,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(action)
    await db.commit()
    return action
