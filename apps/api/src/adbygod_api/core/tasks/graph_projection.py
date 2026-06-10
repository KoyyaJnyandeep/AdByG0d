"""Celery task: (re)project an assessment's graph into Neo4j after ingest.

Runs under the default prefork pool: each task is a synchronous call in a
forked process, so ``asyncio.run`` (a fresh event loop per task) is correct.
Do NOT switch this worker to the gevent/eventlet cooperative pools without a
loop adapter — ``asyncio.run`` conflicts with their monkeypatched loop.
"""
from __future__ import annotations

import asyncio
import logging
import uuid

from adbygod_api.core.celery_app import celery_app
from adbygod_api.core.graph import neo4j_client, projection
from adbygod_api.database import AsyncSessionLocal
from adbygod_api.models import GraphProjectionState, _utcnow_naive

log = logging.getLogger(__name__)


def enqueue(assessment_id: str) -> None:
    """Fire-and-forget: queue a Neo4j re-projection for ``assessment_id``.

    Single source for enqueuing projection so callers (ingest, the reproject
    route, ai_operator tools) don't each duplicate the ``.delay`` call or
    reach across layers for it.
    """
    project_assessment.delay(str(assessment_id))


async def _set_state(assessment_id: uuid.UUID, **fields) -> None:
    """Upsert the projection-state row for an assessment in a fresh session."""
    async with AsyncSessionLocal() as db:
        state = await db.get(GraphProjectionState, assessment_id)
        if state is None:
            state = GraphProjectionState(assessment_id=assessment_id)
            db.add(state)
        for key, value in fields.items():
            setattr(state, key, value)
        await db.commit()


async def _run(assessment_id: str) -> dict[str, int]:
    # connect()+close() per task: asyncio.run creates a fresh event loop each
    # call and closes it on return. The Neo4j driver binds its internals to the
    # loop alive at creation, so a singleton reused across tasks would operate
    # on a closed loop and fail on the 2nd task in a long-lived worker. Closing
    # here forces the next connect() to build a fresh driver on the new loop.
    aid = uuid.UUID(assessment_id)
    await neo4j_client.connect()
    try:
        async with AsyncSessionLocal() as db:
            result = await projection.reproject_assessment(db, assessment_id)

        # The projection already succeeded; a failure writing "ready" state must
        # NOT propagate (it would retry the expensive projection and wrongly mark
        # the assessment "error"). Log and swallow — state can be re-derived.
        try:
            await _set_state(
                aid,
                status="ready",
                node_count=result.get("nodes", 0),
                edge_count=result.get("edges", 0),
                last_projected_at=_utcnow_naive(),
            )
        except Exception as state_err:
            log.warning("Failed to write ready state for assessment %s: %s", assessment_id, state_err)

        return result
    except Exception:
        # Record error state in a fresh session — the projection session may be
        # unusable after an exception. Never let the state write mask the original.
        try:
            await _set_state(aid, status="error")
        except Exception as state_err:
            log.warning("Failed to record error state for assessment %s: %s", assessment_id, state_err)
        raise
    finally:
        await neo4j_client.close()


@celery_app.task(
    name="graph.project_assessment",
    queue="offensive_jobs",
    acks_late=True,
    reject_on_worker_lost=True,
)
def project_assessment(assessment_id: str) -> dict[str, int]:
    return asyncio.run(_run(assessment_id))
