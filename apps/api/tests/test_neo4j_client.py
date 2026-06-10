from __future__ import annotations

import pytest

from adbygod_api.config import settings
from adbygod_api.core.graph import neo4j_client


def test_get_driver_raises_before_connect():
    neo4j_client._driver = None  # ensure clean state
    with pytest.raises(RuntimeError, match="not initialised"):
        neo4j_client.get_driver()


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_ensure_schema_is_idempotent(neo4j_driver):
    await neo4j_client.ensure_schema()
    await neo4j_client.ensure_schema()  # second call must not raise
    async with neo4j_client.get_driver().session(database=settings.NEO4J_DATABASE) as s:
        result = await s.run("SHOW CONSTRAINTS YIELD name RETURN count(*) AS n")
        rec = await result.single()
        assert rec["n"] >= 1
