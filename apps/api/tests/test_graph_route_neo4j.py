"""Graph routes served from the Neo4j engine.

The shared ``test_app`` TestClient runs the ASGI app in a different event loop
than the async ``neo4j_driver`` fixture's driver, which would trip the
"future attached to a different loop" guard. So the @neo4j tests here call the
route handler coroutines directly (awaited in the fixture's loop) with the
access-control dependency patched out — authz is covered in
test_authz_route_scoping.py. The two unit tests at the bottom (503/501 mapping)
need no container and run in the default suite.
"""
from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from adbygod_api.config import settings
from adbygod_api.routes import graph as graph_routes

AID = "55555555-5555-5555-5555-555555555555"


async def _seed(driver):
    async with driver.session(database=settings.NEO4J_DATABASE) as s:
        await s.run("MATCH (n {assessment_id:$aid}) DETACH DELETE n", aid=AID)
        await s.run(
            "CREATE (a:Entity {id:'r-src', assessment_id:$aid, entity_type:'USER', "
            "sam_account_name:'svc'}) "
            "CREATE (d:Entity {id:'r-da', assessment_id:$aid, entity_type:'GROUP', "
            "sam_account_name:'Domain Admins', tier:0, is_crown_jewel:true}) "
            "CREATE (a)-[:GENERIC_ALL {id:'r-e1', assessment_id:$aid, risk_weight:1.0, "
            "provenance:'', edge_confidence:1.0}]->(d)",
            aid=AID,
        )


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_paths_route_returns_neo4j_result(neo4j_driver, monkeypatch):
    await _seed(neo4j_driver)
    monkeypatch.setattr(graph_routes, "require_assessment_access", AsyncMock())
    result = await graph_routes.get_exposure_paths(
        assessment_id=uuid.UUID(AID), source_id="r-src", target_id="r-da",
        tier=None, max_paths=20, algorithm="bfs", directed=False, k=1,
        db=None, current_user=MagicMock(),
    )
    assert isinstance(result, list) and result
    assert result[0]["target"] == "r-da"
    assert "r-da" in result[0]["path"]
    assert result[0]["edge_types"] == ["GENERIC_ALL"]


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_paths_route_yen_algorithm(neo4j_driver, monkeypatch):
    await _seed(neo4j_driver)
    monkeypatch.setattr(graph_routes, "require_assessment_access", AsyncMock())
    result = await graph_routes.get_exposure_paths(
        assessment_id=uuid.UUID(AID), source_id="r-src", target_id="r-da",
        tier=None, max_paths=20, algorithm="yen", directed=False, k=3,
        db=None, current_user=MagicMock(),
    )
    assert result and result[0]["target"] == "r-da"


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_data_route_returns_neo4j_export(neo4j_driver, monkeypatch):
    await _seed(neo4j_driver)
    monkeypatch.setattr(graph_routes, "require_assessment_access", AsyncMock())
    data = await graph_routes.get_graph_data(
        assessment_id=uuid.UUID(AID), max_nodes=2000, entity_types=None,
        db=None, current_user=MagicMock(),
    )
    payload = data.model_dump() if hasattr(data, "model_dump") else dict(data)
    assert {n["id"] for n in payload["nodes"]} == {"r-src", "r-da"}
    assert payload["edge_count"] == 1


@pytest.mark.neo4j
@pytest.mark.asyncio
async def test_neighborhood_route_returns_neo4j_subgraph(neo4j_driver, monkeypatch):
    await _seed(neo4j_driver)
    monkeypatch.setattr(graph_routes, "require_assessment_access", AsyncMock())
    nb = await graph_routes.get_neighborhood(
        assessment_id=uuid.UUID(AID), node_id="r-da", hops=1, max_nodes=200,
        db=None, current_user=MagicMock(),
    )
    assert {n["id"] for n in nb["nodes"]} == {"r-src", "r-da"}


def test_run_query_maps_driver_not_initialised_to_503():
    """A RuntimeError from get_driver() (engine not connected) maps to HTTP 503."""
    async def boom():
        raise RuntimeError("Neo4j driver not initialised")

    with pytest.raises(HTTPException) as ei:
        asyncio.run(graph_routes._run_query(boom()))
    assert ei.value.status_code == 503


def test_guarded_route_returns_501(monkeypatch):
    """A Phase-3 analytics route is guarded with 501 before touching Neo4j."""
    monkeypatch.setattr(graph_routes, "require_assessment_access", AsyncMock())
    with pytest.raises(HTTPException) as ei:
        asyncio.run(graph_routes.get_attack_categories(
            assessment_id=uuid.UUID(AID), db=None, current_user=MagicMock(),
        ))
    assert ei.value.status_code == 501
