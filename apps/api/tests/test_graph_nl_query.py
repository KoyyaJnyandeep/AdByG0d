"""
Integration tests for the graph nl-query endpoint.
Verifies every major query pattern returns correct results against real DB data.
"""
from __future__ import annotations

import uuid
import pytest

import adbygod_api.models as models


# ---------------------------------------------------------------------------
# Fixture: assessment with a rich graph for query testing
# ---------------------------------------------------------------------------

@pytest.fixture()
def graph_scenario(test_app):
    db = test_app["db"]
    client = test_app["client"]

    # Users
    superadmin = db.run(db.create_user("operator", "op@corp.local", is_superadmin=True))
    headers = test_app["headers_for"](superadmin)

    assessment = db.run(db.create_assessment(
        "NL Query Test", "corp.local", workspace_id=None, created_by=superadmin.id,
        status=models.AssessmentStatus.COMPLETED,
    ))
    aid = assessment.id

    # Entities
    user_low  = db.run(db.create_entity(aid, entity_type=models.EntityType.USER,
                                         sam_account_name="rahul.low", tier=3))
    user_svc  = db.run(db.create_entity(aid, entity_type=models.EntityType.USER,
                                         sam_account_name="svc.kerberoast", tier=2))
    user_da   = db.run(db.create_entity(aid, entity_type=models.EntityType.USER,
                                         sam_account_name="Administrator", tier=0,
                                         is_crown_jewel=True))
    group_da  = db.run(db.create_entity(aid, entity_type=models.EntityType.GROUP,
                                         sam_account_name="Domain Admins", tier=0,
                                         is_crown_jewel=True))
    comp_dc   = db.run(db.create_entity(aid, entity_type=models.EntityType.COMPUTER,
                                         sam_account_name="DC01$", tier=0))
    comp_ws   = db.run(db.create_entity(aid, entity_type=models.EntityType.COMPUTER,
                                         sam_account_name="WS01$", tier=3))

    # Edges
    db.run(db.create_edge(aid, user_low.id, group_da.id,
                           edge_type=models.EdgeType.GENERIC_ALL))
    db.run(db.create_edge(aid, user_low.id, group_da.id,
                           edge_type=models.EdgeType.WRITE_DACL))
    db.run(db.create_edge(aid, user_svc.id, comp_dc.id,
                           edge_type=models.EdgeType.HAS_SPN))
    db.run(db.create_edge(aid, user_da.id, group_da.id,
                           edge_type=models.EdgeType.MEMBER_OF))
    db.run(db.create_edge(aid, user_low.id, comp_ws.id,
                           edge_type=models.EdgeType.CAN_RDP))
    db.run(db.create_edge(aid, user_da.id, comp_dc.id,
                           edge_type=models.EdgeType.DCSYNC))
    db.run(db.create_edge(aid, user_low.id, comp_dc.id,
                           edge_type=models.EdgeType.ADMIN_TO))

    return {
        "client": client,
        "headers": headers,
        "aid": str(aid),
        "user_low_id": str(user_low.id),
        "user_svc_id": str(user_svc.id),
        "user_da_id": str(user_da.id),
        "group_da_id": str(group_da.id),
        "comp_dc_id": str(comp_dc.id),
        "comp_ws_id": str(comp_ws.id),
    }


def _post_nl(scenario, query: str):
    return scenario["client"].post(
        f"/api/v1/graph/{scenario['aid']}/nl-query",
        json={"query": query},
        headers=scenario["headers"],
    )


# NL graph-query is not yet ported to the Neo4j engine; the route is 501-guarded
# (Phase 4 of the migration). These tests pin the transitional contract: access
# control and input validation still run; a well-formed query returns 501.


def test_nl_query_valid_query_returns_501(graph_scenario):
    r = _post_nl(graph_scenario, "kerberoastable accounts")
    assert r.status_code == 501, f"HTTP {r.status_code}: {r.text}"


def test_nl_query_empty_body_400(graph_scenario):
    """Empty query is rejected with 400 before the engine is consulted."""
    r = _post_nl(graph_scenario, "   ")
    assert r.status_code == 400


def test_nl_query_wrong_assessment_denied(graph_scenario):
    """Access control runs first: a foreign assessment is denied (403/404)."""
    r = graph_scenario["client"].post(
        f"/api/v1/graph/{uuid.uuid4()}/nl-query",
        json={"query": "kerberoastable"},
        headers=graph_scenario["headers"],
    )
    assert r.status_code in (403, 404)
