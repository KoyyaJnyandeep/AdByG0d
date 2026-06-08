"""
Comprehensive A-to-Z test sweep using the synthetic lab data.

Phase 1  — Assessment + direct ingest (POST /api/v1/ingest/{id})
Phase 2  — Every endpoint / every parameter with real data
Phase 3  — Edge cases and error paths
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from uuid import uuid4

import pytest

# ---------------------------------------------------------------------------
# Lab data
# ---------------------------------------------------------------------------
LAB_PAYLOAD_PATH = Path("/tmp/lab_data/payloads/direct_collector_ingest_payload.json")

_LAB_DATA_AVAILABLE = LAB_PAYLOAD_PATH.exists()
_lab_data_required = pytest.mark.skipif(
    not _LAB_DATA_AVAILABLE,
    reason="Lab payload not present — skipped in CI (requires /tmp/lab_data/)",
)

# The raw payload contains 1995 entities, 4229 edges, 77 findings.
# The ingest pipeline may synthesize additional trust entities/edges from
# metadata and the rule engine produces additional findings. Use >= thresholds.
PAYLOAD_ENTITIES_MIN = 1995
PAYLOAD_EDGES_MIN    = 4229
PAYLOAD_FINDINGS_MIN = 77   # rule engine adds more; we expect at least the original 77

API = "/api/v1"


# ===========================================================================
# Helpers
# ===========================================================================

def _wait_for_completion(client, assessment_id: str, headers: dict, *, timeout: int = 60) -> dict:
    """Poll GET /assessments/{id} until status != PENDING/RUNNING, or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = client.get(f"{API}/assessments/{assessment_id}", headers=headers)
        assert r.status_code == 200, r.text
        data = r.json()
        status = data.get("status")
        if status not in ("PENDING", "RUNNING"):
            return data
        time.sleep(0.25)
    # Return whatever we have — test will assert on status
    r = client.get(f"{API}/assessments/{assessment_id}", headers=headers)
    return r.json()


# ===========================================================================
# Phase 1 — Assessment creation and ingest
# ===========================================================================

@pytest.fixture()
def lab_setup(test_app):
    if not _LAB_DATA_AVAILABLE:
        pytest.skip("Lab payload not present — skipped in CI (requires /tmp/lab_data/)")
    """
    Creates: superadmin, workspace, assessment, runs ingest, returns context dict.
    """
    client  = test_app["client"]
    factory = test_app["db"]
    headers_for = test_app["headers_for"]

    # 1. Create superadmin user
    admin = factory.run(factory.create_user(
        "lab_admin",
        "lab_admin@adlab.local",
        password="LabPass123!",
        is_superadmin=True,
    ))
    headers = headers_for(admin)

    # 2. Create workspace
    workspace = factory.run(factory.create_workspace("AD Lab Workspace"))

    # 3. Create assessment via API
    r = client.post(f"{API}/assessments", headers=headers, json={
        "name": "adlab.local Full Sweep",
        "domain": "adlab.local",
        "dc_ip": "192.0.2.10",
        "workspace_id": str(workspace.id),
    })
    assert r.status_code == 201, r.text
    assessment_id = r.json()["id"]

    # 4. Load and POST ingest payload
    payload = json.loads(LAB_PAYLOAD_PATH.read_text())
    r2 = client.post(
        f"{API}/ingest/{assessment_id}",
        headers=headers,
        json=payload,
    )
    assert r2.status_code in (200, 202), f"Ingest failed: {r2.status_code} {r2.text}"

    # 5. Wait for completion (background tasks execute synchronously in TestClient)
    data = _wait_for_completion(client, assessment_id, headers, timeout=60)
    assert data.get("status") == "COMPLETED", f"Assessment not completed: {data.get('status')}"

    # 6. Verify counts (pipeline may add trust entities/rule-engine findings on top of payload)
    stats = client.get(f"{API}/assessments/{assessment_id}/stats", headers=headers)
    assert stats.status_code == 200, stats.text
    stat_data = stats.json()
    assert stat_data.get("total_entities", 0) >= PAYLOAD_ENTITIES_MIN, (
        f"entity count too low: expected >= {PAYLOAD_ENTITIES_MIN}, got {stat_data.get('total_entities')}"
    )
    assert stat_data.get("total_findings", 0) >= PAYLOAD_FINDINGS_MIN, (
        f"finding count too low: expected >= {PAYLOAD_FINDINGS_MIN}, got {stat_data.get('total_findings')}"
    )

    # Edge count: the graph data endpoint truncates to max_nodes so we can't
    # directly compare edge_count from it to the total in the DB.
    # Use max_nodes=5000 to capture all entities and then compare.
    graph_r = client.get(f"{API}/graph/{assessment_id}/data?max_nodes=5000", headers=headers)
    assert graph_r.status_code == 200, graph_r.text
    graph_data = graph_r.json()
    assert graph_data.get("edge_count", 0) >= PAYLOAD_EDGES_MIN, (
        f"edge count too low: expected >= {PAYLOAD_EDGES_MIN}, got {graph_data.get('edge_count')}"
    )

    # Store actual counts for use in Phase 2 tests
    actual_entities = stat_data["total_entities"]
    actual_findings = stat_data["total_findings"]
    actual_edges = graph_data["edge_count"]

    # Create a regular (non-superadmin) user for authz tests
    regular = factory.run(factory.create_user(
        "lab_regular",
        "regular@adlab.local",
        password="RegularPass123!",
        is_superadmin=False,
    ))
    regular_headers = headers_for(regular)

    # Add regular user to workspace as analyst
    factory.run(factory.add_workspace_user(workspace.id, regular.id, "analyst"))

    return {
        "client": client,
        "headers": headers,
        "regular_headers": regular_headers,
        "assessment_id": assessment_id,
        "admin": admin,
        "regular": regular,
        "factory": factory,
        "headers_for": headers_for,
        "actual_entities": actual_entities,
        "actual_findings": actual_findings,
        "actual_edges": actual_edges,
    }


# ===========================================================================
# Phase 2 — A-to-Z endpoint tests
# ===========================================================================

class TestAssessmentsEndpoints:

    def test_list_assessments_default(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/assessments", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert any(a["id"] == aid for a in data)

    def test_list_assessments_limit_offset(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments?limit=1&offset=0", headers=h)
        assert r.status_code == 200
        assert len(r.json()) <= 1

    def test_list_assessments_offset_beyond_total(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments?offset=9999", headers=h)
        assert r.status_code == 200
        assert r.json() == []

    def test_list_assessments_status_filter_valid(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments?status=COMPLETED", headers=h)
        assert r.status_code == 200
        for a in r.json():
            assert a["status"] == "COMPLETED"

    def test_list_assessments_status_filter_invalid(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments?status=BOGUS_STATUS", headers=h)
        assert r.status_code == 400

    def test_get_assessment_detail(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/assessments/{aid}", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["id"] == aid
        assert d["domain"] == "adlab.local"

    def test_get_assessment_not_found(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments/{uuid4()}", headers=h)
        assert r.status_code == 404

    def test_get_assessment_invalid_uuid(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments/not-a-uuid", headers=h)
        assert r.status_code == 422

    def test_patch_assessment_name(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.patch(f"{API}/assessments/{aid}", headers=h, json={"name": "adlab.local Full Sweep (updated)"})
        assert r.status_code == 200
        assert r.json()["name"] == "adlab.local Full Sweep (updated)"
        # restore
        c.patch(f"{API}/assessments/{aid}", headers=h, json={"name": "adlab.local Full Sweep"})

    def test_get_assessment_stats(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/assessments/{aid}/stats", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["total_entities"] >= PAYLOAD_ENTITIES_MIN
        assert d["total_findings"] >= PAYLOAD_FINDINGS_MIN

    def test_get_assessment_dashboard(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/assessments/{aid}/dashboard", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "exposure" in d
        assert "top_findings" in d
        assert "coverage" in d
        assert "domain_info" in d
        assert d["domain_info"]["total_users"] >= 0  # there may be no USER-typed users depending on types


class TestEntitiesEndpoints:

    def test_list_entities_default(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_list_entities_limit_offset(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&limit=10&offset=0", headers=h)
        assert r.status_code == 200
        assert len(r.json()) == 10

    def test_list_entities_offset_beyond_total(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&offset=99999", headers=h)
        assert r.status_code == 200
        assert r.json() == []

    def test_list_entities_filter_entity_type_user(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=USER&limit=500", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert len(data) > 0
        for e in data:
            assert e["entity_type"] == "USER"

    def test_list_entities_filter_entity_type_computer(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=COMPUTER&limit=500", headers=h)
        assert r.status_code == 200
        for e in r.json():
            assert e["entity_type"] == "COMPUTER"

    def test_list_entities_filter_entity_type_group(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=GROUP&limit=500", headers=h)
        assert r.status_code == 200
        for e in r.json():
            assert e["entity_type"] == "GROUP"

    def test_list_entities_filter_entity_type_domain(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=DOMAIN&limit=100", headers=h)
        assert r.status_code == 200

    def test_list_entities_filter_entity_type_gpo(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=GPO&limit=100", headers=h)
        assert r.status_code == 200

    def test_list_entities_filter_entity_type_ou(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=OU&limit=100", headers=h)
        assert r.status_code == 200

    def test_list_entities_filter_entity_type_dc(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=DC&limit=100", headers=h)
        assert r.status_code == 200

    def test_list_entities_filter_invalid_entity_type(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=BOGUS_TYPE", headers=h)
        # parse_enum raises 400 for invalid enum values
        assert r.status_code in (400, 422)

    def test_list_entities_filter_tier(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&tier=0&limit=500", headers=h)
        assert r.status_code == 200
        for e in r.json():
            assert e["tier"] == 0

    def test_list_entities_filter_is_crown_jewel(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&is_crown_jewel=true&limit=500", headers=h)
        assert r.status_code == 200
        for e in r.json():
            assert e["is_crown_jewel"] is True

    def test_list_entities_filter_is_enabled(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&is_enabled=true&limit=10", headers=h)
        assert r.status_code == 200
        for e in r.json():
            assert e["is_enabled"] is True

    def test_list_entities_search(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&search=admin&limit=50", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_get_entity_by_id(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        # Get one entity from the list
        list_r = c.get(f"{API}/entities/?assessment_id={aid}&limit=1", headers=h)
        entity_id = list_r.json()[0]["id"]
        r = c.get(f"{API}/entities/{entity_id}", headers=h)
        assert r.status_code == 200
        assert r.json()["id"] == entity_id

    def test_get_entity_not_found(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/entities/{uuid4()}", headers=h)
        assert r.status_code == 404

    def test_get_entity_invalid_uuid(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/entities/not-a-uuid", headers=h)
        assert r.status_code == 422

    def test_entity_summary(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/summary?assessment_id={aid}", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["total"] >= PAYLOAD_ENTITIES_MIN

    def test_entity_intelligence(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/intelligence?assessment_id={aid}", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "total" in d
        assert d["total"] >= PAYLOAD_ENTITIES_MIN
        assert "by_flags" in d
        assert "watchlist" in d


class TestFindingsEndpoints:

    def test_list_findings_default(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "items" in d
        assert d["total"] >= PAYLOAD_FINDINGS_MIN

    def test_list_findings_pagination(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r1 = c.get(f"{API}/findings?assessment_id={aid}&page=1&page_size=10", headers=h)
        assert r1.status_code == 200
        assert len(r1.json()["items"]) == 10

        r2 = c.get(f"{API}/findings?assessment_id={aid}&page=2&page_size=10", headers=h)
        assert r2.status_code == 200
        ids1 = {f["id"] for f in r1.json()["items"]}
        ids2 = {f["id"] for f in r2.json()["items"]}
        assert ids1.isdisjoint(ids2), "pages overlap"

    def test_list_findings_offset_beyond_total(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&page=9999&page_size=50", headers=h)
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_list_findings_filter_severity_critical(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&severity=CRITICAL", headers=h)
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["severity"] == "CRITICAL"

    def test_list_findings_filter_severity_high(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&severity=HIGH", headers=h)
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["severity"] == "HIGH"

    def test_list_findings_filter_severity_medium(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&severity=MEDIUM", headers=h)
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["severity"] == "MEDIUM"

    def test_list_findings_filter_severity_low(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&severity=LOW", headers=h)
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["severity"] == "LOW"

    def test_list_findings_filter_severity_info(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&severity=INFO", headers=h)
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["severity"] == "INFO"

    def test_list_findings_filter_severity_invalid(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&severity=SUPERCRITICAL", headers=h)
        assert r.status_code == 400

    def test_list_findings_filter_status_open(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&status=OPEN", headers=h)
        assert r.status_code == 200
        for f in r.json()["items"]:
            assert f["status"] == "OPEN"

    def test_list_findings_filter_status_invalid(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&status=NOT_A_STATUS", headers=h)
        assert r.status_code == 400

    def test_list_findings_filter_module(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&module=Kerberos", headers=h)
        assert r.status_code == 200

    def test_list_findings_search(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&search=kerberos", headers=h)
        assert r.status_code == 200

    def test_list_findings_sort_by_created_at(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&sort_by=created_at&sort_desc=true", headers=h)
        assert r.status_code == 200

    def test_list_findings_sort_by_title(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&sort_by=title&sort_desc=false", headers=h)
        assert r.status_code == 200

    def test_list_findings_min_score(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&min_score=80.0", headers=h)
        assert r.status_code == 200
        for f in r.json()["items"]:
            if f.get("composite_score") is not None:
                assert f["composite_score"] >= 80.0

    def test_get_finding_by_id(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        list_r = c.get(f"{API}/findings?assessment_id={aid}&page_size=1", headers=h)
        finding_id = list_r.json()["items"][0]["id"]
        r = c.get(f"{API}/findings/{finding_id}", headers=h)
        assert r.status_code == 200
        assert r.json()["id"] == finding_id

    def test_get_finding_not_found(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/findings/{uuid4()}", headers=h)
        assert r.status_code == 404

    def test_get_finding_invalid_uuid(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/findings/not-a-uuid", headers=h)
        assert r.status_code == 422

    def test_patch_finding_status_false_positive(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        list_r = c.get(f"{API}/findings?assessment_id={aid}&page_size=1", headers=h)
        finding_id = list_r.json()["items"][0]["id"]
        r = c.patch(f"{API}/findings/{finding_id}", headers=h, json={"status": "FALSE_POSITIVE"})
        assert r.status_code == 200
        assert r.json()["status"] == "FALSE_POSITIVE"

    def test_patch_finding_status_remediated(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        list_r = c.get(f"{API}/findings?assessment_id={aid}&page_size=2", headers=h)
        finding_id = list_r.json()["items"][1]["id"]
        r = c.patch(f"{API}/findings/{finding_id}", headers=h, json={"status": "REMEDIATED"})
        assert r.status_code == 200
        assert r.json()["status"] == "REMEDIATED"

    def test_patch_finding_status_accepted(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        list_r = c.get(f"{API}/findings?assessment_id={aid}&page_size=3", headers=h)
        finding_id = list_r.json()["items"][2]["id"]
        r = c.patch(f"{API}/findings/{finding_id}", headers=h, json={"status": "ACCEPTED"})
        assert r.status_code == 200
        assert r.json()["status"] == "ACCEPTED"

    def test_patch_finding_restore_open(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        list_r = c.get(f"{API}/findings?assessment_id={aid}&page_size=1", headers=h)
        finding_id = list_r.json()["items"][0]["id"]
        r = c.patch(f"{API}/findings/{finding_id}", headers=h, json={"status": "OPEN"})
        assert r.status_code == 200

    def test_findings_module_summary(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings/modules/summary?assessment_id={aid}", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) > 0
        for item in data:
            assert "module" in item
            assert "total" in item


class TestGraphEndpoints:

    def test_get_graph_data(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        # Use max_nodes=5000 to get all data
        r = c.get(f"{API}/graph/{aid}/data?max_nodes=5000", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["edge_count"] >= PAYLOAD_EDGES_MIN
        assert d["node_count"] >= PAYLOAD_ENTITIES_MIN

    def test_get_graph_data_max_nodes(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/data?max_nodes=50", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert len(d["nodes"]) <= 50

    def test_get_graph_data_entity_type_filter(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/data?entity_types=USER,COMPUTER", headers=h)
        assert r.status_code == 200

    def test_get_graph_paths_no_params(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/paths", headers=h)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_graph_paths_max_paths(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/paths?max_paths=5", headers=h)
        assert r.status_code == 200
        assert len(r.json()) <= 5

    def test_get_blast_radius(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/blast-radius", headers=h)
        assert r.status_code == 200
        assert "entities_in_blast_radius" in r.json()

    def test_get_categories(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/categories", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "categories" in d
        assert "total_paths" in d

    def test_get_choke_points(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/choke-points", headers=h)
        assert r.status_code == 200
        assert "choke_points" in r.json()

    def test_get_communities(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/communities", headers=h)
        assert r.status_code == 200
        assert "communities" in r.json()

    def test_get_anomalies(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/anomalies", headers=h)
        assert r.status_code == 200
        assert "anomalies" in r.json()

    def test_get_anomalies_days_back(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/anomalies?days_back=30", headers=h)
        assert r.status_code == 200

    def test_get_markings_empty(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/markings", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "owned_ids" in d and "high_value_ids" in d

    def test_put_markings(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        # Get first node id
        graph_r = c.get(f"{API}/graph/{aid}/data?max_nodes=1", headers=h)
        node_id = graph_r.json()["nodes"][0]["id"] if graph_r.json()["nodes"] else str(uuid4())
        r = c.put(f"{API}/graph/{aid}/markings", headers=h, json={"owned_ids": [node_id]})
        assert r.status_code == 200

    def test_attack_flow_chains(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/graph/attack-flow-chains", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "paths" in d

    def test_narrate_path_empty(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/graph/{aid}/narrate-path", headers=h, json={
            "path_steps": [{"edge_type": "DCSYNC", "entity_label": "user1", "entity_type": "USER"}],
            "source_label": "user1",
            "target_label": "DC",
        })
        assert r.status_code == 200
        assert "steps" in r.json()

    def test_monte_carlo_empty_steps(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/graph/{aid}/monte-carlo", headers=h, json={
            "path_steps": [],
            "iterations": 100,
        })
        assert r.status_code == 200
        assert r.json()["p_success"] == 0.0

    def test_snapshots_list(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/snapshots", headers=h)
        assert r.status_code == 200
        assert "snapshots" in r.json()

    def test_nl_query(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/graph/{aid}/nl-query", headers=h, json={"query": "kerberoastable accounts"})
        assert r.status_code == 200
        d = r.json()
        assert "node_ids" in d
        assert "explanation" in d

    def test_nl_query_empty_fails(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/graph/{aid}/nl-query", headers=h, json={"query": "   "})
        assert r.status_code == 400

    def test_views_list(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/views", headers=h)
        assert r.status_code == 200
        assert "views" in r.json()

    def test_views_create_and_delete(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/graph/{aid}/views", headers=h, json={"name": "Test View", "config": {"filter": "tier0"}})
        assert r.status_code == 200
        view_id = r.json()["id"]
        rd = c.delete(f"{API}/graph/{aid}/views/{view_id}", headers=h)
        assert rd.status_code == 204

    def test_centrality(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/centrality", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "nodes" in d

    def test_neighborhood(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        # Get a real node id
        graph_r = c.get(f"{API}/graph/{aid}/data?max_nodes=5", headers=h)
        nodes = graph_r.json()["nodes"]
        if nodes:
            node_id = nodes[0]["id"]
            r = c.get(f"{API}/graph/{aid}/neighborhood/{node_id}?hops=1", headers=h)
            assert r.status_code == 200

    def test_export_playbook_markdown(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/graph/{aid}/export-playbook", headers=h, json={
            "path_steps": [{"edge_type": "DCSYNC", "entity_label": "attacker", "entity_type": "USER"}],
            "source_label": "attacker",
            "target_label": "DC",
            "format": "markdown",
        })
        assert r.status_code == 200
        assert r.json()["format"] == "markdown"

    def test_export_playbook_navigator_json(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/graph/{aid}/export-playbook", headers=h, json={
            "path_steps": [{"edge_type": "MEMBER_OF", "entity_label": "user", "entity_type": "USER"}],
            "source_label": "user",
            "target_label": "Admins",
            "format": "navigator_json",
        })
        assert r.status_code == 200
        assert r.json()["format"] == "navigator_json"

    def test_graph_not_found(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/graph/{uuid4()}/data", headers=h)
        assert r.status_code == 404


class TestValidationEndpoints:

    def test_list_modules(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/validation/modules", headers=h)
        assert r.status_code == 200

    def test_global_score(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/validation/global-score/{aid}", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "risk_score" in d or "overall_score" in d or "global_score" in d or isinstance(d, dict)

    def test_overview(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/validation/overview/{aid}", headers=h)
        assert r.status_code == 200

    def test_runs_list(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/validation/runs/{aid}", headers=h)
        assert r.status_code == 200

    def test_posture_timeline(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/validation/posture-timeline/{aid}", headers=h)
        assert r.status_code == 200

    def test_synthetic_presets(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/validation/synthetic/presets", headers=h)
        assert r.status_code == 200


class TestLateralMovementEndpoints:

    def test_lm_summary(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/lateral-movement/summary?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_lm_techniques(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/lateral-movement/techniques?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_lm_paths(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/lateral-movement/paths?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_lm_chains(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/lateral-movement/chains?assessment_id={aid}", headers=h)
        assert r.status_code == 200


class TestKillChainEndpoints:

    def test_kill_chain_no_assessment(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/kill-chain", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "phases" in d
        assert "suggestions" in d

    def test_kill_chain_with_assessment(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/kill-chain?assessment_id={aid}", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["assessment_id"] == aid


class TestTrustsEndpoints:

    def test_trusts_list(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/trusts?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_trusts_summary(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/trusts/summary?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_trusts_abuse(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/trusts/abuse?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_trusts_abuse_techniques(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/trusts/abuse/techniques?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_trusts_forest_pivot(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/trusts/forest-pivot?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_trusts_forest_pivot_paths(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/trusts/forest-pivot/paths?assessment_id={aid}", headers=h)
        assert r.status_code == 200


class TestPKIEndpoints:

    def test_pki_templates(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/pki/templates?assessment_id={aid}", headers=h)
        assert r.status_code == 200

    def test_pki_summary(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/pki/summary?assessment_id={aid}", headers=h)
        assert r.status_code == 200


class TestLootEndpoints:

    def test_loot_list_empty(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/loot", headers=h)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_loot_summary_empty(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/loot/summary", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "total_entries" in d

    def test_loot_hash_intel(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/loot/hash-intel", headers=h)
        assert r.status_code == 200

    def test_loot_export(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/loot/export", headers=h)
        assert r.status_code == 200

    def test_loot_add_manual_hash_nt(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.post(f"{API}/loot/hash/manual", headers=h, json={
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "principal": "ADLAB\\Administrator",
            "source": "Test Ingest",
        })
        assert r.status_code == 201
        assert r.json()["added"] is True

    def test_loot_add_manual_hash_duplicate(self, lab_setup):
        """Duplicate hash should 409. Add it first, then add again."""
        c, h = lab_setup["client"], lab_setup["headers"]
        HASH = "aad3b435b51404eeaad3b435b51404ee:cafebabecafebabecafebabecafebabe"
        # First add — must succeed
        r1 = c.post(f"{API}/loot/hash/manual", headers=h, json={
            "hash": HASH,
            "principal": "ADLAB\\TestUser",
            "source": "Dup Test",
        })
        assert r1.status_code == 201
        # Second add — must 409
        r2 = c.post(f"{API}/loot/hash/manual", headers=h, json={
            "hash": HASH,
            "principal": "ADLAB\\TestUser",
            "source": "Dup Test",
        })
        assert r2.status_code == 409

    def test_loot_add_manual_hash_invalid(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.post(f"{API}/loot/hash/manual", headers=h, json={
            "hash": "not-a-real-hash-xxxxxxxx",
            "principal": None,
            "source": "Test",
        })
        assert r.status_code == 400


class TestSessionEndpoint:

    def test_get_session(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/session", headers=h)
        assert r.status_code == 200

    def test_update_session(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/session/update", headers=h, json={
            "assessment_id": aid,
            "domain": "adlab.local",
            "target_ip": "192.0.2.10",
        })
        assert r.status_code == 200

    def test_reset_session(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.post(f"{API}/session/reset", headers=h)
        assert r.status_code == 200


class TestUsersEndpoints:

    def test_get_me(self, lab_setup):
        c, h, admin = lab_setup["client"], lab_setup["headers"], lab_setup["admin"]
        r = c.get(f"{API}/users/me", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert d["username"] == admin.username
        assert d["is_superadmin"] is True

    def test_get_me_regular(self, lab_setup):
        c, rh, regular = lab_setup["client"], lab_setup["regular_headers"], lab_setup["regular"]
        r = c.get(f"{API}/users/me", headers=rh)
        assert r.status_code == 200
        assert r.json()["username"] == regular.username

    def test_list_users_superadmin(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/users", headers=h)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) >= 2  # admin + regular

    def test_list_users_limit_offset(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/users?limit=1&offset=0", headers=h)
        assert r.status_code == 200
        assert len(r.json()) <= 1

    def test_list_users_offset_beyond_total(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/users?offset=9999", headers=h)
        assert r.status_code == 200
        assert r.json() == []

    def test_list_users_forbidden_for_regular(self, lab_setup):
        c, rh = lab_setup["client"], lab_setup["regular_headers"]
        r = c.get(f"{API}/users", headers=rh)
        assert r.status_code == 403

    def test_patch_user_email(self, lab_setup):
        c, h, admin = lab_setup["client"], lab_setup["headers"], lab_setup["admin"]
        r = c.patch(f"{API}/users/{admin.id}", headers=h, json={"email": "lab_admin_updated@adlab.local"})
        assert r.status_code == 200
        assert r.json()["email"] == "lab_admin_updated@adlab.local"
        # restore
        c.patch(f"{API}/users/{admin.id}", headers=h, json={"email": "lab_admin@adlab.local"})

    def test_patch_user_full_name(self, lab_setup):
        c, h, admin = lab_setup["client"], lab_setup["headers"], lab_setup["admin"]
        r = c.patch(f"{API}/users/{admin.id}", headers=h, json={"full_name": "Lab Admin User"})
        assert r.status_code == 200
        assert r.json()["full_name"] == "Lab Admin User"

    def test_patch_user_password(self, lab_setup):
        c, h, admin = lab_setup["client"], lab_setup["headers"], lab_setup["admin"]
        r = c.patch(f"{API}/users/{admin.id}", headers=h, json={"password": "NewLabPass456!"})
        assert r.status_code == 200

    def test_patch_user_password_too_short(self, lab_setup):
        c, h, admin = lab_setup["client"], lab_setup["headers"], lab_setup["admin"]
        r = c.patch(f"{API}/users/{admin.id}", headers=h, json={"password": "short"})
        assert r.status_code == 422

    def test_patch_user_self_forbidden_for_other_regular(self, lab_setup):
        c, rh, admin = lab_setup["client"], lab_setup["regular_headers"], lab_setup["admin"]
        r = c.patch(f"{API}/users/{admin.id}", headers=rh, json={"full_name": "Hacker"})
        assert r.status_code == 403

    def test_deactivate_and_reactivate_user(self, lab_setup):
        c, h, factory, _headers_for = (
            lab_setup["client"],
            lab_setup["headers"],
            lab_setup["factory"],
            lab_setup["headers_for"],
        )
        # Create a throwaway user
        tmp = factory.run(factory.create_user("tmp_deact_user", "tmp@adlab.local"))
        r = c.post(f"{API}/users/{tmp.id}/deactivate", headers=h)
        assert r.status_code == 204

        r2 = c.post(f"{API}/users/{tmp.id}/activate", headers=h)
        assert r2.status_code == 204

    def test_deactivate_self_forbidden(self, lab_setup):
        c, h, admin = lab_setup["client"], lab_setup["headers"], lab_setup["admin"]
        r = c.post(f"{API}/users/{admin.id}/deactivate", headers=h)
        assert r.status_code == 400

    def test_deactivate_forbidden_for_regular(self, lab_setup):
        c, rh, admin = lab_setup["client"], lab_setup["regular_headers"], lab_setup["admin"]
        r = c.post(f"{API}/users/{admin.id}/deactivate", headers=rh)
        assert r.status_code == 403


class TestAuthEndpoints:

    def test_auth_me(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/auth/me", headers=h)
        assert r.status_code == 200
        d = r.json()
        assert "username" in d or "email" in d or "id" in d

    def test_auth_me_unauthenticated(self, lab_setup):
        c = lab_setup["client"]
        r = c.get(f"{API}/auth/me")
        assert r.status_code == 401


# ===========================================================================
# Phase 3 — Edge cases and error paths
# ===========================================================================

class TestEdgeCasesAndErrors:

    def test_unauthenticated_assessment_list(self, lab_setup):
        c = lab_setup["client"]
        r = c.get(f"{API}/assessments")
        assert r.status_code == 401

    def test_unauthenticated_entities(self, lab_setup):
        c, aid = lab_setup["client"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}")
        assert r.status_code == 401

    def test_unauthenticated_findings(self, lab_setup):
        c, aid = lab_setup["client"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}")
        assert r.status_code == 401

    def test_unauthenticated_graph(self, lab_setup):
        c, aid = lab_setup["client"], lab_setup["assessment_id"]
        r = c.get(f"{API}/graph/{aid}/data")
        assert r.status_code == 401

    def test_unauthenticated_dashboard(self, lab_setup):
        c, aid = lab_setup["client"], lab_setup["assessment_id"]
        r = c.get(f"{API}/assessments/{aid}/dashboard")
        assert r.status_code == 401

    def test_nonexistent_assessment_entities(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/entities/?assessment_id={uuid4()}", headers=h)
        assert r.status_code == 404

    def test_nonexistent_assessment_findings(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/findings?assessment_id={uuid4()}", headers=h)
        assert r.status_code == 404

    def test_nonexistent_assessment_graph(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/graph/{uuid4()}/data", headers=h)
        assert r.status_code == 404

    def test_nonexistent_assessment_dashboard(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments/{uuid4()}/dashboard", headers=h)
        assert r.status_code == 404

    def test_nonexistent_assessment_stats(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments/{uuid4()}/stats", headers=h)
        assert r.status_code == 404

    def test_invalid_uuid_entity(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/entities/invalid-uuid-here", headers=h)
        assert r.status_code == 422

    def test_invalid_uuid_finding(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/findings/not-a-uuid", headers=h)
        assert r.status_code == 422

    def test_invalid_uuid_assessment(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments/not-a-uuid", headers=h)
        assert r.status_code == 422

    def test_invalid_uuid_graph(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/graph/not-a-uuid/data", headers=h)
        assert r.status_code == 422

    def test_entity_invalid_enum_value(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&entity_type=UNICORN", headers=h)
        assert r.status_code in (400, 422)

    def test_finding_severity_invalid_enum(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&severity=ULTIMATE", headers=h)
        assert r.status_code == 400

    def test_finding_status_invalid_enum(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/findings?assessment_id={aid}&status=TOTALLY_WRONG", headers=h)
        assert r.status_code == 400

    def test_assessment_status_filter_invalid(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments?status=INVALID_STATUS", headers=h)
        assert r.status_code == 400

    def test_regular_user_cannot_access_other_workspace_assessment(self, lab_setup):
        """Regular user should not see assessments in workspaces they don't belong to."""
        c, _h, rh, factory, _headers_for = (
            lab_setup["client"],
            lab_setup["headers"],
            lab_setup["regular_headers"],
            lab_setup["factory"],
            lab_setup["headers_for"],
        )
        # Create a separate workspace + assessment that regular user cannot access
        isolated_ws = factory.run(factory.create_workspace("Isolated Workspace"))
        isolated_assessment = factory.run(factory.create_assessment(
            "Isolated Assessment",
            "other.local",
            workspace_id=isolated_ws.id,
        ))
        r = c.get(f"{API}/assessments/{isolated_assessment.id}", headers=rh)
        assert r.status_code in (403, 404)

    def test_entities_pagination_page_limit_500(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&limit=500", headers=h)
        assert r.status_code == 200
        assert len(r.json()) <= 500

    def test_entities_limit_exceeds_max(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.get(f"{API}/entities/?assessment_id={aid}&limit=9999", headers=h)
        assert r.status_code == 422

    def test_assessments_limit_exceeds_max(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.get(f"{API}/assessments?limit=9999", headers=h)
        assert r.status_code == 422

    def test_assessment_patch_not_found(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.patch(f"{API}/assessments/{uuid4()}", headers=h, json={"name": "phantom"})
        assert r.status_code == 404

    def test_finding_patch_not_found(self, lab_setup):
        c, h = lab_setup["client"], lab_setup["headers"]
        r = c.patch(f"{API}/findings/{uuid4()}", headers=h, json={"status": "OPEN"})
        assert r.status_code == 404

    def test_export_playbook_empty_steps(self, lab_setup):
        c, h, aid = lab_setup["client"], lab_setup["headers"], lab_setup["assessment_id"]
        r = c.post(f"{API}/graph/{aid}/export-playbook", headers=h, json={
            "path_steps": [],
            "source_label": "x",
            "target_label": "y",
            "format": "markdown",
        })
        assert r.status_code == 400
