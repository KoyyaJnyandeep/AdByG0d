"""
A-to-Z test sweep using the BIG synthetic lab data (megacorp.local).
7527 entities · 9756 edges · 78 findings · 30 cert templates

Phase 1  — Assessment creation + direct ingest (POST /api/v1/ingest/{id})
Phase 2  — Every endpoint / every parameter with real data
Phase 3  — Edge cases, error paths, boundary values
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from uuid import uuid4

import pytest

BIG_LAB_PATH = Path("/tmp/big_lab_data/payloads/direct_collector_ingest_payload.json")
_BIG_LAB_AVAILABLE = BIG_LAB_PATH.exists()

PAYLOAD_ENTITIES_MIN = 7527
PAYLOAD_FINDINGS_MIN = 78
PAYLOAD_CERT_MIN     = 30

API = "/api/v1"


# ===========================================================================
# Helpers
# ===========================================================================

def _wait_for_completion(client, assessment_id: str, headers: dict, *, timeout: int = 120) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = client.get(f"{API}/assessments/{assessment_id}", headers=headers)
        assert r.status_code == 200, r.text
        data = r.json()
        if data.get("status") not in ("PENDING", "RUNNING"):
            return data
        time.sleep(0.3)
    return client.get(f"{API}/assessments/{assessment_id}", headers=headers).json()


# ===========================================================================
# Phase 1 — Setup fixture
# ===========================================================================

@pytest.fixture()
def big_lab(test_app):
    """Creates superadmin, workspace, assessment, ingests big lab data."""
    if not _BIG_LAB_AVAILABLE:
        pytest.skip("Big lab payload not present — skipped in CI (requires /tmp/big_lab_data/)")
    client      = test_app["client"]
    factory     = test_app["db"]
    headers_for = test_app["headers_for"]

    admin = factory.run(factory.create_user(
        "biglab_admin", "biglab_admin@megacorp.local",
        password="BigLabPass1!", is_superadmin=True,
    ))
    headers = headers_for(admin)

    regular = factory.run(factory.create_user(
        "biglab_regular", "biglab_regular@megacorp.local",
        password="RegularPass1!", is_superadmin=False,
    ))
    reg_headers = headers_for(regular)

    workspace = factory.run(factory.create_workspace("MegaCorp Lab Workspace"))
    factory.run(factory.add_workspace_user(workspace.id, admin.id, role="admin"))
    factory.run(factory.add_workspace_user(workspace.id, regular.id, role="analyst"))

    r = client.post(f"{API}/assessments", headers=headers, json={
        "name": "megacorp.local Big Lab Sweep",
        "domain": "megacorp.local",
        "dc_ip": "192.0.2.20",
        "workspace_id": str(workspace.id),
    })
    assert r.status_code == 201, r.text
    aid = r.json()["id"]

    payload = json.loads(BIG_LAB_PATH.read_text())
    r2 = client.post(f"{API}/ingest/{aid}", headers=headers, json=payload)
    assert r2.status_code in (200, 202), f"Ingest failed: {r2.status_code} {r2.text}"

    data = _wait_for_completion(client, aid, headers, timeout=120)
    assert data.get("status") == "COMPLETED", f"Not completed: {data.get('status')} — {data}"

    stats = client.get(f"{API}/assessments/{aid}/stats", headers=headers)
    assert stats.status_code == 200, stats.text
    sd = stats.json()
    assert sd.get("total_entities", 0) >= PAYLOAD_ENTITIES_MIN, (
        f"entities {sd.get('total_entities')} < {PAYLOAD_ENTITIES_MIN}"
    )
    assert sd.get("total_findings", 0) >= PAYLOAD_FINDINGS_MIN, (
        f"findings {sd.get('total_findings')} < {PAYLOAD_FINDINGS_MIN}"
    )

    yield {
        "client": client,
        "h": headers,
        "rh": reg_headers,
        "aid": aid,
        "admin": admin,
        "regular": regular,
        "workspace_id": str(workspace.id),
        "stats": sd,
    }


# ===========================================================================
# Phase 1 — Ingest validation
# ===========================================================================

class TestBigLabIngest:

    def test_entity_count_meets_minimum(self, big_lab):
        assert big_lab["stats"]["total_entities"] >= PAYLOAD_ENTITIES_MIN

    def test_finding_count_meets_minimum(self, big_lab):
        assert big_lab["stats"]["total_findings"] >= PAYLOAD_FINDINGS_MIN

    def test_assessment_status_completed(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/{big_lab['aid']}", headers=big_lab["h"]
        )
        assert r.json()["status"] == "COMPLETED"

    def test_domain_stored_correctly(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/{big_lab['aid']}", headers=big_lab["h"]
        )
        assert r.json()["domain"] == "megacorp.local"

    def test_dc_ip_stored(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/{big_lab['aid']}", headers=big_lab["h"]
        )
        assert r.json().get("dc_ip") == "192.0.2.20"

    def test_modules_run_populated(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/{big_lab['aid']}", headers=big_lab["h"]
        )
        assert len(r.json().get("modules_run") or []) >= 5


# ===========================================================================
# Phase 2 — Assessments
# ===========================================================================

class TestAssessmentsEndpoints:

    def test_list_assessments(self, big_lab):
        r = big_lab["client"].get(f"{API}/assessments", headers=big_lab["h"])
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_list_pagination_limit(self, big_lab):
        r = big_lab["client"].get(f"{API}/assessments?limit=1", headers=big_lab["h"])
        assert r.status_code == 200
        assert len(r.json()) <= 1

    def test_list_pagination_offset_beyond(self, big_lab):
        r = big_lab["client"].get(f"{API}/assessments?offset=9999", headers=big_lab["h"])
        assert r.status_code == 200

    def test_list_filter_status_completed(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments?status=COMPLETED", headers=big_lab["h"]
        )
        assert r.status_code == 200
        for a in r.json():
            assert a["status"] == "COMPLETED"

    def test_get_assessment_detail(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/{big_lab['aid']}", headers=big_lab["h"]
        )
        assert r.status_code == 200
        assert r.json()["id"] == big_lab["aid"]

    def test_patch_assessment_name(self, big_lab):
        r = big_lab["client"].patch(
            f"{API}/assessments/{big_lab['aid']}", headers=big_lab["h"],
            json={"name": "megacorp.local Big Lab Sweep (updated)"},
        )
        assert r.status_code == 200
        assert "updated" in r.json()["name"]

    def test_assessment_stats(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/{big_lab['aid']}/stats", headers=big_lab["h"]
        )
        assert r.status_code == 200
        assert r.json()["total_entities"] >= PAYLOAD_ENTITIES_MIN

    def test_assessment_dashboard(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/{big_lab['aid']}/dashboard", headers=big_lab["h"]
        )
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — Entities  (correct path: /entities/?assessment_id=...)
# ===========================================================================

class TestEntitiesEndpoints:

    def _e(self, big_lab, **params):
        return big_lab["client"].get(
            f"{API}/entities/", headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"], **params},
        )

    def test_list_entities_default(self, big_lab):
        r = self._e(big_lab)
        assert r.status_code == 200
        assert len(r.json()) > 0

    def test_filter_entity_type_user(self, big_lab):
        r = self._e(big_lab, entity_type="USER", limit=20)
        assert r.status_code == 200
        assert all(e["entity_type"] == "USER" for e in r.json())

    def test_filter_entity_type_computer(self, big_lab):
        r = self._e(big_lab, entity_type="COMPUTER", limit=20)
        assert r.status_code == 200
        assert all(e["entity_type"] == "COMPUTER" for e in r.json())

    def test_filter_entity_type_group(self, big_lab):
        r = self._e(big_lab, entity_type="GROUP", limit=20)
        assert r.status_code == 200

    def test_filter_entity_type_domain(self, big_lab):
        r = self._e(big_lab, entity_type="DOMAIN", limit=20)
        assert r.status_code == 200
        assert len(r.json()) >= 1

    def test_filter_entity_type_gpo(self, big_lab):
        r = self._e(big_lab, entity_type="GPO", limit=20)
        assert r.status_code == 200

    def test_filter_entity_type_ou(self, big_lab):
        r = self._e(big_lab, entity_type="OU", limit=20)
        assert r.status_code == 200

    def test_filter_tier_0(self, big_lab):
        r = self._e(big_lab, tier=0, limit=500)
        assert r.status_code == 200
        assert len(r.json()) >= 1
        assert all(e.get("tier") == 0 for e in r.json())

    def test_filter_tier_1(self, big_lab):
        r = self._e(big_lab, tier=1, limit=50)
        assert r.status_code == 200

    def test_filter_crown_jewels(self, big_lab):
        r = self._e(big_lab, is_crown_jewel=True, limit=500)
        assert r.status_code == 200
        assert len(r.json()) >= 1
        assert all(e.get("is_crown_jewel") is True for e in r.json())

    def test_filter_enabled(self, big_lab):
        r = self._e(big_lab, is_enabled=True, limit=10)
        assert r.status_code == 200

    def test_search(self, big_lab):
        r = self._e(big_lab, search="admin", limit=50)
        assert r.status_code == 200

    def test_pagination(self, big_lab):
        p1 = self._e(big_lab, limit=10, offset=0).json()
        p2 = self._e(big_lab, limit=10, offset=10).json()
        if len(p1) == 10 and len(p2) == 10:
            assert p1[0]["id"] != p2[0]["id"]

    def test_large_limit(self, big_lab):
        r = self._e(big_lab, limit=500)
        assert r.status_code == 200

    def test_get_entity_by_id(self, big_lab):
        items = self._e(big_lab, limit=1).json()
        eid = items[0]["id"]
        r = big_lab["client"].get(
            f"{API}/entities/{eid}", headers=big_lab["h"]
        )
        assert r.status_code == 200
        assert r.json()["id"] == eid

    def test_entity_summary(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/entities/summary",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_entity_intelligence(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/entities/intelligence",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_combined_filter(self, big_lab):
        r = self._e(big_lab, entity_type="COMPUTER", search="WS", limit=20)
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — Findings  (correct path: /findings?assessment_id=...)
# ===========================================================================

class TestFindingsEndpoints:

    def _f(self, big_lab, **params):
        return big_lab["client"].get(
            f"{API}/findings",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"], **params},
        )

    def test_list_findings_default(self, big_lab):
        r = self._f(big_lab, page_size=200)
        assert r.status_code == 200
        data = r.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        assert len(items) >= PAYLOAD_FINDINGS_MIN

    def test_filter_severity_critical(self, big_lab):
        r = self._f(big_lab, severity="CRITICAL", page_size=100)
        assert r.status_code == 200

    def test_filter_severity_high(self, big_lab):
        r = self._f(big_lab, severity="HIGH", page_size=100)
        assert r.status_code == 200

    def test_filter_severity_medium(self, big_lab):
        r = self._f(big_lab, severity="MEDIUM")
        assert r.status_code == 200

    def test_filter_severity_low(self, big_lab):
        r = self._f(big_lab, severity="LOW")
        assert r.status_code == 200

    def test_filter_severity_info(self, big_lab):
        r = self._f(big_lab, severity="INFO")
        assert r.status_code == 200

    def test_filter_module_kerberos(self, big_lab):
        r = self._f(big_lab, module="Kerberos")
        assert r.status_code == 200

    def test_filter_module_acl(self, big_lab):
        r = self._f(big_lab, module="ACL")
        assert r.status_code == 200

    def test_filter_module_adcs(self, big_lab):
        r = self._f(big_lab, module="ADCS")
        assert r.status_code == 200

    def test_search(self, big_lab):
        r = self._f(big_lab, search="kerberoast")
        assert r.status_code == 200

    def test_pagination(self, big_lab):
        r1 = self._f(big_lab, page=1, page_size=10).json()
        r2 = self._f(big_lab, page=2, page_size=10).json()
        items1 = r1.get("items", r1) if isinstance(r1, dict) else r1
        items2 = r2.get("items", r2) if isinstance(r2, dict) else r2
        if len(items1) == 10 and len(items2) == 10:
            assert items1[0]["id"] != items2[0]["id"]

    def test_sort_by_title(self, big_lab):
        r = self._f(big_lab, sort_by="title", sort_desc=False)
        assert r.status_code == 200

    def test_sort_desc(self, big_lab):
        r = self._f(big_lab, sort_by="created_at", sort_desc=True)
        assert r.status_code == 200

    def test_filter_status_open(self, big_lab):
        r = self._f(big_lab, status="OPEN")
        assert r.status_code == 200

    def test_get_finding_by_id(self, big_lab):
        raw = self._f(big_lab, page_size=1).json()
        items = raw.get("items", raw) if isinstance(raw, dict) else raw
        fid = items[0]["id"]
        r = big_lab["client"].get(f"{API}/findings/{fid}", headers=big_lab["h"])
        assert r.status_code == 200
        assert r.json()["id"] == fid

    def test_patch_finding_false_positive(self, big_lab):
        raw = self._f(big_lab, page_size=1).json()
        items = raw.get("items", raw) if isinstance(raw, dict) else raw
        fid = items[0]["id"]
        r = big_lab["client"].patch(
            f"{API}/findings/{fid}", headers=big_lab["h"],
            json={"status": "FALSE_POSITIVE"},
        )
        assert r.status_code == 200

    def test_patch_finding_back_to_open(self, big_lab):
        raw = self._f(big_lab, page_size=1).json()
        items = raw.get("items", raw) if isinstance(raw, dict) else raw
        fid = items[0]["id"]
        big_lab["client"].patch(
            f"{API}/findings/{fid}", headers=big_lab["h"],
            json={"status": "FALSE_POSITIVE"},
        )
        r = big_lab["client"].patch(
            f"{API}/findings/{fid}", headers=big_lab["h"],
            json={"status": "OPEN"},
        )
        assert r.status_code == 200

    def test_min_score_filter(self, big_lab):
        r = self._f(big_lab, min_score=80.0)
        assert r.status_code == 200

    def test_modules_summary(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/findings/modules/summary",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_adcs_findings_exist(self, big_lab):
        r = self._f(big_lab, module="ADCS", page_size=50)
        assert r.status_code == 200
        raw = r.json()
        items = raw.get("items", raw) if isinstance(raw, dict) else raw
        assert len(items) >= 1

    def test_kerberos_findings_exist(self, big_lab):
        r = self._f(big_lab, module="Kerberos", page_size=50)
        assert r.status_code == 200
        raw = r.json()
        items = raw.get("items", raw) if isinstance(raw, dict) else raw
        assert len(items) >= 1


# ===========================================================================
# Phase 2 — Graph  (correct path: /graph/{assessment_id}/...)
# ===========================================================================

class TestGraphEndpoints:

    def test_graph_data_default(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/data?max_nodes=5000",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_max_nodes_50(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/data?max_nodes=50",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_max_nodes_1(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/data?max_nodes=1",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_filter_entity_types(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/data?entity_types=USER,COMPUTER&max_nodes=100",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_attack_paths(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/paths",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_paths_max_paths(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/paths?max_paths=5",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_blast_radius(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/blast-radius",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_categories(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/categories",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_choke_points(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/choke-points",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_communities(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/communities",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_centrality(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/centrality",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_markings(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/markings",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_snapshots(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/snapshots",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_anomalies(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/anomalies",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_views_list(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{big_lab['aid']}/views",
            headers=big_lab["h"],
        )
        assert r.status_code == 200

    def test_graph_attack_flow_chains(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/attack-flow-chains",
            headers=big_lab["h"],
        )
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — Lateral movement  (/lateral-movement/...?assessment_id=)
# ===========================================================================

class TestLateralMovementEndpoints:

    def test_summary(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/lateral-movement/summary",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_techniques(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/lateral-movement/techniques",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_paths(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/lateral-movement/paths",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_chains(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/lateral-movement/chains",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — Kill chain
# ===========================================================================

class TestKillChainEndpoints:

    def test_with_assessment_id(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/kill-chain",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_without_assessment_id(self, big_lab):
        r = big_lab["client"].get(f"{API}/kill-chain", headers=big_lab["h"])
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — Trusts  (/trusts?assessment_id=...)
# ===========================================================================

class TestTrustsEndpoints:

    def test_list(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/trusts",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_summary(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/trusts/summary",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_abuse(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/trusts/abuse",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_abuse_techniques(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/trusts/abuse/techniques",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_forest_pivot(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/trusts/forest-pivot",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200

    def test_forest_pivot_paths(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/trusts/forest-pivot/paths",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — PKI  (/pki/...?assessment_id=...)
# ===========================================================================

class TestPKIEndpoints:

    def test_templates(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/pki/templates",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200
        assert len(r.json()) >= PAYLOAD_CERT_MIN

    def test_summary(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/pki/summary",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — Loot  (/loot/...)
# ===========================================================================

class TestLootEndpoints:

    def test_list(self, big_lab):
        r = big_lab["client"].get(f"{API}/loot", headers=big_lab["h"])
        assert r.status_code == 200

    def test_summary(self, big_lab):
        r = big_lab["client"].get(f"{API}/loot/summary", headers=big_lab["h"])
        assert r.status_code == 200

    def test_hash_intel(self, big_lab):
        r = big_lab["client"].get(f"{API}/loot/hash-intel", headers=big_lab["h"])
        assert r.status_code == 200

    def test_export(self, big_lab):
        r = big_lab["client"].get(f"{API}/loot/export", headers=big_lab["h"])
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — Validation  (/validation/...)
# ===========================================================================

class TestValidationEndpoints:

    def test_modules(self, big_lab):
        r = big_lab["client"].get(f"{API}/validation/modules", headers=big_lab["h"])
        assert r.status_code == 200

    def test_global_score(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/validation/global-score/{big_lab['aid']}", headers=big_lab["h"]
        )
        assert r.status_code == 200

    def test_overview(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/validation/overview/{big_lab['aid']}", headers=big_lab["h"]
        )
        assert r.status_code == 200

    def test_runs(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/validation/runs/{big_lab['aid']}", headers=big_lab["h"]
        )
        assert r.status_code == 200

    def test_synthetic_presets(self, big_lab):
        r = big_lab["client"].get(f"{API}/validation/synthetic/presets", headers=big_lab["h"])
        assert r.status_code == 200


# ===========================================================================
# Phase 2 — Users
# ===========================================================================

class TestUsersEndpoints:

    def test_get_me(self, big_lab):
        r = big_lab["client"].get(f"{API}/users/me", headers=big_lab["h"])
        assert r.status_code == 200
        assert r.json()["username"] == "biglab_admin"

    def test_list_users_superadmin(self, big_lab):
        r = big_lab["client"].get(f"{API}/users", headers=big_lab["h"])
        assert r.status_code == 200
        assert len(r.json()) >= 2

    def test_list_forbidden_regular(self, big_lab):
        r = big_lab["client"].get(f"{API}/users", headers=big_lab["rh"])
        assert r.status_code == 403

    def test_update_own_email(self, big_lab):
        uid = big_lab["regular"].id
        r = big_lab["client"].patch(
            f"{API}/users/{uid}", headers=big_lab["rh"],
            json={"email": "biglab_regular_new@megacorp.local"},
        )
        assert r.status_code == 200

    def test_update_own_full_name(self, big_lab):
        uid = big_lab["regular"].id
        r = big_lab["client"].patch(
            f"{API}/users/{uid}", headers=big_lab["rh"],
            json={"full_name": "Big Lab Regular"},
        )
        assert r.status_code == 200

    def test_update_own_password(self, big_lab):
        uid = big_lab["regular"].id
        r = big_lab["client"].patch(
            f"{API}/users/{uid}", headers=big_lab["rh"],
            json={"password": "NewBigLabPass99!"},
        )
        assert r.status_code == 200

    def test_superadmin_updates_other(self, big_lab):
        uid = big_lab["regular"].id
        r = big_lab["client"].patch(
            f"{API}/users/{uid}", headers=big_lab["h"],
            json={"full_name": "Updated by Admin"},
        )
        assert r.status_code == 200

    def test_regular_cannot_update_other(self, big_lab):
        uid = big_lab["admin"].id
        r = big_lab["client"].patch(
            f"{API}/users/{uid}", headers=big_lab["rh"],
            json={"full_name": "Hacked"},
        )
        assert r.status_code == 403

    def test_deactivate_and_reactivate(self, big_lab):
        uid = big_lab["regular"].id
        r1 = big_lab["client"].post(
            f"{API}/users/{uid}/deactivate", headers=big_lab["h"]
        )
        assert r1.status_code == 204
        r2 = big_lab["client"].post(
            f"{API}/users/{uid}/activate", headers=big_lab["h"]
        )
        assert r2.status_code == 204

    def test_list_pagination(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/users?limit=1&offset=0", headers=big_lab["h"]
        )
        assert r.status_code == 200
        assert len(r.json()) <= 1


# ===========================================================================
# Phase 2 — Auth
# ===========================================================================

class TestAuthEndpoints:

    def test_get_me_authenticated(self, big_lab):
        r = big_lab["client"].get(f"{API}/auth/me", headers=big_lab["h"])
        assert r.status_code == 200
        assert r.json()["username"] == "biglab_admin"

    def test_get_me_unauthenticated(self, big_lab):
        r = big_lab["client"].get(f"{API}/auth/me")
        assert r.status_code == 401


# ===========================================================================
# Phase 3 — Edge cases and error paths
# ===========================================================================

class TestEdgeCasesAndErrors:

    FAKE_ID = str(uuid4())

    # 401 — no auth on protected routes
    def test_401_entities_no_auth(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/entities/",
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 401

    def test_401_findings_no_auth(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/findings",
            params={"assessment_id": big_lab["aid"]},
        )
        assert r.status_code == 401

    def test_401_graph_no_auth(self, big_lab):
        r = big_lab["client"].get(f"{API}/graph/{big_lab['aid']}/data")
        assert r.status_code == 401

    # 404 — non-existent resources
    def test_404_nonexistent_assessment(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/{self.FAKE_ID}", headers=big_lab["h"]
        )
        assert r.status_code == 404

    def test_404_nonexistent_entity(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/entities/{self.FAKE_ID}", headers=big_lab["h"]
        )
        assert r.status_code == 404

    def test_404_graph_nonexistent_assessment(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/{uuid4()}/data", headers=big_lab["h"]
        )
        assert r.status_code == 404

    # 422 — invalid inputs
    def test_422_invalid_assessment_uuid(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments/not-a-uuid", headers=big_lab["h"]
        )
        assert r.status_code == 422

    def test_422_invalid_entity_uuid(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/entities/not-a-uuid", headers=big_lab["h"]
        )
        assert r.status_code == 422

    def test_422_invalid_entity_type_filter(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/entities/",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"], "entity_type": "BOGUS_TYPE"},
        )
        assert r.status_code in (400, 422)

    def test_422_invalid_severity_filter(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/findings",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"], "severity": "SUPERCRITICAL"},
        )
        assert r.status_code in (400, 422)

    def test_422_entities_limit_too_large(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/entities/",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"], "limit": 9999},
        )
        assert r.status_code == 422

    def test_422_graph_invalid_uuid(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/graph/not-a-uuid/data", headers=big_lab["h"]
        )
        assert r.status_code == 422

    # 403 — authorization failures
    def test_403_users_list_regular(self, big_lab):
        r = big_lab["client"].get(f"{API}/users", headers=big_lab["rh"])
        assert r.status_code == 403

    def test_403_cannot_update_other_user(self, big_lab):
        r = big_lab["client"].patch(
            f"{API}/users/{big_lab['admin'].id}",
            headers=big_lab["rh"],
            json={"full_name": "Hacked"},
        )
        assert r.status_code == 403

    # 400 — business logic errors
    def test_400_cannot_deactivate_self(self, big_lab):
        r = big_lab["client"].post(
            f"{API}/users/{big_lab['admin'].id}/deactivate",
            headers=big_lab["h"],
        )
        assert r.status_code == 400

    # 409 — duplicate email
    def test_409_duplicate_email(self, big_lab):
        uid = big_lab["admin"].id
        r = big_lab["client"].patch(
            f"{API}/users/{uid}", headers=big_lab["h"],
            json={"email": "biglab_regular@megacorp.local"},
        )
        assert r.status_code == 409

    # Pagination boundary — offset beyond total → empty not error
    def test_entities_offset_beyond_total(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/entities/",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"], "offset": 999999, "limit": 10},
        )
        assert r.status_code == 200
        assert r.json() == []

    def test_findings_page_beyond_total(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/findings",
            headers=big_lab["h"],
            params={"assessment_id": big_lab["aid"], "page": 9999, "page_size": 50},
        )
        assert r.status_code == 200
        raw = r.json()
        items = raw.get("items", raw) if isinstance(raw, dict) else raw
        assert items == []

    # Password validation
    def test_422_short_password(self, big_lab):
        uid = big_lab["regular"].id
        r = big_lab["client"].patch(
            f"{API}/users/{uid}", headers=big_lab["rh"],
            json={"password": "short"},
        )
        assert r.status_code == 422

    def test_422_invalid_email(self, big_lab):
        uid = big_lab["regular"].id
        r = big_lab["client"].patch(
            f"{API}/users/{uid}", headers=big_lab["rh"],
            json={"email": "not-an-email"},
        )
        assert r.status_code == 422

    # PATCH non-existent assessment → 404
    def test_404_patch_ghost_assessment(self, big_lab):
        r = big_lab["client"].patch(
            f"{API}/assessments/{self.FAKE_ID}",
            headers=big_lab["h"],
            json={"name": "Ghost"},
        )
        assert r.status_code == 404

    # Status filter validation
    def test_422_invalid_assessment_status_filter(self, big_lab):
        r = big_lab["client"].get(
            f"{API}/assessments?status=BOGUS_STATUS", headers=big_lab["h"]
        )
        assert r.status_code in (400, 422)
