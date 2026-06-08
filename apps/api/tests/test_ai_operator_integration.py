"""Tests for Phase 5 AI-enhanced features."""
from adbygod_api.core.graph.mitre_mapping import (
    edge_to_mitre,
    path_to_techniques,
)

def test_mitre_mapping_covers_common_edges():
    for edge_type in ["DCSYNC", "GENERIC_ALL", "HAS_SPN", "ALLOWED_TO_DELEGATE", "CAN_ENROLL"]:
        result = edge_to_mitre(edge_type)
        assert result is not None, f"Missing MITRE mapping for {edge_type}"
        assert "technique_id" in result
        assert "technique_name" in result

def test_path_to_techniques_deduplicates():
    steps = [
        {"edge_type": "DCSYNC"},
        {"edge_type": "DCSYNC"},
        {"edge_type": "GENERIC_ALL"},
    ]
    techniques = path_to_techniques(steps)
    ids = [t["technique_id"] for t in techniques]
    assert len(ids) == len(set(ids))


def test_monte_carlo_returns_probability():
    from adbygod_api.routes.graph import _run_monte_carlo
    path_steps = [
        {"edge_type": "GENERIC_ALL"},
        {"edge_type": "DCSYNC"},
    ]
    result = _run_monte_carlo(path_steps, iterations=200)
    assert 0.0 <= result["p_success"] <= 1.0
    assert "histogram" in result
    assert len(result["histogram"]) == 10


def test_narration_request_schema():
    from adbygod_api.routes.graph import NarratePathRequest
    req = NarratePathRequest(
        path_steps=[{"edge_type": "DCSYNC", "entity_label": "UserA", "entity_type": "USER"}],
        source_label="UserA",
        target_label="Domain Admins",
    )
    assert req.source_label == "UserA"


def test_playbook_export_markdown():
    from adbygod_api.routes.graph import _generate_playbook_markdown
    steps = [
        {"edge_type": "HAS_SPN", "entity_label": "SvcAccount", "entity_type": "USER"},
        {"edge_type": "DCSYNC", "entity_label": "SvcAccount", "entity_type": "USER"},
    ]
    md = _generate_playbook_markdown(steps, "SvcAccount", "Domain Admins")
    assert "T1558.003" in md or "Kerberoast" in md
    assert "SvcAccount" in md
    assert "Domain Admins" in md

def test_playbook_export_navigator_json():
    from adbygod_api.routes.graph import _generate_navigator_json
    steps = [{"edge_type": "DCSYNC"}, {"edge_type": "HAS_SPN"}]
    layer = _generate_navigator_json(steps)
    assert layer["name"] is not None
    assert len(layer["techniques"]) > 0
    for t in layer["techniques"]:
        assert "techniqueID" in t


def test_anomaly_detection_finds_outlier_degree():
    from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
    a = ADGraphAnalyzer()
    entities = [{"id": f"n{i}", "label": f"N{i}", "entity_type": "USER", "attributes": {}} for i in range(10)]
    edges = [
        {"id": f"e{i}", "source_id": "n0", "target_id": f"n{i+1}",
         "edge_type": "GENERIC_ALL", "risk_weight": 1.0, "attributes": {}}
        for i in range(9)
    ]
    a.load_from_dicts(entities=entities, edges=edges)
    anomalies = a.detect_anomalies(days_back=999)
    outlier_ids = [x["node_id"] for x in anomalies if x.get("reason") == "outlier_degree"]
    assert "n0" in outlier_ids
