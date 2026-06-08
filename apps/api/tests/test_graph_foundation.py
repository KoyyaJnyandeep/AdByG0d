"""Tests for Phase 1 graph foundation models and service."""
import networkx as nx

from adbygod_api.core.graph.graph_service import ADGraphAnalyzer
from adbygod_api.models import (
    GraphCentrality, GraphLayout, GraphSnapshot,
    GraphMarkings, GraphView,
)


def test_new_models_importable():
    assert GraphCentrality.__tablename__ == "graph_centrality"
    assert GraphLayout.__tablename__ == "graph_layout"
    assert GraphSnapshot.__tablename__ == "graph_snapshot"
    assert GraphMarkings.__tablename__ == "graph_markings"
    assert GraphView.__tablename__ == "graph_view"

def test_analyzer_uses_multidigraph():
    a = ADGraphAnalyzer()
    assert isinstance(a.graph, nx.MultiDiGraph)

def test_multidigraph_stores_parallel_edges():
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[
            {"id": "u1", "label": "User1", "entity_type": "USER", "attributes": {}},
            {"id": "u2", "label": "User2", "entity_type": "USER", "attributes": {}},
        ],
        edges=[
            {"source_id": "u1", "target_id": "u2", "edge_type": "GENERIC_ALL", "risk_weight": 1.0, "attributes": {}},
            {"source_id": "u1", "target_id": "u2", "edge_type": "WRITE_DACL", "risk_weight": 0.9, "attributes": {}},
        ],
    )
    assert a.graph.number_of_edges("u1", "u2") == 2

def test_community_detection_returns_partition():
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[
            {"id": f"n{i}", "label": f"Node{i}", "entity_type": "USER", "attributes": {}}
            for i in range(6)
        ],
        edges=[
            {"source_id": "n0", "target_id": "n1", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
            {"source_id": "n1", "target_id": "n2", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
            {"source_id": "n3", "target_id": "n4", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
            {"source_id": "n4", "target_id": "n5", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
        ],
    )
    partition = a.compute_communities()
    assert isinstance(partition, dict)
    assert all(k in partition for k in ["n0","n1","n2","n3","n4","n5"])
    assert len(set(partition.values())) >= 1

def test_community_detection_populates_entity_meta():
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[{"id": "x1", "label": "X", "entity_type": "USER", "attributes": {}}],
        edges=[],
    )
    a.compute_communities()
    assert "community_id" in a.entity_meta.get("x1", {})

def test_centrality_computation():
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[
            {"id": "a", "label": "A", "entity_type": "USER", "attributes": {}},
            {"id": "b", "label": "B", "entity_type": "USER", "attributes": {}},
            {"id": "c", "label": "C", "entity_type": "USER", "attributes": {}},
        ],
        edges=[
            {"source_id": "a", "target_id": "b", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
            {"source_id": "b", "target_id": "c", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
        ],
    )
    metrics = a.compute_centrality_metrics()
    assert "a" in metrics
    assert "betweenness" in metrics["a"]
    assert "degree_centrality" in metrics["a"]
    assert "pagerank" in metrics["a"]
    assert metrics["b"]["betweenness"] >= metrics["a"]["betweenness"]

def test_neighborhood_returns_subgraph():
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[{"id": f"n{i}", "label": f"N{i}", "entity_type": "USER", "attributes": {}} for i in range(5)],
        edges=[
            {"source_id": "n0", "target_id": "n1", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
            {"source_id": "n1", "target_id": "n2", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
            {"source_id": "n2", "target_id": "n3", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
            {"source_id": "n3", "target_id": "n4", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
        ],
    )
    result = a.get_neighborhood("n0", hops=2, max_nodes=200)
    node_ids = {n["id"] for n in result["nodes"]}
    assert "n0" in node_ids
    assert "n1" in node_ids
    assert "n2" in node_ids
    assert "n3" not in node_ids  # 3 hops away

def test_neighborhood_unknown_node_returns_empty():
    a = ADGraphAnalyzer()
    result = a.get_neighborhood("nonexistent", hops=2)
    assert result["nodes"] == []
    assert result["edges"] == []


def test_graph_diff_logic():
    """Unit test the diff computation logic."""
    snap_a = {
        "nodes": [{"id": "n1"}, {"id": "n2"}],
        "edges": [{"id": "e1", "source": "n1", "target": "n2", "edge_type": "MEMBER_OF"}],
    }
    snap_b = {
        "nodes": [{"id": "n2"}, {"id": "n3"}],
        "edges": [{"id": "e2", "source": "n2", "target": "n3", "edge_type": "GENERIC_ALL"}],
    }
    from adbygod_api.routes.graph import _compute_snapshot_diff
    diff = _compute_snapshot_diff(snap_a, snap_b)
    assert any(n["id"] == "n3" for n in diff["added_nodes"])
    assert any(n["id"] == "n1" for n in diff["removed_nodes"])
    assert any(e["id"] == "e2" for e in diff["added_edges"])
    assert any(e["id"] == "e1" for e in diff["removed_edges"])


def test_path_confidence_caps_score_for_heuristic_edges():
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[
            {"id": "s", "label": "Source", "entity_type": "USER", "attributes": {}},
            {"id": "t", "label": "Target", "entity_type": "USER", "attributes": {"tier": 0}},
        ],
        edges=[{
            "id": "e1", "source_id": "s", "target_id": "t",
            "edge_type": "GENERIC_ALL", "risk_weight": 1.0,
            "edge_confidence": 0.4, "edge_provenance_type": "heuristic",
            "attributes": {},
        }],
    )
    path = a._build_attack_path(["s", "t"])
    assert path.path_score <= 70.0
    assert hasattr(path, 'confidence')
    assert path.confidence == 0.4

def test_path_confidence_full_for_collected_edges():
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[
            {"id": "s", "label": "Source", "entity_type": "USER", "attributes": {}},
            {"id": "t", "label": "Target", "entity_type": "USER", "attributes": {"tier": 0}},
        ],
        edges=[{
            "id": "e1", "source_id": "s", "target_id": "t",
            "edge_type": "DCSYNC", "risk_weight": 1.0,
            "edge_confidence": 1.0, "edge_provenance_type": "collected",
            "attributes": {},
        }],
    )
    path = a._build_attack_path(["s", "t"])
    assert path.confidence == 1.0
    assert path.path_score > 70.0


def test_path_score_uses_new_formula():
    """Verify the improved scoring weights are applied."""
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[
            {"id": "u", "label": "User", "entity_type": "USER", "attributes": {}},
            {"id": "da", "label": "DA", "entity_type": "GROUP", "tier": 0, "attributes": {}},
        ],
        edges=[{
            "id": "e1", "source_id": "u", "target_id": "da",
            "edge_type": "DCSYNC", "risk_weight": 1.0,
            "edge_confidence": 1.0, "edge_provenance_type": "collected",
            "attributes": {},
        }],
    )
    path = a._build_attack_path(["u", "da"])
    assert path.path_score >= 85.0
    assert path.hop_count == 1
    assert path.involves_credential_access is True

def test_path_score_lower_for_long_chains():
    a = ADGraphAnalyzer()
    entities = [{"id": f"n{i}", "label": f"N{i}", "entity_type": "USER", "attributes": {}} for i in range(5)]
    entities[-1]["attributes"] = {"tier": 0}
    edges = [{
        "id": f"e{i}", "source_id": f"n{i}", "target_id": f"n{i+1}",
        "edge_type": "ADD_MEMBER", "risk_weight": 0.7,
        "edge_confidence": 1.0, "edge_provenance_type": "collected",
        "attributes": {},
    } for i in range(4)]
    a.load_from_dicts(entities=entities, edges=edges)
    short_path = a._build_attack_path(["n3", "n4"])
    long_path = a._build_attack_path(["n0", "n1", "n2", "n3", "n4"])
    assert short_path.path_score > long_path.path_score


def test_directed_path_respects_edge_direction():
    """Directed path should not traverse edges backwards."""
    a = ADGraphAnalyzer()
    a.load_from_dicts(
        entities=[
            {"id": "a", "label": "A", "entity_type": "USER", "attributes": {}},
            {"id": "b", "label": "B", "entity_type": "USER", "attributes": {}},
            {"id": "c", "label": "C", "entity_type": "USER", "attributes": {}},
        ],
        edges=[
            {"id": "e1", "source_id": "a", "target_id": "b", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
            {"id": "e2", "source_id": "b", "target_id": "c", "edge_type": "MEMBER_OF", "risk_weight": 0.5, "attributes": {}},
        ],
    )
    result = a.find_directed_path("a", "c")
    assert result is not None
    assert "b" in result.node_ids

    result_rev = a.find_directed_path("c", "a")
    assert result_rev is None
