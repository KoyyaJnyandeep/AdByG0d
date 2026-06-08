"""Unit tests for forest pivot analyzer."""
from __future__ import annotations
from adbygod_api.core.analyzers.forest_pivot_analyzer import (
    detect_forest_techniques,
    compute_pivot_paths,
    build_forest_graph,
    FOREST_TECHNIQUE_CATALOGUE,
)


def _trust(name="PARTNER.FOREST", direction_val=3, sid_filtering=False,
           forest_trust=True, transitive=True, trust_type="Forest (AD)",
           partner="LOCAL.FOREST", quarantine=False):
    return {
        "name": name, "direction_val": direction_val, "sid_filtering": sid_filtering,
        "forest_trust": forest_trust, "transitive": transitive,
        "trust_type": trust_type, "partner": partner, "quarantine": quarantine,
    }


def test_trust_key_forgery_detected():
    trusts = [_trust(forest_trust=True, sid_filtering=False)]
    results = detect_forest_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "FOREST_TRUST_KEY_FORGERY" in ids


def test_adcs_cross_forest_detected():
    trusts = [_trust(forest_trust=True, sid_filtering=False)]
    results = detect_forest_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "FOREST_ADCS_ESC1_CROSS" in ids


def test_transitive_hop_detected():
    trusts = [_trust(forest_trust=True, transitive=True)]
    results = detect_forest_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "FOREST_TRANSITIVE_HOP" in ids


def test_mit_realm_trust_detected():
    trusts = [_trust(trust_type="MIT Realm", forest_trust=False)]
    results = detect_forest_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "FOREST_MIT_NO_FILTER" in ids


def test_sid_filter_partial_bypass_detected():
    trusts = [_trust(forest_trust=True, sid_filtering=True, quarantine=False)]
    results = detect_forest_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert "FOREST_SID_FILTER_PARTIAL" in ids


def test_pivot_paths_computed():
    trusts = [
        _trust(name="A.FOREST", partner="B.FOREST"),
        _trust(name="B.FOREST", partner="C.FOREST"),
    ]
    paths = compute_pivot_paths(trusts)
    path_strings = [" -> ".join(p["path"]) for p in paths]
    # Should detect at least one indirect path A->B->C
    assert any("A.FOREST" in s and "C.FOREST" in s for s in path_strings)


def test_build_forest_graph_nodes():
    trusts = [_trust(name="PARTNER.FOREST", partner="LOCAL.FOREST")]
    entities = [{"domain": "LOCAL.FOREST", "entity_type": "USER"}]
    graph = build_forest_graph(trusts, entities)
    assert "nodes" in graph
    assert "edges" in graph
    node_ids = [n["id"] for n in graph["nodes"]]
    assert "PARTNER.FOREST" in node_ids or "LOCAL.FOREST" in node_ids


def test_no_false_positives_on_hardened_trust():
    trusts = [_trust(forest_trust=True, sid_filtering=True, quarantine=True, transitive=False)]
    results = detect_forest_techniques(trusts, entities=[], edges=[])
    critical = [t for t in results if t["severity"] == "CRITICAL"]
    assert len(critical) == 0


def test_catalogue_completeness():
    expected = {
        "FOREST_TRUST_KEY_FORGERY", "FOREST_ADCS_ESC1_CROSS", "FOREST_UGMC_STALE",
        "FOREST_TRANSITIVE_HOP", "FOREST_SCHEMA_NC_WRITE", "FOREST_SID_FILTER_PARTIAL",
        "FOREST_MIT_NO_FILTER", "FOREST_EXCHANGE_WRITEDACL", "FOREST_RODC_REVEALED_CREDS",
        "FOREST_SHADOW_PRINCIPAL_PAM", "FOREST_NOPAC_CROSS",
    }
    assert expected.issubset(set(FOREST_TECHNIQUE_CATALOGUE.keys()))


def test_deduplication():
    trusts = [_trust(), _trust(name="EXTRA.FOREST")]
    results = detect_forest_techniques(trusts, entities=[], edges=[])
    ids = [t["technique_id"] for t in results]
    assert len(ids) == len(set(ids))
