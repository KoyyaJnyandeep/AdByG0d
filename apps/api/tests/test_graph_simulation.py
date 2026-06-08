from adbygod_api.core.graph.graph_service import ADGraphAnalyzer


def test_edge_removal_reports_exposed_principal_metric_aliases():
    analyzer = ADGraphAnalyzer()
    analyzer.load_from_dicts(
        entities=[
            {"id": "intern", "entity_type": "USER", "sam_account_name": "intern_ops"},
            {"id": "admin", "entity_type": "USER", "sam_account_name": "Administrator", "tier": 0},
            {"id": "da", "entity_type": "GROUP", "sam_account_name": "Domain Admins", "tier": 0},
        ],
        edges=[
            {"source_id": "intern", "target_id": "admin", "edge_type": "FORCE_CHANGE_PASSWORD"},
            {"source_id": "admin", "target_id": "da", "edge_type": "MEMBER_OF"},
            {"source_id": "intern", "target_id": "da", "edge_type": "ADD_MEMBER"},
        ],
    )

    result = analyzer.simulate_edge_removal([("intern", "admin")])

    assert result["metric"] == "exposed_principals_reaching_tier0"
    assert result["before"] == result["exposed_principals_before"] == 1
    assert result["after"] == result["exposed_principals_after"] == 1
    assert result["eliminated"] == result["exposed_principals_eliminated"] == 0
    assert result["alternative_paths"] == [
        {
            "source_label": "intern_ops",
            "target_label": "Domain Admins",
            "hop_count": 1,
            "edge_types": ["ADD_MEMBER"],
        }
    ]


def test_per_edge_analysis_uses_canonical_field_name():
    """Regression: per_edge_analysis must use exposed_principals_eliminated_if_removed.

    The frontend SimulationEdge type was previously consuming the old field
    paths_eliminated_if_removed which no longer exists on the backend.
    This test pins the field name so that API/UI drift cannot recur silently.
    """
    analyzer = ADGraphAnalyzer()
    analyzer.load_from_dicts(
        entities=[
            {"id": "u1", "entity_type": "USER", "sam_account_name": "user1"},
            {"id": "da", "entity_type": "GROUP", "sam_account_name": "Domain Admins", "tier": 0},
        ],
        edges=[
            {"source_id": "u1", "target_id": "da", "edge_type": "MEMBER_OF"},
        ],
    )

    result = analyzer.simulate_edge_removal([("u1", "da")])

    assert "per_edge_analysis" in result
    assert len(result["per_edge_analysis"]) == 1
    edge = result["per_edge_analysis"][0]

    # This is the canonical name. The old name paths_eliminated_if_removed must
    # not exist.
    assert "exposed_principals_eliminated_if_removed" in edge
    assert "paths_eliminated_if_removed" not in edge

    # Also verify optimal_removal uses the same field.
    if result.get("optimal_removal"):
        assert "exposed_principals_eliminated_if_removed" in result["optimal_removal"]
        assert "paths_eliminated_if_removed" not in result["optimal_removal"]
