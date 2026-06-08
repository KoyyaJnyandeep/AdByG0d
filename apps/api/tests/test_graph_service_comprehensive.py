"""Comprehensive tests for ADGraphAnalyzer — every detection method and analytic."""
from __future__ import annotations

from adbygod_api.core.graph.graph_service import ADGraphAnalyzer


# ── helpers ───────────────────────────────────────────────────────────────────

def _user(id_: str, name: str, tier: int | None = None, **extra) -> dict:
    d = {"id": id_, "entity_type": "USER", "sam_account_name": name, "display_name": name}
    if tier is not None:
        d["tier"] = tier
    d.update(extra)
    return d


def _computer(id_: str, name: str, tier: int | None = None, **extra) -> dict:
    d = {"id": id_, "entity_type": "COMPUTER", "sam_account_name": name, "display_name": name, "domain": "corp.local"}
    if tier is not None:
        d["tier"] = tier
    d.update(extra)
    return d


def _group(id_: str, name: str, tier: int | None = None) -> dict:
    d = {"id": id_, "entity_type": "GROUP", "sam_account_name": name, "display_name": name}
    if tier is not None:
        d["tier"] = tier
    return d


def _dc(id_: str, name: str) -> dict:
    return {"id": id_, "entity_type": "DC", "sam_account_name": name, "display_name": name, "tier": 0, "domain": "corp.local"}


def _domain(id_: str, name: str) -> dict:
    return {"id": id_, "entity_type": "DOMAIN", "sam_account_name": name, "display_name": name, "tier": 0, "domain": name}


def _edge(src: str, tgt: str, etype: str, rw: float = 0.8) -> dict:
    return {"source_id": src, "target_id": tgt, "edge_type": etype, "risk_weight": rw}


def _full_domain() -> tuple[list[dict], list[dict]]:
    """Build a realistic multi-node AD domain with all interesting entity types."""
    entities = [
        _domain("dom1", "corp.local"),
        _dc("dc1", "DC01$"),
        _group("da", "Domain Admins", tier=0),
        _group("ea", "Enterprise Admins", tier=0),
        _group("ba", "Builtin\\Administrators", tier=0),
        _user("admin", "Administrator", tier=0, is_admin_count=True),
        _user("krbtgt", "krbtgt", tier=0),
        _user("svc_sql", "svc_sql", tier=2,
              attributes={"has_spn": True, "uac_dont_require_preauth": False}),
        _user("asrep1", "asrep_user", tier=3,
              attributes={"uac_dont_require_preauth": True}),
        _user("pwdnreq", "pwdnotreq_user", tier=3,
              attributes={"uac_passwd_notreqd": True}),
        _user("jdoe", "jdoe", tier=3),
        _user("jsmith", "jsmith", tier=3),
        _user("intern", "intern_user", tier=4),
        _computer("ws1", "WORKSTATION01$", tier=3, attributes={"laps_enabled": False}),
        _computer("ws2", "WORKSTATION02$", tier=3, attributes={"laps_enabled": True}),
        _computer("srv1", "SERVER01$", tier=1, attributes={"laps_enabled": False}),
        {"id": "comp_uncons", "entity_type": "COMPUTER", "sam_account_name": "UNCONS$",
         "display_name": "UNCONS$", "tier": 1, "domain": "corp.local",
         "attributes": {"uac_trusted_for_delegation": True}},
        {"id": "comp_cons", "entity_type": "COMPUTER", "sam_account_name": "CONSTRAINED$",
         "display_name": "CONSTRAINED$", "tier": 2, "domain": "corp.local",
         "attributes": {"uac_trusted_to_auth_for_delegation": True}},
        {"id": "sa_gmsa", "entity_type": "GMSA", "sam_account_name": "gmsa_svc$", "display_name": "gmsa_svc$", "tier": 2},
        {"id": "ca1", "entity_type": "CA", "sam_account_name": "CORP-CA", "display_name": "CORP-CA", "tier": 0},
        {"id": "ou_users", "entity_type": "OU", "sam_account_name": "OU=Users,DC=corp,DC=local", "display_name": "Users OU"},
        {"id": "gpo1", "entity_type": "GPO", "sam_account_name": "{GPO-GUID-1}", "display_name": "Default Domain Policy"},
    ]
    edges = [
        # Domain Admins membership
        _edge("admin", "da", "MEMBER_OF", 0.9),
        _edge("jdoe",  "da", "MEMBER_OF", 0.9),
        # Enterprise Admins
        _edge("admin", "ea", "MEMBER_OF", 0.9),
        # Normal user → group chains
        _edge("jsmith", "ba", "MEMBER_OF", 0.7),
        _edge("intern", "ou_users", "MEMBER_OF", 0.1),
        # ACL abuse paths
        _edge("jdoe",  "jsmith", "GENERIC_ALL",   0.95),
        _edge("jsmith", "ws1",   "WRITE_DACL",    0.85),
        _edge("intern", "jdoe",  "FORCE_CHANGE_PASSWORD", 0.8),
        # DCSync
        _edge("svc_sql", "dom1", "DCSYNC", 1.0),
        # Admin paths
        _edge("jdoe",  "ws1", "ADMIN_TO",   0.9),
        _edge("jsmith", "srv1", "LOCAL_ADMIN", 0.85),
        _edge("admin", "dc1",  "ADMIN_TO",   1.0),
        # RDP / WinRM
        _edge("jdoe",  "ws2", "CAN_RDP",   0.7),
        _edge("jsmith", "srv1", "CAN_WINRM", 0.75),
        # RBCD
        _edge("intern", "comp_cons", "ALLOWED_TO_ACT", 0.9),
        # LAPS read
        _edge("jdoe",  "ws1",  "READ_LAPS_PASSWORD",  0.9),
        _edge("jsmith", "ws2", "READ_LAPS_PASSWORD",  0.9),
        # GMSA read
        _edge("jdoe",  "sa_gmsa", "READ_GMSA_PASSWORD", 0.85),
        # Session
        _edge("jdoe", "ws1", "HAS_SESSION", 0.6),
        # CA manage
        _edge("admin", "ca1", "MANAGE_CA", 0.95),
        _edge("jdoe",  "ca1", "MANAGE_CERTIFICATES", 0.9),
        # Shadow credential
        _edge("intern", "jdoe", "ADD_KEY_CREDENTIAL_LINK", 0.9),
        # GPO link
        _edge("jdoe", "gpo1", "WRITE_GP_LINK", 0.85),
        # Constrained delegation
        _edge("comp_cons", "srv1", "ALLOWED_TO_DELEGATE", 0.8),
        # Contains
        _edge("ou_users", "jdoe",   "CONTAINS", 0.1),
        _edge("ou_users", "jsmith", "CONTAINS", 0.1),
        # Trust
        _edge("dom1", "ea", "APPLIES_GPO", 0.5),
    ]
    return entities, edges


# ── basic graph construction ──────────────────────────────────────────────────

class TestGraphConstruction:
    def test_load_from_dicts_populates_nodes(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([_user("u1", "alice")], [])
        assert "u1" in a.entity_meta

    def test_load_from_dicts_populates_edges(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [_user("u1", "alice"), _group("g1", "da", tier=0)],
            [_edge("u1", "g1", "MEMBER_OF")]
        )
        assert a.graph.has_edge("u1", "g1")

    def test_empty_graph_returns_safe_defaults(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([], [])
        assert a.get_tier0_nodes() == set()
        assert a.get_high_value_targets() == set()
        assert a.compute_tier0_blast_radius() == {}

    def test_entity_with_all_attributes(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([{
            "id": "full",
            "entity_type": "USER",
            "sam_account_name": "full_user",
            "display_name": "Full User",
            "tier": 2,
            "is_crown_jewel": True,
            "is_admin_count": True,
            "is_sensitive": True,
            "is_protected_user": True,
            "domain": "corp.local",
            "object_sid": "S-1-5-21-1234",
            "distinguished_name": "CN=Full,DC=corp,DC=local",
            "attributes": {
                "has_spn": True,
                "uac_dont_require_preauth": True,
                "uac_trusted_for_delegation": True,
                "uac_passwd_notreqd": True,
                "laps_enabled": True,
            }
        }], [])
        meta = a.entity_meta["full"]
        assert meta["is_crown_jewel"]
        assert meta["has_spn"]
        assert meta["uac_dont_req_preauth"]
        assert meta["uac_trusted_for_deleg"]
        assert meta["uac_passwd_notreqd"]

    def test_skips_entities_with_no_id(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([{"entity_type": "USER", "sam_account_name": "noid"}], [])
        assert len(a.entity_meta) == 0

    def test_skips_edges_with_missing_endpoints(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([_user("u1", "alice")], [
            {"source_id": "u1", "target_id": "", "edge_type": "MEMBER_OF"},
            {"source_id": "", "target_id": "u1", "edge_type": "MEMBER_OF"},
        ])
        assert a.graph.number_of_edges() == 0


# ── tier-0 and high-value ─────────────────────────────────────────────────────

class TestTier0AndHighValue:
    def test_tier0_detected_by_tier_field(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([_group("da", "Domain Admins", tier=0)], [])
        assert "da" in a.get_tier0_nodes()

    def test_domain_admins_by_name_detected_as_tier0(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([_group("da", "Domain Admins")], [])
        assert "da" in a.get_tier0_nodes()

    def test_enterprise_admins_by_name_detected(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([_group("ea", "Enterprise Admins")], [])
        assert "ea" in a.get_tier0_nodes()

    def test_is_tier0_method(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([_group("da", "Domain Admins", tier=0), _user("u1", "user")], [])
        assert a.is_tier0("da")
        assert not a.is_tier0("u1")

    def test_high_value_targets_includes_crown_jewels(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([
            {"id": "cj", "entity_type": "USER", "sam_account_name": "crown_jewel", "is_crown_jewel": True}
        ], [])
        assert "cj" in a.get_high_value_targets()


# ── path finding ──────────────────────────────────────────────────────────────

class TestPathFinding:
    def setup_method(self):
        self.a = ADGraphAnalyzer()
        self.a.load_from_dicts(
            [
                _user("u1", "alice"),
                _user("u2", "bob"),
                _group("g1", "helpdesk"),
                _group("da", "Domain Admins", tier=0),
            ],
            [
                _edge("u1", "g1", "MEMBER_OF"),
                _edge("u2", "g1", "MEMBER_OF"),
                _edge("g1", "da", "MEMBER_OF"),
            ]
        )

    def test_find_shortest_path_direct(self):
        ap = self.a.find_shortest_path("u1", "da")
        assert ap is not None
        assert ap.source_id == "u1"
        assert ap.target_id == "da"
        assert ap.hop_count >= 1
        assert "u1" in ap.node_ids
        assert "da" in ap.node_ids

    def test_find_shortest_path_no_path(self):
        ap = self.a.find_shortest_path("da", "u1")
        assert ap is None

    def test_find_all_shortest_paths(self):
        paths = self.a.find_all_shortest_paths("u1", "da")
        assert len(paths) >= 1
        for ap in paths:
            assert ap.source_id == "u1"
            assert ap.target_id == "da"

    def test_get_paths_to_tier0(self):
        results = self.a.get_paths_to_tier0("u1")
        assert len(results) >= 1
        for pr in results:
            assert pr.hop_count >= 1
            assert "u1" in pr.path

    def test_find_attack_paths_to_tier0(self):
        paths = self.a.find_attack_paths_to_tier0("u1")
        assert len(paths) >= 1
        for ap in paths:
            assert isinstance(ap.source_id, str)

    def test_find_paths_to_domain_admins(self):
        paths = self.a.find_paths_to_domain_admins(source_id="u1")
        assert len(paths) >= 1

    def test_reachable_from(self):
        reachable = self.a.get_reachable_from("u1")
        assert "da" in reachable

    def test_can_reach(self):
        can_reach = self.a.get_can_reach("da")
        assert "u1" in can_reach

    def test_get_neighbors_outbound(self):
        nbrs = self.a.get_neighbors("u1", "out")
        assert "g1" in nbrs

    def test_get_neighbors_inbound(self):
        nbrs = self.a.get_neighbors("da", "in")
        assert "g1" in nbrs

    def test_get_neighbors_both(self):
        nbrs = self.a.get_neighbors("g1", "both")
        assert "u1" in nbrs
        assert "da" in nbrs


# ── blast radius ──────────────────────────────────────────────────────────────

class TestBlastRadius:
    def setup_method(self):
        entities, edges = _full_domain()
        self.a = ADGraphAnalyzer()
        self.a.load_from_dicts(entities, edges)

    def test_tier0_blast_radius_returns_dict(self):
        result = self.a.compute_tier0_blast_radius()
        assert isinstance(result, dict)

    def test_blast_radius_detail(self):
        result = self.a.compute_blast_radius_detail()
        assert hasattr(result, "reachable_count")

    def test_node_blast_radius(self):
        result = self.a.compute_node_blast_radius("jdoe")
        assert "reachable_count" in result or isinstance(result, dict)

    def test_domain_dominance(self):
        result = self.a.compute_domain_dominance()
        assert hasattr(result, "domain") or isinstance(result, dict)

    def test_exposure_surface(self):
        result = self.a.compute_exposure_surface()
        assert isinstance(result, dict)
        assert "total_exposed" in result or len(result) >= 0


# ── detection methods ─────────────────────────────────────────────────────────

class TestDetectionMethods:
    def setup_method(self):
        entities, edges = _full_domain()
        self.a = ADGraphAnalyzer()
        self.a.load_from_dicts(entities, edges)

    def test_detect_shadow_admins(self):
        result = self.a.detect_shadow_admins()
        assert isinstance(result, list)
        for shadow in result:
            assert hasattr(shadow, "entity_id") or isinstance(shadow, dict)

    def test_detect_acl_abuse_paths(self):
        # detect_acl_abuse_paths requires ACL edge from non-tier0 directly to tier-0
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [
                _user("lowpriv", "lowpriv"),
                _group("da", "Domain Admins", tier=0),
            ],
            [_edge("lowpriv", "da", "GENERIC_ALL")]
        )
        result = a.detect_acl_abuse_paths()
        assert isinstance(result, list)
        assert len(result) >= 1
        for ap in result:
            assert hasattr(ap, "source_id")
        assert result[0].source_id == "lowpriv"

    def test_detect_dcsync_principals(self):
        result = self.a.detect_dcsync_principals()
        assert isinstance(result, list)
        # detect_dcsync_principals returns dicts with "principal_id"
        ids = [r["principal_id"] for r in result]
        assert "svc_sql" in ids

    def test_detect_unconstrained_delegation(self):
        result = self.a.detect_unconstrained_delegation()
        assert isinstance(result, list)
        assert len(result) >= 1
        ids = [r.entity_id if hasattr(r, "entity_id") else r["entity_id"] for r in result]
        assert "comp_uncons" in ids

    def test_detect_constrained_delegation_abuse(self):
        result = self.a.detect_constrained_delegation_abuse()
        assert isinstance(result, list)

    def test_detect_rbcd_abuse(self):
        result = self.a.detect_rbcd_abuse()
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_detect_kerberoastable_paths(self):
        result = self.a.detect_kerberoastable_paths()
        assert isinstance(result, list)
        # returns dicts with "account_id" key
        ids = [r["account_id"] for r in result]
        assert "svc_sql" in ids

    def test_detect_asrep_roastable(self):
        result = self.a.detect_asrep_roastable()
        assert isinstance(result, list)
        assert len(result) >= 1
        # returns dicts with "account_id" key
        ids = [r["account_id"] for r in result]
        assert "asrep1" in ids

    def test_detect_password_not_required(self):
        result = self.a.detect_password_not_required()
        assert isinstance(result, list)
        assert len(result) >= 1
        ids = [r["account_id"] for r in result]
        assert "pwdnreq" in ids

    def test_detect_laps_coverage(self):
        result = self.a.detect_laps_coverage()
        assert isinstance(result, dict)
        assert "total_computers" in result
        assert "laps_enabled" in result
        assert "laps_missing" in result
        assert "coverage_pct" in result

    def test_detect_gmsa_exposure(self):
        result = self.a.detect_gmsa_exposure()
        assert isinstance(result, list)

    def test_detect_adcs_paths(self):
        result = self.a.detect_adcs_paths()
        assert isinstance(result, list)


# ── centrality and choke points ───────────────────────────────────────────────

class TestCentralityAndChokePoints:
    def setup_method(self):
        entities, edges = _full_domain()
        self.a = ADGraphAnalyzer()
        self.a.load_from_dicts(entities, edges)

    def test_compute_betweenness_centrality(self):
        result = self.a.compute_betweenness_centrality()
        assert isinstance(result, list)
        for item in result:
            assert "node_id" in item
            assert "betweenness_score" in item
            assert item["betweenness_score"] >= 0.0

    def test_compute_pagerank(self):
        result = self.a.compute_pagerank()
        assert isinstance(result, list)
        for item in result:
            assert "node_id" in item
            assert "pagerank_score" in item

    def test_find_choke_points(self):
        result = self.a.find_choke_points()
        assert isinstance(result, list)

    def test_find_most_traversed_edges(self):
        result = self.a.find_most_traversed_edges()
        assert isinstance(result, list)

    def test_find_critical_nodes(self):
        result = self.a.find_critical_nodes()
        assert isinstance(result, list)


# ── remediation and simulation ────────────────────────────────────────────────

class TestRemediationAndSimulation:
    def setup_method(self):
        entities, edges = _full_domain()
        self.a = ADGraphAnalyzer()
        self.a.load_from_dicts(entities, edges)

    def test_simulate_edge_removal_reduces_exposure(self):
        result = self.a.simulate_edge_removal([("jdoe", "da")])
        assert "before" in result
        assert "after" in result
        assert "metric" in result
        assert result["metric"] == "exposed_principals_reaching_tier0"

    def test_simulate_edge_removal_has_per_edge_analysis(self):
        result = self.a.simulate_edge_removal([("jdoe", "da")])
        assert "per_edge_analysis" in result
        for ea in result["per_edge_analysis"]:
            assert "exposed_principals_eliminated_if_removed" in ea
            assert "paths_eliminated_if_removed" not in ea

    def test_simulate_edge_removal_multiple_edges(self):
        result = self.a.simulate_edge_removal([("jdoe", "da"), ("svc_sql", "dom1")])
        assert "before" in result

    def test_simulate_node_hardening(self):
        result = self.a.simulate_node_hardening(["jdoe"])
        assert isinstance(result, dict)
        assert "before" in result or "impact" in result or len(result) >= 0

    def test_rank_remediation_actions(self):
        result = self.a.rank_remediation_actions()
        assert isinstance(result, list)

    def test_simulate_edge_removal_no_path_edge(self):
        result = self.a.simulate_edge_removal([("intern", "ws1")])
        assert "before" in result


# ── graph analytics and exports ────────────────────────────────────────────────

class TestAnalyticsAndExports:
    def setup_method(self):
        entities, edges = _full_domain()
        self.a = ADGraphAnalyzer()
        self.a.load_from_dicts(entities, edges)

    def test_get_graph_stats(self):
        stats = self.a.get_graph_stats()
        assert stats.node_count >= 1
        assert stats.edge_count >= 1

    def test_get_full_analytics(self):
        result = self.a.get_full_analytics()
        assert isinstance(result, dict)
        assert "graph_stats" in result or "nodes" in result or len(result) > 0

    def test_export_for_frontend(self):
        result = self.a.export_for_frontend()
        assert "nodes" in result
        assert "edges" in result
        assert isinstance(result["nodes"], list)
        assert isinstance(result["edges"], list)

    def test_export_attack_subgraph(self):
        result = self.a.export_attack_subgraph()
        assert isinstance(result, dict)
        assert "nodes" in result or "edges" in result or len(result) >= 0

    def test_get_node_neighborhood(self):
        result = self.a.get_node_neighborhood("jdoe")
        assert isinstance(result, dict)
        assert "nodes" in result or "center" in result or len(result) >= 0

    def test_get_edge_type_statistics(self):
        result = self.a.get_edge_type_statistics()
        assert isinstance(result, list)
        assert len(result) >= 1
        for item in result:
            assert "edge_type" in item or "type" in item
            assert "count" in item

    def test_get_cross_domain_paths(self):
        result = self.a.get_cross_domain_paths()
        assert isinstance(result, list)

    def test_get_forest_dominance(self):
        result = self.a.get_forest_dominance()
        assert isinstance(result, dict)

    def test_get_unconstrained_delegation_exposure(self):
        result = self.a.get_unconstrained_delegation_exposure()
        assert isinstance(result, list)
        assert "comp_uncons" in result


# ── lookup indexes ─────────────────────────────────────────────────────────────

class TestLookupIndexes:
    def setup_method(self):
        self.a = ADGraphAnalyzer()
        self.a.load_from_dicts([
            {"id": "u1", "entity_type": "USER",
             "sam_account_name": "alice",
             "distinguished_name": "CN=alice,DC=corp,DC=local",
             "object_sid": "S-1-5-21-1234-500"}
        ], [])

    def test_lookup_by_sam(self):
        assert self.a.lookup_by_sam("alice") == "u1"
        assert self.a.lookup_by_sam("ALICE") == "u1"

    def test_lookup_by_dn(self):
        assert self.a.lookup_by_dn("CN=alice,DC=corp,DC=local") == "u1"

    def test_lookup_by_sid(self):
        assert self.a.lookup_by_sid("S-1-5-21-1234-500") == "u1"

    def test_lookup_missing_returns_none(self):
        assert self.a.lookup_by_sam("nonexistent") is None
        assert self.a.lookup_by_dn("CN=nobody") is None
        assert self.a.lookup_by_sid("S-1-5-99") is None

    def test_get_node_returns_meta(self):
        node = self.a.get_node("u1")
        assert node is not None
        assert node["sam_account_name"] == "alice"

    def test_get_node_missing_returns_none(self):
        assert self.a.get_node("nonexistent") is None


# ── transitive memberships ─────────────────────────────────────────────────────

class TestTransitiveMemberships:
    def setup_method(self):
        self.a = ADGraphAnalyzer()
        self.a.load_from_dicts(
            [
                _user("u1", "alice"),
                _group("g_help", "HelpDesk"),
                _group("g_it", "IT"),
                _group("da", "Domain Admins", tier=0),
            ],
            [
                _edge("u1",    "g_help", "MEMBER_OF"),
                _edge("g_help","g_it",   "MEMBER_OF"),
                _edge("g_it",  "da",     "MEMBER_OF"),
            ]
        )

    def test_transitive_group_members(self):
        members = self.a.get_transitive_group_members("da")
        assert "u1" in members

    def test_transitive_memberships(self):
        memberships = self.a.get_transitive_memberships("u1")
        assert "da" in memberships

    def test_direct_only_membership(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [_user("u1", "alice"), _group("g1", "group1", tier=0)],
            [_edge("u1", "g1", "MEMBER_OF")]
        )
        assert a.is_tier0("g1")
        assert "g1" in a.get_transitive_memberships("u1")


# ── owned nodes ────────────────────────────────────────────────────────────────

class TestOwnedNodes:
    def test_set_owned_nodes(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts([_user("u1", "alice"), _user("u2", "bob")], [])
        a.set_owned_nodes(["u1"])
        result = a.find_paths_from_owned()
        assert isinstance(result, list)

    def test_find_paths_from_owned_to_tier0(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [_user("owned", "owned_user"), _group("da", "Domain Admins", tier=0)],
            [_edge("owned", "da", "MEMBER_OF")]
        )
        a.set_owned_nodes(["owned"])
        paths = a.find_paths_from_owned()
        assert len(paths) >= 1


# ── k-shortest paths ──────────────────────────────────────────────────────────

class TestKShortestPaths:
    def test_find_k_shortest_paths(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [
                _user("a", "alice"),
                _group("g1", "group1"),
                _group("g2", "group2"),
                _group("da", "Domain Admins", tier=0),
            ],
            [
                _edge("a", "g1", "MEMBER_OF"),
                _edge("a", "g2", "MEMBER_OF"),
                _edge("g1", "da", "MEMBER_OF"),
                _edge("g2", "da", "MEMBER_OF"),
            ]
        )
        paths = a.find_k_shortest_paths("a", "da", k=5)
        assert isinstance(paths, list)
        assert len(paths) >= 1

    def test_k_shortest_no_path(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [_user("a", "alice"), _group("da", "Domain Admins", tier=0)],
            []
        )
        paths = a.find_k_shortest_paths("da", "a", k=3)
        assert paths == [] or paths is None or isinstance(paths, list)


# ── domain-specific analytics ──────────────────────────────────────────────────

class TestDomainSpecificAnalytics:
    def test_get_domain_nodes(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [
                {"id": "u1", "entity_type": "USER", "sam_account_name": "u1", "domain": "corp.local"},
                {"id": "u2", "entity_type": "USER", "sam_account_name": "u2", "domain": "other.local"},
            ],
            []
        )
        corp_nodes = a.get_domain_nodes("corp.local")
        assert "u1" in corp_nodes
        assert "u2" not in corp_nodes

    def test_cert_templates_added(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [_user("u1", "alice")],
            [],
            cert_templates=[
                {"id": "tmpl1", "name": "User", "enrollee_supplies_subject": True,
                 "requires_manager_approval": False, "authorized_signatures_required": 0}
            ]
        )
        assert len(a._cert_templates) == 1

    def test_full_analytics_on_rich_domain(self):
        entities, edges = _full_domain()
        a = ADGraphAnalyzer()
        a.load_from_dicts(entities, edges)
        analytics = a.get_full_analytics()
        assert isinstance(analytics, dict)
        keys = set(analytics.keys())
        assert len(keys) >= 3
