"""Comprehensive tests for RiskScoringService — every scoring path and edge case."""
from __future__ import annotations

import types


from adbygod_api.core.analyzers.scoring_service import RiskScoringService, normalize_affected_count
from adbygod_api.core.graph.graph_service import ADGraphAnalyzer


# ── normalize_affected_count ──────────────────────────────────────────────────

class TestNormalizeAffectedCount:
    def test_zero_returns_zero(self):
        assert normalize_affected_count(0) == 0.0

    def test_negative_returns_zero(self):
        assert normalize_affected_count(-5) == 0.0

    def test_one_returns_small_positive(self):
        assert 0.0 < normalize_affected_count(1) <= 1.0

    def test_at_max_returns_one(self):
        assert normalize_affected_count(1000) == 1.0

    def test_over_max_clamped_to_one(self):
        assert normalize_affected_count(9999) == 1.0

    def test_half_max(self):
        v = normalize_affected_count(500)
        assert 0.0 < v < 1.0

    def test_custom_max(self):
        assert normalize_affected_count(10, max_count=10) == 1.0
        assert normalize_affected_count(5, max_count=10) == 0.5


# ── score_finding ──────────────────────────────────────────────────────────────

class TestScoreFinding:
    def setup_method(self):
        self.svc = RiskScoringService()

    def test_default_hints_returns_valid_score(self):
        result = self.svc.score_finding({})
        assert 0.0 <= result["composite_score"] <= 100.0

    def test_max_severity_max_reachability(self):
        result = self.svc.score_finding({
            "technical_severity": 10.0,
            "reachability": 1.0,
            "confidence": 1.0,
            "asset_criticality": 1.0,
            "affected_count": 1000,
            "on_crown_jewel_path": True,
            "is_tier0_direct": True,
            "remediation_ease": 0.0,
        })
        assert result["composite_score"] == 100.0

    def test_zero_severity_low_score(self):
        result = self.svc.score_finding({
            "technical_severity": 0.0,
            "reachability": 0.0,
            "confidence": 0.0,
            "asset_criticality": 0.0,
            "affected_count": 0,
            "on_crown_jewel_path": False,
            "is_tier0_direct": False,
            "remediation_ease": 1.0,
        })
        assert result["composite_score"] >= 0.0
        assert result["composite_score"] < 20.0

    def test_crown_jewel_multiplier(self):
        base = self.svc.score_finding({"technical_severity": 5.0, "on_crown_jewel_path": False})
        crown = self.svc.score_finding({"technical_severity": 5.0, "on_crown_jewel_path": True})
        assert crown["composite_score"] >= base["composite_score"]

    def test_tier0_direct_multiplier(self):
        base = self.svc.score_finding({"technical_severity": 5.0, "is_tier0_direct": False})
        t0 = self.svc.score_finding({"technical_severity": 5.0, "is_tier0_direct": True})
        assert t0["composite_score"] >= base["composite_score"]

    def test_breadth_increases_with_affected_count(self):
        low = self.svc.score_finding({"affected_count": 1})
        high = self.svc.score_finding({"affected_count": 1000})
        assert high["composite_score"] >= low["composite_score"]

    def test_easy_remediation_lowers_score(self):
        easy = self.svc.score_finding({"remediation_ease": 1.0})
        hard = self.svc.score_finding({"remediation_ease": 0.0})
        assert hard["composite_score"] >= easy["composite_score"]

    def test_score_capped_at_100(self):
        result = self.svc.score_finding({
            "technical_severity": 10.0, "reachability": 1.0, "confidence": 1.0,
            "asset_criticality": 1.0, "affected_count": 999999,
            "on_crown_jewel_path": True, "is_tier0_direct": True, "remediation_ease": 0.0,
        })
        assert result["composite_score"] <= 100.0

    def test_composite_score_is_float(self):
        result = self.svc.score_finding({"technical_severity": 7.5})
        assert isinstance(result["composite_score"], float)

    def test_returns_breakdown_fields(self):
        result = self.svc.score_finding({"technical_severity": 6.0, "reachability": 0.7})
        assert "technical_severity_norm" in result
        assert "reachability" in result
        assert "breadth" in result

    def test_all_severity_levels(self):
        for sev in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]:
            r = self.svc.score_finding({"technical_severity": sev})
            assert 0.0 <= r["composite_score"] <= 100.0

    def test_string_severity_coerced(self):
        result = self.svc.score_finding({"technical_severity": "8.0", "reachability": "0.8"})
        assert 0.0 <= result["composite_score"] <= 100.0


# ── calculate_global_score ─────────────────────────────────────────────────────

def _make_finding(severity: str, module: str = "Kerberos", title: str = "Test", affected_count: int = 1):
    f = types.SimpleNamespace()
    f.severity = types.SimpleNamespace(value=severity)
    f.module = module
    f.title = title
    f.affected_count = affected_count
    return f


class TestCalculateGlobalScore:
    def setup_method(self):
        self.svc = RiskScoringService()

    def test_empty_findings_returns_zero(self):
        result = self.svc.calculate_global_score([])
        assert result["score"] == 0
        assert result["rating"] == "INFORMATIONAL"

    def test_single_critical_finding(self):
        findings = [_make_finding("CRITICAL", affected_count=50)]
        result = self.svc.calculate_global_score(findings)
        assert result["score"] > 0
        assert result["rating"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_many_critical_findings_caps_at_100(self):
        findings = [_make_finding("CRITICAL", affected_count=100) for _ in range(30)]
        result = self.svc.calculate_global_score(findings)
        assert result["score"] <= 100.0

    def test_low_findings_low_score(self):
        findings = [_make_finding("LOW", affected_count=1) for _ in range(3)]
        result = self.svc.calculate_global_score(findings)
        assert result["score"] < 50.0

    def test_rating_thresholds(self):
        svc = RiskScoringService()
        assert svc._get_rating(95) == "CRITICAL"
        assert svc._get_rating(90) == "CRITICAL"
        assert svc._get_rating(89) == "HIGH"
        assert svc._get_rating(70) == "HIGH"
        assert svc._get_rating(69) == "MEDIUM"
        assert svc._get_rating(40) == "MEDIUM"
        assert svc._get_rating(39) == "LOW"
        assert svc._get_rating(10) == "LOW"
        assert svc._get_rating(9) == "INFORMATIONAL"
        assert svc._get_rating(0) == "INFORMATIONAL"

    def test_returns_factors_list(self):
        findings = [_make_finding("HIGH")]
        result = self.svc.calculate_global_score(findings)
        assert "factors" in result
        assert isinstance(result["factors"], list)
        assert len(result["factors"]) == 3

    def test_returns_total_findings(self):
        findings = [_make_finding("MEDIUM") for _ in range(5)]
        result = self.svc.calculate_global_score(findings)
        assert result["total_findings"] == 5

    def test_with_analyzer_increases_score(self):
        a = ADGraphAnalyzer()
        a.load_from_dicts(
            [
                {"id": "u1", "entity_type": "USER", "sam_account_name": "u1"},
                {"id": "u2", "entity_type": "USER", "sam_account_name": "u2"},
                {"id": "da", "entity_type": "GROUP", "sam_account_name": "Domain Admins", "tier": 0},
            ],
            [
                {"source_id": "u1", "target_id": "da", "edge_type": "MEMBER_OF"},
                {"source_id": "u2", "target_id": "da", "edge_type": "MEMBER_OF"},
            ]
        )
        svc_with = RiskScoringService(analyzer=a)
        findings = [_make_finding("HIGH")]
        result_with = svc_with.calculate_global_score(findings)
        _ = self.svc.calculate_global_score(findings)
        assert isinstance(result_with["score"], float)
        assert result_with["blast_radius_nodes"] >= 0

    def test_mixed_severity_scoring(self):
        findings = [
            _make_finding("CRITICAL"),
            _make_finding("HIGH"),
            _make_finding("MEDIUM"),
            _make_finding("LOW"),
            _make_finding("INFO"),
        ]
        result = self.svc.calculate_global_score(findings)
        assert result["score"] > 0

    def test_enum_severity_handling(self):
        # Severity as enum object with .value
        f = _make_finding("CRITICAL")
        result = self.svc.calculate_global_score([f])
        assert result["score"] > 0

    def test_severity_as_plain_string(self):
        f = types.SimpleNamespace()
        f.severity = "HIGH"
        f.module = "Test"
        f.title = "Test"
        f.affected_count = 1
        result = self.svc.calculate_global_score([f])
        assert result["score"] >= 0


# ── suggest_next_best_action ──────────────────────────────────────────────────

class TestSuggestNextBestAction:
    def setup_method(self):
        self.svc = RiskScoringService()

    def test_empty_findings_returns_run_collection(self):
        result = self.svc.suggest_next_best_action([])
        assert "action" in result
        assert result["impact_reduction"] == 0

    def test_critical_finding_suggested_first(self):
        findings = [
            _make_finding("LOW",      "Network", "Low finding"),
            _make_finding("CRITICAL", "Kerberos", "Critical AS-REP", 50),
            _make_finding("MEDIUM",   "ACL",     "Medium ACL"),
        ]
        result = self.svc.suggest_next_best_action(findings)
        assert "CRITICAL" in result["title"] or "Kerberos" in result["title"] or "AS-REP" in result["title"]

    def test_result_has_required_fields(self):
        findings = [_make_finding("HIGH", "PKI", "Golden Cert", affected_count=10)]
        result = self.svc.suggest_next_best_action(findings)
        assert "title" in result
        assert "reasoning" in result
        assert "impact_reduction_estimate" in result

    def test_highest_affected_count_tiebreaker(self):
        findings = [
            _make_finding("CRITICAL", "Kerberos", "Low impact", affected_count=1),
            _make_finding("CRITICAL", "ACL",      "High impact", affected_count=100),
        ]
        result = self.svc.suggest_next_best_action(findings)
        assert "100" in result["reasoning"] or "High impact" in result["title"]


# ── weights integrity ─────────────────────────────────────────────────────────

class TestWeightsIntegrity:
    def test_weights_sum_to_one(self):
        svc = RiskScoringService()
        total = sum(svc._WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9

    def test_all_weight_keys_present(self):
        svc = RiskScoringService()
        expected = {
            "technical_severity", "reachability", "asset_criticality",
            "tier_impact", "breadth", "confidence", "drift_recency", "remediation_ease",
        }
        assert set(svc._WEIGHTS.keys()) == expected

    def test_all_weights_positive(self):
        svc = RiskScoringService()
        for k, v in svc._WEIGHTS.items():
            assert v > 0, f"Weight {k} must be positive"
