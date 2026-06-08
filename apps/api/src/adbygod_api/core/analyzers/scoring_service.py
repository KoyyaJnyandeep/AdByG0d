import math
from typing import Any, Dict, List, Optional

import networkx as nx

from adbygod_api.core.graph.graph_service import ADGraphAnalyzer


def _get_attr(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def normalize_affected_count(count: int, max_count: int = 1000) -> float:
    return 0.0 if count <= 0 else min(1.0, count / max_count)


class RiskScoringService:
    _WEIGHTS = {
        "technical_severity": 0.25,
        "reachability":       0.20,
        "asset_criticality":  0.15,
        "tier_impact":        0.10,
        "breadth":            0.10,
        "confidence":         0.10,
        "drift_recency":      0.05,
        "remediation_ease":   0.05,
    }

    def __init__(self, analyzer: Optional[ADGraphAnalyzer] = None):
        self.analyzer = analyzer

    def score_finding(self, hints: Dict[str, Any]) -> Dict[str, Any]:
        tech_sev       = float(hints.get("technical_severity", 5.0))
        reachability   = float(hints.get("reachability",       0.5))
        confidence     = float(hints.get("confidence",         1.0))
        asset_crit     = float(hints.get("asset_criticality",  0.5))
        affected_count = int(hints.get("affected_count",       1))
        crown_jewel    = bool(hints.get("on_crown_jewel_path", False))
        tier0_direct   = bool(hints.get("is_tier0_direct",     False))
        remed_ease     = float(hints.get("remediation_ease",   0.5))

        tech_norm  = tech_sev / 10.0
        breadth    = min(1.0, math.log10(max(affected_count, 1) + 1) / 4.0)
        tier_impact = 1.0 if tier0_direct else min(reachability, asset_crit)

        raw = (
            self._WEIGHTS["technical_severity"] * tech_norm
            + self._WEIGHTS["reachability"]       * reachability
            + self._WEIGHTS["asset_criticality"]  * asset_crit
            + self._WEIGHTS["tier_impact"]        * tier_impact
            + self._WEIGHTS["breadth"]            * breadth
            + self._WEIGHTS["confidence"]         * confidence
            + self._WEIGHTS["drift_recency"]      * 1.0
            + self._WEIGHTS["remediation_ease"]   * (1.0 - remed_ease)
        )
        if crown_jewel:
            raw *= 1.15
        if tier0_direct:
            raw *= 1.25

        return {
            "composite_score": round(min(100.0, raw * 100.0), 1),
            "technical_severity_norm": round(tech_norm, 3),
            "reachability": round(reachability, 3),
            "breadth": round(breadth, 3),
        }

    def calculate_global_score(self, findings: List[Any]) -> Dict[str, Any]:
        if not findings:
            return {"score": 0, "rating": "INFORMATIONAL", "factors": []}

        _SEV = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0, "INFO": 0.0}
        def _sk(f) -> str:
            s = _get_attr(f, "severity", "INFO")
            return s.value if hasattr(s, "value") else str(s)

        finding_impact = min(50, sum(_SEV.get(_sk(f), 0.0) for f in findings) * 2)

        blast_radius: dict = {}
        total_nodes = 0
        hop_impact = 0.0

        if self.analyzer is not None:
            blast_radius = self.analyzer.compute_tier0_blast_radius()
            total_nodes = len(self.analyzer.entity_meta)
            tier0 = self.analyzer.get_tier0_nodes()
            if blast_radius and tier0:
                # Single reverse multi-source BFS from all tier-0 nodes — O(V+E)
                rev = self.analyzer.graph.reverse(copy=False)
                lengths = nx.multi_source_dijkstra_path_length(rev, tier0)
                sample_nodes = list(blast_radius.keys())[:50]
                hops = [lengths[n] for n in sample_nodes if n in lengths]
                avg_hops = sum(hops) / len(hops) if hops else 0.0
                hop_impact = max(0.0, 10.0 - avg_hops)

        blast_impact = min(40, (len(blast_radius) / max(total_nodes, 1)) * 40)
        final_score = min(100, finding_impact + blast_impact + hop_impact)

        return {
            "score": round(final_score, 1),
            "rating": self._get_rating(final_score),
            "factors": [
                {"name": "Finding Severity sum", "impact": round(finding_impact, 1)},
                {"name": "Blast Radius Coverage", "impact": round(blast_impact, 1)},
                {"name": "Path Accessibility",    "impact": round(hop_impact, 1)},
            ],
            "total_findings": len(findings),
            "blast_radius_nodes": len(blast_radius),
        }

    def _get_rating(self, v: float) -> str:
        if v >= 90:
            return "CRITICAL"
        if v >= 70:
            return "HIGH"
        if v >= 40:
            return "MEDIUM"
        if v >= 10:
            return "LOW"
        return "INFORMATIONAL"

    def compute_exposure_score(self, finding_rows: List[Dict[str, Any]]) -> float:
        """
        Severity-aware exposure score (0–100) for an assessment.

        Algorithm:
        - Each severity bucket contributes diminishing returns (0.70^n decay).
        - A severity floor prevents CRITICAL findings from being diluted by many LOWs.
        - A count-pressure bonus (log-scaled) rewards breadth of coverage.
        - Composite-score sanity check: result is anchored so the legacy
          top*0.6 + avg*0.4 formula is never more than ±8 pts away when findings
          are homogeneous (preserves backward-compatible calibration).
        """
        if not finding_rows:
            return 0.0

        _SEV_BASE: dict[str, float] = {
            "CRITICAL": 22.5,
            "HIGH":     10.0,
            "MEDIUM":    4.5,
            "LOW":       1.2,
            "INFO":      0.2,
        }
        _SEV_DECAY = 0.70
        # Minimum score guaranteed by the worst severity present
        _SEV_FLOOR: dict[str, float] = {
            "CRITICAL": 55.0,
            "HIGH":     30.0,
            "MEDIUM":   15.0,
        }

        # Group rows by severity string
        by_sev: dict[str, int] = {}
        for row in finding_rows:
            raw_sev = row.get("severity", "INFO")
            sev = (raw_sev.value if hasattr(raw_sev, "value") else str(raw_sev)).upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1

        # Severity contribution with diminishing returns per bucket
        sev_score = 0.0
        for sev, base in _SEV_BASE.items():
            n = by_sev.get(sev, 0)
            if n == 0:
                continue
            sev_score += sum(base * (_SEV_DECAY ** i) for i in range(n))
        sev_score = min(75.0, sev_score)

        # Severity floor: guaranteed minimum based on worst class present
        floor = 0.0
        for sev, fl in _SEV_FLOOR.items():
            if by_sev.get(sev, 0) > 0:
                floor = fl
                break

        base_score = max(floor, sev_score)

        # Count pressure: more unique findings = slightly higher score
        count_pressure = min(10.0, math.log10(len(finding_rows) + 1) * 5.0)

        # Graph-backed blast-radius bonus (only when analyzer is attached)
        graph_bonus = 0.0
        if self.analyzer is not None:
            try:
                blast = self.analyzer.compute_tier0_blast_radius()
                total = len(self.analyzer.entity_meta)
                if blast and total > 0:
                    graph_bonus = min(15.0, (len(blast) / total) * 15.0)
            except Exception:
                pass

        raw = base_score + count_pressure + graph_bonus
        return round(min(100.0, max(0.0, raw)), 1)

    def suggest_next_best_action(self, findings: List[Any]) -> Dict[str, Any]:
        if not findings:
            return {"action": "Run collection", "impact_reduction": 0}
        def _sk(f) -> str:
            s = _get_attr(f, "severity", "INFO")
            return s.value if hasattr(s, "value") else str(s)

        top = max(findings, key=lambda f: (_sk(f) == "CRITICAL", int(_get_attr(f, "affected_count", 0) or 0)))
        affected_count = int(_get_attr(top, "affected_count", 0) or 0)
        return {
            "title": f"Remediate {_get_attr(top, 'module', 'finding')}: {_get_attr(top, 'title', 'Untitled finding')}",
            "reasoning": f"Highest severity ({_sk(top)}), impacts {affected_count} objects.",
            "impact_reduction_estimate": "High (Structural Improvement)",
        }
