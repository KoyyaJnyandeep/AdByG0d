from __future__ import annotations
import logging
import networkx as nx
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert

log = logging.getLogger(__name__)


class GraphReachabilityExpert(BaseExpert):
    expert_id = "graph_reachability_expert"
    expert_name = "Graph Reachability Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        analyzer = ctx.analyzer
        if not ctx.has_edges or analyzer is None:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No graph edges available for reachability analysis.",
                missing_signals=["Graph edge data"],
            )

        tier0 = analyzer.get_tier0_nodes()
        hvt = analyzer.get_high_value_targets()
        total_nodes = len(analyzer.entity_meta)

        if not tier0:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.NEUTRAL, score_delta=0.0, confidence=0.5,
                summary="No tier-0 nodes identified — reachability analysis has no high-value targets.",
                missing_signals=["Tier-0 node classification"],
            )

        # Multi-hop BFS: all nodes that can reach any tier-0 node
        g = analyzer.graph
        reachable_from: set[str] = set()
        for t0_node in tier0:
            if t0_node in g:
                reachable_from.update(nx.ancestors(g, t0_node))

        non_tier0_total = total_nodes - len(tier0)
        reachable_count = len(reachable_from - tier0)
        reach_pct = reachable_count / max(non_tier0_total, 1) * 100

        supporting: list[str] = []
        contradicting: list[str] = []
        reasoning: list[str] = []

        supporting.append(
            f"{len(tier0)} tier-0 node(s) identified. {reachable_count}/{non_tier0_total} "
            f"non-tier-0 nodes have direct edge(s) to tier-0 ({reach_pct:.0f}%)."
        )

        # Module-specific check
        module_relevant_edges: list[tuple[str,str]] = []
        edge_type_map = {
            "kerberos": ["ALLOWED_TO_DELEGATE", "ALLOWED_TO_ACT", "HAS_SPN"],
            "ntlm_relay": ["ADMIN_TO", "LOCAL_ADMIN"],
            "acl": ["GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS"],
            "dcsync": ["DCSYNC"],
            "trust": ["TRUSTS"],
        }
        relevant_types = edge_type_map.get(module_id, [])
        for etype in relevant_types:
            module_relevant_edges += analyzer._edge_type_index.get(etype, [])

        relevant_to_tier0 = [(s, t) for s, t in module_relevant_edges if t in tier0 or s in tier0]
        if relevant_to_tier0:
            supporting.append(
                f"{len(relevant_to_tier0)} {module_id}-relevant edge(s) directly adjacent to tier-0."
            )
            reasoning.append("Direct tier-0 adjacency amplifies module exposure.")

        severity_hint: str | None = None
        if reach_pct > 30:
            verdict = ExpertVerdict.SUPPORTS_EXPOSURE
            score_delta = min(0.7, reach_pct / 100 * 1.5)
            confidence = 0.75
            severity_hint = "HIGH"
            summary = f"High graph reachability: {reach_pct:.0f}% of nodes have path to tier-0."
        elif reach_pct > 10:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.2
            confidence = 0.55
            severity_hint = "MEDIUM"
            summary = f"Moderate reachability: {reach_pct:.0f}% of nodes adjacent to tier-0."
        elif relevant_to_tier0:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.15
            confidence = 0.5
            severity_hint = "MEDIUM"
            summary = f"Low overall reachability but {len(relevant_to_tier0)} module-relevant tier-0 adjacencies."
        else:
            verdict = ExpertVerdict.NEUTRAL
            score_delta = 0.0
            confidence = 0.5
            summary = f"Low tier-0 reachability ({reach_pct:.0f}%). Graph paths limited."

        telemetry = {
            "tier0_count": len(tier0),
            "hvt_count": len(hvt),
            "total_nodes": total_nodes,
            "reachable_from_tier0": reachable_count,
            "reach_pct": round(reach_pct, 1),
            "module_relevant_edges": len(module_relevant_edges),
            "relevant_to_tier0": len(relevant_to_tier0),
        }

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint,
            summary=summary, reasoning=reasoning,
            supporting_signals=supporting, contradicting_signals=contradicting,
            telemetry=telemetry,
        )
