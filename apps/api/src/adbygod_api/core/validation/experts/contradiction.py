from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert

log = logging.getLogger(__name__)


class ContradictionExpert(BaseExpert):
    """
    Looks for reasons the engine should NOT overstate exposure.
    A strong CONTRADICTS_EXPOSURE verdict from this expert caps final confidence.
    """
    expert_id = "contradiction_expert"
    expert_name = "Contradiction & FP-Suppression Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        contradictions: list[str] = []
        supporting: list[str] = []

        # 1. Are claimed vulnerable entities actually disabled?
        analyzer = ctx.analyzer
        if module_id == "kerberos":
            asrep_all = [
                e for e in ctx.entities
                if analyzer.entity_meta.get(str(e.id), {}).get("uac_dont_req_preauth", False)
            ]
            asrep_disabled = [e for e in asrep_all if not getattr(e, 'is_enabled', True)]
            if asrep_disabled and len(asrep_disabled) == len(asrep_all):
                contradictions.append(
                    "ALL pre-auth disabled accounts are DISABLED — no live AS-REP roast risk."
                )

        # 2. No data for claimed module
        if module_id == "ntlm_relay" and not ctx.findings and not ctx.evidence:
            contradictions.append(
                "Relay module: no findings or evidence records — cannot support relay exposure claim."
            )

        if module_id == "trust" and not ctx.has_entities and not ctx.has_edges:
            contradictions.append(
                "Trust module: no entity or edge data — cannot evaluate trust boundaries."
            )

        # 3. Stale/imported-only data with no collected corroboration
        dist = ctx.origin_distribution
        collected = dist.get("COLLECTED", 0)
        imported = dist.get("IMPORTED", 0)
        if imported > 0 and collected == 0:
            contradictions.append(
                f"All {imported} evidence record(s) are IMPORTED (not freshly collected) — "
                f"data may be stale. Confidence reduced."
            )

        # 4. ACL module: no path to sensitive target
        if module_id == "acl":
            tier0 = analyzer.get_tier0_nodes()
            toxic_to_t0 = sum(
                1 for etype in ["GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS"]
                for src, tgt in analyzer._edge_type_index.get(etype, [])
                if tgt in tier0
            )
            if not tier0:
                contradictions.append(
                    "No tier-0 nodes in graph — ACL paths have no confirmed sensitive target."
                )
            elif toxic_to_t0 == 0 and ctx.has_edges:
                supporting.append(
                    "Edges present but none target tier-0 objects — ACL exposure context: lateral movement only."
                )

        # 5. DCSync: all principals are expected
        if module_id == "dcsync":
            from adbygod_api.core.validation.experts.dcsync import _classify_principal
            dcsync_edges = analyzer._edge_type_index.get("DCSYNC", [])
            if dcsync_edges:
                all_expected = all(
                    _classify_principal(analyzer.entity_meta.get(src_id, {})) == "expected"
                    for src_id, _ in dcsync_edges
                )
                if all_expected:
                    contradictions.append(
                        "All DCSYNC principals are expected built-ins (DCs, DAs, built-in groups). "
                        "False-positive suppressed."
                    )

        # 6. No graph at all
        if not ctx.has_edges and module_id in ("acl", "dcsync", "kerberos"):
            contradictions.append(
                f"No graph edges in assessment — {module_id} path analysis cannot be performed."
            )

        if contradictions:
            verdict = ExpertVerdict.CONTRADICTS_EXPOSURE
            score_delta = -0.4 * min(1.0, len(contradictions) * 0.3)
            confidence = 0.75
            summary = f"{len(contradictions)} contradiction(s) found that reduce exposure confidence."
        else:
            verdict = ExpertVerdict.NEUTRAL
            score_delta = 0.0
            confidence = 0.7
            summary = "No significant contradictions or false-positive patterns detected."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            summary=summary, reasoning=contradictions,
            contradicting_signals=contradictions, supporting_signals=supporting,
            telemetry={"contradictions_found": len(contradictions)},
        )
