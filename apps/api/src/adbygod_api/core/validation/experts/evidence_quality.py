"""
Evidence Quality — v3.

Quality is determined by what we HAVE, not by what we're missing.
Findings from the rule engine ARE evidence. Graph edges ARE evidence.
Evidence records are bonus corroboration, not the primary source.
"""
from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict, EvidenceQualityBand
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert

log = logging.getLogger(__name__)


def _quality_band(score: int) -> EvidenceQualityBand:
    if score >= 80:
        return EvidenceQualityBand.VERY_HIGH
    if score >= 60:
        return EvidenceQualityBand.HIGH
    if score >= 35:
        return EvidenceQualityBand.MODERATE
    if score >= 15:
        return EvidenceQualityBand.LOW
    return EvidenceQualityBand.FRAGILE


def compute_evidence_quality(ctx: ValidationAssessmentContext) -> tuple[int, EvidenceQualityBand, list[str]]:
    """
    Returns (score 0-100, band, reasons).

    Scoring tiers:
      Tier 1 — Entities  (primary graph data,          max 25 pts)
      Tier 2 — Findings  (rule engine output = evidence, max 35 pts)
      Tier 3 — Graph edges (connectivity,               max 15 pts)
      Tier 4 — Evidence records (corroboration bonus,   max 15 pts)
      Tier 5 — Collection mode,                         max 10 pts)
    """
    score = 0
    reasons: list[str] = []

    # ── Tier 1: Entities ──────────────────────────────────────────
    if ctx.has_entities:
        n = len(ctx.entities)
        pts = min(25, 5 + n // 5)
        score += pts
        reasons.append(f"{n} entities ({pts}pts)")

    # ── Tier 2: Findings — rule engine ground truth ───────────────
    if ctx.has_findings:
        critical = sum(1 for f in ctx.findings if getattr(f, 'severity', '') == 'CRITICAL')
        high     = sum(1 for f in ctx.findings if getattr(f, 'severity', '') == 'HIGH')
        medium   = sum(1 for f in ctx.findings if getattr(f, 'severity', '') == 'MEDIUM')
        pts = min(35, critical * 4 + high * 2 + medium * 1)
        score += pts
        reasons.append(f"{len(ctx.findings)} findings ({critical}C/{high}H/{medium}M) → {pts}pts")

    # ── Tier 3: Graph edges ───────────────────────────────────────
    if ctx.has_edges:
        n = len(ctx.edges)
        pts = min(15, n // 3)
        score += pts
        reasons.append(f"{n} graph edges ({pts}pts)")

    # ── Tier 4: Evidence records (bonus) ─────────────────────────
    if ctx.has_evidence:
        n = len(ctx.evidence)
        dist = ctx.origin_distribution
        _W = {"COLLECTED": 1.0, "IMPORTED": 0.65, "SIMULATED": 0.2}
        weighted = sum(_W.get(k, 0.3) * v for k, v in dist.items())
        pts = int(min(15, weighted / max(n, 1) * 15))
        score += pts
        reasons.append(f"{n} evidence records ({pts}pts)")

    # ── Tier 5: Collection mode ───────────────────────────────────
    mode = (ctx.collection_mode or "").upper()
    if mode in ("NATIVE", "LIVE", "COLLECTED"):
        score += 10
        reasons.append("Live/native collection (+10pts)")
    elif mode in ("IMPORTED", "BLOODHOUND", "INFERRED"):
        score += 7
        reasons.append("Imported collection (+7pts)")
    elif mode in ("SIMULATED", "SYNTHETIC"):
        score += 4
        reasons.append("Simulated data (+4pts)")
    else:
        score += 5   # unknown but findings exist

    score = min(100, max(0, score))
    return score, _quality_band(score), reasons


class EvidenceQualityExpert(BaseExpert):
    expert_id = "evidence_quality_expert"
    expert_name = "Evidence Quality Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        score, band, reasons = compute_evidence_quality(ctx)

        if band in (EvidenceQualityBand.VERY_HIGH, EvidenceQualityBand.HIGH):
            verdict, delta, conf = ExpertVerdict.SUPPORTS_EXPOSURE, 0.05, 0.90
            summary = f"Evidence quality: {band.value} ({score}/100) — strong basis."
        elif band == EvidenceQualityBand.MODERATE:
            verdict, delta, conf = ExpertVerdict.NEUTRAL, 0.0, 0.75
            summary = f"Evidence quality: MODERATE ({score}/100)."
        else:
            verdict, delta, conf = ExpertVerdict.NEUTRAL, 0.0, 0.50
            summary = f"Evidence quality: {band.value} ({score}/100) — elevated uncertainty."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=delta, confidence=conf,
            summary=summary, reasoning=reasons,
            supporting_signals=[f"Quality: {band.value} ({score}/100)"],
            telemetry={"evidence_quality_score": score, "evidence_quality_band": band.value},
        )
