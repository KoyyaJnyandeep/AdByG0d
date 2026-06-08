from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("timeroast_exposure")
class TimeroastExposureExpert(BaseExpert):
    expert_id = "timeroast_exposure_expert"
    expert_name = "Timeroasting Exposure Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        sntp_evidence = [
            ev for ev in ctx.evidence
            if _get(_get(ev, "raw_data", {}), "probe_type", "") == "ntp_sntp_probe"
            or "timeroast" in (_get(ev, "collection_method", "") or "").lower()
        ]
        timeroast_findings = [
            f for f in ctx.findings
            if "timeroast" in str(_get(f, "finding_type", "")).lower()
            or "timeroast" in str(_get(f, "title", "")).lower()
            or "ms-sntp" in str(_get(f, "title", "")).lower()
        ]

        if not sntp_evidence and not timeroast_findings:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No MS-SNTP probe data or Timeroasting findings present.",
                missing_signals=["NTP/MS-SNTP probe result from recon scan"],
            )

        hashes = sum(
            int(_get(_get(ev, "raw_data", {}), "hashes_found", 0))
            for ev in sntp_evidence
        )
        score = min(0.4 + (0.1 * hashes), 0.9)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE,
            score_delta=score,
            confidence=0.85,
            severity_hint="HIGH",
            summary=f"MS-SNTP hash extraction possible — {hashes} hash(es) captured via NTP without credentials",
            supporting_signals=[
                "MS-SNTP extension responds to unauthenticated NTP packets with computer account hash",
                f"{hashes} SNTP hash(es) captured — crack with hashcat mode 31300",
            ],
            mitre_techniques=["T1558"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "Disable NTP signing: configure W32Time to not expose MS-SNTP extension",
            ],
            detection_opportunities=[
                "Monitor NTP traffic for MS-SNTP extension responses to unauthenticated sources",
            ],
        )
