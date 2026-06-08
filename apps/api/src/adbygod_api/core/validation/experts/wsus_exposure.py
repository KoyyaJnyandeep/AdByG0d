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


@register("wsus_exposure")
class WSUSExposureExpert(BaseExpert):
    expert_id = "wsus_exposure_expert"
    expert_name = "WSUS HTTP Exposure Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        wsus_evidence = [
            ev for ev in ctx.evidence
            if _get(_get(ev, "raw_data", {}), "probe_type", "") == "wsus_http_probe"
            or "wsus" in (_get(ev, "collection_method", "") or "").lower()
        ]
        wsus_findings = [
            f for f in ctx.findings
            if "wsus" in str(_get(f, "finding_type", "")).lower()
            or "wsus" in str(_get(f, "title", "")).lower()
        ]

        if not wsus_evidence and not wsus_findings:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No WSUS HTTP exposure evidence present.",
                missing_signals=["Port 8530 scan result", "WSUS HTTP probe from recon scan"],
            )

        servers = list({
            _get(_get(ev, "raw_data", {}), "server", "unknown")
            for ev in wsus_evidence
        })

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE,
            score_delta=0.9,
            confidence=0.92,
            severity_hint="CRITICAL",
            summary=f"WSUS server(s) accessible via HTTP on port 8530: {', '.join(servers)}. SYSTEM code execution possible via update spoofing.",
            supporting_signals=[
                f"WSUS HTTP endpoint responds on {', '.join(servers)} — pywsus/SharpWSUS can deliver malicious update",
                "Update delivery over HTTP allows MiTM injection without certificate validation",
            ],
            mitre_techniques=["T1072"],
            kill_chain_stage="execution",
            blast_radius_hint=100,
            remediation_commands=[
                "Enforce SSL on WSUS: IIS Manager → WSUS → SSL Settings → Require SSL",
                "Set WSUS to use HTTPS port 8531 instead of HTTP 8530",
            ],
            detection_opportunities=[
                "Alert on HTTP traffic to port 8530 from non-DC/WSUS hosts",
                "Monitor IIS WSUS logs for unknown computer accounts requesting updates",
            ],
            cve_refs=["CVE-2020-1013"],
        )
