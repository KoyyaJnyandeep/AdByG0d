from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

_RELAY_FINDING_TYPES = frozenset([
    "SMB_SIGNING_DISABLED", "SMB_SIGNING_NOT_REQUIRED", "NTLM_RELAY",
    "COERCION_EXPOSURE", "ADCS_ESC8", "RELAY_PRECONDITION",
])
_RELAY_KEYWORDS = ("relay", "smb_sign", "coercion", "esc8", "ntlm", "epa", "channel_binding")


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("ntlm_relay")
class NTLMRelayExpert(BaseExpert):
    expert_id = "ntlm_relay_expert"
    expert_name = "NTLM Relay Precondition Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        # Scan findings for relay-relevant signals
        relay_findings = [
            f for f in ctx.findings
            if str(_get(f, "finding_type", "")).upper() in _RELAY_FINDING_TYPES
            or any(kw in str(_get(f, "finding_type", "") or "").lower() for kw in _RELAY_KEYWORDS)
            or any(kw in str(_get(f, "title", "") or "").lower() for kw in _RELAY_KEYWORDS)
        ]

        # ESC8 is a CA-level property (HTTP web enrollment endpoint reachable for relay),
        # not a template-level flag. Use esc8_vulnerable when present; fall back to
        # presence of ADCS_ESC8 findings as the signal — do NOT alias esc1_vulnerable.
        esc8_templates = [
            t for t in ctx.cert_templates
            if getattr(t, 'esc8_vulnerable', False)
        ]
        ca_entities = [
            e for e in ctx.entities
            if (raw_type := _get(e, 'entity_type', _get(e, 'type', None)))
            and str(_get(raw_type, 'value', raw_type)) == "CA"
        ]

        # Evidence scan
        relay_evidence = [
            ev for ev in ctx.evidence
            if any(kw in str(ev.raw_data or {}).lower() for kw in _RELAY_KEYWORDS)
            or any(kw in (ev.collection_method or "").lower() for kw in _RELAY_KEYWORDS)
        ]

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        reasoning: list[str] = []
        finding_ids: list[str] = []

        smb_findings = [f for f in relay_findings if "smb" in str(_get(f, "finding_type", "")).lower() or "smb" in str(_get(f, "title", "") or "").lower()]
        coercion_findings = [f for f in relay_findings if "coercion" in str(_get(f, "finding_type", "")).lower() or "coercion" in str(_get(f, "title", "") or "").lower()]
        adcs_findings = [f for f in relay_findings if "esc" in str(_get(f, "finding_type", "")).lower() or "adcs" in str(_get(f, "finding_type", "") or "").lower()]

        if smb_findings:
            supporting.append(f"{len(smb_findings)} SMB signing/relay-precondition finding(s) in assessment data.")
            finding_ids += [str(_get(f, "id", "")) for f in smb_findings[:5]]
        else:
            missing.append("SMB signing posture data (collection module may not have run)")

        if coercion_findings:
            supporting.append(f"{len(coercion_findings)} coercion-exposure finding(s) found.")
            finding_ids += [str(_get(f, "id", "")) for f in coercion_findings[:3]]
        else:
            missing.append("Coercion surface data (print spooler, petitpotam, etc.)")

        if adcs_findings or esc8_templates:
            count = len(adcs_findings) + len(esc8_templates)
            supporting.append(f"{count} AD CS relay adjacency signal(s) (ESC8 / web enrollment).")
            finding_ids += [str(_get(f, "id", "")) for f in adcs_findings[:3]]
        else:
            missing.append("AD CS web enrollment posture (ESC8 assessment)")

        if ca_entities:
            supporting.append(f"{len(ca_entities)} CA entity/entities in assessment scope.")

        if relay_evidence:
            supporting.append(f"{len(relay_evidence)} relay-relevant evidence record(s) found.")

        # Verdict
        strong_count = len(smb_findings) + len(coercion_findings) + len(adcs_findings) + len(esc8_templates)

        if strong_count >= 3:
            verdict = ExpertVerdict.SUPPORTS_EXPOSURE
            score_delta = min(0.9, 0.5 + strong_count * 0.08)
            confidence = 0.78
            severity_hint = "CRITICAL"
            summary = (
                f"Relay preconditions modeled: {len(smb_findings)} SMB, "
                f"{len(coercion_findings)} coercion, {len(adcs_findings)+len(esc8_templates)} ADCS signals."
            )
            reasoning.append("Combination of SMB signing gap + coercion + ADCS = high relay exposure model.")
        elif strong_count >= 1:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.3
            confidence = 0.5
            severity_hint = "HIGH"
            summary = f"Partial relay precondition signals ({strong_count} finding(s)); full relay chain not fully modeled."
        else:
            verdict = ExpertVerdict.INSUFFICIENT_DATA
            score_delta = 0.0
            confidence = 0.25
            severity_hint = None
            summary = "No relay precondition evidence found in current assessment data."

        telemetry = {
            "relay_findings_total": len(relay_findings),
            "smb_findings": len(smb_findings),
            "coercion_findings": len(coercion_findings),
            "adcs_findings": len(adcs_findings) + len(esc8_templates),
            "relay_evidence": len(relay_evidence),
        }

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            reasoning=reasoning, supporting_signals=supporting,
            contradicting_signals=contradicting, missing_signals=missing,
            related_finding_ids=finding_ids[:10],
            telemetry=telemetry,
            mitre_techniques=["T1557.001"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                "# Enable SMB signing on all hosts via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options",
            ],
            detection_opportunities=[
                "Monitor for NTLM authentication events from unexpected sources (event 4624 type 3 with NTLM)",
                "Alert on SMB relay tool signatures (Responder, ntlmrelayx) in network traffic",
            ],
        )


@register("ntlm_relay")
class PetitPotamExpert(BaseExpert):
    expert_id = "petitpotam"
    expert_name = "PetitPotam / WebClient Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        # Check for WebClient service running (enables HTTP coercion)
        # Check findings mentioning WebClient or coercion
        webclient_findings = [
            f for f in ctx.findings
            if any(kw in (getattr(f, 'title', '') or '').lower() for kw in ['webclient', 'petitpotam', 'coerce', 'efsr', 'webdav'])
        ]
        has_risk = bool(webclient_findings) or ctx.dc_count > 0  # DCs present = coercion surface exists

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id=module_id,
            verdict=ExpertVerdict.WEAK_SUPPORT if has_risk else ExpertVerdict.NEUTRAL,
            score_delta=0.5 if has_risk else 0.0,
            confidence=0.5,
            severity_hint="HIGH" if has_risk else None,
            summary=f"PetitPotam/WebClient coercion: {'surface exists' if has_risk else 'no indicators'}",
            reasoning=[
                "WebClient service enables HTTP coercion from workstations",
                "PetitPotam can coerce DC machine account over MS-EFSR",
            ],
            mitre_techniques=["T1557.001"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "Disable-WindowsOptionalFeature -FeatureName 'WebClient' -Online",
                "netsh rpc filter add rule layer=um actiontype=block",
                "# Block EFS RPC endpoint if not needed",
            ],
            detection_opportunities=[
                "Monitor for MS-EFSR/MS-FSRVP RPC calls from non-DC sources",
                "Alert on WebClient service start events (7045)",
            ],
        )

    async def analyze(self, ctx: ValidationAssessmentContext) -> ExpertDecision:
        return self.evaluate("ntlm_relay", ctx)
