from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

UAC_PASSWD_NOTREQD = 0x20


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _uac(entity) -> int:
    attrs = _get(entity, "attributes", {}) or {}
    raw = attrs.get("userAccountControl", 0)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


@register("pre2k_exposure")
class Pre2kExposureExpert(BaseExpert):
    expert_id = "pre2k_exposure_expert"
    expert_name = "Pre-Win2000 Account Exposure Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        if not ctx.has_entities:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No entity data available for Pre-Win2000 analysis.",
                missing_signals=["Computer entities with UAC flags"],
            )

        computers = [
            e for e in ctx.entities
            if str(_get(e, "entity_type", "")).upper() in ("COMPUTER", "DC")
        ]

        passwd_notreqd = [c for c in computers if _uac(c) & UAC_PASSWD_NOTREQD]

        if not passwd_notreqd:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.NEUTRAL, score_delta=0.0, confidence=0.6,
                summary="No computer accounts with PASSWD_NOTREQD flag found.",
            )

        names = [_get(c, "sam_account_name", "unknown") for c in passwd_notreqd]
        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE,
            score_delta=min(0.3 * len(passwd_notreqd), 1.0),
            confidence=0.9,
            severity_hint="CRITICAL",
            summary=f"{len(passwd_notreqd)} computer account(s) with PASSWD_NOTREQD (UAC 0x20): {', '.join(names[:5])}",
            supporting_signals=[
                f"Computer '{n}' has UAC flag PASSWD_NOTREQD — default password is lowercase hostname"
                for n in names
            ],
            related_entity_ids=[str(_get(c, "id", "")) for c in passwd_notreqd if _get(c, "id")],
            mitre_techniques=["T1078.002", "T1110.003"],
            kill_chain_stage="initial_access",
            blast_radius_hint=len(passwd_notreqd),
            remediation_commands=[
                "Get-ADComputer -Filter {(userAccountControl -band 32) -ne 0} | Set-ADAccountControl -PasswordNotRequired $false",
            ],
            detection_opportunities=[
                "Audit computer account authentication from unusual source IPs",
                "Alert on PASSWD_NOTREQD flag set on new computer accounts",
            ],
        )
