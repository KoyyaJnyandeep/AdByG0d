from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

_ANON_LDAP_TYPES = frozenset(["ANONYMOUS_LDAP_ENABLED", "LDAP_ANONYMOUS_BIND", "ANON_LDAP"])
_SMB_NULL_TYPES  = frozenset(["SMB_NULL_SESSION", "SMB_NULL_AUTH", "NULL_SESSION"])
_DNS_ZONE_TYPES  = frozenset(["DNS_ZONE_TRANSFER", "AXFR_ENABLED"])


def _get(obj, key, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("recon_exposure")
class ReconExposureExpert(BaseExpert):
    expert_id = "recon_exposure_expert"
    expert_name = "Recon Exposure Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        anon_ldap = [
            f for f in ctx.findings
            if str(_get(f, "finding_type", "")).upper() in _ANON_LDAP_TYPES
            or (
                "anonymous" in str(_get(f, "title", "")).lower()
                and "ldap" in str(_get(f, "title", "")).lower()
            )
        ]
        smb_null = [
            f for f in ctx.findings
            if str(_get(f, "finding_type", "")).upper() in _SMB_NULL_TYPES
            or "null session" in str(_get(f, "title", "")).lower()
        ]
        dns_zone = [
            f for f in ctx.findings
            if str(_get(f, "finding_type", "")).upper() in _DNS_ZONE_TYPES
        ]

        supporting: list[str] = []
        score_delta = 0.0

        if anon_ldap:
            supporting.append(f"Anonymous LDAP binding enabled — {len(anon_ldap)} finding(s) confirm unauthenticated directory access")
            score_delta += 0.7

        if smb_null:
            supporting.append("SMB null session permitted — allows RID cycling and share enumeration without credentials")
            score_delta += 0.5

        if dns_zone:
            supporting.append(f"DNS zone transfer enabled — {len(dns_zone)} finding(s); full DNS zone exposed to unauthenticated queries")
            score_delta += 0.4

        if not supporting:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.NEUTRAL, score_delta=0.0, confidence=0.3,
                summary="No anonymous-access recon exposure signals detected.",
                missing_signals=["ANONYMOUS_LDAP_ENABLED", "SMB_NULL_SESSION", "DNS_ZONE_TRANSFER"],
            )

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE,
            score_delta=min(score_delta, 1.0),
            confidence=0.85,
            severity_hint="HIGH",
            summary=f"Unauthenticated recon vectors detected: {', '.join(['anon LDAP'] * bool(anon_ldap) + ['SMB null'] * bool(smb_null) + ['DNS zone xfer'] * bool(dns_zone))}",
            supporting_signals=supporting,
            mitre_techniques=["T1087.002", "T1135", "T1590.002"],
            kill_chain_stage="reconnaissance",
            remediation_commands=[
                "Set-ADObject (Get-ADRootDSE).defaultNamingContext -Replace @{dSHeuristics='0000002'}",
                "Set-SmbServerConfiguration -RestrictNullSessions $true -Force",
            ],
            detection_opportunities=[
                "Event ID 4625 — anonymous LDAP bind attempt",
                "Event ID 5140 — anonymous SMB network share access",
            ],
        )
