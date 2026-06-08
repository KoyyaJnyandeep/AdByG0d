from __future__ import annotations

from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("sid_history")
class SIDHistoryPresenceExpert(BaseExpert):
    expert_id = "sid_history_presence"
    expert_name = "SID History Presence Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        sid_entities = getattr(ctx, 'sid_history_entities', [])
        sid_findings = [f for f in getattr(ctx, 'findings', [])
                        if (getattr(f, 'finding_type', '') or '') == 'SID_HISTORY_POPULATED']
        count = len(sid_entities) + len(sid_findings)

        if count >= 10:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.7, "HIGH"
        elif count >= 3:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.4, "MEDIUM"
        elif count:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.2, "LOW"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="sid_history",
            verdict=verdict, score_delta=score, confidence=0.8 if count else 0.45,
            severity_hint=sev,
            summary=f"SID History: {count} entity(ies) with sIDHistory attribute",
            reasoning=[
                "sIDHistory preserves legacy group memberships but can be abused",
                "Legacy SIDs may include privileged group membership",
                "Often left over from domain migrations",
            ] if count else ["No sIDHistory found"],
            supporting_signals=[f"{count} entities with sIDHistory"] if count else [],
            mitre_techniques=["T1134.005"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "# Audit sIDHistory: Get-ADUser -Filter * -Properties SIDHistory | Where-Object {$_.SIDHistory -ne $null}",
                "# Remove after verifying no dependency: Set-ADUser -Identity <name> -Remove @{sIDHistory=<old_sid>}",
            ],
            detection_opportunities=[
                "Monitor for authentication using sIDHistory SIDs (event 4672 with extra SIDs)",
                "Alert on access granted via historical SID not matching current group membership",
            ],
        )


@register("sid_history")
class SIDHistoryPrivilegedExpert(BaseExpert):
    expert_id = "sid_history_privileged"
    expert_name = "Privileged SID History Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        sid_entities = getattr(ctx, 'sid_history_entities', [])
        # Check for SID history entries resolving to privileged groups
        priv_sids = [
            e for e in sid_entities
            if any(kw in str(_get(e, 'resolved_sids', [])).lower()
                   for kw in ['domain admins', 'enterprise admins', 'schema admins', 's-1-5-21'])
        ]
        sid_findings = [f for f in getattr(ctx, 'findings', [])
                        if (getattr(f, 'finding_type', '') or '') == 'SID_HISTORY_POPULATED'
                        and any(kw in (getattr(f, 'title', '') or '').lower() for kw in ['admin', 'privilege', 'domain admin'])]

        count = len(priv_sids) + len(sid_findings)

        if count >= 3:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.9, "CRITICAL"
        elif count >= 1:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.75, "CRITICAL"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        names = [_get(e, 'name', '') for e in priv_sids[:3]]

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="sid_history",
            verdict=verdict, score_delta=score, confidence=0.9 if count else 0.4,
            severity_hint=sev,
            summary=f"Privileged SID history: {count} entity(ies) with DA/EA in sIDHistory{': ' + ', '.join(names) if names else ''}",
            reasoning=[
                "Account has Domain Admin/Enterprise Admin SID in sIDHistory",
                "This grants DA-equivalent access WITHOUT group membership",
                "Invisible to standard group membership audits",
                "Persists through password resets — cannot be removed easily",
            ] if count else ["No privileged SID history found"],
            supporting_signals=[f"{count} implicit DA/EA via sIDHistory"] if count else [],
            blast_radius_hint=getattr(ctx, 'computer_count', 0) + getattr(ctx, 'user_count', 0),
            mitre_techniques=["T1134.005"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "# URGENT: Remove privileged SIDs from sIDHistory",
                "# Verify: Get-ADUser -Identity <name> -Properties SIDHistory",
                "Set-ADUser -Identity <name> -Remove @{sIDHistory='<privileged_sid>'}",
                "# Force password reset after removal to invalidate any cached TGTs",
            ],
            detection_opportunities=[
                "CRITICAL: Monitor for logon events with SIDHistory SIDs in token (event 4672)",
                "Alert on any access granted via sIDHistory SID",
            ],
        )


@register("sid_history")
class SIDFilteringTrustExpert(BaseExpert):
    expert_id = "sid_filtering_trust"
    expert_name = "Trust SID Filtering Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # Cross-trust SID history: trust without filtering + sIDHistory = cross-forest privilege
        sid_entities = getattr(ctx, 'sid_history_entities', [])
        [f for f in getattr(ctx, 'findings', [])
                          if (getattr(f, 'finding_type', '') or '') in ('TRUST_NO_SID_FILTERING', 'SID_HISTORY_POPULATED', 'BIDIRECTIONAL_EXTERNAL_TRUST')]

        cross_trust_risk = bool(sid_entities and getattr(ctx, 'domain_count', 1) > 1)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="sid_history",
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE if cross_trust_risk else ExpertVerdict.NEUTRAL,
            score_delta=0.7 if cross_trust_risk else 0.0,
            confidence=0.65 if cross_trust_risk else 0.35,
            severity_hint="HIGH" if cross_trust_risk else None,
            summary=f"Trust SID filtering: {'multi-domain + sIDHistory = cross-forest risk' if cross_trust_risk else 'single domain or no sIDHistory'}",
            reasoning=[
                "Multiple domains without SID filtering + sIDHistory = cross-forest privilege escalation",
                "Attacker in trusted domain can craft tickets with privileged SIDs of trusting domain",
            ] if cross_trust_risk else [],
            supporting_signals=["Multiple domains", f"{len(sid_entities)} sIDHistory entities"] if cross_trust_risk else [],
            mitre_techniques=["T1134.005", "T1482"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "# Enable SID filtering on all trust relationships:",
                "netdom trust <trusted_domain> /domain:<trusting_domain> /quarantine:yes",
                "# For forest trusts: enable SID filtering (disables sIDHistory use cross-forest)",
            ],
            detection_opportunities=["Monitor cross-domain/forest authentications with extra SIDs in PAC"],
        )
