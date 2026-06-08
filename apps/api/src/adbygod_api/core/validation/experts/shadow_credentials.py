from __future__ import annotations

from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("shadow_credentials")
class KeyCredentialLinkExpert(BaseExpert):
    """Shadow credentials (msDS-KeyCredentialLink) write access expert."""
    expert_id = "key_credential_link"
    expert_name = "msDS-KeyCredentialLink Write Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # Check shadow_credential_edges from context or findings
        shadow_edges = getattr(ctx, 'shadow_credential_edges', [])
        sc_findings = [f for f in getattr(ctx, 'findings', [])
                       if (getattr(f, 'finding_type', '') or '') in ('SHADOW_CREDENTIALS', 'ADD_KEY_CREDENTIAL_LINK_ABUSE_PATH')]

        write_edges = shadow_edges or sc_findings
        count = len(shadow_edges) if shadow_edges else len(sc_findings)

        if count >= 3:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.9, "CRITICAL"
        elif count >= 1:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.7, "HIGH"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        targets = [_get(e, 'target_name', _get(e, 'target_id', '')) for e in shadow_edges[:3]] if shadow_edges else []

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="shadow_credentials",
            verdict=verdict, score_delta=score, confidence=0.85 if write_edges else 0.4,
            severity_hint=sev,
            summary=f"Shadow creds: {count} KeyCredentialLink write edge(s){': ' + ', '.join(targets) if targets else ''}",
            reasoning=[
                "msDS-KeyCredentialLink write = ability to add shadow credential to any targeted account",
                "Shadow credential allows PKINIT auth as target account without knowing password",
                "Persistent, invisible to password resets, survives account password changes",
            ] if write_edges else ["No shadow credential write edges found"],
            supporting_signals=[f"{count} KeyCredentialLink write edge(s)"] if write_edges else [],
            mitre_techniques=["T1098.004"],
            kill_chain_stage="persistence",
            remediation_commands=[
                "# Audit msDS-KeyCredentialLink on all accounts:",
                "Get-ADUser -Filter * -Properties msDS-KeyCredentialLink | Where-Object {$_.'msDS-KeyCredentialLink' -ne $null}",
                "# Remove unauthorized entries:",
                "Set-ADObject -Identity <target> -Clear msDS-KeyCredentialLink",
            ],
            detection_opportunities=[
                "Monitor for msDS-KeyCredentialLink attribute modifications (event 4738, 5136)",
                "Alert on PKINIT authentication from accounts that don't normally use certificates",
                "Whisker artifact: non-empty KeyCredentialLink on non-service accounts",
            ],
        )


@register("shadow_credentials")
class WhiskerReachabilityExpert(BaseExpert):
    """Whisker attack reachability via shadow credentials."""
    expert_id = "whisker_reachability"
    expert_name = "Whisker Attack Reachability Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # Whisker requires: WriteProperty to msDS-KeyCredentialLink + PKINIT available
        shadow_edges = getattr(ctx, 'shadow_credential_edges', [])
        # Check if any write edges target privileged accounts
        priv_targets = [
            e for e in shadow_edges
            if any(kw in str(_get(e, 'target_name', _get(e, 'target_id', ''))).lower()
                   for kw in ['admin', 'da', 'domain admin', 'enterprise'])
        ]

        has_priv = bool(priv_targets)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="shadow_credentials",
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE if has_priv else (ExpertVerdict.WEAK_SUPPORT if shadow_edges else ExpertVerdict.NEUTRAL),
            score_delta=0.8 if has_priv else (0.4 if shadow_edges else 0.0),
            confidence=0.75 if shadow_edges else 0.3,
            severity_hint="CRITICAL" if has_priv else ("HIGH" if shadow_edges else None),
            summary=f"Whisker: {len(priv_targets)} privileged targets reachable via shadow credentials",
            reasoning=[
                "Whisker/pywhisker can add KeyCredentialLink to targeted account",
                "Combined with PKINIT: attacker obtains TGT as target account",
                f"{len(priv_targets)} privileged target(s) reachable",
            ] if shadow_edges else ["No shadow credential write surface found"],
            supporting_signals=[f"{len(priv_targets)} privileged targets"] if priv_targets else [],
            mitre_techniques=["T1098.004", "T1558"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Restrict WriteProperty on msDS-KeyCredentialLink via AdminSDHolder",
                "# Monitor with: DSACLs.exe or PowerView Get-DomainObjectAcl",
            ],
            detection_opportunities=[
                "Alert on shadow credential additions to admin accounts",
                "Monitor Whisker/pywhisker tool signatures in process logs",
            ],
        )


@register("shadow_credentials")
class ShadowCredentialChainExpert(BaseExpert):
    """Shadow credential chain to domain compromise."""
    expert_id = "shadow_credential_chain"
    expert_name = "Shadow Credential Chain Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # Cross-check: shadow write to DA/EA path = full chain
        shadow_edges = getattr(ctx, 'shadow_credential_edges', [])
        dcsync_edges = [e for e in getattr(ctx, 'edges', [])
                        if 'replication' in str(_get(e, 'relationship_type', _get(getattr(e, 'edge_type', None), 'value', getattr(e, 'edge_type', '')))).lower()
                        or 'getncchanges' in str(_get(e, 'relationship_type', _get(getattr(e, 'edge_type', None), 'value', getattr(e, 'edge_type', '')))).lower()]

        # Full chain: shadow cred write + target has DA-equivalent access
        full_chain = bool(shadow_edges and (dcsync_edges or getattr(ctx, 'dcsync_principals', [])))

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="shadow_credentials",
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE if full_chain else (ExpertVerdict.WEAK_SUPPORT if shadow_edges else ExpertVerdict.INSUFFICIENT_DATA),
            score_delta=0.9 if full_chain else (0.3 if shadow_edges else 0.0),
            confidence=0.8 if full_chain else 0.5,
            severity_hint="CRITICAL" if full_chain else None,
            summary=f"Shadow cred chain: {'FULL CHAIN — shadow write → PKINIT → DCSync reachable' if full_chain else 'partial surface only'}",
            reasoning=[
                "Full chain: shadow credential write + target can DCSync = domain compromise",
                "Attack: add shadow cred → PKINIT as target → extract NT hashes → Golden Ticket",
            ] if full_chain else ["Incomplete chain — no DCSync path from shadow credential targets"],
            supporting_signals=["Shadow write edges present", "DCSync path present"] if full_chain else [],
            mitre_techniques=["T1098.004", "T1558", "T1003.006"],
            kill_chain_stage="credential_access",
            blast_radius_hint=getattr(ctx, 'computer_count', 0),
            remediation_commands=[
                "# Priority: remove shadow credential write edges AND fix DCSync ACL",
                "# Double remediation required to break chain",
            ],
            detection_opportunities=[
                "Correlate: KeyCredentialLink modification followed by PKINIT auth",
                "Alert on DCSync immediately after new shadow credential enrollment",
            ],
        )
