from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)


@register("kerberos")
class KerberosExpert(BaseExpert):
    expert_id = "kerberos_expert"
    expert_name = "Kerberos Exposure Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        if not ctx.has_entities:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No entity data available for Kerberos analysis.",
                missing_signals=["Entity data with UAC attributes"],
            )

        # AS-REP roastable: enabled, uac_dont_req_preauth=True
        asrep_enabled = [
            e for e in ctx.entities
            if getattr(e, 'is_enabled', True)
            and ctx.analyzer.entity_meta.get(str(e.id), {}).get("uac_dont_req_preauth", False)
        ]
        asrep_disabled = [
            e for e in ctx.entities
            if not getattr(e, 'is_enabled', True)
            and ctx.analyzer.entity_meta.get(str(e.id), {}).get("uac_dont_req_preauth", False)
        ]

        # Kerberoastable: has_spn
        spn_entities = [
            e for e in ctx.entities
            if ctx.analyzer.entity_meta.get(str(e.id), {}).get("has_spn", False)
        ]
        spn_admin = [
            e for e in spn_entities
            if getattr(e, 'is_admin_count', False)
            or ctx.analyzer.entity_meta.get(str(e.id), {}).get("tier") == 0
        ]

        # Delegation
        deleg_edges = ctx.edge_type_index.get("ALLOWED_TO_DELEGATE", [])
        act_edges = ctx.edge_type_index.get("ALLOWED_TO_ACT", [])

        # Protected users (good — reduces attack surface)
        protected = [
            e for e in ctx.entities
            if getattr(e, 'is_protected_user', False)
        ]
        gmsa = [
            e for e in ctx.entities
            if ctx.analyzer.entity_meta.get(str(e.id), {}).get("gmsa", False)
        ]

        tier0 = ctx.analyzer.get_tier0_nodes()
        spn_reach_tier0 = [
            e for e in spn_entities
            if str(e.id) in tier0
            or any(
                tgt in tier0
                for src, tgt in ctx.analyzer._edge_type_index.get("MEMBER_OF", [])
                if src == str(e.id)
            )
        ]

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        entity_ids: list[str] = []
        reasoning: list[str] = []

        if asrep_enabled:
            supporting.append(
                f"{len(asrep_enabled)} ENABLED principal(s) with pre-authentication disabled "
                f"(AS-REP roastable): {[ctx.entity_name(str(e.id)) for e in asrep_enabled[:3]]}"
            )
            entity_ids += [str(e.id) for e in asrep_enabled]
            reasoning.append("AS-REP roast allows offline cracking of hash without sending any credentials.")

        if asrep_disabled:
            contradicting.append(
                f"{len(asrep_disabled)} DISABLED account(s) with pre-auth disabled "
                f"— lower risk since accounts cannot authenticate."
            )

        if spn_entities:
            supporting.append(
                f"{len(spn_entities)} SPN-bearing principal(s) exposed to Kerberoast."
            )
            entity_ids += [str(e.id) for e in spn_entities[:5]]

        if spn_admin:
            supporting.append(
                f"{len(spn_admin)} SPN-bearing account(s) are admin-count or tier-0 — "
                f"cracking would yield privileged credential material."
            )
            reasoning.append("Privileged SPN accounts dramatically increase Kerberoast impact.")

        if spn_reach_tier0:
            supporting.append(
                f"{len(spn_reach_tier0)} SPN-bearing account(s) have path proximity to tier-0."
            )

        if deleg_edges:
            supporting.append(f"{len(deleg_edges)} unconstrained/constrained delegation edge(s) present.")
        if act_edges:
            supporting.append(f"{len(act_edges)} RBCD (ALLOWED_TO_ACT) delegation edge(s) present.")

        if protected:
            contradicting.append(
                f"{len(protected)} principal(s) in Protected Users group — "
                f"Kerberos delegation and certain auth mechanisms blocked."
            )
        if gmsa:
            contradicting.append(
                f"{len(gmsa)} gMSA account(s) with auto-rotating passwords — "
                f"Kerberoast value reduced for these accounts."
            )

        if not asrep_enabled and not spn_entities:
            missing.append("Accounts with pre-auth disabled or SPN attributes")

        # Score
        has_real_signal = bool(asrep_enabled or spn_admin or spn_reach_tier0)
        has_weak_signal = bool(spn_entities or deleg_edges or act_edges)

        if has_real_signal:
            verdict = ExpertVerdict.SUPPORTS_EXPOSURE
            score_delta = 0.8 if spn_admin or spn_reach_tier0 else 0.6
            confidence = 0.82
            severity_hint = "CRITICAL" if spn_admin else "HIGH"
            summary = (
                f"Kerberos credential exposure modeled: {len(asrep_enabled)} AS-REP roastable, "
                f"{len(spn_entities)} Kerberoastable, {len(spn_admin)} privileged."
            )
        elif has_weak_signal:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.3
            confidence = 0.55
            severity_hint = "MEDIUM"
            summary = f"Weak Kerberos signals: {len(spn_entities)} SPN accounts, {len(deleg_edges)} delegation edges."
        else:
            verdict = ExpertVerdict.INSUFFICIENT_DATA
            score_delta = 0.0
            confidence = 0.35
            severity_hint = None
            summary = "Insufficient Kerberos exposure signals in current data."

        telemetry = {
            "asrep_enabled": len(asrep_enabled),
            "asrep_disabled": len(asrep_disabled),
            "spn_accounts": len(spn_entities),
            "spn_privileged": len(spn_admin),
            "delegation_edges": len(deleg_edges) + len(act_edges),
            "protected_users": len(protected),
        }

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            reasoning=reasoning, supporting_signals=supporting,
            contradicting_signals=contradicting, missing_signals=missing,
            related_entity_ids=list(set(entity_ids[:10])),
            telemetry=telemetry,
            mitre_techniques=["T1558.003", "T1558.004"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false",
                "Set-ADUser -Identity <spn_account> -KerberosEncryptionType AES128,AES256",
                "Add-ADGroupMember -Identity 'Protected Users' -Members <privileged_accounts>",
            ],
            detection_opportunities=[
                "Alert on AS-REP responses (event 4768 with no pre-auth)",
                "Monitor for high-volume TGS requests for service accounts (event 4769)",
                "Detect offline cracking attempts via honeypot SPN accounts",
            ],
        )


@register("kerberos")
class GoldenTicketRiskExpert(BaseExpert):
    expert_id = "golden_ticket_risk"
    expert_name = "Golden Ticket Risk Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        # Check krbtgt in asrep_candidates or having old password (simulate via: no recent reset signal)
        # In real env: check krbtgt password age via pwdLastSet
        # Here: check if Protected Users group has krbtgt, check AdminSDHolder

        krbtgt_at_risk = False

        # Check for stale krbtgt or DCSync access — both indicate Golden Ticket risk
        dcsync_findings = [
            f for f in ctx.findings
            if 'dcsync' in str(getattr(f, 'finding_type', '') or getattr(f, 'category', '') or '').lower()
            or 'replication' in str(getattr(f, 'title', '') or '').lower()
        ]
        krbtgt_stale_findings = [
            f for f in ctx.findings
            if getattr(f, 'finding_type', '') == 'KRBTGT_STALE'
            or 'krbtgt' in str(getattr(f, 'title', '') or '').lower()
        ]

        if dcsync_findings or krbtgt_stale_findings:
            krbtgt_at_risk = True

        verdict = ExpertVerdict.SUPPORTS_EXPOSURE if krbtgt_at_risk else ExpertVerdict.NEUTRAL
        score = 0.85 if (dcsync_findings and krbtgt_stale_findings) else 0.8 if krbtgt_at_risk else 0.0

        supporting = []
        if dcsync_findings:
            supporting.append(f"{len(dcsync_findings)} DCSync-related finding(s) — krbtgt hash extractable.")
        if krbtgt_stale_findings:
            supporting.append("krbtgt password stale — stale key extends Golden Ticket forgery window.")

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id=module_id,
            verdict=verdict,
            score_delta=score,
            confidence=0.75 if (dcsync_findings and krbtgt_stale_findings) else 0.65 if krbtgt_at_risk else 0.4,
            severity_hint="CRITICAL" if krbtgt_at_risk else None,
            summary=f"Golden Ticket risk: {'stale krbtgt + DCSync access = confirmed forge path' if (dcsync_findings and krbtgt_stale_findings) else 'krbtgt at risk via DCSync or stale key' if krbtgt_at_risk else 'no Golden Ticket path found'}",
            reasoning=["DCSync access implies krbtgt hash extraction", "Stale krbtgt extends validity window for forged tickets", "krbtgt hash = unlimited persistence via Golden Ticket"] if krbtgt_at_risk else ["No DCSync path or stale krbtgt found"],
            supporting_signals=supporting,
            mitre_techniques=["T1558.001"],
            kill_chain_stage="persistence",
            remediation_commands=[
                "Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString 'NewP@ss!' -AsPlainText -Force)",
                "# Reset krbtgt password TWICE (once per day) to invalidate all Golden Tickets",
            ],
            detection_opportunities=[
                "Monitor for TGS requests with unusual lifetimes (>10h)",
                "Alert on Kerberos tickets with krbtgt NTLM hash (event 4769 from unusual sources)",
            ],
        )

    async def analyze_async(self, ctx: ValidationAssessmentContext) -> ExpertDecision:
        return self.evaluate("kerberos", ctx)


@register("kerberos")
class KerberosEncryptionExpert(BaseExpert):
    expert_id = "encryption"
    expert_name = "Kerberos Encryption Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        # Check for RC4-only accounts (no AES keys), DES enabled
        rc4_only = []
        for e in ctx.entities:
            props = e.get('properties', {}) if isinstance(e, dict) else {}
            # Accounts with only RC4 encryption supported (no AES flag in msDS-SupportedEncryptionTypes)
            enc_types = props.get('supportedencryptiontypes', 28)  # 28 = AES128+AES256+RC4
            if isinstance(enc_types, int) and enc_types in (4, 0):  # RC4 only or unset
                rc4_only.append(e.get('name', '') if isinstance(e, dict) else '')

        # Check for DES-only flag in findings
        des_findings = [
            f for f in ctx.findings
            if 'des' in str(getattr(f, 'title', '') or '').lower()
        ]

        has_weak_enc = bool(rc4_only or des_findings)
        verdict = ExpertVerdict.WEAK_SUPPORT if has_weak_enc else ExpertVerdict.NEUTRAL

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id=module_id,
            verdict=verdict,
            score_delta=0.3 if has_weak_enc else 0.0,
            confidence=0.6,
            severity_hint="MEDIUM" if has_weak_enc else None,
            summary=f"Encryption: {len(rc4_only)} RC4-only accounts, {len(des_findings)} DES findings",
            reasoning=["RC4 is crackable offline after Kerberoasting", "DES is completely broken"],
            supporting_signals=[f"{len(rc4_only)} RC4-only service accounts"] if rc4_only else [],
            mitre_techniques=["T1550.003"],
            kill_chain_stage="credential_access",
            remediation_commands=["Set-ADUser -Identity <name> -KerberosEncryptionType AES128,AES256"],
            detection_opportunities=["Alert on RC4 Kerberos ticket requests (etype 23 in event 4769)"],
        )

    async def analyze_async(self, ctx: ValidationAssessmentContext) -> ExpertDecision:
        return self.evaluate("kerberos", ctx)


@register("kerberos")
class KerberosDelegationExpert(BaseExpert):
    expert_id = "delegation"
    expert_name = "Kerberos Delegation Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        # Check unconstrained delegation (highest risk) and RBCD
        unconstrained = ctx.unconstrained_delegation  # list of entity IDs
        rbcd = ctx.rbcd_edges  # list of dicts

        # Constrained delegation to sensitive targets
        constrained = ctx.constrained_delegation  # list of {entity_id, allowed_spns}
        dc_spns = [c for c in constrained if any(
            "ldap" in str(s).lower() or "cifs/dc" in str(s).lower() or "host/dc" in str(s).lower()
            for s in c.get('allowed_spns', [])
        )]

        tier0 = ctx.analyzer.get_tier0_nodes() if ctx.analyzer else set()
        unconstrained_tier0 = [eid for eid in unconstrained if eid in tier0]

        supporting: list[str] = []
        reasoning: list[str] = []

        if unconstrained:
            supporting.append(f"{len(unconstrained)} account(s) with unconstrained delegation — TGT harvesting risk.")
            reasoning.append("Unconstrained delegation stores TGTs in memory, enabling pass-the-ticket.")
        if unconstrained_tier0:
            supporting.append(f"{len(unconstrained_tier0)} unconstrained delegation account(s) are tier-0.")
        if rbcd:
            supporting.append(f"{len(rbcd)} RBCD (msDS-AllowedToActOnBehalfOf) edge(s) — impersonation risk.")
        if dc_spns:
            supporting.append(f"{len(dc_spns)} constrained delegation target(s) include DC SPNs — escalation path.")

        has_critical = bool(unconstrained_tier0 or dc_spns)
        has_risk = bool(unconstrained or rbcd)

        if has_critical:
            verdict = ExpertVerdict.SUPPORTS_EXPOSURE
            score_delta = 0.85
            confidence = 0.82
            severity_hint = "CRITICAL"
            summary = f"Delegation critical risk: {len(unconstrained_tier0)} unconstrained tier-0, {len(dc_spns)} constrained-to-DC."
        elif has_risk:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.4
            confidence = 0.6
            severity_hint = "HIGH"
            summary = f"Delegation risk: {len(unconstrained)} unconstrained, {len(rbcd)} RBCD edges."
        else:
            verdict = ExpertVerdict.NEUTRAL
            score_delta = 0.0
            confidence = 0.4
            severity_hint = None
            summary = "No significant delegation misconfigurations detected."

        return ExpertDecision(
            expert_id=self.expert_id,
            expert_name=self.expert_name,
            module_id=module_id,
            verdict=verdict,
            score_delta=score_delta,
            confidence=confidence,
            severity_hint=severity_hint,
            summary=summary,
            reasoning=reasoning,
            supporting_signals=supporting,
            mitre_techniques=["T1558.001", "T1134.001"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "Set-ADComputer -Identity <computer> -TrustedForDelegation $false",
                "# Replace unconstrained delegation with constrained or resource-based constrained delegation",
                "Set-ADAccountControl -Identity <account> -TrustedToAuthForDelegation $false",
            ],
            detection_opportunities=[
                "Monitor for TGT delegation events (event 4769 with ticket options forwardable)",
                "Alert on new msDS-AllowedToActOnBehalfOfOtherIdentity attribute writes (event 5136)",
                "Detect PrintSpooler/MS-RPRN coercion attempts targeting unconstrained delegation hosts",
            ],
        )
