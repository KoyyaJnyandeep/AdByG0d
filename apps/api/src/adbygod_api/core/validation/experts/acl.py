from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

_TOXIC_EDGE_TYPES = frozenset([
    "GENERIC_ALL", "WRITE_DACL", "WRITE_OWNER", "OWNS",
    "FORCE_CHANGE_PASSWORD", "ADD_MEMBER",
])


@register("acl")
class ACLExpert(BaseExpert):
    expert_id = "acl_expert"
    expert_name = "ACL Privilege Path Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        if not ctx.has_edges:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No edge data available for ACL analysis.",
                missing_signals=["ACL graph edges"],
            )

        tier0 = ctx.analyzer.get_tier0_nodes()
        toxic_to_tier0: list[tuple[str, str, str]] = []  # (src, tgt, edge_type)
        toxic_non_tier0: list[tuple[str, str, str]] = []
        entity_ids: list[str] = []

        for etype in _TOXIC_EDGE_TYPES:
            for src_id, tgt_id in ctx.analyzer._edge_type_index.get(etype, []):
                tgt_meta = ctx.analyzer.entity_meta.get(tgt_id, {})
                tgt_tier = tgt_meta.get("tier")
                is_tgt_tier0 = tgt_id in tier0 or tgt_tier == 0

                # Only flag if source is lower-tier than target (or source is non-privileged)
                if is_tgt_tier0:
                    toxic_to_tier0.append((src_id, tgt_id, etype))
                    entity_ids += [src_id, tgt_id]
                else:
                    toxic_non_tier0.append((src_id, tgt_id, etype))

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        reasoning: list[str] = []

        if toxic_to_tier0:
            by_type: dict[str, int] = {}
            for _, _, et in toxic_to_tier0:
                by_type[et] = by_type.get(et, 0) + 1
            supporting.append(
                f"{len(toxic_to_tier0)} toxic ACL edge(s) targeting tier-0 objects: "
                + ", ".join(f"{v}x {k}" for k, v in by_type.items())
            )
            examples = [(ctx.entity_name(s), ctx.entity_name(t), et) for s, t, et in toxic_to_tier0[:3]]
            supporting.append(f"Examples: {examples}")
            reasoning.append("ACL edges to tier-0 objects allow direct privilege escalation.")

        if toxic_non_tier0:
            supporting.append(
                f"{len(toxic_non_tier0)} additional toxic ACL edge(s) to non-tier-0 objects "
                f"(lateral movement / stepping stones)."
            )

        if not toxic_to_tier0 and not toxic_non_tier0:
            contradicting.append("No toxic ACL edges (GenericAll, WriteDACL, WriteOwner, etc.) found in graph.")
            missing.append("ACL data may be incomplete if collection modules did not run")

        # Verdict
        if toxic_to_tier0:
            verdict = ExpertVerdict.SUPPORTS_EXPOSURE
            score_delta = min(0.95, 0.7 + len(toxic_to_tier0) * 0.05)
            confidence = 0.88
            severity_hint = "CRITICAL"
            summary = (
                f"{len(toxic_to_tier0)} toxic ACL path(s) to tier-0 targets modeled. "
                f"Privilege escalation path exists in current graph state."
            )
        elif toxic_non_tier0:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.35
            confidence = 0.6
            severity_hint = "HIGH"
            summary = f"{len(toxic_non_tier0)} toxic ACL edge(s) found but none targeting tier-0 directly."
        else:
            verdict = ExpertVerdict.INSUFFICIENT_DATA
            score_delta = 0.0
            confidence = 0.4
            summary = "No toxic ACL edges detected in current graph data."

        telemetry = {
            "toxic_edges_to_tier0": len(toxic_to_tier0),
            "toxic_edges_other": len(toxic_non_tier0),
            "tier0_nodes": len(tier0),
        }

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            reasoning=reasoning, supporting_signals=supporting,
            contradicting_signals=contradicting, missing_signals=missing,
            related_entity_ids=list(set(entity_ids[:10])),
            telemetry=telemetry,
            mitre_techniques=["T1222.001", "T1078.002"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "Get-ObjectAcl -Identity <target> | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|WriteDACL|WriteOwner'} | Remove-ObjectAcl",
                "# Review and revoke excessive ACL permissions on tier-0 objects",
            ],
            detection_opportunities=[
                "Monitor ACL modification events (event 5136 — directory service object modification)",
                "Alert on WriteDACL/WriteOwner exercises against Domain Admins or Domain Controllers",
            ],
        )


@register("acl")
class OwnershipAbuseExpert(BaseExpert):
    expert_id = "ownership_abuse"
    expert_name = "Ownership Abuse Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        if not ctx.has_edges:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No edge data for ownership abuse analysis.",
                missing_signals=["ACL graph edges"],
            )

        tier0 = ctx.analyzer.get_tier0_nodes()
        writeowner_to_priv: list[tuple[str, str]] = []
        writeowner_other: list[tuple[str, str]] = []

        for src_id, tgt_id in ctx.analyzer._edge_type_index.get("WRITE_OWNER", []):
            tgt_meta = ctx.analyzer.entity_meta.get(tgt_id, {})
            is_priv = tgt_id in tier0 or tgt_meta.get("tier") == 0 or tgt_meta.get("is_admin_count", False)
            if is_priv:
                writeowner_to_priv.append((src_id, tgt_id))
            else:
                writeowner_other.append((src_id, tgt_id))

        supporting: list[str] = []
        reasoning: list[str] = []
        entity_ids: list[str] = []

        if writeowner_to_priv:
            supporting.append(
                f"{len(writeowner_to_priv)} WriteOwner edge(s) targeting privileged/tier-0 objects."
            )
            entity_ids = [s for s, _ in writeowner_to_priv[:5]] + [t for _, t in writeowner_to_priv[:5]]
            reasoning.append("WriteOwner on privileged object allows taking ownership then granting arbitrary ACL rights.")
        if writeowner_other:
            supporting.append(f"{len(writeowner_other)} WriteOwner edge(s) to non-tier-0 objects (stepping stones).")

        has_risk = bool(writeowner_to_priv)
        has_weak = bool(writeowner_other)

        if has_risk:
            verdict = ExpertVerdict.SUPPORTS_EXPOSURE
            score_delta = min(0.9, 0.65 + len(writeowner_to_priv) * 0.05)
            confidence = 0.82
            severity_hint = "CRITICAL"
            summary = f"{len(writeowner_to_priv)} WriteOwner edge(s) to privileged objects — ownership takeover path modeled."
        elif has_weak:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.3
            confidence = 0.55
            severity_hint = "HIGH"
            summary = f"{len(writeowner_other)} WriteOwner edge(s) found to non-tier-0 objects."
        else:
            verdict = ExpertVerdict.NEUTRAL
            score_delta = 0.0
            confidence = 0.4
            summary = "No WriteOwner edges detected targeting privileged objects."

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
            related_entity_ids=list(set(entity_ids[:10])),
            mitre_techniques=["T1222.001"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "Set-ADObject -Identity <target> -Replace @{nTSecurityDescriptor=<corrected_acl>}",
                "# Remove WriteOwner rights from non-admin principals on privileged objects",
            ],
            detection_opportunities=[
                "Monitor ownership changes on privileged AD objects (event 5136)",
                "Alert on DACL modification following ownership change on tier-0 objects",
            ],
        )

    async def analyze(self, ctx: ValidationAssessmentContext) -> ExpertDecision:
        return self.evaluate("acl", ctx)


@register("acl")
class AdminSDHolderExpert(BaseExpert):
    expert_id = "adminsd_holder"
    expert_name = "AdminSDHolder Abuse Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        if not ctx.has_edges:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No edge data for AdminSDHolder analysis.",
                missing_signals=["ACL graph edges"],
            )

        # Check for GenericAll/WriteDACL edges to AdminSDHolder container
        adminsd_targets: list[tuple[str, str, str]] = []
        dangerous_etypes = ("GENERIC_ALL", "WRITE_DACL")

        for etype in dangerous_etypes:
            for src_id, tgt_id in ctx.analyzer._edge_type_index.get(etype, []):
                tgt_meta = ctx.analyzer.entity_meta.get(tgt_id, {})
                tgt_name = str(tgt_meta.get("name", "") or tgt_meta.get("distinguishedname", "") or "").lower()
                # Match AdminSDHolder by name/dn
                if "adminsdholder" in tgt_name or "cn=adminsdholder" in tgt_name:
                    adminsd_targets.append((src_id, tgt_id, etype))

        # Also check findings for AdminSDHolder references
        adminsd_findings = [
            f for f in ctx.findings
            if "adminsdholder" in str(getattr(f, 'title', '') or '').lower()
            or "adminsdholder" in str(getattr(f, 'finding_type', '') or '').lower()
        ]

        has_risk = bool(adminsd_targets or adminsd_findings)

        supporting: list[str] = []
        reasoning: list[str] = []
        entity_ids: list[str] = []

        if adminsd_targets:
            supporting.append(f"{len(adminsd_targets)} GenericAll/WriteDACL edge(s) to AdminSDHolder container.")
            entity_ids = [s for s, _, _ in adminsd_targets[:5]]
            reasoning.append("WriteDACL on AdminSDHolder propagates to ALL protected principals via SDProp (every 60 min).")
        if adminsd_findings:
            supporting.append(f"{len(adminsd_findings)} AdminSDHolder-related finding(s) in assessment.")

        if has_risk:
            verdict = ExpertVerdict.SUPPORTS_EXPOSURE
            score_delta = 0.85
            confidence = 0.8
            severity_hint = "CRITICAL"
            summary = f"AdminSDHolder abuse path modeled: {len(adminsd_targets)} dangerous ACL edge(s) to AdminSDHolder."
        else:
            verdict = ExpertVerdict.NEUTRAL
            score_delta = 0.0
            confidence = 0.4
            summary = "No dangerous edges to AdminSDHolder detected."

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
            related_entity_ids=list(set(entity_ids[:10])),
            mitre_techniques=["T1078.002"],
            kill_chain_stage="persistence",
            remediation_commands=[
                "# Review ACL on CN=AdminSDHolder,CN=System,DC=domain,DC=com",
                "Get-ObjectAcl -Identity 'CN=AdminSDHolder,CN=System' | Where-Object {$_.ActiveDirectoryRights -match 'GenericAll|WriteDACL'} | Remove-ObjectAcl",
            ],
            detection_opportunities=[
                "Monitor ACL changes to CN=AdminSDHolder,CN=System (event 5136)",
                "Alert on SDProp propagation anomalies — unexpected ACL inheritance on protected groups",
            ],
        )

    async def analyze(self, ctx: ValidationAssessmentContext) -> ExpertDecision:
        return self.evaluate("acl", ctx)
