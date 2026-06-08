from __future__ import annotations
import logging
from adbygod_api.core.dcsync_principals import classify_dcsync_principal
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

def _classify_principal(meta: dict) -> str:
    """Backward-compatible wrapper used by the expert tests."""
    return classify_dcsync_principal(meta)


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("dcsync")
class DCSyncExpert(BaseExpert):
    expert_id = "dcsync_expert"
    expert_name = "DCSync Rights Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        analyzer = ctx.analyzer
        dcsync_edges = analyzer._edge_type_index.get("DCSYNC", []) if analyzer else ctx.edge_type_index.get("DCSYNC", [])

        if not ctx.has_entities and not ctx.has_edges:
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.2,
                summary="No entity or edge data available for DCSync analysis.",
                missing_signals=["DCSYNC graph edges", "Entity data"],
            )

        if not dcsync_edges:
            # check findings
            dc_findings = [
                f for f in ctx.findings
                if "dcsync" in str(_get(f, "finding_type", "")).lower()
                or "replication" in str(_get(f, "title", "") or "").lower()
            ]
            if dc_findings:
                return ExpertDecision(
                    expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                    verdict=ExpertVerdict.WEAK_SUPPORT, score_delta=0.2, confidence=0.4,
                    summary="DCSync-related findings present but no graph edges collected.",
                    related_finding_ids=[str(f.id) for f in dc_findings[:5]],
                    supporting_signals=[f"Finding: {f.title}" for f in dc_findings[:3]],
                    missing_signals=["DCSYNC graph edges for confirmation"],
                    mitre_techniques=["T1003.006"],
                    kill_chain_stage="credential_access",
                    detection_opportunities=["Monitor replication traffic from non-DC sources (event 4662 with replication GUIDs)"],
                )
            return ExpertDecision(
                expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
                verdict=ExpertVerdict.INSUFFICIENT_DATA, score_delta=0.0, confidence=0.3,
                summary="No DCSYNC edges found in graph.",
                missing_signals=["DCSYNC graph edges"],
            )

        expected: list[tuple[str, str]] = []
        sync_like: list[tuple[str, str]] = []
        suspicious: list[tuple[str, str]] = []

        for src_id, tgt_id in dcsync_edges:
            meta = analyzer.entity_meta.get(src_id, {}) if analyzer else {}
            classification = _classify_principal(meta)
            if classification == "expected":
                expected.append((src_id, tgt_id))
            elif classification == "sync_like":
                sync_like.append((src_id, tgt_id))
            else:
                suspicious.append((src_id, tgt_id))

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        entity_ids: list[str] = []
        reasoning: list[str] = []

        if expected:
            contradicting.append(
                f"{len(expected)} DCSYNC edge(s) from expected principals "
                f"(DC/Domain Admins/built-ins) — treated as normal operational context."
            )
            reasoning.append(f"Expected principals: {[ctx.entity_name(s) for s,_ in expected[:3]]}")

        if sync_like:
            supporting.append(
                f"{len(sync_like)} DCSYNC edge(s) from sync-like accounts require legitimacy review "
                f"(possible Azure AD Connect): {[ctx.entity_name(s) for s,_ in sync_like[:3]]}"
            )
            entity_ids += [s for s, _ in sync_like]
            reasoning.append("Sync-like accounts are not auto-safe — verify authorization.")

        if suspicious:
            supporting.append(
                f"{len(suspicious)} DCSYNC edge(s) from NON-DEFAULT principals at domain scope: "
                f"{[ctx.entity_name(s) for s,_ in suspicious[:5]]}"
            )
            entity_ids += [s for s, _ in suspicious]
            reasoning.append(
                "Non-default principals with DCSync rights can replicate all domain secrets "
                "including krbtgt — strong exposure indicator."
            )

        # Check tier-0 adjacency of suspicious principals
        tier0 = analyzer.get_tier0_nodes() if analyzer else set()
        suspicious_reach_tier0 = [s for s, tgt_id in suspicious if tgt_id in tier0 or s in tier0]

        if suspicious:
            if suspicious_reach_tier0:
                verdict = ExpertVerdict.SUPPORTS_EXPOSURE
                score_delta = 0.95
                confidence = 0.88
                severity_hint = "CRITICAL"
                summary = (
                    f"{len(suspicious)} non-default principal(s) hold DCSync rights at domain scope. "
                    f"Combined with tier-0 adjacency, this models a critical replication exposure path."
                )
            else:
                verdict = ExpertVerdict.SUPPORTS_EXPOSURE
                score_delta = 0.85
                confidence = 0.82
                severity_hint = "CRITICAL"
                summary = (
                    f"{len(suspicious)} non-default principal(s) hold DCSync rights. "
                    f"This models a plausible domain credential replication exposure."
                )
        elif sync_like:
            verdict = ExpertVerdict.WEAK_SUPPORT
            score_delta = 0.35
            confidence = 0.55
            severity_hint = "HIGH"
            summary = (
                f"{len(sync_like)} sync-like account(s) hold DCSync rights. "
                f"Legitimacy review required — may be expected for directory sync but needs verification."
            )
        else:
            verdict = ExpertVerdict.CONTRADICTS_EXPOSURE
            score_delta = -0.5
            confidence = 0.85
            severity_hint = None
            summary = (
                f"All {len(expected)} DCSYNC edge(s) originate from expected built-in principals "
                f"(DCs, Domain Admins, built-ins). No anomalous replication rights detected."
            )

        if not sync_like and not suspicious:
            missing.append("Non-default principal with DCSync rights (none found — this is good)")

        telemetry = {
            "total_dcsync_edges": len(dcsync_edges),
            "expected_principals": len(expected),
            "sync_like_principals": len(sync_like),
            "suspicious_principals": len(suspicious),
        }

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            reasoning=reasoning, supporting_signals=supporting,
            contradicting_signals=contradicting, missing_signals=missing,
            related_entity_ids=list(set(entity_ids[:10])),
            telemetry=telemetry,
            mitre_techniques=["T1003.006"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Audit and revoke DS-Replication-Get-Changes-All from non-DC accounts",
                "Get-ObjectAcl -Identity 'DC=domain,DC=com' | Where-Object {$_.ObjectType -match 'Replication'} | ft IdentityReference",
                "Remove-ADPermission -Identity 'DC=domain,DC=com' -User <suspicious_account> -AccessRights ExtendedRight -Properties 'DS-Replication-Get-Changes-All'",
            ],
            detection_opportunities=[
                "Monitor event 4662 with replication GUIDs from non-DC sources",
                "Alert on replication traffic from workstations/member servers (unusual replication partner)",
                "Use Microsoft ATA/Defender for Identity to detect DCSync attacks in real-time",
            ],
        )
