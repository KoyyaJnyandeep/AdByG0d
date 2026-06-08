from __future__ import annotations
import logging
from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.context import ValidationAssessmentContext
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register

log = logging.getLogger(__name__)

def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)

def _finding_type(f) -> str:
    return str(_get(f, "finding_type", "") or "").upper()

def _finding_title(f) -> str:
    return str(_get(f, "title", "") or "").lower()


@register("domain_config")
class KrbtgtRotationExpert(BaseExpert):
    expert_id = "dom_krbtgt_rotation"
    expert_name = "KRBTGT Password Rotation Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        krbtgt_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("KRBTGT_STALE", "DOM-002", "KRBTGT_PASSWORD_AGE")
            or any(kw in _finding_title(f) for kw in ("krbtgt", "kerberos tgt", "golden ticket", "krb password"))
        ]

        # Get krbtgt age from domain info in context (set by collector)
        krbtgt_age = 0
        for ev in ctx.evidence:
            raw = getattr(ev, "raw_data", None) or {}
            if isinstance(raw, dict) and "krbtgt_password_age_days" in raw:
                krbtgt_age = int(raw.get("krbtgt_password_age_days", 0))
                break

        # Also check entity attributes for krbtgt entity
        for e in ctx.entities:
            if str(_get(e, "sam_account_name", "")).lower() == "krbtgt":
                age_candidate = int(_get(e, "attributes", {}).get("days_since_last_logon", 0) or 0)
                if age_candidate > 0:
                    krbtgt_age = max(krbtgt_age, age_candidate)

        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        finding_ids = [str(_get(f, "id", "")) for f in krbtgt_findings[:5]]

        if krbtgt_findings:
            supporting.append(f"{len(krbtgt_findings)} KRBTGT staleness finding(s) — golden ticket forgery risk elevated.")
        if krbtgt_age > 0:
            if krbtgt_age > 365:
                supporting.append(f"KRBTGT password age: {krbtgt_age} days — severely stale, golden ticket window wide open.")
            elif krbtgt_age > 180:
                supporting.append(f"KRBTGT password age: {krbtgt_age} days — rotation overdue (recommended: 180 days max).")
            elif krbtgt_age > 90:
                supporting.append(f"KRBTGT password age: {krbtgt_age} days — approaching recommended rotation threshold.")
            else:
                contradicting.append(f"KRBTGT password rotated recently ({krbtgt_age} days ago) — within acceptable window.")
        else:
            missing.append("KRBTGT password age (requires Get-ADUser krbtgt -Properties PasswordLastSet)")

        if krbtgt_age > 365 or len(krbtgt_findings) >= 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.90, 0.85, "CRITICAL"
            summary = f"KRBTGT stale: {krbtgt_age}d age — existing compromised krbtgt hash enables persistent golden tickets."
        elif krbtgt_age > 180:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.65, 0.75, "HIGH"
            summary = f"KRBTGT rotation overdue ({krbtgt_age} days) — golden ticket forgery window open."
        elif krbtgt_age > 0:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.25, 0.60, "MEDIUM"
            summary = f"KRBTGT age {krbtgt_age} days — within acceptable range but monitor for rotation."
        elif contradicting:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.CONTRADICTS_EXPOSURE, -0.2, 0.65, None
            summary = "KRBTGT recently rotated — golden ticket persistence window minimized."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.25, None
            summary = "KRBTGT password age unknown — collection did not run krbtgt enumeration."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, contradicting_signals=contradicting, missing_signals=missing,
            related_finding_ids=finding_ids,
            telemetry={"krbtgt_age_days": krbtgt_age, "krbtgt_findings": len(krbtgt_findings)},
            mitre_techniques=["T1003.006", "T1558"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Rotate KRBTGT password TWICE (24h apart) to invalidate existing golden tickets:",
                "# Step 1: Reset-KrbtgtPassword (Microsoft script from https://aka.ms/krbtgtkeys)",
                "# Step 2: Wait 10 hours (max ticket lifetime), then rotate again",
                "# Or use: Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (New-Object SecureString)",
            ],
            detection_opportunities=[
                "Monitor for TGT tickets with timestamps predating the last KRBTGT rotation",
                "Alert on TGT tickets with unusual privilege attributes (event 4768 with unusual PAC data)",
                "Use Microsoft Defender for Identity golden ticket detection",
            ],
        )


@register("domain_config")
class DomainFunctionalLevelExpert(BaseExpert):
    expert_id = "dom_functional_level"
    expert_name = "Domain Functional Level & MAQ Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        dfl_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("LOW_DOMAIN_FUNCTIONAL_LEVEL", "DOM-001", "LOW_FUNCTIONAL_LEVEL")
            or any(kw in _finding_title(f) for kw in ("domain functional level", "functional level", "dfl", "forest functional"))
        ]
        maq_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("MACHINE_ACCOUNT_QUOTA", "MAQ-001", "MAQ_ABUSE")
            or any(kw in _finding_title(f) for kw in ("machine account quota", "maq", "ms-ds-machineaccountquota"))
        ]

        maq_value = ctx.maq_value
        supporting: list[str] = []
        contradicting: list[str] = []
        missing: list[str] = []
        finding_ids = [str(_get(f, "id", "")) for f in (dfl_findings + maq_findings)[:8]]

        if dfl_findings:
            supporting.append(f"{len(dfl_findings)} domain functional level finding(s) — legacy DFL limits security features.")
        if maq_findings:
            supporting.append(f"{len(maq_findings)} machine account quota finding(s) — any domain user can create {maq_value} computer accounts.")

        if maq_value >= 10:
            supporting.append(f"ms-DS-MachineAccountQuota = {maq_value} — enables RBCD/Kerberoast via machine account creation by any domain user.")
        elif maq_value > 0:
            supporting.append(f"ms-DS-MachineAccountQuota = {maq_value} — non-zero MAQ creates some computer account creation surface.")
        elif maq_value == 0:
            contradicting.append("ms-DS-MachineAccountQuota = 0 — computer account creation by non-admins disabled.")

        if not (dfl_findings or maq_findings):
            missing.append("Domain functional level and MAQ data (requires Get-ADDomain)")

        total = len(dfl_findings) + len(maq_findings)
        if total >= 2 or maq_value >= 10:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.72, 0.78, "HIGH"
            summary = f"Domain config gaps: DFL={len(dfl_findings)} findings, MAQ={maq_value} ({len(maq_findings)} findings)."
        elif total == 1 or (0 < maq_value < 10):
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.35, 0.58, "MEDIUM"
            summary = f"Partial domain config issue: {total} finding(s), MAQ={maq_value}."
        elif contradicting:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.CONTRADICTS_EXPOSURE, -0.15, 0.65, None
            summary = "Domain functional level and MAQ appear adequately configured."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.25, None
            summary = "Domain configuration data not available."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, contradicting_signals=contradicting, missing_signals=missing,
            related_finding_ids=finding_ids,
            telemetry={"dfl_findings": len(dfl_findings), "maq_findings": len(maq_findings), "maq_value": maq_value},
            mitre_techniques=["T1558", "T1098"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "# Set MAQ to 0 (recommended — prevents non-admin computer account creation):",
                "Set-ADDomain -Identity corp.local -Replace @{'ms-DS-MachineAccountQuota'=0}",
                "# Raise domain functional level via Active Directory Domains and Trusts MMC",
                "# Or: Set-ADDomainMode -Identity corp.local -DomainMode Windows2016Domain",
            ],
            detection_opportunities=[
                "Alert on new computer account creation by non-computer-admin accounts (event 4741)",
                "Monitor domain functional level changes (event 4739)",
            ],
        )


@register("domain_config")
class DomainSecurityBaselineExpert(BaseExpert):
    expert_id = "dom_security_baseline"
    expert_name = "Domain Security Baseline Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        """Aggregate domain configuration security posture across all domain-level findings."""
        dom_findings = [
            f for f in ctx.findings
            if any(kw in _finding_type(f) for kw in ("DOM-", "KRBTGT", "MAQ", "MACHINE_ACCOUNT", "FUNCTIONAL_LEVEL"))
            or any(kw in _finding_title(f) for kw in (
                "domain", "krbtgt", "machine account quota", "functional level",
                "domain controller", "dc configuration"
            ))
        ]

        critical = [f for f in dom_findings if str(_get(f, "severity", "")).upper() == "CRITICAL"]
        high = [f for f in dom_findings if str(_get(f, "severity", "")).upper() == "HIGH"]

        supporting: list[str] = []
        missing: list[str] = []

        if critical:
            supporting.append(f"{len(critical)} CRITICAL domain configuration finding(s).")
        if high:
            supporting.append(f"{len(high)} HIGH domain configuration finding(s).")
        if ctx.dc_count > 0:
            supporting.append(f"{ctx.dc_count} domain controller(s) in scope.")
        if not dom_findings:
            missing.append("Domain baseline data (Get-ADDomain, Get-ADDomainController, krbtgt enumeration)")

        if len(critical) >= 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.88, 0.83, "CRITICAL"
            summary = f"Critical domain baseline gaps: {len(critical)} CRITICAL + {len(high)} HIGH config findings."
        elif len(dom_findings) >= 2:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.65, 0.72, "HIGH"
            summary = f"Domain configuration gaps: {len(dom_findings)} finding(s) across baseline controls."
        elif len(dom_findings) == 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.35, 0.55, "MEDIUM"
            summary = "Single domain configuration issue detected."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.20, None
            summary = "Domain configuration baseline data not available."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, missing_signals=missing,
            related_finding_ids=[str(_get(f, "id", "")) for f in dom_findings[:10]],
            telemetry={"total_dom_findings": len(dom_findings), "critical": len(critical), "high": len(high), "dc_count": ctx.dc_count, "maq": ctx.maq_value},
            mitre_techniques=["T1003.006", "T1558", "T1098"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=["# Review and implement CIS Domain Security Baseline v3.0"],
            detection_opportunities=["Monitor domain-wide configuration changes via AD audit events 4739, 4742"],
        )
