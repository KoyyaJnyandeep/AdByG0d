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

def _attrs(e) -> dict:
    raw = _get(e, "attributes", None) or _get(e, "attrs", None) or {}
    return raw if isinstance(raw, dict) else {}


@register("user_accounts")
class PasswordNotRequiredExpert(BaseExpert):
    expert_id = "usr_passwd_notreqd"
    expert_name = "PASSWD_NOTREQD Flag Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        notreqd_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("PASSWD_NOTREQD", "USR-001", "PASSWORD_NOT_REQUIRED")
            or any(kw in _finding_title(f) for kw in ("passwd_notreqd", "password not required", "no password required"))
        ]

        notreqd_entities = [
            e for e in ctx.entities
            if _attrs(e).get("uac_passwd_notreqd") or _attrs(e).get("passwd_notreqd")
        ]

        supporting: list[str] = []
        missing: list[str] = []
        finding_ids = [str(_get(f, "id", "")) for f in notreqd_findings[:8]]
        entity_ids = [str(_get(e, "id", "")) for e in notreqd_entities[:10]]

        if notreqd_findings:
            supporting.append(f"{len(notreqd_findings)} PASSWD_NOTREQD finding(s) — accounts can authenticate with blank password.")
            supporting.append("Attackers can enumerate and abuse these accounts for initial foothold without credentials.")
        if notreqd_entities:
            admin_notreqd = [e for e in notreqd_entities if _get(e, "is_admin_count", False)]
            supporting.append(f"{len(notreqd_entities)} entity/entities with PASSWD_NOTREQD flag in graph ({len(admin_notreqd)} admin-count).")

        if not (notreqd_findings or notreqd_entities):
            missing.append("PASSWD_NOTREQD UAC flag data (requires user enumeration with UAC attributes)")

        total = len(notreqd_findings) + len(notreqd_entities)
        admin_exposed = any(_get(e, "is_admin_count", False) for e in notreqd_entities)

        if admin_exposed or len(notreqd_findings) >= 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.90, 0.85, "CRITICAL"
            summary = f"PASSWD_NOTREQD accounts detected ({total} signals) — blank password authentication possible."
        elif notreqd_entities:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.70, 0.75, "HIGH"
            summary = f"{len(notreqd_entities)} account(s) with PASSWD_NOTREQD flag allow unauthenticated access."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.25, None
            summary = "No PASSWD_NOTREQD data available — UAC enumeration may not have run."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, missing_signals=missing,
            related_finding_ids=finding_ids, related_entity_ids=entity_ids,
            telemetry={"notreqd_findings": len(notreqd_findings), "notreqd_entities": len(notreqd_entities)},
            mitre_techniques=["T1078", "T1110.001"],
            kill_chain_stage="initial_access",
            remediation_commands=[
                "# Find and remediate PASSWD_NOTREQD accounts:",
                "Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired | Select SamAccountName,Enabled,DistinguishedName",
                "# Set-ADUser -Identity <account> -PasswordNotRequired $false",
                "# Then force a password reset: Set-ADAccountPassword -Identity <account> -Reset",
            ],
            detection_opportunities=[
                "Monitor for authentication with blank passwords (event 4624 with empty password field in NTLM audit)",
                "Alert on any PASSWD_NOTREQD flag change (event 4738)",
            ],
        )


@register("user_accounts")
class PrivilegedAccountHygieneExpert(BaseExpert):
    expert_id = "usr_privileged_hygiene"
    expert_name = "Privileged Account Hygiene Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        stale_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("STALE_ADMIN_ACCOUNT", "USR-003", "ADMIN_STALE")
            or any(kw in _finding_title(f) for kw in ("stale admin", "dormant admin", "inactive admin"))
        ]
        noexpiry_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("ADMIN_PWD_NEVER_EXPIRES", "USR-002", "NEVER_EXPIRE")
            or any(kw in _finding_title(f) for kw in ("never expires", "password never", "admin.*never"))
        ]
        rid500_findings = [
            f for f in ctx.findings
            if _finding_type(f) in ("DEFAULT_ADMIN_ENABLED", "USR-004")
            or any(kw in _finding_title(f) for kw in ("rid 500", "default admin", "administrator enabled", "built-in admin"))
        ]

        supporting: list[str] = []
        missing: list[str] = []
        finding_ids: list[str] = []

        if noexpiry_findings:
            supporting.append(f"{len(noexpiry_findings)} admin account(s) with non-expiring passwords — rotation never enforced.")
            finding_ids += [str(_get(f, "id", "")) for f in noexpiry_findings[:5]]
        else:
            missing.append("Admin password expiry policy data (USR-002)")

        if stale_findings:
            supporting.append(f"{len(stale_findings)} stale privileged account(s) — unused admin accounts expand attack surface.")
            finding_ids += [str(_get(f, "id", "")) for f in stale_findings[:5]]
        else:
            missing.append("Stale admin account data (last-logon timestamps for admin-count accounts)")

        if rid500_findings:
            supporting.append(f"{len(rid500_findings)} built-in Administrator (RID-500) account(s) enabled — well-known attack target.")
            finding_ids += [str(_get(f, "id", "")) for f in rid500_findings[:3]]

        total = len(stale_findings) + len(noexpiry_findings) + len(rid500_findings)
        if total >= 3:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.78, 0.80, "HIGH"
            summary = f"Multiple privileged account hygiene gaps: {total} findings (stale={len(stale_findings)}, no-expiry={len(noexpiry_findings)}, RID500={len(rid500_findings)})."
        elif total >= 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.42, 0.62, "HIGH"
            summary = f"Privileged account hygiene issues: {total} finding(s)."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.25, None
            summary = "No privileged account hygiene data available."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, missing_signals=missing,
            related_finding_ids=finding_ids[:10],
            telemetry={"stale": len(stale_findings), "no_expiry": len(noexpiry_findings), "rid500": len(rid500_findings)},
            mitre_techniques=["T1078.002"],
            kill_chain_stage="privilege_escalation",
            remediation_commands=[
                "# Find admin accounts with password never expires:",
                "Get-ADUser -Filter {AdminCount -eq 1 -and PasswordNeverExpires -eq $true} | Select SamAccountName",
                "# Disable built-in Administrator: Disable-ADAccount -Identity Administrator",
                "# Find stale admin accounts (no logon > 90 days):",
                "Get-ADUser -Filter {AdminCount -eq 1} -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-90)}",
            ],
            detection_opportunities=[
                "Alert on authentication from stale/disabled admin accounts (event 4625 for disabled, 4648 for explicit logon)",
                "Monitor built-in Administrator usage (event 4624 with RID 500)",
            ],
        )


@register("user_accounts")
class AccountFlagSweepExpert(BaseExpert):
    expert_id = "usr_flag_sweep"
    expert_name = "User Account UAC Flag Sweep Expert"

    def evaluate(self, module_id: str, ctx: ValidationAssessmentContext) -> ExpertDecision:
        """Aggregate sweep of all user account flag findings."""
        uac_findings = [
            f for f in ctx.findings
            if any(kw in _finding_type(f) for kw in ("USR-", "PASSWD_", "ADMIN_PWD", "STALE_ADMIN", "DEFAULT_ADMIN"))
            or any(kw in _finding_title(f) for kw in (
                "password not required", "never expires", "stale admin", "default admin",
                "uac", "account flag", "user account control"
            ))
        ]

        critical_uac = [f for f in uac_findings if str(_get(f, "severity", "")).upper() == "CRITICAL"]
        high_uac = [f for f in uac_findings if str(_get(f, "severity", "")).upper() == "HIGH"]

        # Count entity-level signals
        entities_with_uac_issues = [
            e for e in ctx.entities
            if (
                _attrs(e).get("uac_passwd_notreqd")
                or _attrs(e).get("pwd_never_expires")
                or _attrs(e).get("uac_dont_expire_passwd")
            )
            and _get(e, "is_admin_count", False)
        ]

        supporting: list[str] = []
        missing: list[str] = []

        if critical_uac:
            supporting.append(f"{len(critical_uac)} CRITICAL user account flag finding(s).")
        if high_uac:
            supporting.append(f"{len(high_uac)} HIGH user account flag finding(s).")
        if entities_with_uac_issues:
            supporting.append(f"{len(entities_with_uac_issues)} admin-count entity/entities with UAC hygiene flags.")

        if not uac_findings:
            missing.append("User account UAC flag enumeration (requires Get-ADUser with UAC properties)")

        total = len(uac_findings)
        if len(critical_uac) >= 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.85, 0.82, "CRITICAL"
            summary = f"Critical user account hygiene gaps: {len(critical_uac)} CRITICAL, {len(high_uac)} HIGH findings."
        elif total >= 2:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.SUPPORTS_EXPOSURE, 0.68, 0.72, "HIGH"
            summary = f"Multiple user account hygiene issues: {total} findings."
        elif total == 1:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.WEAK_SUPPORT, 0.38, 0.55, "MEDIUM"
            summary = "Single user account hygiene issue detected."
        else:
            verdict, score_delta, confidence, severity_hint = ExpertVerdict.INSUFFICIENT_DATA, 0.0, 0.20, None
            summary = "User account UAC data not collected."

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id=module_id,
            verdict=verdict, score_delta=score_delta, confidence=confidence,
            severity_hint=severity_hint, summary=summary,
            supporting_signals=supporting, missing_signals=missing,
            related_finding_ids=[str(_get(f, "id", "")) for f in uac_findings[:10]],
            related_entity_ids=[str(_get(e, "id", "")) for e in entities_with_uac_issues[:10]],
            telemetry={"total_uac_findings": total, "critical": len(critical_uac), "high": len(high_uac), "admin_uac_entities": len(entities_with_uac_issues)},
            mitre_techniques=["T1078", "T1078.002"],
            kill_chain_stage="initial_access",
            remediation_commands=[
                "# Full UAC flag audit: Get-ADUser -Filter * -Properties UserAccountControl | Where-Object {$_.UserAccountControl -band 32}",
            ],
            detection_opportunities=["Monitor for new accounts with problematic UAC flags (event 4720 + 4738)"],
        )
