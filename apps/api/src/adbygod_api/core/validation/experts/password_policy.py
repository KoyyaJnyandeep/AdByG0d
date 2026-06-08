from __future__ import annotations

from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("password_policy")
class DefaultPasswordPolicyExpert(BaseExpert):
    expert_id = "default_policy"
    expert_name = "Default Password Policy Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        policies = getattr(ctx, 'password_policy_objects', [])
        default_policy = next((p for p in policies if _get(p, 'is_default', True)), {})

        min_length = _get(default_policy, 'min_length', _get(default_policy, 'minpwdlength', 7))
        max_age_days = _get(default_policy, 'max_age_days', _get(default_policy, 'maxpwdage', 42))
        complexity = _get(default_policy, 'complexity_enabled', _get(default_policy, 'pwdproperties', 0))
        lockout = _get(default_policy, 'lockout_threshold', _get(default_policy, 'lockoutthreshold', 0))

        issues = []
        if int(min_length) < 12:
            issues.append(f"min length {min_length} < 12")
        if int(max_age_days) > 90 if max_age_days else False:
            issues.append(f"max age {max_age_days}d > 90d")
        if not complexity:
            issues.append("complexity disabled")
        if not lockout:
            issues.append("no lockout threshold")

        spray_findings = [f for f in getattr(ctx, 'findings', [])
                          if (getattr(f, 'finding_type', '') or '') in ('LARGE_SPRAY_SURFACE', 'WEAK_PASSWORD_LENGTH', 'NO_PASSWORD_COMPLEXITY', 'NO_LOCKOUT_POLICY')]

        score = min(0.9, len(issues) * 0.2 + len(spray_findings) * 0.1)

        if score >= 0.6:
            verdict, sev = ExpertVerdict.SUPPORTS_EXPOSURE, "HIGH"
        elif score > 0:
            verdict, sev = ExpertVerdict.WEAK_SUPPORT, "MEDIUM"
        else:
            verdict, sev = ExpertVerdict.NEUTRAL, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="password_policy",
            verdict=verdict, score_delta=score, confidence=0.8 if policies else 0.4,
            severity_hint=sev,
            summary=f"Default policy: {', '.join(issues) if issues else 'acceptable'}",
            reasoning=[f"Policy weakness: {i}" for i in issues] if issues else ["Default password policy is acceptable"],
            supporting_signals=issues if issues else [],
            mitre_techniques=["T1110.003"],
            kill_chain_stage="initial_access",
            remediation_commands=[
                "# Set minimum 12-character passwords (ideally 14+):",
                "Set-ADDefaultDomainPasswordPolicy -Identity domain.com -MinPasswordLength 14",
                "Set-ADDefaultDomainPasswordPolicy -Identity domain.com -LockoutThreshold 5",
                "Set-ADDefaultDomainPasswordPolicy -Identity domain.com -MaxPasswordAge (New-TimeSpan -Days 90)",
            ],
            detection_opportunities=[
                "Monitor for password spray patterns: many 4625 events across many accounts",
                "Alert on >5 failed logins across >10 distinct accounts in 10 minutes",
            ],
        )


@register("password_policy")
class FineGrainedPolicyExpert(BaseExpert):
    expert_id = "fgpp"
    expert_name = "Fine-Grained Password Policy Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        policies = getattr(ctx, 'password_policy_objects', [])
        fgpp = [p for p in policies if not _get(p, 'is_default', True)]

        # Check if privileged groups have FGPP
        has_admin_fgpp = any(
            any(kw in str(_get(p, 'applies_to', '')).lower() for kw in ['admin', 'da', 'domain admin'])
            for p in fgpp
        )

        missing_fgpp = not has_admin_fgpp

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="password_policy",
            verdict=ExpertVerdict.WEAK_SUPPORT if missing_fgpp else ExpertVerdict.NEUTRAL,
            score_delta=0.3 if missing_fgpp else 0.0,
            confidence=0.6,
            severity_hint="MEDIUM" if missing_fgpp else None,
            summary=f"FGPP: {len(fgpp)} policy(ies), privileged groups covered: {'yes' if has_admin_fgpp else 'NO'}",
            reasoning=[
                "Privileged accounts without FGPP use potentially weak default policy",
                "Domain Admins should have FGPP: min 20+ chars, no expiry, low lockout",
            ] if missing_fgpp else ["Privileged accounts have FGPP coverage"],
            supporting_signals=["No FGPP for admin groups"] if missing_fgpp else [],
            mitre_techniques=["T1110.003"],
            kill_chain_stage="initial_access",
            remediation_commands=[
                "# Create FGPP for Domain Admins:",
                "New-ADFineGrainedPasswordPolicy -Name 'AdminPolicy' -Precedence 1 -MinPasswordLength 20 -LockoutThreshold 3",
                "Add-ADFineGrainedPasswordPolicySubject 'AdminPolicy' -Subjects 'Domain Admins'",
            ],
            detection_opportunities=["FGPP audit: Get-ADFineGrainedPasswordPolicy -Filter *"],
        )


@register("password_policy")
class SprayCandidateExpert(BaseExpert):
    expert_id = "spray_candidate"
    expert_name = "Password Spray Candidate Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        spray_candidates = getattr(ctx, 'spray_candidates', [])
        spray_findings = [f for f in getattr(ctx, 'findings', [])
                          if (getattr(f, 'finding_type', '') or '') in ('LARGE_SPRAY_SURFACE', 'ADMIN_PWD_NEVER_EXPIRES')]

        # Extract the actual candidate count from the sentinel dict populated by the context builder
        candidate_count = sum(
            (c.get('count', 1) if isinstance(c, dict) else 1)
            for c in spray_candidates
        )
        user_count = getattr(ctx, 'user_count', 0) or len([
            e for e in getattr(ctx, 'entities', [])
            if (getattr(getattr(e, 'entity_type', None), 'value', '') or '').lower() == 'user'
        ])
        count = candidate_count + len(spray_findings)
        pct = (candidate_count / max(user_count, 1) * 100) if candidate_count else 0

        if pct > 15 or count > 10 or candidate_count > 20:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.8, "HIGH"
        elif pct > 5 or count > 10:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.45, "MEDIUM"
        elif count:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.2, "LOW"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="password_policy",
            verdict=verdict, score_delta=score, confidence=0.75,
            severity_hint=sev,
            summary=f"Spray surface: {count} candidate(s) ({pct:.0f}% of users)",
            reasoning=[
                f"{count} accounts are spray candidates (enabled, weak/no policy)",
                "Password spray with 1 attempt/account bypasses lockout",
                "Kerberoastable accounts = offline crack after spray",
            ] if count else ["Minimal spray surface detected"],
            supporting_signals=[f"{count} spray candidate(s)"] if count else [],
            blast_radius_hint=count,
            mitre_techniques=["T1110.003"],
            kill_chain_stage="initial_access",
            remediation_commands=[
                "# Identify passwordNeverExpires accounts:",
                "Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true}",
                "# Enforce password rotation policy on all accounts",
            ],
            detection_opportunities=[
                "Alert on >1 failed login per unique account across >20 accounts in 5 minutes",
                "Monitor for Kerberos pre-auth failures across many usernames (AS-REP spray)",
            ],
        )


@register("password_policy")
class PasswordNotRequiredExpert(BaseExpert):
    expert_id = "password_not_required"
    expert_name = "Password Not Required Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        notreqd_findings = [f for f in getattr(ctx, 'findings', [])
                            if (getattr(f, 'finding_type', '') or '') == 'PASSWD_NOTREQD']
        aes_findings = [f for f in getattr(ctx, 'findings', [])
                        if (getattr(f, 'finding_type', '') or '') in ('KERBEROAST_RC4_ONLY', 'DES_ONLY_KERBEROS_ACCOUNT')]

        count = len(notreqd_findings) + len(aes_findings)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="password_policy",
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE if count >= 2 else (ExpertVerdict.WEAK_SUPPORT if count else ExpertVerdict.NEUTRAL),
            score_delta=0.6 if count >= 2 else (0.3 if count else 0.0),
            confidence=0.75 if count else 0.4,
            severity_hint="HIGH" if count >= 2 else ("MEDIUM" if count else None),
            summary=f"Password flags: {len(notreqd_findings)} PASSWD_NOTREQD, {len(aes_findings)} RC4-only accounts",
            reasoning=[
                "PASSWD_NOTREQD = account can authenticate with empty password",
                "RC4-only service accounts = offline crackable after Kerberoasting",
            ] if count else [],
            supporting_signals=[f"{len(notreqd_findings)} PASSWD_NOTREQD accounts"] if notreqd_findings else [],
            mitre_techniques=["T1110", "T1558.003"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Find PASSWD_NOTREQD accounts: Get-ADUser -Filter {PasswordNotRequired -eq $true}",
                "# Clear the flag: Set-ADAccountControl -Identity <name> -PasswordNotRequired $false",
            ],
            detection_opportunities=["Audit PASSWD_NOTREQD flag changes (event 4738)"],
        )
