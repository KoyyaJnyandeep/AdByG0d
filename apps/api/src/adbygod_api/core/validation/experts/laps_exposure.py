from __future__ import annotations

from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("laps_exposure")
class LAPSReadExpert(BaseExpert):
    """LAPS read access allows local admin password access."""
    expert_id = "laps_read"
    expert_name = "LAPS Read Access Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        laps_read_edges = [
            e for e in getattr(ctx, 'edges', [])
            if (_get(e, 'relationship_type', '') or _get(getattr(e, 'edge_type', None), 'value', getattr(e, 'edge_type', ''))) in ('ReadLAPSPassword', 'ReadGMSAPassword')
        ]
        laps_findings = [f for f in getattr(ctx, 'findings', [])
                         if (getattr(f, 'finding_type', '') or '') in ('LAPS_PASSWORD_READABLE', 'GMSA_PASSWORD_READABLE')]

        exposed_accounts = set()
        for e in laps_read_edges:
            exposed_accounts.add(_get(e, 'source_name', _get(e, 'source_id', '')))

        count = len(laps_read_edges) + len(laps_findings)

        if count >= 5:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.85, "HIGH"
        elif count >= 2:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.65, "HIGH"
        elif count == 1:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.4, "MEDIUM"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="laps_exposure",
            verdict=verdict, score_delta=score, confidence=0.85 if laps_read_edges else 0.4,
            severity_hint=sev,
            summary=f"LAPS read: {count} exposure(s), {len(exposed_accounts)} accounts with read access",
            reasoning=[
                "Non-admin LAPS read = local admin password of affected computers",
                "Local admin → pass-the-hash → lateral movement chain",
                f"{len(exposed_accounts)} accounts can read LAPS passwords",
            ] if count else ["No LAPS read exposure found"],
            supporting_signals=[f"{count} LAPS read edge(s)"] if count else [],
            blast_radius_hint=len(laps_read_edges),
            mitre_techniques=["T1552.001", "T1078.003"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Audit LAPS ACLs: Find-AdmPwdExtendedRights -Identity <OU>",
                "# Remove unnecessary read rights",
                "Set-AdmPwdComputerSelfPermission -Identity <OU>",
            ],
            detection_opportunities=[
                "Monitor ms-Mcs-AdmPwd attribute reads (enable object-level auditing)",
                "Alert on LAPS password reads by non-admin accounts (event 4662)",
            ],
        )


@register("laps_exposure")
class LAPSCoverageExpert(BaseExpert):
    """LAPS coverage gap detection."""
    expert_id = "laps_coverage"
    expert_name = "LAPS Coverage Gap Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        laps_computers = getattr(ctx, 'laps_computers', [])
        computer_count = getattr(ctx, 'computer_count', 0)

        if computer_count == 0:
            coverage_pct = 100.0
        else:
            coverage_pct = (len(laps_computers) / computer_count) * 100

        gap = 100.0 - coverage_pct

        if gap > 50:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.75, "HIGH"
        elif gap > 20:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.4, "MEDIUM"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="laps_exposure",
            verdict=verdict, score_delta=score, confidence=0.7,
            severity_hint=sev,
            summary=f"LAPS coverage: {coverage_pct:.0f}% ({len(laps_computers)}/{computer_count} computers)",
            reasoning=[
                f"{gap:.0f}% of computers lack LAPS — shared/static local admin passwords likely",
                "Without LAPS: compromising one computer's local admin = lateral movement to all",
            ] if gap > 20 else [f"LAPS coverage is {coverage_pct:.0f}% — acceptable"],
            supporting_signals=[f"{100-coverage_pct:.0f}% LAPS gap"] if gap > 20 else [],
            mitre_techniques=["T1078.003"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Deploy LAPS to all workstations and servers",
                "Install-Module LAPS -Scope CurrentUser",
                "Update-AdmPwdADSchema",
                "Set-AdmPwdComputerSelfPermission -Identity <OU>",
            ],
            detection_opportunities=["Audit computers without ms-Mcs-AdmPwdExpirationTime attribute"],
        )


@register("laps_exposure")
class LAPSPasswordExpiryExpert(BaseExpert):
    """LAPS password expiry and rotation checks."""
    expert_id = "laps_expiry"
    expert_name = "LAPS Password Expiry Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # Check for LAPS passwords not rotated recently
        expiry_findings = [f for f in getattr(ctx, 'findings', [])
                           if (getattr(f, 'finding_type', '') or '') in ('LAPS_PASSWORD_READABLE', 'NO_LAPS', 'COMPUTERS_NO_LAPS')]
        # Heuristic: if LAPS deployed but no recent rotation findings, signal low risk
        has_expiry = bool(expiry_findings)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="laps_exposure",
            verdict=ExpertVerdict.WEAK_SUPPORT if has_expiry else ExpertVerdict.NEUTRAL,
            score_delta=0.3 if has_expiry else 0.0,
            confidence=0.6,
            severity_hint="MEDIUM" if has_expiry else None,
            summary=f"LAPS expiry: {len(expiry_findings)} stale password finding(s)",
            reasoning=["LAPS passwords not rotating = window for credential reuse after exposure"] if has_expiry else [],
            supporting_signals=[f"{len(expiry_findings)} expiry issue(s)"] if has_expiry else [],
            mitre_techniques=["T1552.001"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Force LAPS rotation: Reset-AdmPwdPassword -ComputerName <name>",
                "# Set max password age: Set-AdmPwdPasswordExpirationTime -ComputerName <name> -Time (Get-Date)",
            ],
            detection_opportunities=["Audit ms-Mcs-AdmPwdExpirationTime for overdue rotations"],
        )
