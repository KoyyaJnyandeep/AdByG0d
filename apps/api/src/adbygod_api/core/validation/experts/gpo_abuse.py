from __future__ import annotations

from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@register("gpo_abuse")
class GPOWriteExpert(BaseExpert):
    """GPO write access to inject policies across domain."""
    expert_id = "gpo_write"
    expert_name = "GPO Write Access Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        gpo_write_edges = [
            e for e in getattr(ctx, 'edges', [])
            if (_get(e, 'relationship_type', '') or _get(getattr(e, 'edge_type', None), 'value', getattr(e, 'edge_type', ''))) in ('WriteDACL', 'WriteProperty', 'GenericAll', 'GenericWrite')
            and ('gpo' in str(_get(e, 'target_label', '')).lower() or 'policy' in str(_get(e, 'target_label', '')).lower())
        ]
        gpo_findings = [f for f in getattr(ctx, 'findings', [])
                        if (getattr(f, 'finding_type', '') or '') in ('DANGEROUS_GPO_DELEGATION', 'SYSVOL_GPP_CPASSWORD', 'WRITE_GP_LINK_ABUSE_PATH')]

        count = len(gpo_write_edges) + len(getattr(ctx, 'gpo_objects', []))
        combined = gpo_write_edges or gpo_findings

        if count >= 5:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.9, "CRITICAL"
        elif count >= 2:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.75, "HIGH"
        elif combined:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.4, "HIGH"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="gpo_abuse",
            verdict=verdict, score_delta=score, confidence=0.8 if combined else 0.4,
            severity_hint=sev,
            summary=f"GPO write: {count} writable GPO(s) detected",
            reasoning=[
                "Non-admin GPO write access enables policy injection across all linked computers",
                "Attackers add startup scripts, scheduled tasks, or registry modifications",
                "All computers in linked OUs execute attacker-controlled code on next GP refresh",
            ] if combined else ["No GPO write access found"],
            supporting_signals=[f"{len(gpo_write_edges)} GPO write edge(s)"] if gpo_write_edges else [],
            mitre_techniques=["T1484.001"],
            kill_chain_stage="persistence",
            remediation_commands=[
                "# Audit GPO permissions: Get-GPPermission -All -ReportType XML",
                "# Remove non-admin modify permissions from all GPOs",
                "(Get-GPO -All).ForEach{Get-GPPermission -Id $_.Id -All}",
            ],
            detection_opportunities=[
                "Monitor for GPO modifications by non-admin accounts (event 5136)",
                "Alert on new startup scripts or scheduled tasks in GPO (event 4657)",
                "GP processing anomaly detection: new policies appearing on endpoints",
            ],
        )


@register("gpo_abuse")
class GPOScopeExpert(BaseExpert):
    """GPO scope and blast radius estimation."""
    expert_id = "gpo_scope"
    expert_name = "GPO Scope & Blast Radius Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        gpo_objects = getattr(ctx, 'gpo_objects', [])
        computer_count = getattr(ctx, 'computer_count', 0)

        # Estimate: writable GPO linked to OU with many computers
        blast_radius = min(computer_count, len(gpo_objects) * 50)  # rough estimate

        has_scope_risk = bool(gpo_objects and computer_count > 5)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="gpo_abuse",
            verdict=ExpertVerdict.WEAK_SUPPORT if has_scope_risk else ExpertVerdict.NEUTRAL,
            score_delta=0.5 if has_scope_risk else 0.0,
            confidence=0.6 if gpo_objects else 0.3,
            severity_hint="HIGH" if blast_radius > 50 else ("MEDIUM" if blast_radius > 10 else None),
            summary=f"GPO scope: {len(gpo_objects)} GPO(s), ~{blast_radius} computers in blast radius",
            reasoning=[f"GPO scope covers approximately {blast_radius} computers"],
            supporting_signals=[f"~{blast_radius} computer blast radius"] if has_scope_risk else [],
            mitre_techniques=["T1484.001"],
            kill_chain_stage="persistence",
            blast_radius_hint=blast_radius,
            remediation_commands=[
                "# Minimize GPO link scope — link to smallest possible OU",
                "# Use security filtering to restrict GPO application",
            ],
            detection_opportunities=["Monitor GPO link creation/modification events"],
        )


@register("gpo_abuse")
class ImmediateScheduledTaskExpert(BaseExpert):
    """GPO scheduled task injection for immediate execution."""
    expert_id = "scheduled_task"
    expert_name = "GPO Scheduled Task Injection Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        task_findings = [f for f in getattr(ctx, 'findings', [])
                         if any(kw in (getattr(f, 'title', '') or '').lower() for kw in ['scheduled task', 'startup script', 'logon script'])]

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="gpo_abuse",
            verdict=ExpertVerdict.SUPPORTS_EXPOSURE if task_findings else ExpertVerdict.NEUTRAL,
            score_delta=0.7 if task_findings else 0.0,
            confidence=0.75 if task_findings else 0.3,
            severity_hint="CRITICAL" if task_findings else None,
            summary=f"GPO task injection: {len(task_findings)} finding(s) of scheduled task abuse",
            reasoning=["Scheduled tasks via GPO execute as SYSTEM on all linked computers"] if task_findings else [],
            supporting_signals=[f"{len(task_findings)} task injection finding(s)"] if task_findings else [],
            mitre_techniques=["T1053.005", "T1484.001"],
            kill_chain_stage="execution",
            remediation_commands=[
                "# Audit GPO scheduled tasks: Get-GPOReport -All -ReportType XML | Select-String 'ScheduledTasks'",
                "# Remove unauthorized scheduled tasks from all GPOs",
            ],
            detection_opportunities=[
                "Monitor for scheduled task creation via GPO (event 4698, 4702)",
                "Sysmon event 1: scheduled task process spawned by GP client",
            ],
        )


@register("gpo_abuse")
class GPODelegationExpert(BaseExpert):
    """GPO delegation and GpLink access delegation."""
    expert_id = "gpo_delegation"
    expert_name = "GPO Delegation Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # GpoApply edges + CreateLink edges on OU objects
        gpo_link_edges = [
            e for e in getattr(ctx, 'edges', [])
            if (_get(e, 'relationship_type', '') or _get(getattr(e, 'edge_type', None), 'value', getattr(e, 'edge_type', ''))) in ('GpLink', 'GpoApply', 'CreateGpoLink')
        ]
        has_delegation = bool(gpo_link_edges)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="gpo_abuse",
            verdict=ExpertVerdict.WEAK_SUPPORT if has_delegation else ExpertVerdict.NEUTRAL,
            score_delta=0.35 if has_delegation else 0.0,
            confidence=0.55 if gpo_link_edges else 0.3,
            severity_hint="MEDIUM" if has_delegation else None,
            summary=f"GPO delegation: {len(gpo_link_edges)} GPO link/apply edge(s)",
            reasoning=["GPO link delegation allows non-admins to scope GPO to target OUs"],
            supporting_signals=[f"{len(gpo_link_edges)} delegation edge(s)"] if gpo_link_edges else [],
            mitre_techniques=["T1484.001"],
            kill_chain_stage="persistence",
            remediation_commands=["# Audit GpLink delegations: Get-ADOrganizationalUnit -Filter * | Get-GPInheritance"],
            detection_opportunities=["Monitor for GPO link creation events (event 5136 on OU objects)"],
        )
