from __future__ import annotations
from adbygod_api.core.validation.contracts import PlaybookStep, ExpertDecision


class PlaybookGenerator:
    def generate(
        self,
        decisions: list[ExpertDecision],
        ctx,
        module_id: str,
    ) -> list[PlaybookStep]:
        steps: list[PlaybookStep] = []
        seen_commands: set[str] = set()
        step_idx = 0

        # Sort decisions by score (highest first = highest priority)
        def _is_exposed(d):
            v = d.verdict.value if hasattr(d.verdict, 'value') else str(d.verdict)
            return v in ("SUPPORTS_EXPOSURE", "WEAK_SUPPORT")

        scored_decisions = sorted(
            [d for d in decisions if _is_exposed(d)],
            key=lambda d: d.score_delta,
            reverse=True,
        )

        for decision in scored_decisions:
            cmds = getattr(decision, 'remediation_commands', [])
            if not cmds:
                continue

            # Substitute real entity names if available
            enriched_cmds = []
            for cmd in cmds:
                if '<' in cmd and '>' in cmd:
                    cmd = self._substitute_entities(cmd, decision, ctx)
                if cmd not in seen_commands:
                    seen_commands.add(cmd)
                    enriched_cmds.append(cmd)

            if not enriched_cmds:
                continue

            severity = getattr(decision, 'severity_hint', 'MEDIUM') or 'MEDIUM'

            steps.append(PlaybookStep(
                step_index=step_idx,
                title=f"Remediate: {decision.expert_name}",
                description=decision.summary,
                commands=enriched_cmds,
                applies_to=getattr(decision, 'related_entity_ids', [])[:5],
                verification_command=self._make_verification(decision, ctx),
                mitre_mitigates=getattr(decision, 'mitre_techniques', []),
                priority=severity if severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') else 'MEDIUM',
            ))
            step_idx += 1

        # Sort by priority: CRITICAL > HIGH > MEDIUM > LOW
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        steps.sort(key=lambda s: priority_order.get(s.priority, 4))

        # Re-index after sort
        for i, step in enumerate(steps):
            step.step_index = i

        return steps

    def _substitute_entities(self, cmd: str, decision: ExpertDecision, ctx) -> str:
        """Replace <account_name>, <entity_name> etc. with real values from context."""
        entity_ids = getattr(decision, 'related_entity_ids', [])
        entities = getattr(ctx, 'entities', [])

        if entity_ids and entities:
            # Find first entity matching the decision
            entity_name = None
            for e in entities:
                eid = str(e.get('id', '') if isinstance(e, dict) else getattr(e, 'id', ''))
                if eid in entity_ids:
                    entity_name = (
                        e.get('name', '') if isinstance(e, dict)
                        else str(getattr(e, 'name', getattr(e, 'sam_account_name', getattr(e, 'display_name', ''))))
                    )
                    break

            if entity_name:
                cmd = cmd.replace('<account_name>', entity_name)
                cmd = cmd.replace('<entity_name>', entity_name)
                cmd = cmd.replace('<name>', entity_name)

        # Substitute domain name
        domain = getattr(ctx, 'domain', getattr(ctx, 'domain_name', 'domain.local'))
        cmd = cmd.replace('<domain>', str(domain))

        return cmd

    def _make_verification(self, decision: ExpertDecision, ctx) -> str:
        """Generate a verification command to confirm remediation was applied."""
        expert = decision.expert_id

        verification_map = {
            'asrep_roast': "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth",
            'kerberoast': "Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName | Measure-Object",
            'laps_read': "Find-AdmPwdExtendedRights -Identity (Get-ADDomain).DistinguishedName",
            'laps_coverage': "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime | Where-Object {$_.'ms-Mcs-AdmPwdExpirationTime' -eq $null} | Measure-Object",
            'maq': "(Get-ADDomain).DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota' | Select -ExpandProperty 'ms-DS-MachineAccountQuota'",
            'esc1': "certutil -v -dstemplate | Select-String 'CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT'",
            'unconstrained': "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Where-Object {$_.Name -notlike '*DC*'}",
            'rbcd': "Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null}",
            'default_policy': "Get-ADDefaultDomainPasswordPolicy | Select MinPasswordLength, LockoutThreshold, MaxPasswordAge",
        }

        return verification_map.get(expert, f"# Verify {expert} remediation complete")
