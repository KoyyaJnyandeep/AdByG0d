from __future__ import annotations

from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register


@register("delegation")
class UnconstrainedDelegationExpert(BaseExpert):
    expert_id = "unconstrained"
    expert_name = "Unconstrained Delegation Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        unconstrained = getattr(ctx, 'unconstrained_delegation', [])
        # Exclude DCs — unconstrained on DCs is expected
        dc_ids = set(
            str(e.id) for e in getattr(ctx, 'entities', [])
            if hasattr(e, 'entity_type') and (
                'domaincontroller' in (e.entity_type.value if hasattr(e.entity_type, 'value') else str(e.entity_type)).lower()
                or (e.attributes or {}).get('isDC') or (e.attributes or {}).get('isdc')
            )
        )
        non_dc_unconstrained = [eid for eid in unconstrained if eid not in dc_ids]

        if non_dc_unconstrained:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.85, "CRITICAL"
        elif unconstrained:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.3, "MEDIUM"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="delegation",
            verdict=verdict, score_delta=score, confidence=0.85 if unconstrained else 0.4,
            severity_hint=sev,
            summary=f"Unconstrained delegation: {len(non_dc_unconstrained)} non-DC accounts",
            reasoning=[
                "Non-DC accounts with unconstrained delegation capture TGTs of any connecting user",
                "Printer bug / PetitPotam can coerce DC machine account to connect → DC TGT captured",
                "DC TGT → DCSync → all domain hashes",
            ] if non_dc_unconstrained else ["No non-DC unconstrained delegation found"],
            supporting_signals=[f"{len(non_dc_unconstrained)} non-DC unconstrained account(s)"] if non_dc_unconstrained else [],
            blast_radius_hint=getattr(ctx, 'computer_count', 0),
            mitre_techniques=["T1558.001"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# Identify unconstrained accounts: Get-ADComputer -Filter {TrustedForDelegation -eq $true}",
                "# Migrate to constrained or resource-based delegation",
                "Set-ADAccountControl -Identity <account> -TrustedForDelegation $false",
            ],
            detection_opportunities=[
                "Alert on TGT requests to non-DC unconstrained hosts (event 4768)",
                "Monitor for printer spooler / EFS coercion to unconstrained hosts",
            ],
        )


@register("delegation")
class ConstrainedDelegationExpert(BaseExpert):
    expert_id = "constrained"
    expert_name = "Constrained Delegation Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        constrained = getattr(ctx, 'constrained_delegation', [])
        # Check for S4U2Self abuse: accounts with protocol transition (TrustedToAuthForDelegation)
        s4u_findings = [f for f in getattr(ctx, 'findings', [])
                        if (getattr(f, 'finding_type', '') or '') in ('CONSTRAINED_DELEGATION_KCD', 'CONSTRAINED_DELEGATION_ANY_PROTOCOL')]
        count = len(constrained) + len(s4u_findings)

        priv_targets = [d for d in constrained if any(
            kw in str(d.get('allowed_spns', [])) for kw in ['krbtgt', 'ldap/dc', 'cifs/dc'])]

        if priv_targets:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.75, "HIGH"
        elif count:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.35, "MEDIUM"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="delegation",
            verdict=verdict, score_delta=score, confidence=0.7 if count else 0.4,
            severity_hint=sev,
            summary=f"Constrained delegation: {count} account(s), {len(priv_targets)} targeting privileged SPNs",
            reasoning=[
                "S4U2Proxy with protocol transition: impersonate any user to target SPN without password",
                "Constrained to LDAP/CIFS on DC = near-equivalent to DCSync",
            ] if count else ["No constrained delegation found"],
            supporting_signals=[f"{len(priv_targets)} priv-SPN delegation(s)"] if priv_targets else [],
            mitre_techniques=["T1550.003"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Enumerate: Get-ADObject -Filter {msDS-AllowedToDelegateTo -like '*'}",
                "# Remove unnecessary SPNs from msDS-AllowedToDelegateTo",
                "# Disable protocol transition (TrustedToAuthForDelegation) where not required",
            ],
            detection_opportunities=["Alert on S4U2Self/S4U2Proxy TGS requests (event 4769 with unusual service names)"],
        )


@register("delegation")
class RBCDExpert(BaseExpert):
    expert_id = "rbcd"
    expert_name = "RBCD Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        rbcd_edges = getattr(ctx, 'rbcd_edges', [])
        rbcd_findings = [f for f in getattr(ctx, 'findings', [])
                         if (getattr(f, 'finding_type', '') or '') == 'RBCD_CONFIGURED']
        count = len(rbcd_edges) + len(rbcd_findings)

        if count >= 3:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.85, "CRITICAL"
        elif count >= 1:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.65, "HIGH"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="delegation",
            verdict=verdict, score_delta=score, confidence=0.8 if count else 0.4,
            severity_hint=sev,
            summary=f"RBCD: {count} msDS-AllowedToActOnBehalfOfOtherIdentity edge(s)",
            reasoning=[
                "RBCD write: attacker adds their computer account to target's AllowedToAct",
                "Then S4U2Proxy: impersonate domain admin to target computer",
                "Result: full local admin on target computer as any user",
            ] if count else ["No RBCD edges found"],
            supporting_signals=[f"{count} RBCD edge(s)"] if count else [],
            blast_radius_hint=count * 50,
            mitre_techniques=["T1550.003"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Audit RBCD: Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity",
                "# Clear unauthorized entries: Set-ADComputer -Identity <name> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
            detection_opportunities=[
                "Monitor msDS-AllowedToActOnBehalfOfOtherIdentity modifications (event 5136)",
                "Alert on S4U2Proxy from newly added computer accounts",
            ],
        )


@register("delegation")
class DelegationChainExpert(BaseExpert):
    expert_id = "delegation_chain"
    expert_name = "Delegation Kill Chain Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        unconstrained = getattr(ctx, 'unconstrained_delegation', [])
        dc_count = getattr(ctx, 'dc_count', 0)
        dcsync = [f for f in getattr(ctx, 'findings', [])
                  if (getattr(f, 'finding_type', '') or '') == 'DCSYNC_RIGHTS']

        full_chain = bool(unconstrained and dc_count >= 1)
        extended_chain = full_chain and bool(dcsync)

        if extended_chain:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.95, "CRITICAL"
        elif full_chain:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.8, "CRITICAL"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="delegation",
            verdict=verdict, score_delta=score, confidence=0.9 if full_chain else 0.4,
            severity_hint=sev,
            summary=f"Delegation chain: {'CRITICAL — coerce DC → unconstrained host → DCSync' if full_chain else 'no full chain'}",
            reasoning=[
                "Full chain: coerce DC via printer bug → captured TGT → impersonate DC → DCSync",
                "No foothold needed beyond network access to coerce DC",
                "This is a domain-compromise-level finding",
            ] if full_chain else ["Incomplete delegation chain"],
            supporting_signals=[
                f"{len(unconstrained)} unconstrained account(s)",
                f"{dc_count} DC(s) present",
                f"{len(dcsync)} DCSync finding(s)" if dcsync else None,
            ],
            blast_radius_hint=getattr(ctx, 'computer_count', 0) + getattr(ctx, 'user_count', 0),
            mitre_techniques=["T1558.001", "T1003.006"],
            kill_chain_stage="credential_access",
            remediation_commands=[
                "# PRIORITY 1: Disable printer spooler on DCs: Stop-Service -Name Spooler; Set-Service -Name Spooler -StartupType Disabled",
                "# PRIORITY 2: Remove unconstrained delegation from non-DCs",
                "# Enable Protected Users group for privileged accounts",
            ],
            detection_opportunities=[
                "Alert on TGT tickets arriving at non-DC servers (coercion indicator)",
                "Monitor for MS-RPRN/MS-EFSR calls to DCs from non-DC hosts",
            ],
        )


@register("delegation")
class KerberosOnlyDCExpert(BaseExpert):
    expert_id = "kerberos_only_dc"
    expert_name = "Kerberos-Only DC Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # DCs without kerberos-only authentication = NTLM relay + delegation compound
        dc_count = getattr(ctx, 'dc_count', 0)
        ntlm_findings = [f for f in getattr(ctx, 'findings', [])
                         if 'ntlm' in str(getattr(f, 'module', '') or '').lower()
                         or 'ntlm' in str(getattr(f, 'finding_type', '') or '').lower()]

        has_risk = bool(dc_count > 0 and ntlm_findings)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="delegation",
            verdict=ExpertVerdict.WEAK_SUPPORT if has_risk else ExpertVerdict.NEUTRAL,
            score_delta=0.4 if has_risk else 0.0,
            confidence=0.55 if dc_count > 0 else 0.3,
            severity_hint="HIGH" if has_risk else None,
            summary=f"Kerberos-only DCs: {dc_count} DCs, NTLM exposure: {'yes' if ntlm_findings else 'no'}",
            reasoning=["DCs accepting NTLM + delegation = relay-to-delegation chain viable"] if has_risk else [],
            supporting_signals=[f"{dc_count} DCs", f"{len(ntlm_findings)} NTLM findings"] if has_risk else [],
            mitre_techniques=["T1557.001", "T1558.001"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Enable Kerberos-only authentication on DCs via GPO",
                "# Network security: Restrict NTLM: Incoming NTLM traffic = Deny all accounts",
            ],
            detection_opportunities=["Monitor NTLM authentication events on DCs (event 4624, type 3 NTLM)"],
        )
