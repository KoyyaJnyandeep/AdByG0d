from __future__ import annotations

from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict
from adbygod_api.core.validation.experts.base import BaseExpert
from adbygod_api.core.validation.registry import register


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _edge_type(edge) -> str:
    etype = _get(edge, 'edge_type', _get(edge, 'relationship_type', ''))
    return str(_get(etype, 'value', etype))


@register("maq_rbcd")
class MAQExpert(BaseExpert):
    expert_id = "maq"
    expert_name = "Machine Account Quota Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        maq = getattr(ctx, 'maq_value', 10)

        if maq >= 10:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.7, "HIGH"
        elif maq >= 5:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.4, "MEDIUM"
        elif maq > 0:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.2, "LOW"
        else:
            verdict, score, sev = ExpertVerdict.CONTRADICTS_EXPOSURE, -0.2, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="maq_rbcd",
            verdict=verdict, score_delta=score, confidence=0.9,
            severity_hint=sev,
            summary=f"MAQ: ms-DS-MachineAccountQuota = {maq}",
            reasoning=[
                f"MAQ={maq}: any domain user can add {maq} computer accounts",
                "Computer accounts are valid Kerberos principals for S4U2Self/RBCD attacks",
                "Required enabler for RBCD-via-MAQ domain compromise chain",
            ] if maq > 0 else ["MAQ=0: domain users cannot add computer accounts (good)"],
            supporting_signals=[f"MAQ={maq}"] if maq > 0 else [],
            contradicting_signals=["MAQ=0 — RBCD via MAQ not viable"] if maq == 0 else [],
            mitre_techniques=["T1550.003"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Set MAQ to 0:",
                "Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'='0'}",
                "# Verify: (Get-ADDomain).DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'",
            ],
            detection_opportunities=[
                "Monitor for new computer account creation by non-admin users (event 4741)",
                "Alert on rapid machine account creation (>3 in 1 hour from same user)",
            ],
        )


@register("maq_rbcd")
class RBCDViaMaqExpert(BaseExpert):
    expert_id = "rbcd_via_maq"
    expert_name = "RBCD via MAQ Chain Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        maq = getattr(ctx, 'maq_value', 10)
        rbcd_edges = getattr(ctx, 'rbcd_edges', [])
        # Check for GenericWrite on computer objects
        _write_types = {'GENERIC_ALL', 'HAS_CONTROL', 'WRITE_DACL', 'WRITE_OWNER'}
        write_computer_edges = []
        for e in getattr(ctx, 'edges', []):
            etype = _edge_type(e)
            if etype not in _write_types:
                continue
            tgt_entity = ctx.entity_index.get(str(_get(e, 'target_id', '')))
            raw_tgt_type = _get(tgt_entity, 'entity_type', '') if tgt_entity else ''
            tgt_type = str(_get(raw_tgt_type, 'value', raw_tgt_type)).lower()
            if 'computer' in tgt_type:
                write_computer_edges.append(e)

        chain_viable = maq > 0 and bool(write_computer_edges or rbcd_edges)

        if chain_viable and maq >= 5:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.9, "CRITICAL"
        elif chain_viable:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.7, "HIGH"
        elif maq > 0:
            verdict, score, sev = ExpertVerdict.WEAK_SUPPORT, 0.35, "MEDIUM"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        write_count = len(write_computer_edges) + len(rbcd_edges)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="maq_rbcd",
            verdict=verdict, score_delta=score, confidence=0.85 if chain_viable else 0.5,
            severity_hint=sev,
            summary=f"RBCD/MAQ chain: MAQ={maq}, {write_count} computer write edge(s) — chain {'VIABLE' if chain_viable else 'not viable'}",
            reasoning=[
                "Full RBCD chain: MAQ>0 + GenericWrite on computer → add shadow principal → S4U2Proxy as DA",
                f"{write_count} computer write edge(s) enable RBCD setup",
                "Only requires: domain user foothold + network access",
            ] if chain_viable else [f"MAQ={maq}: {'add write edges needed' if maq > 0 else 'set MAQ>0 needed'}"],
            supporting_signals=[f"MAQ={maq}", f"{write_count} computer write edge(s)"] if chain_viable else [],
            blast_radius_hint=write_count * 100,
            mitre_techniques=["T1550.003"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Fix BOTH: set MAQ=0 AND remove GenericWrite on computers",
                "# RBCD write cleanup: Set-ADComputer -Identity <name> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity",
            ],
            detection_opportunities=[
                "Correlate: new computer account creation followed by msDS-AllowedToActOnBehalfOfOtherIdentity modification",
                "Alert on S4U2Proxy from newly created computer accounts",
            ],
        )


@register("maq_rbcd")
class CreateChildComputerExpert(BaseExpert):
    expert_id = "create_child_computer"
    expert_name = "Create Computer in OU Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        # CreateChild(computer) edges on OUs
        create_edges = []
        for e in getattr(ctx, 'edges', []):
            etype = _edge_type(e)
            if etype != 'ADD_MEMBER':
                continue
            tgt_entity = ctx.entity_index.get(str(_get(e, 'target_id', '')))
            raw_tgt_type = _get(tgt_entity, 'entity_type', '') if tgt_entity else ''
            tgt_type = str(_get(raw_tgt_type, 'value', raw_tgt_type)).lower()
            if 'ou' in tgt_type or 'container' in tgt_type:
                create_edges.append(e)

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="maq_rbcd",
            verdict=ExpertVerdict.WEAK_SUPPORT if create_edges else ExpertVerdict.NEUTRAL,
            score_delta=0.4 if create_edges else 0.0,
            confidence=0.65 if create_edges else 0.3,
            severity_hint="HIGH" if create_edges else None,
            summary=f"CreateChild on OU: {len(create_edges)} edge(s) — alternative computer creation path",
            reasoning=["CreateChild on OU bypasses MAQ=0 restriction — attacker can still add computers to specific OUs"] if create_edges else [],
            supporting_signals=[f"{len(create_edges)} CreateChild edge(s) on OUs"] if create_edges else [],
            mitre_techniques=["T1550.003"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# Remove CreateChild permissions from non-admin accounts on OUs",
                "# Audit: dsacls 'OU=Computers,DC=domain,DC=com' | findstr /i 'create child'",
            ],
            detection_opportunities=["Alert on new computer account creation in targeted OUs (event 4741)"],
        )


@register("maq_rbcd")
class ComputerTakeoverChainExpert(BaseExpert):
    expert_id = "computer_takeover_chain"
    expert_name = "Full Computer Takeover Chain Expert"

    async def analyze(self, ctx) -> ExpertDecision:
        maq = getattr(ctx, 'maq_value', 10)
        rbcd_edges = getattr(ctx, 'rbcd_edges', [])
        getattr(ctx, 'constrained_delegation', [])
        dc_count = getattr(ctx, 'dc_count', 0)

        # Full chain: any of (MAQ + write) or (RBCD) → S4U2Proxy → DA
        has_maq_path = maq > 0
        has_rbcd_path = bool(rbcd_edges)
        full_chain = (has_maq_path or has_rbcd_path) and dc_count > 0

        if full_chain and (has_maq_path and has_rbcd_path):
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.95, "CRITICAL"
        elif full_chain:
            verdict, score, sev = ExpertVerdict.SUPPORTS_EXPOSURE, 0.8, "CRITICAL"
        else:
            verdict, score, sev = ExpertVerdict.NEUTRAL, 0.0, None

        return ExpertDecision(
            expert_id=self.expert_id, expert_name=self.expert_name, module_id="maq_rbcd",
            verdict=verdict, score_delta=score, confidence=0.85 if full_chain else 0.4,
            severity_hint=sev,
            summary=f"Computer takeover chain: {'CRITICAL — MAQ+RBCD→S4U2Proxy→DA VIABLE' if full_chain else 'chain not viable'}",
            reasoning=[
                "Complete attack chain: create machine account (MAQ) → write RBCD → S4U2Proxy as DA → pwned",
                "Any domain user can execute this attack with no special privileges",
                "Attack requires only foothold as domain user and network access to DC",
            ] if full_chain else ["Incomplete chain — MAQ=0 or no RBCD surface"],
            supporting_signals=[
                f"MAQ={maq}" if has_maq_path else None,
                f"{len(rbcd_edges)} RBCD edge(s)" if has_rbcd_path else None,
                f"{dc_count} DC(s) present",
            ],
            blast_radius_hint=getattr(ctx, 'computer_count', 0) + getattr(ctx, 'user_count', 0),
            mitre_techniques=["T1550.003", "T1558"],
            kill_chain_stage="lateral_movement",
            remediation_commands=[
                "# PRIORITY: Set MAQ=0",
                "Set-ADDomain -Identity (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'='0'}",
                "# Remove all RBCD write permissions",
                "# Audit: Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object {$_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne $null}",
            ],
            detection_opportunities=[
                "Correlate: new machine account + RBCD modification + S4U2Proxy within 1 hour",
                "Alert on S4U2Self/S4U2Proxy requests from newly created computer accounts",
                "SIEM rule: machine_account_created → rbcd_modified → s4u2proxy_issued (within 60min)",
            ],
        )
