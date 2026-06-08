from __future__ import annotations

from adbygod_api.core.validation.contracts import KillChain, KillChainStep, ExpertDecision


KNOWN_CHAINS = [
    {
        "id": "asrep_acl_dcsync",
        "name": "AS-REP Roast → ACL Abuse → DCSync → Golden Ticket",
        "steps": [
            ("kerberos", "asrep_roast", "T1558.004", "AS-REP roast: obtain crackable hash without auth"),
            ("acl", "acl_edge", "T1222.001", "ACL abuse: WriteDACL/GenericAll on privileged object"),
            ("dcsync", "dcsync", "T1003.006", "DCSync: GetNCChanges → all domain hashes"),
            ("kerberos", "golden_ticket_risk", "T1558.001", "Golden Ticket: unlimited persistence with krbtgt hash"),
        ],
        "threat_actors": ["apt29", "apt28"],
    },
    {
        "id": "rbcd_maq_s4u",
        "name": "MAQ/RBCD → S4U2Proxy → DA Impersonation",
        "steps": [
            ("maq_rbcd", "maq", "T1550.003", "MAQ>0: create machine account as domain user"),
            ("maq_rbcd", "rbcd_via_maq", "T1550.003", "Write RBCD to target computer"),
            ("delegation", "constrained", "T1550.003", "S4U2Proxy: impersonate domain admin to target"),
        ],
        "threat_actors": ["apt29", "fin7"],
    },
    {
        "id": "shadow_cred_pkinit",
        "name": "Shadow Credentials → PKINIT → TGT → DA",
        "steps": [
            ("shadow_credentials", "key_credential_link", "T1098.004", "Add shadow credential to target account"),
            ("shadow_credentials", "whisker_reachability", "T1558", "PKINIT auth using shadow certificate"),
            ("kerberos", "golden_ticket_risk", "T1558.001", "Obtain TGT for impersonated account → DA"),
        ],
        "threat_actors": ["apt29"],
    },
    {
        "id": "adcs_esc1_cert",
        "name": "ADCS ESC1 → Certificate → Pass-the-Cert → DA",
        "steps": [
            ("adcs", "esc1", "T1649", "ESC1: request certificate with arbitrary SAN"),
            ("adcs", "cert_mapping", "T1649", "Pass-the-Cert: use certificate for PKINIT"),
            ("kerberos", "golden_ticket_risk", "T1558.001", "Obtain DA TGT via PKINIT"),
        ],
        "threat_actors": ["apt29", "fin7"],
    },
    {
        "id": "unconstrained_dcsync",
        "name": "Unconstrained Delegation → TGT Capture → DCSync",
        "steps": [
            ("delegation", "unconstrained", "T1558.001", "Coerce DC to connect to unconstrained host"),
            ("delegation", "delegation_chain", "T1558.001", "Capture DC TGT via delegation"),
            ("dcsync", "dcsync", "T1003.006", "DCSync with captured DC TGT"),
        ],
        "threat_actors": ["apt29", "apt28"],
    },
    {
        "id": "gpo_write_exec",
        "name": "GPO Write → Scheduled Task → Mass Lateral Movement",
        "steps": [
            ("gpo_abuse", "gpo_write", "T1484.001", "Write malicious GPO affecting linked OUs"),
            ("gpo_abuse", "scheduled_task", "T1053.005", "Inject scheduled task executing as SYSTEM"),
        ],
        "threat_actors": ["apt28", "lockbit"],
    },
    {
        "id": "laps_pth",
        "name": "LAPS Read → Local Admin → Pass-the-Hash → DA",
        "steps": [
            ("laps_exposure", "laps_read", "T1552.001", "Read LAPS password from AD"),
            ("ntlm_relay", "ntlm_relay", "T1557.001", "Pass-the-Hash with LAPS local admin cred"),
        ],
        "threat_actors": ["lockbit", "fin7"],
    },
    {
        "id": "kerberoast_service_da",
        "name": "Kerberoast → Crack → Service Account → DA Path",
        "steps": [
            ("kerberos", "kerberoast", "T1558.003", "Kerberoast: obtain crackable TGS for SPN account"),
            ("acl", "acl_edge", "T1222.001", "Crack + abuse ACL edges from service account"),
        ],
        "threat_actors": ["apt29", "apt28", "lazarus"],
    },
]


class KillChainComposer:
    def compose(
        self,
        decisions: list[ExpertDecision],
        module_id: str,
    ) -> list[KillChain]:
        supported_experts: set[tuple[str, str]] = set()
        for d in decisions:
            verdict_val = d.verdict.value if hasattr(d.verdict, 'value') else str(d.verdict)
            if verdict_val in ("SUPPORTS_EXPOSURE", "WEAK_SUPPORT"):
                supported_experts.add((d.module_id, d.expert_id))

        chains: list[KillChain] = []
        for chain_def in KNOWN_CHAINS:
            # Check if any steps in this chain are supported by current decisions
            steps = chain_def["steps"]
            matched_steps = []
            for i, (step_module, step_expert, _mitre_id, _description) in enumerate(steps):
                # Match if this module/expert combo is supported OR if module_id matches
                if (step_module, step_expert) in supported_experts or step_module == module_id:
                    matched_steps.append(i)

            if not matched_steps:
                continue

            match_ratio = len(matched_steps) / len(steps)
            if match_ratio < 0.4:  # Need at least 40% of steps matched
                continue

            # Compute composite risk
            relevant_decisions = [
                d for d in decisions
                if d.module_id in {s[0] for s in steps}
            ]
            base_score = sum(d.score_delta for d in relevant_decisions) / max(len(relevant_decisions), 1)
            composite_risk = min(10.0, base_score * 10 * match_ratio)

            # Build chain steps
            chain_steps = [
                KillChainStep(
                    step_index=i,
                    module_id=step_module,
                    finding_id=None,
                    technique=description.split(":")[0].strip(),
                    mitre_id=mitre_id,
                    description=description,
                    entity_ids=[],
                )
                for i, (step_module, step_expert, mitre_id, description) in enumerate(steps)
            ]

            # Generate narrative
            narrative_parts = [
                f"An attacker with initial domain user foothold could execute the "
                f"'{chain_def['name']}' attack chain:"
            ]
            for step in chain_steps:
                narrative_parts.append(f"  Step {step.step_index + 1}: {step.description}")
            narrative_parts.append(
                f"This chain has a composite risk score of {composite_risk:.1f}/10.0 "
                f"based on {len(matched_steps)}/{len(steps)} confirmed steps."
            )

            chains.append(KillChain(
                chain_id=chain_def["id"],
                name=chain_def["name"],
                composite_risk=composite_risk,
                steps=chain_steps,
                narrative="\n".join(narrative_parts),
                threat_actors=chain_def["threat_actors"],
            ))

        return sorted(chains, key=lambda c: c.composite_risk, reverse=True)
