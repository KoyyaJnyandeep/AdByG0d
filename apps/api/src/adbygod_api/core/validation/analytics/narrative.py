from __future__ import annotations
from adbygod_api.core.validation.contracts import ExpertDecision, KillChain


class RedTeamNarrativeGenerator:
    STAGE_ORDER = [
        "initial_access",
        "credential_access",
        "lateral_movement",
        "privilege_escalation",
        "persistence",
        "exfiltration",
    ]

    def generate(
        self,
        kill_chains: list[KillChain],
        decisions: list[ExpertDecision],
        fusion,
        ctx,
    ) -> str:
        domain = getattr(ctx, 'domain', getattr(ctx, 'domain_name', 'the target domain'))
        user_count = getattr(ctx, 'user_count', 0)
        computer_count = getattr(ctx, 'computer_count', 0)
        dc_count = getattr(ctx, 'dc_count', 0)
        verdict = fusion.final_verdict.value if hasattr(fusion.final_verdict, 'value') else str(fusion.final_verdict)
        score = getattr(fusion, 'risk_score', 0.0)
        confidence = getattr(fusion, 'confidence', 0)
        severity = getattr(fusion, 'severity_projection', 'UNKNOWN')

        parts: list[str] = []

        # Executive summary
        parts.append("=" * 70)
        parts.append("RED TEAM SIMULATION NARRATIVE")
        parts.append("=" * 70)
        parts.append("")
        parts.append("EXECUTIVE SUMMARY")
        parts.append("-" * 40)
        parts.append(
            f"During the simulated assessment of '{domain}', the validation engine "
            f"identified a {severity} exposure with a risk score of {score:.1f}/10.0 "
            f"and {confidence}% confidence. Final verdict: {verdict}."
        )
        parts.append(
            f"Environment: {user_count} users, {computer_count} computers, {dc_count} domain controller(s)."
        )
        parts.append("")

        # Group decisions by kill chain stage
        by_stage: dict[str, list[ExpertDecision]] = {}
        for d in decisions:
            verdict_val = d.verdict.value if hasattr(d.verdict, 'value') else str(d.verdict)
            if verdict_val not in ("SUPPORTS_EXPOSURE", "WEAK_SUPPORT"):
                continue
            stage = getattr(d, 'kill_chain_stage', 'unknown') or 'unknown'
            by_stage.setdefault(stage, []).append(d)

        stage_titles = {
            "initial_access": "PHASE 1: INITIAL ACCESS",
            "credential_access": "PHASE 2: CREDENTIAL ACCESS",
            "lateral_movement": "PHASE 3: LATERAL MOVEMENT",
            "privilege_escalation": "PHASE 4: PRIVILEGE ESCALATION",
            "persistence": "PHASE 5: PERSISTENCE",
            "exfiltration": "PHASE 6: IMPACT / EXFILTRATION",
        }

        for stage in self.STAGE_ORDER:
            stage_decisions = by_stage.get(stage, [])
            if not stage_decisions:
                continue

            parts.append(stage_titles.get(stage, stage.upper()))
            parts.append("-" * 40)

            for d in stage_decisions:
                parts.append(f"[{d.expert_name}]")
                parts.append(f"  Finding: {d.summary}")
                if d.reasoning:
                    parts.append(f"  Analysis: {d.reasoning[0]}")
                if getattr(d, 'mitre_techniques', []):
                    parts.append(f"  MITRE: {', '.join(d.mitre_techniques[:3])}")
                if getattr(d, 'detection_opportunities', []):
                    parts.append(f"  Detection: {d.detection_opportunities[0]}")
                parts.append("")

        # Kill chain narratives
        if kill_chains:
            parts.append("ATTACK CHAINS IDENTIFIED")
            parts.append("-" * 40)
            for i, chain in enumerate(kill_chains[:3], 1):
                parts.append(f"Chain {i}: {chain.name}")
                parts.append(f"  Composite Risk: {chain.composite_risk:.1f}/10.0")
                parts.append(f"  Threat Actors: {', '.join(chain.threat_actors)}")
                parts.append("  Steps:")
                for step in chain.steps:
                    parts.append(f"    {step.step_index + 1}. [{step.mitre_id}] {step.description}")
                parts.append("")

        # Blast radius
        blast = getattr(fusion, 'blast_radius', None)
        if blast and getattr(blast, 'total_reachable', 0) > 0:
            parts.append("BLAST RADIUS ASSESSMENT")
            parts.append("-" * 40)
            parts.append("If the highest-risk account is compromised:")
            parts.append(f"  Reachable computers:  {blast.reachable_computers}")
            parts.append(f"  Reachable DCs:        {blast.reachable_domain_controllers}")
            parts.append(f"  Reachable users:      {blast.reachable_users}")
            parts.append(f"  Total reachable:      {blast.total_reachable}")
            if blast.tier0_reachable:
                parts.append("  WARNING: TIER-0 ASSETS REACHABLE — Domain compromise achievable")
            parts.append("")

        # Recommendations
        parts.append("RECOMMENDED IMMEDIATE ACTIONS")
        parts.append("-" * 40)
        recommended = getattr(fusion, 'recommended_actions', [])
        playbook = getattr(fusion, 'remediation_playbook', [])

        if recommended:
            for i, action in enumerate(recommended[:5], 1):
                parts.append(f"  {i}. {action}")
        elif playbook:
            critical_steps = [s for s in playbook if s.priority == 'CRITICAL'][:3]
            high_steps = [s for s in playbook if s.priority == 'HIGH'][:3]
            for i, step in enumerate(critical_steps + high_steps, 1):
                parts.append(f"  {i}. [{step.priority}] {step.title}: {step.description}")
        else:
            parts.append("  See playbook section for remediation steps.")
        parts.append("")

        parts.append("=" * 70)
        parts.append("END OF SIMULATION NARRATIVE")
        parts.append("=" * 70)

        return "\n".join(parts)
