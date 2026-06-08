from __future__ import annotations
from adbygod_api.core.validation.contracts import KillChain, PlaybookStep


class RemediationImpactCalculator:
    def calculate(
        self,
        kill_chains: list[KillChain],
        playbook: list[PlaybookStep],
    ) -> dict[str, float]:
        """Returns {step_title: path_reduction_pct}."""
        if not kill_chains or not playbook:
            return {}

        impact: dict[str, float] = {}
        total_chains = len(kill_chains)

        for step in playbook:
            mitigates = set(getattr(step, 'mitre_mitigates', []))
            if not mitigates:
                impact[step.title] = 0.0
                continue

            # Count how many kill chain steps are broken by this playbook step
            broken_chains = 0
            for chain in kill_chains:
                chain_techs = {s.mitre_id for s in chain.steps}
                if chain_techs & mitigates:
                    broken_chains += 1

            pct = (broken_chains / total_chains) * 100 if total_chains > 0 else 0.0
            impact[step.title] = round(pct, 1)

        return impact
