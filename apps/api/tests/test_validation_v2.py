"""Integration coverage for Validation Engine V2.

These tests exercise the public contracts that the API and web validation UI
depend on: module catalog shape, expert registration, synthetic contexts,
analytics helpers, and the V2 streaming/run entry points.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

CORE_MODULE_IDS = {
    "kerberos",
    "acl",
    "dcsync",
    "ntlm_relay",
    "trust",
    "adcs",
    "shadow_credentials",
    "gpo_abuse",
    "laps_exposure",
    "delegation",
    "password_policy",
    "sid_history",
    "maq_rbcd",
}

EXPANDED_MODULE_IDS = CORE_MODULE_IDS | {
    "network_posture",
    "user_accounts",
    "service_accounts",
    "domain_config",
    "pre2k_exposure",
    "recon_exposure",
    "timeroast_exposure",
    "wsus_exposure",
}


@pytest.fixture(scope="module")
def registered_modules():
    import adbygod_api.core.validation.experts  # noqa: F401
    from adbygod_api.core.validation.registry import all_module_ids

    return set(all_module_ids())


@pytest.fixture(scope="module")
def pentest_context():
    from adbygod_api.core.validation.synthetic.generator import SyntheticADGenerator
    from adbygod_api.core.validation.synthetic.presets import PRESETS

    return SyntheticADGenerator().generate(PRESETS["pentest_target"])


def _decision(
    module_id: str,
    expert_id: str,
    *,
    score_delta: float = 0.8,
    mitre: list[str] | None = None,
    command: str | None = None,
):
    from adbygod_api.core.validation.contracts import ExpertDecision, ExpertVerdict

    return ExpertDecision(
        expert_id=expert_id,
        expert_name=expert_id.replace("_", " ").title(),
        module_id=module_id,
        verdict=ExpertVerdict.SUPPORTS_EXPOSURE,
        score_delta=score_delta,
        confidence=0.85,
        severity_hint="HIGH",
        summary=f"{module_id} exposure signal",
        reasoning=["synthetic test decision"],
        supporting_signals=["synthetic support"],
        mitre_techniques=mitre or [],
        kill_chain_stage="credential_access",
        blast_radius_hint=10,
        remediation_commands=[command] if command else [],
    )


class TestCatalogAndRegistry:
    def test_catalog_has_current_modules(self):
        from adbygod_api.core.validation.catalog import VALIDATION_MODULE_INDEX

        assert set(VALIDATION_MODULE_INDEX) == EXPANDED_MODULE_IDS

    def test_catalog_entries_are_ui_ready(self):
        from adbygod_api.core.validation.catalog import list_validation_modules

        modules = list_validation_modules()
        assert len(modules) == len(EXPANDED_MODULE_IDS)
        for module in modules:
            assert module["id"] in EXPANDED_MODULE_IDS
            assert module["name"]
            assert module["description"]
            assert module["version"]
            assert module["expert_count"] >= 1
            assert module["mitre_techniques"]
            assert len(module["severity_range"]) == 2
            assert module["risk_category"]

    def test_all_expected_modules_registered(self, registered_modules):
        assert EXPANDED_MODULE_IDS <= registered_modules

    def test_registry_has_expected_expert_volume(self, registered_modules):
        from adbygod_api.core.validation.registry import get_experts_for, registered_count

        assert registered_count() >= 43
        for module_id in CORE_MODULE_IDS:
            experts = get_experts_for(module_id)
            assert experts, f"{module_id} has no registered experts"
            assert all(hasattr(cls(), "analyze") for cls in experts)


class TestSyntheticGenerator:
    def test_presets_and_apt_scenarios_exist(self):
        from adbygod_api.core.validation.synthetic.apt_scenarios import APT_SCENARIOS
        from adbygod_api.core.validation.synthetic.presets import PRESETS

        assert "pentest_target" in PRESETS
        assert "red_team_worst_case" in PRESETS
        assert "apt29_compromise" in APT_SCENARIOS
        assert len(APT_SCENARIOS) >= 4

    def test_generated_context_has_rich_validation_fields(self, pentest_context):
        ctx = pentest_context

        assert ctx.assessment_id.startswith("synth-")
        assert ctx.collection_mode == "SYNTHETIC"
        assert len(ctx.entities) > 0
        assert len(ctx.edges) > 0
        assert len(ctx.findings) > 0
        assert ctx.computer_count > 0
        assert ctx.dc_count > 0
        assert ctx.certificate_templates
        assert ctx.gpo_objects
        assert ctx.laps_computers
        assert ctx.unconstrained_delegation
        assert ctx.password_policy_objects

    def test_generation_scales_with_config(self):
        from adbygod_api.core.validation.synthetic.generator import SyntheticADConfig, SyntheticADGenerator

        gen = SyntheticADGenerator()
        small = gen.generate(SyntheticADConfig(user_count=25, computer_count=10))
        large = gen.generate(SyntheticADConfig(user_count=250, computer_count=100))

        assert len(large.entities) > len(small.entities)
        assert large.computer_count > small.computer_count


class TestAnalytics:
    def test_kill_chain_composer_returns_known_chain(self):
        from adbygod_api.core.validation.analytics.kill_chain import KillChainComposer

        decisions = [
            _decision("kerberos", "kerberoast", mitre=["T1558.003"]),
            _decision("acl", "acl_edge", mitre=["T1222.001"]),
        ]

        chains = KillChainComposer().compose(decisions, "kerberos")

        assert chains
        assert all(chain.chain_id and chain.name for chain in chains)
        assert all(chain.steps for chain in chains)

    def test_cross_module_correlator_uses_scores_and_decisions(self):
        from adbygod_api.core.validation.analytics.cross_module import CrossModuleCorrelator

        decisions = {
            "kerberos": [_decision("kerberos", "kerberoast")],
            "acl": [_decision("acl", "acl_edge")],
        }
        scores = {"kerberos": 4.0, "acl": 3.0}

        chains = CrossModuleCorrelator().correlate(scores, decisions)

        assert chains
        assert chains[0].compound_risk >= 0

    def test_threat_actor_matcher_matches_mitre_overlap(self):
        from adbygod_api.core.validation.analytics.threat_actor import ThreatActorMatcher

        matches = ThreatActorMatcher().match([
            _decision("kerberos", "kerberoast", mitre=["T1558.003", "T1003.006", "T1649"])
        ])

        assert matches
        assert matches[0].match_score > 0

    def test_playbook_generator_builds_steps(self, pentest_context):
        from adbygod_api.core.validation.analytics.playbook import PlaybookGenerator

        steps = PlaybookGenerator().generate(
            [
                _decision(
                    "kerberos",
                    "asrep_roast",
                    mitre=["T1558.004"],
                    command="Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}",
                )
            ],
            pentest_context,
            "kerberos",
        )

        assert len(steps) == 1
        assert steps[0].title
        assert steps[0].commands
        assert steps[0].priority == "HIGH"

    def test_narrative_generator_returns_report(self, pentest_context):
        from adbygod_api.core.validation.analytics.kill_chain import KillChainComposer
        from adbygod_api.core.validation.analytics.narrative import RedTeamNarrativeGenerator
        from adbygod_api.core.validation.scoring import ConsensusArbitrator

        decisions = [_decision("kerberos", "kerberoast", mitre=["T1558.003"])]
        fusion = ConsensusArbitrator().fuse(decisions, pentest_context, "kerberos")
        chains = KillChainComposer().compose(decisions, "kerberos")

        narrative = RedTeamNarrativeGenerator().generate(chains, decisions, fusion, pentest_context)

        assert isinstance(narrative, str)
        assert "RED TEAM SIMULATION NARRATIVE" in narrative
        assert "kerberos" in narrative.lower() or "credential" in narrative.lower()


class TestScoring:
    def test_arbitrator_returns_fusion_result(self, pentest_context):
        from adbygod_api.core.validation.contracts import FusionResult
        from adbygod_api.core.validation.scoring import ConsensusArbitrator, compute_mitre_coverage

        decisions = [
            _decision("kerberos", "kerberoast", mitre=["T1558.003"]),
            _decision("acl", "acl_edge", score_delta=0.6, mitre=["T1222.001"]),
        ]

        result = ConsensusArbitrator().fuse(decisions, pentest_context, "kerberos")
        coverage = compute_mitre_coverage(decisions)

        assert isinstance(result, FusionResult)
        assert result.risk_score >= 0
        assert result.final_verdict is not None
        covered_techniques = {technique for techniques in coverage.values() for technique in techniques}
        assert "T1558.003" in covered_techniques


class TestconsensusEngineV2:
    def _collect_events(self, module_id: str, ctx):
        from adbygod_api.core.validation.engine import ValidationConsensusEngineV2

        async def collect():
            engine = ValidationConsensusEngineV2()
            events = []
            async for event in engine.run_stream(module_id, ctx.assessment_id, None, ctx):
                events.append(event)
            return events, engine._last_fusion

        return asyncio.run(collect())

    @pytest.mark.parametrize(
        "module_id",
        ["kerberos", "acl", "adcs", "delegation", "password_policy", "maq_rbcd"],
    )
    def test_stream_produces_fusion_for_supported_modules(self, module_id, pentest_context):
        events, fusion = self._collect_events(module_id, pentest_context)
        event_types = [event["type"] for event in events]

        assert event_types[0] == "log"
        assert "fusion_start" in event_types
        assert "fusion_complete" in event_types
        assert "analytics_complete" in event_types
        assert "result" in event_types
        assert fusion is not None
        assert fusion.module_id == module_id
        assert fusion.risk_score >= 0
        assert fusion.telemetry["experts_run"] >= 1

    def test_run_returns_fusion_result(self, pentest_context):
        from adbygod_api.core.validation.contracts import FusionResult
        from adbygod_api.core.validation.engine import ValidationConsensusEngineV2

        async def run():
            return await ValidationConsensusEngineV2().run(
                "kerberos",
                pentest_context.assessment_id,
                None,
                pentest_context,
            )

        result = asyncio.run(run())

        assert isinstance(result, FusionResult)
        assert result.module_id == "kerberos"
        assert result.duration_ms >= 0

    def test_unknown_module_returns_insufficient_data_stream(self, pentest_context):
        events, fusion = self._collect_events("not_a_module", pentest_context)

        assert any(event["type"] == "fusion_complete" for event in events)
        assert any(event.get("verdict") == "INSUFFICIENT_DATA" for event in events)
        assert fusion is None
