#!/usr/bin/env python3
"""
Validation Engine V2 — Smoke Test Script

Runs all 13 modules against synthetic presets and prints a summary report.
No DB or HTTP required — pure in-process validation.

Usage:
    python scripts/validate_connectivity.py
    python scripts/validate_connectivity.py --module kerberos
    python scripts/validate_connectivity.py --preset red_team_worst_case
    python scripts/validate_connectivity.py --all-presets
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ── ANSI colors ───────────────────────────────────────────────

RED     = "\033[91m"
ORANGE  = "\033[33m"
GREEN   = "\033[92m"
BLUE    = "\033[94m"
PURPLE  = "\033[95m"
CYAN    = "\033[96m"
GRAY    = "\033[90m"
BOLD    = "\033[1m"
RESET   = "\033[0m"


def _color_verdict(verdict: str) -> str:
    if verdict == "LIKELY_EXPOSED":
        return f"{RED}{BOLD}{verdict}{RESET}"
    if verdict == "CONDITIONALLY_EXPOSED":
        return f"{ORANGE}{verdict}{RESET}"
    if verdict == "LOW_CONFIDENCE_SIGNAL":
        return f"{BLUE}{verdict}{RESET}"
    return f"{GRAY}{verdict}{RESET}"


def _color_score(score: float) -> str:
    if score >= 8:
        return f"{RED}{BOLD}{score:.1f}{RESET}"
    if score >= 6:
        return f"{ORANGE}{score:.1f}{RESET}"
    if score >= 4:
        return f"{ORANGE}{score:.1f}{RESET}"
    return f"{GREEN}{score:.1f}{RESET}"


# ── Run single module ─────────────────────────────────────────

async def run_module(module_id: str, ctx, verbose: bool = False) -> dict:
    from adbygod_api.core.validation.engine import ValidationConsensusEngineV2

    engine = ValidationConsensusEngineV2()
    result = None
    expert_count = 0
    errors = []
    t0 = time.perf_counter()

    async for event in engine.run_stream(module_id, ctx.assessment_id, None, ctx):
        etype = event.get("type")
        if etype == "expert_decision":
            expert_count += 1
            if verbose:
                verdict = event.get("verdict", "?")
                name = event.get("expert_name", "?")
                print(f"  {GRAY}  [{verdict:25s}] {name}{RESET}")
        elif etype == "fusion_complete":
            result = {
                "final_verdict": event.get("verdict", "INSUFFICIENT_DATA"),
                "risk_score": event.get("risk_score", 0.0),
                "confidence": event.get("confidence", 0),
                "severity_projection": event.get("severity_projection", "INFO"),
            }
        elif etype == "error":
            errors.append(event.get("message", "unknown error"))

    fusion = getattr(engine, "_last_fusion", None)
    if fusion is not None:
        result = {
            "final_verdict": fusion.final_verdict.value if hasattr(fusion.final_verdict, "value") else str(fusion.final_verdict),
            "risk_score": fusion.risk_score,
            "confidence": fusion.confidence,
            "severity_projection": fusion.severity_projection,
            "kill_chains": fusion.kill_chains,
            "remediation_playbook": fusion.remediation_playbook,
            "threat_actor_matches": fusion.threat_actor_matches,
        }

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return {
        "module_id": module_id,
        "result": result,
        "expert_count": expert_count,
        "errors": errors,
        "elapsed_ms": elapsed_ms,
    }


# ── Print module row ──────────────────────────────────────────

def print_module_row(run: dict) -> None:
    mod = run["module_id"]
    result = run["result"] or {}
    verdict = result.get("final_verdict", "ERROR")
    score = result.get("risk_score", 0.0)
    experts = run["expert_count"]
    chains = len(result.get("kill_chains", []))
    playbook = len(result.get("remediation_playbook", []))
    actors = len(result.get("threat_actor_matches", []))
    elapsed = run["elapsed_ms"]
    errors = run["errors"]

    if errors:
        print(f"  {RED}✗{RESET} {mod:<22} {'ERROR: ' + errors[0]:<50} {GRAY}{elapsed:6.0f}ms{RESET}")
    elif result.get("final_verdict") == "ERROR":
        print(f"  {RED}✗{RESET} {mod:<22} {'ERROR: no fusion result':<50} {GRAY}{elapsed:6.0f}ms{RESET}")
    else:
        print(
            f"  {GREEN}✓{RESET} {BOLD}{mod:<22}{RESET} "
            f"{_color_verdict(verdict):<40} "
            f"score={_color_score(score)}  "
            f"experts={CYAN}{experts}{RESET}  "
            f"chains={PURPLE}{chains}{RESET}  "
            f"playbook={BLUE}{playbook}{RESET}  "
            f"actors={PURPLE}{actors}{RESET}  "
            f"{GRAY}{elapsed:5.0f}ms{RESET}"
        )


# ── All modules list ──────────────────────────────────────────

ALL_MODULES = [
    "kerberos", "acl", "dcsync", "ntlm_relay", "trust",
    "adcs", "shadow_credentials", "gpo_abuse", "laps_exposure",
    "delegation", "password_policy", "sid_history", "maq_rbcd",
]


# ── Main ──────────────────────────────────────────────────────

async def main(args: argparse.Namespace) -> int:
    # Trigger expert registration
    import adbygod_api.core.validation.experts  # noqa: F401

    from adbygod_api.core.validation.registry import registered_count, all_module_ids
    from adbygod_api.core.validation.synthetic.generator import SyntheticADGenerator
    from adbygod_api.core.validation.synthetic.presets import PRESETS
    from adbygod_api.core.validation.synthetic.apt_scenarios import APT_SCENARIOS

    modules_to_run = [args.module] if args.module else ALL_MODULES
    preset_name = args.preset or "pentest_target"

    # Resolve preset
    all_presets = {**PRESETS, **APT_SCENARIOS}
    if preset_name not in all_presets:
        print(f"{RED}Unknown preset '{preset_name}'. Available: {list(all_presets.keys())}{RESET}")
        return 1

    presets_to_run = list(all_presets.keys()) if args.all_presets else [preset_name]

    # Print header
    print(f"\n{BOLD}{'═' * 90}{RESET}")
    print(f"{BOLD}  Validation Engine V2 — Smoke Test{RESET}")
    print(f"  Registered: {CYAN}{registered_count()}{RESET} experts across {CYAN}{len(all_module_ids())}{RESET} modules")
    print(f"  Modules: {modules_to_run}")
    print(f"  Presets: {presets_to_run}")
    print(f"{BOLD}{'═' * 90}{RESET}\n")

    overall_pass = True
    gen = SyntheticADGenerator()

    for preset_key in presets_to_run:
        preset = all_presets[preset_key]
        cfg = preset.get("config") if isinstance(preset, dict) else preset
        ctx = gen.generate(cfg)
        entity_count = len(ctx.entities)
        finding_count = len(ctx.findings)
        edge_count = len(ctx.edges)

        print(f"{BOLD}  Preset: {PURPLE}{preset_key}{RESET}  "
              f"{GRAY}({entity_count} entities, {finding_count} findings, {edge_count} edges){RESET}")
        print(f"  {'─' * 80}")

        preset_results = []
        for module_id in modules_to_run:
            run = await run_module(module_id, ctx, verbose=args.verbose)
            print_module_row(run)
            preset_results.append(run)
            if run["errors"] or not run["result"]:
                overall_pass = False

        # Preset summary
        exposed = [r for r in preset_results if (r["result"] or {}).get("final_verdict") == "LIKELY_EXPOSED"]
        total_chains = sum(len((r["result"] or {}).get("kill_chains", [])) for r in preset_results)
        total_actors = sum(len((r["result"] or {}).get("threat_actor_matches", [])) for r in preset_results)
        total_playbook = sum(len((r["result"] or {}).get("remediation_playbook", [])) for r in preset_results)
        total_time = sum(r["elapsed_ms"] for r in preset_results)

        print(f"\n  {GRAY}Summary for {preset_key}:{RESET}")
        print(f"    {RED}LIKELY_EXPOSED{RESET}: {len(exposed)}/{len(modules_to_run)} modules")
        print(f"    Kill chains:      {PURPLE}{total_chains}{RESET}")
        print(f"    Threat actors:    {PURPLE}{total_actors}{RESET}")
        print(f"    Playbook steps:   {BLUE}{total_playbook}{RESET}")
        print(f"    Total time:       {GRAY}{total_time:.0f}ms{RESET}\n")

    # Analytics showcase (single run on pentest_target for all modules)
    if not args.module and not args.all_presets:
        print(f"{BOLD}  Kill Chain / Cross-Module Deep Analysis{RESET}")
        print(f"  {'─' * 80}")
        preset = all_presets.get("pentest_target", list(all_presets.values())[0])
        cfg = preset.get("config") if isinstance(preset, dict) else preset
        await _analytics_showcase(gen, cfg)

    print(f"\n{BOLD}{'═' * 90}{RESET}")
    if overall_pass:
        print(f"  {GREEN}{BOLD}ALL SMOKE TESTS PASSED{RESET}")
    else:
        print(f"  {RED}{BOLD}SMOKE TESTS FAILED — see errors above{RESET}")
    print(f"{'═' * 90}{RESET}\n")

    return 0 if overall_pass else 1


async def _analytics_showcase(gen, cfg) -> None:
    from adbygod_api.core.validation.analytics.kill_chain import KillChainComposer
    from adbygod_api.core.validation.analytics.cross_module import CrossModuleCorrelator
    from adbygod_api.core.validation.analytics.threat_actor import ThreatActorMatcher
    from adbygod_api.core.validation.analytics.playbook import PlaybookGenerator
    from adbygod_api.core.validation.analytics.narrative import RedTeamNarrativeGenerator
    from adbygod_api.core.validation.scoring import ConsensusArbitrator
    from adbygod_api.core.validation.engine import ValidationConsensusEngineV2

    ctx = gen.generate(cfg)
    engine = ValidationConsensusEngineV2()
    all_decisions = []

    for module_id in ALL_MODULES:
        async for event in engine.run_stream(module_id, ctx.assessment_id, None, ctx):
            if event.get("type") == "expert_decision":
                # Reconstruct decision from event data
                pass  # decisions are held inside engine; use result analytics instead

    # Collect all decisions by running each module
    from adbygod_api.core.validation.registry import get_experts_for
    from adbygod_api.core.validation.contracts import ExpertDecision

    for module_id in ALL_MODULES:
        experts = get_experts_for(module_id)
        for cls in experts:
            try:
                d = await cls().analyze(ctx)
                all_decisions.append(d)
            except Exception:
                pass

    # Kill chains
    chains = KillChainComposer().compose(all_decisions, "full")
    print(f"  {PURPLE}Kill Chains:{RESET} {len(chains)} identified")
    for chain in chains[:3]:
        print(f"    {GRAY}→ {chain.name} (risk={chain.composite_risk:.1f}){RESET}")

    # Cross-module
    module_scores = {}
    module_decisions = {}
    for decision in all_decisions:
        module_decisions.setdefault(decision.module_id, []).append(decision)
        module_scores[decision.module_id] = max(module_scores.get(decision.module_id, 0.0), decision.score_delta * 10)
    compound = CrossModuleCorrelator().correlate(module_scores, module_decisions)
    print(f"  {PURPLE}Cross-Module Chains:{RESET} {len(compound)} compound rules triggered")
    for c in compound[:2]:
        print(f"    {GRAY}→ {' + '.join(c.modules)} → severity={c.compound_severity}{RESET}")

    # Threat actors
    actors = ThreatActorMatcher().match(all_decisions)
    print(f"  {PURPLE}Threat Actor Matches:{RESET} {len(actors)} profiles matched")
    for actor in actors[:3]:
        print(f"    {GRAY}→ {actor.actor_name} ({actor.match_score * 100:.0f}% match){RESET}")

    # Playbook
    steps = PlaybookGenerator().generate(all_decisions, ctx, "full")
    print(f"  {BLUE}Playbook:{RESET} {len(steps)} remediation steps generated")

    # Narrative
    fusion = ConsensusArbitrator().fuse(all_decisions, ctx, "full") if all_decisions else None
    narrative = (
        RedTeamNarrativeGenerator().generate(chains, all_decisions, fusion, ctx)
        if fusion is not None else ""
    )
    lines = narrative.strip().split("\n")
    print(f"  {CYAN}Narrative:{RESET} {len(lines)} lines, {len(narrative)} chars")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validation Engine V2 smoke test")
    parser.add_argument("--module", "-m", help="Run only this module ID")
    parser.add_argument("--preset", "-p", default="pentest_target", help="Synthetic preset to use")
    parser.add_argument("--all-presets", action="store_true", help="Run all presets")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show per-expert decisions")
    args = parser.parse_args()

    sys.exit(asyncio.run(main(args)))
