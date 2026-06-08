"use client";

import { ArrowRight, GitCompare } from "lucide-react";
import type { FusionResult } from "../lib/types";
import { VERDICT_COLORS } from "../lib/types";

interface RunComparisonProps {
  before: FusionResult | null;
  after: FusionResult | null;
}

function scoreDelta(before: number, after: number) {
  const delta = after - before;
  return `${delta >= 0 ? "+" : ""}${delta.toFixed(1)}`;
}

export default function RunComparison({ before, after }: RunComparisonProps) {
  if (!before || !after) {
    return (
      <div className="rounded-lg border border-white/10 bg-white/[0.04] p-8 text-center">
        <GitCompare className="mx-auto mb-3 h-6 w-6 text-gray-600" />
        <div className="text-sm text-gray-500">Select two completed runs to compare posture changes.</div>
      </div>
    );
  }

  const beforeChains = new Set((before.kill_chains ?? []).map((chain) => chain.chain_id));
  const afterChains = new Set((after.kill_chains ?? []).map((chain) => chain.chain_id));
  const eliminated = [...beforeChains].filter((chain) => !afterChains.has(chain));
  const added = [...afterChains].filter((chain) => !beforeChains.has(chain));
  const beforeMitre = new Set(Object.values(before.mitre_coverage ?? {}).flat());
  const afterMitre = new Set(Object.values(after.mitre_coverage ?? {}).flat());
  const removedMitre = [...beforeMitre].filter((technique) => !afterMitre.has(technique));
  const addedMitre = [...afterMitre].filter((technique) => !beforeMitre.has(technique));
  const verdictChanged = before.final_verdict !== after.final_verdict;
  const riskDelta = after.risk_score - before.risk_score;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <section className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
          <div className="mb-2 text-xs font-semibold text-gray-500">VERDICT</div>
          <div className="flex items-center gap-2 text-sm font-bold">
            <span style={{ color: VERDICT_COLORS[before.final_verdict] }}>{before.final_verdict.replace(/_/g, " ")}</span>
            <ArrowRight className="h-4 w-4 text-gray-600" />
            <span style={{ color: VERDICT_COLORS[after.final_verdict] }}>{after.final_verdict.replace(/_/g, " ")}</span>
          </div>
          <div className="mt-2 text-xs text-gray-500">{verdictChanged ? "Verdict changed" : "Verdict unchanged"}</div>
        </section>

        <section className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
          <div className="mb-2 text-xs font-semibold text-gray-500">RISK SCORE</div>
          <div className="flex items-end gap-2">
            <span className="font-mono text-2xl font-bold text-white">{after.risk_score.toFixed(1)}</span>
            <span className={riskDelta <= 0 ? "text-sm font-semibold text-green-400" : "text-sm font-semibold text-red-400"}>
              {scoreDelta(before.risk_score, after.risk_score)}
            </span>
          </div>
          <div className="mt-2 text-xs text-gray-500">Previous {before.risk_score.toFixed(1)}</div>
        </section>

        <section className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
          <div className="mb-2 text-xs font-semibold text-gray-500">ATTACK PATHS</div>
          <div className="text-2xl font-bold text-white">{eliminated.length}</div>
          <div className="mt-2 text-xs text-gray-500">eliminated, {added.length} added</div>
        </section>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <section className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
          <h3 className="mb-3 text-sm font-semibold text-white">Kill Chain Diff</h3>
          <div className="space-y-2">
            <div>
              <div className="mb-1 text-[10px] font-semibold text-green-400">ELIMINATED</div>
              <div className="flex flex-wrap gap-1">{eliminated.length ? eliminated.map((id) => <span key={id} className="rounded bg-green-950/30 px-1.5 py-0.5 font-mono text-[10px] text-green-300">{id}</span>) : <span className="text-xs text-gray-600">None</span>}</div>
            </div>
            <div>
              <div className="mb-1 text-[10px] font-semibold text-red-400">ADDED</div>
              <div className="flex flex-wrap gap-1">{added.length ? added.map((id) => <span key={id} className="rounded bg-red-950/30 px-1.5 py-0.5 font-mono text-[10px] text-red-300">{id}</span>) : <span className="text-xs text-gray-600">None</span>}</div>
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
          <h3 className="mb-3 text-sm font-semibold text-white">MITRE Diff</h3>
          <div className="space-y-2">
            <div>
              <div className="mb-1 text-[10px] font-semibold text-green-400">NO LONGER TRIGGERED</div>
              <div className="flex flex-wrap gap-1">{removedMitre.length ? removedMitre.map((id) => <span key={id} className="rounded bg-green-950/30 px-1.5 py-0.5 font-mono text-[10px] text-green-300">{id}</span>) : <span className="text-xs text-gray-600">None</span>}</div>
            </div>
            <div>
              <div className="mb-1 text-[10px] font-semibold text-red-400">NEWLY TRIGGERED</div>
              <div className="flex flex-wrap gap-1">{addedMitre.length ? addedMitre.map((id) => <span key={id} className="rounded bg-red-950/30 px-1.5 py-0.5 font-mono text-[10px] text-red-300">{id}</span>) : <span className="text-xs text-gray-600">None</span>}</div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
