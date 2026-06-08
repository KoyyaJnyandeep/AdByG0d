"use client";

import type { FusionResult } from "../lib/types";

interface MitrePanelProps {
  result: FusionResult | null;
}

const TACTIC_COLORS: Record<string, string> = {
  initial_access: "#60a5fa",
  execution: "#fbbf24",
  persistence: "#f59e0b",
  privilege_escalation: "#a78bfa",
  defense_evasion: "#34d399",
  credential_access: "#f87171",
  discovery: "#22d3ee",
  lateral_movement: "#fb923c",
  collection: "#818cf8",
  exfiltration: "#f472b6",
  impact: "#ef4444",
};

export default function MitrePanel({ result }: MitrePanelProps) {
  const coverage = result?.mitre_coverage ?? {};
  const entries = Object.entries(coverage).filter(([, techniques]) => techniques.length > 0);
  const total = entries.reduce((sum, [, techniques]) => sum + techniques.length, 0);

  if (entries.length === 0) {
    return (
      <div className="text-center py-16 text-gray-600 text-sm">
        Run a module to see MITRE ATT&amp;CK coverage.
      </div>
    );
  }

  const navigatorJson = {
    name: `AdByG0d ${result?.module_id ?? "validation"} exposure`,
    version: "4.5",
    domain: "enterprise-attack",
    techniques: entries.flatMap(([, techniques]) =>
      techniques.map((techniqueID) => ({
        techniqueID,
        score: 1,
        color: "#ef4444",
        comment: "Observed by AdByG0d validation engine",
      }))
    ),
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-bold text-white">MITRE ATT&amp;CK Coverage</h2>
        <a
          href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(navigatorJson, null, 2))}`}
          download={`adbygod-mitre-${result?.run_id ?? "coverage"}.json`}
          className="rounded-md border border-white/10 bg-white/5 px-2.5 py-1.5 text-xs text-gray-300 hover:text-white"
        >
          Export Navigator JSON
        </a>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        {entries.map(([tactic, techniques]) => {
          const color = TACTIC_COLORS[tactic] ?? "#9ca3af";
          const pct = total > 0 ? Math.round((techniques.length / total) * 100) : 0;
          return (
            <section key={tactic} className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
              <div className="mb-3 flex items-center gap-2">
                <div className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                <h3 className="text-sm font-semibold capitalize text-white">{tactic.replace(/_/g, " ")}</h3>
                <span className="ml-auto font-mono text-xs text-gray-500">{pct}%</span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {techniques.map((technique) => (
                  <span
                    key={technique}
                    className="rounded border px-1.5 py-0.5 font-mono text-[10px]"
                    style={{ borderColor: `${color}55`, backgroundColor: `${color}14`, color }}
                    title={`${technique} observed in ${tactic.replace(/_/g, " ")}`}
                  >
                    {technique}
                  </span>
                ))}
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}
