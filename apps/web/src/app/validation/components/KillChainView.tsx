"use client";
import type { KillChain, ThreatActorMatch } from "../lib/types";

interface KillChainViewProps {
  killChains: KillChain[];
  threatActors: ThreatActorMatch[];
}

const STAGE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  initial_access: { bg: "bg-blue-950/60", text: "text-blue-300", border: "border-blue-700/40" },
  credential_access: { bg: "bg-red-950/60", text: "text-red-300", border: "border-red-700/40" },
  lateral_movement: { bg: "bg-orange-950/60", text: "text-orange-300", border: "border-orange-700/40" },
  privilege_escalation: { bg: "bg-purple-950/60", text: "text-purple-300", border: "border-purple-700/40" },
  persistence: { bg: "bg-yellow-950/60", text: "text-yellow-300", border: "border-yellow-700/40" },
  exfiltration: { bg: "bg-pink-950/60", text: "text-pink-300", border: "border-pink-700/40" },
  execution: { bg: "bg-gray-950/60", text: "text-gray-300", border: "border-gray-700/40" },
};

function KillChainCard({ chain }: { chain: KillChain }) {
  const riskColor = chain.composite_risk >= 8 ? "#ef4444" : chain.composite_risk >= 6 ? "#f97316" : "#eab308";

  return (
    <div className="rounded-xl border border-white/10 bg-white/5 p-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 mb-4">
        <div>
          <h3 className="text-sm font-bold text-white mb-1">{chain.name}</h3>
          <div className="flex flex-wrap gap-1">
            {chain.threat_actors.map((a) => (
              <span key={a} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-900/20 text-purple-400 border border-purple-700/20">
                {a.toUpperCase()}
              </span>
            ))}
          </div>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-2xl font-bold font-mono" style={{ color: riskColor }}>
            {chain.composite_risk.toFixed(1)}
          </div>
          <div className="text-[10px] text-gray-500">composite risk</div>
        </div>
      </div>

      {/* Steps flow */}
      <div className="flex items-center gap-1 flex-wrap mb-4">
        {chain.steps.map((step, i) => {
          const colors = STAGE_COLORS[step.module_id] ?? STAGE_COLORS.execution;
          return (
            <div key={i} className="flex items-center gap-1">
              <div className={`px-2 py-1.5 rounded-lg border text-xs ${colors.bg} ${colors.text} ${colors.border}`}>
                <div className="font-mono text-[9px] opacity-60 mb-0.5">{step.mitre_id}</div>
                <div className="font-semibold leading-tight max-w-[100px] truncate">{step.technique}</div>
              </div>
              {i < chain.steps.length - 1 && (
                <span className="text-gray-600 text-sm font-bold">→</span>
              )}
            </div>
          );
        })}
      </div>

      {/* Narrative */}
      {chain.narrative && (
        <div className="p-3 rounded-lg bg-black/30 border border-white/5 text-xs text-gray-400 leading-relaxed whitespace-pre-wrap font-mono">
          {chain.narrative}
        </div>
      )}
    </div>
  );
}

export default function KillChainView({ killChains, threatActors }: KillChainViewProps) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-bold text-white">Attack Kill Chains</h2>
        <span className="text-xs text-gray-500">{killChains.length} chain{killChains.length !== 1 ? "s" : ""} identified</span>
      </div>

      {/* Threat actors */}
      {threatActors.length > 0 && (
        <div className="p-3 rounded-xl bg-purple-950/20 border border-purple-700/20">
          <div className="text-[10px] font-semibold text-purple-400 mb-2">THREAT ACTOR OVERLAP</div>
          <div className="flex flex-col gap-2">
            {threatActors.map((actor) => (
              <div key={actor.actor_id} className="flex items-start gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-white">{actor.actor_name}</span>
                    <span className="text-xs font-mono text-purple-400">{(actor.match_score * 100).toFixed(0)}% match</span>
                  </div>
                  <p className="text-xs text-gray-400 mt-0.5">{actor.description}</p>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {actor.matched_techniques.map((t) => (
                      <span key={t} className="text-[9px] font-mono px-1 py-0.5 rounded bg-purple-900/30 text-purple-400 border border-purple-700/30">{t}</span>
                    ))}
                  </div>
                </div>
                <div className="shrink-0">
                  <div className="w-12 h-1.5 rounded-full bg-white/10 overflow-hidden">
                    <div className="h-full rounded-full bg-purple-500" style={{ width: `${actor.match_score * 100}%` }} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Kill chain cards */}
      {killChains.map((chain) => (
        <KillChainCard key={chain.chain_id} chain={chain} />
      ))}

      {killChains.length === 0 && (
        <div className="text-center py-8 text-gray-600 text-sm">No kill chains identified. Run validation module to see attack chains.</div>
      )}
    </div>
  );
}
