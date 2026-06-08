"use client";
import { useState } from "react";
import type { ExpertDecision, ExpertVerdict } from "../lib/types";

interface ExpertDecisionListProps {
  decisions: ExpertDecision[];
  moduleId: string;
}

const VERDICT_STYLES: Record<ExpertVerdict, string> = {
  SUPPORTS_EXPOSURE: "bg-red-900/40 text-red-300 border-red-700/40",
  WEAK_SUPPORT: "bg-orange-900/40 text-orange-300 border-orange-700/40",
  NEUTRAL: "bg-gray-800/40 text-gray-400 border-gray-700/40",
  CONTRADICTS_EXPOSURE: "bg-green-900/40 text-green-300 border-green-700/40",
  INSUFFICIENT_DATA: "bg-blue-900/40 text-blue-400 border-blue-700/40",
};

const STAGE_COLORS: Record<string, string> = {
  initial_access: "text-blue-400",
  credential_access: "text-red-400",
  lateral_movement: "text-orange-400",
  privilege_escalation: "text-purple-400",
  persistence: "text-yellow-400",
  exfiltration: "text-pink-400",
};

function ExpertCard({ d }: { d: ExpertDecision }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className={`rounded-xl border transition-colors ${
      d.verdict === "SUPPORTS_EXPOSURE" ? "border-red-700/30 bg-red-950/10" :
      d.verdict === "CONTRADICTS_EXPOSURE" ? "border-green-700/30 bg-green-950/10" :
      "border-white/10 bg-white/5"
    }`}>
      {/* Header */}
      <button
        className="w-full flex items-start gap-3 p-3 text-left hover:bg-white/5 transition-colors rounded-xl"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className="text-sm font-semibold text-white">{d.expert_name}</span>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${VERDICT_STYLES[d.verdict]}`}>
              {d.verdict.replace(/_/g, " ")}
            </span>
            {d.severity_hint && (
              <span className="text-[10px] font-bold text-orange-400">{d.severity_hint}</span>
            )}
            {d.kill_chain_stage && (
              <span className={`text-[10px] ${STAGE_COLORS[d.kill_chain_stage] ?? "text-gray-500"}`}>
                {d.kill_chain_stage.replace(/_/g, " ")}
              </span>
            )}
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">{d.summary}</p>
        </div>
        <div className="shrink-0 text-right">
          <div className="text-sm font-mono text-white">{(d.score_delta * 10).toFixed(1)}</div>
          <div className="text-[10px] text-gray-600">score</div>
        </div>
      </button>

      {/* Confidence bar */}
      <div className="px-3 pb-2 flex items-center gap-2">
        <div className="flex-1 h-1 rounded-full bg-white/10 overflow-hidden">
          <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${d.confidence * 100}%` }} />
        </div>
        <span className="text-[10px] font-mono text-gray-500">{(d.confidence * 100).toFixed(0)}%</span>
      </div>

      {/* Signals chips */}
      <div className="px-3 pb-2 flex flex-wrap gap-1">
        {d.supporting_signals.map((s, i) => (
          <span key={`s${i}`} className="text-[9px] px-1.5 py-0.5 rounded bg-red-900/20 text-red-400 border border-red-700/20">+ {s}</span>
        ))}
        {d.contradicting_signals.map((s, i) => (
          <span key={`c${i}`} className="text-[9px] px-1.5 py-0.5 rounded bg-green-900/20 text-green-400 border border-green-700/20">- {s}</span>
        ))}
        {d.mitre_techniques.map((t) => (
          <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-purple-900/20 text-purple-400 border border-purple-700/20">{t}</span>
        ))}
        {d.cve_refs?.map((c) => (
          <span key={c} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-orange-900/20 text-orange-400 border border-orange-700/20">{c}</span>
        ))}
      </div>

      {/* Expandable details */}
      {expanded && (
        <div className="px-3 pb-3 flex flex-col gap-3 border-t border-white/5 pt-3">
          {d.reasoning.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold text-gray-500 mb-1">REASONING</div>
              <ul className="space-y-1">
                {d.reasoning.map((r, i) => (
                  <li key={i} className="text-xs text-gray-300 flex gap-2"><span className="text-gray-600">•</span>{r}</li>
                ))}
              </ul>
            </div>
          )}

          {d.remediation_commands.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold text-gray-500 mb-1">REMEDIATION</div>
              <div className="p-2 rounded bg-black/40 font-mono text-[10px] text-green-400 space-y-1">
                {d.remediation_commands.map((cmd, i) => (
                  <div key={i} className={cmd.startsWith("#") ? "text-gray-600" : "text-green-400"}>{cmd}</div>
                ))}
              </div>
            </div>
          )}

          {d.detection_opportunities.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold text-gray-500 mb-1">DETECTION OPPORTUNITIES</div>
              <ul className="space-y-1">
                {d.detection_opportunities.map((o, i) => (
                  <li key={i} className="text-xs text-cyan-400 flex gap-2"><span className="text-cyan-600">•</span>{o}</li>
                ))}
              </ul>
            </div>
          )}

          {d.missing_signals.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold text-gray-500 mb-1">MISSING SIGNALS</div>
              <div className="flex flex-wrap gap-1">
                {d.missing_signals.map((s, i) => (
                  <span key={i} className="text-[9px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-500 border border-gray-700">? {s}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ExpertDecisionList({ decisions, moduleId }: ExpertDecisionListProps) {
  const sorted = [...decisions].sort((a, b) => b.score_delta - a.score_delta);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-300">
          Expert Analysis — {moduleId.replace(/_/g, " ").toUpperCase()}
        </h3>
        <span className="text-xs text-gray-500">{decisions.length} expert{decisions.length !== 1 ? "s" : ""}</span>
      </div>
      {sorted.map((d, i) => <ExpertCard key={i} d={d} />)}
      {decisions.length === 0 && (
        <div className="text-center py-8 text-gray-600 text-sm">No expert decisions yet. Run the module to see results.</div>
      )}
    </div>
  );
}
