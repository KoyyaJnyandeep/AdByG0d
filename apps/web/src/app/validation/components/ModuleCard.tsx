"use client";
import type { ValidationModule, FusionResult, SeverityLevel } from "../lib/types";
import { SEVERITY_COLORS, VERDICT_COLORS, MODULE_ICONS } from "../lib/types";

interface ModuleCardProps {
  module: ValidationModule;
  lastResult?: FusionResult | null;
  isSelected: boolean;
  isRunning: boolean;
  onClick: () => void;
}

const RISK_CATEGORY_LABELS: Record<string, string> = {
  credential_access: "Credential Access",
  lateral_movement: "Lateral Movement",
  privilege_escalation: "Priv. Escalation",
  persistence: "Persistence",
  initial_access: "Initial Access",
  defense_evasion: "Defense Evasion",
};

const RISK_CATEGORY_COLORS: Record<string, string> = {
  credential_access: "bg-red-900/40 text-red-300 border-red-700/50",
  lateral_movement: "bg-orange-900/40 text-orange-300 border-orange-700/50",
  privilege_escalation: "bg-purple-900/40 text-purple-300 border-purple-700/50",
  persistence: "bg-yellow-900/40 text-yellow-300 border-yellow-700/50",
  initial_access: "bg-blue-900/40 text-blue-300 border-blue-700/50",
  defense_evasion: "bg-gray-900/40 text-gray-300 border-gray-700/50",
};

export default function ModuleCard({ module, lastResult, isSelected, isRunning, onClick }: ModuleCardProps) {
  const verdict = lastResult?.final_verdict;
  const riskScore = lastResult?.risk_score ?? 0;
  const severity = lastResult?.severity_projection as SeverityLevel | undefined;
  const verdictColor = verdict ? VERDICT_COLORS[verdict] : "#6b7280";
  const severityColor = severity ? SEVERITY_COLORS[severity] : "#6b7280";
  const icon = MODULE_ICONS[module.id] ?? "🔍";

  const glowStyle = isSelected && verdict
    ? { boxShadow: `0 0 20px ${verdictColor}40, 0 0 40px ${verdictColor}20` }
    : {};

  return (
    <button
      onClick={onClick}
      className={`
        relative w-full text-left p-4 rounded-xl border transition-all duration-200
        bg-white/5 hover:bg-white/8 backdrop-blur-sm
        ${isSelected ? "border-white/30 bg-white/10" : "border-white/10"}
        ${isRunning ? "animate-pulse" : ""}
      `}
      style={glowStyle}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <span className="text-xl">{icon}</span>
          <div>
            <h3 className="text-sm font-semibold text-white leading-tight">{module.name}</h3>
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${RISK_CATEGORY_COLORS[module.risk_category] ?? "bg-gray-800 text-gray-400 border-gray-700"}`}>
              {RISK_CATEGORY_LABELS[module.risk_category] ?? module.risk_category}
            </span>
          </div>
        </div>
        <span className="text-xs text-gray-500 shrink-0">{module.expert_count}E</span>
      </div>

      {/* Verdict badge */}
      {verdict ? (
        <div className="mb-3 flex items-center gap-2">
          <span
            className="text-[10px] font-bold px-2 py-0.5 rounded"
            style={{ backgroundColor: `${verdictColor}20`, color: verdictColor, border: `1px solid ${verdictColor}40` }}
          >
            {verdict.replace(/_/g, " ")}
          </span>
          <span className="text-xs font-mono" style={{ color: severityColor }}>{severity}</span>
        </div>
      ) : (
        <div className="mb-3">
          <span className="text-[10px] text-gray-600 border border-gray-700/50 rounded px-2 py-0.5">NOT RUN</span>
        </div>
      )}

      {/* Risk score bar */}
      <div className="mb-3">
        <div className="flex justify-between items-center mb-1">
          <span className="text-[10px] text-gray-500">Risk Score</span>
          <span className="text-[11px] font-mono text-white">{riskScore.toFixed(1)}/10</span>
        </div>
        <div className="h-1.5 rounded-full bg-white/10 overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${riskScore * 10}%`,
              backgroundColor: verdictColor,
            }}
          />
        </div>
      </div>

      {/* MITRE chips */}
      <div className="flex flex-wrap gap-1">
        {module.mitre_techniques.slice(0, 3).map((t) => (
          <span key={t} className="text-[9px] font-mono px-1 py-0.5 rounded bg-white/5 text-gray-500 border border-white/5">
            {t}
          </span>
        ))}
        {module.mitre_techniques.length > 3 && (
          <span className="text-[9px] text-gray-600">+{module.mitre_techniques.length - 3}</span>
        )}
      </div>

      {/* Running indicator */}
      {isRunning && (
        <div className="absolute top-2 right-2 w-2 h-2 rounded-full bg-green-400 animate-ping" />
      )}
    </button>
  );
}
