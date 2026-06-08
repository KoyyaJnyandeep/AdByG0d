"use client";
import { useState } from "react";
import type { FusionResult } from "../lib/types";
import { VERDICT_COLORS, VERDICT_LABELS, SEVERITY_COLORS } from "../lib/types";

interface VerdictPanelProps {
  result: FusionResult;
  moduleId: string;
}

function RiskDial({ score }: { score: number | undefined }) {
  const s = score ?? 0;
  const pct = s / 10;
  const r = 40;
  const cx = 50;
  const cy = 55;
  const circumference = Math.PI * r;
  const strokeDashoffset = circumference * (1 - pct);
  const color = s >= 8 ? "#ef4444" : s >= 6 ? "#f97316" : s >= 4 ? "#eab308" : "#22c55e";

  return (
    <svg width="100" height="70" viewBox="0 0 100 70">
      <path
        d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
        fill="none"
        stroke="#ffffff15"
        strokeWidth="8"
        strokeLinecap="round"
      />
      <path
        d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={strokeDashoffset}
        style={{ transition: "stroke-dashoffset 0.8s ease, stroke 0.5s ease" }}
      />
      <text x={cx} y={cy - 4} textAnchor="middle" fill={color} fontSize="18" fontWeight="bold" fontFamily="monospace">
        {s.toFixed(1)}
      </text>
      <text x={cx} y={cy + 10} textAnchor="middle" fill="#6b7280" fontSize="8" fontFamily="sans-serif">
        / 10.0
      </text>
    </svg>
  );
}

function Collapsible({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  if (count === 0) return null;
  return (
    <div className="border border-white/10 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-sm text-gray-300 hover:bg-white/5 transition-colors"
      >
        <span>{title}</span>
        <span className="flex items-center gap-2">
          <span className="text-xs text-gray-500">{count} item{count !== 1 ? "s" : ""}</span>
          <span className="text-gray-600">{open ? "▲" : "▼"}</span>
        </span>
      </button>
      {open && <div className="px-3 pb-3">{children}</div>}
    </div>
  );
}

export default function VerdictPanel({ result, moduleId }: VerdictPanelProps) {
  const verdictColor = VERDICT_COLORS[result.final_verdict] ?? "#6b7280";
  const severityColor = SEVERITY_COLORS[result.severity_projection] ?? "#6b7280";
  const isPulsing = result.final_verdict === "LIKELY_EXPOSED";

  return (
    <div className="flex flex-col gap-4 p-4 rounded-xl bg-white/5 border border-white/10">
      {/* Module + duration */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500 font-mono">
          {moduleId.toUpperCase().replace(/_/g, " ")} MODULE
        </span>
        {(result.duration_ms ?? 0) > 0 && (
          <span className="text-xs text-gray-600 font-mono">{result.duration_ms}ms</span>
        )}
      </div>

      {/* Verdict + dial */}
      <div className="flex items-center gap-6">
        {/* Verdict badge */}
        <div className="flex-1">
          <div
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl border text-sm font-bold ${isPulsing ? "animate-pulse" : ""}`}
            style={{
              backgroundColor: `${verdictColor}15`,
              borderColor: `${verdictColor}40`,
              color: verdictColor,
              boxShadow: isPulsing ? `0 0 20px ${verdictColor}30` : undefined,
            }}
          >
            {isPulsing && <span className="w-2 h-2 rounded-full animate-ping" style={{ backgroundColor: verdictColor }} />}
            {VERDICT_LABELS[result.final_verdict] ?? result.final_verdict}
          </div>
          <div className="mt-2 flex items-center gap-3">
            <span className="text-xs font-bold" style={{ color: severityColor }}>
              {result.severity_projection}
            </span>
            <span className="text-xs text-gray-500">
              {result.confidence}% confidence
            </span>
          </div>
        </div>
        <RiskDial score={result.risk_score} />
      </div>

      {/* Evidence quality + consensus */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Confidence", value: result.confidence ?? 0, color: "#60a5fa" },
          { label: "Consensus", value: result.consensus_score ?? 0, color: "#a78bfa" },
          { label: "Evidence Quality", value: result.evidence_quality_score ?? 0, color: "#34d399" },
        ].map(({ label, value, color }) => (
          <div key={label} className="p-2 rounded-lg bg-black/20 border border-white/5">
            <div className="text-[10px] text-gray-500 mb-1">{label}</div>
            <div className="flex items-center gap-1.5">
              <div className="flex-1 h-1.5 rounded-full bg-white/10 overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${value}%`, backgroundColor: color }} />
              </div>
              <span className="text-[11px] font-mono" style={{ color }}>{value}%</span>
            </div>
          </div>
        ))}
      </div>

      {/* Summary */}
      {result.summary && (
        <p className="text-sm text-gray-300 leading-relaxed">{result.summary}</p>
      )}

      {/* Operator brief */}
      {result.operator_brief && (
        <div className="p-3 rounded-lg bg-black/30 border border-white/5 font-mono text-xs text-green-400 leading-relaxed whitespace-pre-wrap">
          {result.operator_brief}
        </div>
      )}

      {/* Expert counts */}
      <div className="flex gap-4 text-xs">
        <span className="text-red-400"><strong>{result.support_count ?? 0}</strong> support</span>
        <span className="text-green-400"><strong>{result.contradiction_count ?? 0}</strong> contradict</span>
        <span className="text-gray-500"><strong>{result.insufficient_count ?? 0}</strong> insufficient</span>
        <span className="text-blue-400"><strong>{result.mapped_attack_steps ?? 0}</strong> attack steps</span>
      </div>

      {/* Collapsible sections */}
      <div className="flex flex-col gap-2">
        <Collapsible title="What Increased Confidence" count={(result.what_increased_confidence ?? []).length}>
          <ul className="mt-2 space-y-1">
            {(result.what_increased_confidence ?? []).map((item, i) => (
              <li key={i} className="text-xs text-red-300 flex gap-2"><span className="text-red-500">+</span>{item}</li>
            ))}
          </ul>
        </Collapsible>

        <Collapsible title="What Reduced Confidence" count={(result.what_reduced_confidence ?? []).length}>
          <ul className="mt-2 space-y-1">
            {(result.what_reduced_confidence ?? []).map((item, i) => (
              <li key={i} className="text-xs text-green-300 flex gap-2"><span className="text-green-500">-</span>{item}</li>
            ))}
          </ul>
        </Collapsible>

        <Collapsible title="What Would Raise Confidence" count={(result.what_would_raise_confidence ?? []).length}>
          <ul className="mt-2 space-y-1">
            {(result.what_would_raise_confidence ?? []).map((item, i) => (
              <li key={i} className="text-xs text-blue-300 flex gap-2"><span className="text-blue-500">?</span>{item}</li>
            ))}
          </ul>
        </Collapsible>

        <Collapsible title="Recommended Actions" count={(result.recommended_actions ?? []).length}>
          <ul className="mt-2 space-y-1">
            {(result.recommended_actions ?? []).map((item, i) => (
              <li key={i} className="text-xs text-yellow-300 flex gap-2"><span className="text-yellow-500">{i+1}.</span>{item}</li>
            ))}
          </ul>
        </Collapsible>

        {/* Control mapping */}
        {(result.control_mapping ?? []).length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {(result.control_mapping ?? []).map((ctrl, i) => (
              <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-blue-900/20 text-blue-400 border border-blue-700/20">
                {ctrl}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
