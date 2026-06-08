"use client";
import { useState, useEffect } from "react";
import { fetchPresets } from "../lib/api";
import type { SyntheticPresetsResponse, SyntheticConfig } from "../lib/types";

interface SyntheticDataPanelProps {
  onRunPreset: (presetName: string, isApt: boolean) => void;
  onCustomGenerate: (config: SyntheticConfig) => void;
  isRunning: boolean;
}

const SLIDER_FIELDS: Array<{
  key: keyof SyntheticConfig;
  label: string;
  min: number;
  max: number;
  step: number;
  unit?: string;
  dangerous?: boolean;
}> = [
  { key: "user_count", label: "Users", min: 50, max: 5000, step: 50 },
  { key: "computer_count", label: "Computers", min: 20, max: 2000, step: 20 },
  { key: "dc_count", label: "Domain Controllers", min: 1, max: 10, step: 1 },
  { key: "asrep_pct", label: "AS-REP Roastable %", min: 0, max: 0.5, step: 0.01, unit: "%", dangerous: true },
  { key: "kerberoastable_pct", label: "Kerberoastable %", min: 0, max: 0.5, step: 0.01, unit: "%", dangerous: true },
  { key: "laps_coverage_pct", label: "LAPS Coverage %", min: 0, max: 1, step: 0.05, unit: "%" },
  { key: "esc1_templates", label: "ESC1 Templates", min: 0, max: 10, step: 1, dangerous: true },
  { key: "shadow_credential_write_edges", label: "Shadow Cred Write Edges", min: 0, max: 20, step: 1, dangerous: true },
  { key: "gpo_write_edges", label: "GPO Write Edges", min: 0, max: 20, step: 1, dangerous: true },
  { key: "maq_value", label: "Machine Account Quota", min: 0, max: 10, step: 1, dangerous: true },
  { key: "rbcd_edges", label: "RBCD Edges", min: 0, max: 10, step: 1, dangerous: true },
  { key: "sid_history_count", label: "SID History Entries", min: 0, max: 50, step: 1, dangerous: true },
  { key: "password_policy_minlength", label: "Password Min Length", min: 6, max: 20, step: 1 },
  { key: "password_lockout_threshold", label: "Lockout Threshold", min: 0, max: 10, step: 1 },
];

const DEFAULTS: SyntheticConfig = {
  user_count: 300, computer_count: 100, dc_count: 2,
  asrep_pct: 0.05, kerberoastable_pct: 0.08,
  laps_coverage_pct: 0.5, esc1_templates: 1,
  shadow_credential_write_edges: 2, gpo_write_edges: 3,
  maq_value: 10, rbcd_edges: 2, sid_history_count: 5,
  password_policy_minlength: 8, password_lockout_threshold: 0,
};

function estimateExposure(cfg: SyntheticConfig): number {
  let score = 0;
  score += (cfg.asrep_pct ?? 0) * 20;
  score += (cfg.kerberoastable_pct ?? 0) * 15;
  score += (1 - (cfg.laps_coverage_pct ?? 1)) * 10;
  score += (cfg.esc1_templates ?? 0) * 8;
  score += Math.min((cfg.shadow_credential_write_edges ?? 0), 5) * 6;
  score += Math.min((cfg.gpo_write_edges ?? 0), 5) * 4;
  score += ((cfg.maq_value ?? 0) > 0 ? 10 : 0);
  score += Math.min((cfg.rbcd_edges ?? 0), 5) * 5;
  score += ((cfg.password_lockout_threshold ?? 0) === 0 ? 8 : 0);
  score += Math.max(0, 14 - (cfg.password_policy_minlength ?? 8)) * 2;
  return Math.min(100, Math.round(score));
}

export default function SyntheticDataPanel({ onRunPreset, onCustomGenerate, isRunning }: SyntheticDataPanelProps) {
  const [tab, setTab] = useState<"presets" | "custom">("presets");
  const [presets, setPresets] = useState<SyntheticPresetsResponse | null>(null);
  const [config, setConfig] = useState<SyntheticConfig>(DEFAULTS);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    fetchPresets()
      .then(setPresets)
      .catch(() => setPresets({ presets: {}, apt_scenarios: {} }))
      .finally(() => setLoading(false));
  }, []);

  const exposure = estimateExposure(config);
  const exposureColor = exposure >= 70 ? "#ef4444" : exposure >= 40 ? "#f97316" : "#22c55e";

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-2">
        {(["presets", "custom"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-lg text-sm font-semibold transition-colors ${
              tab === t ? "bg-white/15 text-white" : "text-gray-400 hover:text-white"
            }`}
          >
            {t === "presets" ? "Scenario Presets" : "Custom Builder"}
          </button>
        ))}
      </div>

      {tab === "presets" && (
        <div className="flex flex-col gap-4">
          {loading ? (
            <div className="text-gray-500 text-sm text-center py-8">Loading presets...</div>
          ) : (
            <>
              <div>
                <h4 className="text-xs font-semibold text-gray-500 mb-2">STANDARD SCENARIOS</h4>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(presets?.presets ?? {}).map(([name, preset]) => (
                    <button
                      key={name}
                      disabled={isRunning}
                      onClick={() => onRunPreset(name, false)}
                      className="text-left p-3 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 hover:border-white/20 transition-all disabled:opacity-50"
                    >
                      <div className="text-sm font-semibold text-white mb-1">{preset.name}</div>
                      <div className="text-xs text-gray-400 leading-relaxed mb-2">{preset.description}</div>
                      <div className="text-[10px] text-gray-600">
                        {preset.user_count} users · {preset.computer_count} computers
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-xs font-semibold text-purple-400 mb-2">APT SCENARIO TEMPLATES</h4>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(presets?.apt_scenarios ?? {}).map(([name, scenario]) => (
                    <button
                      key={name}
                      disabled={isRunning}
                      onClick={() => onRunPreset(name, true)}
                      className="text-left p-3 rounded-xl bg-purple-950/20 border border-purple-700/20 hover:bg-purple-950/30 hover:border-purple-700/40 transition-all disabled:opacity-50"
                    >
                      <div className="text-sm font-semibold text-white mb-1">{scenario.name}</div>
                      <div className="text-xs text-gray-400 leading-relaxed mb-2">{scenario.description}</div>
                      <div className="text-[10px] text-purple-400">{scenario.threat_actor}</div>
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {tab === "custom" && (
        <div className="flex flex-col gap-4">
          {/* Estimated exposure gauge */}
          <div className="flex items-center gap-4 p-3 rounded-xl bg-white/5 border border-white/10">
            <div>
              <div className="text-xs text-gray-500 mb-1">Estimated Exposure Score</div>
              <div className="text-2xl font-bold font-mono" style={{ color: exposureColor }}>{exposure}%</div>
            </div>
            <div className="flex-1 h-3 rounded-full bg-white/10 overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-300"
                style={{ width: `${exposure}%`, backgroundColor: exposureColor }}
              />
            </div>
          </div>

          {/* Sliders */}
          <div className="grid grid-cols-2 gap-3">
            {SLIDER_FIELDS.map(({ key, label, min, max, step, unit, dangerous }) => {
              const raw = config[key] as number ?? min;
              const display = unit === "%" ? `${(raw * 100).toFixed(0)}%` : raw;
              return (
                <div key={key} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <label className={`text-[11px] ${dangerous ? "text-orange-400" : "text-gray-400"}`}>{label}</label>
                    <span className={`text-[11px] font-mono ${dangerous && raw > min ? "text-orange-300" : "text-gray-300"}`}>
                      {display}
                    </span>
                  </div>
                  <input
                    type="range"
                    min={min}
                    max={max}
                    step={step}
                    value={raw}
                    onChange={(e) => setConfig(prev => ({ ...prev, [key]: parseFloat(e.target.value) }))}
                    className="w-full h-1 rounded-full appearance-none bg-white/10 accent-blue-500"
                  />
                </div>
              );
            })}
          </div>

          {/* Generate button */}
          <button
            disabled={isRunning}
            onClick={() => onCustomGenerate(config)}
            className="w-full py-3 rounded-xl font-bold text-sm bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isRunning ? "Running..." : "Generate & Run All Modules"}
          </button>
        </div>
      )}
    </div>
  );
}
