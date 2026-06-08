"use client";

import { Clipboard, ShieldCheck } from "lucide-react";
import type { FusionResult } from "../lib/types";
import { SEVERITY_COLORS } from "../lib/types";

interface PlaybookPanelProps {
  result: FusionResult | null;
}

export default function PlaybookPanel({ result }: PlaybookPanelProps) {
  const steps = result?.remediation_playbook ?? [];
  const impact = result?.remediation_impact ?? {};

  if (steps.length === 0) {
    return (
      <div className="text-center py-16 text-gray-600 text-sm">
        Run a module to generate a remediation playbook.
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-bold text-white">Remediation Playbook</h2>
        <span className="text-xs text-gray-500">{steps.length} step{steps.length === 1 ? "" : "s"}</span>
      </div>

      {steps.map((step) => {
        const color = SEVERITY_COLORS[step.priority] ?? "#6b7280";
        const impactValue = impact[step.title];

        return (
          <section key={`${step.step_index}-${step.title}`} className="rounded-lg border border-white/10 bg-white/[0.04] p-4">
            <div className="flex items-start gap-3">
              <div
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-bold"
                style={{ backgroundColor: `${color}22`, color }}
              >
                {step.step_index + 1}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-sm font-semibold text-white">{step.title}</h3>
                  <span className="rounded border px-1.5 py-0.5 text-[10px] font-bold" style={{ borderColor: `${color}55`, color }}>
                    {step.priority}
                  </span>
                  {typeof impactValue === "number" && (
                    <span className="rounded border border-green-700/30 bg-green-950/20 px-1.5 py-0.5 text-[10px] font-semibold text-green-400">
                      {impactValue.toFixed(0)}% path reduction
                    </span>
                  )}
                </div>
                {step.description && <p className="mt-1 text-xs leading-5 text-gray-400">{step.description}</p>}
              </div>
            </div>

            {step.applies_to.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1">
                {step.applies_to.map((entity) => (
                  <span key={entity} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-gray-400">
                    {entity}
                  </span>
                ))}
              </div>
            )}

            {step.commands.length > 0 && (
              <div className="mt-3 flex flex-col gap-1.5">
                {step.commands.map((command, index) => (
                  <div key={`${command}-${index}`} className="flex items-start gap-2 rounded border border-white/10 bg-black/40 px-3 py-2">
                    <Clipboard className="mt-0.5 h-3.5 w-3.5 shrink-0 text-gray-500" />
                    <code className="min-w-0 break-words font-mono text-xs text-green-400">{command}</code>
                  </div>
                ))}
              </div>
            )}

            {step.verification_command && (
              <div className="mt-2 flex items-start gap-2 rounded border border-blue-700/20 bg-blue-950/10 px-3 py-2">
                <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-blue-400" />
                <code className="min-w-0 break-words font-mono text-xs text-blue-300">{step.verification_command}</code>
              </div>
            )}

            {step.mitre_mitigates.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1">
                {step.mitre_mitigates.map((technique) => (
                  <span key={technique} className="rounded border border-purple-700/20 bg-purple-950/20 px-1.5 py-0.5 font-mono text-[10px] text-purple-300">
                    {technique}
                  </span>
                ))}
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}
