"use client";
import type { ValidationModule, FusionResult } from "../lib/types";
import ModuleCard from "./ModuleCard";

interface ModuleGridProps {
  modules: ValidationModule[];
  results: Record<string, FusionResult>;
  activeModuleId: string | null;
  runningModuleId: string | null;
  onSelectModule: (moduleId: string) => void;
}

const CATEGORY_ORDER = [
  "initial_access", "credential_access", "lateral_movement",
  "privilege_escalation", "persistence", "defense_evasion",
];

export default function ModuleGrid({
  modules, results, activeModuleId, runningModuleId, onSelectModule,
}: ModuleGridProps) {
  const sortedModules = [...modules].sort((a, b) => {
    const leftIndex = CATEGORY_ORDER.indexOf(a.risk_category);
    const rightIndex = CATEGORY_ORDER.indexOf(b.risk_category);
    return (leftIndex === -1 ? 99 : leftIndex) - (rightIndex === -1 ? 99 : rightIndex);
  });

  const totalRisk = modules.reduce((sum, m) => sum + (results[m.id]?.risk_score ?? 0), 0);
  const avgRisk = modules.length > 0 ? totalRisk / modules.length : 0;
  const runCount = Object.keys(results).length;
  const criticalCount = Object.values(results).filter(r => r.final_verdict === "LIKELY_EXPOSED").length;

  return (
    <div className="flex flex-col gap-4">
      {/* Summary bar */}
      <div className="grid grid-cols-3 gap-3 p-3 rounded-xl bg-white/5 border border-white/10">
        <div className="text-center">
          <div className="text-xl font-bold text-white">{runCount}/{modules.length}</div>
          <div className="text-[10px] text-gray-500">Modules Run</div>
        </div>
        <div className="text-center">
          <div className="text-xl font-bold" style={{ color: avgRisk > 7 ? "#ef4444" : avgRisk > 4 ? "#f97316" : "#22c55e" }}>
            {avgRisk.toFixed(1)}
          </div>
          <div className="text-[10px] text-gray-500">Avg Risk</div>
        </div>
        <div className="text-center">
          <div className="text-xl font-bold text-red-400">{criticalCount}</div>
          <div className="text-[10px] text-gray-500">LIKELY EXPOSED</div>
        </div>
      </div>

      {/* Module grid */}
      <div className="grid grid-cols-1 gap-2">
        {sortedModules.map((module) => (
          <ModuleCard
            key={module.id}
            module={module}
            lastResult={results[module.id] ?? null}
            isSelected={activeModuleId === module.id}
            isRunning={runningModuleId === module.id}
            onClick={() => onSelectModule(module.id)}
          />
        ))}
      </div>
    </div>
  );
}
