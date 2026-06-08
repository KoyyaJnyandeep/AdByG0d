"use client";
import { useMemo } from "react";
import type { FusionResult, SeverityLevel } from "../lib/types";
import { SEVERITY_COLORS } from "../lib/types";

interface HeatMapProps {
  modules: Array<{ id: string; name: string }>;
  results: Record<string, FusionResult>;
  onCellClick?: (moduleId: string, severity: SeverityLevel) => void;
}

const SEVERITIES: SeverityLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function riskToHeatColor(score: number): string {
  if (score === 0) return "rgba(255,255,255,0.03)";
  if (score >= 8) return "rgba(239,68,68,0.35)";
  if (score >= 6) return "rgba(249,115,22,0.30)";
  if (score >= 4) return "rgba(234,179,8,0.25)";
  if (score >= 2) return "rgba(34,197,94,0.20)";
  return "rgba(107,114,128,0.15)";
}

export default function HeatMap({ modules, results, onCellClick }: HeatMapProps) {
  const cellData = useMemo(() => {
    const data: Record<string, Record<SeverityLevel, { count: number; score: number }>> = {};
    for (const mod of modules) {
      data[mod.id] = {} as Record<SeverityLevel, { count: number; score: number }>;
      for (const sev of SEVERITIES) {
        data[mod.id][sev] = { count: 0, score: 0 };
      }
      const result = results[mod.id];
      if (result) {
        const sev = result.severity_projection as SeverityLevel;
        if (sev && data[mod.id][sev]) {
          data[mod.id][sev].count = result.support_count || 1;
          data[mod.id][sev].score = result.risk_score;
        }
      }
    }
    return data;
  }, [modules, results]);

  const totals = useMemo(() => {
    const t: Record<SeverityLevel, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const sev of SEVERITIES) {
      t[sev] = modules.filter((m) => results[m.id]?.severity_projection === sev).length;
    }
    return t;
  }, [modules, results]);

  if (modules.length === 0) {
    return <div className="text-center py-8 text-gray-600 text-sm">No modules loaded.</div>;
  }

  return (
    <div className="overflow-x-auto">
      <div className="min-w-[640px]">
        <h3 className="text-base font-bold text-white mb-4">Module × Severity Heat Map</h3>
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th className="text-left text-xs text-gray-500 font-semibold pb-2 pr-3 w-40">MODULE</th>
              {SEVERITIES.map((sev) => (
                <th key={sev} className="text-center text-[10px] font-bold pb-2 px-1" style={{ color: SEVERITY_COLORS[sev] }}>
                  {sev}
                </th>
              ))}
              <th className="text-center text-xs text-gray-500 font-semibold pb-2 px-1">RISK</th>
            </tr>
          </thead>
          <tbody>
            {modules.map((mod) => {
              const result = results[mod.id];
              const rowScore = result?.risk_score ?? 0;
              const trend = rowScore > 5 ? "↑" : rowScore > 2 ? "→" : "↓";
              const trendColor = rowScore > 5 ? "#ef4444" : rowScore > 2 ? "#eab308" : "#22c55e";
              return (
                <tr key={mod.id} className="border-t border-white/5">
                  <td className="text-xs text-gray-300 py-2 pr-3 truncate max-w-[150px]">{mod.name}</td>
                  {SEVERITIES.map((sev) => {
                    const cell = cellData[mod.id]?.[sev];
                    const bg = riskToHeatColor(cell?.score ?? 0);
                    return (
                      <td
                        key={sev}
                        className="py-1 px-1 text-center cursor-pointer"
                        onClick={() => cell?.count ? onCellClick?.(mod.id, sev) : undefined}
                      >
                        <div
                          className="rounded w-full h-8 flex items-center justify-center transition-all hover:scale-105"
                          style={{ backgroundColor: bg }}
                        >
                          {cell?.count ? (
                            <span className="text-xs font-bold text-white">{cell.count}</span>
                          ) : (
                            <span className="text-[10px] text-gray-700">-</span>
                          )}
                        </div>
                      </td>
                    );
                  })}
                  <td className="text-center py-1 px-1">
                    <span className="text-sm font-bold font-mono" style={{ color: trendColor }}>
                      {rowScore.toFixed(1)} {trend}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
          <tfoot>
            <tr className="border-t border-white/10">
              <td className="text-xs text-gray-500 pt-2 pr-3">TOTALS</td>
              {SEVERITIES.map((sev) => (
                <td key={sev} className="text-center pt-2 px-1">
                  <span className="text-sm font-bold" style={{ color: totals[sev] > 0 ? SEVERITY_COLORS[sev] : "#374151" }}>
                    {totals[sev]}
                  </span>
                </td>
              ))}
              <td />
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  );
}
