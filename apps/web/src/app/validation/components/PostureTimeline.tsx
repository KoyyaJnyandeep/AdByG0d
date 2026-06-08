"use client";
import { useMemo } from "react";
import { safeDateMs } from "@/lib/utils";

interface PostureTimelineProps {
  runs: Array<{
    run_id: string;
    module_id: string;
    verdict: string;
    risk_score: number;
    created_at: string | null;
  }>;
  assessmentId: string;
}

export default function PostureTimeline({ runs, assessmentId }: PostureTimelineProps) {
  const grouped = useMemo(() => {
    const byModule: Record<string, typeof runs> = {};
    for (const run of runs) {
      byModule[run.module_id] = byModule[run.module_id] ?? [];
      byModule[run.module_id].push(run);
    }
    return byModule;
  }, [runs]);

  const modules = Object.keys(grouped);
  const maxScore = 10;
  const chartWidth = 600;
  const chartHeight = 200;
  const padL = 40;
  const padB = 30;
  const padT = 20;

  const moduleColors = [
    "#ef4444", "#f97316", "#eab308", "#22c55e", "#60a5fa",
    "#a78bfa", "#ec4899", "#14b8a6", "#f59e0b", "#84cc16",
    "#06b6d4", "#8b5cf6", "#fb923c",
  ];

  if (runs.length === 0) {
    return (
      <div className="flex flex-col gap-4 p-4 rounded-xl bg-white/5 border border-white/10">
        <h3 className="text-base font-bold text-white">Posture Timeline</h3>
        <div className="text-center py-8 text-gray-600 text-sm">
          No historical runs yet. Run validation modules to build timeline.
        </div>
      </div>
    );
  }

  // Sort runs by date
  const sorted = [...runs].sort((a, b) => {
    const ta = safeDateMs(a.created_at) ?? 0;
    const tb = safeDateMs(b.created_at) ?? 0;
    return ta - tb;
  });

  const times = sorted.map((r) => safeDateMs(r.created_at) ?? 0);
  const tMin = Math.min(...times);
  const tMax = Math.max(...times) || tMin + 1;
  const tRange = tMax - tMin || 1;

  const innerW = chartWidth - padL;
  const innerH = chartHeight - padB - padT;

  const tX = (t: number) => padL + ((t - tMin) / tRange) * innerW;
  const scoreY = (s: number) => padT + (1 - s / maxScore) * innerH;

  return (
    <div className="flex flex-col gap-4 p-4 rounded-xl bg-white/5 border border-white/10">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-bold text-white">Posture Timeline</h3>
        <span className="text-xs text-gray-500">{runs.length} run{runs.length !== 1 ? "s" : ""} · {assessmentId.slice(0, 8)}</span>
      </div>

      {/* SVG Chart */}
      <div className="overflow-x-auto">
        <svg width={chartWidth} height={chartHeight} className="block">
          {/* Y-axis labels */}
          {[0, 2, 4, 6, 8, 10].map((v) => (
            <g key={v}>
              <line x1={padL} y1={scoreY(v)} x2={chartWidth} y2={scoreY(v)} stroke="#ffffff08" strokeWidth="1" />
              <text x={padL - 4} y={scoreY(v) + 4} textAnchor="end" fill="#6b7280" fontSize="9">{v}</text>
            </g>
          ))}

          {/* Per-module lines */}
          {modules.map((mid, mi) => {
            const color = moduleColors[mi % moduleColors.length];
            const pts = grouped[mid]
              .map((r) => {
                const t = safeDateMs(r.created_at) ?? tMin;
                return `${tX(t)},${scoreY(r.risk_score)}`;
              })
              .join(" ");

            return (
              <g key={mid}>
                {grouped[mid].length > 1 && (
                  <polyline
                    points={pts}
                    fill="none"
                    stroke={color}
                    strokeWidth="1.5"
                    strokeOpacity="0.7"
                    strokeLinejoin="round"
                  />
                )}
                {grouped[mid].map((r, i) => {
                  const t = safeDateMs(r.created_at) ?? tMin;
                  return (
                    <circle
                      key={i}
                      cx={tX(t)}
                      cy={scoreY(r.risk_score)}
                      r="3"
                      fill={color}
                      opacity="0.9"
                    />
                  );
                })}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3">
        {modules.slice(0, 8).map((mid, mi) => (
          <div key={mid} className="flex items-center gap-1.5">
            <div className="w-3 h-1.5 rounded-full" style={{ backgroundColor: moduleColors[mi % moduleColors.length] }} />
            <span className="text-[10px] text-gray-400">{mid.replace(/_/g, " ")}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
