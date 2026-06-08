"use client";
import type { BlastRadiusResult } from "../lib/types";

interface BlastRadiusPanelProps {
  blastRadius: BlastRadiusResult;
}

function ConcentricRings({ blast }: { blast: BlastRadiusResult }) {
  const total = blast.total_reachable || 1;
  const rings = [
    { label: "DCs", count: blast.reachable_domain_controllers, color: "#ef4444", r: 20 },
    { label: "Computers", count: blast.reachable_computers, color: "#f97316", r: 32 },
    { label: "Groups", count: blast.reachable_groups, color: "#eab308", r: 44 },
    { label: "Users", count: blast.reachable_users, color: "#60a5fa", r: 56 },
  ];

  return (
    <div className="relative flex items-center justify-center" style={{ width: 130, height: 130 }}>
      {rings.map(({ label, count, color, r }) => {
        if (count === 0) return null;
        const pct = Math.min(count / total, 1);
        const circumference = 2 * Math.PI * r;
        const offset = circumference * (1 - pct);
        return (
          <svg key={label} className="absolute" width={130} height={130} viewBox="0 0 130 130">
            <circle cx={65} cy={65} r={r} fill="none" stroke="#ffffff08" strokeWidth="8" />
            <circle
              cx={65} cy={65} r={r}
              fill="none" stroke={color} strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              transform="rotate(-90 65 65)"
            />
          </svg>
        );
      })}
      <div className="text-center z-10">
        <div className="text-xl font-bold text-white">{blast.total_reachable}</div>
        <div className="text-[9px] text-gray-500">reachable</div>
      </div>
    </div>
  );
}

export default function BlastRadiusPanel({ blastRadius }: BlastRadiusPanelProps) {
  const metrics = [
    { label: "Domain Controllers", value: blastRadius.reachable_domain_controllers, color: "#ef4444" },
    { label: "Computers", value: blastRadius.reachable_computers, color: "#f97316" },
    { label: "Domains", value: blastRadius.reachable_domains, color: "#eab308" },
    { label: "OUs", value: blastRadius.reachable_ous, color: "#a78bfa" },
    { label: "Groups", value: blastRadius.reachable_groups, color: "#34d399" },
    { label: "Users", value: blastRadius.reachable_users, color: "#60a5fa" },
  ];

  return (
    <div className="flex flex-col gap-4 p-4 rounded-xl bg-white/5 border border-white/10">
      <h3 className="text-base font-bold text-white">Blast Radius Analysis</h3>

      {/* Tier-0 warning */}
      {blastRadius.tier0_reachable && (
        <div className="flex items-center gap-2 px-4 py-3 rounded-xl bg-red-950/40 border border-red-700/50 animate-pulse">
          <span className="text-red-400 font-bold text-sm">TIER-0 ASSETS REACHABLE</span>
          <span className="text-xs text-red-300">Domain compromise achievable from this foothold</span>
        </div>
      )}

      {/* Visual + metrics */}
      <div className="flex items-center gap-6">
        <ConcentricRings blast={blastRadius} />
        <div className="flex-1 grid grid-cols-2 gap-2">
          {metrics.map(({ label, value, color }) => (
            <div key={label} className="flex items-center gap-2 p-2 rounded-lg bg-black/20 border border-white/5">
              <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
              <div>
                <div className="text-sm font-bold" style={{ color }}>{value}</div>
                <div className="text-[10px] text-gray-500">{label}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Critical paths */}
      {blastRadius.critical_paths.length > 0 && (
        <div>
          <div className="text-[10px] font-semibold text-gray-500 mb-2">CRITICAL PATHS TO TIER-0</div>
          <div className="flex flex-col gap-1">
            {blastRadius.critical_paths.map((path, i) => (
              <div key={i} className="text-xs font-mono text-red-400 bg-red-950/20 border border-red-700/20 rounded px-2 py-1">
                {path}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
