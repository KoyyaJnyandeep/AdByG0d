'use client'
import { FlaskConical, ArrowRight } from 'lucide-react'

interface SimPath {
  path: string
  technique: string
  hops: number
  success_probability: string
  detection_risk?: string
}

export function SimulationResultCard({
  owned,
  target,
  paths,
  verdict,
}: {
  owned: string[]
  target: string
  paths: SimPath[]
  verdict: string
}) {
  return (
    <div
      className="rounded-xl overflow-hidden my-2"
      style={{ background: 'rgba(251,191,36,0.04)', border: '1px solid rgba(251,191,36,0.18)' }}
    >
      <div
        className="flex items-center gap-2 px-3 py-2 border-b"
        style={{ borderColor: 'rgba(251,191,36,0.12)' }}
      >
        <FlaskConical className="h-3.5 w-3.5 text-yellow-400 shrink-0" />
        <span className="text-[11px] font-bold text-yellow-400">SIMULATION — NO EXECUTION</span>
      </div>
      <div className="px-3 py-2 space-y-2">
        <div className="flex items-center gap-1.5 text-[11px]">
          <span className="text-zinc-500">From:</span>
          <span className="text-zinc-300 font-mono">{owned.join(', ')}</span>
          <ArrowRight className="h-3 w-3 text-zinc-600 shrink-0" />
          <span className="text-yellow-300 font-mono">{target}</span>
        </div>
        <div className="space-y-1">
          {paths.slice(0, 3).map((p, i) => (
            <div
              key={i}
              className="flex items-center gap-2 px-2 py-1.5 rounded-lg text-[11px]"
              style={{ background: 'rgba(0,0,0,0.3)' }}
            >
              <span className="text-zinc-600 shrink-0 font-mono">#{i + 1}</span>
              <span className="text-zinc-300 font-mono flex-1 truncate">{p.technique}</span>
              <span className="text-zinc-500 shrink-0">{p.hops} hop{p.hops !== 1 ? 's' : ''}</span>
              <span
                className="shrink-0 font-semibold"
                style={{ color: p.success_probability === 'HIGH' ? '#34d399' : '#fbbf24' }}
              >
                {p.success_probability}
              </span>
            </div>
          ))}
        </div>
        <p className="text-[11px] text-zinc-400 italic">{verdict}</p>
      </div>
    </div>
  )
}
