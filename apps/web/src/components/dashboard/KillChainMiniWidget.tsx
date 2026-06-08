'use client'

import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { Link2, ArrowRight } from 'lucide-react'
import { killChainApi, PHASE_STATUS_COLORS } from '@/lib/killChainApi'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }
const PHASE_SHORT = ['Recon', 'Init', 'Enum', 'PrivEsc', 'LatMov', 'Creds', 'Persist', 'Cloud', 'Adv']

export function KillChainMiniWidget({ assessmentId }: { assessmentId?: string }) {
  const { data } = useQuery({
    queryKey: ['kill-chain-mini', assessmentId],
    queryFn: () => killChainApi.get(assessmentId),
    refetchInterval: 60_000,
  })

  const phases = data?.phases || []
  const completedCount = phases.filter(p => p.status === 'complete').length
  const overallPct = phases.length ? Math.round(phases.reduce((a, p) => a + p.completion_pct, 0) / phases.length) : 0
  const displayPhases = phases.length ? phases : PHASE_SHORT.map((l, i) => ({
    phase_id: i, label: l, status: 'not_started' as const, completion_pct: 0, techniques_run: [], findings_count: 0,
  }))

  return (
    <div className="p-4 rounded-2xl border h-full flex flex-col gap-3"
      style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.07)' }}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Link2 className="h-4 w-4" style={{ color: '#818cf8' }} />
          <span className="text-sm font-bold text-slate-200" style={MONO}>Kill Chain</span>
        </div>
        <Link href="/kill-chain" className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-300 transition-colors" style={MONO}>
          <span>{overallPct}%</span>
          <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
      <div className="flex gap-1 flex-wrap">
        {displayPhases.map(phase => {
          const c = PHASE_STATUS_COLORS[phase.status]
          return (
            <div key={phase.phase_id} className="h-7 rounded px-1.5 flex items-center"
              style={{ background: c.bg, border: `1px solid ${c.border}55`, minWidth: 28 }}>
              <span className="text-[9px] font-bold" style={{ ...MONO, color: c.text }}>
                {PHASE_SHORT[phase.phase_id] || phase.label.slice(0, 4)}
              </span>
            </div>
          )
        })}
      </div>
      <div className="flex items-center justify-between text-[10px] text-slate-500" style={MONO}>
        <span>{completedCount}/9 complete</span>
        {data?.suggestions?.[0] && (
          <span className="text-purple-400 truncate max-w-[160px]">→ {data.suggestions[0].title.slice(0, 28)}...</span>
        )}
      </div>
    </div>
  )
}
