'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { Link2, Zap, ArrowRight } from 'lucide-react'
import { killChainApi, PHASE_STATUS_COLORS, type KillChainPhase, type KillChainSuggestion } from '@/lib/killChainApi'
import { BackButton } from '@/components/ui/BackButton'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const PHASE_ICONS: Record<number, string> = {
  0: '🔍', 1: '⚡', 2: '📋', 3: '🔼', 4: '↔️', 5: '🔑', 6: '🪝', 7: '☁️', 8: '🔬',
}

function PhaseBar({ phase, selected, onClick }: { phase: KillChainPhase; selected: boolean; onClick: () => void }) {
  const c = PHASE_STATUS_COLORS[phase.status]
  return (
    <motion.button onClick={onClick} whileHover={{ y: -2 }}
      className="flex flex-col items-center gap-1.5 p-3 rounded-xl border transition-all min-w-[88px]"
      style={{ background: selected ? c.bg : 'rgba(255,255,255,0.02)', borderColor: selected ? c.border : 'rgba(255,255,255,0.06)' }}>
      <span className="text-xl">{PHASE_ICONS[phase.phase_id]}</span>
      <span className="text-[9px] font-bold text-center leading-tight" style={{ ...MONO, color: c.text }}>{phase.label}</span>
      <div className="w-full h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${phase.completion_pct}%`, background: c.border }} />
      </div>
      <span className="text-[9px]" style={{ color: c.text }}>{phase.completion_pct}%</span>
    </motion.button>
  )
}

function SuggestionCard({ s }: { s: KillChainSuggestion }) {
  return (
    <motion.div initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}
      className="p-3 rounded-xl border flex items-start gap-3"
      style={{ background: 'rgba(124,58,237,0.06)', borderColor: '#7c3aed33' }}>
      <ArrowRight className="h-4 w-4 mt-0.5 flex-shrink-0" style={{ color: '#a78bfa' }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-0.5">
          <span className="text-[10px] px-1.5 py-0.5 rounded font-bold"
            style={{ ...MONO, background: 'rgba(124,58,237,0.2)', color: '#a78bfa', border: '1px solid #7c3aed55' }}>
            {s.mitre_id}
          </span>
          <span className="text-[10px] text-slate-500" style={MONO}>Phase {s.phase_id}</span>
        </div>
        <p className="text-sm font-medium text-slate-200" style={MONO}>{s.title}</p>
        <p className="text-xs text-slate-400 mt-0.5">{s.reason}</p>
      </div>
    </motion.div>
  )
}

function PhaseDetail({ phase }: { phase: KillChainPhase }) {
  const c = PHASE_STATUS_COLORS[phase.status]
  return (
    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }}
      className="p-4 rounded-xl border mt-2"
      style={{ background: 'rgba(255,255,255,0.02)', borderColor: 'rgba(255,255,255,0.06)' }}>
      <div className="flex items-center gap-3 mb-3">
        <span className="text-2xl">{PHASE_ICONS[phase.phase_id]}</span>
        <div>
          <h3 className="font-bold text-slate-100" style={MONO}>Phase {phase.phase_id}: {phase.label}</h3>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[10px] px-2 py-0.5 rounded font-bold"
              style={{ background: c.bg, color: c.text, border: `1px solid ${c.border}55` }}>
              {c.label}
            </span>
            <span className="text-[10px] text-slate-500" style={MONO}>{phase.techniques_run.length} techniques</span>
            <span className="text-[10px] text-slate-500" style={MONO}>{phase.findings_count} findings</span>
          </div>
        </div>
      </div>
      {phase.techniques_run.length > 0 && (
        <div>
          <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mb-2" style={MONO}>Executed</p>
          <div className="flex flex-wrap gap-1.5">
            {phase.techniques_run.map(t => (
              <span key={t} className="text-[10px] px-2 py-0.5 rounded"
                style={{ ...MONO, background: 'rgba(255,255,255,0.05)', color: '#94a3b8', border: '1px solid rgba(255,255,255,0.08)' }}>
                {t}
              </span>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  )
}

export function KillChainTracker({ assessmentId }: { assessmentId?: string }) {
  const [selectedPhase, setSelectedPhase] = useState<number | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['kill-chain', assessmentId],
    queryFn: () => killChainApi.get(assessmentId),
    refetchInterval: 30_000,
  })

  if (isLoading || !data) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="flex items-center gap-2 text-slate-400" style={MONO}>
          <Link2 className="h-4 w-4 animate-pulse" />
          <span className="text-sm">Loading kill chain...</span>
        </div>
      </div>
    )
  }

  const overallPct = Math.round(data.phases.reduce((a, p) => a + p.completion_pct, 0) / data.phases.length)
  const completedPhases = data.phases.filter(p => p.status === 'complete').length

  return (
    <div className="h-full flex flex-col gap-5 p-4">
      <BackButton />
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg" style={{ background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.3)' }}>
            <Link2 className="h-5 w-5" style={{ color: '#818cf8' }} />
          </div>
          <div>
            <h1 className="text-lg font-bold text-slate-100" style={MONO}>KILL CHAIN TRACKER</h1>
            <p className="text-xs text-slate-400">9-phase AD attack coverage per assessment</p>
          </div>
        </div>
        <div className="flex items-center gap-5">
          <div className="text-right">
            <p className="text-2xl font-bold" style={{ ...MONO, color: '#818cf8' }}>{overallPct}%</p>
            <p className="text-[10px] text-slate-500" style={MONO}>overall</p>
          </div>
          <div className="text-right">
            <p className="text-2xl font-bold" style={{ ...MONO, color: '#39d98a' }}>{completedPhases}/9</p>
            <p className="text-[10px] text-slate-500" style={MONO}>phases</p>
          </div>
        </div>
      </div>

      <div className="flex gap-2 overflow-x-auto pb-2">
        {data.phases.map(phase => (
          <PhaseBar key={phase.phase_id} phase={phase} selected={selectedPhase === phase.phase_id}
            onClick={() => setSelectedPhase(selectedPhase === phase.phase_id ? null : phase.phase_id)} />
        ))}
      </div>

      <AnimatePresence>
        {selectedPhase !== null && data.phases.find(p => p.phase_id === selectedPhase) && (
          <PhaseDetail phase={data.phases.find(p => p.phase_id === selectedPhase)!} />
        )}
      </AnimatePresence>

      {data.suggestions.length > 0 && (
        <div className="flex-1 min-h-0">
          <div className="flex items-center gap-2 mb-3">
            <Zap className="h-4 w-4" style={{ color: '#ffd166' }} />
            <span className="text-sm font-bold text-slate-200" style={MONO}>NEXT SUGGESTED</span>
            <span className="text-xs text-slate-500" style={MONO}>based on current state</span>
          </div>
          <div className="space-y-2 overflow-y-auto max-h-64">
            {data.suggestions.map((s, i) => <SuggestionCard key={i} s={s} />)}
          </div>
        </div>
      )}
    </div>
  )
}
