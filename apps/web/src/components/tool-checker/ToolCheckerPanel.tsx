'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Wrench, CheckCircle2, XCircle, RefreshCw, Terminal, Search } from 'lucide-react'
import { toolCheckerApi, type ToolResult } from '@/lib/toolCheckerApi'
import { cn } from '@/lib/utils'
import { BackButton } from '@/components/ui/BackButton'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const PHASE_LABELS: Record<number, string> = {
  0: 'Recon', 1: 'Access', 2: 'Enum', 3: 'PrivEsc',
  4: 'Lateral', 5: 'Persist', 6: 'Loot', 7: 'Evasion',
}

const PHASE_COLORS: Record<number, string> = {
  0: '#60a5fa', 1: '#f97316', 2: '#fbbf24', 3: '#fb923c',
  4: '#a78bfa', 5: '#34d399', 6: '#22d3ee', 7: '#f472b6',
}

function ToolCard({ tool }: { tool: ToolResult }) {
  return (
    <div className={cn(
      'rounded-xl border p-4 transition-all',
      tool.available ? 'border-green-500/20 bg-green-500/5' : 'border-white/5 bg-white/[0.02]'
    )}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            {tool.available
              ? <CheckCircle2 className="h-3.5 w-3.5 text-green-400 flex-shrink-0" />
              : <XCircle className="h-3.5 w-3.5 text-zinc-600 flex-shrink-0" />
            }
            <span className="text-sm font-semibold text-zinc-200" style={MONO}>{tool.tool_name}</span>
          </div>
          {tool.available && tool.version && (
            <div className="mt-1 ml-5 text-[10px] text-zinc-500" style={MONO}>{tool.version}</div>
          )}
          {!tool.available && (
            <div className="mt-2 ml-5 flex items-center gap-1.5">
              <Terminal className="h-2.5 w-2.5 text-zinc-600 flex-shrink-0" />
              <span className="text-[10px] text-zinc-600 break-all" style={MONO}>{tool.install_cmd}</span>
            </div>
          )}
        </div>
        <div className="flex flex-wrap gap-1 justify-end max-w-[140px]">
          {tool.phases.map(p => (
            <span
              key={p}
              className="rounded px-1.5 py-0.5 text-[9px] font-bold uppercase whitespace-nowrap"
              style={{ color: PHASE_COLORS[p] ?? '#64748b', background: `${PHASE_COLORS[p] ?? '#64748b'}18` }}
            >
              P{p} {PHASE_LABELS[p] ?? ''}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

export function ToolCheckerPanel() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [filterPhase, setFilterPhase] = useState<number | null>(null)
  const [filterAvailable, setFilterAvailable] = useState<boolean | null>(null)
  const [scanning, setScanning] = useState(false)

  const { data: results = [], isLoading } = useQuery({
    queryKey: ['tool-checker-results'],
    queryFn: toolCheckerApi.results,
    refetchInterval: scanning ? 3000 : false,
  })

  useEffect(() => {
    if (scanning && results.length > 0) {
      setScanning(false)
    }
  }, [scanning, results.length])

  const scanMut = useMutation({
    mutationFn: toolCheckerApi.scan,
    onSuccess: () => {
      setScanning(true)
      qc.invalidateQueries({ queryKey: ['tool-checker-results'] })
    },
  })

  const filtered = results.filter(t => {
    if (search && !t.tool_name.toLowerCase().includes(search.toLowerCase())) return false
    if (filterPhase !== null && !t.phases.includes(filterPhase)) return false
    if (filterAvailable !== null && t.available !== filterAvailable) return false
    return true
  })

  const available = results.filter(t => t.available).length
  const total = results.length

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <BackButton />
          <h1 className="text-2xl font-bold text-white">Tool Checker</h1>
          <p className="text-sm text-zinc-500 mt-1">
            {total > 0 ? (
              <><span className="text-green-400 font-semibold">{available}</span> / {total} tools available</>
            ) : 'Run a scan to check tool availability'}
          </p>
        </div>
        <button
          onClick={() => scanMut.mutate()}
          disabled={scanMut.isPending}
          className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-zinc-300 hover:border-cyan-500/30 hover:text-cyan-300 transition-all disabled:opacity-50"
        >
          <RefreshCw className={cn('h-3.5 w-3.5', scanMut.isPending && 'animate-spin')} />
          {scanMut.isPending ? 'Scanning…' : 'Run Scan'}
        </button>
      </div>

      {scanning && (
        <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-sm text-cyan-300">
          Scan running — probing tools in background. Results will appear automatically (may take 30–120s).
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter tools…"
            className="w-full rounded-xl border border-white/10 bg-white/[0.03] py-2.5 pl-9 pr-4 text-sm text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-white/20"
          />
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setFilterAvailable(filterAvailable === true ? null : true)}
            className={cn('rounded-xl border px-3 py-2 text-[11px] font-semibold transition-all', filterAvailable === true ? 'border-green-500/40 bg-green-500/15 text-green-400' : 'border-white/10 text-zinc-600 hover:border-white/20')}
          >Available</button>
          <button
            onClick={() => setFilterAvailable(filterAvailable === false ? null : false)}
            className={cn('rounded-xl border px-3 py-2 text-[11px] font-semibold transition-all', filterAvailable === false ? 'border-red-500/40 bg-red-500/15 text-red-400' : 'border-white/10 text-zinc-600 hover:border-white/20')}
          >Missing</button>
        </div>
        <div className="flex flex-wrap gap-1">
          {Object.entries(PHASE_LABELS).map(([p, label]) => (
            <button
              key={p}
              onClick={() => setFilterPhase(filterPhase === Number(p) ? null : Number(p))}
              className="rounded-full border px-2.5 py-1 text-[9px] font-bold uppercase transition-all"
              style={{
                color: filterPhase === Number(p) ? '#000' : PHASE_COLORS[Number(p)],
                borderColor: `${PHASE_COLORS[Number(p)]}50`,
                background: filterPhase === Number(p) ? PHASE_COLORS[Number(p)] : `${PHASE_COLORS[Number(p)]}10`,
              }}
            >P{p} {label}</button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-zinc-600 text-sm">Loading…</div>
      ) : filtered.length === 0 && total === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 gap-3">
          <Wrench className="h-10 w-10 text-zinc-700" />
          <p className="text-sm text-zinc-600">No scan results yet. Click &quot;Run Scan&quot; to start.</p>
        </div>
      ) : (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map(tool => <ToolCard key={tool.tool_name} tool={tool} />)}
        </motion.div>
      )}
    </div>
  )
}
