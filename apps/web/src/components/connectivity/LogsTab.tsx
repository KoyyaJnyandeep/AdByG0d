'use client'

import { useState, useRef, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Terminal, RefreshCw } from 'lucide-react'
import { connectivityApi, type ConnectivityProfile } from '@/lib/connectivityApi'

const LEVEL_COLORS: Record<string, string> = {
  ERROR: '#f87171', FAIL: '#f87171', WARN: '#f59e0b', WARNING: '#f59e0b',
  INFO: '#22d3ee80', OK: '#34d399', CONNECT: '#34d399', START: '#34d399',
}

function colorLine(line: string): string {
  const upper = line.toUpperCase()
  for (const [kw, color] of Object.entries(LEVEL_COLORS)) {
    if (upper.includes(kw)) return color
  }
  return 'rgba(255,255,255,0.35)'
}

export function LogsTab({ profile }: { profile: ConnectivityProfile }) {
  const mode = profile.mode
  const [filter, setFilter] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  const enabled = mode === 'CHISEL' || mode === 'LIGOLO' || mode === 'MANAGED_SSH_SOCKS'

  const logsQ = useQuery({
    queryKey: ['logs', mode, profile.id],
    queryFn: () => {
      if (mode === 'CHISEL') return connectivityApi.chiselLogs(profile.id)
      if (mode === 'LIGOLO') return connectivityApi.ligoloLogs(profile.id)
      return connectivityApi.tunnelLogs(profile.id)
    },
    enabled,
    refetchInterval: 3000,
  })

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logsQ.data])

  const lines = logsQ.data?.lines ?? []
  const filtered = filter
    ? lines.filter(l => l.toLowerCase().includes(filter.toLowerCase()))
    : lines

  if (!enabled) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-center">
        <Terminal className="w-8 h-8 text-white/10 mb-3" />
        <p className="font-mono text-xs text-white/20">No logs available for {mode} profiles.</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-2 items-center">
        <input
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="filter logs…"
          className="flex-1 bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 font-mono text-xs text-white/60 placeholder-white/15 focus:outline-none focus:border-cyan-400/30"
        />
        <button
          onClick={() => logsQ.refetch()}
          className="p-1.5 rounded-lg border border-white/10 text-white/30 hover:text-white/60 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${logsQ.isFetching ? 'animate-spin' : ''}`} />
        </button>
        <span className="font-mono text-[9px] text-white/20">{filtered.length} lines</span>
      </div>

      <div
        className="rounded-xl border border-white/5 p-3 font-mono text-[10px] leading-relaxed overflow-y-auto"
        style={{ background: '#030308', maxHeight: '280px' }}
      >
        {filtered.length === 0 ? (
          <span className="text-white/20">No log output yet. Start the tunnel to see logs.</span>
        ) : (
          filtered.map((line, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-white/15 flex-shrink-0 select-none">{String(i + 1).padStart(3, ' ')}</span>
              <span style={{ color: colorLine(line) }}>{line}</span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
