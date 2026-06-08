'use client'

import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { Target, Loader2, CheckCircle2, XCircle } from 'lucide-react'
import { connectivityApi, type ConnectivityProfile, type ConnectivityTestResult, type ProbeHistoryEntry } from '@/lib/connectivityApi'
import { fmtTime } from '@/lib/utils'
import { ALL_AD_PORTS, AD_PORT_LABELS } from './shared'

type StoredProbe = {
  status?: ConnectivityTestResult['status']
  probes?: ConnectivityTestResult['details']
  capabilities?: ConnectivityTestResult['capabilities']
  readiness_pct?: number
  open_ports?: number[]
}

const CAPABILITIES_ORDERED = [
  'ldap_collection', 'ldaps_collection', 'kerberoast', 'asreproast',
  'dcsync', 'secretsdump', 'lateral_movement', 'winrm', 'winrm_ssl',
  'global_catalog', 'global_catalog_ssl', 'dns_resolution',
]

export function ProbeTab({
  profile,
  onProbed,
}: {
  profile: ConnectivityProfile
  onProbed?: () => void
}) {
  const cfg = profile.config as Record<string, unknown>
  const defaultTarget =
    typeof cfg.dc_ip === 'string' ? cfg.dc_ip :
    typeof cfg.dc_hostname === 'string' ? cfg.dc_hostname : ''
  const [target, setTarget] = useState(defaultTarget)
  const [result, setResult] = useState<ConnectivityTestResult | null>(() => {
    const lp = cfg.last_probe as StoredProbe | undefined
    if (!lp) return null
    return {
      profile_id: profile.id,
      success: lp.status === 'ONLINE',
      status: lp.status ?? 'UNKNOWN',
      latency_ms: profile.last_latency_ms,
      error: null,
      details: lp.probes ?? {},
      capabilities: lp.capabilities ?? {},
      readiness_pct: lp.readiness_pct ?? 0,
      open_ports: lp.open_ports ?? [],
    }
  })

  const history = (cfg.probe_history as ProbeHistoryEntry[]) ?? []

  const probeMut = useMutation({
    mutationFn: () => connectivityApi.testProfile(profile.id, target),
    onSuccess: (r) => { setResult(r); onProbed?.() },
  })

  const openSet = new Set(result?.open_ports ?? [])
  const probing = probeMut.isPending

  return (
    <div className="space-y-4">
      {/* Target input + probe button */}
      <div className="flex gap-2">
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && target && probeMut.mutate()}
          placeholder={defaultTarget || 'DC IP or hostname'}
          className="flex-1 bg-black/60 border border-cyan-500/20 rounded-xl px-4 py-2.5 font-mono text-sm text-white/80 placeholder-white/15 focus:outline-none focus:border-cyan-400/40 focus:shadow-[0_0_10px_rgba(6,182,212,0.08)]"
        />
        <motion.button
          whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
          onClick={() => probeMut.mutate()}
          disabled={!target || probing}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl border font-mono font-bold text-sm disabled:opacity-40 transition-all"
          style={{ background: '#22d3ee12', borderColor: '#22d3ee35', color: '#22d3ee' }}
        >
          {probing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Target className="w-4 h-4" />}
          {probing ? 'PROBING…' : 'PROBE'}
        </motion.button>
      </div>

      {/* Probing animation */}
      {probing && (
        <div className="flex justify-center py-6">
          <div className="relative w-16 h-16">
            {[0, 1, 2].map(i => (
              <motion.div
                key={i}
                className="absolute inset-0 rounded-full border border-cyan-400/30"
                animate={{ scale: [1, 2.5], opacity: [0.5, 0] }}
                transition={{ repeat: Infinity, duration: 1.5, delay: i * 0.5 }}
              />
            ))}
            <div className="absolute inset-0 flex items-center justify-center">
              <Target className="w-6 h-6 text-cyan-400" />
            </div>
          </div>
        </div>
      )}

      <AnimatePresence>
        {result && !probing && (
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">

            {/* Summary banner */}
            <div
              className="flex items-center gap-3 p-3 rounded-xl border"
              style={{
                borderColor: result.success ? '#34d39930' : '#f4717130',
                background: result.success ? '#34d39908' : '#f4717108',
              }}
            >
              {result.success
                ? <CheckCircle2 className="w-5 h-5 text-emerald-400 flex-shrink-0" />
                : <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
              }
              <div className="flex-1">
                <div className="font-mono font-bold text-sm" style={{ color: result.success ? '#34d399' : '#f87171' }}>
                  {result.success ? `LDAP READY — ${profile.mode}` : `${result.status} — ${profile.mode}`}
                </div>
                {result.latency_ms != null && (
                  <div className="text-[10px] font-mono text-white/30">Latency: {result.latency_ms}ms</div>
                )}
                {result.error && <div className="text-[10px] font-mono text-red-400/60 mt-0.5">{result.error}</div>}
              </div>
              <div
                className="text-right flex-shrink-0 px-3 py-1.5 rounded-lg border"
                style={{ borderColor: '#34d39930', background: '#34d39910' }}
              >
                <div className="text-lg font-black font-mono text-emerald-400">{result.readiness_pct}%</div>
                <div className="text-[7px] font-mono text-emerald-400/50 tracking-wider">READY</div>
              </div>
            </div>

            {/* Readiness bar */}
            <div>
              <div className="flex justify-between text-[8px] font-mono text-white/30 mb-1 tracking-widest">
                <span>AD ATTACK READINESS</span>
                <span style={{ color: '#34d399' }}>{result.readiness_pct}% · {result.open_ports.length}/10 PORTS OPEN</span>
              </div>
              <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                <motion.div
                  className="h-full rounded-full"
                  style={{ background: 'linear-gradient(90deg, #22d3ee, #34d399)' }}
                  initial={{ width: 0 }}
                  animate={{ width: `${result.readiness_pct}%` }}
                  transition={{ duration: 0.6 }}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {/* Port matrix */}
              <div>
                <div className="text-[8px] font-mono text-white/25 tracking-widest uppercase mb-2">ALL 10 AD PORTS</div>
                <div className="grid grid-cols-2 gap-1.5">
                  {ALL_AD_PORTS.map(port => {
                    const open = openSet.has(port)
                    const portMeta = AD_PORT_LABELS[port]
                    const serviceKey = portMeta?.name?.toLowerCase() ?? ''
                    const detail = result.details[serviceKey] as { latency_ms?: number } | undefined
                    return (
                      <div
                        key={port}
                        className="rounded-lg px-2 py-1.5 text-center"
                        style={{
                          background: open ? '#34d39908' : '#f4717106',
                          border: `1px solid ${open ? '#34d39930' : '#f4717118'}`,
                        }}
                      >
                        <div className="font-mono font-bold text-[8px]" style={{ color: open ? '#34d399' : '#f87171' }}>
                          {portMeta?.abbr ?? String(port)}
                        </div>
                        <div className="font-mono text-[7px] text-white/20">:{port}</div>
                        <div className="font-mono font-bold text-[8px]" style={{ color: open ? '#34d39980' : '#f8717160' }}>
                          {open ? `${detail?.latency_ms ?? '?'}ms` : 'CLOSED'}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Capability matrix */}
              <div>
                <div className="text-[8px] font-mono text-white/25 tracking-widest uppercase mb-2">ATTACK CAPABILITIES</div>
                <div className="space-y-1">
                  {CAPABILITIES_ORDERED.map(cap => {
                    const available = result.capabilities[cap]
                    return (
                      <div
                        key={cap}
                        className="flex items-center gap-2 px-2 py-1 rounded text-[8px] font-mono"
                        style={{
                          background: available ? '#34d39910' : '#ffffff04',
                          border: `1px solid ${available ? '#34d39925' : '#ffffff08'}`,
                          color: available ? '#34d39990' : '#ffffff25',
                        }}
                      >
                        <span>{available ? '✓' : '✗'}</span>
                        <span>{cap.replace(/_/g, ' ').toUpperCase()}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>

          </motion.div>
        )}
      </AnimatePresence>

      {/* Probe history */}
      {history.length > 0 && (
        <div>
          <div className="text-[8px] font-mono text-white/25 tracking-widest uppercase mb-2">PROBE HISTORY</div>
          <div className="space-y-1">
            {history.slice(0, 10).map((h, i) => {
              const color = h.status === 'ONLINE' ? '#34d399' : h.status === 'DEGRADED' ? '#f59e0b' : '#f87171'
              const maxLat = 200
              const barPct = h.latency_ms != null ? Math.min(100, (h.latency_ms / maxLat) * 100) : 0
              return (
                <div key={i} className="flex items-center gap-3">
                  <div className="font-mono text-[8px] text-white/20 w-[90px] flex-shrink-0">
                    {fmtTime(h.tested_at)}
                  </div>
                  <div className="font-mono font-bold text-[8px] w-[55px] flex-shrink-0" style={{ color }}>{h.status}</div>
                  <div className="font-mono text-[8px] w-[35px] text-right flex-shrink-0" style={{ color }}>
                    {h.latency_ms != null ? `${h.latency_ms}ms` : '—'}
                  </div>
                  <div className="flex-1 h-[3px] bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${barPct}%`, background: color, opacity: 0.6 }} />
                  </div>
                  <div className="font-mono text-[8px] text-white/20 flex-shrink-0">
                    {h.open_ports.length}/10
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
