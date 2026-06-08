'use client'

import { motion } from 'framer-motion'
import { Trash2, Copy, Search } from 'lucide-react'
import type { ConnectivityProfile } from '@/lib/connectivityApi'
import { MODE_META, STATUS_META, ALL_AD_PORTS } from './shared'

function SparkLine({ history }: { history: Array<{ latency_ms: number | null; status: string }> }) {
  if (!history.length) return (
    <div className="flex items-end gap-[2px] h-[14px] mb-[5px]">
      {[...Array(10)].map((_, i) => (
        <div key={i} className="w-[4px] rounded-[1px] bg-white/[0.06]" style={{ height: '3px' }} />
      ))}
    </div>
  )
  const maxLat = Math.max(...history.map(h => h.latency_ms ?? 0), 1)
  const entries = [...history].reverse().slice(-12)
  return (
    <div className="flex items-end gap-[2px] h-[14px] mb-[5px]">
      {entries.map((h, i) => {
        const color = h.status === 'ONLINE' ? '#34d399' : h.status === 'DEGRADED' ? '#f59e0b' : '#f87171'
        const pct = h.latency_ms != null ? Math.max(20, (h.latency_ms / maxLat) * 100) : 20
        return <div key={i} className="w-[4px] rounded-[1px]" style={{ height: `${pct}%`, background: color, opacity: 0.75 }} />
      })}
    </div>
  )
}

function PortMatrix({ openPorts }: { openPorts: number[] }) {
  const openSet = new Set(openPorts)
  return (
    <div className="grid grid-cols-10 gap-[2px] mb-[5px]">
      {ALL_AD_PORTS.map(port => (
        <div
          key={port}
          className="h-[4px] rounded-[1px]"
          style={{ background: openSet.has(port) ? '#34d399' : openPorts.length > 0 ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.04)' }}
          title={`Port ${port}`}
        />
      ))}
    </div>
  )
}

export function ProfileCard({
  profile, isSelected, delay, onClick, onDelete, onClone, onQuickProbe,
}: {
  profile: ConnectivityProfile
  isSelected: boolean
  delay: number
  onClick: () => void
  onDelete: () => void
  onClone: () => void
  onQuickProbe: () => void
}) {
  const meta = MODE_META[profile.mode] ?? MODE_META.DIRECT
  const st = STATUS_META[profile.status] ?? STATUS_META.UNKNOWN
  const cfg = profile.config as Record<string, unknown>
  const lastProbe = cfg.last_probe as Record<string, unknown> | undefined
  const openPorts = (lastProbe?.open_ports as number[]) ?? []
  const history = (cfg.probe_history as Array<{ latency_ms: number | null; status: string }>) ?? []

  const borderColor = isSelected ? '#22d3ee70' : `${st.color}25`
  const bgColor = isSelected ? '#22d3ee08' : '#08081a'
  const boxShadow = isSelected ? '0 0 24px rgba(34,211,238,0.12)' : undefined

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ delay, duration: 0.3, ease: [0.23, 1, 0.32, 1] }}
      onClick={onClick}
      className="relative rounded-xl p-3 cursor-pointer overflow-hidden group transition-all duration-200"
      style={{ background: bgColor, border: `1px solid ${borderColor}`, boxShadow }}
    >
      {/* Bottom accent bar */}
      <div
        className="absolute bottom-0 left-0 right-0 h-[2px]"
        style={{
          background: `linear-gradient(90deg, transparent, ${st.color}, transparent)`,
          opacity: isSelected ? 0.8 : 0.3,
        }}
      />

      {/* Header row */}
      <div className="flex items-start gap-2 mb-2">
        <div
          className="w-[28px] h-[28px] rounded-lg flex items-center justify-center text-sm flex-shrink-0"
          style={{ background: `${meta.color}15`, border: `1px solid ${meta.color}25` }}
        >
          {meta.icon}
        </div>
        <div className="flex-1 min-w-0">
          <div className="font-mono font-bold text-[10px] text-white/90 truncate">{profile.name}</div>
          <div className="font-mono text-[8px] tracking-wider" style={{ color: `${meta.color}60` }}>{meta.label.toUpperCase()}</div>
        </div>
        {profile.is_default && (
          <span className="text-[7px] font-mono px-1.5 py-0.5 rounded flex-shrink-0" style={{ background: '#a78bfa18', border: '1px solid #a78bfa30', color: '#a78bfa' }}>
            DEFAULT
          </span>
        )}
      </div>

      {/* Status row */}
      <div className="flex items-center gap-2 mb-2">
        <div
          className="w-[6px] h-[6px] rounded-full flex-shrink-0"
          style={{ background: st.color, boxShadow: st.glow ? `0 0 5px ${st.glow}` : undefined }}
        />
        <span className="font-mono font-bold text-[8px] tracking-wider" style={{ color: st.color }}>{st.label}</span>
        {profile.last_latency_ms != null && (
          <span className="font-mono text-[8px] text-white/20 ml-auto">{profile.last_latency_ms}ms</span>
        )}
      </div>

      {/* Sparkline */}
      <SparkLine history={history} />

      {/* Port matrix */}
      <PortMatrix openPorts={openPorts} />

      {/* Footer */}
      <div className="flex items-center justify-between">
        <span className="font-mono text-[7px] text-white/20">
          {openPorts.length > 0 ? `${openPorts.length}/10 ports` : lastProbe ? '0/10 ports' : 'untested'}
        </span>
        <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <button
            onClick={e => { e.stopPropagation(); onQuickProbe() }}
            className="p-1 rounded text-[7px] font-mono font-bold transition-all"
            style={{ background: '#22d3ee10', border: '1px solid #22d3ee25', color: '#22d3ee60' }}
            title="Quick probe"
          >
            <Search className="w-2.5 h-2.5" />
          </button>
          <button
            onClick={e => { e.stopPropagation(); onClone() }}
            className="p-1 rounded transition-all"
            style={{ background: '#a78bfa10', border: '1px solid #a78bfa25', color: '#a78bfa60' }}
            title="Clone profile"
          >
            <Copy className="w-2.5 h-2.5" />
          </button>
          <button
            onClick={e => { e.stopPropagation(); onDelete() }}
            className="p-1 rounded transition-all hover:text-red-400"
            style={{ background: '#f4717110', border: '1px solid #f4717120', color: '#f4717150' }}
            title="Delete"
          >
            <Trash2 className="w-2.5 h-2.5" />
          </button>
        </div>
      </div>
    </motion.div>
  )
}
