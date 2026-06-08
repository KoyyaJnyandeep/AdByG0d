'use client'

import { motion } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import { Plus } from 'lucide-react'
import { connectivityApi, type ConnectivityStats } from '@/lib/connectivityApi'

function StatCard({
  value, label, color, barPct, delay,
}: {
  value: string; label: string; color: string; barPct: number; delay: number
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="relative rounded-xl p-3 overflow-hidden"
      style={{ background: '#08081a', border: `1px solid ${color}20` }}
    >
      <div
        className="absolute top-0 right-0 w-12 h-12 rounded-full opacity-[0.06] translate-x-4 -translate-y-4"
        style={{ background: color }}
      />
      <div className="text-xl font-black font-mono relative z-10" style={{ color }}>{value}</div>
      <div className="text-[8px] font-mono tracking-widest uppercase mt-0.5 relative z-10" style={{ color: `${color}50` }}>{label}</div>
      <div className="h-[2px] rounded-full mt-2 relative z-10" style={{ background: `${color}25` }}>
        <motion.div
          className="h-full rounded-full"
          style={{ background: color, opacity: 0.6 }}
          initial={{ width: 0 }}
          animate={{ width: `${barPct}%` }}
          transition={{ delay: delay + 0.2, duration: 0.6 }}
        />
      </div>
    </motion.div>
  )
}

export function StatsRow({ onNew }: { onNew: () => void }) {
  const { data: stats } = useQuery<ConnectivityStats>({
    queryKey: ['connectivity-stats'],
    queryFn: () => connectivityApi.getStats(),
    refetchInterval: 10_000,
  })

  const s = stats
  const onlinePct = s && s.total > 0 ? (s.online / s.total) * 100 : 0
  const bestLat = s?.best_latency_ms != null ? `${s.best_latency_ms}ms` : '—'
  const latPct = s?.best_latency_ms != null ? Math.max(5, 100 - s.best_latency_ms) : 0

  return (
    <div className="grid grid-cols-6 gap-2 mb-3">
      <StatCard value={s ? `${s.online}/${s.total}` : '—'} label="ONLINE" color="#22d3ee" barPct={onlinePct} delay={0} />
      <StatCard value={s ? String(s.active_tunnels) : '—'} label="ACTIVE TUNNELS" color="#a78bfa" barPct={s ? Math.min(100, s.active_tunnels * 33) : 0} delay={0.05} />
      <StatCard value={s?.total_open_ports != null ? String(s.total_open_ports) : '—'} label="OPEN AD PORTS" color="#f472b6" barPct={s ? Math.min(100, (s.total_open_ports / 50) * 100) : 0} delay={0.1} />
      <StatCard value={bestLat} label="BEST LATENCY" color="#f59e0b" barPct={latPct} delay={0.15} />
      <StatCard value={s ? String(s.total) : '—'} label="PROFILES" color="#34d399" barPct={s ? Math.min(100, s.total * 20) : 0} delay={0.2} />
      <motion.button
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.25 }}
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.98 }}
        onClick={onNew}
        className="rounded-xl flex flex-col items-center justify-center gap-1.5 text-cyan-400/60 font-mono font-bold text-[10px] tracking-widest transition-all hover:text-cyan-400 hover:bg-cyan-500/5"
        style={{ background: 'transparent', border: '1px dashed #22d3ee25' }}
      >
        <Plus className="w-4 h-4" />
        NEW PROFILE
      </motion.button>
    </div>
  )
}
