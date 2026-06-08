'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { Wifi, WifiOff, Upload, Zap } from 'lucide-react'
import { connectivityApi, type ConnectivityProfile, type ConnectivityMode } from '@/lib/connectivityApi'
import { StatsRow } from './StatsRow'
import { ProfileCard } from './ProfileCard'
import { ModeSelector } from './ModeSelector'
import { ConnectivityDrawer } from './ConnectivityDrawer'
import { DirectConfig } from './DirectConfig'
import { Socks5Config } from './Socks5Config'
import { ChiselConfig } from './ChiselConfig'
import { LigoloConfig } from './LigoloConfig'
import { RelayAgentConfig } from './RelayAgentConfig'
import { ManagedSshConfig } from './ManagedSshConfig'
import { MODE_META } from './shared'

type ModeFilter = ConnectivityMode | 'ALL' | 'OFFLINE'

function NewProfilePanel({ mode, onSaved, onCancel }: { mode: ConnectivityMode; onSaved: (p: ConnectivityProfile) => void; onCancel: () => void }) {
  const props = { profile: null, onSaved, onCancel }
  if (mode === 'DIRECT')            return <DirectConfig {...props} />
  if (mode === 'SOCKS5')            return <Socks5Config {...props} />
  if (mode === 'CHISEL')            return <ChiselConfig {...props} />
  if (mode === 'LIGOLO')            return <LigoloConfig {...props} />
  if (mode === 'RELAY_AGENT')       return <RelayAgentConfig {...props} />
  if (mode === 'MANAGED_SSH_SOCKS') return <ManagedSshConfig {...props} />
  return null
}

export function ConnectivityDashboard() {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<ConnectivityProfile | null>(null)
  const [creating, setCreating] = useState(false)
  const [newMode, setNewMode] = useState<ConnectivityMode | null>(null)
  const [modeFilter, setModeFilter] = useState<ModeFilter>('ALL')
  const [search, setSearch] = useState('')
  const [batchProbing, setBatchProbing] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['connectivity-profiles'],
    queryFn: () => connectivityApi.listProfiles(),
    refetchInterval: 10_000,
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => connectivityApi.deleteProfile(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
      qc.invalidateQueries({ queryKey: ['connectivity-stats'] })
      setSelected(null)
    },
  })

  const cloneMut = useMutation({
    mutationFn: (id: string) => connectivityApi.cloneProfile(id),
    onSuccess: (cloned) => {
      qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
      qc.invalidateQueries({ queryKey: ['connectivity-stats'] })
      setSelected(cloned)
      setCreating(false)
    },
  })

  const filtered = useMemo(() => {
    let list = profiles
    if (modeFilter !== 'ALL') {
      if (modeFilter === 'OFFLINE') {
        list = list.filter(p => p.status === 'OFFLINE')
      } else {
        list = list.filter(p => p.mode === modeFilter)
      }
    }
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(p =>
        p.name.toLowerCase().includes(q) ||
        p.mode.toLowerCase().includes(q) ||
        JSON.stringify(p.config).toLowerCase().includes(q)
      )
    }
    return list
  }, [profiles, modeFilter, search])

  const handleBatchProbe = async () => {
    const testable = profiles.filter(p => {
      const cfg = p.config as Record<string, unknown>
      return cfg.dc_ip || cfg.dc_hostname
    })
    if (!testable.length) return
    setBatchProbing(true)
    try {
      await Promise.allSettled(
        testable.map(p => {
          const cfg = p.config as Record<string, unknown>
          const target = String(cfg.dc_ip || cfg.dc_hostname)
          return connectivityApi.testProfile(p.id, target)
        })
      )
      qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
      qc.invalidateQueries({ queryKey: ['connectivity-stats'] })
    } finally {
      setBatchProbing(false)
    }
  }

  const handleImport = () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.json'
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (!file) return
      try {
        const text = await file.text()
        const data = JSON.parse(text) as Record<string, unknown>
        await connectivityApi.createProfile({
          name: typeof data.name === 'string' ? `${data.name} (imported)` : 'Imported Profile',
          mode: data.mode as ConnectivityMode,
          config: (data.config as Record<string, unknown>) ?? {},
          notes: typeof data.notes === 'string' ? data.notes : undefined,
        })
        qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
        qc.invalidateQueries({ queryKey: ['connectivity-stats'] })
      } catch {
        alert('Invalid profile JSON')
      }
    }
    input.click()
  }

  const FILTER_OPTIONS: Array<{ key: ModeFilter; label: string }> = [
    { key: 'ALL', label: `ALL (${profiles.length})` },
    ...Object.entries(MODE_META).map(([mode, meta]) => ({
      key: mode as ConnectivityMode,
      label: `${meta.icon} ${meta.label}`,
    })),
    { key: 'OFFLINE', label: '🔴 OFFLINE' },
  ]

  return (
    <div className="min-h-full bg-transparent p-6">
      {/* Header */}
      <div className="mb-5 overflow-hidden rounded-lg border border-white/[0.08] bg-[#050607]">
        <div className="flex flex-col gap-4 border-b border-cyan-400/10 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex min-w-0 items-center gap-4">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-md border border-cyan-400/25 bg-cyan-400/10 shadow-[0_0_24px_rgba(34,211,238,0.12)]">
              <Wifi className="h-6 w-6 text-cyan-300" />
            </div>
            <div className="min-w-0">
              <div className="mb-1 font-mono text-[10px] font-semibold uppercase tracking-[0.24em] text-cyan-500/70">
                Transport Control
              </div>
              <h1 className="text-2xl font-semibold uppercase leading-tight tracking-normal text-zinc-100 sm:text-3xl">
                Pivoting Layer
              </h1>
              <p className="mt-1 max-w-2xl text-sm leading-5 text-zinc-500">
                Manage SOCKS, relay, SSH, Chisel, and Ligolo routes for controlled network traversal.
              </p>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2 sm:justify-end">
            <motion.button
              whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
              onClick={handleBatchProbe}
              disabled={batchProbing || profiles.length === 0}
              className="flex items-center gap-2 rounded-md border border-cyan-400/25 bg-cyan-400/10 px-3 py-2 font-mono text-[11px] font-bold uppercase tracking-[0.12em] text-cyan-200 transition-all hover:border-cyan-300/45 hover:bg-cyan-400/15 disabled:opacity-40"
            >
              {batchProbing
                ? <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}><Zap className="w-3.5 h-3.5" /></motion.div>
                : <Zap className="w-3.5 h-3.5" />}
              {batchProbing ? 'PROBING ALL…' : 'PROBE ALL'}
            </motion.button>
            <motion.button whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}
              onClick={handleImport}
              className="flex items-center gap-2 rounded-md border border-white/[0.08] bg-white/[0.03] px-3 py-2 font-mono text-[11px] font-bold uppercase tracking-[0.12em] text-zinc-400 transition hover:border-white/15 hover:text-zinc-200">
              <Upload className="w-3.5 h-3.5" /> IMPORT
            </motion.button>
          </div>
        </div>
      </div>

      {/* Stats row */}
      <StatsRow onNew={() => { setCreating(true); setSelected(null); setNewMode(null) }} />

      {/* Toolbar: filter chips + search */}
      <div className="flex flex-wrap gap-2 mb-4 items-center">
        {FILTER_OPTIONS.map(opt => (
          <button
            key={opt.key}
            onClick={() => setModeFilter(opt.key)}
            className="px-3 py-1.5 rounded-full font-mono font-bold text-[8px] tracking-widest transition-all"
            style={modeFilter === opt.key
              ? { background: '#22d3ee18', border: '1px solid #22d3ee45', color: '#22d3ee' }
              : { border: '1px solid rgba(255,255,255,0.08)', color: 'rgba(255,255,255,0.25)' }
            }
          >
            {opt.label}
          </button>
        ))}
        <div className="ml-auto">
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="🔍 search profiles…"
            className="bg-black/60 border border-white/10 rounded-lg px-3 py-1.5 font-mono text-[10px] text-white/50 placeholder-white/15 focus:outline-none focus:border-cyan-400/30 w-44"
          />
        </div>
      </div>

      {/* Profile grid */}
      {isLoading && (
        <div className="text-cyan-500/30 font-mono text-sm animate-pulse px-2 mb-4">Scanning profiles…</div>
      )}

      <div className="grid grid-cols-3 gap-3 mb-4">
        <AnimatePresence>
          {filtered.map((p, i) => (
            <ProfileCard
              key={p.id}
              profile={p}
              isSelected={selected?.id === p.id && !creating}
              delay={i * 0.04}
              onClick={() => { setSelected(p); setCreating(false) }}
              onDelete={() => deleteMut.mutate(p.id)}
              onClone={() => cloneMut.mutate(p.id)}
              onQuickProbe={() => { setSelected(p); setCreating(false) }}
            />
          ))}
        </AnimatePresence>

        {!isLoading && filtered.length === 0 && (
          <motion.div
            key="empty"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="col-span-3 rounded-2xl border border-dashed border-cyan-500/15 p-12 text-center"
          >
            <WifiOff className="w-10 h-10 text-cyan-500/15 mx-auto mb-3" />
            <p className="text-cyan-500/30 font-mono text-sm">
              {search || modeFilter !== 'ALL' ? 'No profiles match filter.' : 'No profiles. Create one to start.'}
            </p>
          </motion.div>
        )}

        {/* Add profile ghost card */}
        {!creating && (
          <motion.div
            key="add"
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            onClick={() => { setCreating(true); setSelected(null); setNewMode(null) }}
            className="rounded-xl border border-dashed border-cyan-500/15 flex flex-col items-center justify-center gap-2 min-h-[120px] cursor-pointer transition-all hover:border-cyan-500/30 hover:bg-cyan-500/[0.03]"
          >
            <div className="text-2xl text-cyan-500/15">＋</div>
            <div className="font-mono text-[8px] text-cyan-500/25 tracking-widest">NEW PROFILE</div>
          </motion.div>
        )}
      </div>

      {/* Detail drawer / create panel */}
      <AnimatePresence mode="wait">
        {creating && !newMode && (
          <motion.div key="mode-select" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
            <ModeSelector onSelect={setNewMode} />
          </motion.div>
        )}
        {creating && newMode && (
          <motion.div key={`new-${newMode}`} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}>
            <NewProfilePanel
              mode={newMode}
              onSaved={(p) => {
                setCreating(false)
                setSelected(p)
                setNewMode(null)
                qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
                qc.invalidateQueries({ queryKey: ['connectivity-stats'] })
              }}
              onCancel={() => { setCreating(false); setNewMode(null) }}
            />
          </motion.div>
        )}
        {!creating && selected && (
          <ConnectivityDrawer
            key={selected.id}
            profile={selected}
            onUpdated={(p) => {
              setSelected(p)
              qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
              qc.invalidateQueries({ queryKey: ['connectivity-stats'] })
            }}
            onDeleted={() => { deleteMut.mutate(selected.id) }}
            onCloned={(p) => {
              setSelected(p)
              qc.invalidateQueries({ queryKey: ['connectivity-profiles'] })
              qc.invalidateQueries({ queryKey: ['connectivity-stats'] })
            }}
            onClose={() => setSelected(null)}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
