'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Copy, Trash2, Download } from 'lucide-react'
import type { ConnectivityProfile } from '@/lib/connectivityApi'
import { connectivityApi } from '@/lib/connectivityApi'
import { MODE_META, STATUS_META } from './shared'
import { ProbeTab } from './ProbeTab'
import { ControlTab } from './ControlTab'
import { LogsTab } from './LogsTab'
import { DirectConfig } from './DirectConfig'
import { Socks5Config } from './Socks5Config'
import { ChiselConfig } from './ChiselConfig'
import { LigoloConfig } from './LigoloConfig'
import { RelayAgentConfig } from './RelayAgentConfig'
import { ManagedSshConfig } from './ManagedSshConfig'

type DrawerTab = 'CONFIG' | 'CONTROL' | 'PROBE' | 'LOGS'

const TABS: DrawerTab[] = ['CONFIG', 'CONTROL', 'PROBE', 'LOGS']

function ConfigPanel({ profile, onSaved, onCancel }: { profile: ConnectivityProfile; onSaved: (p: ConnectivityProfile) => void; onCancel: () => void }) {
  const props = { profile, onSaved, onCancel }
  if (profile.mode === 'DIRECT')            return <DirectConfig {...props} />
  if (profile.mode === 'SOCKS5')            return <Socks5Config {...props} />
  if (profile.mode === 'CHISEL')            return <ChiselConfig {...props} />
  if (profile.mode === 'LIGOLO')            return <LigoloConfig {...props} />
  if (profile.mode === 'RELAY_AGENT')       return <RelayAgentConfig {...props} />
  if (profile.mode === 'MANAGED_SSH_SOCKS') return <ManagedSshConfig {...props} />
  return null
}

export function ConnectivityDrawer({
  profile,
  onUpdated,
  onDeleted,
  onCloned,
  onClose,
}: {
  profile: ConnectivityProfile
  onUpdated: (p: ConnectivityProfile) => void
  onDeleted: () => void
  onCloned: (p: ConnectivityProfile) => void
  onClose: () => void
}) {
  const [activeTab, setActiveTab] = useState<DrawerTab>('PROBE')
  const meta = MODE_META[profile.mode] ?? MODE_META.DIRECT
  const st = STATUS_META[profile.status] ?? STATUS_META.UNKNOWN

  const handleClone = async () => {
    const cloned = await connectivityApi.cloneProfile(profile.id)
    onCloned(cloned)
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 12 }}
      transition={{ duration: 0.25, ease: [0.23, 1, 0.32, 1] }}
      className="rounded-2xl border overflow-hidden"
      style={{ borderColor: '#22d3ee22', background: '#08081a' }}
    >
      {/* Drawer header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-white/5" style={{ background: '#0a0a1a' }}>
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center text-sm flex-shrink-0"
          style={{ background: `${meta.color}12`, border: `1px solid ${meta.color}25` }}
        >
          {meta.icon}
        </div>
        <div>
          <div className="font-mono font-bold text-sm text-white/90">{profile.name}</div>
          <div className="font-mono text-[8px] tracking-widest" style={{ color: `${meta.color}50` }}>
            {meta.label.toUpperCase()}
            {(profile.config as Record<string, unknown>).dc_ip ? ` · ${(profile.config as Record<string, unknown>).dc_ip}` : ''}
          </div>
        </div>
        <div
          className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg border ml-2 flex-shrink-0"
          style={{ borderColor: `${st.color}25`, background: `${st.color}08` }}
        >
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: st.color, boxShadow: st.glow ? `0 0 5px ${st.glow}` : undefined }} />
          <span className="font-mono font-bold text-[8px] tracking-wider" style={{ color: st.color }}>
            {st.label}{profile.last_latency_ms != null ? ` · ${profile.last_latency_ms}ms` : ''}
          </span>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 ml-auto">
          {TABS.map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="px-3 py-1.5 rounded-lg font-mono font-bold text-[9px] tracking-widest transition-all"
              style={activeTab === tab
                ? { background: '#22d3ee18', border: '1px solid #22d3ee35', color: '#22d3ee' }
                : { border: '1px solid transparent', color: '#ffffff25' }
              }
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Actions */}
        <div className="flex gap-1.5 ml-3">
          <button
            onClick={handleClone}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg font-mono text-[9px] font-bold transition-all"
            style={{ border: '1px solid #a78bfa25', color: '#a78bfa60' }}
            title="Clone profile"
          >
            <Copy className="w-3 h-3" /> CLONE
          </button>
          <button
            onClick={() => connectivityApi.exportProfile(profile)}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg font-mono text-[9px] font-bold transition-all"
            style={{ border: '1px solid #22d3ee20', color: '#22d3ee50' }}
            title="Export profile as JSON"
          >
            <Download className="w-3 h-3" /> EXPORT
          </button>
          <button
            onClick={onDeleted}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-lg font-mono text-[9px] font-bold transition-all hover:bg-red-500/10"
            style={{ border: '1px solid #f4717120', color: '#f4717150' }}
            title="Delete profile"
          >
            <Trash2 className="w-3 h-3" /> DELETE
          </button>
        </div>
      </div>

      {/* Tab body */}
      <div className="p-4">
        <AnimatePresence mode="wait">
          {activeTab === 'CONFIG' && (
            <motion.div key="config" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <ConfigPanel profile={profile} onSaved={onUpdated} onCancel={onClose} />
            </motion.div>
          )}
          {activeTab === 'CONTROL' && (
            <motion.div key="control" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <ControlTab profile={profile} />
            </motion.div>
          )}
          {activeTab === 'PROBE' && (
            <motion.div key="probe" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <ProbeTab profile={profile} onProbed={() => onUpdated(profile)} />
            </motion.div>
          )}
          {activeTab === 'LOGS' && (
            <motion.div key="logs" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <LogsTab profile={profile} />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}
