'use client'

import { motion } from 'framer-motion'
import type { ConnectivityMode } from '@/lib/connectivityApi'
import { MODE_META } from './shared'

const MODE_DETAIL: Record<ConnectivityMode, { when: string; requires: string }> = {
  DIRECT:            { when: 'Attack box has direct network access to DC', requires: 'None' },
  SOCKS5:            { when: 'You already have a SOCKS proxy (ssh -D, msfconsole, etc.)', requires: 'External proxy running' },
  CHISEL:            { when: 'You need a lightweight HTTP tunnel through firewall', requires: 'chisel binary on jump host' },
  LIGOLO:            { when: 'You need full TUN routing to a network segment', requires: 'ligolo-ng agent on jump host, CAP_NET_ADMIN' },
  RELAY_AGENT:       { when: 'Deploying a managed relay agent to jump host [BETA]', requires: 'Agent binary + connectivity to relay host' },
  MANAGED_SSH_SOCKS: { when: 'AdByG0d manages the ssh -D tunnel lifecycle', requires: 'SSH access to jumpbox, key or password' },
}

export function ModeSelector({
  onSelect,
}: {
  onSelect: (mode: ConnectivityMode) => void
}) {
  const modes = Object.entries(MODE_META) as [ConnectivityMode, typeof MODE_META[ConnectivityMode]][]

  return (
    <div className="rounded-2xl border border-fuchsia-500/20 bg-black/60 p-5 backdrop-blur-sm">
      <div className="text-xs font-black font-mono tracking-widest uppercase mb-1" style={{ color: '#a78bfa' }}>
        SELECT TRANSPORT MODE
      </div>
      <p className="text-[10px] font-mono text-white/25 mb-5">Choose how AdByG0d connects to the target network.</p>
      <div className="grid grid-cols-1 gap-2">
        {modes.map(([mode, meta], i) => {
          const detail = MODE_DETAIL[mode]
          return (
            <motion.button
              key={mode}
              initial={{ opacity: 0, x: 10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.04 }}
              whileHover={{ scale: 1.005 }}
              whileTap={{ scale: 0.995 }}
              onClick={() => onSelect(mode)}
              className="group text-left rounded-xl p-3.5 transition-all duration-150 border border-white/5 hover:border-white/15"
              style={{ background: '#0a0a14' }}
            >
              <div className="flex items-center gap-3">
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center text-lg flex-shrink-0 transition-transform group-hover:scale-110"
                  style={{ background: `${meta.color}12`, border: `1px solid ${meta.color}25` }}
                >
                  {meta.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-mono font-bold text-sm text-white/90">{meta.label}</div>
                  <div className="text-[10px] font-mono text-white/35 mt-0.5">{detail.when}</div>
                </div>
                <div className="text-right flex-shrink-0">
                  <div
                    className="text-[9px] font-mono px-2 py-0.5 rounded font-bold"
                    style={{ background: `${meta.color}12`, border: `1px solid ${meta.color}25`, color: meta.color }}
                  >
                    {mode}
                  </div>
                  <div className="text-[8px] font-mono text-white/20 mt-1 max-w-[120px] text-right">
                    {detail.requires}
                  </div>
                </div>
              </div>
            </motion.button>
          )
        })}
      </div>
    </div>
  )
}
