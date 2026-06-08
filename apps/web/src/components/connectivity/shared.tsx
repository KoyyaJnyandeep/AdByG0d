'use client'

import { motion } from 'framer-motion'

export const AD_PORT_LABELS: Record<number, { name: string; abbr: string }> = {
  53:   { name: 'DNS',      abbr: 'DNS'   },
  88:   { name: 'Kerberos', abbr: 'KRB'  },
  135:  { name: 'RPC',      abbr: 'RPC'  },
  389:  { name: 'LDAP',     abbr: 'LDAP' },
  445:  { name: 'SMB',      abbr: 'SMB'  },
  636:  { name: 'LDAPS',    abbr: 'LDAPS'},
  3268: { name: 'Global Catalog',     abbr: 'GC'    },
  3269: { name: 'Global Catalog SSL', abbr: 'GC-S'  },
  5985: { name: 'WinRM',    abbr: 'WRMH' },
  5986: { name: 'WinRM SSL',abbr: 'WRMS' },
}

export const ALL_AD_PORTS = [53, 88, 135, 389, 445, 636, 3268, 3269, 5985, 5986] as const

export const MODE_META = {
  DIRECT:            { label: 'Direct',       icon: '⚡', color: '#22d3ee', desc: 'No proxy. Requires direct route to DC.' },
  SOCKS5:            { label: 'SOCKS5',        icon: '⬡', color: '#a78bfa', desc: 'Existing SOCKS5 proxy (ssh -D, metasploit, etc.)' },
  CHISEL:            { label: 'Chisel',         icon: '📡', color: '#f59e0b', desc: 'AdByG0d spawns chisel server. Run client on jump host.' },
  LIGOLO:            { label: 'Ligolo-ng',      icon: '🌿', color: '#34d399', desc: 'TUN-based routing. Full network segment access.' },
  RELAY_AGENT:       { label: 'Relay Agent',    icon: '🔗', color: '#f87171', desc: 'Deploy relay agent to jump host. [BETA]' },
  MANAGED_SSH_SOCKS: { label: 'Managed SSH',   icon: '🔑', color: '#38bdf8', desc: 'Backend-managed ssh -D SOCKS tunnel to jumpbox.' },
} as const

export const STATUS_META = {
  ONLINE:   { color: '#34d399', label: 'ONLINE',   glow: '#34d39970' as string | null },
  OFFLINE:  { color: '#f87171', label: 'OFFLINE',  glow: null as string | null },
  DEGRADED: { color: '#f59e0b', label: 'DEGRADED', glow: '#f59e0b70' as string | null },
  UNKNOWN:  { color: '#6b7280', label: 'UNKNOWN',  glow: null as string | null },
} as const

export function ConfigField({
  label, children, hint,
}: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <div>
      <label className="block text-xs font-mono text-cyan-500/60 tracking-widest uppercase mb-1.5">{label}</label>
      {children}
      {hint && <p className="text-[11px] font-mono text-white/25 mt-1">{hint}</p>}
    </div>
  )
}

export function CInput({
  value, onChange, placeholder, type = 'text',
}: {
  value: string | number
  onChange: (v: string) => void
  placeholder?: string
  type?: string
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full bg-black border border-cyan-500/20 rounded-xl px-4 py-2.5 font-mono text-sm text-white/80 placeholder-white/15 focus:outline-none focus:border-cyan-400/50 focus:shadow-[0_0_10px_rgba(6,182,212,0.12)]"
    />
  )
}

export function SaveBar({
  onSave, onCancel, saving, label = 'SAVE PROFILE', error,
}: {
  onSave: () => void
  onCancel: () => void
  saving?: boolean
  label?: string
  error?: string | null
}) {
  return (
    <div className="space-y-2 pt-2">
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs font-mono text-red-300">
          {error}
        </div>
      )}
      <div className="flex gap-3">
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={onSave}
          disabled={saving}
          className="flex-1 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500/20 to-fuchsia-500/20 border border-cyan-500/40 text-cyan-400 font-mono font-bold text-sm hover:border-cyan-400/60 transition-all disabled:opacity-40"
        >
          {saving ? 'SAVING...' : label}
        </motion.button>
        <button
          onClick={onCancel}
          className="px-5 py-2.5 rounded-xl border border-white/10 text-white/30 font-mono text-sm hover:text-white/60 hover:border-white/20 transition-all"
        >
          CANCEL
        </button>
      </div>
    </div>
  )
}

export function PanelShell({
  title, color, children,
}: { title: string; color: string; children: React.ReactNode }) {
  return (
    <div
      className="rounded-[24px] border bg-black p-6"
      style={{ borderColor: `${color}30`, boxShadow: `0 0 30px ${color}10` }}
    >
      <h2
        className="text-lg font-black font-mono tracking-widest uppercase mb-6"
        style={{ color }}
      >
        {title}
      </h2>
      <div className="space-y-4">{children}</div>
    </div>
  )
}
