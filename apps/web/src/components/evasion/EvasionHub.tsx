'use client'

import { copyText } from '@/lib/clipboard'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Shield, Eye, Cpu, Search, Copy, ChevronRight, Package, Radio, Check } from 'lucide-react'
import { adCommandsApi } from '@/lib/api'
import { BackButton } from '@/components/ui/BackButton'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const TABS = [
  { key: 'amsi',    label: 'AMSI / ETW',        icon: Shield,  color: '#f472b6' },
  { key: 'clm',     label: 'CLM / AppLocker',   icon: Eye,     color: '#a78bfa' },
  { key: 'edr',     label: 'EDR / AV Bypass',   icon: Cpu,     color: '#fb923c' },
  { key: 'payload', label: 'Payload Delivery',  icon: Package, color: '#34d399' },
  { key: 'c2',      label: 'C2 Integration',    icon: Radio,   color: '#22d3ee' },
] as const

type TabKey = typeof TABS[number]['key']

const TAB_TECHNIQUE_IDS: Record<TabKey, string[]> = {
  amsi: [
    'evasion-amsi-reflection-patch', 'evasion-amsi-env-var', 'evasion-amsi-scriptblock-logging',
    'evasion-amsi-isinitialized', 'evasion-amsi-com-bypass', 'evasion-amsi-alternate-runspace',
    'evasion-etw-patch', 'evasion-ps-downgrade', 'evasion-codecepticon',
    'evasion-base64-splitting', 'evasion-string-obfuscation', 'evasion-memory-only-payload',
    'evasion-wdac-bypass', 'evasion-lolbas-certutil', 'evasion-lolbas-bitsadmin',
  ],
  clm: [
    'evasion-clm-bypass-runspace', 'evasion-clm-bypass-wmic', 'evasion-applocker-regsvr32',
    'evasion-applocker-mshta', 'evasion-applocker-installutil', 'evasion-applocker-rundll32',
    'ia-clm-bypass', 'ia-applocker-bypass', 'ia-powershell-downgrade', 'ia-bypass-constrained',
    'ia-bypass-wscript', 'ia-bypass-mshta', 'ia-bypass-regsvr32', 'ia-bypass-msbuild',
  ],
  edr: [
    'evasion-edr-nanodump', 'evasion-edr-mockingjay', 'evasion-edr-rwxfinder',
    'evasion-edr-syswhispers3', 'evasion-edr-bof-cs', 'evasion-edr-process-inject-crt',
    'evasion-edr-ppid-spoof', 'evasion-edr-process-hollow', 'evasion-edr-ntdll-unhook',
    'evasion-edr-sleep-obfuscation', 'evasion-edr-donut', 'evasion-edr-indirect-syscall',
    'ia-edr-nanodump', 'ia-edr-rwxfinder', 'ia-edr-bof',
  ],
  payload: [
    'evasion-payload-certutil', 'evasion-payload-bitsadmin', 'evasion-payload-mshta',
    'evasion-payload-regsvr32', 'evasion-payload-msbuild', 'evasion-payload-iex-cradle',
    'evasion-payload-donut', 'evasion-payload-vba-macro',
    'evasion-lolbas-certutil', 'evasion-lolbas-bitsadmin', 'evasion-memory-only-payload',
    'evasion-base64-splitting', 'evasion-string-obfuscation', 'evasion-codecepticon',
    'evasion-edr-donut', 'evasion-edr-indirect-syscall',
  ],
  c2: [
    'evasion-c2-sliver-gen', 'evasion-c2-havoc-demon', 'evasion-c2-http-redirector',
    'evasion-c2-smb-beacon', 'evasion-c2-socks5-pivot',
    'evasion-edr-sleep-obfuscation', 'evasion-edr-process-hollow', 'evasion-edr-ntdll-unhook',
    'evasion-edr-ppid-spoof', 'evasion-edr-syswhispers3', 'evasion-edr-bof-cs',
  ],
}

type Technique = {
  id: string
  title: string
  tool: string
  risk_level: string
  platform: string
  mitre_technique_id: string
  description: string
  commands: { label: string; command: string; params: string[] }[]
}

const RISK_META: Record<string, { color: string; bg: string; border: string; glow: string }> = {
  CRITICAL: { color: '#ff4d6d', bg: 'rgba(255,77,109,0.08)', border: 'rgba(255,77,109,0.28)', glow: 'rgba(255,77,109,0.4)' },
  HIGH:     { color: '#ff8a3d', bg: 'rgba(255,138,61,0.07)', border: 'rgba(255,138,61,0.25)', glow: 'rgba(255,138,61,0.35)' },
  MEDIUM:   { color: '#ffd166', bg: 'rgba(255,209,102,0.07)', border: 'rgba(255,209,102,0.2)', glow: 'rgba(255,209,102,0.3)' },
  LOW:      { color: '#51cf66', bg: 'rgba(81,207,102,0.06)', border: 'rgba(81,207,102,0.18)', glow: 'rgba(81,207,102,0.25)' },
}

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={e => { e.stopPropagation(); copyText(text); setCopied(true); setTimeout(() => setCopied(false), 1400) }}
      className="flex items-center gap-1 rounded px-2 py-0.5 text-[9px] transition-all"
      style={{ border: `1px solid ${copied ? 'rgba(52,211,153,0.4)' : 'rgba(255,255,255,0.07)'}`, color: copied ? '#34d399' : 'rgba(100,116,139,0.7)', background: copied ? 'rgba(52,211,153,0.06)' : 'rgba(0,0,0,0.4)' }}
    >
      {copied ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
      {copied ? 'ok' : 'copy'}
    </button>
  )
}

function TechCard({ tech, isOpen, onToggle, accentColor }: { tech: Technique; isOpen: boolean; onToggle: () => void; accentColor: string }) {
  const risk = RISK_META[tech.risk_level?.toUpperCase()] ?? RISK_META.LOW
  const isCritical = ['CRITICAL', 'HIGH'].includes(tech.risk_level?.toUpperCase())
  return (
    <div
      className="relative overflow-hidden transition-all duration-200"
      style={{
        borderRadius: 13,
        border: isOpen ? `1px solid rgba(${accentColor},0.25)` : '1px solid rgba(255,255,255,0.05)',
        background: isOpen ? 'rgba(0,0,0,0.55)' : 'rgba(255,255,255,0.015)',
      }}
    >
      <div className="absolute left-0 top-2 bottom-2 w-[3px] rounded-full" style={{ background: risk.color, boxShadow: isOpen ? `0 0 8px ${risk.glow}` : 'none', opacity: isCritical ? 1 : 0.35 }} />
      <button className="flex w-full items-start gap-3 pl-5 pr-4 py-3 text-left group" onClick={onToggle}>
        <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md transition-all" style={{ background: isOpen ? risk.bg : 'rgba(255,255,255,0.03)', border: `1px solid ${isOpen ? risk.border : 'rgba(255,255,255,0.06)'}` }}>
          <ChevronRight className="h-2.5 w-2.5 transition-transform duration-200" style={{ color: isOpen ? risk.color : '#4b5563', transform: isOpen ? 'rotate(90deg)' : 'none' }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13px] font-semibold text-zinc-100 group-hover:text-white transition-colors">{tech.title}</span>
            <span className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-black uppercase tracking-wider" style={{ color: risk.color, background: risk.bg, border: `1px solid ${risk.border}` }}>{tech.risk_level}</span>
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-zinc-600 truncate max-w-[180px]" style={MONO}>{tech.tool}</span>
            <span className="text-zinc-800 text-[10px]">·</span>
            <span className="text-[10px] font-semibold text-zinc-500" style={MONO}>{tech.mitre_technique_id}</span>
          </div>
        </div>
      </button>
      {isOpen && (
        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
          <div className="px-5 pb-4 pt-2 space-y-2.5 border-t" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
            <p className="text-[11px] leading-relaxed text-zinc-400">{tech.description}</p>
            {tech.commands.map((cmd, i) => (
              <div key={`${cmd.label}-${i}`} className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.55)' }}>
                <div className="flex items-center justify-between px-3 py-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', background: 'rgba(255,255,255,0.02)' }}>
                  <span className="text-[9px] font-semibold text-zinc-500">{cmd.label}</span>
                  <CopyBtn text={cmd.command} />
                </div>
                <pre className="px-3 py-2.5 text-[10px] text-emerald-400 whitespace-pre-wrap break-all leading-relaxed" style={MONO}>{cmd.command}</pre>
              </div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  )
}

export function EvasionHub() {
  const [activeTab, setActiveTab] = useState<TabKey>('amsi')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const ids = TAB_TECHNIQUE_IDS[activeTab]
  const tab = TABS.find(t => t.key === activeTab)!

  const { data: techniques = [], isLoading } = useQuery({
    queryKey: ['ad-commands', 'evasion', activeTab],
    queryFn: () => adCommandsApi.list<Technique>({ ids: ids.join(',') }),
    staleTime: 5 * 60 * 1000,
  })

  const visible = techniques.filter(t =>
    !search || t.title.toLowerCase().includes(search.toLowerCase()) || t.tool.toLowerCase().includes(search.toLowerCase())
  )

  // Parse hex color to rgb string for CSS
  const hexToRgb = (hex: string) => {
    const m = hex.replace('#', '').match(/.{2}/g)
    return m ? m.map(h => parseInt(h, 16)).join(',') : '100,116,139'
  }
  const tabRgb = hexToRgb(tab.color)

  return (
    <div className="min-h-full" style={{ background: 'rgba(2,3,8,0.98)' }}>
      <div className="max-w-[1300px] mx-auto p-6 space-y-5">
        <BackButton />

        {/* Header */}
        <div
          className="relative overflow-hidden rounded-[22px] p-7"
          style={{ border: `1px solid rgba(${tabRgb},0.2)`, background: `linear-gradient(135deg, rgba(${tabRgb},0.07) 0%, rgba(0,0,0,0.9) 100%)` }}
        >
          <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, rgba(${tabRgb},0.8), transparent)` }} />
          <h1 className="text-2xl font-black tracking-tight text-white mb-1">Defense Evasion</h1>
          <p className="text-[12px] text-zinc-500">AMSI · ETW · CLM · AppLocker · EDR · Payload Delivery · C2 Integration</p>
        </div>

        {/* Tabs */}
        <div className="flex flex-wrap gap-1.5">
          {TABS.map(({ key, label, icon: Icon, color }) => {
            const isActive = activeTab === key
            const rgb = hexToRgb(color)
            return (
              <button
                key={key}
                onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
                className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-[12px] font-semibold transition-all duration-200"
                style={{
                  background: isActive ? `rgba(${rgb},0.15)` : 'rgba(255,255,255,0.02)',
                  border: isActive ? `1px solid rgba(${rgb},0.4)` : '1px solid rgba(255,255,255,0.05)',
                  color: isActive ? color : 'rgba(100,116,139,0.6)',
                  boxShadow: isActive ? `0 0 14px rgba(${rgb},0.1)` : 'none',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
              >
                <Icon className="h-3.5 w-3.5" style={{ filter: isActive ? `drop-shadow(0 0 6px ${color})` : 'none' }} />
                {label}
              </button>
            )
          })}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={`Search ${tab.label}…`}
            className="w-full rounded-[13px] py-2.5 pl-9 pr-4 text-sm text-zinc-200 outline-none transition-all"
            style={{ background: 'rgba(0,0,0,0.5)', border: `1px solid ${search ? `rgba(${tabRgb},0.3)` : 'rgba(255,255,255,0.07)'}`, fontFamily: 'JetBrains Mono, monospace' }}
          />
        </div>

        {/* Count */}
        <div className="flex items-center gap-2 text-[10px]" style={MONO}>
          <span className="text-zinc-600">{visible.length} techniques</span>
          <span style={{ color: tab.color }}>· {tab.label}</span>
        </div>

        {/* List */}
        {isLoading ? (
          <div className="space-y-2">{[1,2,3,4].map(i => <div key={i} className="h-12 rounded-[13px] animate-pulse" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }} />)}</div>
        ) : (
          <motion.div key={activeTab} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.22 }} className="space-y-2">
            {visible.length === 0 && (
              <div className="py-16 text-center text-sm text-zinc-600">
                {techniques.length === 0 ? 'Techniques will appear once catalog entries are loaded.' : 'No techniques match.'}
              </div>
            )}
            {visible.map((tech, i) => (
              <motion.div key={tech.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.025 }}>
                <TechCard tech={tech} isOpen={openId === tech.id} onToggle={() => setOpenId(openId === tech.id ? null : tech.id)} accentColor={tabRgb} />
              </motion.div>
            ))}
          </motion.div>
        )}
      </div>
    </div>
  )
}
