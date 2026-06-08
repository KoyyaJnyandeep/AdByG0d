'use client'

import { copyText } from '@/lib/clipboard'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Crown, Key, Database, Shield, Settings, Clock, Archive, Zap, Search, Copy, ChevronRight, Cpu, Box } from 'lucide-react'
import { adCommandsApi } from '@/lib/api'
import { BackButton } from '@/components/ui/BackButton'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const TABS = [
  { key: 'golden',    label: 'Golden Ticket',     icon: Crown,    color: '#fbbf24' },
  { key: 'skeleton',  label: 'Skeleton Key',      icon: Key,      color: '#f97316' },
  { key: 'dcshadow',  label: 'DCSync / DCShadow', icon: Database, color: '#ef4444' },
  { key: 'acl',       label: 'ACL Backdoors',     icon: Shield,   color: '#a78bfa' },
  { key: 'gpo',       label: 'GPO Persistence',   icon: Settings, color: '#60a5fa' },
  { key: 'scheduled', label: 'Scheduled Tasks',   icon: Clock,    color: '#34d399' },
  { key: 'sid',       label: 'SID History',       icon: Archive,  color: '#fb923c' },
  { key: 'adcs',      label: 'ADCS Persist',      icon: Zap,      color: '#f472b6' },
  { key: 'wmi',       label: 'WMI Subscriptions', icon: Cpu,      color: '#22d3ee' },
  { key: 'com',       label: 'COM Hijacking',     icon: Box,      color: '#a78bfa' },
] as const

type TabKey = typeof TABS[number]['key']

const TAB_TECHNIQUE_IDS: Record<TabKey, string[]> = {
  golden: [
    'persist-golden-ticket', 'persist-golden-krbtgt', 'persist-golden-aes256',
    'persist-golden-mimikatz', 'persist-golden-rubeus', 'persist-golden-impacket',
    'persist-diamond-ticket', 'persist-sapphire-ticket', 'persist-forged-pac',
    'persist-tgt-extract-dc', 'persist-golden-rodc', 'persist-golden-forge-sid',
  ],
  skeleton: [
    'persist-skeleton-key', 'persist-skeleton-mimikatz', 'persist-dkm-key',
    'persist-krbtgt-number2', 'persist-custom-ssp', 'persist-mimilib-ssp',
    'persist-wdigest-enable', 'persist-credential-manager', 'persist-dpapi-backup',
    'persist-dpapi-domain-key', 'persist-lsa-secrets', 'persist-ntds-extract',
  ],
  dcshadow: [
    'persist-dcsync-rights', 'persist-dcsync-mimikatz', 'persist-dcsync-impacket',
    'persist-dcshadow-minimal', 'persist-dcshadow-full', 'persist-dcshadow-sid',
    'persist-dcshadow-admincount', 'persist-dcshadow-acl', 'persist-add-replication-rights',
    'persist-add-dcsync-user', 'persist-dcsync-all-hashes', 'persist-replication-access',
  ],
  acl: [
    'persist-acl-genericall', 'persist-acl-writedacl', 'persist-acl-forcechangepassword',
    'persist-acl-addself', 'persist-acl-addmember', 'persist-acl-writeproperty',
    'persist-acl-extended-right', 'persist-acl-adminsdHolder', 'persist-acl-sdprop',
    'persist-acl-domain-level', 'persist-acl-ou-level', 'persist-acl-generic-write',
  ],
  gpo: [
    'persist-gpo-immediate-task', 'persist-gpo-startup-script', 'persist-gpo-logon-script',
    'persist-gpo-registry-run', 'persist-gpo-scheduled-task', 'persist-gpo-restricted-groups',
    'persist-gpo-service-install', 'persist-gpo-file-deploy', 'persist-gpo-add-local-admin',
    'persist-gpo-add-domain-admin', 'persist-gpo-disable-defender', 'persist-gpo-disable-firewall',
  ],
  scheduled: [
    'persist-schtask-create', 'persist-schtask-remote', 'persist-schtask-system',
    'persist-schtask-xml', 'persist-schtask-elevated', 'persist-schtask-hidden',
    'persist-schtask-dllinject', 'persist-schtask-wmi-subscription', 'persist-schtask-wmi-event',
    'persist-schtask-logon', 'persist-schtask-startup', 'persist-schtask-boot',
  ],
  sid: [
    'persist-sid-history-add', 'persist-sid-history-mimikatz', 'persist-sid-history-impacket',
    'persist-sid-history-enterprise-admin', 'persist-sid-history-schema-admin',
    'persist-sid-history-cross-domain', 'persist-sid-history-forest', 'persist-extraSids',
    'persist-extraSids-forest', 'persist-extraSids-golden', 'persist-sidfiltering-disable',
    'persist-sidfiltering-bypass',
  ],
  adcs: [
    'persist-adcs-golden-cert', 'persist-adcs-rouge-ca', 'persist-adcs-certsync',
    'persist-adcs-pkinit-persist', 'persist-adcs-esc4-template', 'persist-adcs-shadow-cred',
    'persist-adcs-forge-cert', 'persist-adcs-auth-with-cert', 'persist-adcs-machine-cert',
    'persist-adcs-krbtgt-via-cert', 'persist-adcs-ca-backup', 'persist-adcs-ca-pfx',
  ],
  wmi: [
    'persist-wmi-filter', 'persist-wmi-consumer-cmd', 'persist-wmi-consumer-active',
    'persist-wmi-binding', 'persist-wmi-mof-file', 'persist-wmi-powershell',
    'persist-wmi-powershell',
  ],
  com: [
    'persist-com-inprocserver32', 'persist-com-clsid-hijack', 'persist-com-dll-search',
    'persist-com-dcom-lateral', 'persist-boot-efi-bypass', 'persist-boot-bcd-edit',
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

const PERSIST_RISK: Record<string, { color: string; bg: string; border: string }> = {
  CRITICAL: { color: '#ff4d6d', bg: 'rgba(255,77,109,0.08)', border: 'rgba(255,77,109,0.28)' },
  HIGH:     { color: '#ff8a3d', bg: 'rgba(255,138,61,0.07)', border: 'rgba(255,138,61,0.25)' },
  MEDIUM:   { color: '#ffd166', bg: 'rgba(255,209,102,0.07)', border: 'rgba(255,209,102,0.2)' },
  LOW:      { color: '#51cf66', bg: 'rgba(81,207,102,0.06)', border: 'rgba(81,207,102,0.18)' },
}

function PersistCopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button onClick={e => { e.stopPropagation(); copyText(text); setCopied(true); setTimeout(() => setCopied(false), 1400) }}
      className="flex items-center gap-1 rounded px-2 py-0.5 text-[9px] transition-all"
      style={{ border: `1px solid ${copied ? 'rgba(52,211,153,0.4)' : 'rgba(255,255,255,0.07)'}`, color: copied ? '#34d399' : 'rgba(100,116,139,0.7)', background: copied ? 'rgba(52,211,153,0.06)' : 'rgba(0,0,0,0.4)' }}>
      {copied ? <Database className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}{copied ? 'done' : 'copy'}
    </button>
  )
}

function TechCard({ tech, isOpen, onToggle, accentColor }: { tech: Technique; isOpen: boolean; onToggle: () => void; accentColor?: string }) {
  const risk = PERSIST_RISK[tech.risk_level?.toUpperCase()] ?? PERSIST_RISK.LOW
  const accent = accentColor ?? '#8b9cff'
  return (
    <div className="relative overflow-hidden transition-all duration-200"
      style={{ borderRadius: 13, border: isOpen ? `1px solid ${accent}30` : '1px solid rgba(255,255,255,0.05)', background: isOpen ? `linear-gradient(135deg, ${accent}08 0%, rgba(0,0,0,0.65) 100%)` : 'rgba(255,255,255,0.015)' }}>
      <div className="absolute left-0 top-2 bottom-2 w-[3px] rounded-full" style={{ background: risk.color, opacity: ['CRITICAL','HIGH'].includes(tech.risk_level?.toUpperCase()) ? 0.9 : 0.35 }} />
      <button className="flex w-full items-start gap-3 pl-5 pr-4 py-3 text-left group" onClick={onToggle}>
        <div className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md transition-all"
          style={{ background: isOpen ? risk.bg : 'rgba(255,255,255,0.03)', border: `1px solid ${isOpen ? risk.border : 'rgba(255,255,255,0.06)'}` }}>
          <ChevronRight className="h-2.5 w-2.5 transition-transform duration-200" style={{ color: isOpen ? risk.color : '#4b5563', transform: isOpen ? 'rotate(90deg)' : 'none' }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13px] font-semibold text-zinc-100 group-hover:text-white transition-colors">{tech.title}</span>
            <span className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-black uppercase tracking-wider" style={{ color: risk.color, background: risk.bg, border: `1px solid ${risk.border}` }}>{tech.risk_level}</span>
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-zinc-600 truncate max-w-[200px]" style={MONO}>{tech.tool}</span>
            <span className="text-zinc-800 text-[10px]">·</span>
            <span className="text-[10px] text-zinc-500 font-semibold" style={MONO}>{tech.mitre_technique_id}</span>
          </div>
        </div>
      </button>
      {isOpen && (
        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} transition={{ duration: 0.2 }} className="overflow-hidden">
          <div className="px-5 pb-4 pt-2 space-y-2.5 border-t" style={{ borderColor: 'rgba(255,255,255,0.04)' }}>
            <p className="text-[11px] leading-relaxed text-zinc-400">{tech.description}</p>
            {tech.commands.map((cmd, i) => (
              <div key={`${cmd.label}-${i}`} className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.55)' }}>
                <div className="flex items-center justify-between px-3 py-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', background: 'rgba(255,255,255,0.02)' }}>
                  <span className="text-[9px] font-semibold text-zinc-500">{cmd.label}</span>
                  <PersistCopyBtn text={cmd.command} />
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

const hexToRgbP = (hex: string) => hex.replace('#', '').match(/.{2}/g)?.map(h => parseInt(h, 16)).join(',') ?? '100,116,139'

export function PersistenceHub() {
  const [activeTab, setActiveTab] = useState<TabKey>('golden')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const ids = TAB_TECHNIQUE_IDS[activeTab]
  const tab = TABS.find(t => t.key === activeTab)!
  const tabRgb = hexToRgbP(tab.color)

  const { data: techniques = [], isLoading } = useQuery({
    queryKey: ['ad-commands', 'persistence', activeTab],
    queryFn: () => adCommandsApi.list<Technique>({ ids: ids.join(',') }),
    staleTime: 5 * 60 * 1000,
  })

  const visible = techniques.filter(t =>
    !search || t.title.toLowerCase().includes(search.toLowerCase()) || t.tool.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="min-h-full" style={{ background: 'rgba(2,3,8,0.98)' }}>
      <div className="max-w-[1300px] mx-auto p-6 space-y-5">
        <BackButton />

        {/* Header */}
        <div className="relative overflow-hidden rounded-[22px] p-7"
          style={{ border: `1px solid rgba(${tabRgb},0.2)`, background: `linear-gradient(135deg, rgba(${tabRgb},0.07) 0%, rgba(0,0,0,0.92) 100%)` }}>
          <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, rgba(${tabRgb},0.9), transparent)` }} />
          <div className="flex items-center gap-3 mb-1">
            <motion.div animate={{ rotate: [0, 360] }} transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
              className="w-5 h-5 rounded-full border-2 border-transparent"
              style={{ borderTopColor: tab.color, borderRightColor: `${tab.color}66` }} />
            <h1 className="text-2xl font-black tracking-tight text-white">Persistence</h1>
          </div>
          <p className="text-[12px] text-zinc-500">Golden Ticket · Skeleton Key · DCSync · ACL Backdoor · GPO · SID History · ADCS · WMI · COM Hijacking</p>
        </div>

        {/* Tabs — scrollable row */}
        <div className="flex flex-wrap gap-1.5">
          {TABS.map(({ key, label, icon: Icon, color }) => {
            const isActive = activeTab === key
            const rgb = hexToRgbP(color)
            return (
              <button key={key} onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all"
                style={{
                  background: isActive ? `rgba(${rgb},0.14)` : 'rgba(255,255,255,0.02)',
                  border: isActive ? `1px solid rgba(${rgb},0.38)` : '1px solid rgba(255,255,255,0.05)',
                  color: isActive ? color : 'rgba(100,116,139,0.55)',
                  fontFamily: 'JetBrains Mono, monospace',
                  boxShadow: isActive ? `0 0 12px rgba(${rgb},0.1)` : 'none',
                }}>
                <Icon className="h-3 w-3" style={{ filter: isActive ? `drop-shadow(0 0 5px ${color})` : 'none' }} />
                {label}
              </button>
            )
          })}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder={`Search ${tab.label}…`}
            className="w-full rounded-[13px] py-2.5 pl-9 pr-4 text-sm text-zinc-200 outline-none transition-all"
            style={{ background: 'rgba(0,0,0,0.5)', border: `1px solid ${search ? `rgba(${tabRgb},0.3)` : 'rgba(255,255,255,0.07)'}`, fontFamily: 'JetBrains Mono, monospace' }} />
        </div>

        <div className="text-[10px] text-zinc-600 px-1" style={MONO}>{visible.length} techniques · {tab.label}</div>

        {isLoading ? (
          <div className="space-y-2">{[1,2,3,4].map(i => <div key={i} className="h-12 rounded-[13px] animate-pulse" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }} />)}</div>
        ) : (
          <motion.div key={activeTab} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.22 }} className="space-y-2">
            {visible.length === 0 && (
              <div className="py-16 text-center text-sm text-zinc-600">
                {techniques.length === 0 ? 'Techniques will appear once catalog is loaded.' : 'No techniques match.'}
              </div>
            )}
            {visible.map((tech, i) => (
              <motion.div key={tech.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.025 }}>
                <TechCard tech={tech} isOpen={openId === tech.id} onToggle={() => setOpenId(openId === tech.id ? null : tech.id)} accentColor={tab.color} />
              </motion.div>
            ))}
          </motion.div>
        )}
      </div>
    </div>
  )
}
