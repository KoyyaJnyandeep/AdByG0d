'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import { Search, Radio, Shield, Eye, Lock, Zap, Cloud, Key, Smartphone, Building2, ServerCrash } from 'lucide-react'
import { cn } from '@/lib/utils'
import { adCommandsApi } from '@/lib/api'
import { BackButton } from '@/components/ui/BackButton'
import { AttackTechCard } from '@/components/ui/AttackTechCard'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const TABS = [
  { key: 'relay',   label: 'Capture & Relay', icon: Radio,     color: '#ff4d6d' },
  { key: 'evasion', label: 'Defense Evasion', icon: Shield,    color: '#a78bfa' },
  { key: 'edr',     label: 'EDR Evasion',     icon: Eye,       color: '#f472b6' },
  { key: 'uac',     label: 'UAC Bypass',      icon: Lock,      color: '#ffd166' },
  { key: 'preauth', label: 'Pre-Auth Abuse',  icon: Zap,          color: '#fb923c' },
  { key: 'wsus',    label: 'WSUS Attack',     icon: ServerCrash,  color: '#ef4444' },
  { key: 'entra',   label: 'Entra ID',        icon: Cloud,        color: '#60a5fa' },
  { key: 'adfs',    label: 'ADFS / Golden SAML', icon: Building2, color: '#818cf8' },
  { key: 'aitm',    label: 'AiTM / MFA Bypass',  icon: Smartphone, color: '#34d399' },
  { key: 'm365',    label: 'M365 & Teams',    icon: Key,       color: '#f97316' },
] as const

type TabKey = typeof TABS[number]['key']

const TAB_TECHNIQUE_IDS: Record<TabKey, string[]> = {
  relay: [
    'ia-responder-capture', 'ia-ntlm-relay', 'ia-dhcpv6-mitm6', 'ia-arp-poison',
    'ia-rid-hijack', 'ia-coerce-printerbug', 'ia-coerce-petitpotam', 'ia-coerce-dfscoerce',
    'ia-relay-smb', 'ia-relay-ldaps', 'ia-relay-adcs', 'ia-relay-mssql',
    'ia-smb-signing-scan', 'ia-llmnr-poisoning', 'ia-nbns-poisoning',
  ],
  evasion: [
    'ia-amsi-bypass', 'ia-etw-bypass', 'ia-download-cradles', 'ia-clm-bypass',
    'ia-applocker-bypass', 'ia-codecepticon', 'ia-powershell-downgrade', 'ia-bypass-constrained',
    'ia-bypass-wscript', 'ia-bypass-mshta', 'ia-bypass-regsvr32', 'ia-bypass-msbuild',
    'evasion-amsi-reflection-patch', 'evasion-amsi-isinitialized', 'evasion-memory-only-payload',
  ],
  edr: [
    'ia-edr-nanodump', 'ia-edr-rwxfinder', 'ia-edr-bof',
    'evasion-edr-nanodump', 'evasion-edr-mockingjay', 'evasion-edr-rwxfinder',
    'evasion-edr-syswhispers3', 'evasion-edr-process-inject-crt', 'evasion-edr-ppid-spoof',
    'evasion-edr-process-hollow', 'evasion-edr-ntdll-unhook', 'evasion-edr-sleep-obfuscation',
    'evasion-edr-donut', 'evasion-edr-indirect-syscall',
  ],
  uac: [
    'uac-fodhelper', 'uac-eventvwr', 'uac-sdclt', 'uac-diskcleanup',
    'uac-wsreset', 'uac-cmstp', 'uac-computerdefaults', 'uac-token-manipulation',
    'uac-silentcleanup', 'uac-icmlua', 'uac-auto-elevation', 'uac-juicypotato',
    'uac-printspoofer', 'uac-uacme-full', 'uac-powerup',
  ],
  preauth: [
    'ia-pre2k-detect', 'ia-pre2k-auth', 'ia-timeroast', 'ia-maq-abuse',
    'ia-wsus-spoof', 'ia-wsus-exec', 'ia-asrep-roast', 'ia-password-spray',
    'ia-kerbrute-spray', 'ia-credential-stuffing', 'ia-ldap-password-spray',
    'ia-smb-password-spray', 'ia-owa-spray', 'ia-invalid-user-enum',
  ],
  entra: [
    'cloud-entra-device-code-phish', 'cloud-entra-prt-theft', 'cloud-entra-app-consent',
    'cloud-entra-cap-enum', 'cloud-entra-sp-enum', 'cloud-entra-global-admin-enum',
    'cloud-entra-prt-sso', 'cloud-entra-token-replay', 'cloud-entra-app-reg-secret',
    'cloud-entra-cap-bypass', 'cloud-entra-guest-enum', 'cloud-entra-sp-cred',
  ],
  adfs: [
    'cloud-adfs-enum', 'cloud-adfs-key-extract', 'cloud-adfs-golden-saml',
    'cloud-adfs-token-craft', 'cloud-adfs-relay', 'cloud-adfs-bypass',
    'cloud-adfs-persistent', 'cloud-adfs-ropc', 'cloud-adfs-wia-abuse',
    'cloud-adfs-smartcard-bypass',
  ],
  aitm: [
    'cloud-aitm-evilginx2', 'cloud-aitm-session-cookie', 'cloud-aitm-legacy-auth',
    'cloud-aitm-persistent-access', 'cloud-aitm-modlishka', 'cloud-aitm-muraena',
    'cloud-aitm-token-replay', 'cloud-aitm-adversary-in-browser',
    'cloud-aitm-auth-flow-hijack', 'cloud-aitm-owa-phish',
  ],
  m365: [
    'cloud-m365-teams-phish', 'cloud-m365-graph-enum', 'cloud-m365-mailbox-delegate',
    'cloud-m365-onedrive-exfil', 'cloud-m365-teams-enum', 'cloud-m365-sharepoint-stage',
    'cloud-m365-mail-exfil', 'cloud-m365-sp-secret-dump',
    'cloud-m365-power-automate', 'cloud-m365-app-proxy',
  ],
  wsus: [
    'ia-wsus-spoof', 'ia-wsus-exec',
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

const hexToRgbStr = (hex: string) => {
  const m = hex.replace('#', '').match(/.{2}/g)
  return m ? m.map(h => parseInt(h, 16)).join(',') : '100,116,139'
}

const CLOUD_TABS: TabKey[] = ['entra', 'adfs', 'aitm', 'm365']

export function InitialAccessHub() {
  const [activeTab, setActiveTab] = useState<TabKey>('relay')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [platform, setPlatform] = useState<'linux' | 'windows' | 'all'>('all')
  const ids = TAB_TECHNIQUE_IDS[activeTab]
  const tab = TABS.find(t => t.key === activeTab)!
  const tabRgb = hexToRgbStr(tab.color)
  const isCloud = CLOUD_TABS.includes(activeTab)

  const { data: techniques = [], isLoading } = useQuery({
    queryKey: ['ad-commands', 'initial-access', activeTab],
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
        <div
          className="relative overflow-hidden rounded-[22px] p-7"
          style={{ border: `1px solid rgba(${tabRgb},0.18)`, background: `linear-gradient(135deg, rgba(${tabRgb},0.06) 0%, rgba(0,0,0,0.9) 100%)` }}
        >
          <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, rgba(${tabRgb},0.8), transparent)` }} />
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-2xl font-black tracking-tight text-white">Initial Access</h1>
            {isCloud && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full" style={{ background: `rgba(${tabRgb},0.15)`, border: `1px solid rgba(${tabRgb},0.3)`, color: tab.color, ...MONO }}>
                CLOUD
              </span>
            )}
          </div>
          <p className="text-[12px] text-zinc-500">Capture & Relay · Defense Evasion · EDR · UAC Bypass · Pre-Auth · Entra ID · ADFS · AiTM · M365</p>
        </div>

        {/* Two-row tab layout: on-prem vs cloud */}
        <div className="space-y-1.5">
          <div className="text-[9px] uppercase tracking-[0.2em] text-zinc-700 px-1" style={MONO}>On-Prem</div>
          <div className="flex flex-wrap gap-1.5">
            {TABS.filter(t => !CLOUD_TABS.includes(t.key as TabKey)).map(({ key, label, icon: Icon, color }) => {
              const isActive = activeTab === key
              const rgb = hexToRgbStr(color)
              return (
                <button key={key} onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all"
                  style={{ background: isActive ? `rgba(${rgb},0.14)` : 'rgba(255,255,255,0.02)', border: isActive ? `1px solid rgba(${rgb},0.38)` : '1px solid rgba(255,255,255,0.05)', color: isActive ? color : 'rgba(100,116,139,0.55)', fontFamily: 'JetBrains Mono, monospace' }}>
                  <Icon className="h-3 w-3" />{label}
                </button>
              )
            })}
          </div>
          <div className="text-[9px] uppercase tracking-[0.2em] text-zinc-700 px-1 pt-1" style={MONO}>Cloud / Hybrid</div>
          <div className="flex flex-wrap gap-1.5">
            {TABS.filter(t => CLOUD_TABS.includes(t.key as TabKey)).map(({ key, label, icon: Icon, color }) => {
              const isActive = activeTab === key
              const rgb = hexToRgbStr(color)
              return (
                <button key={key} onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all"
                  style={{ background: isActive ? `rgba(${rgb},0.14)` : 'rgba(255,255,255,0.02)', border: isActive ? `1px solid rgba(${rgb},0.38)` : '1px solid rgba(255,255,255,0.05)', color: isActive ? color : 'rgba(100,116,139,0.55)', fontFamily: 'JetBrains Mono, monospace', boxShadow: isActive ? `0 0 14px rgba(${rgb},0.1)` : 'none' }}>
                  <Icon className="h-3 w-3" />{label}
                </button>
              )
            })}
          </div>
        </div>

        {/* Search + platform filter */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder={`Search ${tab.label}…`}
              className="w-full rounded-[13px] py-2.5 pl-9 pr-4 text-sm text-zinc-200 outline-none transition-all"
              style={{ background: 'rgba(0,0,0,0.5)', border: `1px solid ${search ? `rgba(${tabRgb},0.3)` : 'rgba(255,255,255,0.07)'}`, fontFamily: 'JetBrains Mono, monospace' }} />
          </div>
          {(['all', 'linux', 'windows'] as const).map(p => (
            <button key={p} onClick={() => setPlatform(p)}
              className={cn('rounded-xl border px-3 py-2 text-[11px] font-semibold transition-all flex-shrink-0',
                platform === p ? 'border-transparent text-black' : 'border-white/10 text-zinc-500 hover:text-zinc-300 bg-white/[0.02]'
              )}
              style={platform === p ? { background: p === 'linux' ? '#34d399' : p === 'windows' ? '#60a5fa' : '#6366f1' } : {}}>
              {p === 'all' ? 'All' : p === 'linux' ? '🐧' : '🪟'}
            </button>
          ))}
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
                <AttackTechCard
                  tech={tech}
                  isOpen={openId === tech.id}
                  onToggle={() => setOpenId(openId === tech.id ? null : tech.id)}
                  accentColor={tab.color}
                  platformFilter={platform}
                />
              </motion.div>
            ))}
          </motion.div>
        )}
      </div>
    </div>
  )
}
