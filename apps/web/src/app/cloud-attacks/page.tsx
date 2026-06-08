'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useEffect, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Cloud, Building2, Smartphone, Mail, Search, Copy, ChevronRight,
  Check, Wifi, ShieldAlert, Zap, Globe, Lock, Terminal,
} from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { BackButton } from '@/components/ui/BackButton'
import { adCommandsApi } from '@/lib/api'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const RISK: Record<string, { color: string; bg: string; border: string; glow: string }> = {
  CRITICAL: { color: '#ff4d6d', bg: 'rgba(255,77,109,0.08)', border: 'rgba(255,77,109,0.28)', glow: 'rgba(255,77,109,0.4)' },
  HIGH:     { color: '#ff8a3d', bg: 'rgba(255,138,61,0.07)', border: 'rgba(255,138,61,0.25)', glow: 'rgba(255,138,61,0.35)' },
  MEDIUM:   { color: '#ffd166', bg: 'rgba(255,209,102,0.07)', border: 'rgba(255,209,102,0.22)', glow: 'rgba(255,209,102,0.3)' },
  LOW:      { color: '#51cf66', bg: 'rgba(81,207,102,0.06)', border: 'rgba(81,207,102,0.18)', glow: 'rgba(81,207,102,0.25)' },
}

const TABS = [
  {
    key: 'entra', label: 'Entra ID', short: 'ENTRA', icon: Cloud, color: '#60a5fa',
    rgb: '96,165,250', desc: 'Azure AD / Entra identity attacks',
    tags: ['Device Code', 'PRT Theft', 'PIM Abuse', 'Pass-the-Cert', 'ADSync Abuse'],
  },
  {
    key: 'adfs', label: 'ADFS / Golden SAML', short: 'ADFS', icon: Building2, color: '#818cf8',
    rgb: '129,140,248', desc: 'Federated identity & SAML forgery',
    tags: ['Golden SAML', 'Token Signing Key', 'ADFS Relay', 'Cred Spray'],
  },
  {
    key: 'aitm', label: 'AiTM / MFA Bypass', short: 'AiTM', icon: Smartphone, color: '#34d399',
    rgb: '52,211,153', desc: 'Adversary-in-the-Middle & MFA evasion',
    tags: ['Evilginx2', 'Cookie Harvest', 'STS Harvest', 'AiTB'],
  },
  {
    key: 'm365', label: 'M365 & Teams', short: 'M365', icon: Mail, color: '#f97316',
    rgb: '249,115,22', desc: 'Microsoft 365 & Teams attack surface',
    tags: ['Teams Phish', 'Graph API', 'Inbox Rules', 'eDiscovery'],
  },
] as const
type TabKey = typeof TABS[number]['key']

const TAB_TECHNIQUE_IDS: Record<TabKey, string[]> = {
  entra: [
    'cloud-entra-device-code-phish', 'cloud-entra-prt-theft', 'cloud-entra-prt-sso',
    'cloud-entra-token-replay', 'cloud-entra-app-consent', 'cloud-entra-app-reg-secret',
    'cloud-entra-cap-enum', 'cloud-entra-cap-bypass', 'cloud-entra-guest-enum',
    'cloud-entra-sp-enum', 'cloud-entra-sp-cred', 'cloud-entra-global-admin-enum',
    'cloud-entra-password-spray', 'cloud-entra-aadinternals-recon', 'cloud-entra-managed-identity',
    'cloud-entra-pim-abuse', 'cloud-entra-pass-the-cert', 'cloud-entra-adsync-abuse',
    'cloud-entra-seamless-sso', 'cloud-entra-app-proxy-abuse',
  ],
  adfs: [
    'cloud-adfs-enum', 'cloud-adfs-key-extract', 'cloud-adfs-golden-saml',
    'cloud-adfs-token-craft', 'cloud-adfs-relay', 'cloud-adfs-bypass',
    'cloud-adfs-persistent', 'cloud-adfs-ropc', 'cloud-adfs-wia-abuse',
    'cloud-adfs-smartcard-bypass',
    'cloud-adfs-user-enum', 'cloud-adfs-cred-spray', 'cloud-adfs-sts-abuse',
    'cloud-adfs-drs-backdoor',
  ],
  aitm: [
    'cloud-aitm-evilginx2', 'cloud-aitm-modlishka', 'cloud-aitm-muraena',
    'cloud-aitm-session-cookie', 'cloud-aitm-token-replay', 'cloud-aitm-adversary-in-browser',
    'cloud-aitm-legacy-auth', 'cloud-aitm-auth-flow-hijack',
    'cloud-aitm-persistent-access', 'cloud-aitm-owa-phish',
    'cloud-aitm-caffeine', 'cloud-aitm-callback-phish', 'cloud-aitm-sts-harvest',
    'cloud-aitm-cookie-import',
  ],
  m365: [
    'cloud-m365-teams-phish', 'cloud-m365-teams-enum', 'cloud-m365-sharepoint-stage',
    'cloud-m365-onedrive-exfil', 'cloud-m365-mailbox-delegate', 'cloud-m365-mail-exfil',
    'cloud-m365-sp-secret-dump', 'cloud-m365-graph-enum',
    'cloud-m365-power-automate', 'cloud-m365-app-proxy',
    'cloud-m365-exchange-rules', 'cloud-m365-folder-perm', 'cloud-m365-ediscovery-sweep',
    'cloud-m365-teams-tab-inject', 'cloud-m365-sharepoint-webpart',
  ],
}

type Technique = {
  id: string; title: string; tool: string; risk_level: string; platform: string
  mitre_technique_id: string; description: string
  commands: { label: string; command: string; params: string[] }[]
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={e => { e.stopPropagation(); copyText(text); setCopied(true); setTimeout(() => setCopied(false), 1400) }}
      className="flex items-center gap-1 rounded border px-2 py-0.5 text-[9px] transition-all duration-200"
      style={{
        borderColor: copied ? 'rgba(52,211,153,0.4)' : 'rgba(255,255,255,0.08)',
        color: copied ? '#34d399' : 'rgba(100,116,139,0.7)',
        background: copied ? 'rgba(52,211,153,0.06)' : 'transparent',
      }}
    >
      {copied ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
      {copied ? 'copied' : 'copy'}
    </button>
  )
}

function TechCard({ tech, isOpen, onToggle, tabColor }: { tech: Technique; isOpen: boolean; onToggle: () => void; tabColor: string }) {
  const risk = RISK[tech.risk_level?.toUpperCase()] ?? RISK.LOW
  const criticalOrHigh = ['CRITICAL', 'HIGH'].includes(tech.risk_level?.toUpperCase())

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="relative overflow-hidden"
      style={{
        borderRadius: 14,
        border: isOpen ? `1px solid rgba(${tabColor.replace('#', '').match(/.{2}/g)?.map(h => parseInt(h, 16)).join(',')},0.25)` : '1px solid rgba(255,255,255,0.05)',
        background: isOpen ? 'rgba(0,0,0,0.6)' : 'rgba(255,255,255,0.015)',
        transition: 'all 0.2s ease',
      }}
    >
      {/* Left severity bar */}
      <div
        className="absolute left-0 top-0 bottom-0 w-[3px] rounded-l-xl"
        style={{
          background: risk.color,
          boxShadow: isOpen ? `0 0 12px ${risk.glow}` : 'none',
          opacity: criticalOrHigh ? 1 : 0.4,
        }}
      />

      <button
        className="flex w-full items-start gap-3 px-4 pl-5 py-3.5 text-left group"
        onClick={onToggle}
      >
        <div
          className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg transition-all"
          style={{
            background: isOpen ? `${risk.bg}` : 'rgba(255,255,255,0.03)',
            border: `1px solid ${isOpen ? risk.border : 'rgba(255,255,255,0.06)'}`,
          }}
        >
          <ChevronRight
            className="h-3 w-3 transition-transform duration-200"
            style={{ color: isOpen ? risk.color : 'rgba(100,116,139,0.5)', transform: isOpen ? 'rotate(90deg)' : 'rotate(0deg)' }}
          />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-zinc-100 group-hover:text-white transition-colors">{tech.title}</span>
            <span
              className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-black uppercase tracking-widest"
              style={{ color: risk.color, background: risk.bg, border: `1px solid ${risk.border}` }}
            >
              {tech.risk_level}
            </span>
            {criticalOrHigh && (
              <motion.span
                animate={{ opacity: [1, 0.4, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
                className="h-1.5 w-1.5 rounded-full shrink-0"
                style={{ background: risk.color }}
              />
            )}
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[10px] text-zinc-600 truncate max-w-[180px]" style={MONO}>{tech.tool}</span>
            <span className="text-zinc-800 text-[10px]">·</span>
            <span className="text-[10px] font-semibold" style={{ color: `${tabColor}88`, ...MONO }}>{tech.mitre_technique_id}</span>
          </div>
        </div>
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: [0.23, 1, 0.32, 1] }}
            className="overflow-hidden"
          >
            <div
              className="px-5 pb-4 pt-2 space-y-3 border-t"
              style={{ borderColor: 'rgba(255,255,255,0.05)' }}
            >
              <p className="text-[11px] leading-relaxed text-zinc-400">{tech.description}</p>
              <div className="space-y-2">
                {tech.commands?.map((cmd, i) => (
                  <div
                    key={`${cmd.label}-${i}`}
                    className="rounded-xl overflow-hidden"
                    style={{ border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(0,0,0,0.5)' }}
                  >
                    <div
                      className="flex items-center justify-between px-3 py-2"
                      style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', background: 'rgba(255,255,255,0.02)' }}
                    >
                      <div className="flex items-center gap-2">
                        <Terminal className="h-3 w-3 text-zinc-600" />
                        <span className="text-[10px] font-semibold text-zinc-400">{cmd.label}</span>
                      </div>
                      <CopyButton text={cmd.command} />
                    </div>
                    <div className="px-3 py-2.5">
                      <pre className="text-[10px] leading-relaxed whitespace-pre-wrap break-all" style={{ color: tabColor, opacity: 0.9, ...MONO }}>{cmd.command}</pre>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}

function OrbitalRing({ delay, size, opacity }: { delay: number; size: number; opacity: number }) {
  return (
    <motion.div
      className="absolute rounded-full border border-blue-400/20 pointer-events-none"
      style={{ width: size, height: size, left: '50%', top: '50%', x: '-50%', y: '-50%', opacity }}
      animate={{ scale: [1, 1.06, 1], opacity: [opacity, opacity * 0.4, opacity] }}
      transition={{ duration: 4 + delay, repeat: Infinity, delay, ease: 'easeInOut' }}
    />
  )
}

function SignalBeam() {
  return (
    <motion.div
      className="absolute inset-x-0 pointer-events-none z-[2]"
      style={{
        height: 60,
        background: 'linear-gradient(180deg, transparent, rgba(96,165,250,0.04) 40%, rgba(129,140,248,0.06) 50%, rgba(96,165,250,0.04) 60%, transparent)',
      }}
      initial={{ top: '-60px' }}
      animate={{ top: ['-60px', '100%'] }}
      transition={{ duration: 7, repeat: Infinity, repeatDelay: 2.5, ease: 'linear' }}
    />
  )
}

export default function CloudAttacksPage() {
  const [activeTab, setActiveTab] = useState<TabKey>('entra')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const searchRef = useRef<HTMLInputElement>(null)

  const tab = TABS.find(t => t.key === activeTab)!
  const ids = TAB_TECHNIQUE_IDS[activeTab]

  const { data: techniques = [], isLoading } = useQuery({
    queryKey: ['ad-commands', 'cloud', activeTab],
    queryFn: () => adCommandsApi.list<Technique>({ ids: ids.join(',') }),
    staleTime: 5 * 60 * 1000,
  })

  const visible = techniques.filter(t =>
    !search || t.title.toLowerCase().includes(search.toLowerCase()) || t.description?.toLowerCase().includes(search.toLowerCase())
  )

  const criticalCount = visible.filter(t => t.risk_level?.toUpperCase() === 'CRITICAL').length
  const highCount = visible.filter(t => t.risk_level?.toUpperCase() === 'HIGH').length

  useEffect(() => { setOpenId(null); setSearch('') }, [activeTab])

  return (
    <AppShell>
      <div className="min-h-full" style={{ background: 'linear-gradient(180deg, rgba(4,5,12,1) 0%, rgba(2,3,8,1) 100%)' }}>
        <div className="max-w-[1440px] mx-auto px-6 md:px-8 py-8 space-y-6">
          <BackButton />

          {/* ── Hero ── */}
          <motion.div
            initial={{ opacity: 0, y: -16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
            className="relative overflow-hidden"
            style={{ borderRadius: 24, border: '1px solid rgba(96,165,250,0.18)', background: 'linear-gradient(135deg, rgba(2,4,16,0.98) 0%, rgba(4,8,28,0.96) 50%, rgba(2,4,16,0.98) 100%)' }}
          >
            {/* Background orbital rings */}
            <div className="absolute right-8 top-1/2 hidden h-48 w-48 -translate-y-1/2 pointer-events-none md:block">
              <OrbitalRing delay={0} size={192} opacity={0.3} />
              <OrbitalRing delay={1.2} size={140} opacity={0.2} />
              <OrbitalRing delay={2.4} size={90} opacity={0.15} />
              <div
                className="absolute inset-0 m-auto w-10 h-10 rounded-full"
                style={{ background: 'radial-gradient(circle, rgba(96,165,250,0.3) 0%, transparent 70%)', left: '50%', top: '50%', transform: 'translate(-50%,-50%)' }}
              />
            </div>

            {/* Scan beam */}
            <SignalBeam />

            {/* Top edge glow */}
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(96,165,250,0.8) 30%, rgba(129,140,248,0.9) 60%, transparent)' }} />

            <div className="relative z-10 p-6 md:p-8 md:pr-40">
              <div className="flex items-center gap-2 mb-4">
                <motion.div
                  animate={{ boxShadow: ['0 0 8px rgba(96,165,250,0.3)', '0 0 18px rgba(96,165,250,0.6)', '0 0 8px rgba(96,165,250,0.3)'] }}
                  transition={{ duration: 2.5, repeat: Infinity }}
                  className="flex items-center justify-center w-7 h-7 rounded-lg"
                  style={{ background: 'rgba(96,165,250,0.12)', border: '1px solid rgba(96,165,250,0.3)' }}
                >
                  <Globe className="h-3.5 w-3.5 text-blue-400" />
                </motion.div>
                <span className="text-[10px] font-bold uppercase tracking-[0.3em]" style={{ color: 'rgba(96,165,250,0.7)', ...MONO }}>
                  Cloud Attack Surface
                </span>
              </div>

              <h1 className="text-[28px] font-black tracking-tight text-white leading-none mb-2" style={{ textShadow: '0 0 30px rgba(96,165,250,0.2)' }}>
                Cloud Attacks
              </h1>
              <p className="text-[13px] text-zinc-400 max-w-lg leading-relaxed">
                Entra ID identity abuse, ADFS federation attacks, AiTM session hijacking, MFA bypass, M365 / Teams exploitation, eDiscovery data sweep, and Azure App Proxy pivoting.
              </p>

              {/* Stat chips */}
              <div className="flex items-center gap-3 mt-5 flex-wrap">
                {[
                  { label: 'Categories', val: TABS.length, color: '#60a5fa' },
                  { label: 'Techniques', val: Object.values(TAB_TECHNIQUE_IDS).flat().length, color: '#818cf8' },
                  { label: 'MITRE ATT&CK', val: 'T1078·T1528·T1557·T1649·T1558', color: '#34d399', mono: true },
                ].map(s => (
                  <div
                    key={s.label}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                    style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}
                  >
                    <span className="text-[10px] text-zinc-600 uppercase tracking-wider">{s.label}</span>
                    <span className="text-[11px] font-bold" style={{ color: s.color, ...(s.mono ? MONO : {}) }}>{s.val}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Bottom edge */}
            <div className="absolute inset-x-0 bottom-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(96,165,250,0.2) 50%, transparent)' }} />
          </motion.div>

          {/* ── Tab Selector ── */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1, duration: 0.4 }}
            className="grid grid-cols-2 gap-2 md:grid-cols-4"
          >
            {TABS.map(({ key, label, icon: Icon, color, rgb, desc, tags }) => {
              const isActive = activeTab === key
              return (
                <button
                  key={key}
                  onClick={() => setActiveTab(key)}
                  className="relative overflow-hidden text-left p-4 rounded-[18px] transition-all duration-200"
                  style={{
                    background: isActive
                      ? `linear-gradient(135deg, rgba(${rgb},0.14) 0%, rgba(0,0,0,0.8) 100%)`
                      : 'rgba(255,255,255,0.02)',
                    border: isActive ? `1px solid rgba(${rgb},0.4)` : '1px solid rgba(255,255,255,0.05)',
                    boxShadow: isActive ? `0 0 24px rgba(${rgb},0.12), inset 0 1px 0 rgba(${rgb},0.1)` : 'none',
                  }}
                >
                  {isActive && (
                    <motion.div
                      layoutId="tab-glow"
                      className="absolute inset-0 pointer-events-none"
                      style={{ background: `radial-gradient(circle at 30% 50%, rgba(${rgb},0.08) 0%, transparent 70%)` }}
                    />
                  )}
                  {isActive && (
                    <div className="absolute top-0 inset-x-0 h-px" style={{ background: `linear-gradient(90deg, transparent, rgba(${rgb},0.8), transparent)` }} />
                  )}
                  <div className="flex items-center gap-2 mb-2.5 relative z-10">
                    <div
                      className="flex items-center justify-center w-7 h-7 rounded-lg transition-all"
                      style={{
                        background: isActive ? `rgba(${rgb},0.2)` : 'rgba(255,255,255,0.04)',
                        border: `1px solid ${isActive ? `rgba(${rgb},0.4)` : 'rgba(255,255,255,0.06)'}`,
                        boxShadow: isActive ? `0 0 12px rgba(${rgb},0.3)` : 'none',
                      }}
                    >
                      <Icon className="h-3.5 w-3.5" style={{ color: isActive ? color : 'rgba(100,116,139,0.5)' }} />
                    </div>
                    {isActive && (
                      <motion.div
                        animate={{ opacity: [0.4, 1, 0.4] }}
                        transition={{ duration: 2, repeat: Infinity }}
                        className="h-1.5 w-1.5 rounded-full"
                        style={{ background: color }}
                      />
                    )}
                  </div>
                  <div className="text-[11px] font-bold tracking-wide relative z-10" style={{ color: isActive ? '#fff' : 'rgba(148,163,184,0.6)', ...MONO }}>{label}</div>
                  <div className="text-[9px] mt-0.5 text-zinc-600 relative z-10 leading-relaxed">{desc}</div>
                  <div className="flex flex-wrap gap-1 mt-2 relative z-10">
                    {tags.map(t => (
                      <span key={t} className="text-[8px] px-1.5 py-0.5 rounded" style={{ background: `rgba(${rgb},0.08)`, color: `rgba(${rgb.split(',').map(Number).map(n => Math.min(255, n + 40)).join(',')},0.9)`, border: `1px solid rgba(${rgb},0.15)` }}>{t}</span>
                    ))}
                  </div>
                </button>
              )
            })}
          </motion.div>

          {/* ── Main Content ── */}
          <div className="grid grid-cols-1 xl:grid-cols-[1fr_300px] gap-4">

            {/* Left: technique list */}
            <div className="space-y-3">
              {/* Search bar */}
              <div className="relative">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
                <input
                  ref={searchRef}
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder={`Search ${tab.label} techniques…`}
                  className="w-full py-2.5 pl-10 pr-4 text-sm text-zinc-200 outline-none transition-all"
                  style={{
                    background: 'rgba(0,0,0,0.5)',
                    border: `1px solid ${search ? `rgba(${tab.rgb},0.35)` : 'rgba(255,255,255,0.07)'}`,
                    borderRadius: 14,
                    fontFamily: 'JetBrains Mono, monospace',
                    boxShadow: search ? `0 0 16px rgba(${tab.rgb},0.08)` : 'none',
                  }}
                />
                {search && (
                  <button
                    onClick={() => setSearch('')}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-600 hover:text-zinc-300 transition-colors"
                  >
                    ×
                  </button>
                )}
              </div>

              {/* Count bar */}
              <div className="flex items-center gap-3 px-1">
                <span className="text-[10px] text-zinc-600" style={MONO}>{visible.length} techniques</span>
                {criticalCount > 0 && (
                  <span className="text-[10px] font-bold" style={{ color: '#ff4d6d', ...MONO }}>{criticalCount} critical</span>
                )}
                {highCount > 0 && (
                  <span className="text-[10px] font-bold" style={{ color: '#ff8a3d', ...MONO }}>{highCount} high</span>
                )}
              </div>

              {/* Cards */}
              {isLoading ? (
                <div className="space-y-2">
                  {[1, 2, 3, 4].map(i => (
                    <div key={i} className="h-14 rounded-2xl animate-pulse" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }} />
                  ))}
                </div>
              ) : visible.length === 0 ? (
                <div className="py-20 text-center">
                  <Search className="h-8 w-8 text-zinc-700 mx-auto mb-3" />
                  <p className="text-sm text-zinc-600">No techniques match your search</p>
                </div>
              ) : (
                <motion.div className="space-y-2" layout>
                  {visible.map((tech, i) => (
                    <motion.div
                      key={tech.id}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.03, duration: 0.3 }}
                    >
                      <TechCard
                        tech={tech}
                        isOpen={openId === tech.id}
                        onToggle={() => setOpenId(openId === tech.id ? null : tech.id)}
                        tabColor={tab.color}
                      />
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </div>

            {/* Right: info panel */}
            <div className="space-y-3">
              {/* Category summary */}
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-[18px] overflow-hidden"
                style={{ border: `1px solid rgba(${tab.rgb},0.2)`, background: `linear-gradient(160deg, rgba(${tab.rgb},0.06) 0%, rgba(0,0,0,0.7) 100%)` }}
              >
                <div className="p-4 border-b" style={{ borderColor: `rgba(${tab.rgb},0.12)` }}>
                  <div className="flex items-center gap-2">
                    <tab.icon className="h-3.5 w-3.5" style={{ color: tab.color }} />
                    <span className="text-[11px] font-bold uppercase tracking-[0.2em]" style={{ color: tab.color, ...MONO }}>{tab.label}</span>
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5 leading-relaxed">{tab.desc}</p>
                </div>
                <div className="p-4 space-y-2">
                  {tab.tags.map(tag => (
                    <div key={tag} className="flex items-center gap-2.5">
                      <div className="h-1 w-1 rounded-full shrink-0" style={{ background: tab.color }} />
                      <span className="text-[11px] text-zinc-400">{tag}</span>
                    </div>
                  ))}
                </div>
              </motion.div>

              {/* Risk breakdown */}
              {!isLoading && visible.length > 0 && (
                <div
                  className="rounded-[18px] p-4 space-y-3"
                  style={{ border: '1px solid rgba(255,255,255,0.06)', background: 'rgba(255,255,255,0.015)' }}
                >
                  <div className="text-[9px] font-bold uppercase tracking-[0.25em] text-zinc-600" style={MONO}>Risk Distribution</div>
                  {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(level => {
                    const count = visible.filter(t => t.risk_level?.toUpperCase() === level).length
                    if (count === 0) return null
                    const pct = Math.round((count / visible.length) * 100)
                    return (
                      <div key={level} className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[9px] font-bold uppercase tracking-wider" style={{ color: RISK[level].color, ...MONO }}>{level}</span>
                          <span className="text-[9px] text-zinc-600" style={MONO}>{count}</span>
                        </div>
                        <div className="h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.05)' }}>
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${pct}%` }}
                            transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
                            className="h-full rounded-full"
                            style={{ background: RISK[level].color, boxShadow: `0 0 6px ${RISK[level].glow}` }}
                          />
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}

              {/* Cloud kill chain */}
              <div
                className="rounded-[18px] p-4"
                style={{ border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.4)' }}
              >
                <div className="text-[9px] font-bold uppercase tracking-[0.25em] text-zinc-600 mb-3" style={MONO}>Cloud Kill Chain</div>
                {[
                  { stage: 'Recon', icon: Wifi, color: '#60a5fa' },
                  { stage: 'Initial Access', icon: Lock, color: '#818cf8' },
                  { stage: 'Credential Theft', icon: ShieldAlert, color: '#f97316' },
                  { stage: 'Persistence', icon: Zap, color: '#ff4d6d' },
                ].map(({ stage, icon: Icon, color }, i) => (
                  <div key={stage} className="flex items-center gap-2.5 py-1.5">
                    <div className="flex items-center justify-center w-5 h-5 rounded-md shrink-0" style={{ background: `rgba(${color.replace('#', '').match(/.{2}/g)?.map(h => parseInt(h, 16)).join(',')},0.12)`, border: `1px solid ${color}30` }}>
                      <Icon className="h-2.5 w-2.5" style={{ color }} />
                    </div>
                    <span className="text-[10px] text-zinc-400 flex-1">{stage}</span>
                    {i < 3 && <div className="text-zinc-700 text-xs">↓</div>}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  )
}
