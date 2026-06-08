'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  HardDrive, Monitor, Database, Key, Search, Copy, ChevronRight,
  Check, Terminal, AlertTriangle, ShieldOff,
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
    key: 'lsass', label: 'LSASS Dump', short: 'LSASS', icon: Monitor, color: '#ff4d6d', rgb: '255,77,109',
    desc: 'Live process memory extraction', threat: 'CRITICAL',
    note: 'Dumps LSASS process memory — NT hashes, Kerberos tickets, plaintext creds',
  },
  {
    key: 'ntds', label: 'SAM / NTDS.dit', short: 'NTDS', icon: HardDrive, color: '#f97316', rgb: '249,115,22',
    desc: 'Domain database & SAM hive extraction', threat: 'CRITICAL',
    note: 'All domain hashes via VSS shadow copy or ntdsutil snapshot',
  },
  {
    key: 'dpapi', label: 'DPAPI', short: 'DPAPI', icon: Key, color: '#a78bfa', rgb: '167,139,250',
    desc: 'DPAPI blob decryption & key theft', threat: 'HIGH',
    note: 'Domain backup key → decrypt all user credentials, browser data, certificates',
  },
  {
    key: 'remote', label: 'Remote Secrets', short: 'REMOTE', icon: Database, color: '#22d3ee', rgb: '34,211,238',
    desc: 'Over-network credential extraction', threat: 'CRITICAL',
    note: 'secretsdump, DCSync, LAPS, gMSA over authenticated SMB/DRSUAPI',
  },
] as const
type TabKey = typeof TABS[number]['key']

const TAB_TECHNIQUE_IDS: Record<TabKey, string[]> = {
  lsass: [
    'cred-dump-lsass-comsvcs', 'cred-dump-lsass-nanodump', 'cred-dump-lsass-pypykatz',
    'evasion-edr-nanodump', 'evasion-edr-mockingjay', 'cred-dump-lsass-procdump',
  ],
  ntds: [
    'cred-dump-ntds-vss', 'cred-dump-ntds-ntdsutil', 'cred-dump-sam-reg',
    'cred-dump-dcc2-cached', 'cred-dump-lsa-secrets',
  ],
  dpapi: [
    'dpapi-masterkey-backup', 'dpapi-masterkey-domain', 'dpapi-chrome-passwords',
    'dpapi-credential-files', 'dpapi-vault-files', 'dpapi-rdp-credentials',
    'dpapi-wifi-passwords', 'dpapi-sspi-creds', 'dpapi-sharpdpapi-run',
  ],
  remote: [
    'cred-dump-secretsdump-remote', 'secretsdump', 'dcsync',
    'laps_dump', 'gmsa_dump', 'dpapi_backup_key',
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
      className="flex items-center gap-1 rounded px-2 py-0.5 text-[9px] transition-all duration-200"
      style={{
        border: `1px solid ${copied ? 'rgba(52,211,153,0.4)' : 'rgba(255,255,255,0.07)'}`,
        color: copied ? '#34d399' : 'rgba(100,116,139,0.7)',
        background: copied ? 'rgba(52,211,153,0.06)' : 'rgba(0,0,0,0.4)',
      }}
    >
      {copied ? <Check className="h-2.5 w-2.5" /> : <Copy className="h-2.5 w-2.5" />}
      {copied ? 'copied' : 'copy'}
    </button>
  )
}

function TechCard({ tech, isOpen, onToggle, tabColor, tabRgb }: {
  tech: Technique; isOpen: boolean; onToggle: () => void; tabColor: string; tabRgb: string
}) {
  const risk = RISK[tech.risk_level?.toUpperCase()] ?? RISK.LOW
  const isCritical = tech.risk_level?.toUpperCase() === 'CRITICAL'

  return (
    <div
      className="relative overflow-hidden transition-all duration-200"
      style={{
        borderRadius: 14,
        border: isOpen
          ? `1px solid rgba(${tabRgb},0.3)`
          : `1px solid rgba(255,255,255,0.05)`,
        background: isOpen
          ? `linear-gradient(135deg, rgba(${tabRgb},0.05) 0%, rgba(0,0,0,0.7) 100%)`
          : 'rgba(255,255,255,0.015)',
        boxShadow: isOpen ? `0 0 20px rgba(${tabRgb},0.06), inset 0 1px 0 rgba(${tabRgb},0.06)` : 'none',
      }}
    >
      {/* Severity left bar */}
      <div
        className="absolute left-0 top-2 bottom-2 w-[3px] rounded-full"
        style={{
          background: `linear-gradient(180deg, ${risk.color}, ${risk.color}88)`,
          boxShadow: isOpen ? `0 0 8px ${risk.glow}` : 'none',
          opacity: isCritical ? 1 : 0.45,
        }}
      />

      <button className="flex w-full items-start gap-3 pl-5 pr-4 py-3.5 text-left group" onClick={onToggle}>
        <div
          className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-md transition-all"
          style={{
            background: isOpen ? risk.bg : 'rgba(255,255,255,0.03)',
            border: `1px solid ${isOpen ? risk.border : 'rgba(255,255,255,0.06)'}`,
          }}
        >
          <ChevronRight
            className="h-2.5 w-2.5 transition-transform duration-200"
            style={{ color: isOpen ? risk.color : '#4b5563', transform: isOpen ? 'rotate(90deg)' : 'none' }}
          />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13px] font-semibold text-zinc-100 group-hover:text-white transition-colors leading-tight">{tech.title}</span>
            <span
              className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-black uppercase tracking-[0.1em]"
              style={{ color: risk.color, background: risk.bg, border: `1px solid ${risk.border}` }}
            >
              {tech.risk_level}
            </span>
            {isCritical && (
              <motion.span
                animate={{ opacity: [1, 0.2, 1] }}
                transition={{ duration: 1.8, repeat: Infinity }}
                className="h-1.5 w-1.5 rounded-full shrink-0"
                style={{ background: '#ff4d6d', boxShadow: '0 0 6px rgba(255,77,109,0.6)' }}
              />
            )}
          </div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-[10px] text-zinc-600 truncate max-w-[200px]" style={MONO}>{tech.tool}</span>
            <span className="text-zinc-700 text-[10px]">·</span>
            <span className="text-[10px] font-semibold" style={{ color: `${tabColor}99`, ...MONO }}>{tech.mitre_technique_id}</span>
          </div>
        </div>
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.23, 1, 0.32, 1] }}
            className="overflow-hidden"
          >
            <div className="px-5 pb-4 pt-3 space-y-3 border-t" style={{ borderColor: `rgba(${tabRgb},0.1)` }}>
              <p className="text-[11px] leading-relaxed text-zinc-400">{tech.description}</p>
              <div className="space-y-2">
                {tech.commands?.map((cmd, i) => (
                  <div
                    key={`${cmd.label}-${i}`}
                    className="rounded-xl overflow-hidden"
                    style={{ border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.6)' }}
                  >
                    {/* Terminal title bar */}
                    <div
                      className="flex items-center justify-between px-3 py-2"
                      style={{ background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid rgba(255,255,255,0.04)' }}
                    >
                      <div className="flex items-center gap-2">
                        <div className="flex gap-1">
                          <div className="h-2 w-2 rounded-full bg-red-500/40" />
                          <div className="h-2 w-2 rounded-full bg-yellow-500/40" />
                          <div className="h-2 w-2 rounded-full bg-green-500/40" />
                        </div>
                        <Terminal className="h-2.5 w-2.5 text-zinc-700" />
                        <span className="text-[9px] text-zinc-500" style={MONO}>{cmd.label}</span>
                      </div>
                      <CopyButton text={cmd.command} />
                    </div>
                    <div className="px-3 py-3">
                      <pre
                        className="text-[10px] leading-relaxed whitespace-pre-wrap break-all"
                        style={{ color: tabColor, opacity: 0.85, ...MONO }}
                      >
                        {cmd.command}
                      </pre>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

/* Animated binary rain strip for header decoration */
function BinaryStrip() {
  const chars = '01010110100010110001011010110010110100101'.split('')
  return (
    <div className="absolute right-6 top-0 bottom-0 flex items-center gap-1.5 pointer-events-none opacity-[0.07] overflow-hidden" style={MONO}>
      {[0, 1, 2].map(col => (
        <motion.div
          key={col}
          className="flex flex-col gap-0.5 text-[8px] text-red-400"
          animate={{ y: [0, -20, 0] }}
          transition={{ duration: 4 + col * 1.3, repeat: Infinity, ease: 'linear', delay: col * 0.8 }}
        >
          {chars.slice(col * 13, col * 13 + 13).map((c, i) => (
            <span key={i}>{c}</span>
          ))}
        </motion.div>
      ))}
    </div>
  )
}

export default function CredDumpPage() {
  const [activeTab, setActiveTab] = useState<TabKey>('lsass')
  const [openId, setOpenId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const searchRef = useRef<HTMLInputElement>(null)

  const tab = TABS.find(t => t.key === activeTab)!
  const ids = TAB_TECHNIQUE_IDS[activeTab]

  const { data: techniques = [], isLoading } = useQuery({
    queryKey: ['ad-commands', 'cred-dump', activeTab],
    queryFn: () => adCommandsApi.list<Technique>({ ids: ids.join(',') }),
    staleTime: 5 * 60 * 1000,
  })

  const visible = techniques.filter(t =>
    !search || t.title.toLowerCase().includes(search.toLowerCase()) || t.description.toLowerCase().includes(search.toLowerCase())
  )

  const criticalCount = visible.filter(t => t.risk_level?.toUpperCase() === 'CRITICAL').length

  return (
    <AppShell>
      <div className="min-h-full" style={{ background: 'rgba(2,3,8,1)' }}>
        <div className="max-w-[1440px] mx-auto px-6 md:px-8 py-8 space-y-6">
          <BackButton />

          {/* ── Hero ── */}
          <motion.div
            initial={{ opacity: 0, y: -14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
            className="relative overflow-hidden"
            style={{
              borderRadius: 22,
              border: '1px solid rgba(255,77,109,0.2)',
              background: 'linear-gradient(135deg, rgba(10,2,4,0.99) 0%, rgba(16,4,6,0.98) 50%, rgba(8,2,4,0.99) 100%)',
            }}
          >
            {/* Top glow line */}
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(255,77,109,0.7) 25%, rgba(249,115,22,0.5) 55%, transparent)' }} />

            {/* Binary decoration */}
            <BinaryStrip />

            {/* Scan line */}
            <motion.div
              className="absolute inset-x-0 pointer-events-none"
              style={{ height: 2, background: 'linear-gradient(90deg, transparent, rgba(255,77,109,0.15), transparent)' }}
              animate={{ top: ['-2px', '100%'] }}
              transition={{ duration: 5, repeat: Infinity, repeatDelay: 3, ease: 'linear' }}
            />

            <div className="relative z-10 p-8">
              <div className="flex items-center gap-2 mb-4">
                <motion.div
                  animate={{ boxShadow: ['0 0 8px rgba(255,77,109,0.3)', '0 0 18px rgba(255,77,109,0.7)', '0 0 8px rgba(255,77,109,0.3)'] }}
                  transition={{ duration: 2, repeat: Infinity }}
                  className="flex items-center justify-center w-7 h-7 rounded-lg"
                  style={{ background: 'rgba(255,77,109,0.12)', border: '1px solid rgba(255,77,109,0.35)' }}
                >
                  <ShieldOff className="h-3.5 w-3.5 text-red-400" />
                </motion.div>
                <span className="text-[10px] font-bold uppercase tracking-[0.3em]" style={{ color: 'rgba(255,77,109,0.7)', ...MONO }}>
                  Credential Extraction
                </span>
                <motion.span
                  animate={{ opacity: [1, 0, 1] }}
                  transition={{ duration: 1.2, repeat: Infinity }}
                  className="h-3.5 w-[2px] bg-red-400 ml-1"
                />
              </div>

              <h1 className="text-[28px] font-black tracking-tight text-white leading-none mb-2" style={{ textShadow: '0 0 30px rgba(255,77,109,0.15)' }}>
                Credential Dump &amp; DPAPI
              </h1>
              <p className="text-[13px] text-zinc-400 max-w-lg leading-relaxed">
                LSASS memory extraction, NTDS.dit via VSS, SAM hive, DPAPI domain backup key, Chrome passwords, and remote secretsdump workflows.
              </p>

              {/* Stat chips */}
              <div className="flex items-center gap-3 mt-5 flex-wrap">
                {[
                  { label: 'Modules', val: TABS.length, color: '#ff4d6d' },
                  { label: 'Techniques', val: Object.values(TAB_TECHNIQUE_IDS).flat().length, color: '#f97316' },
                  { label: 'Severity', val: 'CRITICAL', color: '#ff4d6d' },
                ].map(s => (
                  <div
                    key={s.label}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
                    style={{ background: 'rgba(255,255,255,0.025)', border: '1px solid rgba(255,255,255,0.05)' }}
                  >
                    <span className="text-[9px] text-zinc-600 uppercase tracking-wider">{s.label}</span>
                    <span className="text-[11px] font-bold" style={{ color: s.color, ...MONO }}>{s.val}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="absolute inset-x-0 bottom-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(255,77,109,0.15) 50%, transparent)' }} />
          </motion.div>

          {/* ── Tab Selector ── */}
          <motion.div
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="grid grid-cols-2 gap-2 md:grid-cols-4"
          >
            {TABS.map(({ key, label, icon: Icon, color, rgb, desc, threat }) => {
              const isActive = activeTab === key
              return (
                <button
                  key={key}
                  onClick={() => { setActiveTab(key); setOpenId(null); setSearch('') }}
                  className="relative overflow-hidden text-left p-4 rounded-[16px] transition-all duration-200"
                  style={{
                    background: isActive
                      ? `linear-gradient(135deg, rgba(${rgb},0.12) 0%, rgba(0,0,0,0.85) 100%)`
                      : 'rgba(255,255,255,0.02)',
                    border: isActive ? `1px solid rgba(${rgb},0.38)` : '1px solid rgba(255,255,255,0.05)',
                    boxShadow: isActive ? `0 0 20px rgba(${rgb},0.1), inset 0 1px 0 rgba(${rgb},0.08)` : 'none',
                  }}
                >
                  {isActive && (
                    <div className="absolute top-0 inset-x-0 h-px" style={{ background: `linear-gradient(90deg, transparent, rgba(${rgb},0.9), transparent)` }} />
                  )}

                  <div className="flex items-center justify-between mb-2.5">
                    <div
                      className="flex items-center justify-center w-7 h-7 rounded-lg transition-all"
                      style={{
                        background: isActive ? `rgba(${rgb},0.18)` : 'rgba(255,255,255,0.04)',
                        border: `1px solid ${isActive ? `rgba(${rgb},0.4)` : 'rgba(255,255,255,0.06)'}`,
                        boxShadow: isActive ? `0 0 10px rgba(${rgb},0.25)` : 'none',
                      }}
                    >
                      <Icon className="h-3.5 w-3.5" style={{ color: isActive ? color : 'rgba(100,116,139,0.4)' }} />
                    </div>
                    <span
                      className="text-[8px] font-black px-1.5 py-0.5 rounded uppercase tracking-wider"
                      style={{ color: RISK[threat]?.color ?? '#ff4d6d', background: RISK[threat]?.bg, border: `1px solid ${RISK[threat]?.border}` }}
                    >
                      {threat}
                    </span>
                  </div>

                  <div className="text-[11px] font-bold" style={{ color: isActive ? '#fff' : 'rgba(148,163,184,0.5)', ...MONO }}>{label}</div>
                  <div className="text-[9px] mt-1 leading-relaxed" style={{ color: isActive ? 'rgba(156,163,175,0.8)' : 'rgba(100,116,139,0.5)' }}>{desc}</div>
                </button>
              )
            })}
          </motion.div>

          {/* ── Main Content ── */}
          <div className="grid grid-cols-1 xl:grid-cols-[1fr_280px] gap-4">

            {/* Left: technique list */}
            <div className="space-y-3">
              {/* Search */}
              <div className="relative">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-600" />
                <input
                  ref={searchRef}
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder={`Search ${tab.label}…`}
                  className="w-full py-2.5 pl-10 pr-4 text-sm text-zinc-200 outline-none transition-all"
                  style={{
                    background: 'rgba(0,0,0,0.6)',
                    border: `1px solid ${search ? `rgba(${tab.rgb},0.35)` : 'rgba(255,255,255,0.07)'}`,
                    borderRadius: 13,
                    fontFamily: 'JetBrains Mono, monospace',
                  }}
                />
              </div>

              {/* Count + alert */}
              <div className="flex items-center gap-3 px-1">
                <span className="text-[10px] text-zinc-600" style={MONO}>{visible.length} techniques</span>
                {criticalCount > 0 && (
                  <motion.span
                    animate={{ opacity: [1, 0.5, 1] }}
                    transition={{ duration: 2, repeat: Infinity }}
                    className="flex items-center gap-1.5 text-[10px] font-bold"
                    style={{ color: '#ff4d6d', ...MONO }}
                  >
                    <AlertTriangle className="h-3 w-3" />
                    {criticalCount} critical
                  </motion.span>
                )}
              </div>

              {/* Cards */}
              {isLoading ? (
                <div className="space-y-2">
                  {[1, 2, 3, 4, 5].map(i => (
                    <div key={i} className="h-14 rounded-[14px] animate-pulse" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }} />
                  ))}
                </div>
              ) : visible.length === 0 ? (
                <div className="py-20 text-center">
                  <Search className="h-8 w-8 text-zinc-700 mx-auto mb-3" />
                  <p className="text-sm text-zinc-600">No techniques match</p>
                </div>
              ) : (
                <motion.div className="space-y-2" layout>
                  {visible.map((tech, i) => (
                    <motion.div
                      key={tech.id}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.04, duration: 0.3 }}
                    >
                      <TechCard
                        tech={tech}
                        isOpen={openId === tech.id}
                        onToggle={() => setOpenId(openId === tech.id ? null : tech.id)}
                        tabColor={tab.color}
                        tabRgb={tab.rgb}
                      />
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </div>

            {/* Right: info panel */}
            <div className="space-y-3">
              {/* Module detail */}
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-[18px] overflow-hidden"
                style={{ border: `1px solid rgba(${tab.rgb},0.2)`, background: `linear-gradient(160deg, rgba(${tab.rgb},0.06) 0%, rgba(0,0,0,0.8) 100%)` }}
              >
                <div className="p-4 border-b" style={{ borderColor: `rgba(${tab.rgb},0.12)` }}>
                  <div className="flex items-center gap-2 mb-1">
                    <tab.icon className="h-3.5 w-3.5" style={{ color: tab.color }} />
                    <span className="text-[11px] font-bold uppercase tracking-[0.18em]" style={{ color: tab.color, ...MONO }}>{tab.short}</span>
                  </div>
                  <p className="text-[10px] leading-relaxed text-zinc-500">{tab.note}</p>
                </div>
                <div className="p-4">
                  <div className="text-[9px] font-bold uppercase tracking-[0.22em] text-zinc-600 mb-2" style={MONO}>Coverage</div>
                  {TAB_TECHNIQUE_IDS[activeTab].slice(0, 6).map(id => (
                    <div key={id} className="flex items-center gap-2 py-1">
                      <div className="h-1 w-1 rounded-full shrink-0" style={{ background: tab.color, opacity: 0.6 }} />
                      <span className="text-[9px] text-zinc-600 truncate" style={MONO}>{id}</span>
                    </div>
                  ))}
                  {TAB_TECHNIQUE_IDS[activeTab].length > 6 && (
                    <div className="text-[9px] text-zinc-700 mt-1 pl-3" style={MONO}>+{TAB_TECHNIQUE_IDS[activeTab].length - 6} more</div>
                  )}
                </div>
              </motion.div>

              {/* Risk breakdown */}
              {!isLoading && visible.length > 0 && (
                <div className="rounded-[18px] p-4 space-y-3" style={{ border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.5)' }}>
                  <div className="text-[9px] font-bold uppercase tracking-[0.25em] text-zinc-600" style={MONO}>Risk Distribution</div>
                  {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(level => {
                    const count = visible.filter(t => t.risk_level?.toUpperCase() === level).length
                    if (count === 0) return null
                    const pct = Math.round((count / visible.length) * 100)
                    return (
                      <div key={level} className="space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="text-[9px] font-black uppercase tracking-wider" style={{ color: RISK[level].color, ...MONO }}>{level}</span>
                          <span className="text-[9px] text-zinc-600" style={MONO}>{count}</span>
                        </div>
                        <div className="h-1 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.04)' }}>
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${pct}%` }}
                            transition={{ duration: 0.7, ease: [0.23, 1, 0.32, 1] }}
                            className="h-full rounded-full"
                            style={{ background: RISK[level].color, boxShadow: `0 0 6px ${RISK[level].glow}` }}
                          />
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}

              {/* Credential triage priority */}
              <div className="rounded-[18px] p-4" style={{ border: '1px solid rgba(255,255,255,0.05)', background: 'rgba(0,0,0,0.4)' }}>
                <div className="text-[9px] font-bold uppercase tracking-[0.25em] text-zinc-600 mb-3" style={MONO}>Triage Priority</div>
                {[
                  { label: 'krbtgt hash', note: 'Golden Ticket access', color: '#ff4d6d' },
                  { label: 'NTLM hashes', note: 'PTH laterally', color: '#f97316' },
                  { label: 'DPAPI backup key', note: 'All user secrets', color: '#a78bfa' },
                  { label: 'Kerberos tickets', note: 'Pass-the-Ticket', color: '#ffd166' },
                ].map(({ label, note, color }) => (
                  <div key={label} className="flex items-start gap-2.5 py-1.5 border-b border-white/[0.03] last:border-0">
                    <div className="mt-1 h-1.5 w-1.5 rounded-full shrink-0" style={{ background: color, boxShadow: `0 0 4px ${color}88` }} />
                    <div>
                      <div className="text-[10px] font-semibold text-zinc-300" style={MONO}>{label}</div>
                      <div className="text-[9px] text-zinc-600">{note}</div>
                    </div>
                  </div>
                ))}
              </div>

              {/* OpSec warning */}
              <div
                className="rounded-[18px] p-4 flex items-start gap-3"
                style={{ border: '1px solid rgba(255,77,109,0.15)', background: 'rgba(255,77,109,0.04)' }}
              >
                <AlertTriangle className="h-3.5 w-3.5 text-red-400 shrink-0 mt-0.5" />
                <div className="text-[10px] leading-relaxed text-zinc-500">
                  All techniques require authenticated access. LSASS dumping triggers Defender/EDR alerts. Use EDR-evasive methods (nanodump, comsvcs) in hardened environments.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AppShell>
  )
}
