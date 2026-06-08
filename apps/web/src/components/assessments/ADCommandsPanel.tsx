'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useMemo, useCallback, useEffect, useRef } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Terminal, Copy, CheckCircle2, AlertCircle, Loader2,
  ChevronRight, Search, Zap, Monitor, Cpu,
  ClipboardCheck, XCircle, Globe, Target, Lock, User, Network,
  ShieldAlert, Filter, BookOpen, Layers,
  Crosshair, Radio, TrendingUp, Eye, Skull, History,
} from 'lucide-react'
import { adCommandsApi, ADTechnique, ADExecuteResult } from '@/lib/api'
import { obfuscateCommand, OBFUSCATION_TECHNIQUES, LEVEL_COLORS, TechniqueId } from '@/lib/powershellObfuscator'

export interface TargetConfig {
  ip: string
  domain: string
  baseDn: string
  ldapUrl: string
  username: string
  password: string
}

const TARGET_PARAM_MAP: Record<keyof TargetConfig, string[]> = {
  ip:       ['DC_IP', 'DC', 'Target', 'ComputerName', 'TargetComputer', 'TargetMachine', 'DC_HOSTNAME', 'DCName', 'DC1', 'DC2', 'TargetDC', 'OurDC', 'RootDC', 'ADCS_IP', 'DNSMachine', 'DNSServer'],
  domain:   ['Domain', 'DomainName', 'ExternalForest', 'ForestName', 'RootDomain', 'CurrentDomain', 'OurDomain'],
  baseDn:   ['BaseDN', 'BaseDn', 'SearchBase', 'Base', 'DomainDN', 'TargetDN'],
  ldapUrl:  ['LDAPUrl', 'LDAPURL', 'LdapUrl'],
  username: ['Username', 'User', 'UserName', 'DomainUser', 'AnyUser', 'creduser', 'AdminUser', 'Principal', 'TargetUser', 'AccountName'],
  password: ['Password', 'credpassword', 'MachinePassword'],
}

function buildDefaultParams(target: TargetConfig, params: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const p of params) {
    for (const [key, names] of Object.entries(TARGET_PARAM_MAP) as [keyof TargetConfig, string[]][]) {
      if (names.includes(p) && target[key]) { out[p] = target[key]; break }
    }
  }
  return out
}

function getErrorDetail(error: unknown, fallback: string): string {
  const axErr = error as { response?: { status?: number; data?: { detail?: unknown } }; code?: string; message?: string }
  const status = axErr?.response?.status
  const detail = axErr?.response?.data?.detail
  if (status === 504) return 'Command timed out (>180s). Try a faster variant or run manually.'
  if (status === 409) return 'Required tool not installed on this host. Copy command and run manually.'
  if (status === 403) return 'Execution not authorized. Ensure ENABLE_COMMAND_EXECUTION=true and you are superadmin.'
  if (status === 422) return typeof detail === 'string' ? `Missing params: ${detail}` : 'Missing required parameters.'
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map(String).join(', ')
  if (axErr?.code === 'ECONNABORTED') return 'Request timeout — proxy limit exceeded. Try a lighter command.'
  return error instanceof Error ? error.message : fallback
}

const CATEGORY_ACCENT: Record<string, string> = {
  'Domain Enumeration':          '#06b6d4',
  'Credential Attacks':          '#f43f5e',
  'Local Privilege Escalation':  '#f97316',
  'Lateral Movement':            '#a78bfa',
  'Domain Privilege Escalation': '#ef4444',
  'Domain Persistence':          '#eab308',
  'Cross Forest Attacks':        '#10b981',
  'SID History Abuse':           '#8b5cf6',
}

const CATEGORY_ICON: Record<string, React.ReactNode> = {
  'Domain Enumeration':          <Eye className="w-3 h-3" />,
  'Credential Attacks':          <Lock className="w-3 h-3" />,
  'Local Privilege Escalation':  <TrendingUp className="w-3 h-3" />,
  'Lateral Movement':            <Radio className="w-3 h-3" />,
  'Domain Privilege Escalation': <ShieldAlert className="w-3 h-3" />,
  'Domain Persistence':          <Crosshair className="w-3 h-3" />,
  'Cross Forest Attacks':        <Globe className="w-3 h-3" />,
  'SID History Abuse':           <Zap className="w-3 h-3" />,
}

const PLATFORM_BADGE: Record<string, { label: string; color: string; border: string }> = {
  linux:   { label: 'Linux',   color: 'rgba(6,182,212,0.15)',   border: 'rgba(6,182,212,0.35)'  },
  windows: { label: 'Windows', color: 'rgba(139,92,246,0.15)',  border: 'rgba(139,92,246,0.35)' },
  both:    { label: 'Both',    color: 'rgba(34,197,94,0.12)',   border: 'rgba(34,197,94,0.3)'   },
}

const RISK_COLORS: Record<string, { bg: string; border: string; text: string; glow: string }> = {
  HIGH:   { bg: 'rgba(248,113,113,0.12)', border: 'rgba(248,113,113,0.4)',  text: '#fca5a5', glow: 'rgba(248,113,113,0.25)' },
  MEDIUM: { bg: 'rgba(251,191,36,0.10)',  border: 'rgba(251,191,36,0.35)',  text: '#fde68a', glow: 'rgba(251,191,36,0.2)'  },
  LOW:    { bg: 'rgba(34,197,94,0.10)',   border: 'rgba(34,197,94,0.3)',    text: '#86efac', glow: 'rgba(34,197,94,0.2)'   },
}


interface ExecutionState {
  techniqueId: string; cmdIndex: number; params: Record<string, string>
  result: ADExecuteResult | null; error: string | null
}

function PlatformBadge({ platform }: { platform: string }) {
  const b = PLATFORM_BADGE[platform] ?? PLATFORM_BADGE.both
  const Icon = platform === 'linux' ? Monitor : platform === 'windows' ? Cpu : Globe
  return (
    <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider"
      style={{ background: b.color, border: `1px solid ${b.border}`, color: b.border }}>
      <Icon className="w-2.5 h-2.5" />{b.label}
    </span>
  )
}

function RiskBadge({ risk }: { risk: string }) {
  const c = RISK_COLORS[risk] ?? RISK_COLORS.LOW
  return (
    <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase tracking-wider"
      style={{ background: c.bg, border: `1px solid ${c.border}`, color: c.text, boxShadow: `0 0 8px ${c.glow}` }}>
      <ShieldAlert className="w-2.5 h-2.5" />{risk}
    </span>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = useCallback(async () => {
    await copyText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1800)
  }, [text])
  return (
    <button onClick={copy}
      className="flex items-center gap-1 rounded-lg px-2 py-1 text-[10px] transition-all duration-200 hover:scale-105"
      style={{
        background: copied ? 'rgba(34,197,94,0.12)' : 'rgba(255,255,255,0.04)',
        border: `1px solid ${copied ? 'rgba(34,197,94,0.4)' : 'rgba(255,255,255,0.1)'}`,
        color: copied ? '#86efac' : 'rgba(161,161,170,0.7)',
      }}>
      {copied ? <ClipboardCheck className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}


function Glass3DCard({ children, className = '', accent = '#06b6d4', active = false }: {
  children: React.ReactNode; className?: string; accent?: string; active?: boolean
}) {
  const r = useRef<HTMLDivElement>(null)
  const [tilt, setTilt] = useState({ x: 0, y: 0 })
  const [gp, setGp] = useState({ x: 50, y: 50 })
  const [hov, setHov] = useState(false)

  const onMove = useCallback((e: React.MouseEvent) => {
    const el = r.current; if (!el) return
    const rect = el.getBoundingClientRect()
    const dx = (e.clientX - rect.left - rect.width / 2) / (rect.width / 2)
    const dy = (e.clientY - rect.top - rect.height / 2) / (rect.height / 2)
    setTilt({ x: dy * -6, y: dx * 6 })
    setGp({ x: ((e.clientX - rect.left) / rect.width) * 100, y: ((e.clientY - rect.top) / rect.height) * 100 })
  }, [])

  return (
    <div ref={r} onMouseMove={onMove}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => { setTilt({ x: 0, y: 0 }); setHov(false) }}
      style={{ perspective: '1200px' }} className={className}>
      <div style={{
        transform: `rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`,
        transition: hov ? 'transform .06s ease-out' : 'transform .7s cubic-bezier(.23,1,.32,1)',
        transformStyle: 'preserve-3d', position: 'relative',
        background: active ? `${accent}14` : 'rgba(8,5,20,0.52)',
        border: `1px solid ${active ? `${accent}50` : 'rgba(255,255,255,0.08)'}`,
        borderRadius: '16px',
        backdropFilter: 'blur(16px)',
        boxShadow: active
          ? `0 0 28px ${accent}22, 0 8px 32px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.08)`
          : `0 4px 24px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.05)`,
      }}>
        <div className="pointer-events-none absolute inset-0 rounded-[16px] z-20 transition-opacity duration-200"
          style={{
            opacity: hov ? 0.1 : 0,
            background: `radial-gradient(circle at ${gp.x}% ${gp.y}%, rgba(200,160,255,.9) 0%, transparent 55%)`,
          }} />
        <div className="pointer-events-none absolute inset-x-0 top-0 h-px rounded-t-[16px]"
          style={{ background: `linear-gradient(90deg, transparent, ${accent}60, transparent)`, opacity: active ? 1 : 0.3 }} />
        {children}
      </div>
    </div>
  )
}

const TARGET_FIELDS = [
  { key: 'ip'       as const, label: 'Target IP / DC', icon: <Network className="w-3 h-3" />, placeholder: '192.168.1.100' },
  { key: 'domain'   as const, label: 'Domain',         icon: <Globe className="w-3 h-3" />,   placeholder: 'corp.local' },
  { key: 'baseDn'   as const, label: 'Base DN',        icon: <Layers className="w-3 h-3" />,  placeholder: 'DC=corp,DC=local' },
  { key: 'ldapUrl'  as const, label: 'LDAP URL',       icon: <Radio className="w-3 h-3" />,   placeholder: 'ldap://192.168.1.100:389' },
  { key: 'username' as const, label: 'Username',       icon: <User className="w-3 h-3" />,    placeholder: 'administrator' },
  { key: 'password' as const, label: 'Password',       icon: <Lock className="w-3 h-3" />,    placeholder: '••••••••', type: 'password' as const },
]

function TargetBar({ target, onChange, obfuscationEnabled, onObfuscationToggle, obfuscTech, onTechniqueChange }: {
  target: TargetConfig; onChange: (t: TargetConfig) => void
  obfuscationEnabled: boolean; onObfuscationToggle: () => void
  obfuscTech: TechniqueId; onTechniqueChange: (t: TechniqueId) => void
}) {
  const selectedTech = OBFUSCATION_TECHNIQUES.find(t => t.id === obfuscTech)
  const hasTarget = !!(target.ip || target.domain || target.ldapUrl)

  return (
    <div className="flex-shrink-0 px-5 py-3.5 relative overflow-hidden"
      style={{ borderBottom: '1px solid rgba(255,255,255,0.07)', background: '#000', backdropFilter: 'blur(20px)' }}>
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px"
        style={{ background: 'linear-gradient(90deg,transparent,rgba(239,68,68,0.7),transparent)' }} />
      <div className="flex items-center gap-3 mb-3">
        <div className="flex items-center gap-2">
          <Target className="w-3.5 h-3.5" style={{ color: hasTarget ? '#f87171' : 'rgba(161,161,170,0.4)' }} />
          <span className="text-[9px] uppercase tracking-[0.28em] font-semibold"
            style={{ color: hasTarget ? '#f87171' : 'rgba(161,161,170,0.4)', fontFamily: 'JetBrains Mono, monospace' }}>
            Live Target
          </span>
          {hasTarget && (
            <span className="ml-1 rounded-full px-2 py-0.5 text-[9px] font-bold animate-pulse"
              style={{ background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.4)', color: '#f87171' }}>
              ARMED
            </span>
          )}
        </div>
        <div className="ml-auto flex items-center gap-2">
          {/* ── Obfuscation skull toggle ── */}
          <button
            onClick={onObfuscationToggle}
            title={obfuscationEnabled ? 'Obfuscation ON — click to disable' : 'Enable advanced PS obfuscation'}
            className="relative flex items-center gap-2 rounded-xl px-3 py-1.5 transition-all duration-300 select-none"
            style={{
              background: obfuscationEnabled
                ? 'rgba(239,68,68,0.15)'
                : 'rgba(255,255,255,0.04)',
              border: `1px solid ${obfuscationEnabled ? 'rgba(239,68,68,0.55)' : 'rgba(255,255,255,0.1)'}`,
              boxShadow: obfuscationEnabled
                ? '0 0 18px rgba(239,68,68,0.35), inset 0 0 12px rgba(239,68,68,0.08)'
                : 'none',
            }}
          >
            {/* Skull — glows red when on */}
            <Skull
              className="w-4 h-4 transition-all duration-300"
              style={{
                color: obfuscationEnabled ? '#f87171' : 'rgba(161,161,170,0.35)',
                filter: obfuscationEnabled
                  ? 'drop-shadow(0 0 6px rgba(239,68,68,0.9)) drop-shadow(0 0 12px rgba(239,68,68,0.5))'
                  : 'none',
                animation: obfuscationEnabled ? 'skullPulse 2s ease-in-out infinite' : 'none',
              }}
            />
            {/* Pill switch track */}
            <div
              className="relative w-8 h-4 rounded-full transition-all duration-300"
              style={{
                background: obfuscationEnabled ? 'rgba(239,68,68,0.45)' : 'rgba(255,255,255,0.08)',
                border: `1px solid ${obfuscationEnabled ? 'rgba(239,68,68,0.7)' : 'rgba(255,255,255,0.12)'}`,
                boxShadow: obfuscationEnabled ? '0 0 8px rgba(239,68,68,0.4)' : 'none',
              }}
            >
              <div
                className="absolute top-[2px] w-[10px] h-[10px] rounded-full transition-all duration-300"
                style={{
                  left: obfuscationEnabled ? 'calc(100% - 12px)' : '2px',
                  background: obfuscationEnabled ? '#f87171' : 'rgba(161,161,170,0.4)',
                  boxShadow: obfuscationEnabled ? '0 0 8px rgba(239,68,68,0.9)' : 'none',
                }}
              />
            </div>
            <span
              className="text-[9px] font-black uppercase tracking-[0.22em] transition-colors duration-300"
              style={{
                fontFamily: 'JetBrains Mono, monospace',
                color: obfuscationEnabled ? '#f87171' : 'rgba(161,161,170,0.35)',
                letterSpacing: '0.22em',
              }}
            >
              OBFSC
            </span>
            {/* Pulsing outer glow ring when active */}
            {obfuscationEnabled && (
              <span
                className="pointer-events-none absolute inset-0 rounded-xl"
                style={{ animation: 'obfscGlow 2s ease-in-out infinite', border: '1px solid rgba(239,68,68,0.3)' }}
              />
            )}
          </button>

          <span className="flex items-center gap-1.5 rounded-xl px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider"
            style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#f87171' }}>
            <Skull className="w-3 h-3" /> GOD MODE
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-2">
        {TARGET_FIELDS.map(({ key, label, icon, placeholder, type }) => (
          <div key={key}>
            <label className="flex items-center gap-1 text-[9px] uppercase tracking-wider mb-1.5"
              style={{ color: 'rgba(100,116,139,0.8)', fontFamily: 'JetBrains Mono, monospace' }}>
              {icon} {label}
            </label>
            <div className="relative">
              <input
                type={type ?? 'text'} placeholder={placeholder} value={target[key]}
                autoComplete={type === 'password' ? 'new-password' : 'off'}
                onChange={(e) => onChange({ ...target, [key]: e.target.value })}
                className="w-full rounded-xl px-3 py-2 text-[11px] font-mono text-zinc-200 outline-none transition-all"
                style={{
                  background: target[key] ? 'rgba(6,182,212,0.07)' : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${target[key] ? 'rgba(6,182,212,0.25)' : 'rgba(255,255,255,0.08)'}`,
                  caretColor: '#67e8f9',
                }}
                onFocus={(e) => { e.currentTarget.style.borderColor = 'rgba(6,182,212,0.5)'; e.currentTarget.style.background = 'rgba(6,182,212,0.1)' }}
                onBlur={(e) => { e.currentTarget.style.borderColor = target[key] ? 'rgba(6,182,212,0.25)' : 'rgba(255,255,255,0.08)'; e.currentTarget.style.background = target[key] ? 'rgba(6,182,212,0.07)' : 'rgba(255,255,255,0.03)' }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* ── Technique selector strip (slides in when obfuscation active) ── */}
      <AnimatePresence>
        {obfuscationEnabled && (
          <motion.div
            key="tech-strip"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.28, ease: [0.23, 1, 0.32, 1] }}
            className="overflow-hidden"
          >
            <div className="pt-3">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-[9px] font-black uppercase tracking-[0.25em]"
                  style={{ color: 'rgba(239,68,68,0.55)', fontFamily: 'JetBrains Mono, monospace' }}>
                  Obfuscation Technique
                </span>
                {selectedTech && (
                  <span className="text-[8px] font-bold rounded px-1.5 py-0.5"
                    style={{ background: `${LEVEL_COLORS[selectedTech.level]}15`, border: `1px solid ${LEVEL_COLORS[selectedTech.level]}35`, color: LEVEL_COLORS[selectedTech.level] }}>
                    {selectedTech.level} · {selectedTech.name}
                  </span>
                )}
              </div>
              {/* Horizontal scrollable chip row */}
              <div className="flex gap-1.5 overflow-x-auto pb-1 scrollbar-none" style={{ scrollbarWidth: 'none' }}>
                {OBFUSCATION_TECHNIQUES.map(tech => {
                  const active = obfuscTech === tech.id
                  const lvlColor = LEVEL_COLORS[tech.level]
                  return (
                    <button
                      key={String(tech.id)}
                      onClick={() => onTechniqueChange(tech.id)}
                      title={`${tech.name}: ${tech.desc}`}
                      className="flex-shrink-0 rounded-xl px-3 py-2 text-left transition-all duration-200 relative overflow-hidden"
                      style={{
                        background: active ? 'rgba(239,68,68,0.14)' : 'rgba(255,255,255,0.03)',
                        border: `1px solid ${active ? 'rgba(239,68,68,0.55)' : 'rgba(255,255,255,0.08)'}`,
                        boxShadow: active ? '0 0 10px rgba(239,68,68,0.2)' : 'none',
                        minWidth: '68px',
                      }}
                    >
                      {active && (
                        <div className="pointer-events-none absolute inset-x-0 top-0 h-px"
                          style={{ background: 'linear-gradient(90deg,transparent,rgba(239,68,68,0.8),transparent)' }} />
                      )}
                      <div className="text-[9px] font-black font-mono"
                        style={{ color: active ? '#f87171' : 'rgba(226,232,240,0.55)' }}>
                        {tech.shortName}
                      </div>
                      <div className="mt-0.5 text-[7px] font-bold uppercase"
                        style={{ color: lvlColor, opacity: active ? 1 : 0.6 }}>
                        {tech.level}
                      </div>
                    </button>
                  )
                })}
              </div>
              {/* Description of currently selected technique */}
              {selectedTech && (
                <div className="mt-2 rounded-lg px-3 py-1.5 text-[9px] leading-4"
                  style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)', color: 'rgba(252,165,165,0.7)', fontFamily: 'JetBrains Mono, monospace' }}>
                  <span className="text-red-400/90 font-bold">{selectedTech.tag} · </span>{selectedTech.desc}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function CommandCard({
  cmd, cmdIndex, technique, defaultParams, onRun, isRunning, execution, obfuscationEnabled, obfuscTech,
}: {
  cmd: { label: string; command: string; params: string[]; platform: string; execution_mode?: 'argv' | 'manual' }
  cmdIndex: number; technique: ADTechnique; defaultParams: Record<string, string>
  onRun: (techniqueId: string, cmdIndex: number, params: Record<string, string>) => void
  isRunning: boolean; execution: ExecutionState | null
  obfuscationEnabled: boolean; obfuscTech: TechniqueId
}) {
  const [paramValues, setParamValues] = useState<Record<string, string>>(defaultParams)

  useEffect(() => {
    setParamValues((prev) => {
      const merged = { ...defaultParams }
      for (const [k, v] of Object.entries(prev)) { if (!defaultParams[k] && v) merged[k] = v }
      return merged
    })
  }, [defaultParams])

  const isManualOnly = cmd.execution_mode !== 'argv'
  const canExecute = technique.execution_supported && cmd.platform !== 'windows' && !isManualOnly
  const isThisRunning = isRunning && execution?.techniqueId === technique.id && execution?.cmdIndex === cmdIndex
  const thisResult = execution?.techniqueId === technique.id && execution?.cmdIndex === cmdIndex ? execution : null

  const rawFilledCommand = useMemo(() => {
    let c = cmd.command
    for (const [k, v] of Object.entries(paramValues)) { c = c.replace(new RegExp(`\\{${k}\\}`, 'g'), v || `{${k}}`) }
    return c
  }, [cmd.command, paramValues])

  const filledCommand = useMemo(
    () => obfuscationEnabled ? obfuscateCommand(rawFilledCommand, obfuscTech) : rawFilledCommand,
    [rawFilledCommand, obfuscationEnabled, obfuscTech]
  )

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-2xl overflow-hidden"
      style={{
        background: '#000',
        border: canExecute ? '1px solid rgba(239,68,68,0.15)' : '1px solid rgba(255,255,255,0.07)',
        backdropFilter: 'blur(12px)',
      }}>
      <div className="flex items-center justify-between gap-3 px-4 py-3"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <div className="flex items-center gap-2 min-w-0">
          <Terminal className="w-3.5 h-3.5 flex-shrink-0 text-zinc-500" />
          <span className="text-sm font-medium text-zinc-200 truncate">{cmd.label}</span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <PlatformBadge platform={cmd.platform} />
          <CopyButton text={filledCommand} />
        </div>
      </div>

      <div className="px-4 pb-4 pt-3">
        {obfuscationEnabled && (
          <div className="mb-2 flex items-center gap-2 rounded-lg px-3 py-1.5 text-[9px] font-bold uppercase tracking-[0.2em]"
            style={{
              background: 'rgba(239,68,68,0.08)',
              border: '1px solid rgba(239,68,68,0.22)',
              color: '#f87171',
              fontFamily: 'JetBrains Mono, monospace',
            }}>
            <Skull className="w-3 h-3" style={{ filter: 'drop-shadow(0 0 4px rgba(239,68,68,0.8))' }} />
            OBFUSCATED · copy-safe · AV-evasion layer active
          </div>
        )}
        <pre className="rounded-xl px-4 py-3 text-xs leading-relaxed overflow-x-auto whitespace-pre-wrap break-all font-mono"
          style={{
            background: '#000',
            color: obfuscationEnabled ? '#fca5a5' : '#c4b5fd',
            border: `1px solid ${obfuscationEnabled ? 'rgba(239,68,68,0.18)' : 'rgba(255,255,255,0.06)'}`,
            letterSpacing: '0.01em',
            boxShadow: obfuscationEnabled ? '0 0 12px rgba(239,68,68,0.08) inset' : 'none',
          }}>
          {filledCommand}
        </pre>

        {cmd.params.length > 0 && (
          <div className="mt-3 grid gap-2 sm:grid-cols-2">
            {cmd.params.map((param) => {
              const isFromTarget = Object.values(TARGET_PARAM_MAP).some((names) => names.includes(param)) && !!defaultParams[param]
              return (
                <div key={param}>
                  <label className="flex items-center gap-1 text-[9px] uppercase tracking-wider mb-1.5"
                    style={{ color: isFromTarget ? 'rgba(6,182,212,0.7)' : 'rgba(161,161,170,0.5)', fontFamily: 'JetBrains Mono, monospace' }}>
                    {isFromTarget && <Target className="w-2.5 h-2.5" />}{param}
                    {isFromTarget && <span style={{ color: 'rgba(6,182,212,0.5)' }}>(auto)</span>}
                  </label>
                  <input
                    type={param.toLowerCase().includes('password') ? 'password' : 'text'}
                    placeholder={`{${param}}`} value={paramValues[param] ?? ''}
                    onChange={(e) => setParamValues((p) => ({ ...p, [param]: e.target.value }))}
                    className="w-full rounded-xl px-3 py-2 text-xs font-mono text-zinc-200 outline-none transition-all"
                    style={{
                      background: isFromTarget ? 'rgba(6,182,212,0.07)' : 'rgba(255,255,255,0.03)',
                      border: `1px solid ${isFromTarget ? 'rgba(6,182,212,0.22)' : 'rgba(255,255,255,0.08)'}`,
                    }}
                    onFocus={(e) => { e.currentTarget.style.borderColor = 'rgba(6,182,212,0.5)' }}
                    onBlur={(e) => { e.currentTarget.style.borderColor = isFromTarget ? 'rgba(6,182,212,0.22)' : 'rgba(255,255,255,0.08)' }}
                  />
                </div>
              )
            })}
          </div>
        )}

        {canExecute && (
          <div className="mt-3 flex items-center gap-3">
            <button disabled={isThisRunning} onClick={() => onRun(technique.id, cmdIndex, paramValues)}
              className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-bold uppercase tracking-wider transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed hover:scale-[1.02]"
              style={{
                background: isThisRunning ? 'rgba(239,68,68,0.08)' : 'linear-gradient(135deg, rgba(239,68,68,0.22), rgba(220,38,38,0.15))',
                border: '1px solid rgba(239,68,68,0.5)', color: '#f87171',
                boxShadow: isThisRunning ? 'none' : '0 0 20px rgba(239,68,68,0.2)',
              }}>
              {isThisRunning ? <><Loader2 className="w-3 h-3 animate-spin" /> Executing...</> : <><Skull className="w-3 h-3" /> Fire</>}
            </button>
            <span className="text-[10px] font-mono" style={{ color: 'rgba(239,68,68,0.5)' }}>live execution</span>
          </div>
        )}

        {!canExecute && (
          <div className="mt-3 rounded-xl px-3 py-2.5 text-[11px] leading-relaxed flex items-center gap-2"
            style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)', color: '#52525b' }}>
            <Cpu className="w-3 h-3 flex-shrink-0" />
            {isManualOnly
              ? 'Manual-only command — copy and run in the appropriate shell.'
              : cmd.platform === 'windows'
              ? 'Windows-only command — copy and run on a domain-joined Windows host.'
              : technique.execution_disabled_reason ?? 'Tool not available on this host. Copy command and run manually.'}
          </div>
        )}

        {thisResult?.result && (
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
            className="mt-3 rounded-xl overflow-hidden"
            style={{ border: `1px solid ${thisResult.result.exit_code === 0 ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`, boxShadow: thisResult.result.exit_code === 0 ? '0 0 20px rgba(34,197,94,0.08)' : '0 0 20px rgba(239,68,68,0.08)' }}>
            <div className="flex items-center justify-between px-3 py-2 text-[10px] font-mono"
              style={{ background: '#000', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
              <div className="flex items-center gap-2">
                <History className="w-3 h-3" style={{ color: 'rgba(161,161,170,0.4)' }} />
                <span className="uppercase tracking-widest text-[9px] font-bold" style={{ color: 'rgba(161,161,170,0.5)' }}>AD Recon Output</span>
                <span className="mx-1" style={{ color: 'rgba(255,255,255,0.15)' }}>·</span>
                {thisResult.result.exit_code === 0
                  ? <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  : <XCircle className="w-3 h-3 text-red-400" />}
                <span style={{ color: thisResult.result.exit_code === 0 ? '#86efac' : '#fca5a5' }}>
                  exit {thisResult.result.exit_code}
                </span>
              </div>
              <span className="text-zinc-700 truncate max-w-[200px]">
                {thisResult.result.rendered_command.slice(0, 55)}{thisResult.result.rendered_command.length > 55 ? '…' : ''}
              </span>
            </div>
            {thisResult.result.stdout && (
              <pre className="px-3 py-2 text-xs font-mono overflow-x-auto max-h-64 whitespace-pre-wrap"
                style={{ color: '#a7f3d0', background: '#000' }}>
                {thisResult.result.stdout}
              </pre>
            )}
            {thisResult.result.stderr && (
              <pre className="px-3 py-2 text-xs font-mono overflow-x-auto max-h-40 whitespace-pre-wrap"
                style={{ color: '#fca5a5', background: 'rgba(239,68,68,0.04)', borderTop: '1px solid rgba(239,68,68,0.12)' }}>
                {thisResult.result.stderr}
              </pre>
            )}
          </motion.div>
        )}

        {thisResult?.error && (
          <motion.div initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
            className="mt-2 rounded-xl overflow-hidden"
            style={{ border: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.06)' }}>
            <div className="flex items-center gap-2 px-3 py-1.5"
              style={{ borderBottom: '1px solid rgba(239,68,68,0.15)', background: '#000' }}>
              <History className="w-3 h-3" style={{ color: 'rgba(161,161,170,0.4)' }} />
              <span className="uppercase tracking-widest text-[9px] font-bold" style={{ color: 'rgba(161,161,170,0.5)' }}>AD Recon Output</span>
              <XCircle className="w-3 h-3 ml-auto text-red-400" />
              <span className="text-[10px]" style={{ color: '#fca5a5' }}>error</span>
            </div>
            <div className="flex items-start gap-2 px-3 py-2 text-xs font-mono" style={{ color: '#fca5a5' }}>
              <AlertCircle className="w-3 h-3 flex-shrink-0 mt-0.5" />
              <span>{thisResult.error}</span>
            </div>
          </motion.div>
        )}
      </div>
    </motion.div>
  )
}

function TechniqueDetail({ technique, target, onRun, isRunning, execution, obfuscationEnabled, obfuscTech }: {
  technique: ADTechnique; target: TargetConfig
  onRun: (id: string, idx: number, params: Record<string, string>) => void
  isRunning: boolean; execution: ExecutionState | null
  obfuscationEnabled: boolean; obfuscTech: TechniqueId
}) {
  const accent = CATEGORY_ACCENT[technique.category] ?? '#a78bfa'

  return (
    <div className="h-full flex flex-col min-h-0">
      <div className="flex-shrink-0 px-6 py-5 relative overflow-hidden"
        style={{ borderBottom: '1px solid rgba(255,255,255,0.07)', background: '#000', backdropFilter: 'blur(20px)' }}>
        <div className="pointer-events-none absolute inset-x-0 top-0 h-px"
          style={{ background: `linear-gradient(90deg, transparent, ${accent}70, transparent)` }} />
        <div className="pointer-events-none absolute top-0 right-0 w-64 h-32 opacity-10"
          style={{ background: `radial-gradient(circle at top right, ${accent}, transparent 70%)` }} />

        <div className="relative flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2 mb-3">
              <span className="inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-widest"
                style={{ background: `${accent}18`, border: `1px solid ${accent}35`, color: accent, boxShadow: `0 0 14px ${accent}20` }}>
                {CATEGORY_ICON[technique.category] ?? <Zap className="w-3 h-3" />}
                {technique.category}
              </span>
              <PlatformBadge platform={technique.platform} />
              <RiskBadge risk={technique.risk_level ?? 'MEDIUM'} />
              {technique.execution_supported && (
                <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold"
                  style={{ background: 'rgba(6,182,212,0.12)', border: '1px solid rgba(6,182,212,0.3)', color: '#67e8f9', boxShadow: '0 0 10px rgba(6,182,212,0.15)' }}>
                  <Zap className="w-2.5 h-2.5" /> Executable
                </span>
              )}
              {technique.id.startsWith('pen200-') && (
                <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold"
                  style={{ background: 'rgba(251,146,60,0.12)', border: '1px solid rgba(251,146,60,0.3)', color: '#fdba74', fontFamily: 'JetBrains Mono, monospace' }}>
                  <BookOpen className="w-2.5 h-2.5" /> PEN-200
                </span>
              )}
            </div>
            <h3 className="text-lg font-bold text-white leading-tight">{technique.title}</h3>
            <p className="mt-1.5 text-sm text-zinc-400 leading-relaxed max-w-2xl">{technique.description}</p>
            <div className="mt-3 flex items-center gap-3 flex-wrap">
              <span className="text-[11px] font-mono" style={{ color: `${accent}80` }}>
                {technique.tool}
              </span>
              <span className="text-zinc-700">·</span>
              <span className="text-[11px] text-zinc-500">{technique.commands.length} command{technique.commands.length !== 1 ? 's' : ''}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-3">
        {technique.commands.map((cmd, idx) => (
          <CommandCard
            key={`${technique.id}-${idx}`}
            cmd={cmd} cmdIndex={idx} technique={technique}
            defaultParams={buildDefaultParams(target, cmd.params)}
            onRun={onRun} isRunning={isRunning} execution={execution}
            obfuscationEnabled={obfuscationEnabled}
            obfuscTech={obfuscTech}
          />
        ))}
      </div>
    </div>
  )
}

export function ADCommandsPanel({
  initialTarget,
  initialLinuxOnly = true,
  obfuscationEnabled: obfuscationProp,
  obfuscationTechnique: techniqueProp,
  onObfuscationChange,
  onTechniqueChange,
}: {
  initialTarget?: Partial<TargetConfig>
  initialLinuxOnly?: boolean
  obfuscationEnabled?: boolean
  obfuscationTechnique?: TechniqueId
  onObfuscationChange?: (v: boolean) => void
  onTechniqueChange?: (t: TechniqueId) => void
}) {
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const [selectedTechnique, setSelectedTechnique] = useState<ADTechnique | null>(null)
  const [search, setSearch] = useState('')
  const [linuxOnly, setLinuxOnly] = useState(initialLinuxOnly)
  const [riskFilter, setRiskFilter] = useState<string | null>(null)
  const [execution, setExecution] = useState<ExecutionState | null>(null)
  // Obfuscation — controlled from parent if prop provided, otherwise internal state
  const [obfuscationInternal, setObfuscationInternal] = useState(false)
  const [techniqueInternal, setTechniqueInternal] = useState<TechniqueId>('auto')
  const obfuscationEnabled = obfuscationProp ?? obfuscationInternal
  const obfuscTech: TechniqueId = techniqueProp ?? techniqueInternal
  const handleObfuscationToggle = useCallback(() => {
    const next = !obfuscationEnabled
    if (onObfuscationChange) onObfuscationChange(next)
    else setObfuscationInternal(next)
  }, [obfuscationEnabled, onObfuscationChange])
  const handleTechniqueChange = useCallback((t: TechniqueId) => {
    if (onTechniqueChange) onTechniqueChange(t)
    else setTechniqueInternal(t)
  }, [onTechniqueChange])
  const [target, setTarget] = useState<TargetConfig>({
    ip: '192.168.56.10',
    domain: 'lab.local',
    baseDn: 'DC=lab,DC=local',
    ldapUrl: 'ldap://192.168.56.10:389',
    username: 'scanner@lab.local',
    password: '',
    ...initialTarget,
  })
  useEffect(() => {
    if (!initialTarget) return
    setTarget((current) => ({ ...current, ...initialTarget }))
  }, [initialTarget])

  const { data: categories = [], isError: categoriesError, refetch: refetchCategories } = useQuery({
    queryKey: ['ad-commands-categories'],
    queryFn: () => adCommandsApi.categories(),
    staleTime: 300_000, retry: 2,
  })

  const { data: techniquesRaw = [], isLoading, isError: techniquesError, refetch: refetchTechniques } = useQuery({
    queryKey: ['ad-commands-techniques', selectedCategory, search, linuxOnly],
    queryFn: () => adCommandsApi.techniques({
      category: selectedCategory ?? undefined,
      search: search.trim() || undefined,
      linux_only: linuxOnly || undefined,
    }),
    staleTime: 60_000, retry: 2,
  })

  const techniques = useMemo(
    () => riskFilter ? techniquesRaw.filter((t) => t.risk_level === riskFilter) : techniquesRaw,
    [techniquesRaw, riskFilter]
  )

  const executeMutation = useMutation({
    mutationFn: ({ id, idx, params }: { id: string; idx: number; params: Record<string, string> }) =>
      adCommandsApi.execute(id, idx, params),
    onMutate: ({ id, idx, params }) => { setExecution({ techniqueId: id, cmdIndex: idx, params, result: null, error: null }) },
    onSuccess: (result, { id, idx, params }) => { setExecution({ techniqueId: id, cmdIndex: idx, params, result, error: null }) },
    onError: (err, { id, idx, params }) => {
      setExecution({
        techniqueId: id,
        cmdIndex: idx,
        params,
        result: null,
        error: getErrorDetail(err, 'Command execution failed'),
      })
    },
  })

  const handleRun = useCallback((id: string, idx: number, params: Record<string, string>) => {
    executeMutation.mutate({ id, idx, params })
  }, [executeMutation])

  const totalCommands = useMemo(() => techniques.reduce((s, t) => s + t.commands.length, 0), [techniques])
  const executableCount = useMemo(() => techniques.filter(t => t.execution_supported).length, [techniques])

  return (
    <div className="flex flex-col h-full min-h-0 rounded-[24px] overflow-hidden"
      style={{ border: '1px solid rgba(239,68,68,0.2)', background: '#000', backdropFilter: 'blur(24px)', boxShadow: '0 0 60px rgba(239,68,68,0.05)' }}>

      <TargetBar
        target={target}
        onChange={setTarget}
        obfuscationEnabled={obfuscationEnabled}
        onObfuscationToggle={handleObfuscationToggle}
        obfuscTech={obfuscTech}
        onTechniqueChange={handleTechniqueChange}
      />


      <div className="flex flex-1 min-h-0 overflow-hidden">

        {/* ── Category Sidebar ─────────────────────────────────────────── */}
        <div className="w-52 flex-shrink-0 flex flex-col overflow-hidden"
          style={{ borderRight: '1px solid rgba(255,255,255,0.06)', background: '#000' }}>

          <div className="px-3 py-3 flex-shrink-0 space-y-2" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
            <div className="text-[9px] uppercase tracking-[0.3em] flex items-center gap-1.5 mb-1"
              style={{ color: 'rgba(161,161,170,0.4)', fontFamily: 'JetBrains Mono, monospace' }}>
              <Filter className="w-2.5 h-2.5" /> Filters
            </div>
            <button
              onClick={() => { setLinuxOnly((v) => !v); setSelectedCategory(null); setSelectedTechnique(null) }}
              className="w-full flex items-center gap-2 rounded-xl px-3 py-2 text-[11px] transition-all duration-200"
              style={{
                background: linuxOnly ? 'rgba(6,182,212,0.12)' : 'rgba(255,255,255,0.03)',
                border: `1px solid ${linuxOnly ? 'rgba(6,182,212,0.35)' : 'rgba(255,255,255,0.06)'}`,
                color: linuxOnly ? '#67e8f9' : 'rgba(161,161,170,0.5)',
                fontFamily: 'JetBrains Mono, monospace',
                boxShadow: linuxOnly ? '0 0 12px rgba(6,182,212,0.15)' : 'none',
              }}>
              <Monitor className="w-3 h-3 flex-shrink-0" />Linux only
            </button>
            <div className="flex gap-1">
              {(['HIGH', 'MEDIUM', 'LOW'] as const).map((r) => {
                const c = RISK_COLORS[r]; const active = riskFilter === r
                return (
                  <button key={r} onClick={() => { setRiskFilter(active ? null : r); setSelectedTechnique(null) }}
                    className="flex-1 rounded-lg py-1.5 text-[9px] font-bold uppercase tracking-wider transition-all duration-200"
                    style={{
                      background: active ? c.bg : 'rgba(255,255,255,0.02)',
                      border: `1px solid ${active ? c.border : 'rgba(255,255,255,0.06)'}`,
                      color: active ? c.text : 'rgba(161,161,170,0.35)',
                      boxShadow: active ? `0 0 10px ${c.glow}` : 'none',
                    }}>
                    {r[0]}
                  </button>
                )
              })}
            </div>
          </div>

          <nav className="flex-1 overflow-y-auto py-2 px-2">
            <div className="text-[8px] uppercase tracking-[0.3em] px-3 mb-2 mt-1"
              style={{ color: 'rgba(161,161,170,0.3)', fontFamily: 'JetBrains Mono, monospace' }}>
              Categories
            </div>
            <button onClick={() => { setSelectedCategory(null); setSelectedTechnique(null) }}
              className="w-full flex items-center justify-between gap-2 rounded-xl px-3 py-2.5 mb-1 text-[11px] transition-all duration-200"
              style={{
                background: selectedCategory === null ? 'rgba(255,255,255,0.07)' : 'transparent',
                border: `1px solid ${selectedCategory === null ? 'rgba(255,255,255,0.15)' : 'transparent'}`,
                color: selectedCategory === null ? '#f1f5f9' : 'rgba(161,161,170,0.5)',
                fontFamily: 'JetBrains Mono, monospace',
              }}>
              <span className="flex items-center gap-1.5 truncate"><Layers className="w-3 h-3 flex-shrink-0" />All</span>
              <span className="text-[9px] rounded-full px-1.5 py-0.5 flex-shrink-0"
                style={{ background: 'rgba(255,255,255,0.07)', color: 'rgba(161,161,170,0.6)' }}>
                {categories.reduce((s, c) => s + c.technique_count, 0)}
              </span>
            </button>

            {categories.map((cat) => {
              const accent = CATEGORY_ACCENT[cat.name] ?? '#a78bfa'
              const icon = CATEGORY_ICON[cat.name] ?? <Zap className="w-3 h-3" />
              const active = selectedCategory === cat.name
              return (
                <button key={cat.name} onClick={() => { setSelectedCategory(cat.name); setSelectedTechnique(null) }}
                  className="w-full flex items-start justify-between gap-2 rounded-xl px-3 py-2.5 mb-0.5 text-[11px] text-left transition-all duration-200"
                  style={{
                    background: active ? `${accent}14` : 'transparent',
                    border: `1px solid ${active ? `${accent}40` : 'transparent'}`,
                    color: active ? '#f1f5f9' : 'rgba(161,161,170,0.5)',
                    fontFamily: 'JetBrains Mono, monospace',
                    boxShadow: active ? `0 0 14px ${accent}18` : 'none',
                  }}>
                  <span className="flex items-start gap-1.5 flex-1 leading-snug">
                    <span className="mt-0.5 flex-shrink-0" style={{ color: active ? accent : 'rgba(161,161,170,0.35)' }}>{icon}</span>
                    <span className="leading-relaxed">{cat.name}</span>
                  </span>
                  <span className="mt-0.5 text-[9px] rounded-full px-1.5 py-0.5 flex-shrink-0"
                    style={{ background: `${accent}18`, color: accent, border: `1px solid ${accent}25` }}>
                    {cat.technique_count}
                  </span>
                </button>
              )
            })}
          </nav>

          {/* Stats strip */}
          <div className="flex-shrink-0 px-3 py-3 space-y-1.5"
            style={{ borderTop: '1px solid rgba(255,255,255,0.05)', background: '#000' }}>
            {[
              { label: 'Techniques', value: techniquesRaw.length, color: '#a78bfa' },
              { label: 'Executable', value: executableCount, color: '#67e8f9' },
              { label: 'Commands', value: totalCommands, color: '#fde68a' },
            ].map(s => (
              <div key={s.label} className="flex items-center justify-between">
                <span className="text-[9px] uppercase tracking-widest" style={{ color: 'rgba(161,161,170,0.35)', fontFamily: 'JetBrains Mono, monospace' }}>{s.label}</span>
                <span className="text-[11px] font-bold tabular-nums" style={{ color: s.color }}>{s.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Technique List ───────────────────────────────────────────── */}
        <div className="w-72 flex-shrink-0 flex flex-col overflow-hidden"
          style={{ borderRight: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="px-4 py-3.5 flex-shrink-0" style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', background: '#000' }}>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-600" />
              <input type="text" placeholder="Search techniques…" value={search}
                onChange={(e) => { setSearch(e.target.value); setSelectedTechnique(null) }}
                className="w-full rounded-xl pl-9 pr-3 py-2.5 text-xs outline-none transition-all"
                style={{
                  background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
                  color: '#e2e8f0', fontFamily: 'JetBrains Mono, monospace',
                }}
                onFocus={(e) => { e.currentTarget.style.borderColor = 'rgba(6,182,212,0.4)'; e.currentTarget.style.background = 'rgba(6,182,212,0.06)' }}
                onBlur={(e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.background = 'rgba(255,255,255,0.04)' }}
              />
            </div>
            <div className="mt-2 flex items-center gap-2 flex-wrap">
              <span className="text-[10px] font-mono" style={{ color: 'rgba(167,139,250,0.6)' }}>{techniques.length} techniques</span>
              <span className="text-zinc-700 text-[10px]">·</span>
              <span className="text-[10px] font-mono" style={{ color: 'rgba(6,182,212,0.5)' }}>{totalCommands} cmds</span>
              {riskFilter && (
                <button onClick={() => setRiskFilter(null)}
                  className="text-[9px] rounded-full px-2 py-0.5 flex items-center gap-1 ml-auto"
                  style={{ background: RISK_COLORS[riskFilter].bg, border: `1px solid ${RISK_COLORS[riskFilter].border}`, color: RISK_COLORS[riskFilter].text }}>
                  {riskFilter} <XCircle className="w-2.5 h-2.5" />
                </button>
              )}
            </div>
          </div>

          <div className="flex-1 overflow-y-auto py-2 px-2">
            {isLoading ? (
              <div className="flex items-center justify-center py-16">
                <Loader2 className="w-5 h-5 animate-spin text-zinc-600" />
              </div>
            ) : techniquesError || categoriesError ? (
              <div className="px-3 py-8 text-center">
                <AlertCircle className="w-5 h-5 mx-auto mb-2 text-red-500/60" />
                <div className="text-xs text-red-400/80 mb-1 font-mono">API unreachable</div>
                <div className="text-[10px] text-zinc-600 mb-3">Ensure the backend is running</div>
                <button onClick={() => { refetchCategories(); refetchTechniques() }}
                  className="text-[10px] rounded-lg px-3 py-1.5 transition-all"
                  style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)', color: 'rgba(161,161,170,0.7)', fontFamily: 'JetBrains Mono, monospace' }}>
                  Retry
                </button>
              </div>
            ) : techniques.length === 0 ? (
              <div className="px-4 py-10 text-center text-sm text-zinc-600 font-mono">No techniques match</div>
            ) : (
              techniques.map((t) => {
                const accent = CATEGORY_ACCENT[t.category] ?? '#a78bfa'
                const active = selectedTechnique?.id === t.id

                return (
                  <Glass3DCard key={t.id} accent={accent} active={active}
                    className="mb-1 cursor-pointer" >
                    <button onClick={() => setSelectedTechnique(t)}
                      className="w-full rounded-[16px] px-3 py-3 text-left transition-colors duration-150">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-1.5 mb-1.5">
                            <span style={{ color: accent, flexShrink: 0 }}>
                              {CATEGORY_ICON[t.category] ?? <Zap className="w-3 h-3" />}
                            </span>
                            <span className="text-xs font-semibold leading-snug" style={{ color: active ? '#f1f5f9' : 'rgba(226,232,240,0.75)' }}>
                              {t.title}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-[9px] truncate max-w-[80px] font-mono" style={{ color: `${accent}60` }}>
                              {t.tool.split('/')[0].trim()}
                            </span>
                            {t.executable_on_linux && (
                              <span className="inline-flex items-center gap-0.5 text-[9px] font-semibold" style={{ color: '#67e8f9' }}>
                                <Zap className="w-2 h-2" /> exec
                              </span>
                            )}
                            {t.risk_level === 'HIGH' && <span className="text-[9px] font-semibold" style={{ color: '#fca5a5' }}>HIGH</span>}
                            {t.id.startsWith('pen200-') && <span className="text-[9px] font-mono" style={{ color: '#fdba74' }}>PEN-200</span>}
                          </div>
                        </div>
                        <div className="flex flex-col items-end gap-1 flex-shrink-0">
                          <span className="text-[9px] rounded-full px-1.5 py-0.5 font-bold"
                            style={{ background: `${accent}18`, color: accent, border: `1px solid ${accent}25` }}>
                            {t.commands.length}
                          </span>
                          {t.execution_supported && <Zap className="w-3 h-3" style={{ color: '#f87171' }} />}
                          {active && <ChevronRight className="w-3 h-3" style={{ color: accent }} />}
                        </div>
                      </div>
                    </button>
                  </Glass3DCard>
                )
              })
            )}
          </div>
        </div>

        {/* ── Command Detail ───────────────────────────────────────────── */}
        <div className="flex-1 min-w-0 overflow-hidden flex flex-col" style={{ background: '#000' }}>
          <AnimatePresence mode="wait">
            {selectedTechnique ? (
              <motion.div key={selectedTechnique.id} initial={{ opacity: 0, x: 14 }} animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }} transition={{ duration: 0.22, ease: [0.23, 1, 0.32, 1] }}
                className="h-full overflow-hidden flex flex-col">
                <TechniqueDetail
                  technique={selectedTechnique} target={target}
                  onRun={handleRun} isRunning={executeMutation.isPending} execution={execution}
                  obfuscationEnabled={obfuscationEnabled}
                  obfuscTech={obfuscTech}
                />
              </motion.div>
            ) : (
              <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                className="flex-1 flex flex-col items-center justify-center p-10 text-center relative overflow-hidden">

                <div className="pointer-events-none absolute inset-0 opacity-[0.03]"
                  style={{ backgroundImage: 'linear-gradient(rgba(255,255,255,0.15) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.15) 1px,transparent 1px)', backgroundSize: '32px 32px' }} />

                <div className="relative">
                  <div className="w-20 h-20 rounded-2xl flex items-center justify-center mb-5 relative"
                    style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.1)' }}>
                    <div className="absolute inset-0 rounded-2xl animate-pulse"
                      style={{ background: 'radial-gradient(circle at center, rgba(167,139,250,0.1), transparent 70%)' }} />
                    <Terminal className="w-8 h-8 text-zinc-600" />
                  </div>

                  <div className="text-lg font-semibold text-white mb-2">Select a technique</div>
                  <div className="text-sm text-zinc-500 max-w-xs leading-relaxed">
                    {selectedCategory
                      ? `${techniques.length} techniques in ${selectedCategory}. Pick one to view all commands.`
                      : 'Choose a category then select a technique to view commands and execute against your target.'}
                  </div>

                  {!selectedCategory && categories.length > 0 && (
                    <div className="mt-8 grid grid-cols-2 gap-2 max-w-lg w-full">
                      {categories.map((cat) => {
                        const accent = CATEGORY_ACCENT[cat.name] ?? '#a78bfa'
                        const icon = CATEGORY_ICON[cat.name] ?? <Zap className="w-3 h-3" />
                        return (
                          <Glass3DCard key={cat.name} accent={accent}>
                            <button onClick={() => setSelectedCategory(cat.name)}
                              className="w-full rounded-[16px] px-4 py-3 text-left">
                              <div className="flex items-center gap-2 mb-1.5">
                                <span style={{ color: accent }}>{icon}</span>
                                <div className="font-semibold text-white text-xs leading-tight truncate">{cat.name}</div>
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="text-[10px] font-bold" style={{ color: accent }}>{cat.technique_count}</span>
                                <span className="text-[9px] text-zinc-600">techniques</span>
                                <span className="text-zinc-700">·</span>
                                <span className="text-[9px] text-zinc-500">{cat.linux_executable_count} linux</span>
                              </div>
                            </button>
                          </Glass3DCard>
                        )
                      })}
                    </div>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  )
}
