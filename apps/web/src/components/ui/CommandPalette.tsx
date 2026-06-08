'use client'

import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { AnimatePresence, motion } from 'framer-motion'
import {
  Activity,
  ArrowRight,
  BarChart3,
  Boxes,
  BrainCircuit,
  Command,
  Crosshair,
  Database,
  FileText,
  FlaskConical,
  GitBranch,
  Key,
  Layers,
  Loader2,
  Lock,
  Network,
  RotateCcw,
  Search,
  Settings,
  Shield,
  Swords,
  Target,
  Terminal,
  Workflow,
  Wifi,
  X,
} from 'lucide-react'

import { globalSearchApi } from '@/lib/api'
import { cn } from '@/lib/utils'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }
const RECENT_KEY = 'adbygod.commandPalette.recents.v3'

type CommandKind = 'page' | 'finding' | 'entity' | 'action'

interface CommandItem {
  id: string
  kind?: CommandKind
  label: string
  href?: string
  icon: React.ElementType
  section: string
  subtitle?: string
  keywords?: string[]
  severity?: string
  action?: () => void
}

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
}

const PAGE_COMMANDS: CommandItem[] = [
  { id: 'page-dashboard', label: 'Dashboard', href: '/', icon: BarChart3, section: 'Command Center', subtitle: 'Executive exposure overview and posture score', keywords: ['home', 'overview', 'summary', 'score'] },
  { id: 'page-assessments', label: 'Assessments', href: '/assessments', icon: Activity, section: 'Command Center', subtitle: 'Create, import, and manage assessment workspaces', keywords: ['collection', 'scan', 'import', 'ldap'] },
  { id: 'page-findings', label: 'Findings', href: '/findings', icon: Shield, section: 'Command Center', subtitle: 'Prioritized identity exposure findings', keywords: ['risk', 'issues', 'vulnerabilities', 'evidence'] },
  { id: 'page-ai-operator', label: 'AI Operator', href: '/ai-operator', icon: BrainCircuit, section: 'Command Center', subtitle: 'Assisted investigation, handoff briefs, and operator actions', keywords: ['ai', 'assistant', 'operator', 'handoff'] },
  { id: 'page-tool-checker', label: 'Tool Checker', href: '/tool-checker', icon: Terminal, section: 'Command Center', subtitle: 'Verify offensive tool availability and install coverage', keywords: ['tools', 'install', 'missing', 'kali'] },

  { id: 'page-recon', label: 'Recon', href: '/recon', icon: Search, section: 'Attack Workflow', subtitle: 'Discovery and target surface collection', keywords: ['p0', 'reconnaissance', 'enumerate', 'discover'] },
  { id: 'page-initial-access', label: 'Initial Access', href: '/initial-access', icon: Key, section: 'Attack Workflow', subtitle: 'Credential, relay, and entry-point techniques', keywords: ['p1', 'access', 'spray', 'relay', 'phish'] },
  { id: 'page-enumeration', label: 'Enumeration', href: '/enumeration', icon: Boxes, section: 'Attack Workflow', subtitle: 'Identity, host, domain, and service enumeration', keywords: ['p2', 'enum', 'users', 'shares', 'ldap'] },
  { id: 'page-priv-esc', label: 'Privilege Escalation', href: '/priv-esc', icon: Layers, section: 'Attack Workflow', subtitle: 'Local and domain privilege escalation mapping', keywords: ['p3', 'privesc', 'escalation', 'admin'] },
  { id: 'page-lateral', label: 'Lateral Movement', href: '/lateral-movement', icon: Network, section: 'Attack Workflow', subtitle: 'Movement paths, pivots, sessions, and remoting', keywords: ['p4', 'lateral', 'pivot', 'winrm', 'smb'] },
  { id: 'page-persistence', label: 'Persistence', href: '/persistence', icon: RotateCcw, section: 'Attack Workflow', subtitle: 'Persistence opportunities and durability checks', keywords: ['p5', 'persistence', 'backdoor', 'gpo'] },
  { id: 'page-loot', label: 'Loot', href: '/loot', icon: Database, section: 'Attack Workflow', subtitle: 'Hashes, tickets, secrets, and collected material', keywords: ['p6', 'hash', 'ticket', 'kirbi', 'secrets'] },
  { id: 'page-evasion', label: 'Evasion', href: '/evasion', icon: Shield, section: 'Attack Workflow', subtitle: 'Detection bypass, OPSEC, and stealth controls', keywords: ['p7', 'evasion', 'opsec', 'bypass'] },

  { id: 'page-graph', label: 'Graph Engine', href: '/graph', icon: GitBranch, section: 'Graph & Paths', subtitle: 'Explore identity relationships and attack graph data', keywords: ['bloodhound', 'nodes', 'edges', 'relationships'] },
  { id: 'page-paths', label: 'Attack Paths', href: '/paths', icon: Target, section: 'Graph & Paths', subtitle: 'Ranked privilege paths to high-value assets', keywords: ['path', 'da', 'domain admin', 'chain'] },
  { id: 'page-kill-chain', label: 'Kill Chain Tracker', href: '/kill-chain', icon: Workflow, section: 'Graph & Paths', subtitle: 'Track chained attack progression across phases', keywords: ['kill chain', 'chain', 'stages', 'progress'] },
  { id: 'page-trust-abuse', label: 'Trust Abuse', href: '/trust-abuse', icon: Network, section: 'Graph & Paths', subtitle: 'Trust relationship abuse and cross-boundary exposure', keywords: ['trust', 'forest', 'sid', 'hybrid'] },

  { id: 'page-validation', label: 'Validation Modules', href: '/validation', icon: Swords, section: 'Exposure Validation', subtitle: 'Run validation modules against collected evidence', keywords: ['modules', 'checks', 'validate'] },
  { id: 'page-remediation', label: 'Remediation Simulator', href: '/remediation', icon: Shield, section: 'Exposure Validation', subtitle: 'Preview risk reduction before changes', keywords: ['fix', 'simulate', 'mitigation'] },
  { id: 'page-assets', label: 'Assets & Identities', href: '/assets', icon: Boxes, section: 'Exposure Validation', subtitle: 'Users, groups, computers, and identities', keywords: ['entities', 'users', 'groups', 'computers'] },
  { id: 'page-pki', label: 'PKI / AD CS', href: '/pki', icon: Lock, section: 'Exposure Validation', subtitle: 'Certificate services posture and templates', keywords: ['adcs', 'certificates', 'ca', 'esc'] },
  { id: 'page-service-accounts', label: 'Service Accounts', href: '/service-accounts', icon: Key, section: 'Exposure Validation', subtitle: 'Service account exposure and Kerberoast posture', keywords: ['spn', 'kerberoast', 'accounts'] },
  { id: 'page-trusts', label: 'Trusts & Hybrid', href: '/trusts', icon: Network, section: 'Exposure Validation', subtitle: 'Trust relationships and hybrid identity posture', keywords: ['trust', 'azure', 'entra', 'hybrid'] },

  { id: 'page-ops', label: 'Ops Center', href: '/ops', icon: Crosshair, section: 'Operations', subtitle: 'Operational jobs and execution tracking', keywords: ['jobs', 'run', 'execute'] },
  { id: 'page-techniques', label: 'Technique Browser', href: '/techniques', icon: Swords, section: 'Operations', subtitle: 'ATT&CK techniques and mapped modules', keywords: ['mitre', 'attack', 'techniques'] },
  { id: 'page-arsenal', label: 'Exploit Arsenal', href: '/arsenal', icon: FlaskConical, section: 'Operations', subtitle: 'CVE checks and target configuration', keywords: ['cve', 'exploit', 'zerologon', 'printnightmare'] },
  { id: 'page-cloud-attacks', label: 'Cloud Attacks', href: '/cloud-attacks', icon: Network, section: 'Operations', subtitle: 'Cloud and hybrid attack workflows', keywords: ['cloud', 'azure', 'entra', 'aws'] },
  { id: 'page-cred-dump', label: 'Credential Dumping', href: '/cred-dump', icon: Database, section: 'Operations', subtitle: 'Credential dumping checks and collection workflows', keywords: ['credentials', 'dump', 'lsass', 'sam', 'ntds'] },
  { id: 'page-forest-pivoting', label: 'Forest Pivoting', href: '/forest-pivoting', icon: GitBranch, section: 'Operations', subtitle: 'Forest, domain, and trust pivot workflows', keywords: ['forest', 'pivot', 'domain', 'trust'] },
  { id: 'page-connectivity', label: 'Pivoting Layer', href: '/connectivity', icon: Wifi, section: 'Operations', subtitle: 'Tunnels, relays, and pivoting profiles', keywords: ['tunnel', 'socks', 'ssh', 'ligolo', 'chisel', 'pivot'] },

  { id: 'page-reports', label: 'Reports', href: '/reports', icon: FileText, section: 'System', subtitle: 'Generate and review reports', keywords: ['export', 'evidence', 'summary'] },
  { id: 'page-audit', label: 'Audit Ledger', href: '/audit', icon: FileText, section: 'System', subtitle: 'Activity and audit history', keywords: ['logs', 'history', 'events'] },
  { id: 'page-settings', label: 'Settings', href: '/settings', icon: Settings, section: 'System', subtitle: 'Application settings and providers', keywords: ['config', 'preferences', 'provider'] },
  { id: 'page-ad-commands', label: 'AD Commands', href: '/assessments', icon: Terminal, section: 'System', subtitle: 'Open assessment command tooling', keywords: ['commands', 'powershell', 'collector'] },
]

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-300',
  HIGH: 'text-orange-300',
  MEDIUM: 'text-yellow-300',
  LOW: 'text-cyan-300',
  INFO: 'text-zinc-400',
}

const SECTION_ACCENTS: Record<string, { rgb: string; glow: string }> = {
  'Command Center': { rgb: '56,189,248', glow: 'rgba(56,189,248,0.22)' },
  'Attack Workflow': { rgb: '244,114,182', glow: 'rgba(244,114,182,0.20)' },
  'Graph & Paths': { rgb: '34,197,94', glow: 'rgba(34,197,94,0.18)' },
  'Exposure Validation': { rgb: '168,85,247', glow: 'rgba(168,85,247,0.20)' },
  Operations: { rgb: '251,146,60', glow: 'rgba(251,146,60,0.20)' },
  System: { rgb: '148,163,184', glow: 'rgba(148,163,184,0.16)' },
  Findings: { rgb: '248,113,113', glow: 'rgba(248,113,113,0.22)' },
  Entities: { rgb: '45,212,191', glow: 'rgba(45,212,191,0.18)' },
  Actions: { rgb: '250,204,21', glow: 'rgba(250,204,21,0.16)' },
  Recent: { rgb: '96,165,250', glow: 'rgba(96,165,250,0.20)' },
}

function commandAccent(section: string) {
  return SECTION_ACCENTS[section] ?? { rgb: '45,212,191', glow: 'rgba(45,212,191,0.18)' }
}

function normalize(value: string) {
  return value.trim().toLowerCase()
}

function scoreCommand(command: CommandItem, query: string) {
  const q = normalize(query)
  if (!q) return 1

  const fields = [
    command.label,
    command.section,
    command.subtitle ?? '',
    ...(command.keywords ?? []),
  ].map(normalize)

  let score = 0
  for (const field of fields) {
    if (!field) continue
    if (field === q) score = Math.max(score, 100)
    else if (field.startsWith(q)) score = Math.max(score, 75)
    else if (field.includes(q)) score = Math.max(score, 45)
    else {
      const terms = q.split(/\s+/).filter(Boolean)
      if (terms.length > 1 && terms.every(term => field.includes(term))) score = Math.max(score, 35)
    }
  }
  return score
}

function commandText(command: CommandItem) {
  return [command.label, command.subtitle, command.section, ...(command.keywords ?? [])].filter(Boolean).join(' ')
}

function commandKind(command: CommandItem): CommandKind {
  return command.kind ?? 'page'
}

function readRecents(): string[] {
  if (typeof window === 'undefined') return []
  try {
    const parsed = JSON.parse(window.localStorage.getItem(RECENT_KEY) ?? '[]')
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === 'string').slice(0, 6) : []
  } catch {
    return []
  }
}

function writeRecents(ids: string[]) {
  if (typeof window === 'undefined') return
  window.localStorage.setItem(RECENT_KEY, JSON.stringify(ids.slice(0, 6)))
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const router = useRouter()
  const pathname = usePathname()
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const [query, setQuery] = useState('')
  const [activeIdx, setActiveIdx] = useState(0)
  const [remoteCommands, setRemoteCommands] = useState<CommandItem[]>([])
  const [searching, setSearching] = useState(false)
  const [recents, setRecents] = useState<string[]>([])

  const actionCommands = useMemo<CommandItem[]>(() => [
    {
      id: 'action-refresh',
      kind: 'action',
      label: 'Reload current page',
      icon: RotateCcw,
      section: 'Actions',
      subtitle: 'Refresh data and route state',
      keywords: ['refresh', 'reload'],
      action: () => router.refresh(),
    },
    {
      id: 'action-close',
      kind: 'action',
      label: 'Close search',
      icon: X,
      section: 'Actions',
      subtitle: 'Dismiss the command palette',
      keywords: ['escape', 'dismiss'],
      action: onClose,
    },
  ], [router, onClose])

  useEffect(() => {
    if (!open) return
    setQuery('')
    setRemoteCommands([])
    setSearching(false)
    setActiveIdx(0)
    setRecents(readRecents())
    const id = window.setTimeout(() => inputRef.current?.focus(), 40)
    return () => window.clearTimeout(id)
  }, [open])

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    const q = query.trim()
    if (q.length < 2) {
      setRemoteCommands([])
      setSearching(false)
      return
    }

    setSearching(true)
    debounceRef.current = setTimeout(async () => {
      try {
        const result = await globalSearchApi.search(q)
        const next: CommandItem[] = [
          ...result.findings.slice(0, 10).map(finding => ({
            id: `finding-${finding.id}`,
            kind: 'finding' as const,
            label: finding.title,
            href: `/findings/${finding.id}`,
            icon: Shield,
            section: 'Findings',
            subtitle: 'Open finding detail',
            severity: finding.severity,
            keywords: [finding.severity, 'finding', 'risk'],
          })),
          ...result.entities.slice(0, 10).map(entity => ({
            id: `entity-${entity.id}`,
            kind: 'entity' as const,
            label: entity.label,
            href: `/assets?q=${encodeURIComponent(entity.label)}`,
            icon: Boxes,
            section: 'Entities',
            subtitle: entity.entity_type.replaceAll('_', ' '),
            keywords: [entity.entity_type, 'entity', 'asset', 'identity'],
          })),
        ]
        setRemoteCommands(next)
      } catch {
        setRemoteCommands([])
      } finally {
        setSearching(false)
      }
    }, 180)

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [query])

  const pageCommands = useMemo(() => {
    const q = query.trim()
    return PAGE_COMMANDS
      .map(command => ({ command, score: scoreCommand(command, q) }))
      .filter(item => !q || item.score > 0)
      .sort((a, b) => b.score - a.score || a.command.label.localeCompare(b.command.label))
      .map(item => item.command)
  }, [query])

  const recentCommands = useMemo(() => {
    if (query.trim()) return []
    const byId = new Map(PAGE_COMMANDS.map(command => [command.id, command]))
    return recents.map(id => byId.get(id)).filter((command): command is CommandItem => !!command)
  }, [query, recents])

  const visibleCommands = useMemo<CommandItem[]>(() => {
    const q = query.trim()
    const base = q ? [...remoteCommands, ...pageCommands, ...actionCommands.filter(command => scoreCommand(command, q) > 0)] : [...recentCommands, ...pageCommands]
    const seen = new Set<string>()
    return base.filter(command => {
      if (seen.has(command.id)) return false
      seen.add(command.id)
      return true
    })
  }, [actionCommands, pageCommands, query, recentCommands, remoteCommands])

  useEffect(() => {
    setActiveIdx(0)
  }, [query, visibleCommands.length])

  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${activeIdx}"]`) as HTMLElement | null
    el?.scrollIntoView({ block: 'nearest' })
  }, [activeIdx])

  const runCommand = useCallback((command: CommandItem) => {
    if (commandKind(command) === 'page') {
      const next = [command.id, ...recents.filter(id => id !== command.id)]
      setRecents(next)
      writeRecents(next)
    }

    if (command.action) command.action()
    else if (command.href) router.push(command.href)
    onClose()
  }, [onClose, recents, router])

  const handleKeyDown = useCallback((e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActiveIdx(idx => Math.min(idx + 1, Math.max(visibleCommands.length - 1, 0)))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActiveIdx(idx => Math.max(idx - 1, 0))
    } else if (e.key === 'Home') {
      e.preventDefault()
      setActiveIdx(0)
    } else if (e.key === 'End') {
      e.preventDefault()
      setActiveIdx(Math.max(visibleCommands.length - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const command = visibleCommands[activeIdx]
      if (command) runCommand(command)
    } else if (e.key === 'Escape') {
      e.preventDefault()
      if (query) setQuery('')
      else onClose()
    }
  }, [activeIdx, onClose, query, runCommand, visibleCommands])

  const grouped = useMemo(() => {
    return visibleCommands.reduce<Record<string, { command: CommandItem; idx: number }[]>>((acc, command, idx) => {
      const group = !query.trim() && recentCommands.some(recent => recent.id === command.id) ? 'Recent' : command.section
      if (!acc[group]) acc[group] = []
      acc[group].push({ command, idx })
      return acc
    }, {})
  }, [query, recentCommands, visibleCommands])

  const resultCount = visibleCommands.length

  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div
            key="search-backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.14 }}
            className="fixed inset-0 z-[60] backdrop-blur-[6px]"
            style={{
              background: 'linear-gradient(135deg, rgba(15,5,40,0.82), rgba(10,8,30,0.72) 45%, rgba(5,2,20,0.88))',
            }}
            onClick={onClose}
          />

          <motion.div
            key="search-panel"
            initial={{ opacity: 0, scale: 0.96, y: -18, rotateX: -6 }}
            animate={{ opacity: 1, scale: 1, y: 0, rotateX: 0 }}
            exit={{ opacity: 0, scale: 0.97, y: -14, rotateX: -4 }}
            transition={{ duration: 0.22, ease: [0.23, 1, 0.32, 1] }}
            className="fixed left-1/2 top-[6vh] z-[61] w-[min(860px,calc(100vw-32px))] overflow-hidden"
            style={{
              borderRadius: '36px',
              transform: 'translateX(-50%)',
              transformStyle: 'preserve-3d',
              background: 'linear-gradient(145deg, rgba(30,15,70,0.88) 0%, rgba(15,10,50,0.82) 50%, rgba(8,18,60,0.85) 100%)',
              border: '1px solid rgba(139,92,246,0.35)',
              boxShadow: '0 34px 110px rgba(0,0,0,0.82), 0 18px 55px rgba(99,102,241,0.14), 0 0 80px rgba(139,92,246,0.08), inset 0 1px 0 rgba(167,139,250,0.18)',
              backdropFilter: 'blur(22px) saturate(145%)',
              WebkitBackdropFilter: 'blur(22px) saturate(145%)',
            }}
          >
            <div className="absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(99,102,241,0.95), rgba(139,92,246,0.95), rgba(167,139,250,0.85), rgba(99,102,241,0.7), transparent)' }} />
            <div className="pointer-events-none absolute inset-x-0 top-0 h-32 opacity-60" style={{ background: 'linear-gradient(180deg, rgba(139,92,246,0.15), transparent)' }} />
            <div className="pointer-events-none absolute inset-y-0 left-0 w-1/2 opacity-20" style={{ background: 'linear-gradient(90deg, rgba(99,102,241,0.25), transparent)' }} />

            <div className="relative flex items-center gap-3 px-4 py-3.5" style={{ borderBottom: '1px solid rgba(99,102,241,0.22)' }}>
              <div
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-3xl"
                style={{
                  background: 'linear-gradient(145deg, rgba(99,102,241,0.28), rgba(139,92,246,0.18))',
                  border: '1px solid rgba(139,92,246,0.35)',
                  boxShadow: '0 12px 28px rgba(99,102,241,0.18), inset 0 1px 0 rgba(167,139,250,0.22)',
                }}
              >
                <Search className="h-4 w-4" style={{ color: '#a78bfa' }} />
              </div>
              <input
                ref={inputRef}
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search modules, pages, findings, entities, tools, CVEs..."
                className="min-w-0 flex-1 rounded-3xl px-3 py-2 outline-none"
                style={{
                  color: '#f8fafc',
                  fontSize: '14px',
                  background: 'rgba(15,8,40,0.55)',
                  border: '1px solid rgba(99,102,241,0.30)',
                  boxShadow: 'inset 0 1px 0 rgba(167,139,250,0.08), 0 0 0 1px rgba(139,92,246,0.06)',
                  ...MONO,
                }}
                autoComplete="off"
                spellCheck={false}
              />
              {searching && <Loader2 className="h-3.5 w-3.5 animate-spin" style={{ color: 'rgba(var(--brand-rgb),0.65)' }} />}
              {query && (
                <button
                  type="button"
                  onClick={() => { setQuery(''); setRemoteCommands([]) }}
                  aria-label="Clear search"
                  className="flex h-7 w-7 items-center justify-center rounded-lg transition-colors hover:bg-white/[0.06]"
                  style={{ color: 'rgba(148,163,184,0.75)' }}
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
              <div className="hidden items-center gap-1.5 sm:flex">
                <kbd className="rounded-lg px-2 py-1 text-[10px]" style={{ background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)', color: '#94a3b8', boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.08)', ...MONO }}>ESC</kbd>
              </div>
            </div>

            <div className="relative flex items-center justify-between px-4 py-2.5" style={{ borderBottom: '1px solid rgba(99,102,241,0.14)', background: 'rgba(30,15,70,0.25)' }}>
              <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.22em]" style={{ color: '#a78bfa', ...MONO }}>
                <Command className="h-3 w-3" />
                Unified Search
              </div>
              <div className="text-[10px]" style={{ color: '#94a3b8', ...MONO }}>
                {searching ? 'Searching live data' : `${resultCount} result${resultCount === 1 ? '' : 's'}`}
              </div>
            </div>

            <div ref={listRef} className="relative max-h-[66vh] overflow-y-auto px-2 py-2" style={{ scrollbarWidth: 'thin' }}>
              {resultCount === 0 && !searching && (
                <div className="px-6 py-14 text-center">
                  <Search className="mx-auto mb-3 h-8 w-8" style={{ color: '#1f2937' }} />
                  <div className="text-sm font-semibold" style={{ color: '#94a3b8', ...MONO }}>No results</div>
                  <div className="mt-1 text-xs" style={{ color: '#475569', ...MONO }}>Try a page name, CVE, entity, finding, or command keyword.</div>
                </div>
              )}

              {Object.entries(grouped).map(([section, items]) => (
                <div key={section} className="py-1.5">
                  <div className="flex items-center gap-2 px-3 pb-1.5 pt-2 text-[9px] font-black uppercase tracking-[0.24em]" style={{ color: '#64748b', ...MONO }}>
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: `rgb(${commandAccent(section).rgb})`, boxShadow: `0 0 12px ${commandAccent(section).glow}` }} />
                    {section}
                  </div>
                  {items.map(({ command, idx }) => {
                    const Icon = command.icon
                    const active = idx === activeIdx
                    const current = command.href === pathname
                    const accent = commandAccent(command.section)

                    return (
                      <button
                        key={command.id}
                        type="button"
                        data-idx={idx}
                        onMouseEnter={() => setActiveIdx(idx)}
                        onClick={() => runCommand(command)}
                        className="grid w-full grid-cols-[42px_minmax(0,1fr)_auto] items-center gap-3 rounded-2xl px-3 py-2.5 text-left transition-all duration-150"
                        style={{
                          background: active
                            ? `linear-gradient(135deg, rgba(${accent.rgb},0.18), rgba(255,255,255,0.065))`
                            : 'rgba(255,255,255,0.015)',
                          border: `1px solid ${active ? `rgba(${accent.rgb},0.38)` : 'rgba(255,255,255,0.045)'}`,
                          boxShadow: active
                            ? `0 16px 34px rgba(0,0,0,0.32), 0 0 26px ${accent.glow}, inset 0 1px 0 rgba(255,255,255,0.11)`
                            : 'inset 0 1px 0 rgba(255,255,255,0.025)',
                          transform: active ? 'translateY(-1px) translateZ(18px)' : 'translateZ(0)',
                        }}
                      >
                        <div
                          className="flex h-10 w-10 items-center justify-center rounded-2xl"
                          style={{
                            background: active ? `linear-gradient(145deg, rgba(${accent.rgb},0.30), rgba(255,255,255,0.08))` : 'rgba(255,255,255,0.045)',
                            border: `1px solid ${active ? `rgba(${accent.rgb},0.45)` : 'rgba(255,255,255,0.09)'}`,
                            boxShadow: active ? `0 10px 22px ${accent.glow}, inset 0 1px 0 rgba(255,255,255,0.16)` : 'inset 0 1px 0 rgba(255,255,255,0.06)',
                          }}
                        >
                          <Icon className="h-4 w-4" style={{ color: active ? '#f8fafc' : `rgba(${accent.rgb},0.74)` }} />
                        </div>

                        <div className="min-w-0">
                          <div className="flex min-w-0 items-center gap-2">
                            <span className="truncate text-[13px] font-bold" style={{ color: active ? '#f8fafc' : '#dbeafe', ...MONO }}>
                              {command.label}
                            </span>
                            {current && (
                              <span className="shrink-0 rounded-md px-1.5 py-0.5 text-[9px] font-bold" style={{ background: 'rgba(34,197,94,0.11)', color: '#86efac', border: '1px solid rgba(34,197,94,0.22)', ...MONO }}>
                                Current
                              </span>
                            )}
                            {command.severity && (
                              <span className={cn('shrink-0 text-[9px] font-black', SEVERITY_COLORS[command.severity] ?? 'text-zinc-400')} style={MONO}>
                                {command.severity}
                              </span>
                            )}
                          </div>
                          <div className="mt-0.5 truncate text-[11px]" style={{ color: active ? '#cbd5e1' : '#64748b', ...MONO }}>
                            {command.subtitle ?? commandText(command)}
                          </div>
                        </div>

                        <ArrowRight className="h-4 w-4 opacity-0 transition-all" style={{ color: active ? `rgb(${accent.rgb})` : '#64748b', opacity: active ? 1 : 0, transform: active ? 'translateX(0)' : 'translateX(-4px)' }} />
                      </button>
                    )
                  })}
                </div>
              ))}
            </div>

            <div className="flex items-center gap-4 px-4 py-2.5 text-[9px]" style={{ borderTop: '1px solid rgba(99,102,241,0.18)', color: '#7c6fa0', background: 'rgba(15,8,40,0.45)', ...MONO }}>
              <span>↑↓ Move</span>
              <span>↵ Open</span>
              <span>Esc Clear / Close</span>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  )
}
