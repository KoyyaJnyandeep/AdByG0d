'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { motion, AnimatePresence, useMotionValue, useTransform, useSpring } from 'framer-motion'
import { useMemo, useRef, useState, useCallback, useEffect } from 'react'
import {
  LayoutDashboard, Shield, GitBranch, Target, Swords, Layers,
  FileText, Settings, Activity, Search,
  ChevronRight, Boxes, Lock, Network, Key, Command,
  Crosshair, Database, Zap, Radio, Wifi, FlaskConical, History, X,
  ShieldAlert, TreePine, Radar, Link2,
  Bot, Wrench, Eye, Archive, HardDrive, Cloud, Download,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'

import { assessmentApi, findingsApi } from '@/lib/api'
import { cn } from '@/lib/utils'

const MONO = { fontFamily: 'JetBrains Mono, monospace' }

const SECTION_THEMES: Record<string, { color: string; rgb: string; dim: string; glow: string }> = {
  'Platform':            { color: '#8b9cff', rgb: '139,156,255', dim: 'rgba(139,156,255,0.12)', glow: 'rgba(139,156,255,0.28)' },
  'Graph & Paths':       { color: '#22d3ee', rgb: '34,211,238',  dim: 'rgba(34,211,238,0.12)',  glow: 'rgba(34,211,238,0.28)' },
  'Exposure Validation': { color: '#fbbf24', rgb: '251,191,36',  dim: 'rgba(251,191,36,0.10)',  glow: 'rgba(251,191,36,0.24)' },
  'Workspaces':          { color: '#34d399', rgb: '52,211,153',  dim: 'rgba(52,211,153,0.10)',  glow: 'rgba(52,211,153,0.24)' },
  'Offensive Ops':       { color: '#f87171', rgb: '248,113,113', dim: 'rgba(248,113,113,0.11)', glow: 'rgba(248,113,113,0.26)' },
  'Action':              { color: '#c084fc', rgb: '192,132,252', dim: 'rgba(192,132,252,0.11)', glow: 'rgba(192,132,252,0.26)' },
}

const SECTION_ICONS: Record<string, React.ReactNode> = {
  'Platform':            <Radio className="h-2.5 w-2.5" />,
  'Graph & Paths':       <GitBranch className="h-2.5 w-2.5" />,
  'Exposure Validation': <Shield className="h-2.5 w-2.5" />,
  'Workspaces':          <Boxes className="h-2.5 w-2.5" />,
  'Offensive Ops':       <Zap className="h-2.5 w-2.5" />,
  'Action':              <Settings className="h-2.5 w-2.5" />,
}

const NAV_ITEMS = [
  { label: 'Platform', items: [
    { href: '/',            icon: LayoutDashboard, label: 'Dashboard' },
    { href: '/assessments', icon: Activity,        label: 'Assessments' },
    { href: '/findings',    icon: Shield,          label: 'Findings', badge: 'findings' },
  ]},
  { label: 'Graph & Paths', items: [
    { href: '/graph',    icon: GitBranch, label: 'Graph Engine' },
    { href: '/paths',    icon: Target,    label: 'Attack Paths' },
    { href: '/priv-esc', icon: Layers,    label: 'Privilege Esc Mapping' },
  ]},
  { label: 'Exposure Validation', items: [
    { href: '/validation',  icon: Swords, label: 'Validation Modules' },
    { href: '/remediation', icon: Shield, label: 'Remediation Sim' },
  ]},
  { label: 'Workspaces', items: [
    { href: '/assets',           icon: Boxes,       label: 'Assets & Identities' },
    { href: '/pki',              icon: Lock,        label: 'PKI / AD CS' },
    { href: '/service-accounts', icon: Key,         label: 'Service Accounts' },
    { href: '/trusts',           icon: Network,     label: 'Trusts & Hybrid' },
    { href: '/trust-abuse',      icon: ShieldAlert, label: 'Trust Abuse' },
    { href: '/forest-pivoting',  icon: TreePine,    label: 'Forest Pivoting' },
  ]},
  { label: 'Offensive Ops', items: [
    { href: '/recon',            icon: Radar,        label: 'Recon & OSINT' },
    { href: '/initial-access',   icon: Zap,          label: 'Initial Access' },
    { href: '/enumeration',      icon: Search,       label: 'Enumeration' },
    { href: '/kill-chain',       icon: Link2,        label: 'Kill Chain' },
    { href: '/lateral-movement', icon: Crosshair,    label: 'Lateral Movement' },
    { href: '/persistence',      icon: Archive,      label: 'Persistence' },
    { href: '/evasion',          icon: Eye,          label: 'Defense Evasion' },
    { href: '/priv-esc',         icon: Layers,       label: 'Privilege Esc' },
    { href: '/ops',              icon: HardDrive,    label: 'Ops Center' },
    { href: '/techniques',       icon: Swords,       label: 'Technique Browser' },
    { href: '/loot',             icon: Database,     label: 'Hash Dmp & Brk' },
    { href: '/cred-dump',        icon: Download,     label: 'Cred Dump & DPAPI' },
    { href: '/cloud-attacks',    icon: Cloud,        label: 'Cloud Attacks' },
    { href: '/arsenal',          icon: FlaskConical, label: 'Exploit Arsenal' },
  ]},
  { label: 'Action', items: [
    { href: '/tool-checker',  icon: Wrench,   label: 'Tool Checker' },
    { href: '/ai-operator',   icon: Bot,      label: 'AI Operator' },
    { href: '/reports',       icon: FileText, label: 'Reports' },
    { href: '/audit',         icon: History,  label: 'Audit Ledger' },
    { href: '/connectivity',  icon: Wifi,     label: 'Pivoting Layer' },
    { href: '/settings',      icon: Settings, label: 'Settings' },
  ]},
]

function NavItem3D({
  href, icon: Icon, label, badge, findingsCount, isActive, theme, delay, onNavigate,
}: {
  href: string
  icon: React.ElementType
  label: string
  badge?: string
  findingsCount?: number
  isActive: boolean
  theme: { color: string; rgb: string; dim: string; glow: string }
  delay: number
  onNavigate?: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [hovered, setHovered] = useState(false)
  const rawX = useMotionValue(0)
  const rawY = useMotionValue(0)
  const springConfig = { stiffness: 260, damping: 22 }
  const rotateX = useSpring(useTransform(rawY, [-0.5, 0.5], [7, -7]), springConfig)
  const rotateY = useSpring(useTransform(rawX, [-0.5, 0.5], [-9, 9]), springConfig)
  const scale = useSpring(hovered ? 1.015 : 1, springConfig)

  const onMove = useCallback((e: React.MouseEvent) => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    rawX.set((e.clientX - r.left - r.width / 2) / (r.width / 2))
    rawY.set((e.clientY - r.top - r.height / 2) / (r.height / 2))
  }, [rawX, rawY])

  const onLeave = useCallback(() => {
    setHovered(false)
    rawX.set(0)
    rawY.set(0)
  }, [rawX, rawY])

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, x: -14 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay, duration: 0.36, ease: [0.23, 1, 0.32, 1] }}
      style={{ perspective: '700px', marginBottom: '6px' }}
      onMouseMove={onMove}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={onLeave}
    >
      <motion.div style={{ rotateX, rotateY, scale, transformStyle: 'preserve-3d' }}>
        <Link
          href={href}
          onClick={onNavigate}
          aria-current={isActive ? 'page' : undefined}
          className="group relative flex items-center gap-3 overflow-hidden rounded-[16px] px-3.5 py-3"
          style={{
            background: isActive
              ? 'linear-gradient(135deg, rgba(' + theme.rgb + ',0.20), rgba(10,16,34,0.94) 42%, rgba(' + theme.rgb + ',0.08))'
              : hovered
                ? 'linear-gradient(135deg, rgba(' + theme.rgb + ',0.09), rgba(255,255,255,0.015))'
                : 'rgba(255,255,255,0.015)',
            border: '1px solid ' + (isActive ? 'rgba(' + theme.rgb + ',0.40)' : hovered ? 'rgba(' + theme.rgb + ',0.18)' : 'rgba(255,255,255,0.04)'),
            color: isActive ? '#eef2ff' : hovered ? 'rgba(226,232,240,0.94)' : 'rgba(148,163,184,0.68)',
            boxShadow: isActive
              ? '0 0 0 1px rgba(255,255,255,0.03), 0 0 34px ' + theme.glow + ', 0 10px 24px rgba(0,0,0,0.42), inset 0 1px 0 rgba(255,255,255,0.08)'
              : hovered
                ? '0 10px 28px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.03)'
                : 'inset 0 1px 0 rgba(255,255,255,0.01)',
            ...MONO,
            textDecoration: 'none',
            transition: 'all 0.16s ease',
          }}
        >
          <div
            className="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-[12px]"
            style={{
              background: isActive ? 'rgba(' + theme.rgb + ',0.16)' : hovered ? 'rgba(' + theme.rgb + ',0.10)' : 'rgba(255,255,255,0.02)',
              border: '1px solid ' + (isActive ? 'rgba(' + theme.rgb + ',0.28)' : 'rgba(255,255,255,0.05)'),
              boxShadow: isActive ? '0 0 16px rgba(' + theme.rgb + ',0.22), inset 0 0 10px rgba(255,255,255,0.04)' : 'none',
            }}
          >
            <Icon
              className="h-4 w-4 shrink-0"
              style={{
                color: isActive ? theme.color : hovered ? theme.color : 'rgba(100,116,139,0.62)',
                filter: isActive ? 'drop-shadow(0 0 8px ' + theme.color + ')' : 'none',
              }}
            />
            {isActive && (
              <motion.div
                layoutId={'nav-orb-' + href}
                className="pointer-events-none absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full"
                style={{ background: theme.color, boxShadow: '0 0 12px ' + theme.color + ', 0 0 22px ' + theme.color }}
              />
            )}
          </div>

          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px] font-bold tracking-[0.01em]">{label}</div>
          </div>

          {badge === 'findings' && findingsCount !== undefined && findingsCount > 0 ? (
            <motion.span
              animate={{ boxShadow: ['0 0 8px rgba(239,68,68,0.26)', '0 0 18px rgba(239,68,68,0.46)', '0 0 8px rgba(239,68,68,0.26)'] }}
              transition={{ duration: 2, repeat: Infinity }}
              className="rounded-md px-1.5 py-0.5 text-[10px] font-bold tabular-nums"
              style={{ background: 'rgba(239,68,68,0.12)', color: '#fca5a5', border: '1px solid rgba(239,68,68,0.35)' }}
            >
              {findingsCount}
            </motion.span>
          ) : null}

          <AnimatePresence>
            {isActive && (
              <motion.div initial={{ opacity: 0, x: -3 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }}>
                <ChevronRight className="h-3.5 w-3.5 shrink-0" style={{ color: theme.color }} />
              </motion.div>
            )}
          </AnimatePresence>

          {isActive && (
            <>
              <motion.div
                layoutId={'edge-' + href}
                className="pointer-events-none absolute inset-y-2 left-0 w-[3px] rounded-full"
                style={{ background: 'linear-gradient(180deg, ' + theme.color + ', rgba(255,255,255,0.4), ' + theme.color + ')', boxShadow: '0 0 12px ' + theme.color + ', 0 0 22px ' + theme.color }}
              />
              <div className="pointer-events-none absolute inset-x-0 top-0 h-px" style={{ background: 'linear-gradient(90deg, transparent, rgba(' + theme.rgb + ',0.7), transparent)' }} />
              <motion.div
                className="pointer-events-none absolute inset-y-0 -left-1 w-1/2"
                initial={{ x: '-120%' }}
                animate={{ x: '220%' }}
                transition={{ duration: 3.4, repeat: Infinity, repeatDelay: 2.6, ease: 'easeInOut' }}
                style={{ background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.10), transparent)' }}
              />
            </>
          )}
        </Link>
      </motion.div>
    </motion.div>
  )
}

function GlitchLogo() {
  const [glitch, setGlitch] = useState(false)

  useEffect(() => {
    const tick = () => {
      setGlitch(true)
      setTimeout(() => setGlitch(false), 140)
    }
    const id = setInterval(tick, 4200 + Math.random() * 3200)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="relative" style={{ ...MONO }}>
      <div
        className="relative text-[20px] font-black leading-none tracking-tight"
        style={{ color: '#eef2ff', textShadow: glitch ? '2px 0 #f87171, -2px 0 #22d3ee' : '0 0 20px rgba(139,156,255,0.5)' }}
      >
        {glitch && (
          <>
            <span
              className="absolute inset-0 text-[20px] font-black"
              style={{ color: '#f87171', clipPath: 'inset(0 0 58% 0)', transform: 'translateX(2px)', opacity: 0.8 }}
            >
              AdByG<span style={{ color: '#8b9cff' }}>0</span>d
            </span>
            <span
              className="absolute inset-0 text-[20px] font-black"
              style={{ color: '#22d3ee', clipPath: 'inset(58% 0 0 0)', transform: 'translateX(-2px)', opacity: 0.8 }}
            >
              AdByG<span style={{ color: '#8b9cff' }}>0</span>d
            </span>
          </>
        )}
        AdByG<span style={{ color: '#8b9cff', textShadow: '0 0 14px #8b9cff' }}>0</span>d
      </div>
      <div className="mt-2 text-[10px] uppercase tracking-[0.28em]" style={{ color: 'rgba(139,156,255,0.58)' }}>
        Identity Exposure
      </div>
    </div>
  )
}

function HexGrid() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden opacity-[0.05]">
      <svg width="100%" height="100%" style={{ position: 'absolute' }}>
        <defs>
          <pattern id="hex" x="0" y="0" width="28" height="32" patternUnits="userSpaceOnUse">
            <polygon points="14,2 26,9 26,23 14,30 2,23 2,9" fill="none" stroke="rgba(129,140,248,0.8)" strokeWidth="0.5" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#hex)" />
      </svg>
    </div>
  )
}

function ScanBeam() {
  return (
    <motion.div
      className="pointer-events-none absolute inset-x-0 z-[5]"
      style={{ height: '90px', background: 'linear-gradient(180deg, transparent, rgba(129,140,248,0.035) 38%, rgba(34,211,238,0.045) 50%, rgba(129,140,248,0.035) 62%, transparent)' }}
      initial={{ top: '-90px' }}
      animate={{ top: ['-90px', '100%'] }}
      transition={{ duration: 6.5, repeat: Infinity, repeatDelay: 1.8, ease: 'linear' }}
    />
  )
}

interface SidebarProps {
  findingsCount?: number
  onOpenSearch?: () => void
  mobileOpen?: boolean
  onRequestClose?: () => void
}

export function Sidebar({ findingsCount, onOpenSearch, mobileOpen = false, onRequestClose }: SidebarProps) {
  const pathname = usePathname()
  const activeHref = useMemo(() => {
    const hrefs = NAV_ITEMS.flatMap((section) => section.items.map((item) => item.href))
    return hrefs
      .filter((href) => pathname === href || (href !== '/' && pathname.startsWith(`${href}/`)))
      .sort((left, right) => right.length - left.length)[0] ?? '/'
  }, [pathname])

  const { data: latestAssessments = [] } = useQuery({
    queryKey: ['sidebar', 'latest-assessment'],
    queryFn: () => assessmentApi.list({ limit: 1 }),
    enabled: findingsCount === undefined,
    staleTime: 60_000,
    refetchInterval: 120_000,
  })

  const latestAssessmentId = latestAssessments[0]?.id ?? null

  const { data: openFindings } = useQuery({
    queryKey: ['sidebar', 'open-findings', latestAssessmentId],
    queryFn: () => findingsApi.list({
      assessment_id: latestAssessmentId ?? '',
      status: 'OPEN',
      page: 1,
      page_size: 1,
    }),
    enabled: findingsCount === undefined && Boolean(latestAssessmentId),
    staleTime: 30_000,
    refetchInterval: 60_000,
  })

  const resolvedFindingsCount = findingsCount ?? openFindings?.total ?? 0

  return (
    <aside
      aria-label="Primary navigation"
      className={cn(
        'fixed bottom-0 left-0 top-0 z-50 flex w-[272px] select-none flex-col overflow-hidden transition-transform duration-300 lg:z-30 lg:translate-x-0',
        mobileOpen ? 'translate-x-0' : '-translate-x-full'
      )}
      style={{
        background: 'linear-gradient(180deg, rgba(4,5,12,0.98) 0%, rgba(2,3,8,0.99) 100%)',
        borderRight: '1px solid rgba(255,255,255,0.05)',
        boxShadow: '0 0 0 1px rgba(255,255,255,0.02), 18px 0 70px rgba(0,0,0,0.55), inset -1px 0 0 rgba(139,156,255,0.10)',
      }}
    >
      <HexGrid />
      <ScanBeam />

      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-16 top-10 h-48 w-48 rounded-full blur-3xl" style={{ background: 'rgba(139,156,255,0.14)' }} />
        <div className="absolute -right-14 top-56 h-44 w-44 rounded-full blur-3xl" style={{ background: 'rgba(34,211,238,0.10)' }} />
        <div className="absolute -left-12 bottom-24 h-40 w-40 rounded-full blur-3xl" style={{ background: 'rgba(248,113,113,0.08)' }} />
      </div>

      <div className="pointer-events-none absolute right-0 top-0 bottom-0 w-px z-10" style={{ background: 'linear-gradient(180deg, rgba(139,156,255,0.65) 0%, rgba(34,211,238,0.45) 36%, rgba(248,113,113,0.42) 68%, rgba(192,132,252,0.35) 100%)' }} />
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px z-10" style={{ background: 'linear-gradient(90deg, transparent, rgba(139,156,255,0.95) 22%, rgba(34,211,238,0.9) 58%, transparent)' }} />
      <div className="pointer-events-none absolute bottom-0 left-0 right-0 h-24" style={{ background: 'linear-gradient(180deg, transparent, rgba(0,0,0,0.78))' }} />

      <div className="pointer-events-none absolute left-0 top-0 z-20">
        <div className="h-px w-5" style={{ background: '#22d3ee' }} />
        <div className="h-5 w-px" style={{ background: '#22d3ee' }} />
      </div>
      <div className="pointer-events-none absolute bottom-0 right-0 z-20">
        <div className="ml-auto h-px w-5" style={{ background: '#f87171' }} />
        <div className="ml-auto h-5 w-px" style={{ background: '#f87171' }} />
      </div>

      {onRequestClose ? (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={onRequestClose}
          className="absolute right-3 top-3 z-20 inline-flex h-9 w-9 items-center justify-center rounded-xl border border-white/10 bg-black/80 text-zinc-200 transition hover:border-cyan-300/30 hover:bg-cyan-300/10 lg:hidden"
        >
          <X className="h-4 w-4" />
        </button>
      ) : null}

      <motion.div
        initial={{ opacity: 0, y: -12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
        className="relative z-10 border-b px-4 pb-5 pt-6"
        style={{ borderColor: 'rgba(255,255,255,0.05)' }}
      >
        <div className="flex items-center">
          <div className="min-w-0 flex-1">
            <GlitchLogo />
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.14, duration: 0.4 }}
        className="relative z-10 border-b px-3 py-3"
        style={{ borderColor: 'rgba(255,255,255,0.05)' }}
      >
        <button
          type="button"
          aria-label="Open workspace search"
          onClick={() => {
            onOpenSearch?.()
            onRequestClose?.()
          }}
          className="group w-full rounded-xl border px-3 py-2.5 text-left transition-all duration-200"
          style={{
            background: 'rgba(3,7,18,0.62)',
            borderColor: 'rgba(34,211,238,0.16)',
            boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.025)',
          }}
          onMouseEnter={e => {
            const el = e.currentTarget
            el.style.background = 'rgba(8,18,32,0.82)'
            el.style.borderColor = 'rgba(34,211,238,0.42)'
            el.style.boxShadow = '0 0 18px rgba(34,211,238,0.10), inset 0 1px 0 rgba(255,255,255,0.04)'
          }}
          onMouseLeave={e => {
            const el = e.currentTarget
            el.style.background = 'rgba(3,7,18,0.62)'
            el.style.borderColor = 'rgba(34,211,238,0.16)'
            el.style.boxShadow = 'inset 0 1px 0 rgba(255,255,255,0.025)'
          }}
        >
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border"
              style={{ background: 'rgba(34,211,238,0.08)', borderColor: 'rgba(34,211,238,0.18)' }}>
              <Search className="h-4 w-4" style={{ color: 'rgba(103,232,249,0.88)' }} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[12px] font-semibold leading-none" style={{ color: 'rgba(226,232,240,0.86)', ...MONO }}>Search workspace</div>
              <div className="mt-1 text-[8px] uppercase tracking-[0.2em]" style={{ color: 'rgba(103,232,249,0.42)', ...MONO }}>Nodes / paths / findings</div>
            </div>
            <kbd className="inline-flex shrink-0 items-center gap-1 rounded-lg border px-2 py-1 text-[9px]" style={{ background: 'rgba(255,255,255,0.035)', borderColor: 'rgba(255,255,255,0.08)', color: 'rgba(203,213,225,0.62)', ...MONO }}>
              <Command className="h-3 w-3" />K
            </kbd>
          </div>
        </button>
      </motion.div>

      <nav className="relative z-10 flex-1 overflow-y-auto px-2.5 py-2" style={{ scrollbarWidth: 'thin' }}>
        {NAV_ITEMS.map((section, sIdx) => {
          const theme = SECTION_THEMES[section.label] ?? SECTION_THEMES['Platform']
          return (
            <motion.div key={section.label} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 + sIdx * 0.05 }} className="mb-2.5">
              <div className="mb-2 flex items-center gap-2 px-2 pt-3">
                <motion.div animate={{ opacity: [0.45, 0.92, 0.45] }} transition={{ duration: 3 + sIdx * 0.45, repeat: Infinity, ease: 'easeInOut' }} className="flex items-center justify-center rounded-full" style={{ color: theme.color }}>
                  {SECTION_ICONS[section.label]}
                </motion.div>
                <span className="text-[9px] font-bold uppercase tracking-[0.28em]" style={{ color: 'rgba(' + theme.rgb + ',0.84)', ...MONO }}>
                  {section.label}
                </span>
                <motion.div className="h-px flex-1" initial={{ scaleX: 0 }} animate={{ scaleX: 1 }} transition={{ delay: 0.25 + sIdx * 0.05, duration: 0.6, ease: [0.23, 1, 0.32, 1] }} style={{ background: 'linear-gradient(90deg, rgba(' + theme.rgb + ',0.38), transparent)', transformOrigin: 'left' }} />
              </div>

              {section.items.map((item, iIdx) => {
                const isActive = activeHref === item.href
                return (
                  <NavItem3D
                    key={item.href}
                    href={item.href}
                    icon={item.icon}
                    label={item.label}
                    badge={item.badge}
                    findingsCount={resolvedFindingsCount}
                    isActive={isActive}
                    onNavigate={onRequestClose}
                    theme={theme}
                    delay={0.25 + sIdx * 0.05 + iIdx * 0.03}
                  />
                )
              })}
            </motion.div>
          )
        })}
      </nav>

      <div className="relative z-10 px-4 py-3 border-t" style={{ borderColor: 'rgba(255,255,255,0.05)' }}>
        <div className="text-[9px] text-zinc-600 text-center" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
          by <span className="text-zinc-500">White0xdi3</span>
        </div>
      </div>

    </aside>
  )
}
