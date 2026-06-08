'use client'

import { memo, useCallback, useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Database,
  Eye,
  History,
  Loader2,
  Lock,
  Plus,
  Radar,
  RefreshCw,
  Server,
  Shield,
  Sparkles,
  Terminal,
  Users,
  Zap,
} from 'lucide-react'

import { assessmentApi } from '@/lib/api'
import { Finding } from '@/lib/types'
import { assessmentKeys } from '@/lib/queryKeys'
import { fmtNumber, timeAgo } from '@/lib/utils'
import { ScoreGauge } from '@/components/ui/ScoreGauge'
import { CornerFrame } from '@/components/ui/CornerFrame'
import { TopFindingsList } from './TopFindingsList'
import { KillChainMiniWidget } from './KillChainMiniWidget'

const SeverityBreakdownChart = dynamic(() => import('./SeverityBreakdownChart').then(m => ({ default: m.SeverityBreakdownChart })), { ssr: false })
const ModuleBreakdown = dynamic(() => import('./ModuleBreakdown').then(m => ({ default: m.ModuleBreakdown })), { ssr: false })
const PathMiniGraph = dynamic(() => import('./PathMiniGraph').then(m => ({ default: m.PathMiniGraph })), { ssr: false })
const CoverageMatrix = dynamic(() => import('./CoverageMatrix').then(m => ({ default: m.CoverageMatrix })), { ssr: false })

const EMPTY_STATS = {
  exposure_score: 0,
  score_delta: 0,
  severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  severity_deltas: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  total_findings: 0,
  new_findings: 0,
  resolved_findings: 0,
  regressed_findings: 0,
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff2d55',
  HIGH: '#ff6b2d',
  MEDIUM: '#ffd60a',
  LOW: '#30d158',
  INFO: '#0a84ff',
}

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  visible: (delay: number) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1], delay },
  }),
}

const statNumber = (value: unknown) =>
  typeof value === 'number' && Number.isFinite(value) ? value : 0

const riskLabel = (score: number) => {
  if (score >= 85) return { label: 'CRITICAL', color: '#ff2d55', rgb: '255,45,85' }
  if (score >= 65) return { label: 'HIGH', color: '#ff6b2d', rgb: '255,107,45' }
  if (score >= 40) return { label: 'ELEVATED', color: '#ffd60a', rgb: '255,214,10' }
  if (score > 0)  return { label: 'MANAGED', color: '#30d158', rgb: '48,209,88' }
  return { label: 'OFFLINE', color: '#636366', rgb: '99,99,102' }
}

function AnimatedTitle({ line1, line2 }: { line1: string; line2: string }) {
  return (
    <div className="relative select-none animate-text-glitch">
      {/* Base */}
      <h1 className="text-4xl font-black tracking-tight text-white md:text-6xl xl:text-[5.25rem] xl:leading-[1.0]">
        {line1}
        <span
          className="block"
          style={{
            WebkitTextStroke: '1.5px rgba(var(--brand-rgb),0.7)',
            color: 'transparent',
            textShadow: '0 0 40px rgba(var(--brand-rgb),0.4)',
          }}
        >
          {line2}
        </span>
      </h1>
      {/* Cyan glitch layer */}
      <h1
        aria-hidden
        className="pointer-events-none absolute inset-0 text-4xl font-black tracking-tight md:text-6xl xl:text-[5.25rem] xl:leading-[1.0]"
        style={{
          color: '#00ffff',
          animation: 'glitch-rgb-1 9s ease-in-out infinite',
          opacity: 0.9,
          textShadow: '0 0 8px rgba(0,255,255,0.6)',
          mixBlendMode: 'screen',
        }}
      >
        {line1}
        <span className="block">{line2}</span>
      </h1>
      {/* Magenta glitch layer */}
      <h1
        aria-hidden
        className="pointer-events-none absolute inset-0 text-4xl font-black tracking-tight md:text-6xl xl:text-[5.25rem] xl:leading-[1.0]"
        style={{
          color: '#ff0080',
          animation: 'glitch-rgb-2 9s ease-in-out infinite 0.12s',
          opacity: 0.85,
          textShadow: '0 0 8px rgba(255,0,128,0.6)',
          mixBlendMode: 'screen',
        }}
      >
        {line1}
        <span className="block">{line2}</span>
      </h1>
    </div>
  )
}

const ScanBeam = memo(function ScanBeam({ color = 'var(--brand)' }: { color?: string }) {
  return (
    <div
      className="pointer-events-none absolute inset-x-0 h-[2px] animate-scan-y"
      style={{
        top: 0,
        background: `linear-gradient(90deg, transparent, ${color}aa, rgba(255,255,255,0.8), ${color}aa, transparent)`,
        boxShadow: `0 0 16px ${color}88`,
        zIndex: 5,
      }}
    />
  )
})

function RacePanel({
  children,
  className = '',
  delay = 0,
  accentColor,
  scanBeam = false,
  scanBeamColor,
}: {
  children: React.ReactNode
  className?: string
  delay?: number
  accentColor?: string
  scanBeam?: boolean
  scanBeamColor?: string
}) {
  const accent = accentColor ?? 'rgba(var(--brand-rgb),0.9)'

  return (
    <motion.div
      custom={delay}
      variants={fadeUp}
      initial="hidden"
      animate="visible"
      className={`relative rounded-2xl p-[1px] ${className}`}
      style={{
        background: `linear-gradient(135deg, ${accent} 0%, rgba(255,255,255,0.04) 22%, rgba(255,255,255,0.02) 100%)`,
      }}
    >
      <div
        className="relative h-full overflow-hidden rounded-[15px]"
        style={{ background: '#000' }}
      >
        {scanBeam && <ScanBeam color={scanBeamColor ?? 'rgba(255,255,255,0.3)'} />}
        <CornerFrame size={20} color="rgba(255,255,255,0.2)" />
        <div
          className="pointer-events-none absolute inset-x-0 top-0 h-px"
          style={{ background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.12), transparent)' }}
        />
        {children}
      </div>
    </motion.div>
  )
}

function PanelHeader({
  title,
  eyebrow,
  action,
  icon: Icon,
}: {
  title: string
  eyebrow?: string
  action?: React.ReactNode
  icon?: React.ComponentType<{ className?: string; style?: React.CSSProperties }>
}) {
  return (
    <div className="mb-5 flex items-start justify-between gap-4">
      <div className="min-w-0 flex items-center gap-3">
        {Icon && (
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-white/[0.04] bg-black">
            <Icon className="h-4 w-4" style={{ color: 'rgba(var(--brand-rgb),0.8)' }} />
          </div>
        )}
        <div className="min-w-0">
          {eyebrow && (
            <div className="font-mono text-[9px] uppercase tracking-[0.28em]" style={{ color: 'rgba(var(--accent1-rgb),0.6)' }}>
              {eyebrow}
            </div>
          )}
          <h2 className="truncate text-sm font-bold tracking-wide text-zinc-100">{title}</h2>
        </div>
      </div>
      {action}
    </div>
  )
}

const MetricSkeleton = memo(function MetricSkeleton() {
  return (
    <div className="animate-pulse rounded-xl border border-white/[0.04] bg-transparent p-4">
      <div className="h-2.5 w-16 rounded bg-white/10" />
      <div className="mt-4 h-7 w-12 rounded bg-white/10" />
      <div className="mt-3 h-1.5 w-full rounded bg-white/10" />
    </div>
  )
})

const PanelSkeleton = memo(function PanelSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="animate-pulse space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-white/10" />
          <div className="h-2.5 flex-1 rounded bg-white/10" />
          <div className="h-2.5 w-12 rounded bg-white/10" />
        </div>
      ))}
    </div>
  )
})

function SeverityRail({ counts, total, assessmentId }: { counts: Record<string, number>; total: number; assessmentId?: string | null }) {
  return (
    <div className="space-y-2.5">
      {severityOrder.map((severity, idx) => {
        const count = counts[severity] ?? 0
        const pct = total > 0 ? Math.round((count / total) * 100) : 0
        const color = SEVERITY_COLORS[severity]
        return (
          <Link
            key={severity}
            href={assessmentId ? `/findings?assessment_id=${assessmentId}&severity=${severity}` : `/findings?severity=${severity}`}
            className="group block rounded-xl border border-white/[0.04] bg-transparent px-3 py-2.5 transition-all hover:border-white/16 hover:bg-black"
            style={{ textDecoration: 'none' }}
          >
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ background: color, boxShadow: `0 0 8px ${color}` }}
                />
                <span className="font-mono text-[10px] font-bold tracking-[0.18em] text-zinc-400">{severity}</span>
              </div>
              <div className="font-mono text-sm font-black tabular-nums" style={{ color }}>{count}</div>
            </div>
            <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/5">
              <motion.div
                className="h-full rounded-full"
                initial={{ width: 0 }}
                animate={{ width: `${pct}%` }}
                transition={{ duration: 0.8, delay: idx * 0.08, ease: [0.16, 1, 0.3, 1] }}
                style={{ background: color, boxShadow: `0 0 10px ${color}88` }}
              />
            </div>
          </Link>
        )
      })}
    </div>
  )
}

function MetricTile({
  label,
  value,
  icon: Icon,
  color,
  href,
  loading,
}: {
  label: string
  value: string | number
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>
  color: string
  href?: string
  loading?: boolean
}) {
  const inner = (
    <div
      className="group relative h-full overflow-hidden rounded-2xl border border-white/[0.04] p-4 transition-all duration-300 hover:border-white/20"
      style={{
        background: '#000',
        boxShadow: `inset 0 1px 0 rgba(255,255,255,0.04)`,
      }}
    >
      {/* Corner accent */}
      <div
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100 rounded-2xl"
        style={{ background: `radial-gradient(circle at 0% 0%, ${color}18, transparent 60%)` }}
      />
      <div className="absolute inset-x-0 top-0 h-px opacity-60" style={{ background: `linear-gradient(90deg, transparent, ${color}, transparent)` }} />

      <div className="flex items-start justify-between gap-2">
        <div
          className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/[0.04]"
          style={{ background: `${color}18`, boxShadow: `0 0 20px ${color}22` }}
        >
          <Icon className="h-4.5 w-4.5" style={{ color, filter: `drop-shadow(0 0 6px ${color})` }} />
        </div>
        {href && (
          <ArrowUpRight className="h-3.5 w-3.5 text-zinc-700 transition-colors group-hover:text-zinc-300" />
        )}
      </div>

      <div
        className="mt-4 text-2xl font-black tabular-nums"
        style={{ color: 'white', textShadow: `0 0 30px ${color}66` }}
      >
        {loading ? (
          <div className="h-7 w-10 animate-pulse rounded bg-white/10" />
        ) : value}
      </div>
      <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.2em] text-zinc-500">{label}</div>
    </div>
  )

  return href ? (
    <Link href={href} className="block h-full" style={{ textDecoration: 'none' }}>{inner}</Link>
  ) : inner
}

function TerminalRow({
  label,
  value,
  color,
  blink = false,
}: {
  label: string
  value: string
  color: string
  blink?: boolean
}) {
  return (
    <div className="flex items-center gap-3">
      <span className="font-mono text-[10px] tracking-[0.12em] text-zinc-600 uppercase w-28 shrink-0">{label}</span>
      <span className="font-mono text-[9px] text-zinc-700">{'//'}</span>
      <span
        className="font-mono text-[11px] font-bold uppercase tracking-[0.15em]"
        style={{ color, textShadow: `0 0 12px ${color}88` }}
      >
        {value}
      </span>
      {blink && (
        <span
          className="ml-auto h-2 w-2 rounded-full animate-neon-flicker"
          style={{ background: color, boxShadow: `0 0 8px ${color}` }}
        />
      )}
    </div>
  )
}

export function Dashboard() {
  const [mounted, setMounted] = useState(false)

  const { data: assessments, isLoading: loadingAssessments } = useQuery({
    queryKey: assessmentKeys.latest(),
    queryFn: () => assessmentApi.list({ limit: 1 }),
    staleTime: 5 * 60 * 1000,
  })

  const latestAssessment = assessments?.[0] ?? null
  const assessmentId = latestAssessment?.id ?? null

  const { data: dashData, isLoading: loadingDash, refetch, isFetching } = useQuery({
    queryKey: assessmentKeys.dashboard(assessmentId ?? 'none'),
    queryFn: () => assessmentApi.dashboard(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  useEffect(() => setMounted(true), [])

  const exposure = dashData?.exposure ?? EMPTY_STATS
  const domainInfo = dashData?.domain_info ?? {}
  const topFindings = (dashData?.top_findings ?? []) as Finding[]
  const moduleCounts = dashData?.module_breakdown ?? {}
  const coverageItems = dashData?.coverage ?? []
  const assessment = dashData?.assessment ?? latestAssessment
  const isLoading = loadingAssessments || loadingDash

  const severityCounts = exposure.severity_counts ?? EMPTY_STATS.severity_counts
  const totalFindings =
    statNumber(exposure.total_findings) ||
    Object.values(severityCounts).reduce((s, v) => s + statNumber(v), 0)
  const score = statNumber(exposure.exposure_score)
  const risk = riskLabel(score)

  const lastDate = assessment?.completed_at ?? assessment?.started_at ?? assessment?.created_at ?? null
  const lastAssessedText = lastDate ? (mounted ? timeAgo(lastDate) : 'recently') : 'not assessed'

  const dominantSeverity = useMemo(
    () => severityOrder.find((s) => (severityCounts[s] ?? 0) > 0) ?? 'INFO',
    [severityCounts]
  )

  const handleRefresh = useCallback(() => refetch(), [refetch])

  return (
    <div className="relative min-h-full overflow-hidden">
      {/* ── Main Content ────────────────────────────────────────────────── */}
      <main className="relative z-10 space-y-5 p-4 pb-10 md:p-6 xl:p-7">

        {/* ── HERO — no panel, skull is the hero ────────────────────────── */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.7 }}
          className="relative grid gap-4 xl:grid-cols-[1fr_300px]"
          style={{ minHeight: '520px' }}
        >
          {/* Left — floating text, no box */}
          <div className="flex flex-col justify-between gap-6 py-2">
            {/* Title */}
            <div>
              <AnimatedTitle line1="Identity Exposure" line2="Command Center" />
            </div>

            {/* Terminal */}
            <div
              className="max-w-xs space-y-2 rounded-xl border border-white/[0.04] px-4 py-3 font-mono"
              style={{ background: '#000',  }}
            >
              <div className="mb-2 flex items-center gap-2">
                <Terminal className="h-3 w-3" style={{ color: 'rgba(var(--accent1-rgb),0.6)' }} />
                <span className="text-[9px] uppercase tracking-[0.25em] text-zinc-600">runtime/status</span>
                <span className="ml-auto animate-cursor-blink text-[10px] text-zinc-600">_</span>
              </div>
              <TerminalRow label="Attack Graph" value={assessmentId ? 'Online' : 'Idle'} color={assessmentId ? '#00ffff' : '#636366'} blink={!!assessmentId} />
              <TerminalRow label="Rule Engine"  value={isLoading ? 'Syncing...' : 'Ready'} color="#30d158" blink />
              <TerminalRow label="Risk Model"   value={risk.label} color={risk.color} blink />
              <TerminalRow label="Last Scan"    value={lastAssessedText} color="rgba(var(--brand-rgb),0.7)" />
            </div>

            {/* Metric tiles */}
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <MetricTile label="Findings"    value={isLoading ? '-' : fmtNumber(totalFindings)}                         icon={AlertTriangle} color={SEVERITY_COLORS[dominantSeverity]} href={assessmentId ? `/findings?assessment_id=${assessmentId}` : '/findings'}          loading={isLoading} />
              <MetricTile label="Users"       value={isLoading ? '-' : fmtNumber(Number(domainInfo.total_users) || 0)}   icon={Users}        color="#00ffff"                            loading={isLoading} />
              <MetricTile label="Computers"   value={isLoading ? '-' : fmtNumber(Number(domainInfo.total_computers) || 0)} icon={Server}     color="#a78bfa"                            loading={isLoading} />
              <MetricTile label="New Signals" value={isLoading ? '-' : fmtNumber(Number(exposure.new_findings) || 0)}   icon={Sparkles}     color="#ff2d55"                            href={assessmentId ? `/findings?assessment_id=${assessmentId}` : '/findings'} loading={isLoading} />
            </div>
          </div>

          {/* Right — pitch black score panel */}
          <div className="relative flex flex-col overflow-hidden rounded-2xl" style={{ background: '#000' }}>
            <style>{`
              @import url('https://fonts.googleapis.com/css2?family=Cinzel+Decorative:wght@700;900&family=Cinzel:wght@600;700;900&family=Share+Tech+Mono&display=swap');
              @keyframes redEyePulse{0%,100%{opacity:0.35}50%{opacity:1}}
              .red-eye{animation:redEyePulse 2s ease-in-out infinite}
            `}</style>

            {/* Header */}
            <div className="flex items-center justify-between gap-3 px-5 pt-5">
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="red-eye h-1.5 w-1.5 rounded-full" style={{ background: '#C41230' }} />
                  <span style={{ fontFamily: "'Cinzel', serif", fontSize: '8px', letterSpacing: '0.32em', color: 'rgba(196,18,48,0.45)' }}>
                    EXPOSURE SCORE
                  </span>
                </div>
                <div className="mt-1" style={{ fontFamily: "'Cinzel', serif", fontSize: '15px', fontWeight: 700, letterSpacing: '0.18em', color: '#C41230' }}>
                  {risk.label}
                </div>
              </div>
              <button
                onClick={handleRefresh}
                disabled={isFetching}
                className="inline-flex items-center gap-2 px-3 py-1.5 transition disabled:opacity-40 hover:opacity-70"
                style={{ fontFamily: "'Cinzel', serif", fontSize: '9px', letterSpacing: '0.22em', color: 'rgba(196,18,48,0.55)', background: 'transparent', border: 'none' }}
                type="button"
              >
                {isFetching ? <Loader2 className="h-3 w-3 animate-spin" style={{ color: '#C41230' }} /> : <RefreshCw className="h-3 w-3" style={{ color: '#C41230' }} />}
                SYNC
              </button>
            </div>

            {/* Gauge */}
            <div className="relative flex flex-1 items-center justify-center py-6">
              {isLoading
                ? <div className="h-40 w-40 animate-pulse rounded-full bg-white/5" />
                : <ScoreGauge score={score} size="lg" delta={exposure.score_delta ?? undefined} />
              }
            </div>

            {/* Deltas */}
            <div className="px-5">
              <div className="grid grid-cols-3">
                {[
                  { label: 'NEW',       value: exposure.new_findings,       color: '#FF2200' },
                  { label: 'RESOLVED',  value: exposure.resolved_findings,  color: '#22c55e' },
                  { label: 'REGRESSED', value: exposure.regressed_findings, color: '#FF6B00' },
                ].map((item) => (
                  <div key={item.label} className="flex flex-col items-center gap-1 py-3">
                    <div className="tabular-nums leading-none" style={{ fontFamily: "'Cinzel Decorative', serif", fontSize: '22px', fontWeight: 900, color: item.color }}>
                      {isLoading ? '–' : fmtNumber(Number(item.value) || 0)}
                    </div>
                    <div style={{ fontFamily: "'Cinzel', serif", fontSize: '7px', letterSpacing: '0.28em', color: 'rgba(196,18,48,0.3)' }}>
                      {item.label}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Footer */}
            <div className="mt-4 flex items-center justify-between gap-3 px-5 py-4">
              <span style={{ fontFamily: "'Share Tech Mono', monospace", fontSize: '9px', color: 'rgba(196,18,48,0.3)' }}>
                {'//'} assessed {lastAssessedText}
              </span>
              <Link
                href="/assessments"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 transition hover:opacity-70"
                style={{ fontFamily: "'Cinzel', serif", fontSize: '9px', letterSpacing: '0.2em', color: 'rgba(196,18,48,0.6)', background: 'transparent', border: 'none', textDecoration: 'none' }}
              >
                <Plus className="h-3 w-3" style={{ color: '#C41230' }} />
                NEW SCAN
              </Link>
            </div>
          </div>
        </motion.div>

        {/* ── MID ROW: Severity + Module ──────────────────────────────────── */}
        <div className="grid gap-5 lg:grid-cols-2">
          <RacePanel delay={0.05} scanBeam accentColor="#C41230" scanBeamColor="rgba(196,18,48,0.7)">
            <div className="relative overflow-hidden p-5">
              <PanelHeader title="Severity Distribution" eyebrow="Risk Spectrum" icon={AlertTriangle} />
              {isLoading ? <PanelSkeleton rows={5} /> : <SeverityBreakdownChart counts={severityCounts} />}
            </div>
          </RacePanel>

          <RacePanel delay={0.1} scanBeam accentColor="rgba(var(--brand-rgb),0.9)">
            <div className="p-5">
              <PanelHeader title="Module Signal Density" eyebrow="Detection Sources" icon={Radar} />
              {isLoading ? <PanelSkeleton rows={7} /> : (
                <ModuleBreakdown liveCounts={Object.keys(moduleCounts).length > 0 ? moduleCounts : undefined} />
              )}
            </div>
          </RacePanel>
        </div>

        {/* ── ATTACK PATHS ────────────────────────────────────────────────── */}
        <RacePanel delay={0.15} scanBeam accentColor="rgba(236,72,153,0.9)">
          <div className="p-5">
            <PanelHeader
              title="Privilege Escalation Paths"
              eyebrow="Graph Intelligence"
              icon={Eye}
              action={assessmentId && (
                <Link
                  href={assessmentId ? `/graph?assessment_id=${assessmentId}` : '/graph'}
                  className="inline-flex items-center gap-2 rounded-xl border border-white/[0.04] bg-black px-3 py-2 text-xs text-zinc-300 transition hover:border-white/20 font-mono tracking-wide"
                  style={{ textDecoration: 'none' }}
                >
                  Full Graph
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </Link>
              )}
            />
            {assessmentId ? (
              <PathMiniGraph assessmentId={assessmentId} />
            ) : (
              <div
                className="rounded-2xl border border-dashed border-white/[0.04] p-10 text-center font-mono text-xs tracking-widest text-zinc-600"
              >
                [ AWAITING TARGET — IMPORT OR CREATE ASSESSMENT ]
              </div>
            )}
          </div>
        </RacePanel>

        {/* ── BOTTOM GRID ─────────────────────────────────────────────────── */}
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">

          {/* Top Findings */}
          <RacePanel delay={0.2} scanBeam accentColor="#ff2d55">
            <div className="p-5">
              <PanelHeader
                title="Top Findings by Risk"
                eyebrow="Priority Queue"
                icon={AlertTriangle}
                action={
                  <Link
                    href={assessmentId ? `/findings?assessment_id=${assessmentId}` : '/findings'}
                    className="inline-flex items-center gap-2 rounded-xl border border-white/[0.04] bg-black px-3 py-2 text-xs text-zinc-300 transition hover:border-white/20 font-mono tracking-wide"
                    style={{ textDecoration: 'none' }}
                  >
                    View All
                    <ArrowUpRight className="h-3.5 w-3.5" />
                  </Link>
                }
              />
              {isLoading ? <PanelSkeleton rows={8} /> : <TopFindingsList findings={topFindings} />}
            </div>
          </RacePanel>

          {/* Sidebar */}
          <aside className="space-y-5">

            {/* Severity Rail */}
            <RacePanel delay={0.07} accentColor="#ffd60a">
              <div className="p-5">
                <PanelHeader title="Severity Rail" eyebrow="Open Findings" icon={Shield} />
                {isLoading ? <PanelSkeleton rows={5} /> : (
                  <SeverityRail counts={severityCounts} total={totalFindings} assessmentId={assessmentId} />
                )}
              </div>
            </RacePanel>

            {/* Domain Telemetry */}
            <RacePanel delay={0.12} accentColor="rgba(var(--accent1-rgb),0.9)">
              <div className="p-5">
                <PanelHeader title="Domain Telemetry" eyebrow="Directory Scope" icon={Database} />
                <div className="space-y-2.5">
                  {isLoading ? (
                    <><MetricSkeleton /><MetricSkeleton /></>
                  ) : (
                    [
                      { label: 'Tier-0 Exposure', value: domainInfo.tier0_exposure ?? '-', icon: Shield, color: '#ff2d55' },
                      { label: 'Kerberoastable', value: domainInfo.kerberoastable ?? '-', icon: Lock, color: '#ff6b2d' },
                      { label: 'ESC1 Templates', value: domainInfo.esc1_templates ?? '-', icon: Zap, color: '#ff0080' },
                      { label: 'Assessment', value: assessment?.name ?? 'No assessment', icon: Database, color: '#00ffff' },
                    ].map(({ label, value, icon: Icon, color }) => (
                      <div
                        key={label}
                        className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.04] bg-transparent px-3 py-2.5 transition hover:border-white/12"
                      >
                        <div className="flex min-w-0 items-center gap-2.5">
                          <div
                            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg"
                            style={{ background: `${color}15`, boxShadow: `0 0 12px ${color}18` }}
                          >
                            <Icon className="h-3.5 w-3.5" style={{ color }} />
                          </div>
                          <div className="min-w-0">
                            <div className="truncate text-sm font-medium text-zinc-200">{String(value)}</div>
                            <div className="font-mono text-[8px] uppercase tracking-[0.18em] text-zinc-600">{label}</div>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </RacePanel>

            {/* Kill Chain Mini Widget */}
            <RacePanel delay={0.15} accentColor="rgba(99,102,241,0.9)">
              <KillChainMiniWidget assessmentId={assessmentId ?? undefined} />
            </RacePanel>

            {/* Coverage Matrix */}
            <RacePanel delay={0.18} accentColor="rgba(var(--brand-rgb),0.9)">
              <div className="p-5">
                <PanelHeader title="Coverage Matrix" eyebrow="Control Surface" icon={Activity} />
                {isLoading ? <PanelSkeleton rows={6} /> : <CoverageMatrix items={coverageItems} />}
              </div>
            </RacePanel>

            {/* Ops Ledger */}
            <RacePanel delay={0.24} accentColor="#a78bfa">
              <div className="p-5">
                <PanelHeader title="Operations Ledger" eyebrow="System State" icon={History} />
                <div className="space-y-2.5">
                  {[
                    { icon: Activity, label: 'Validation mode', value: 'Authorized', color: '#30d158' },
                    { icon: Radar, label: 'Graph engine', value: assessmentId ? 'Ready' : 'Idle', color: '#00ffff' },
                    { icon: History, label: 'Audit trail', value: 'Recording', color: '#a78bfa' },
                  ].map(({ icon: Icon, label, value, color }) => (
                    <div
                      key={label}
                      className="flex items-center justify-between rounded-xl border border-white/[0.04] bg-transparent px-3 py-2"
                    >
                      <div className="flex items-center gap-2 font-mono text-xs text-zinc-400">
                        <Icon className="h-3.5 w-3.5" style={{ color }} />
                        {label}
                      </div>
                      <div className="flex items-center gap-2">
                        <span
                          className="h-1.5 w-1.5 rounded-full animate-neon-flicker"
                          style={{ background: color, boxShadow: `0 0 8px ${color}` }}
                        />
                        <span
                          className="font-mono text-[10px] uppercase tracking-[0.16em]"
                          style={{ color }}
                        >
                          {value}
                        </span>
                      </div>
                    </div>
                  ))}
                  <Link
                    href="/audit"
                    className="mt-1 inline-flex w-full items-center justify-center gap-2 rounded-xl border border-white/[0.04] bg-black px-3 py-2 font-mono text-xs text-zinc-300 transition hover:border-white/16 hover:bg-white/[0.06]"
                    style={{ textDecoration: 'none' }}
                  >
                    Audit Ledger
                    <ArrowUpRight className="h-3.5 w-3.5" />
                  </Link>
                </div>
              </div>
            </RacePanel>
          </aside>
        </div>

      </main>
    </div>
  )
}
