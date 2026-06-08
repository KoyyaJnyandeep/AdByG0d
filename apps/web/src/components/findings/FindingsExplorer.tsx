'use client'

import { useDeferredValue, useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Check,
  ChevronRight,
  Crosshair,
  Database,
  Download,
  Filter,
  Flame,
  Gauge,
  GitBranch,
  Layers3,
  Loader2,
  Network,
  RefreshCcw,
  Route,
  Search,
  ShieldAlert,
  Sparkles,
  Target,
  Workflow,
  X,
} from 'lucide-react'

import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { ProvenanceBadge } from '@/components/ui/ProvenanceBadge'
import { assessmentApi, entitiesApi, findingsApi, graphApi } from '@/lib/api'
import { findingsKeys } from '@/lib/queryKeys'
import type { AttackCategory, ChokePoint, Finding, SeverityLevel } from '@/lib/types'
import { cn, fmtConfidence, fmtNumber, fmtScore, moduleColor, safeDateMs, timeAgo } from '@/lib/utils'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'

const SEVERITY_FILTERS: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const STATUS_FILTERS = ['OPEN', 'IN_REVIEW', 'REGRESSED', 'REMEDIATED', 'ACCEPTED', 'FALSE_POSITIVE']

function queryValues(key: string) {
  if (typeof window === 'undefined') return []

  return new URLSearchParams(window.location.search)
    .getAll(key)
    .flatMap((value) => value.split(','))
    .map((value) => value.trim())
    .filter(Boolean)
}

function initialSearchValue() {
  if (typeof window === 'undefined') return ''
  return new URLSearchParams(window.location.search).get('q')?.trim() ?? ''
}

function initialFilterSet(key: string, allowed?: readonly string[], uppercase = false) {
  const values = queryValues(key).map((value) => uppercase ? value.toUpperCase() : value)
  const filtered = allowed ? values.filter((value) => allowed.includes(value)) : values
  return new Set(filtered)
}

function normalizeModuleKey(value: string) {
  const compact = value.trim().toLowerCase().replace(/[\s_-]+/g, '')
  const aliases: Record<string, string> = {
    adcs: 'adcs',
    pki: 'adcs',
    certificateservices: 'adcs',
    trust: 'trust',
    trusts: 'trust',
    topologyandtrusts: 'trust',
    domainandforesttrustanalysis: 'trust',
    crossforestenumeration: 'trust',
    serviceaccount: 'serviceaccounts',
    serviceaccounts: 'serviceaccounts',
    serviceaccountreview: 'serviceaccounts',
    acl: 'acl',
    aclabuse: 'acl',
    directoryacl: 'acl',
    kerberos: 'kerberos',
    kerberosposture: 'kerberos',
  }
  return aliases[compact] ?? compact
}

function moduleMatchesFilter(moduleName: string, filters: Set<string>) {
  if (filters.size === 0) return true
  const moduleKey = normalizeModuleKey(moduleName)
  return Array.from(filters).some(filter => {
    const filterKey = normalizeModuleKey(filter)
    return moduleKey === filterKey || moduleKey.includes(filterKey) || filterKey.includes(moduleKey)
  })
}

const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

type SortField = 'composite_score' | 'severity' | 'affected_count' | 'created_at'

const severityTone: Record<string, { border: string; bg: string; text: string; glow: string }> = {
  CRITICAL: { border: 'border-red-300/35', bg: 'bg-red-500/10', text: 'text-red-100', glow: 'shadow-[0_0_42px_rgba(239,68,68,0.16)]' },
  HIGH: { border: 'border-amber-300/35', bg: 'bg-amber-500/10', text: 'text-amber-100', glow: 'shadow-[0_0_38px_rgba(245,158,11,0.14)]' },
  MEDIUM: { border: 'border-yellow-300/30', bg: 'bg-yellow-500/10', text: 'text-yellow-100', glow: 'shadow-[0_0_30px_rgba(234,179,8,0.1)]' },
  LOW: { border: 'border-emerald-300/25', bg: 'bg-emerald-500/10', text: 'text-emerald-100', glow: 'shadow-[0_0_26px_rgba(16,185,129,0.1)]' },
  INFO: { border: 'border-sky-300/25', bg: 'bg-sky-500/10', text: 'text-sky-100', glow: 'shadow-[0_0_24px_rgba(56,189,248,0.1)]' },
}

function compact(value: number | undefined) {
  if (value === undefined || Number.isNaN(value)) return '--'
  return new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 }).format(value)
}

function scoreTone(score: number) {
  if (score >= 95) return 'text-red-100'
  if (score >= 80) return 'text-amber-100'
  if (score >= 55) return 'text-yellow-100'
  return 'text-cyan-100'
}

function RiskTile({ label, value, detail, icon: Icon, tone }: {
  label: string
  value: string
  detail: string
  icon: typeof ShieldAlert
  tone: string
}) {
  return (
    <div className="border border-white/10 bg-black p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-bold uppercase tracking-[0.22em] text-zinc-500">{label}</div>
          <div className={cn('mt-2 text-2xl font-black', tone)}>{value}</div>
          <div className="mt-1 text-xs text-zinc-500">{detail}</div>
        </div>
        <Icon className={cn('h-5 w-5', tone)} />
      </div>
    </div>
  )
}

function FilterButton({
  active,
  label,
  count,
  onClick,
  color,
}: {
  active: boolean
  label: string
  count?: number
  onClick: () => void
  color?: string
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex w-full items-center justify-between border px-3 py-2 text-left text-xs font-bold uppercase tracking-[0.14em] transition',
        active ? 'border-cyan-300/35 bg-cyan-300/10 text-cyan-100' : 'border-white/10 bg-black text-zinc-400 hover:border-white/20 hover:bg-white/[0.04] hover:text-zinc-200'
      )}
    >
      <span className="flex min-w-0 items-center gap-2">
        <span className="h-1.5 w-1.5 shrink-0" style={{ backgroundColor: color ?? 'rgb(113 113 122)' }} />
        <span className="truncate">{label}</span>
      </span>
      {count !== undefined && <span className="text-[11px] text-zinc-500">{count}</span>}
    </button>
  )
}

function FindingCard({
  finding,
  active,
  onClick,
}: {
  finding: Finding
  active: boolean
  onClick: () => void
}) {
  const tone = severityTone[finding.severity] ?? severityTone.INFO
  const score = finding.composite_score ?? 0

  return (
    <motion.button
      type="button"
      onClick={onClick}
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        'group relative w-full border p-4 text-left transition',
        active ? cn(tone.border, tone.bg, tone.glow) : 'border-white/10 bg-black hover:border-white/20 hover:bg-white/[0.045]'
      )}
    >
      <div className="grid gap-4 xl:grid-cols-[1fr_150px_90px]">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge status={finding.status} />
            <ProvenanceBadge origin={finding.origin} />
            {finding.drift_status && (
              <span className="border border-white/10 bg-black px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.16em] text-zinc-400">
                {finding.drift_status}
              </span>
            )}
          </div>
          <div className="mt-3 text-base font-black leading-6 text-white group-hover:text-cyan-100">{finding.title}</div>
          <p className="mt-2 line-clamp-2 text-sm leading-6 text-zinc-400">{finding.description}</p>
          <div className="mt-3 flex flex-wrap items-center gap-3 text-[11px] text-zinc-500">
            <span className="font-mono uppercase tracking-[0.14em]">{finding.finding_type}</span>
            <span>confidence {fmtConfidence(finding.confidence)}</span>
            {finding.root_cause && <span className="max-w-[520px] truncate">root: {finding.root_cause}</span>}
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <span
            className="w-fit border px-2.5 py-1 text-xs font-bold"
            style={{ color: moduleColor(finding.module), borderColor: `${moduleColor(finding.module)}44`, backgroundColor: `${moduleColor(finding.module)}14` }}
          >
            {finding.module}
          </span>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="border border-white/10 bg-black p-2">
              <div className="text-[9px] uppercase tracking-[0.18em] text-zinc-600">Affected</div>
              <div className="mt-1 font-bold text-white">{compact(finding.affected_count)}</div>
            </div>
            <div className="border border-white/10 bg-black p-2">
              <div className="text-[9px] uppercase tracking-[0.18em] text-zinc-600">Seen</div>
              <div className="mt-1 font-bold text-zinc-300">{timeAgo(finding.created_at)}</div>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between gap-3 xl:block xl:text-right">
          <div>
            <div className={cn('text-2xl font-black', scoreTone(score))}>{fmtScore(score)}</div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-zinc-600">score</div>
          </div>
          <ChevronRight className={cn('h-5 w-5 transition group-hover:translate-x-1', active ? 'text-white' : 'text-zinc-600')} />
        </div>
      </div>
    </motion.button>
  )
}

function FindingDossier({ finding }: { finding: Finding | null }) {
  if (!finding) {
    return (
      <div className="grid min-h-[520px] place-items-center border border-white/10 bg-black/30 p-6 text-center">
        <div>
          <Target className="mx-auto h-10 w-10 text-zinc-600" />
          <div className="mt-3 font-bold text-white">No finding selected</div>
          <div className="mt-2 text-sm text-zinc-500">Select a finding to inspect impact, evidence posture, and fix path.</div>
        </div>
      </div>
    )
  }

  const affected = (finding.affected_objects ?? []).slice(0, 8)
  const steps = (finding.remediation_steps ?? []).slice(0, 5)

  return (
    <div className="sticky top-24 space-y-4">
      <div className={cn('border p-5', severityTone[finding.severity]?.border, severityTone[finding.severity]?.bg)}>
        <div className="flex items-center justify-between gap-3">
          <SeverityBadge severity={finding.severity} />
          <Link href={`/findings/${finding.id}`} className="inline-flex items-center gap-2 border border-white/15 bg-black px-3 py-1.5 text-xs font-bold text-white transition hover:bg-white/[0.1]">
            Open Detail <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </div>
        <h2 className="mt-4 text-xl font-black leading-7 text-white">{finding.title}</h2>
        <p className="mt-3 text-sm leading-6 text-zinc-300">{finding.description || 'No description recorded.'}</p>
        <div className="mt-5 grid grid-cols-3 gap-2">
          <RiskTile label="Score" value={fmtScore(finding.composite_score ?? 0)} detail="composite" icon={Gauge} tone={scoreTone(finding.composite_score ?? 0)} />
          <RiskTile label="Affected" value={compact(finding.affected_count)} detail="objects" icon={Network} tone="text-cyan-100" />
          <RiskTile label="Conf" value={fmtConfidence(finding.confidence)} detail="signal" icon={BadgeCheck} tone="text-emerald-100" />
        </div>
        {(finding.technical_severity != null || finding.reachability_score != null) && (
          <div className="mt-2 grid grid-cols-2 gap-2">
            {finding.technical_severity != null && (
              <RiskTile label="Tech Sev" value={finding.technical_severity.toFixed(1)} detail="technical" icon={ShieldAlert} tone="text-orange-100" />
            )}
            {finding.reachability_score != null && (
              <RiskTile label="Reach" value={`${Math.round(finding.reachability_score * 100)}%`} detail="reachability" icon={Route} tone="text-purple-100" />
            )}
          </div>
        )}
      </div>

      <div className="border border-white/10 bg-black p-5">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.22em] text-zinc-500">
          <Crosshair className="h-4 w-4 text-rose-200" /> Root Cause
        </div>
        <div className="mt-3 text-sm leading-6 text-zinc-300">{finding.root_cause || 'No root cause recorded.'}</div>
        <div className="mt-4 grid gap-2">
          {(finding.causal_chain ?? []).slice(0, 4).map((item, index) => (
            <div key={`${index}-${String(item)}`} className="flex gap-3 border border-white/10 bg-black p-3 text-xs text-zinc-300">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center bg-white text-[10px] font-black text-black">{index + 1}</span>
              <span>{String(item)}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="border border-white/10 bg-black p-5">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.22em] text-zinc-500">
          <Workflow className="h-4 w-4 text-cyan-200" /> Fix Path
        </div>
        <div className="mt-3 space-y-2">
          {steps.length > 0 ? steps.map((step, index) => (
            <div key={`${index}-${String(step)}`} className="flex gap-3 border border-emerald-300/10 bg-emerald-300/[0.035] p-3 text-xs text-emerald-50">
              <Check className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-200" />
              <span>{String(step)}</span>
            </div>
          )) : (
            <div className="text-sm text-zinc-400">{finding.remediation || 'No remediation guidance recorded.'}</div>
          )}
        </div>
      </div>

      <div className="border border-white/10 bg-black p-5">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.22em] text-zinc-500">
          <Database className="h-4 w-4 text-amber-200" /> Affected Preview
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {affected.length > 0 ? affected.map((item, index) => (
            <span key={`${index}-${String(item)}`} className="max-w-full truncate border border-white/10 bg-black px-2 py-1 text-[11px] text-zinc-300">
              {typeof item === 'string' ? item : JSON.stringify(item)}
            </span>
          )) : <span className="text-sm text-zinc-500">No affected object list recorded.</span>}
        </div>
      </div>

      {((finding.mitre_attack_ids?.length ?? 0) > 0 || (finding.cve_ids?.length ?? 0) > 0) && (
        <div className="border border-white/10 bg-black p-5">
          {(finding.mitre_attack_ids?.length ?? 0) > 0 && (
            <div className="mb-3">
              <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.22em] text-zinc-500">
                <ShieldAlert className="h-4 w-4 text-blue-200" /> MITRE ATT&CK
              </div>
              <div className="flex flex-wrap gap-1.5">
                {finding.mitre_attack_ids!.map(m => (
                  <span key={m} className="border border-blue-500/20 px-2 py-0.5 font-mono text-[10px] text-blue-400">{m}</span>
                ))}
              </div>
            </div>
          )}
          {(finding.cve_ids?.length ?? 0) > 0 && (
            <div>
              <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-[0.22em] text-zinc-500">
                <AlertTriangle className="h-4 w-4 text-red-200" /> CVEs
              </div>
              <div className="flex flex-wrap gap-1.5">
                {finding.cve_ids!.map(c => (
                  <span key={c} className="border border-red-500/20 px-2 py-0.5 font-mono text-[10px] text-red-400">{c}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function FindingsExplorer() {
  const [search, setSearch] = useState('')
  const deferredSearch = useDeferredValue(search)
  const [selectedSeverities, setSelectedSeverities] = useState<Set<string>>(new Set())
  const [selectedStatuses, setSelectedStatuses] = useState<Set<string>>(new Set())
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set())
  const [sortField, setSortField] = useState<SortField>('composite_score')
  const [sortDesc, setSortDesc] = useState(true)
  const [activeId, setActiveId] = useState<string | null>(null)

  useEffect(() => {
    setSearch(initialSearchValue())
    setSelectedSeverities(initialFilterSet('severity', SEVERITY_FILTERS, true))
    setSelectedStatuses(initialFilterSet('status', STATUS_FILTERS, true))
    setSelectedModules(initialFilterSet('module'))
  }, [])

  const { assessment: activeAssessment, assessmentId } = useRouteAssessmentScope()

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: findingsKeys.list(assessmentId ?? 'none', 500),
    queryFn: () => findingsApi.list({ assessment_id: assessmentId!, page_size: 500 }),
    enabled: !!assessmentId,
    staleTime: 30_000,
  })

  const { data: stats } = useQuery({
    queryKey: ['findings-assessment-stats', assessmentId],
    queryFn: () => assessmentApi.stats(assessmentId!) as Promise<Record<string, number>>,
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: entitySummary } = useQuery({
    queryKey: ['findings-entity-summary', assessmentId],
    queryFn: () => entitiesApi.summary(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: moduleSummary = [] } = useQuery({
    queryKey: ['findings-module-summary', assessmentId],
    queryFn: () => findingsApi.moduleSummary(assessmentId!) as Promise<Array<{ module: string; total: number }>>,
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: attackCategories } = useQuery({
    queryKey: ['findings-attack-categories', assessmentId],
    queryFn: () => graphApi.getCategories(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: chokePoints } = useQuery({
    queryKey: ['findings-choke-points', assessmentId],
    queryFn: () => graphApi.getChokePoints(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const findings = useMemo(() => data?.items ?? [], [data])

  const availableModules = useMemo(
    () => [...new Set(findings.map(f => f.module).filter(Boolean))].sort(),
    [findings],
  )

  const filtered = useMemo(() => {
    let result = [...findings]
    if (deferredSearch) {
      const q = deferredSearch.toLowerCase()
      result = result.filter(f => {
        if (f.title.toLowerCase().includes(q)) return true
        if (f.finding_type.toLowerCase().includes(q)) return true
        if (f.module.toLowerCase().includes(q)) return true
        if (f.root_cause?.toLowerCase().includes(q)) return true
        if (f.affected_objects?.some(obj =>
          typeof obj === 'string' ? obj.toLowerCase().includes(q) : JSON.stringify(obj).toLowerCase().includes(q),
        )) return true
        return false
      })
    }
    if (selectedSeverities.size > 0) result = result.filter(f => selectedSeverities.has(f.severity))
    if (selectedStatuses.size > 0) result = result.filter(f => selectedStatuses.has(f.status))
    if (selectedModules.size > 0) result = result.filter(f => moduleMatchesFilter(f.module, selectedModules))

    result.sort((a, b) => {
      let av = 0
      let bv = 0
      if (sortField === 'severity') { av = severityOrder[a.severity] ?? 99; bv = severityOrder[b.severity] ?? 99 }
      else if (sortField === 'affected_count') { av = a.affected_count ?? 0; bv = b.affected_count ?? 0 }
      else if (sortField === 'created_at') { av = safeDateMs(a.created_at) ?? 0; bv = safeDateMs(b.created_at) ?? 0 }
      else { av = a.composite_score ?? 0; bv = b.composite_score ?? 0 }
      return sortDesc ? bv - av : av - bv
    })
    return result
  }, [findings, deferredSearch, selectedSeverities, selectedStatuses, selectedModules, sortField, sortDesc])

  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1
    return counts
  }, [findings])

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const finding of findings) counts[finding.status] = (counts[finding.status] ?? 0) + 1
    return counts
  }, [findings])

  const activeFinding = useMemo(
    () => filtered.find(finding => finding.id === activeId) ?? filtered[0] ?? null,
    [activeId, filtered],
  )

  const totalAffected = useMemo(() => findings.reduce((sum, finding) => sum + (finding.affected_count ?? 0), 0), [findings])
  const averageScore = useMemo(() => findings.length ? findings.reduce((sum, finding) => sum + (finding.composite_score ?? 0), 0) / findings.length : 0, [findings])
  const critical = severityCounts.CRITICAL ?? 0
  const high = severityCounts.HIGH ?? 0
  const open = statusCounts.OPEN ?? 0
  const topCategory = useMemo(() => Object.values((attackCategories?.categories ?? {}) as Record<string, AttackCategory>).sort((a, b) => b.count - a.count)[0], [attackCategories])
  const topChoke = ((chokePoints?.choke_points ?? []) as ChokePoint[])[0]

  const clearFilters = () => {
    setSearch('')
    setSelectedSeverities(new Set())
    setSelectedStatuses(new Set())
    setSelectedModules(new Set())
  }

  const toggleFilter = (set: Set<string>, value: string, setter: (next: Set<string>) => void) => {
    const next = new Set(set)
    if (next.has(value)) next.delete(value)
    else next.add(value)
    setter(next)
  }

  const setSort = (field: SortField) => {
    if (sortField === field) setSortDesc(!sortDesc)
    else { setSortField(field); setSortDesc(true) }
  }

  if (!assessmentId) {
    return (
      <div className="grid min-h-[70vh] place-items-center p-10 text-center">
        <div>
          <Sparkles className="mx-auto h-16 w-16 text-cyan-100 drop-shadow-[0_0_18px_rgba(34,211,238,0.8)]" />
          <h2
            className="mt-5 text-3xl font-black tracking-wide text-white md:text-4xl"
            style={{
              textShadow:
                '3px 0 0 rgba(255,0,128,0.72), -3px 0 0 rgba(0,255,255,0.72), 0 0 26px rgba(255,255,255,0.55)',
            }}
          >
            No assessment loaded
          </h2>
          <p
            className="mt-3 text-lg font-semibold text-zinc-100 md:text-xl"
            style={{ textShadow: '2px 0 0 rgba(255,0,128,0.45), -2px 0 0 rgba(0,255,255,0.45), 0 0 18px rgba(0,0,0,0.95)' }}
          >
            Run an assessment first to populate live findings.
          </p>
          <Link
            href="/assessments"
            className="mt-6 inline-flex border border-cyan-300/45 bg-cyan-400/15 px-6 py-3 text-lg font-black text-cyan-100 shadow-[0_0_28px_rgba(34,211,238,0.24)] transition hover:border-fuchsia-300/50 hover:bg-fuchsia-400/15 hover:text-fuchsia-100"
            style={{ textShadow: '1px 0 0 rgba(255,0,128,0.6), -1px 0 0 rgba(0,255,255,0.6)' }}
          >
            Open assessments
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-full">
      <div className="border-b border-white/10 px-5 py-5 lg:px-8">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2 border border-red-300/25 bg-red-400/10 px-2.5 py-1 text-[10px] font-black uppercase tracking-[0.2em] text-red-100">
                <Flame className="h-3.5 w-3.5" /> Findings war room
              </span>
              <span className="inline-flex items-center gap-2 border border-cyan-300/20 bg-cyan-400/10 px-2.5 py-1 text-[10px] font-black uppercase tracking-[0.2em] text-cyan-100">
                <Database className="h-3.5 w-3.5" /> {activeAssessment?.name} · {activeAssessment?.domain}
              </span>
            </div>
            <h1 className="mt-4 text-3xl font-black text-white md:text-5xl">Findings</h1>
            <p className="mt-3 max-w-4xl text-sm leading-6 text-zinc-400">
              Triage identity exposure by blast radius, root cause, exploitability, and fix priority. The list is backed by the current assessment, not static UI.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <button onClick={() => refetch()} className="inline-flex h-10 items-center gap-2 border border-white/10 bg-black px-4 text-sm font-bold text-zinc-200 transition hover:bg-white/[0.08]">
              {isLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCcw className="h-4 w-4" />} Refresh
            </button>
            <Link href="/reports" className="inline-flex h-10 items-center gap-2 border border-cyan-300/20 bg-cyan-400/10 px-4 text-sm font-bold text-cyan-100 transition hover:bg-cyan-400/15">
              <Download className="h-4 w-4" /> Export
            </Link>
          </div>
        </div>
      </div>

      <div className="space-y-5 p-5 lg:p-8">
        <section className="grid gap-3 lg:grid-cols-4">
          <RiskTile label="Critical" value={String(critical)} detail={`${high} high findings queued`} icon={ShieldAlert} tone="text-red-100" />
          <RiskTile label="Affected" value={compact(totalAffected)} detail={`${compact(entitySummary?.total ?? Number(stats?.total_entities))} entities indexed`} icon={Target} tone="text-amber-100" />
          <RiskTile label="Avg Score" value={fmtScore(averageScore)} detail={`${open} open findings`} icon={Gauge} tone={scoreTone(averageScore)} />
          <RiskTile label="Graph Signal" value={topCategory ? compact(topCategory.count) : compact(attackCategories?.total_paths)} detail={topCategory?.name ?? `${compact(topChoke?.paths_through)} choke paths`} icon={GitBranch} tone="text-cyan-100" />
        </section>

        <section className="grid gap-5 2xl:grid-cols-[300px_minmax(0,1fr)_420px]">
          <aside className="space-y-4">
            <div className="border border-white/10 bg-black p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="text-xs font-black uppercase tracking-[0.22em] text-zinc-500">Filters</div>
                <button onClick={clearFilters} className="inline-flex items-center gap-1 text-xs text-zinc-500 transition hover:text-zinc-200">
                  <X className="h-3.5 w-3.5" /> Clear
                </button>
              </div>

              <div className="mt-4 space-y-5">
                <div>
                  <div className="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-600">
                    <Filter className="h-3.5 w-3.5" /> Severity
                  </div>
                  <div className="space-y-2">
                    {SEVERITY_FILTERS.map(severity => (
                      <FilterButton
                        key={severity}
                        active={selectedSeverities.has(severity)}
                        label={severity}
                        count={severityCounts[severity] ?? 0}
                        color={severity === 'CRITICAL' ? '#f87171' : severity === 'HIGH' ? '#fbbf24' : severity === 'MEDIUM' ? '#fde047' : severity === 'LOW' ? '#34d399' : '#38bdf8'}
                        onClick={() => toggleFilter(selectedSeverities, severity, setSelectedSeverities)}
                      />
                    ))}
                  </div>
                </div>

                <div>
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-600">Status</div>
                  <div className="space-y-2">
                    {STATUS_FILTERS.map(status => (
                      <FilterButton
                        key={status}
                        active={selectedStatuses.has(status)}
                        label={status.replaceAll('_', ' ')}
                        count={statusCounts[status] ?? 0}
                        onClick={() => toggleFilter(selectedStatuses, status, setSelectedStatuses)}
                      />
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="border border-white/10 bg-black p-4">
              <div className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.22em] text-zinc-500">
                <Layers3 className="h-4 w-4 text-cyan-200" /> Modules
              </div>
              <div className="mt-4 space-y-2">
                {availableModules.map(module => {
                  const count = moduleSummary.find(item => item.module === module)?.total
                  return (
                    <FilterButton
                      key={module}
                      active={selectedModules.has(module)}
                      label={module}
                      count={count}
                      color={moduleColor(module)}
                      onClick={() => toggleFilter(selectedModules, module, setSelectedModules)}
                    />
                  )
                })}
              </div>
            </div>

            <div className="border border-white/10 bg-black p-4">
              <div className="flex items-center gap-2 text-xs font-black uppercase tracking-[0.22em] text-zinc-500">
                <Route className="h-4 w-4 text-amber-200" /> Leverage
              </div>
              <div className="mt-4 space-y-2">
                <div className="border border-white/10 bg-black p-3">
                  <div className="text-[10px] uppercase tracking-[0.18em] text-zinc-600">Top category</div>
                  <div className="mt-1 text-sm font-bold text-white">{topCategory?.name ?? 'No category yet'}</div>
                </div>
                <div className="border border-white/10 bg-black p-3">
                  <div className="text-[10px] uppercase tracking-[0.18em] text-zinc-600">Top choke</div>
                  <div className="mt-1 truncate text-sm font-bold text-white">{topChoke?.label ?? 'No choke point yet'}</div>
                </div>
              </div>
            </div>
          </aside>

          <main className="space-y-4">
            <div className="border border-white/10 bg-black p-4">
              <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    value={search}
                    onChange={event => setSearch(event.target.value)}
                    placeholder="Search findings, modules, affected objects, root causes..."
                    className="h-11 w-full border border-white/10 bg-black pl-10 pr-4 text-sm text-white outline-none placeholder:text-zinc-500 focus:border-cyan-300/35"
                  />
                </div>
                <div className="grid grid-cols-4 gap-2 text-xs">
                  {[
                    ['Score', 'composite_score'],
                    ['Severity', 'severity'],
                    ['Affected', 'affected_count'],
                    ['Seen', 'created_at'],
                  ].map(([label, field]) => (
                    <button
                      key={field}
                      onClick={() => setSort(field as SortField)}
                      className={cn('border px-3 py-2 font-bold transition', sortField === field ? 'border-cyan-300/35 bg-cyan-300/10 text-cyan-100' : 'border-white/10 bg-black text-zinc-400 hover:bg-white/[0.06]')}
                    >
                      {label}{sortField === field ? (sortDesc ? ' ↓' : ' ↑') : ''}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {isLoading && (
              <div className="grid min-h-[360px] place-items-center border border-white/10 text-zinc-400">
                <div className="flex items-center gap-3"><Loader2 className="h-5 w-5 animate-spin" /> Loading findings...</div>
              </div>
            )}

            {isError && !isLoading && (
              <div className="border border-red-400/20 bg-red-500/10 p-8 text-center">
                <AlertTriangle className="mx-auto h-10 w-10 text-red-300" />
                <h2 className="mt-3 text-lg font-semibold text-white">Could not load findings</h2>
                <p className="mt-2 text-sm text-zinc-300">The API request failed. Refresh after verifying the backend is reachable.</p>
              </div>
            )}

            {!isLoading && !isError && filtered.length === 0 && (
              <div className="border border-white/10 bg-black p-8 text-center">
                <Sparkles className="mx-auto h-10 w-10 text-zinc-500" />
                <h2 className="mt-3 text-lg font-semibold text-white">No findings match the current filters</h2>
                <p className="mt-2 text-sm text-zinc-400">Try widening the search or clearing the current filter set.</p>
              </div>
            )}

            {!isLoading && !isError && filtered.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs text-zinc-500">
                  <span>{fmtNumber(filtered.length)} visible of {fmtNumber(findings.length)} findings</span>
                  <span>{activeAssessment?.domain ?? 'current domain'}</span>
                </div>
                {filtered.map(finding => (
                  <FindingCard
                    key={finding.id}
                    finding={finding}
                    active={activeFinding?.id === finding.id}
                    onClick={() => setActiveId(finding.id)}
                  />
                ))}
              </div>
            )}
          </main>

          <aside>
            <FindingDossier finding={activeFinding} />
          </aside>
        </section>
      </div>
    </div>
  )
}
