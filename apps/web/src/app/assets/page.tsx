'use client'

import { useEffect, useMemo, useState, type ElementType } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion } from 'framer-motion'
import {
  AlertCircle, ArrowDownWideNarrow, Boxes, BrainCircuit, CheckCircle2, Crown, Diamond,
  Download, Eye, Fingerprint, Gauge, KeyRound, Layers3, Loader2, LockKeyhole,
  Monitor, Network, Radar, Search, Shield, ShieldAlert, Sparkles, Target, User,
  Users, Zap,
} from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { entitiesApi, findingsApi } from '@/lib/api'
import { cn, fmtDate, fmtNumber, safeDateMs, timeAgo } from '@/lib/utils'
import { downloadTextFile } from '@/lib/clientDownload'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'
import type { Entity, EntityType, Finding } from '@/lib/types'

type SignalFilter = 'all' | 'tier0' | 'crown' | 'admin' | 'disabled' | 'stale'
type SortMode = 'risk' | 'type' | 'name' | 'recent'

const TYPE_ICONS: Partial<Record<EntityType, ElementType>> = {
  USER: User,
  GROUP: Users,
  COMPUTER: Monitor,
  DOMAIN: Network,
  FOREST: Network,
  OU: Layers3,
  GPO: Shield,
  SERVICE_ACCOUNT: KeyRound,
  GMSA: LockKeyhole,
  DMSA: LockKeyhole,
  DC: ShieldAlert,
  CA: Diamond,
  CERT_TEMPLATE: Fingerprint,
  TRUST: Network,
  SITE: Radar,
  UNKNOWN: Boxes,
}

const TYPE_FILTERS: { label: string; value: EntityType | 'all' }[] = [
  { label: 'All', value: 'all' },
  { label: 'Users', value: 'USER' },
  { label: 'Groups', value: 'GROUP' },
  { label: 'Computers', value: 'COMPUTER' },
  { label: 'Service', value: 'SERVICE_ACCOUNT' },
  { label: 'DCs', value: 'DC' },
  { label: 'PKI', value: 'CA' },
]

const SIGNALS: { label: string; value: SignalFilter; icon: ElementType }[] = [
  { label: 'All Signals', value: 'all', icon: Radar },
  { label: 'Tier-0', value: 'tier0', icon: Target },
  { label: 'Crown', value: 'crown', icon: Crown },
  { label: 'AdminCount', value: 'admin', icon: ShieldAlert },
  { label: 'Disabled', value: 'disabled', icon: Eye },
  { label: 'Stale 90d', value: 'stale', icon: Gauge },
]

const SORTS: { label: string; value: SortMode }[] = [
  { label: 'Risk Rank', value: 'risk' },
  { label: 'Type', value: 'type' },
  { label: 'Name', value: 'name' },
  { label: 'Recent', value: 'recent' },
]

const ENTITY_COLORS: Partial<Record<EntityType, string>> = {
  USER: '#b9a7ff',
  GROUP: '#8ea4ff',
  COMPUTER: '#86a6bd',
  DOMAIN: '#d9b36f',
  FOREST: '#b7c6a3',
  OU: '#9aa3b2',
  GPO: '#a8c66c',
  SERVICE_ACCOUNT: '#c4a0e8',
  GMSA: '#a5b4fc',
  DMSA: '#a5b4fc',
  DC: '#e1a1a6',
  CA: '#d7a1c4',
  CERT_TEMPLATE: '#d6b783',
  TRUST: '#a7b7d8',
  SITE: '#9fb3ad',
  UNKNOWN: '#8f96a3',
}

function typeColor(type: EntityType) {
  return ENTITY_COLORS[type] ?? '#8f96a3'
}

function labelFor(entity: Entity) {
  return entity.display_name || entity.sam_account_name || entity.dns_hostname || 'Unnamed entity'
}

function isStale(date?: string) {
  if (!date) return false
  return Date.now() - new Date(date.endsWith('Z') ? date : `${date}Z`).getTime() > 90 * 24 * 60 * 60 * 1000
}

function riskRank(entity: Entity) {
  let score = 0
  if (entity.tier === 0) score += 45
  if (entity.tier === 1) score += 18
  if (entity.is_crown_jewel) score += 34
  if (entity.is_admin_count) score += 26
  if (entity.is_sensitive) score += 16
  if (entity.is_protected_user) score += 10
  if (!entity.is_enabled) score += 7
  if (isStale(entity.last_logon) || isStale(entity.password_last_set)) score += 9
  if (['DC', 'DOMAIN', 'CA', 'CERT_TEMPLATE'].includes(entity.entity_type)) score += 18
  return Math.min(100, score)
}

function riskTone(score: number) {
  if (score >= 80) return 'border-rose-300/30 bg-rose-950/35 text-rose-100'
  if (score >= 55) return 'border-amber-300/25 bg-amber-950/25 text-amber-100'
  if (score >= 30) return 'border-indigo-300/20 bg-indigo-950/25 text-indigo-100'
  return 'border-white/10 bg-black text-zinc-300'
}

function pct(part = 0, total = 0) {
  if (!total) return 0
  return Math.round((part / total) * 100)
}

function MiniMetric({ label, value, detail, icon: Icon, tone = 'text-indigo-200' }: {
  label: string
  value: string | number
  detail: string
  icon: ElementType
  tone?: string
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.42, ease: [0.23, 1, 0.32, 1] }}
      className="min-h-[132px] rounded-2xl border border-white/10 bg-black p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
    >
      <div className="flex items-center justify-between">
        <div className="text-[11px] uppercase tracking-[0.24em] text-zinc-500">{label}</div>
        <Icon className={cn('h-4 w-4', tone)} />
      </div>
      <div className="mt-4 text-3xl font-semibold text-white">{value}</div>
      <div className="mt-2 text-sm text-zinc-400">{detail}</div>
    </motion.div>
  )
}

function TypeConstellation({ types, active, onPick }: {
  types: [string, number][]
  active: EntityType | 'all'
  onPick: (type: EntityType | 'all') => void
}) {
  const max = Math.max(...types.map(([, count]) => count), 1)
  return (
    <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
      {types.map(([type, count]) => {
        const color = typeColor(type as EntityType)
        return (
          <button
            key={type}
            onClick={() => onPick(type as EntityType)}
            className={cn(
              'group rounded-2xl border p-4 text-left transition hover:-translate-y-0.5',
              active === type ? 'border-indigo-300/35 bg-indigo-400/10' : 'border-white/10 bg-black hover:bg-white/[0.06]'
            )}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase tracking-[0.22em] text-zinc-500">{type.replaceAll('_', ' ')}</span>
              <span className="font-mono text-sm text-white">{fmtNumber(count)}</span>
            </div>
            <div className="mt-4 h-2 overflow-hidden rounded-full bg-black">
              <div className="h-full rounded-full transition-all" style={{ width: `${Math.max(8, (count / max) * 100)}%`, backgroundColor: color }} />
            </div>
          </button>
        )
      })}
    </div>
  )
}

function EntityCard({ entity, selected, onSelect }: { entity: Entity; selected: boolean; onSelect: () => void }) {
  const Icon = TYPE_ICONS[entity.entity_type] ?? Boxes
  const color = typeColor(entity.entity_type)
  const rank = riskRank(entity)
  return (
    <motion.button
      layout
      onClick={onSelect}
      className={cn(
        'w-full rounded-2xl border p-4 text-left transition hover:-translate-y-0.5',
        selected ? 'border-indigo-300/40 bg-indigo-400/10 shadow-[0_0_32px_rgba(129,140,248,0.10)]' : 'border-white/10 bg-black hover:bg-white/[0.06]'
      )}
    >
      <div className="flex items-start gap-4">
        <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-white/10" style={{ backgroundColor: `${color}1f` }}>
          <Icon className="h-5 w-5" style={{ color }} />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-base font-semibold text-white">{labelFor(entity)}</span>
            <span className={cn('rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider', riskTone(rank))}>{rank} risk</span>
            {entity.tier === 0 && <span className="rounded-full border border-rose-300/20 bg-rose-950/35 px-2.5 py-1 text-[10px] font-semibold text-rose-100">Tier-0</span>}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs text-zinc-500">
            <span>{entity.entity_type.replaceAll('_', ' ')}</span>
            {entity.sam_account_name && <span>{entity.sam_account_name}</span>}
            <span>{entity.domain ?? 'unknown domain'}</span>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {entity.is_crown_jewel && <Flag icon={Crown} label="Crown" tone="text-amber-100 bg-amber-950/25 border-amber-300/20" />}
            {entity.is_admin_count && <Flag icon={ShieldAlert} label="AdminCount" tone="text-stone-100 bg-stone-800/35 border-stone-300/15" />}
            {entity.is_sensitive && <Flag icon={Zap} label="Sensitive" tone="text-indigo-100 bg-indigo-950/30 border-indigo-300/20" />}
            {!entity.is_enabled && <Flag icon={Eye} label="Disabled" tone="text-zinc-200 bg-black border-white/10" />}
            {(isStale(entity.last_logon) || isStale(entity.password_last_set)) && <Flag icon={Gauge} label="Stale" tone="text-slate-100 bg-slate-700/25 border-slate-300/15" />}
          </div>
        </div>
      </div>
    </motion.button>
  )
}

function Flag({ icon: Icon, label, tone }: { icon: ElementType; label: string; tone: string }) {
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px]', tone)}>
      <Icon className="h-3 w-3" />
      {label}
    </span>
  )
}

function Dossier({ entity, findings }: { entity?: Entity; findings: Finding[] }) {
  if (!entity) {
    return (
      <div className="rounded-3xl border border-white/10 bg-black p-8 text-center text-sm text-zinc-400">
        <Boxes className="mx-auto h-10 w-10 text-zinc-600" />
        <div className="mt-3">Select an identity to open its dossier.</div>
      </div>
    )
  }
  const rank = riskRank(entity)
  const Icon = TYPE_ICONS[entity.entity_type] ?? Boxes
  const color = typeColor(entity.entity_type)
  const relevantFindings = findings.filter((finding) =>
    JSON.stringify(finding.affected_objects ?? []).toLowerCase().includes(labelFor(entity).toLowerCase()) ||
    (entity.sam_account_name ? JSON.stringify(finding.affected_objects ?? []).toLowerCase().includes(entity.sam_account_name.toLowerCase()) : false)
  ).slice(0, 3)

  return (
    <div className="sticky top-6 space-y-4">
      <div className="overflow-hidden rounded-3xl border border-white/10 bg-black">
        <div className="border-b border-white/10 bg-black p-5">
          <div className="flex items-start gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white/10" style={{ backgroundColor: `${color}22` }}>
              <Icon className="h-6 w-6" style={{ color }} />
            </div>
            <div className="min-w-0">
              <div className="truncate text-lg font-semibold text-white">{labelFor(entity)}</div>
              <div className="mt-1 font-mono text-xs uppercase tracking-[0.18em] text-zinc-500">{entity.entity_type.replaceAll('_', ' ')}</div>
            </div>
          </div>
        </div>
        <div className="p-5">
          <div className="grid grid-cols-3 gap-3">
            <DossierMetric label="Rank" value={rank} />
            <DossierMetric label="Tier" value={entity.tier ?? '-'} />
            <DossierMetric label="Domain" value={entity.domain ?? '-'} small />
          </div>
          <div className="mt-5 space-y-3">
            <Fact label="SAM" value={entity.sam_account_name ?? '-'} />
            <Fact label="SID" value={entity.object_sid ?? '-'} />
            <Fact label="Last logon" value={entity.last_logon ? timeAgo(entity.last_logon) : 'unknown'} />
            <Fact label="Password set" value={entity.password_last_set ? fmtDate(entity.password_last_set) : 'unknown'} />
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            {entity.is_crown_jewel && <Flag icon={Crown} label="Crown Jewel" tone="text-amber-100 bg-amber-950/25 border-amber-300/20" />}
            {entity.is_admin_count && <Flag icon={ShieldAlert} label="AdminCount" tone="text-stone-100 bg-stone-800/35 border-stone-300/15" />}
            {entity.is_protected_user && <Flag icon={CheckCircle2} label="Protected" tone="text-emerald-100 bg-emerald-950/25 border-emerald-300/15" />}
            {entity.is_sensitive && <Flag icon={Zap} label="Sensitive" tone="text-indigo-100 bg-indigo-950/30 border-indigo-300/20" />}
          </div>
        </div>
      </div>

      <div className="rounded-3xl border border-white/10 bg-black p-5">
        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-zinc-500">
          <BrainCircuit className="h-4 w-4 text-indigo-200" />
          Operator Read
        </div>
        <div className="mt-4 space-y-3 text-sm text-zinc-300">
          <p>{rank >= 70 ? 'High leverage identity. Validate ownership, group paths, and ticket exposure before broad remediation.' : 'Inventory signal is stable. Keep it in review if it touches privileged paths or high-value systems.'}</p>
          <p>{!entity.is_enabled ? 'Disabled but still valuable. Confirm it cannot remain in ACLs, delegation paths, or privileged groups.' : 'Enabled object. Prioritize authentication hygiene and blast-radius review.'}</p>
        </div>
      </div>

      <div className="rounded-3xl border border-white/10 bg-black p-5">
        <div className="text-xs uppercase tracking-[0.24em] text-zinc-500">Finding Correlation</div>
        <div className="mt-4 space-y-3">
          {relevantFindings.length ? relevantFindings.map((finding) => (
            <div key={finding.id} className="rounded-2xl border border-white/10 bg-black p-3">
              <div className="text-xs font-semibold text-rose-100">{finding.severity}</div>
              <div className="mt-1 line-clamp-2 text-sm text-white">{finding.title}</div>
            </div>
          )) : (
            <div className="rounded-2xl border border-white/10 bg-black p-4 text-sm text-zinc-400">
              No direct finding text match in the loaded top findings.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function DossierMetric({ label, value, small }: { label: string; value: string | number; small?: boolean }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black p-3">
      <div className="text-[10px] uppercase tracking-[0.18em] text-zinc-500">{label}</div>
      <div className={cn('mt-2 truncate font-semibold text-white', small ? 'text-xs' : 'text-xl')}>{value}</div>
    </div>
  )
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-white/10 pb-2 last:border-b-0">
      <span className="text-xs uppercase tracking-[0.18em] text-zinc-500">{label}</span>
      <span className="truncate text-right font-mono text-xs text-zinc-300">{value}</span>
    </div>
  )
}

export default function AssetsPage() {
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<EntityType | 'all'>('all')
  const [signalFilter, setSignalFilter] = useState<SignalFilter>('all')
  const [sortMode, setSortMode] = useState<SortMode>('risk')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  useEffect(() => {
    if (typeof window === 'undefined') return
    const query = new URLSearchParams(window.location.search).get('q')?.trim() ?? ''
    if (query) setSearch(query)
  }, [])

  const { assessment, assessmentId } = useRouteAssessmentScope()

  const listParams = useMemo(() => ({
    assessment_id: assessmentId!,
    entity_type: typeFilter !== 'all' ? typeFilter : undefined,
    is_crown_jewel: signalFilter === 'crown' ? true : undefined,
    is_admin_count: signalFilter === 'admin' ? true : undefined,
    is_enabled: signalFilter === 'disabled' ? false : undefined,
    tier: signalFilter === 'tier0' ? 0 : undefined,
    search: search || undefined,
    limit: 500,
  }), [assessmentId, search, signalFilter, typeFilter])

  const { data: entities, isLoading, isError } = useQuery({
    queryKey: ['entities', listParams],
    queryFn: () => entitiesApi.list(listParams),
    enabled: !!assessmentId,
    staleTime: 60_000,
    placeholderData: [],
  })

  const { data: summary } = useQuery({
    queryKey: ['entities-summary', assessmentId],
    queryFn: () => entitiesApi.summary(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: intel } = useQuery({
    queryKey: ['entities-intelligence', assessmentId],
    queryFn: () => entitiesApi.intelligence(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: findingsPage } = useQuery({
    queryKey: ['assets-correlated-findings', assessmentId],
    queryFn: () => findingsApi.list({ assessment_id: assessmentId!, page_size: 100, sort_by: 'composite_score', sort_desc: true }),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const displayEntities = useMemo(() => {
    const base = (entities ?? []).filter((entity) => signalFilter !== 'stale' || isStale(entity.last_logon) || isStale(entity.password_last_set))
    return [...base].sort((a, b) => {
      if (sortMode === 'risk') return riskRank(b) - riskRank(a) || labelFor(a).localeCompare(labelFor(b))
      if (sortMode === 'type') return a.entity_type.localeCompare(b.entity_type) || labelFor(a).localeCompare(labelFor(b))
      if (sortMode === 'recent') return (safeDateMs(b.object_modified ?? b.last_logon) ?? 0) - (safeDateMs(a.object_modified ?? a.last_logon) ?? 0)
      return labelFor(a).localeCompare(labelFor(b))
    })
  }, [entities, signalFilter, sortMode])

  useEffect(() => {
    if (!displayEntities.length) {
      setSelectedId(null)
      return
    }
    if (!selectedId || !displayEntities.some((entity) => entity.id === selectedId)) {
      setSelectedId(displayEntities[0].id)
    }
  }, [displayEntities, selectedId])

  const selectedEntity = displayEntities.find((entity) => entity.id === selectedId)
  const topTypes = useMemo(
    () => Object.entries((summary?.by_type as Record<string, number>) ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8),
    [summary]
  )

  const flags = intel?.by_flags ?? {}
  const total = summary?.total ?? intel?.total ?? displayEntities.length
  const highSignalCount = (flags.tier0 ?? 0) + (flags.crown_jewel ?? 0) + (flags.admin_count ?? 0)
  const criticalFindings = findingsPage?.items.filter((finding) => finding.severity === 'CRITICAL').length ?? 0

  const exportCsv = () => {
    if (!displayEntities.length) return
    const headers = ['Name', 'SAM Account', 'Type', 'Domain', 'Tier', 'Risk Rank', 'Crown Jewel', 'Admin Count', 'Enabled', 'Sensitive', 'Last Logon', 'Password Last Set']
    const rows = displayEntities.map((entity) => [
      labelFor(entity),
      entity.sam_account_name ?? '',
      entity.entity_type,
      entity.domain ?? '',
      entity.tier ?? '',
      riskRank(entity),
      entity.is_crown_jewel ? 'Yes' : 'No',
      entity.is_admin_count ? 'Yes' : 'No',
      entity.is_enabled ? 'Yes' : 'No',
      entity.is_sensitive ? 'Yes' : 'No',
      entity.last_logon ?? '',
      entity.password_last_set ?? '',
    ])
    const csv = [headers, ...rows].map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(',')).join('\n')
    downloadTextFile(
      `assets-${assessment?.domain ?? 'export'}-${new Date().toISOString().slice(0, 10)}.csv`,
      csv,
      'text/csv;charset=utf-8;',
    )
  }

  return (
    <AppShell>
      <div className="min-h-full px-5 py-6 lg:px-8">
        <section className="relative overflow-hidden rounded-[30px] border border-white/10 bg-black p-6 lg:p-8">
          <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-indigo-300/35 to-transparent" />
          <div className="flex flex-col gap-8 xl:flex-row xl:items-end xl:justify-between">
            <div className="max-w-4xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-indigo-300/20 bg-indigo-400/10 px-3 py-1.5 text-xs font-semibold text-indigo-100">
                <Radar className="h-3.5 w-3.5" />
                Live Identity Exposure Deck
              </div>
              <h1 className="mt-5 text-4xl font-semibold tracking-normal text-white lg:text-5xl">Assets & Identities</h1>
              <p className="mt-3 max-w-3xl text-sm leading-6 text-zinc-300">
                Inventory, privilege signal, dormant risk, and finding correlation for the selected assessment. Built from backend entity intelligence and the current findings set.
              </p>
            </div>
            <div className="grid min-w-[280px] grid-cols-2 gap-3">
              <div className="rounded-2xl border border-white/10 bg-black p-4">
                <div className="text-[10px] uppercase tracking-[0.24em] text-zinc-500">Domain</div>
                <div className="mt-2 truncate font-mono text-sm text-white">{assessment?.domain ?? 'No assessment'}</div>
              </div>
              <button
                className="rounded-2xl border border-indigo-300/20 bg-indigo-400/10 p-4 text-left transition hover:bg-indigo-400/15 disabled:opacity-40"
                disabled={!displayEntities.length}
                onClick={exportCsv}
              >
                <Download className="h-4 w-4 text-indigo-100" />
                <div className="mt-2 text-sm font-semibold text-indigo-50">Export CSV</div>
              </button>
            </div>
          </div>
        </section>

        <section className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          <MiniMetric label="Indexed" value={fmtNumber(total)} detail={`${fmtNumber(displayEntities.length)} loaded in view`} icon={Boxes} />
          <MiniMetric label="Exposure Pressure" value={`${intel?.exposure_pressure ?? 0}%`} detail={`${fmtNumber(highSignalCount)} high-signal flags`} icon={Gauge} tone="text-rose-100" />
          <MiniMetric label="Tier-0" value={fmtNumber(summary?.tier0_count ?? flags.tier0 ?? 0)} detail="Direct privileged surface" icon={Target} tone="text-amber-100" />
          <MiniMetric label="Crown Jewels" value={fmtNumber(summary?.crown_jewel_count ?? flags.crown_jewel ?? 0)} detail="Business critical identities" icon={Crown} tone="text-amber-100" />
          <MiniMetric label="Critical Findings" value={criticalFindings} detail={`${fmtNumber(findingsPage?.total ?? 0)} total findings`} icon={ShieldAlert} tone="text-rose-100" />
        </section>

        <section className="mt-5 grid gap-5 xl:grid-cols-[1fr_360px]">
          <div className="space-y-5">
            {topTypes.length > 0 && (
              <TypeConstellation types={topTypes} active={typeFilter} onPick={setTypeFilter} />
            )}

            <div className="rounded-[28px] border border-white/10 bg-black p-4">
              <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                <div className="relative w-full xl:max-w-lg">
                  <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search name, SAM account, hostname"
                    className="w-full rounded-2xl border border-white/10 bg-black py-3 pl-11 pr-4 text-sm text-white outline-none placeholder:text-zinc-500 focus:border-indigo-300/40 focus:bg-white/[0.06]"
                  />
                </div>
                <div className="flex flex-wrap gap-2">
                  {TYPE_FILTERS.map((filter) => (
                    <button
                      key={filter.value}
                      onClick={() => setTypeFilter(filter.value)}
                      className={cn(
                        'rounded-full border px-3.5 py-2 text-sm transition',
                        typeFilter === filter.value ? 'border-indigo-300/35 bg-indigo-400/10 text-indigo-100' : 'border-white/10 bg-black text-zinc-400 hover:text-white'
                      )}
                    >
                      {filter.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-4 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
                <div className="flex flex-wrap gap-2">
                  {SIGNALS.map((signal) => {
                    const Icon = signal.icon
                    return (
                      <button
                        key={signal.value}
                        onClick={() => setSignalFilter(signal.value)}
                        className={cn(
                          'inline-flex items-center gap-2 rounded-full border px-3.5 py-2 text-xs font-medium transition',
                          signalFilter === signal.value ? 'border-indigo-300/30 bg-indigo-400/10 text-indigo-100' : 'border-white/10 bg-black text-zinc-400 hover:text-white'
                        )}
                      >
                        <Icon className="h-3.5 w-3.5" />
                        {signal.label}
                      </button>
                    )
                  })}
                </div>
                <div className="flex items-center gap-2 rounded-full border border-white/10 bg-black p-1">
                  <ArrowDownWideNarrow className="ml-2 h-4 w-4 text-zinc-500" />
                  {SORTS.map((sort) => (
                    <button
                      key={sort.value}
                      onClick={() => setSortMode(sort.value)}
                      className={cn('rounded-full px-3 py-1.5 text-xs transition', sortMode === sort.value ? 'bg-white/10 text-white' : 'text-zinc-500 hover:text-zinc-200')}
                    >
                      {sort.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {isLoading && (
              <div className="flex min-h-[360px] items-center justify-center rounded-[28px] border border-white/10 text-zinc-400">
                <div className="flex items-center gap-3 text-sm"><Loader2 className="h-5 w-5 animate-spin" /> Loading live entity intelligence...</div>
              </div>
            )}

            {isError && (
              <div className="rounded-[28px] border border-rose-300/20 bg-rose-950/30 px-5 py-4 text-sm text-rose-100">
                <div className="flex items-start gap-3"><AlertCircle className="mt-0.5 h-5 w-5 shrink-0" /> Failed to load entities. API connectivity or auth needs review.</div>
              </div>
            )}

            {!isLoading && !assessmentId && (
              <div className="rounded-[28px] border border-white/10 bg-black p-10 text-center">
                <Boxes className="mx-auto h-12 w-12 text-zinc-500" />
                <h2 className="mt-4 text-xl font-semibold text-white">No assessment data yet</h2>
                <p className="mt-2 text-sm text-zinc-400">Run an assessment to populate the asset intelligence deck.</p>
              </div>
            )}

            {!isLoading && assessmentId && displayEntities.length > 0 && (
              <div className="grid gap-3">
                {displayEntities.map((entity) => (
                  <EntityCard key={entity.id} entity={entity} selected={selectedId === entity.id} onSelect={() => setSelectedId(entity.id)} />
                ))}
              </div>
            )}

            {!isLoading && assessmentId && displayEntities.length === 0 && (
              <div className="rounded-[28px] border border-white/10 bg-black p-10 text-center">
                <Sparkles className="mx-auto h-12 w-12 text-zinc-500" />
                <h2 className="mt-4 text-xl font-semibold text-white">No entities match this lens</h2>
                <p className="mt-2 text-sm text-zinc-400">Clear a signal, switch type, or broaden the search.</p>
              </div>
            )}
          </div>

          <aside className="space-y-5">
            <div className="rounded-3xl border border-white/10 bg-black p-5">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-zinc-500">
                <ShieldAlert className="h-4 w-4 text-rose-100" />
                Privilege Signals
              </div>
              <div className="mt-5 space-y-4">
                <Pressure label="Tier-0" value={flags.tier0 ?? summary?.tier0_count ?? 0} total={total} />
                <Pressure label="AdminCount" value={flags.admin_count ?? summary?.admin_count ?? 0} total={total} />
                <Pressure label="Sensitive" value={flags.sensitive ?? 0} total={total} />
                <Pressure label="Stale logon" value={flags.stale_logon ?? 0} total={total} />
              </div>
            </div>

            {intel?.dormant_privileged?.length ? (
              <div className="rounded-3xl border border-amber-300/15 bg-amber-950/[0.10] p-5">
                <div className="text-xs uppercase tracking-[0.24em] text-amber-100">Dormant Privileged</div>
                <div className="mt-4 space-y-2">
                  {intel.dormant_privileged.slice(0, 5).map((item) => (
                    <button
                      key={item.id}
                      onClick={() => setSearch(item.sam_account_name ?? item.label)}
                      className="w-full rounded-2xl border border-white/10 bg-black p-3 text-left transition hover:bg-white/[0.05]"
                    >
                      <div className="truncate text-sm font-semibold text-white">{item.label}</div>
                      <div className="mt-1 font-mono text-xs text-zinc-500">{item.entity_type} · {item.last_logon ? timeAgo(item.last_logon) : 'no logon'}</div>
                    </button>
                  ))}
                </div>
              </div>
            ) : null}

            <Dossier entity={selectedEntity} findings={findingsPage?.items ?? []} />
          </aside>
        </section>

        <p className="mt-5 text-center text-xs text-zinc-500">
          Showing {fmtNumber(displayEntities.length)} of {fmtNumber(total)} indexed entities · high-signal density {pct(highSignalCount, total)}%
        </p>
      </div>
    </AppShell>
  )
}

function Pressure({ label, value, total }: { label: string; value: number; total: number }) {
  const width = pct(value, total)
  return (
    <div>
      <div className="flex items-center justify-between text-sm">
        <span className="text-zinc-300">{label}</span>
        <span className="font-mono text-indigo-100">{fmtNumber(value)}</span>
      </div>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-black">
        <div className="h-full rounded-full bg-gradient-to-r from-indigo-300 via-slate-300 to-rose-300" style={{ width: `${Math.max(width, value ? 4 : 0)}%` }} />
      </div>
    </div>
  )
}
