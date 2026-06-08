'use client'

import { useEffect, useMemo, useRef, useState, type MouseEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Plus, Activity, XCircle, Clock, Play,
  Database, Wifi, Shield, FileText, Loader2, AlertCircle,
  Search, Radar, Target, Filter, FolderOpen,
  Terminal, Trash2, X, Upload, Zap, Pencil, AlertTriangle, Code2, Skull,
  Copy, Users, Server, Award, BarChart2, ArrowUpDown,
} from 'lucide-react'
import { ADCommandsPanel, type TargetConfig as CommandTargetConfig } from './ADCommandsPanel'
import { generateCollectorScript, CollectorScriptResult } from '@/lib/powershellCollectorGenerator'
import { OBFUSCATION_TECHNIQUES, LEVEL_COLORS, TechniqueId } from '@/lib/powershellObfuscator'
import { PSScriptModal } from './PSScriptModal'

import { assessmentApi, collectionApi, collectionModulesApi, importApi } from '@/lib/api'
import { connectivityApi } from '@/lib/connectivityApi'
import { useImportStore } from '@/lib/importStore'
import { assessmentKeys, collectionModuleKeys } from '@/lib/queryKeys'
import { Assessment, CollectionModule } from '@/lib/types'
import { safeDateMs } from '@/lib/utils'
import { defaultCollectionModuleIds, fallbackCollectionModules, collectionModuleMeta } from '@/lib/moduleCatalog'
import { ScoreGauge } from '@/components/ui/ScoreGauge'
import { timeAgo, cn, fmtNumber } from '@/lib/utils'

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e',
}
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

const MODULE_META: Record<string, { label: string; accent: string }> = collectionModuleMeta

const STATUS_CONFIG: Record<string, { label: string; color: string; glow: string; dot: string }> = {
  COMPLETED: { label: 'COMPLETED', color: '#4ade80', glow: 'rgba(74,222,128,0.35)', dot: '#22c55e' },
  RUNNING:   { label: 'RUNNING',   color: '#67e8f9', glow: 'rgba(103,232,249,0.35)', dot: '#06b6d4' },
  PENDING:   { label: 'PENDING',   color: '#a1a1aa', glow: 'rgba(161,161,170,0.2)',  dot: '#71717a' },
  FAILED:    { label: 'FAILED',    color: '#f87171', glow: 'rgba(248,113,113,0.35)', dot: '#ef4444' },
  PAUSED:    { label: 'PAUSED',    color: '#fbbf24', glow: 'rgba(251,191,36,0.3)',   dot: '#f59e0b' },
  CANCELLED: { label: 'CANCELLED', color: '#a1a1aa', glow: 'rgba(161,161,170,0.2)', dot: '#71717a' },
}

const MODE_OPTIONS = [
  { id: 'LINUX_REMOTE',   label: 'Remote LDAP Collection', shortLabel: 'Run ldap3 collection from this Linux host', icon: Wifi,   accent: '#06b6d4' },
  { id: 'COMMAND_PLAN',   label: 'Windows Local', shortLabel: 'PowerShell collector zip for import', icon: Terminal, accent: '#facc15' },
  { id: 'IMPORT',         label: 'Import',        shortLabel: 'Upload existing .zip or .json output', icon: Upload, accent: '#fb923c' },
] as const

const STATUS_FILTERS = ['ALL', 'RUNNING', 'PENDING', 'COMPLETED', 'FAILED'] as const

const SORT_OPTIONS = [
  { id: 'newest',   label: 'Newest first' },
  { id: 'oldest',   label: 'Oldest first' },
  { id: 'score',    label: 'Exposure score' },
  { id: 'findings', label: 'Most findings' },
] as const
type SortKey = (typeof SORT_OPTIONS)[number]['id']

const CATEGORY_LABELS: Record<string, string> = {
  directory: 'Directory', topology: 'Topology', identity: 'Kerberos & Identity',
  authorization: 'Privilege Paths', policy: 'Group Policy', 'certificate-services': 'Certificate Services',
  'host-access': 'Shares & Host Access', 'identity-hygiene': 'Password Hygiene',
  infrastructure: 'Infrastructure', 'host-activity': 'Session Context',
  'host-persistence': 'Persistence Indicators', hybrid: 'Hybrid Import',
}

const ALL_MODULES = defaultCollectionModuleIds

const statNumber = (v: unknown) => typeof v === 'number' && isFinite(v) ? v : 0

function getSeverityCounts(a: Assessment) {
  const s = (a.stats ?? {}) as Record<string, unknown>
  const counts = {
    CRITICAL: statNumber(s.CRITICAL ?? s.critical),
    HIGH:     statNumber(s.HIGH     ?? s.high),
    MEDIUM:   statNumber(s.MEDIUM   ?? s.medium),
    LOW:      statNumber(s.LOW      ?? s.low),
  }
  const total = statNumber(s.total_findings) || Object.values(counts).reduce((a, b) => a + b, 0)
  return { counts, total }
}

const moduleSupportsMode = (m: CollectionModule, mode: string) =>
  mode === 'COMMAND_PLAN'
    ? m.supported_modes.includes('WINDOWS_LOCAL') || m.supported_modes.includes('WINDOWS_REMOTE')
    : m.supported_modes.includes(mode)

function mergeCollectionModuleCatalogs(apiModules: CollectionModule[] | undefined, localModules: CollectionModule[]) {
  const merged = new Map<string, CollectionModule>()

  const mergeOne = (incoming: CollectionModule) => {
    const existing = merged.get(incoming.id)
    if (!existing) {
      merged.set(incoming.id, {
        ...incoming,
        supported_modes: [...incoming.supported_modes],
        command_groups: incoming.command_groups.map(group => ({
          ...group,
          commands: [...group.commands],
        })),
        excluded_capabilities: incoming.excluded_capabilities ? [...incoming.excluded_capabilities] : undefined,
      })
      return
    }

    const commandGroups = new Map(existing.command_groups.map(group => [group.id, { ...group, commands: [...group.commands] }]))
    for (const group of incoming.command_groups) {
      const existingGroup = commandGroups.get(group.id)
      if (!existingGroup) {
        commandGroups.set(group.id, { ...group, commands: [...group.commands] })
        continue
      }

      const commands = new Map(existingGroup.commands.map(command => [command.id, command]))
      for (const command of group.commands) commands.set(command.id, command)
      commandGroups.set(group.id, { ...existingGroup, ...group, commands: [...commands.values()] })
    }

    merged.set(incoming.id, {
      ...existing,
      ...incoming,
      supported_modes: Array.from(new Set([...existing.supported_modes, ...incoming.supported_modes])),
      command_groups: [...commandGroups.values()],
      excluded_capabilities: Array.from(new Set([
        ...(existing.excluded_capabilities ?? []),
        ...(incoming.excluded_capabilities ?? []),
      ])),
    })
  }

  for (const collectionModule of apiModules ?? []) mergeOne(collectionModule)
  for (const collectionModule of localModules) mergeOne(collectionModule)
  return [...merged.values()]
}

function StatusPill({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.PENDING
  return (
    <span
      className="inline-flex items-center gap-1.5 border px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.16em]"
      style={{ color: cfg.color, borderColor: `${cfg.color}25`, background: `${cfg.color}08` }}
    >
      <span
        className={cn('h-1.5 w-1.5', status === 'RUNNING' && 'animate-pulse')}
        style={{ background: cfg.dot }}
      />
      {cfg.label}
    </span>
  )
}

function SeverityBar({ counts, total }: { counts: Record<string, number>; total: number }) {
  if (!total) return null
  return (
    <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-white/5">
      {SEV_ORDER.map(s => {
        const pct = (counts[s] / total) * 100
        return pct > 0 ? (
          <div key={s} style={{ width: `${pct}%`, background: SEV_COLORS[s] }} title={`${counts[s]} ${s}`} />
        ) : null
      })}
    </div>
  )
}

function AssessmentCard({ assessment, onSelect }: { assessment: Assessment; rank?: number; onSelect: () => void }) {
  const qc = useQueryClient()
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [showEdit, setShowEdit] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const { counts, total } = getSeverityCounts(assessment)
  const completed = assessment.status === 'COMPLETED'
  const running = assessment.status === 'RUNNING'
  const failed = assessment.status === 'FAILED'
  const cfg = STATUS_CONFIG[assessment.status] ?? STATUS_CONFIG.PENDING
  const moduleCount = (assessment.modules_run ?? []).length
  const dominantSev = SEV_ORDER.find(s => counts[s] > 0)

  const deleteMutation = useMutation({
    mutationFn: () => assessmentApi.delete(assessment.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assessments'] }),
    onError: (error: unknown) => setDeleteError(getApiErrorMessage(error, 'Unable to delete assessment')),
  })

  const { data: workspaces } = useQuery({
    queryKey: assessmentKeys.workspaces(),
    queryFn: () => assessmentApi.workspaces(),
    staleTime: 300_000,
  })
  const cloneMutation = useMutation({
    mutationFn: () => assessmentApi.create({
      name: `${assessment.name} (copy)`,
      domain: assessment.domain,
      dc_ip: assessment.dc_ip,
      collection_mode: assessment.collection_mode ?? 'LINUX_REMOTE',
      workspace_id: workspaces?.[0]?.id,
      collection_config: assessment.collection_config ? { modules: assessment.modules_run } : undefined,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assessments'] }),
  })

  const cardAccent = running ? cfg.color : completed && dominantSev ? SEV_COLORS[dominantSev] : failed ? '#f87171' : 'rgba(255,255,255,0.08)'
  const cardAccentFaint = running ? `${cfg.color}30` : completed && dominantSev ? `${SEV_COLORS[dominantSev]}28` : failed ? 'rgba(248,113,113,0.18)' : 'rgba(255,255,255,0.05)'

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.97 }}
      className="group rounded-2xl p-[1px]"
      style={{
        background: `linear-gradient(135deg, ${cardAccent} 0%, rgba(255,255,255,0.03) 30%, rgba(255,255,255,0.01) 100%)`,
        boxShadow: running ? `0 0 24px ${cfg.color}20` : completed && dominantSev ? `0 0 20px ${SEV_COLORS[dominantSev]}14` : 'none',
      }}
    >
    <div className="relative overflow-hidden rounded-[15px]"
      style={{ background: '#050505' }}>
      {/* Running scan line */}
      {running && (
        <div className="pointer-events-none absolute inset-x-0 top-0 h-[2px] animate-scan-y"
          style={{ background: `linear-gradient(90deg, transparent, ${cfg.color}cc, rgba(255,255,255,0.7), ${cfg.color}cc, transparent)`, boxShadow: `0 0 12px ${cfg.color}88` }} />
      )}

      {/* Top glow line for completed */}
      {!running && (
        <div className="pointer-events-none absolute inset-x-0 top-0 h-px"
          style={{ background: `linear-gradient(90deg, transparent, ${cardAccentFaint.replace('0.', '0.5').replace('28)', '70)')}, transparent)` }} />
      )}

      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 cursor-pointer" onClick={onSelect}>
            <StatusPill status={assessment.status} />
            <h3 className="mt-2.5 truncate text-base font-bold text-white hover:text-indigo-300 transition-colors">{assessment.name}</h3>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-zinc-500">
              <span className="flex items-center gap-1.5">
                <Shield className="h-3.5 w-3.5 text-zinc-600" />
                {assessment.domain}
              </span>
              {assessment.dc_ip && (
                <span className="rounded-md border border-white/8 bg-white/4 px-1.5 py-0.5 font-mono text-zinc-400">
                  {assessment.dc_ip}
                </span>
              )}
              <span className="text-zinc-600">·</span>
              <span style={{ color: 'rgba(255,255,255,0.3)' }}>
                {(assessment.collection_mode ?? 'UNKNOWN').replace('_', ' ')}
              </span>
            </div>
          </div>

          {/* Score / state */}
          <div className="shrink-0">
            {completed ? (
              <ScoreGauge score={assessment.exposure_score} size="sm" showLabel={false} />
            ) : running ? (
              <div className="grid h-12 w-12 place-items-center border"
                style={{ borderColor: `${cfg.color}30`, background: `${cfg.color}08` }}>
                <Radar className="h-5 w-5 animate-pulse" style={{ color: cfg.color }} />
              </div>
            ) : (
              <div className="grid h-12 w-12 place-items-center border border-white/[0.07]">
                <Clock className="h-5 w-5 text-zinc-700" />
              </div>
            )}
          </div>
        </div>

        {/* Stats row */}
        <div className="mt-4 grid grid-cols-3 divide-x divide-white/[0.06] overflow-hidden rounded-xl border border-white/[0.06]"
          style={{ background: 'rgba(255,255,255,0.02)' }}>
          {[
            { label: 'Findings', value: fmtNumber(total), accent: dominantSev ? SEV_COLORS[dominantSev] : '#818cf8' },
            { label: 'Modules',  value: moduleCount,      accent: '#22d3ee' },
            { label: 'Activity', value: timeAgo(assessment.completed_at ?? assessment.started_at ?? assessment.created_at), accent: '#a78bfa' },
          ].map(s => (
            <div key={s.label} className="px-3 py-2.5 text-center">
              <div className="text-base font-bold tabular-nums"
                style={{ color: s.accent, textShadow: `0 0 16px ${s.accent}66` }}>
                {s.value}
              </div>
              <div className="mt-0.5 text-[9px] uppercase tracking-[0.16em] text-zinc-600">{s.label}</div>
            </div>
          ))}
        </div>

        {/* Severity bar */}
        {completed && total > 0 && (
          <div className="mt-3">
            <SeverityBar counts={counts} total={total} />
            <div className="mt-1.5 flex flex-wrap gap-2">
              {SEV_ORDER.map(s => counts[s] > 0 ? (
                <span key={s} className="flex items-center gap-1 text-[10px]" style={{ color: SEV_COLORS[s] }}>
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLORS[s] }} />
                  {counts[s]} {s}
                </span>
              ) : null)}
            </div>
          </div>
        )}

        {/* Empty warning */}
        {completed && total === 0 && (
          <div className="mt-3 flex items-start gap-2.5 rounded-xl border border-amber-500/20 bg-amber-500/5 px-3 py-2.5">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-500" />
            <div className="min-w-0">
              <div className="text-[11px] font-bold text-amber-500/90 leading-none">0 Findings Detected</div>
              <p className="mt-1 text-[10px] text-zinc-500 leading-relaxed">
                Collection finished but returned no data. Check target connectivity and credentials.
              </p>
            </div>
          </div>
        )}

        {/* Running bar */}
        {running && (
          <div className="mt-4">
            <div className="flex items-center justify-between gap-4 mb-1.5 text-[10px] font-bold uppercase tracking-wider text-zinc-500">
              <span className="truncate">{assessment.last_message || 'Awaiting pipeline…'}</span>
              <span>{assessment.progress_pct ?? 0}%</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/5">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${assessment.progress_pct ?? 2}%` }}
                className="h-full rounded-full"
                style={{ background: `linear-gradient(90deg, ${cfg.color}80, ${cfg.color})`, boxShadow: `0 0 12px ${cfg.glow}` }}
              />
            </div>
          </div>
        )}

        {/* Module tags (compact) */}
        {moduleCount > 0 && (
          <div className="mt-3 flex flex-wrap gap-1">
            {(assessment.modules_run ?? []).slice(0, 4).map(mod => {
              const meta = MODULE_META[mod] ?? { accent: '#3f3f46' }
              return (
                <span key={mod} className="border px-1.5 py-0.5 text-[9px]"
                  style={{ borderColor: `${meta.accent}25`, color: `${meta.accent}99` }}>
                  {mod.split('.').pop()?.replace(/-/g, ' ')}
                </span>
              )
            })}
            {moduleCount > 4 && (
              <span className="border border-white/[0.07] px-1.5 py-0.5 text-[9px] text-zinc-600">
                +{moduleCount - 4}
              </span>
            )}
          </div>
        )}

        {/* Actions */}
        {deleteError && (
          <div className="mt-3 flex items-start gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
            <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span className="min-w-0">{deleteError}</span>
          </div>
        )}
        <div className="mt-4 flex items-center gap-1.5">
          {completed ? (
            <>
              <Link href={`/findings?assessment_id=${assessment.id}`}
                className="flex flex-1 items-center justify-center gap-1.5 border border-indigo-500/25 bg-indigo-500/8 py-2 text-xs font-semibold text-indigo-300 transition hover:border-indigo-500/45">
                <Shield className="h-3.5 w-3.5" /> Findings
              </Link>
              <Link href={`/graph?assessment_id=${assessment.id}`}
                className="flex flex-1 items-center justify-center gap-1.5 border border-pink-500/20 bg-pink-500/6 py-2 text-xs font-semibold text-pink-300 transition hover:border-pink-500/40">
                <Target className="h-3.5 w-3.5" /> Graph
              </Link>
              <Link href={`/reports?assessment_id=${assessment.id}`}
                className="flex items-center justify-center border border-white/[0.07] px-3 py-2 text-zinc-600 transition hover:text-zinc-300">
                <FileText className="h-3.5 w-3.5" />
              </Link>
            </>
          ) : failed ? (
            <div className="flex flex-1 items-center gap-1.5">
              <span className="flex flex-1 items-center gap-1.5 border border-red-500/18 bg-red-500/6 px-3 py-2 text-xs text-red-400">
                <XCircle className="h-3.5 w-3.5" /> Failed
              </span>
              <button onClick={() => setShowEdit(true)}
                className="flex items-center gap-1.5 border border-indigo-500/25 bg-indigo-500/8 px-3 py-2 text-xs font-semibold text-indigo-300 transition hover:border-indigo-500/45">
                <Play className="h-3.5 w-3.5" /> Run
              </button>
            </div>
          ) : (
            <div className="flex flex-1 items-center gap-1.5">
              <span className="flex flex-1 items-center gap-1.5 border border-white/[0.07] px-3 py-2 text-xs text-zinc-600">
                <FolderOpen className="h-3.5 w-3.5" /> Pending
              </span>
              <button onClick={() => setShowEdit(true)}
                className="flex items-center gap-1.5 border border-indigo-500/25 bg-indigo-500/8 px-3 py-2 text-xs font-semibold text-indigo-300 transition hover:border-indigo-500/45">
                <Play className="h-3.5 w-3.5" /> Run
              </button>
            </div>
          )}

          {/* Delete / Clone */}
          <AnimatePresence mode="wait">
            {confirmDelete ? (
              <motion.div key="confirm" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                className="flex items-center gap-1">
                <button onClick={() => { setDeleteError(null); deleteMutation.mutate() }} disabled={deleteMutation.isPending}
                  className="border border-red-500/30 bg-red-500/10 p-2 text-red-300 transition hover:bg-red-500/20 disabled:opacity-50">
                  {deleteMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                </button>
                <button onClick={() => setConfirmDelete(false)}
                  className="border border-white/[0.07] p-2 text-zinc-600 transition hover:text-zinc-300">
                  <X className="h-3.5 w-3.5" />
                </button>
              </motion.div>
            ) : (
              <motion.div key="actions" className="flex items-center gap-1">
                <motion.button onClick={onSelect} className="border border-white/[0.07] p-2 text-zinc-600 transition hover:text-indigo-400" title="Dashboard">
                  <BarChart2 className="h-3.5 w-3.5" />
                </motion.button>
                <motion.button onClick={() => cloneMutation.mutate()} disabled={cloneMutation.isPending}
                  className="border border-white/[0.07] p-2 text-zinc-600 transition hover:text-emerald-400 disabled:opacity-40" title="Clone">
                  {cloneMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Copy className="h-3.5 w-3.5" />}
                </motion.button>
                <motion.button onClick={() => setShowEdit(true)} className="border border-white/[0.07] p-2 text-zinc-600 transition hover:text-indigo-400" title="Edit">
                  <Pencil className="h-3.5 w-3.5" />
                </motion.button>
                <motion.button onClick={() => { setDeleteError(null); setConfirmDelete(true) }}
                  className="border border-white/[0.07] p-2 text-zinc-600 transition hover:text-red-400" title="Delete">
                  <Trash2 className="h-3.5 w-3.5" />
                </motion.button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
      <AnimatePresence>
        {showEdit && <EditAssessmentModal assessment={assessment} onClose={() => setShowEdit(false)} />}
      </AnimatePresence>
    </div>
    </motion.div>
  )
}

function EditAssessmentModal({ assessment, onClose }: { assessment: Assessment; onClose: () => void }) {
  const qc = useQueryClient()
  const startImport = useImportStore(s => s.startImport)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [shouldRun, setShouldRun] = useState(false)
  const [form, setForm] = useState({
    name: assessment.name ?? '',
    domain: assessment.domain ?? '',
    dc_ip: assessment.dc_ip ?? '',
    username: '',
    password: '',
  })

  const updateMutation = useMutation({
    mutationFn: () => assessmentApi.update(assessment.id, {
      name: form.name.trim() || undefined,
      domain: form.domain.trim() || undefined,
      dc_ip: form.dc_ip.trim() || undefined,
      username: form.username.trim() || undefined,
      password: form.password || undefined,
    }),
    onSuccess: async () => {
      qc.invalidateQueries({ queryKey: ['assessments'] })
      if (shouldRun) {
        try {
          const authMethod = assessment.collection_mode === 'WINDOWS_REMOTE' ? 'NTLM' : 'SIMPLE'
          const modules = Array.isArray(assessment.collection_config?.modules)
            ? assessment.collection_config.modules.map(String)
            : []
          const storedObfuscation = getStoredObfuscation(assessment.collection_config)
          const job = await collectionApi.ldap(assessment.id, {
            dc_ip: form.dc_ip || assessment.dc_ip || '',
            domain: form.domain || assessment.domain,
            username: form.username || (assessment.collection_config?.target?.username ?? ''),
            password: form.password || (assessment.collection_config?.target?.password ?? ''),
            auth_method: authMethod,
            enum_adcs: modules.includes('adcs'),
            enum_trusts: modules.includes('topology'),
            enum_gpos: modules.includes('gpo'),
            enum_acls: modules.includes('acl'),
            enum_gpo_acls: modules.includes('gpo'),
            scan_sysvol: modules.includes('gpo') || modules.includes('smb'),
            check_adcs_web: modules.includes('adcs'),
            check_esc6: modules.includes('adcs'),
            obfuscation_enabled: storedObfuscation.enabled,
            obfuscation_technique: storedObfuscation.technique,
            opsec_shuffle_attrs: storedObfuscation.enabled,
            opsec_jitter_ms: storedObfuscation.enabled ? 250 : 0,
          })
          startImport({ jobId: job.job_id, streamToken: job.stream_token, filename: `${form.domain || assessment.domain} collection` })
        } catch (err: unknown) {
          console.error('Failed to start collection:', err)
          // We don't block onClose if update succeeded but run failed, but maybe show a toast?
        }
      }
      onClose()
    },
    onError: (error: unknown) => {
      setSubmitError(getApiErrorMessage(error, 'Unable to update assessment'))
    },
  })

  const canSave = !!form.domain.trim() && !updateMutation.isPending

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: '#000' }}>
      <motion.div
        initial={{ opacity: 0, scale: 0.97, y: 12 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.97 }}
        transition={{ duration: 0.25, ease: [0.23, 1, 0.32, 1] }}
        className="relative w-full max-w-md overflow-hidden rounded-[24px]"
        style={{
          background: 'linear-gradient(160deg, rgba(10,4,24,0.98) 0%, rgba(6,2,16,0.99) 100%)',
          border: '1px solid rgba(99,102,241,0.25)',
          boxShadow: '0 0 0 1px rgba(99,102,241,0.08), 0 40px 120px rgba(0,0,0,0.8), 0 0 80px rgba(99,102,241,0.1)',
        }}
      >
        {/* Top gradient bar */}
        <div className="absolute inset-x-0 top-0 h-px"
          style={{ background: 'linear-gradient(90deg, transparent, rgba(99,102,241,0.9) 30%, rgba(168,85,247,0.8) 70%, transparent)' }} />

        {/* Header */}
        <div className="flex items-center justify-between gap-4 border-b border-white/8 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl"
              style={{ background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.3)' }}>
              <Pencil className="h-4 w-4 text-indigo-400" />
            </div>
            <div>
              <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-indigo-400/60">Edit Assessment</div>
              <h2 className="text-base font-bold text-white truncate max-w-[260px]">{assessment.name}</h2>
            </div>
          </div>
          <button onClick={onClose}
            className="rounded-xl border border-white/10 p-2 text-zinc-500 transition hover:border-white/20 hover:text-zinc-300">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="space-y-4 p-6">
          {(updateMutation.isError || submitError) && (
            <div className="flex items-start gap-2 rounded-2xl border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-xs text-red-300">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {submitError ?? 'Unable to update. Check connectivity.'}
            </div>
          )}

          {[
            { label: 'Assessment Name', key: 'name' as const, placeholder: 'corp.local baseline', mono: false },
            { label: 'Target Domain *', key: 'domain' as const, placeholder: 'corp.local', mono: false },
            { label: 'DC IP', key: 'dc_ip' as const, placeholder: '10.10.10.1', mono: true },
            { label: 'Username', key: 'username' as const, placeholder: 'Leave blank to keep current', mono: false },
            { label: 'Password', key: 'password' as const, placeholder: 'Leave blank to keep current', mono: false },
          ].map(f => (
            <div key={f.key}>
              <label className="mb-1.5 block text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">{f.label}</label>
              <input
                type={f.key === 'password' ? 'password' : 'text'}
                value={form[f.key as keyof typeof form]}
                placeholder={f.placeholder}
                onChange={e => setForm(c => ({ ...c, [f.key]: e.target.value }))}
                className={cn(
                  'w-full rounded-xl border border-white/8 bg-white/4 px-3 py-2.5 text-sm text-white outline-none transition placeholder:text-zinc-600 focus:border-indigo-500/50 focus:bg-white/6',
                  f.mono && 'font-mono'
                )}
              />
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 border-t border-white/6 px-6 py-4">
          <button onClick={onClose}
            className="rounded-xl border border-white/8 px-4 py-2.5 text-sm text-zinc-500 transition hover:text-zinc-300">
            Cancel
          </button>
          <button
            onClick={() => { setSubmitError(null); setShouldRun(true); setTimeout(() => updateMutation.mutate(), 0) }}
            disabled={!canSave}
            className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-bold tracking-wide transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
            style={{
              background: 'linear-gradient(135deg, rgba(16,185,129,0.9), rgba(5,150,105,0.85))',
              border: '1px solid rgba(16,185,129,0.5)',
              color: '#fff',
            }}
          >
            {updateMutation.isPending && shouldRun
              ? <><Loader2 className="h-4 w-4 animate-spin" /> Starting…</>
              : <><Play className="h-4 w-4" /> Save & Run</>}
          </button>
          <button
            onClick={() => { setSubmitError(null); setShouldRun(false); setTimeout(() => updateMutation.mutate(), 0) }}
            disabled={!canSave}
            className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-bold tracking-wide transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
            style={{
              background: 'linear-gradient(135deg, rgba(99,102,241,0.9), rgba(168,85,247,0.85))',
              border: '1px solid rgba(99,102,241,0.5)',
              color: '#fff',
              boxShadow: canSave ? '0 0 30px rgba(99,102,241,0.3)' : 'none',
            }}
          >
            {updateMutation.isPending && !shouldRun
              ? <><Loader2 className="h-4 w-4 animate-spin" /> Saving…</>
              : <><Pencil className="h-4 w-4" /> Save Changes</>}
          </button>
        </div>
      </motion.div>
    </div>
  )
}

interface NewAssessmentForm {
  name: string; domain: string; dc_ip: string; username: string; password: string
  collection_mode: string; modules: string[]
  connectivity_profile_id: string  // "" means none selected
}

function getApiErrorMessage(error: unknown, fallback: string) {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    return detail
      .map(item => {
        if (!item || typeof item !== 'object') return String(item)
        const msg = 'msg' in item ? String(item.msg) : 'Invalid request'
        const loc = 'loc' in item && Array.isArray(item.loc) ? item.loc.join('.') : ''
        return loc ? `${loc}: ${msg}` : msg
      })
      .join('; ')
  }
  return fallback
}

function domainToBaseDn(domain: string) {
  return domain
    .split('.')
    .map(part => part.trim())
    .filter(Boolean)
    .map(part => `DC=${part}`)
    .join(',')
}

function profileConfigString(profile: { config?: Record<string, unknown> } | undefined, key: string) {
  const value = profile?.config?.[key]
  return typeof value === 'string' ? value.trim() : ''
}

function profileCapabilities(profile: { config?: Record<string, unknown> } | undefined) {
  const probe = profile?.config?.last_probe
  if (!probe || typeof probe !== 'object') return null
  const capabilities = (probe as { capabilities?: unknown }).capabilities
  return capabilities && typeof capabilities === 'object' ? capabilities as Record<string, boolean> : null
}

function readinessRows(profile: { config?: Record<string, unknown> } | undefined) {
  const caps = profileCapabilities(profile)
  const ldap = !!(caps?.ldap_collection || caps?.ldaps_collection)
  const kerberos = !!(caps?.kerberoast || caps?.asreproast)
  const smb = !!(caps?.lateral_movement || caps?.secretsdump)
  const unknown = !caps
  return [
    ['LDAP', ldap],
    ['Kerberos', kerberos],
    ['SMB', smb],
    ['Directory Inventory', ldap],
    ['Kerberos Posture', kerberos],
    ['SMB Shares', smb],
  ].map(([label, pass]) => ({ label: String(label), state: unknown ? 'UNKNOWN' : pass ? 'PASS' : 'BLOCKED' }))
}

function getStoredObfuscation(config: Assessment['collection_config']) {
  const value = config?.obfuscation
  if (!value || typeof value !== 'object') {
    return { enabled: false, technique: 'auto' as TechniqueId }
  }
  const obfuscation = value as { enabled?: unknown; technique?: unknown }
  const rawTechnique = obfuscation.technique
  const technique: TechniqueId =
    rawTechnique === 'auto' || (typeof rawTechnique === 'number' && Number.isInteger(rawTechnique) && rawTechnique >= 0 && rawTechnique <= 13)
      ? rawTechnique as TechniqueId
      : 'auto'
  return {
    enabled: obfuscation.enabled === true,
    technique,
  }
}

function NewAssessmentModal({
  onClose,
  onCommandPlan,
  obfuscationEnabled: obfuscationProp = false,
  obfuscationTechnique: techniqueProp = 'auto',
  onObfuscationChange,
  onTechniqueChange,
}: {
  onClose: () => void
  onCommandPlan: (target: Partial<CommandTargetConfig>) => void
  obfuscationEnabled?: boolean
  obfuscationTechnique?: TechniqueId
  onObfuscationChange?: (v: boolean) => void
  onTechniqueChange?: (t: TechniqueId) => void
}) {
  // Local mirror so the modal can toggle without re-rendering parent
  const [localObfusc, setLocalObfusc] = useState(obfuscationProp)
  const [localTech, setLocalTech]   = useState<TechniqueId>(techniqueProp)
  const obfuscationEnabled = localObfusc
  const selectedTechnique  = localTech
  const [obfscSearch, setObfscSearch] = useState('')
  const [obfscFilter, setObfscFilter] = useState<'ALL' | 'MEDIUM' | 'HIGH' | 'MAX' | 'GOD'>('ALL')
  const toggleObfusc = () => {
    const next = !localObfusc
    setLocalObfusc(next)
    onObfuscationChange?.(next)
  }
  const setTechnique = (t: TechniqueId) => {
    setLocalTech(t)
    onTechniqueChange?.(t)
  }
  const activeObfscTechnique = useMemo(
    () => OBFUSCATION_TECHNIQUES.find(t => t.id === selectedTechnique) ?? OBFUSCATION_TECHNIQUES[0],
    [selectedTechnique],
  )
  const obfscLevelCounts = useMemo(
    () => OBFUSCATION_TECHNIQUES.reduce((acc, tech) => {
      acc[tech.level] = (acc[tech.level] ?? 0) + 1
      return acc
    }, {} as Record<string, number>),
    [],
  )
  const visibleObfscTechniques = useMemo(() => {
    const q = obfscSearch.trim().toLowerCase()
    return OBFUSCATION_TECHNIQUES.filter(tech => {
      const levelOk = obfscFilter === 'ALL' || tech.level === obfscFilter
      const textOk = !q || `${tech.name} ${tech.shortName} ${tech.level} ${tech.tag} ${tech.desc}`.toLowerCase().includes(q)
      return levelOk && textOk
    })
  }, [obfscFilter, obfscSearch])
  const qc = useQueryClient()
  const startImport = useImportStore(s => s.startImport)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [scriptResult, setScriptResult] = useState<CollectorScriptResult | null>(null)
  const [importFile, setImportFile] = useState<File | null>(null)
  const [importDragging, setImportDragging] = useState(false)
  const importFileInputRef = useRef<HTMLInputElement>(null)
  const [form, setForm] = useState<NewAssessmentForm>({
    name: '', domain: '', dc_ip: '', username: '', password: '', collection_mode: 'LINUX_REMOTE', modules: [...ALL_MODULES],
    connectivity_profile_id: '',
  })

  const { data: apiCollectionModules } = useQuery({ queryKey: collectionModuleKeys.all(), queryFn: () => collectionModulesApi.list(), staleTime: 300_000 })
  const collectionModules = useMemo(
    () => mergeCollectionModuleCatalogs(apiCollectionModules, fallbackCollectionModules),
    [apiCollectionModules],
  )

  const { data: connectivityProfiles = [] } = useQuery({
    queryKey: ['connectivity-profiles'],
    queryFn: () => connectivityApi.listProfiles(),
    staleTime: 30_000,
  })

  const defaultProfile = connectivityProfiles.find(p => p.is_default)

  // Auto-select default profile on first load
  useEffect(() => {
    if (defaultProfile && !form.connectivity_profile_id) {
      setForm(c => ({ ...c, connectivity_profile_id: defaultProfile.id }))
    }
  }, [defaultProfile, form.connectivity_profile_id])

  const compatibleModules = useMemo(
    () => collectionModules.filter(m => moduleSupportsMode(m, form.collection_mode)),
    [collectionModules, form.collection_mode]
  )

  const groupedModules = useMemo(
    () => compatibleModules.reduce<Record<string, CollectionModule[]>>((acc, m) => {
      const k = m.category || 'other'
      acc[k] = [...(acc[k] ?? []), m]
      return acc
    }, {}),
    [compatibleModules]
  )

  const selectedPlaybooks = useMemo(
    () => compatibleModules.filter(m => form.modules.includes(m.id)),
    [compatibleModules, form.modules]
  )

  const cmdCount = useMemo(
    () => selectedPlaybooks.reduce((s, m) => s + m.command_groups.reduce((g, cg) => g + cg.commands.length, 0), 0),
    [selectedPlaybooks]
  )

  const selectedProfile = connectivityProfiles.find(p => p.id === form.connectivity_profile_id)
  const profileDcIp = profileConfigString(selectedProfile, 'dc_ip')
  const profileDcHostname = profileConfigString(selectedProfile, 'dc_hostname')
  const profileDomain = profileConfigString(selectedProfile, 'target_domain')
  const effectiveDcIp = form.dc_ip.trim() || profileDcIp || profileDcHostname
  const effectiveDomain = form.domain.trim() || profileDomain
  const selectedProfileReadiness = readinessRows(selectedProfile)
  const isLinuxRemoteMode = form.collection_mode === 'LINUX_REMOTE'
  const isCredentialRequiredMode = isLinuxRemoteMode
  const canRunRemote = !!effectiveDcIp && !!form.username.trim() && !!form.password
  const isCommandPlanMode = form.collection_mode === 'COMMAND_PLAN'
  const isImportMode = form.collection_mode === 'IMPORT'
  const resolvedCollectionMode = isCommandPlanMode ? 'WINDOWS_LOCAL' : form.collection_mode
  const shouldStartCollection = resolvedCollectionMode === 'LINUX_REMOTE' || resolvedCollectionMode === 'WINDOWS_REMOTE'
  const authMethod = resolvedCollectionMode === 'WINDOWS_REMOTE' ? 'NTLM' : 'SIMPLE'
  const selectedModuleIds = useMemo(
    () => form.modules.filter(id => compatibleModules.some(m => m.id === id)),
    [compatibleModules, form.modules]
  )

  const createMutation = useMutation({
    mutationFn: async () => {
      if (isCommandPlanMode) {
        return { assessment: null, job: null, commandPlan: true, isImport: false }
      }

      if (isImportMode && importFile) {
        const isNativeCollector = importFile.name.toLowerCase().startsWith('adbygod-') && importFile.name.endsWith('.zip')
        const r = isNativeCollector
          ? await importApi.collectorZip(importFile)
          : await importApi.bloodhoundAuto(importFile)
        return { assessment: null, job: r, commandPlan: false, isImport: true }
      }

      const assessment = await assessmentApi.create({
        name: form.name || `${effectiveDomain} Assessment`,
        domain: effectiveDomain,
        dc_ip: effectiveDcIp || undefined,
        collection_mode: resolvedCollectionMode,
        connectivity_profile_id: form.connectivity_profile_id || undefined,
        collection_config: {
          modules: selectedModuleIds,
          requested_mode: form.collection_mode,
          resolved_mode: resolvedCollectionMode,
          target: {
            domain: effectiveDomain,
            dc_ip: effectiveDcIp,
            username: form.username,
            password: form.password,
            auth_method: authMethod,
          },
          obfuscation: {
            enabled: obfuscationEnabled,
            technique: selectedTechnique,
            remote_scope: resolvedCollectionMode === 'LINUX_REMOTE' ? 'ldap_query_shape' : 'remote_command',
          },
          connectivity: form.connectivity_profile_id ? {
            profile_id: form.connectivity_profile_id,
            profile_name: selectedProfile?.name,
            mode: selectedProfile?.mode,
          } : undefined,
        },
      })

      if (!shouldStartCollection) return { assessment, job: null, commandPlan: false }

      const job = await collectionApi.ldap(assessment.id, {
        dc_ip: effectiveDcIp,
        domain: effectiveDomain,
        username: form.username,
        password: form.password,
        auth_method: authMethod,
        enum_adcs: selectedModuleIds.includes('adcs'),
        enum_trusts: selectedModuleIds.includes('topology'),
        enum_gpos: selectedModuleIds.includes('gpo'),
        enum_acls: selectedModuleIds.includes('acl'),
        enum_gpo_acls: selectedModuleIds.includes('gpo'),
        scan_sysvol: selectedModuleIds.includes('gpo') || selectedModuleIds.includes('smb'),
        check_adcs_web: selectedModuleIds.includes('adcs'),
        check_esc6: selectedModuleIds.includes('adcs'),
        obfuscation_enabled: obfuscationEnabled,
        obfuscation_technique: selectedTechnique,
        opsec_shuffle_attrs: obfuscationEnabled,
        opsec_jitter_ms: obfuscationEnabled ? 250 : 0,
      })

      return { assessment, job, commandPlan: false, isImport: false }
    },
    onSuccess: ({ job, commandPlan, isImport }) => {
      if (isImport && job) {
        qc.invalidateQueries({ queryKey: assessmentKeys.all })
        startImport({ jobId: job.job_id, streamToken: job.stream_token, filename: importFile?.name ?? 'import' })
        onClose()
        return
      }

      if (commandPlan) {
        onCommandPlan({
          ip: effectiveDcIp,
          domain: effectiveDomain,
          baseDn: domainToBaseDn(effectiveDomain),
          ldapUrl: effectiveDcIp ? `ldap://${effectiveDcIp}:389` : '',
          username: form.username.trim(),
          password: form.password,
        })
        onClose()
        return
      }

      qc.invalidateQueries({ queryKey: assessmentKeys.all })
      if (job) {
        startImport({ jobId: job.job_id, streamToken: job.stream_token, filename: `${effectiveDomain} collection` })
      }
      onClose()
    },
    onError: (error: unknown) => {
      setSubmitError(getApiErrorMessage(error, 'Unable to create assessment'))
    },
  })

  const toggleModule = (id: string) =>
    setForm(c => ({ ...c, modules: c.modules.includes(id) ? c.modules.filter(x => x !== id) : [...c.modules, id] }))

  const selectAll = () => setForm(c => ({ ...c, modules: Array.from(new Set([...c.modules, ...compatibleModules.map(m => m.id)])) }))
  const clearAll = () => {
    const ids = new Set(compatibleModules.map(m => m.id))
    setForm(c => ({ ...c, modules: c.modules.filter(id => !ids.has(id)) }))
  }

  const activeMode = MODE_OPTIONS.find(m => m.id === form.collection_mode) ?? MODE_OPTIONS[0]
  const missingRemoteTarget = isCredentialRequiredMode && !canRunRemote
  const canLaunch = isImportMode
    ? !!importFile && !createMutation.isPending
    : !!effectiveDomain && !missingRemoteTarget && !createMutation.isPending && selectedPlaybooks.length > 0
  const modeSummary = form.collection_mode === 'LINUX_REMOTE'
    ? 'Remote LDAP Collection runs live ldap3 directory collection from this Linux host'
    : form.collection_mode === 'COMMAND_PLAN'
      ? 'Windows Local opens a PowerShell collector plan that produces an importable zip'
      : form.collection_mode === 'IMPORT'
        ? 'Import is for an existing BloodHound/collector .zip or .json output'
        : null

  const primaryActionLabel = isCommandPlanMode ? 'Open Windows Local' : form.collection_mode === 'IMPORT' ? 'Create Import Slot' : 'Launch Remote LDAP'
  const pendingActionLabel = isCommandPlanMode ? 'Opening…' : form.collection_mode === 'IMPORT' ? 'Creating…' : 'Launching…'
  const PrimaryActionIcon = isCommandPlanMode ? Terminal : Play

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: '#000' }}>
      <motion.div
        initial={{ opacity: 0, scale: 0.97, y: 12 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.97 }}
        transition={{ duration: 0.3, ease: [0.23, 1, 0.32, 1] }}
        className="adbygod-readable-modal relative flex h-[88vh] w-full max-w-4xl flex-col overflow-hidden rounded-[28px]"
        style={{
          background: 'linear-gradient(160deg, rgba(10,4,24,0.98) 0%, rgba(6,2,16,0.99) 100%)',
          border: '1px solid rgba(99,102,241,0.25)',
          boxShadow: '0 0 0 1px rgba(99,102,241,0.08), 0 40px 120px rgba(0,0,0,0.8), 0 0 80px rgba(99,102,241,0.1)',
        }}
      >
        {/* Top gradient bar */}
        <div className="absolute inset-x-0 top-0 h-px"
          style={{ background: 'linear-gradient(90deg, transparent, rgba(99,102,241,0.9) 30%, rgba(168,85,247,0.8) 70%, transparent)' }} />

        {/* Header */}
        <div className="flex items-center justify-between gap-4 border-b border-white/8 px-6 py-4">
          <div className="flex items-center gap-4">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl"
              style={{ background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.3)' }}>
              <Zap className="h-4 w-4 text-indigo-400" />
            </div>
            <div>
              <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-indigo-400/60">
                {isCommandPlanMode ? 'Windows Local' : form.collection_mode === 'IMPORT' ? 'Import Setup' : 'Remote LDAP Collection'}
              </div>
              <h2 className="text-lg font-bold text-white">New Assessment</h2>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* Skull obfuscation toggle — always visible in header */}
            <button
              onClick={toggleObfusc}
              title={obfuscationEnabled ? 'PS Obfuscation ON — click to disable' : 'PS Obfuscation OFF — click to enable'}
              className="relative flex items-center gap-2 rounded-xl px-3 py-2 transition-all duration-300"
              style={{
                background: obfuscationEnabled ? 'rgba(239,68,68,0.12)' : 'rgba(255,255,255,0.04)',
                border: `1px solid ${obfuscationEnabled ? 'rgba(239,68,68,0.5)' : 'rgba(255,255,255,0.1)'}`,
                boxShadow: obfuscationEnabled ? '0 0 16px rgba(239,68,68,0.25), 0 0 6px rgba(239,68,68,0.15)' : 'none',
              }}
            >
              <Skull
                className="h-4 w-4 transition-all duration-300"
                style={{
                  color: obfuscationEnabled ? '#f87171' : 'rgba(161,161,170,0.4)',
                  filter: obfuscationEnabled ? 'drop-shadow(0 0 5px rgba(239,68,68,1)) drop-shadow(0 0 12px rgba(239,68,68,0.6))' : 'none',
                  animation: obfuscationEnabled ? 'skullPulse 2s ease-in-out infinite' : 'none',
                }}
              />
              <span className="text-[9px] font-black uppercase tracking-[0.2em]"
                style={{ fontFamily: 'JetBrains Mono, monospace', color: obfuscationEnabled ? '#f87171' : 'rgba(161,161,170,0.3)' }}>
                {obfuscationEnabled ? 'OBFSC ON' : 'OBFSC'}
              </span>
              <span className="h-1.5 w-1.5 rounded-full transition-all duration-300"
                style={{
                  background: obfuscationEnabled ? '#ef4444' : 'rgba(161,161,170,0.2)',
                  boxShadow: obfuscationEnabled ? '0 0 6px #ef4444, 0 0 12px rgba(239,68,68,0.6)' : 'none',
                  animation: obfuscationEnabled ? 'obfscGlow 1.5s ease-in-out infinite' : 'none',
                }} />
            </button>
            <button onClick={onClose}
              className="rounded-xl border border-white/10 p-2 text-zinc-500 transition hover:border-white/20 hover:text-zinc-300">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex min-h-0 flex-1 overflow-hidden">
          {/* Left panel */}
          <div className="adbygod-left-panel flex w-72 shrink-0 flex-col gap-3 overflow-y-auto border-r border-white/6 p-5">

            {(createMutation.isError || submitError) && (
              <div className="flex items-start gap-2 rounded-2xl border border-red-500/30 bg-red-500/10 px-3 py-2.5 text-xs text-red-300">
                <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {submitError ?? 'Unable to create. Check connectivity.'}
              </div>
            )}
            {/* Mode picker */}
            <div className="rounded-2xl border border-white/6 bg-black p-4">
              <div className="mb-3 text-[10px] font-bold uppercase tracking-[0.2em] text-indigo-400/50">Collection Mode</div>
              <div className="space-y-1.5">
                {MODE_OPTIONS.map(mode => {
                  const sel = form.collection_mode === mode.id
                  const Icon = mode.icon
                  return (
                    <button key={mode.id} type="button" onClick={() => { setForm(c => ({ ...c, collection_mode: mode.id })); if (mode.id !== 'IMPORT') setImportFile(null) }}
                      className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-all"
                      style={{
                        background: sel ? `${mode.accent}15` : 'transparent',
                        border: `1px solid ${sel ? `${mode.accent}40` : 'rgba(255,255,255,0.05)'}`,
                        boxShadow: sel ? `0 0 20px ${mode.accent}15` : 'none',
                      }}>
                      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color: sel ? mode.accent : '#52525b' }} />
                      <div className="min-w-0">
                        <div className="text-xs font-semibold" style={{ color: sel ? '#fff' : '#a1a1aa' }}>{mode.label}</div>
                        <div className="text-[10px]" style={{ color: sel ? `${mode.accent}80` : '#52525b' }}>{mode.shortLabel}</div>
                      </div>
                      {sel && <div className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: mode.accent, boxShadow: `0 0 6px ${mode.accent}` }} />}
                    </button>
                  )
                })}
              </div>
            </div>

            {isCommandPlanMode ? (
              <div className="rounded-2xl border border-amber-400/20 bg-amber-400/8 p-3 text-xs leading-5 text-amber-100/70">
                Windows Local is meant for a domain-joined Windows host. Run the generated PowerShell collector there, then import the produced zip back into AdByG0d.
              </div>
            ) : isImportMode ? (
              <div className="space-y-2">
                <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-orange-400/50">Upload File</div>
                <input
                  ref={importFileInputRef}
                  type="file"
                  accept=".zip,.json"
                  className="sr-only"
                  onChange={e => { const f = e.target.files?.[0]; if (f) setImportFile(f); e.target.value = '' }}
                />
                <div
                  className="relative overflow-hidden rounded-2xl border transition-all cursor-pointer"
                  style={{
                    background: importDragging ? 'rgba(251,146,60,0.08)' : importFile ? 'rgba(251,146,60,0.06)' : 'rgba(255,255,255,0.02)',
                    borderColor: importDragging ? 'rgba(251,146,60,0.6)' : importFile ? 'rgba(251,146,60,0.4)' : 'rgba(255,255,255,0.08)',
                    borderStyle: importFile ? 'solid' : 'dashed',
                    boxShadow: importFile ? '0 0 20px rgba(251,146,60,0.1)' : 'none',
                  }}
                  onDragOver={e => { e.preventDefault(); setImportDragging(true) }}
                  onDragLeave={() => setImportDragging(false)}
                  onDrop={e => {
                    e.preventDefault(); setImportDragging(false)
                    const f = e.dataTransfer.files[0]
                    if (f && (f.name.endsWith('.zip') || f.name.endsWith('.json'))) setImportFile(f)
                  }}
                  onClick={() => importFileInputRef.current?.click()}
                >
                  <div className="flex flex-col items-center justify-center gap-2 px-4 py-5">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl"
                      style={{ background: 'rgba(251,146,60,0.12)', border: '1px solid rgba(251,146,60,0.3)' }}>
                      {importFile
                        ? <FolderOpen className="h-4 w-4 text-orange-400" />
                        : <Upload className="h-4 w-4 text-orange-400" />}
                    </div>
                    {importFile ? (
                      <div className="w-full text-center space-y-0.5">
                        <div className="truncate text-xs font-semibold text-white px-2">{importFile.name}</div>
                        <div className="text-[10px] text-orange-400/60">
                          {(importFile.size / 1024 / 1024).toFixed(1)} MB · click to change
                        </div>
                      </div>
                    ) : (
                      <div className="text-center space-y-0.5">
                        <div className="text-xs font-semibold text-white">Drop file here</div>
                        <div className="text-[10px] text-zinc-500">.zip or .json · BloodHound / AdByGod</div>
                      </div>
                    )}
                  </div>
                </div>
                {importFile && (
                  <button
                    onClick={e => { e.stopPropagation(); setImportFile(null) }}
                    className="flex items-center gap-1 text-[10px] text-zinc-600 hover:text-zinc-400 transition"
                  >
                    <X className="h-3 w-3" /> Clear file
                  </button>
                )}
              </div>
            ) : null}

            {/* Target fields */}
            <div className="rounded-2xl border border-white/6 bg-black p-4 space-y-3">
              <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-indigo-400/50">Target</div>
              {[
                { label: 'Assessment Name', key: 'name' as const, placeholder: form.domain ? `${form.domain} baseline` : 'corp.local baseline', mono: false },
                { label: 'Target Domain *', key: 'domain' as const, placeholder: 'corp.local', mono: false },
              ].map(f => (
                <div key={f.key}>
                  <label className="mb-1 block text-[10px] font-medium text-zinc-500">{f.label}</label>
                  <input type="text" value={form[f.key]} placeholder={f.placeholder}
                    autoComplete="off"
                    onChange={e => setForm(c => ({ ...c, [f.key]: e.target.value }))}
                    className={cn('w-full rounded-xl border border-white/8 bg-white/4 px-3 py-2 text-xs text-white outline-none transition placeholder:text-zinc-600 focus:border-indigo-500/50 focus:bg-white/6', f.mono && 'font-mono')} />
                </div>
              ))}
              {/* Connectivity Profile Selector */}
              <div>
                <label className="mb-1 block text-[10px] font-medium text-zinc-500 uppercase tracking-widest">
                  CONNECTIVITY PROFILE
                </label>
                <select
                  value={form.connectivity_profile_id}
                  onChange={e => setForm(c => ({ ...c, connectivity_profile_id: e.target.value }))}
                  className="w-full bg-black border border-white/8 rounded-xl px-3 py-2 font-mono text-xs text-white/80 focus:outline-none focus:border-indigo-500/50 appearance-none"
                >
                  <option value="">Direct (no profile)</option>
                  {connectivityProfiles.map(p => (
                    <option key={p.id} value={p.id}>
                      {p.name} [{p.mode}]{p.is_default ? ' ★ default' : ''}
                    </option>
                  ))}
                </select>
                {form.connectivity_profile_id && (
                  <div className="mt-2 rounded-xl border border-indigo-400/15 bg-indigo-400/5 p-2">
                    <div className="mb-2 flex items-center justify-between gap-2 text-[10px] font-mono uppercase tracking-widest">
                      <span className="text-indigo-300/50">Transport: {selectedProfile?.mode ?? ''}</span>
                      <span className="text-indigo-300/50">DC: {effectiveDcIp || 'not set'}</span>
                    </div>
                    <div className="grid grid-cols-2 gap-1.5">
                      {selectedProfileReadiness.map(row => (
                        <div key={row.label} className="flex items-center justify-between gap-2 rounded-lg border border-white/5 bg-black/40 px-2 py-1">
                          <span className="truncate text-[10px] text-zinc-400">{row.label}</span>
                          <span className={cn(
                            'text-[9px] font-black tracking-widest',
                            row.state === 'PASS' ? 'text-emerald-400' : row.state === 'BLOCKED' ? 'text-red-400' : 'text-zinc-500'
                          )}>
                            {row.state === 'PASS' ? 'PASS' : row.state === 'BLOCKED' ? 'BLOCK' : 'UNK'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              {[
                { label: isCredentialRequiredMode ? 'DC IP *' : 'DC IP', key: 'dc_ip' as const, placeholder: '10.10.10.1', mono: true },
                { label: isCredentialRequiredMode ? 'Username *' : 'Username', key: 'username' as const, placeholder: 'scanner@corp.local', mono: false },
              ].map(f => (
                <div key={f.key}>
                  <label className="mb-1 block text-[10px] font-medium text-zinc-500">{f.label}</label>
                  <input type="text" value={form[f.key]} placeholder={f.placeholder}
                    autoComplete={f.key === 'username' ? 'off' : undefined}
                    onChange={e => setForm(c => ({ ...c, [f.key]: e.target.value }))}
                    className={cn('w-full rounded-xl border border-white/8 bg-white/4 px-3 py-2 text-xs text-white outline-none transition placeholder:text-zinc-600 focus:border-indigo-500/50 focus:bg-white/6', f.mono && 'font-mono')} />
                </div>
              ))}
              <div>
                <label className="mb-1 block text-[10px] font-medium text-zinc-500">{isCredentialRequiredMode ? 'Password *' : 'Password'}</label>
                <input type="password" value={form.password} placeholder="Account password"
                  autoComplete="new-password"
                  onChange={e => setForm(c => ({ ...c, password: e.target.value }))}
                  className="w-full rounded-xl border border-white/8 bg-white/4 px-3 py-2 text-xs text-white outline-none transition placeholder:text-zinc-600 focus:border-indigo-500/50 focus:bg-white/6" />
              </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 gap-2">
              {[
                { l: 'Modules', v: selectedPlaybooks.length, c: '#a5b4fc' },
                { l: 'Commands', v: cmdCount, c: '#818cf8' },
              ].map(s => (
                <div key={s.l} className="rounded-xl border border-white/6 bg-black p-3 text-center">
                  <div className="text-xl font-bold tabular-nums" style={{ color: s.c }}>{s.v}</div>
                  <div className="mt-0.5 text-[9px] uppercase tracking-[0.18em] text-zinc-600">{s.l}</div>
                </div>
              ))}
            </div>
          </div>

          {/* ── OBFSC Control sidebar — slides in between left panel and module library ── */}
          <AnimatePresence>
            {obfuscationEnabled && (
              <motion.div
                key="obfsc-sidebar"
                initial={{ width: 0, opacity: 0 }}
                animate={{ width: 360, opacity: 1 }}
                exit={{ width: 0, opacity: 0 }}
                transition={{ duration: 0.32, ease: [0.23, 1, 0.32, 1] }}
                className="adbygod-obfsc-panel adbygod-obfsc-v2 relative shrink-0 overflow-hidden flex flex-col"
                style={{
                  borderRight: '1px solid rgba(248,113,113,0.36)',
                  background: 'radial-gradient(circle at top left, rgba(248,113,113,0.14), transparent 34%), linear-gradient(180deg, rgba(22,6,24,0.99) 0%, rgba(7,3,15,0.99) 100%)',
                  boxShadow: 'inset -1px 0 0 rgba(248,113,113,0.18), 8px 0 42px rgba(239,68,68,0.12)',
                }}
              >
                <div className="pointer-events-none absolute inset-x-0 top-0 h-px"
                  style={{ background: 'linear-gradient(90deg,transparent,rgba(248,113,113,0.95),rgba(168,85,247,0.95),transparent)' }} />
                <div className="pointer-events-none absolute -right-16 -top-16 h-40 w-40 rounded-full blur-3xl"
                  style={{ background: 'rgba(239,68,68,0.14)' }} />

                <div className="relative border-b px-4 py-3.5" style={{ borderColor: 'rgba(248,113,113,0.22)', minWidth: 360 }}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-9 w-9 items-center justify-center rounded-2xl border"
                        style={{ background: 'rgba(248,113,113,0.12)', borderColor: 'rgba(248,113,113,0.35)', boxShadow: '0 0 22px rgba(248,113,113,0.22)' }}>
                        <Skull className="h-4 w-4 shrink-0"
                          style={{ color: '#f87171', filter: 'drop-shadow(0 0 7px rgba(239,68,68,0.95))', animation: 'skullPulse 2s ease-in-out infinite' }} />
                      </div>
                      <div>
                        <div className="text-[11px] font-black uppercase tracking-[0.24em]"
                          style={{ fontFamily: 'JetBrains Mono, monospace', color: '#fecaca' }}>
                          OBFSC Control
                        </div>
                        <div className="mt-0.5 text-[10px] font-mono" style={{ color: 'rgba(252,165,165,0.62)' }}>
                          {activeMode.label} · {selectedPlaybooks.length} modules · {cmdCount} cmds
                        </div>
                      </div>
                    </div>
                    <div className="rounded-full border px-2 py-1 text-[9px] font-black uppercase tracking-[0.18em]"
                      style={{ color: '#f87171', borderColor: 'rgba(248,113,113,0.35)', background: 'rgba(248,113,113,0.10)' }}>
                      Live
                    </div>
                  </div>

                  <div className="mt-3 grid grid-cols-3 gap-2">
                    <button type="button" onClick={() => setTechnique('auto')}
                      className="rounded-xl border px-2 py-2 text-left transition hover:brightness-125"
                      style={{
                        background: selectedTechnique === 'auto' ? 'rgba(168,85,247,0.18)' : 'rgba(255,255,255,0.035)',
                        borderColor: selectedTechnique === 'auto' ? 'rgba(168,85,247,0.55)' : 'rgba(255,255,255,0.08)',
                      }}>
                      <div className="text-[9px] font-black uppercase text-fuchsia-200">Smart</div>
                      <div className="text-[8px] text-zinc-400">auto rotate</div>
                    </button>

                    <button type="button" onClick={() => setTechnique(9)}
                      className="rounded-xl border px-2 py-2 text-left transition hover:brightness-125"
                      style={{
                        background: selectedTechnique === 9 ? 'rgba(59,130,246,0.18)' : 'rgba(255,255,255,0.035)',
                        borderColor: selectedTechnique === 9 ? 'rgba(59,130,246,0.50)' : 'rgba(255,255,255,0.08)',
                      }}>
                      <div className="text-[9px] font-black uppercase text-blue-200">Stable</div>
                      <div className="text-[8px] text-zinc-400">utf16 wire</div>
                    </button>

                    <button type="button" onClick={() => setTechnique(0)}
                      className="rounded-xl border px-2 py-2 text-left transition hover:brightness-125"
                      style={{
                        background: selectedTechnique === 0 ? 'rgba(34,211,238,0.16)' : 'rgba(255,255,255,0.035)',
                        borderColor: selectedTechnique === 0 ? 'rgba(34,211,238,0.45)' : 'rgba(255,255,255,0.08)',
                      }}>
                      <div className="text-[9px] font-black uppercase text-cyan-200">Readable</div>
                      <div className="text-[8px] text-zinc-400">simple b64</div>
                    </button>
                  </div>
                </div>

                <div className="border-b px-4 py-3" style={{ borderColor: 'rgba(248,113,113,0.16)', minWidth: 360 }}>
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-red-200/35" />
                    <input
                      value={obfscSearch}
                      onChange={e => setObfscSearch(e.target.value)}
                      placeholder="Search technique, level, tag..."
                      className="w-full rounded-xl border bg-black/35 py-2 pl-9 pr-3 font-mono text-[11px] text-red-50 outline-none transition placeholder:text-red-200/25 focus:border-red-300/40"
                      style={{ borderColor: 'rgba(248,113,113,0.16)' }}
                    />
                  </div>

                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {(['ALL', 'MEDIUM', 'HIGH', 'MAX', 'GOD'] as const).map(level => {
                      const active = obfscFilter === level
                      const color = level === 'ALL' ? '#fca5a5' : LEVEL_COLORS[level]
                      return (
                        <button key={level} type="button" onClick={() => setObfscFilter(level)}
                          className="rounded-full border px-2 py-1 text-[8px] font-black uppercase tracking-[0.12em] transition"
                          style={{
                            color: active ? color : 'rgba(244,244,245,0.45)',
                            background: active ? `${color}18` : 'rgba(255,255,255,0.035)',
                            borderColor: active ? `${color}55` : 'rgba(255,255,255,0.07)',
                          }}>
                          {level}{level !== 'ALL' ? ` ${obfscLevelCounts[level] ?? 0}` : ''}
                        </button>
                      )
                    })}
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto px-3.5 py-3 space-y-2" style={{ minWidth: 360 }}>
                  {visibleObfscTechniques.length === 0 ? (
                    <div className="rounded-2xl border border-white/8 bg-white/4 p-4 text-center text-xs text-zinc-500">
                      No matching techniques.
                    </div>
                  ) : visibleObfscTechniques.map(tech => {
                    const active = selectedTechnique === tech.id
                    const lvlColor = LEVEL_COLORS[tech.level]
                    return (
                      <button
                        key={String(tech.id)}
                        type="button"
                        onClick={() => setTechnique(tech.id)}
                        className="group w-full text-left rounded-2xl px-3.5 py-3 transition-all duration-200 relative overflow-hidden"
                        style={{
                          background: active ? `linear-gradient(135deg, ${lvlColor}20, rgba(239,68,68,0.11))` : 'rgba(255,255,255,0.035)',
                          border: `1px solid ${active ? `${lvlColor}70` : 'rgba(255,255,255,0.075)'}`,
                          boxShadow: active ? `0 0 22px ${lvlColor}22, inset 0 0 18px rgba(255,255,255,0.035)` : 'none',
                        }}
                      >
                        {active && (
                          <>
                            <div className="pointer-events-none absolute inset-y-0 left-0 w-1"
                              style={{ background: lvlColor, boxShadow: `0 0 14px ${lvlColor}` }} />
                            <div className="pointer-events-none absolute right-0 top-0 h-12 w-12 rounded-bl-full"
                              style={{ background: `${lvlColor}12` }} />
                          </>
                        )}

                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="truncate font-mono text-[12px] font-black"
                                style={{ color: active ? '#fff' : 'rgba(226,232,240,0.82)' }}>
                                {tech.shortName}
                              </span>
                              {active && (
                                <span className="rounded-full bg-red-400/15 px-1.5 py-0.5 text-[7px] font-black uppercase tracking-widest text-red-200">
                                  Selected
                                </span>
                              )}
                            </div>
                            <div className="mt-0.5 truncate text-[11px] font-semibold"
                              style={{ color: active ? '#fecaca' : 'rgba(244,244,245,0.64)' }}>
                              {tech.name}
                            </div>
                          </div>

                          <span className="shrink-0 rounded-lg px-2 py-1 text-[8px] font-black uppercase tracking-[0.12em]"
                            style={{ background: `${lvlColor}18`, border: `1px solid ${lvlColor}45`, color: lvlColor }}>
                            {tech.level}
                          </span>
                        </div>

                        <div className="mt-2 flex items-center gap-2">
                          <span className="rounded-full border px-2 py-0.5 font-mono text-[8px]"
                            style={{ color: 'rgba(252,165,165,0.62)', borderColor: 'rgba(252,165,165,0.18)', background: 'rgba(0,0,0,0.20)' }}>
                            {tech.tag}
                          </span>
                          <span className="text-[8px] text-zinc-600">id:{String(tech.id)}</span>
                        </div>

                        <p className="mt-2 text-[10px] leading-4"
                          style={{ color: active ? 'rgba(254,202,202,0.78)' : 'rgba(212,212,216,0.50)' }}>
                          {tech.desc}
                        </p>
                      </button>
                    )
                  })}
                </div>

                <div className="border-t px-4 py-3" style={{ borderColor: 'rgba(248,113,113,0.20)', minWidth: 360 }}>
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-[8px] font-black uppercase tracking-[0.22em]"
                        style={{ color: 'rgba(248,113,113,0.55)', fontFamily: 'JetBrains Mono, monospace' }}>
                        Active Technique
                      </div>
                      <div className="mt-1 truncate text-[12px] font-bold" style={{ color: '#fecaca' }}>
                        {activeObfscTechnique.name}
                      </div>
                    </div>

                    <div className="rounded-xl border px-2.5 py-1.5 text-right"
                      style={{
                        borderColor: `${LEVEL_COLORS[activeObfscTechnique.level]}50`,
                        background: `${LEVEL_COLORS[activeObfscTechnique.level]}12`,
                      }}>
                      <div className="text-[8px] font-black uppercase"
                        style={{ color: LEVEL_COLORS[activeObfscTechnique.level] }}>
                        {activeObfscTechnique.level}
                      </div>
                      <div className="text-[7px] text-zinc-500">profile</div>
                    </div>
                  </div>

                  <div className="mt-2 rounded-xl border border-amber-400/15 bg-amber-400/5 px-3 py-2 text-[9px] leading-4 text-amber-100/55">
                    Use only in authorized lab or client-approved assessment scope. Keep logs and raw collection outputs for auditability.
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Right panel — module library */}
          <div className="adbygod-module-panel flex min-h-0 flex-1 flex-col overflow-hidden">
            <div className="flex items-center justify-between border-b border-white/6 px-5 py-3">
              <div>
                <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-indigo-400/50">Module Library</div>
                <div className="mt-0.5 text-xs text-zinc-500">
                  <span className="text-indigo-300">{compatibleModules.length}</span> available for {activeMode.label}
                  {modeSummary && <span className="text-zinc-600"> · {modeSummary}</span>}
                </div>
              </div>
              <div className="flex gap-2">
                <button onClick={selectAll} className="rounded-xl border border-indigo-500/25 bg-indigo-500/10 px-2.5 py-1.5 text-xs text-indigo-300 transition hover:bg-indigo-500/20">
                  All
                </button>
                <button onClick={clearAll} className="rounded-xl border border-white/8 bg-white/4 px-2.5 py-1.5 text-xs text-zinc-400 transition hover:text-zinc-200">
                  Clear
                </button>
              </div>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto p-5 space-y-5">
              {Object.entries(groupedModules).map(([category, modules]) => (
                <div key={category}>
                  <div className="mb-2 flex items-center gap-3">
                    <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-indigo-300/60">
                      {CATEGORY_LABELS[category] ?? category}
                    </span>
                    <div className="h-px flex-1 bg-white/6" />
                    <span className="text-[10px] text-zinc-600">{modules.length}</span>
                  </div>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {modules.map(module => {
                      const active = form.modules.includes(module.id)
                      const meta = MODULE_META[module.id]
                      const accent = meta?.accent ?? '#6366f1'
                      const cmdCnt = module.command_groups.reduce((s, g) => s + g.commands.length, 0)
                      return (
                        <button key={module.id} type="button" onClick={() => toggleModule(module.id)}
                          className="group rounded-2xl p-3.5 text-left transition-all"
                          style={{
                            background: active ? `${accent}12` : 'rgba(255,255,255,0.02)',
                            border: `1px solid ${active ? `${accent}40` : 'rgba(255,255,255,0.06)'}`,
                            boxShadow: active ? `0 0 20px ${accent}15` : 'none',
                          }}>
                          <div className="flex items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="truncate text-sm font-semibold text-white">{module.name}</div>
                              <div className="mt-0.5 truncate font-mono text-[9px]" style={{ color: `${accent}70` }}>{module.id}</div>
                            </div>
                            <div className="mt-1 h-2 w-2 shrink-0 rounded-full"
                              style={{ background: active ? accent : '#3f3f46', boxShadow: active ? `0 0 8px ${accent}` : 'none' }} />
                          </div>
                          <p className="mt-2 line-clamp-2 text-[11px] leading-5 text-zinc-500">{module.description}</p>
                          <div className="mt-2 flex gap-1.5 flex-wrap">
                            <span className="rounded-full px-1.5 py-0.5 text-[9px]"
                              style={{ background: `${accent}10`, border: `1px solid ${accent}25`, color: `${accent}cc` }}>
                              {cmdCnt} cmds
                            </span>
                            {obfuscationEnabled && active && (
                              <span className="inline-flex items-center gap-0.5 rounded-full px-1.5 py-0.5 text-[8px] font-bold"
                                style={{ background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.35)', color: '#f87171' }}>
                                <Skull className="w-2 h-2" style={{ filter: 'drop-shadow(0 0 3px rgba(239,68,68,0.8))' }} />
                                OBFSC
                              </span>
                            )}
                          </div>
                        </button>
                      )
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center gap-3 border-t border-white/6 px-6 py-4">
          <div className="text-xs text-zinc-600">
            {isImportMode ? (
              importFile
                ? <span><span className="text-orange-400">{importFile.name}</span> · {(importFile.size / 1024 / 1024).toFixed(1)} MB · BloodHound / AdByGod import · {selectedPlaybooks.length} modules</span>
                : <span className="text-amber-400/60">Drop or browse a .zip or .json file to import</span>
            ) : form.domain ? (
              missingRemoteTarget ? (
                <span className="text-amber-400/60">Set DC IP, username, and password to launch live collection</span>
              ) : modeSummary ? (
                <span><span className="text-zinc-400">{form.domain}</span> · {modeSummary} · {selectedPlaybooks.length} modules</span>
              ) : isCommandPlanMode ? (
                <span><span className="text-zinc-400">{form.domain}</span> · PowerShell collector package · importable zip output</span>
              ) : (
                <span><span className="text-zinc-400">{form.domain}</span> · {selectedPlaybooks.length} modules · {cmdCount} commands</span>
              )
            ) : (
              <span className="text-amber-400/60">Set a target domain to continue</span>
            )}
          </div>
          <div className="ml-auto flex items-center gap-2">
            <button onClick={onClose} className="rounded-xl border border-white/8 px-4 py-2.5 text-sm text-zinc-500 transition hover:text-zinc-300">
              Cancel
            </button>
            {isCommandPlanMode && (
              <button
                onClick={() => {
                  const result = generateCollectorScript(
                    selectedPlaybooks,
                    {
                      domain:   form.domain.trim(),
                      dcIp:     form.dc_ip.trim(),
                      username: form.username.trim(),
                      password: form.password,
                    },
                    { obfuscate: obfuscationEnabled, technique: selectedTechnique },
                  )
                  setScriptResult(result)
                }}
                disabled={!form.domain.trim() || selectedPlaybooks.length === 0}
                className="flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-bold tracking-wide transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
                style={{
                  background: 'linear-gradient(135deg, rgba(250,204,21,0.85), rgba(251,146,60,0.8))',
                  border: '1px solid rgba(250,204,21,0.4)',
                  color: '#000',
                  boxShadow: form.domain.trim() ? '0 0 24px rgba(250,204,21,0.2)' : 'none',
                }}
              >
                <Code2 className="h-4 w-4" /> Generate Script
              </button>
            )}
            <button
              onClick={() => { setSubmitError(null); createMutation.mutate() }}
              disabled={!canLaunch}
              className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-bold tracking-wide transition-all hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
              style={{
                background: 'linear-gradient(135deg, rgba(99,102,241,0.9), rgba(168,85,247,0.85))',
                border: '1px solid rgba(99,102,241,0.5)',
                color: '#fff',
                boxShadow: canLaunch ? '0 0 30px rgba(99,102,241,0.3)' : 'none',
              }}
            >
              {createMutation.isPending
                ? <><Loader2 className="h-4 w-4 animate-spin" /> {pendingActionLabel}</>
                : <><PrimaryActionIcon className="h-4 w-4" /> {primaryActionLabel}</>}
            </button>
          </div>
        </div>
        <AnimatePresence>
          {scriptResult && (
            <PSScriptModal
              result={scriptResult}
              domain={form.domain}
              onClose={() => setScriptResult(null)}
            />
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  )
}

function ImportDropZone() {
  const startImport = useImportStore(s => s.startImport)
  const activeJob = useImportStore(s => s.job)
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFile = async (file: File) => {
    if (uploading || activeJob) return
    if (!file.name.endsWith('.zip') && !file.name.endsWith('.json')) {
      setError('Only .zip and .json exports accepted')
      setTimeout(() => setError(null), 4000)
      return
    }
    setUploading(true)
    setError(null)
    try {
      const isNativeCollector = file.name.toLowerCase().startsWith('adbygod-') && file.name.endsWith('.zip')
      const r = isNativeCollector
        ? await importApi.collectorZip(file)
        : await importApi.bloodhoundAuto(file)
      startImport({ jobId: r.job_id, streamToken: r.stream_token, filename: file.name })
    } catch (err: unknown) {
      setError(getApiErrorMessage(err, 'Upload failed'))
      setTimeout(() => setError(null), 5000)
    } finally {
      setUploading(false)
    }
  }

  const zoneColor = error ? '#f87171' : dragging ? '#818cf8' : activeJob ? '#22d3ee' : '#6366f1'
  const zoneRgb   = error ? '248,113,113' : dragging ? '129,140,248' : activeJob ? '34,211,238' : '99,102,241'

  return (
    <div className="rounded-xl p-[1px] transition-all"
      style={{
        background: `linear-gradient(135deg, rgba(${zoneRgb},${dragging ? 0.8 : 0.35}) 0%, rgba(255,255,255,0.03) 50%, rgba(255,255,255,0.01) 100%)`,
        boxShadow: dragging ? `0 0 20px rgba(${zoneRgb},0.2)` : 'none',
      }}>
    <div
      className="flex items-center gap-4 rounded-[11px] border-0 px-4 py-3 transition-all"
      style={{
        background: dragging ? `rgba(${zoneRgb},0.06)` : '#050505',
        borderStyle: 'dashed',
      }}
      onDragOver={e => { e.preventDefault(); setDragging(true) }}
      onDragLeave={() => setDragging(false)}
      onDrop={e => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f) }}
    >
      <input ref={inputRef} type="file" accept=".zip,.json" className="sr-only"
        onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); e.target.value = '' }} />

      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl"
        style={{ background: `rgba(${zoneRgb},0.12)`, border: `1px solid rgba(${zoneRgb},0.3)` }}>
        {uploading ? <Loader2 className="h-4 w-4 animate-spin" style={{ color: zoneColor }} />
          : activeJob ? <Activity className="h-4 w-4 animate-pulse" style={{ color: zoneColor }} />
          : <Upload className="h-4 w-4" style={{ color: zoneColor, filter: `drop-shadow(0 0 5px ${zoneColor})` }} />}
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-xs font-semibold text-zinc-300">
          {uploading ? 'Uploading…' : activeJob ? 'Import in progress' : 'Drop BloodHound or AdByGod ZIP'}
        </div>
        <div className="mt-0.5 text-[10px] text-zinc-500">
          {uploading ? 'Processing file' : activeJob ? 'See progress bar below' : '.zip or .json accepted'}
        </div>
        {error && <p className="mt-0.5 text-[10px] text-red-400">{error}</p>}
      </div>
      {!uploading && !activeJob && (
        <button onClick={() => inputRef.current?.click()}
          className="shrink-0 rounded-lg border px-3 py-1.5 text-[10px] font-semibold transition hover:brightness-110"
          style={{ borderColor: `rgba(${zoneRgb},0.4)`, background: `rgba(${zoneRgb},0.08)`, color: zoneColor }}>
          Browse
        </button>
      )}
    </div>
    </div>
  )
}

const SEV_LABEL: Record<string, string> = { CRITICAL: 'Critical', HIGH: 'High', MEDIUM: 'Medium', LOW: 'Low' }

function AssessmentDetailDrawer({ assessmentId, onClose }: { assessmentId: string; onClose: () => void }) {
  const { data: dash, isLoading } = useQuery({
    queryKey: ['assessment-dashboard', assessmentId],
    queryFn: () => assessmentApi.dashboard(assessmentId),
    staleTime: 60_000,
  })

  const domainInfo = (dash?.domain_info ?? {}) as Record<string, number | string>
  const moduleBreakdown = dash?.module_breakdown ?? {}
  const topFindings = dash?.top_findings ?? []
  const exposure = dash?.exposure
  const assessment = dash?.assessment
  const totalModuleFindings = Object.values(moduleBreakdown).reduce((s, v) => s + v, 0)

  const domainStats = [
    { icon: Users,    label: 'Users',         value: domainInfo.total_users,    color: '#6366f1' },
    { icon: Server,   label: 'Computers',     value: domainInfo.total_computers, color: '#06b6d4' },
    { icon: Award,    label: 'Tier-0 Assets', value: domainInfo.tier0_exposure, color: '#ef4444' },
    { icon: Zap,      label: 'Kerberoastable',value: domainInfo.kerberoastable,  color: '#f97316' },
    { icon: Shield,   label: 'ESC1 Templates',value: domainInfo.esc1_templates,  color: '#a78bfa' },
  ]

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex justify-end"
      style={{ background: 'rgba(0,0,0,0.65)', backdropFilter: 'blur(4px)' }}
      onClick={onClose}
    >
      <motion.div
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', damping: 32, stiffness: 320 }}
        className="relative flex h-full w-[520px] max-w-full flex-col overflow-hidden bg-[#0a0a0a]"
        style={{ borderLeft: '1px solid rgba(255,255,255,0.08)' }}
        onClick={(e: MouseEvent) => e.stopPropagation()}
      >

        {/* Header */}
        <div className="flex items-center justify-between gap-4 border-b border-white/6 px-6 py-4">
          <div className="min-w-0">
            {assessment && <StatusPill status={assessment.status} />}
            <h2 className="mt-1.5 truncate text-lg font-bold text-white">{assessment?.name ?? '…'}</h2>
            <div className="mt-0.5 flex items-center gap-2 text-xs text-zinc-500">
              <Shield className="h-3 w-3 text-zinc-600" />
              {assessment?.domain}
              {assessment?.dc_ip && (
                <span className="font-mono text-zinc-400 border border-white/8 bg-white/4 rounded px-1.5 py-0.5">
                  {assessment.dc_ip}
                </span>
              )}
            </div>
          </div>
          <button onClick={onClose}
            className="flex-shrink-0 rounded-xl border border-white/10 p-2 text-zinc-500 transition hover:border-white/20 hover:text-zinc-300">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {isLoading ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="h-6 w-6 animate-spin text-zinc-600" />
            </div>
          ) : (
            <>
              {/* Exposure score + severity */}
              {exposure && (
                <div className="rounded-2xl border border-white/6 p-4"
                  style={{ background: 'rgba(255,255,255,0.025)' }}>
                  <div className="flex items-center justify-between gap-4 mb-3">
                    <div>
                      <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-600">Exposure Score</div>
                      <div className="mt-1 text-4xl font-black tabular-nums"
                        style={{ color: exposure.exposure_score >= 7 ? '#ef4444' : exposure.exposure_score >= 4 ? '#f97316' : '#22c55e' }}>
                        {exposure.exposure_score.toFixed(1)}
                      </div>
                    </div>
                    <div className="text-right text-xs text-zinc-500 space-y-1">
                      <div><span className="text-white font-semibold">{exposure.total_findings}</span> total findings</div>
                      <div><span className="text-emerald-400 font-semibold">{exposure.resolved_findings}</span> resolved</div>
                      <div><span className="text-amber-400 font-semibold">{exposure.new_findings}</span> new</div>
                    </div>
                  </div>
                  <div className="flex h-2 w-full overflow-hidden rounded-full bg-white/5">
                    {SEV_ORDER.map(s => {
                      const cnt = exposure.severity_counts[s] ?? 0
                      const pct = exposure.total_findings > 0 ? (cnt / exposure.total_findings) * 100 : 0
                      return pct > 0 ? (
                        <div key={s} style={{ width: `${pct}%`, background: SEV_COLORS[s] }} title={`${cnt} ${s}`} />
                      ) : null
                    })}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-3">
                    {SEV_ORDER.map(s => {
                      const cnt = exposure.severity_counts[s] ?? 0
                      return cnt > 0 ? (
                        <span key={s} className="flex items-center gap-1 text-[10px]" style={{ color: SEV_COLORS[s] }}>
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLORS[s] }} />
                          {cnt} {SEV_LABEL[s]}
                        </span>
                      ) : null
                    })}
                  </div>
                </div>
              )}

              {/* Domain intel */}
              <div>
                <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-600">Domain Intel</div>
                <div className="grid grid-cols-5 gap-2">
                  {domainStats.map(stat => (
                    <div key={stat.label} className="rounded-xl p-2.5 text-center"
                      style={{ background: `${stat.color}08`, border: `1px solid ${stat.color}20` }}>
                      <stat.icon className="h-3.5 w-3.5 mx-auto mb-1.5" style={{ color: stat.color }} />
                      <div className="text-base font-bold tabular-nums" style={{ color: stat.color }}>
                        {typeof stat.value === 'number' ? fmtNumber(stat.value) : stat.value ?? '—'}
                      </div>
                      <div className="mt-0.5 text-[8px] uppercase tracking-wider text-zinc-600 leading-tight">{stat.label}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Module breakdown */}
              {Object.keys(moduleBreakdown).length > 0 && (
                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <div className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-600">Module Breakdown</div>
                    <span className="text-[10px] text-zinc-600">{totalModuleFindings} findings</span>
                  </div>
                  <div className="space-y-2">
                    {Object.entries(moduleBreakdown)
                      .sort(([, a], [, b]) => b - a)
                      .slice(0, 8)
                      .map(([mod, count]) => {
                        const pct = totalModuleFindings > 0 ? (count / totalModuleFindings) * 100 : 0
                        const meta = MODULE_META[mod]
                        const accent = meta?.accent ?? '#6366f1'
                        return (
                          <div key={mod}>
                            <div className="flex items-center justify-between mb-1 text-[10px]">
                              <span className="text-zinc-400">{mod.split('.').pop()?.replace(/-/g, ' ') ?? mod}</span>
                              <span className="tabular-nums font-semibold" style={{ color: accent }}>{count}</span>
                            </div>
                            <div className="h-1 w-full overflow-hidden rounded-full bg-white/5">
                              <div className="h-full rounded-full transition-all duration-700"
                                style={{ width: `${pct}%`, background: accent, boxShadow: `0 0 8px ${accent}60` }} />
                            </div>
                          </div>
                        )
                      })}
                  </div>
                </div>
              )}

              {/* Top findings */}
              {topFindings.length > 0 && (
                <div>
                  <div className="mb-2 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-600">Top Findings</div>
                  <div className="space-y-1.5">
                    {topFindings.slice(0, 8).map((f, i) => (
                      <div key={f.id ?? i}
                        className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-xs transition hover:bg-white/4"
                        style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)' }}>
                        <span className="h-1.5 w-1.5 flex-shrink-0 rounded-full" style={{ background: SEV_COLORS[f.severity] ?? '#52525b', boxShadow: `0 0 6px ${SEV_COLORS[f.severity]}80` }} />
                        <span className="flex-1 truncate text-zinc-300">{f.title}</span>
                        <span className="flex-shrink-0 text-[9px] font-bold" style={{ color: SEV_COLORS[f.severity] ?? '#52525b' }}>{f.severity}</span>
                        {f.affected_count > 0 && (
                          <span className="flex-shrink-0 text-[9px] text-zinc-600">{f.affected_count} affected</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer actions */}
        <div className="border-t border-white/6 p-4 flex items-center gap-2">
          <Link href={`/findings?assessment_id=${assessmentId}`}
            className="flex flex-1 items-center justify-center gap-1.5 rounded-xl py-2.5 text-xs font-semibold transition hover:brightness-110"
            style={{ background: 'rgba(99,102,241,0.15)', border: '1px solid rgba(99,102,241,0.3)', color: '#a5b4fc' }}>
            <Shield className="h-3.5 w-3.5" /> Findings
          </Link>
          <Link href={`/graph?assessment_id=${assessmentId}`}
            className="flex flex-1 items-center justify-center gap-1.5 rounded-xl py-2.5 text-xs font-semibold transition hover:brightness-110"
            style={{ background: 'rgba(236,72,153,0.1)', border: '1px solid rgba(236,72,153,0.25)', color: '#f9a8d4' }}>
            <Target className="h-3.5 w-3.5" /> Attack Graph
          </Link>
          <Link href={`/reports?assessment_id=${assessmentId}`}
            className="flex items-center justify-center gap-1.5 rounded-xl px-4 py-2.5 text-xs font-semibold transition hover:bg-white/8"
            style={{ border: '1px solid rgba(255,255,255,0.07)', color: '#71717a' }}>
            <FileText className="h-3.5 w-3.5" /> Report
          </Link>
        </div>
      </motion.div>
    </motion.div>
  )
}

export function AssessmentsView() {
  const [view, setView] = useState<'assessments' | 'commands'>('assessments')
  const [showNewModal, setShowNewModal] = useState(false)
  const [commandTarget, setCommandTarget] = useState<Partial<CommandTargetConfig> | undefined>(undefined)
  const [commandLinuxOnly, setCommandLinuxOnly] = useState(true)
  const [obfuscationEnabled, setObfuscationEnabled] = useState(false)
  const [obfuscationTechnique, setObfuscationTechnique] = useState<TechniqueId>('auto')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<(typeof STATUS_FILTERS)[number]>('ALL')
  const [sortKey, setSortKey] = useState<SortKey>('newest')
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(null)

  const { data: assessments, isLoading, isError, error } = useQuery({
    queryKey: assessmentKeys.list(100),
    queryFn: () => assessmentApi.list({ limit: 100 }),
    staleTime: 30_000,
    refetchInterval: (query) => {
      const data = query.state.data as Assessment[] | undefined
      return data?.some(a => a.status === 'RUNNING') ? 5000 : false
    },
  })

  const errDetail = (
    typeof error === 'object' && error !== null && 'response' in error &&
    typeof (error as { response?: { data?: { detail?: unknown } } }).response?.data?.detail === 'string'
  ) ? (error as { response?: { data?: { detail?: string } } }).response?.data?.detail : null

  const filtered = useMemo(() => {
    const base = (assessments ?? []).filter(a => {
      const matchStatus = statusFilter === 'ALL' || a.status === statusFilter
      const q = search.trim().toLowerCase()
      const matchSearch = !q || [a.name, a.domain, a.dc_ip, a.collection_mode].filter(Boolean).some(v => String(v).toLowerCase().includes(q))
      return matchStatus && matchSearch
    })
    return [...base].sort((a, b) => {
      switch (sortKey) {
        case 'oldest':   return (safeDateMs(a.created_at) ?? 0) - (safeDateMs(b.created_at) ?? 0)
        case 'score':    return (b.exposure_score ?? 0) - (a.exposure_score ?? 0)
        case 'findings': return getSeverityCounts(b).total - getSeverityCounts(a).total
        default:         return (safeDateMs(b.created_at) ?? 0) - (safeDateMs(a.created_at) ?? 0)
      }
    })
  }, [assessments, search, statusFilter, sortKey])

  const completed = (assessments ?? []).filter(a => a.status === 'COMPLETED')
  const running = (assessments ?? []).filter(a => a.status === 'RUNNING').length
  const failed = (assessments ?? []).filter(a => a.status === 'FAILED').length
  const avgExposure = completed.length
    ? Math.round(completed.reduce((s, a) => s + (a.exposure_score ?? 0), 0) / completed.length)
    : 0
  const totalFindings = completed.reduce((s, a) => s + getSeverityCounts(a).total, 0)
  const criticalCount = completed.reduce((s, a) => s + getSeverityCounts(a).counts.CRITICAL, 0)

  return (
    <div className="relative min-h-full">
      {/* Header */}
      <div className="sticky top-0 z-20 border-b border-white/[0.07] bg-black">
        <div className="flex flex-wrap items-center gap-3 px-6 py-3">
          <div className="flex items-center gap-2.5">
            <Shield className="h-4 w-4" style={{ color: '#818cf8', filter: 'drop-shadow(0 0 6px #818cf8)' }} />
            <span className="text-[11px] font-semibold uppercase tracking-[0.18em]"
              style={{ color: 'rgba(129,140,248,0.8)' }}>Assessments</span>
          </div>

          {/* Tab toggle */}
          <div className="flex border border-white/[0.07] bg-black">
            {[
              { id: 'assessments', icon: Activity, label: 'Assessments' },
              { id: 'commands',    icon: Terminal, label: 'AD Commands' },
            ].map(tab => (
              <button key={tab.id} onClick={() => setView(tab.id as typeof view)}
                className={cn(
                  'flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold transition-all',
                  view === tab.id
                    ? 'border-r border-white/[0.07] bg-indigo-500/10 text-indigo-300 last:border-r-0'
                    : 'border-r border-white/[0.07] text-zinc-600 hover:text-zinc-300 last:border-r-0'
                )}>
                <tab.icon className="h-3.5 w-3.5" /> {tab.label}
              </button>
            ))}
          </div>

          {view === 'assessments' && (
            <>
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
                <input value={search} onChange={e => setSearch(e.target.value)}
                  placeholder="Search assessments…"
                  className="w-full border border-white/[0.07] bg-black py-2 pl-9 pr-4 text-xs text-white outline-none placeholder:text-zinc-600 focus:border-white/15 sm:w-56" />
              </div>
              <button onClick={() => setShowNewModal(true)}
                className="ml-auto flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-semibold transition hover:brightness-110"
                style={{
                  background: 'rgba(99,102,241,0.15)',
                  border: '1px solid rgba(99,102,241,0.45)',
                  color: '#a5b4fc',
                  boxShadow: '0 0 16px rgba(99,102,241,0.25)',
                }}>
                <Plus className="h-3.5 w-3.5" /> New Assessment
              </button>
            </>
          )}
        </div>
      </div>

      {/* Commands view */}
      {view === 'commands' && (
        <div className="px-6 py-4" style={{ height: 'calc(100vh - 56px)' }}>
          <ADCommandsPanel
            initialTarget={commandTarget}
            initialLinuxOnly={commandLinuxOnly}
            obfuscationEnabled={obfuscationEnabled}
            obfuscationTechnique={obfuscationTechnique}
            onObfuscationChange={setObfuscationEnabled}
            onTechniqueChange={setObfuscationTechnique}
          />
        </div>
      )}

      {/* Assessments view */}
      {view === 'assessments' && (
        <div className="space-y-4 px-6 py-4">

          {/* KPI row */}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {[
              { label: 'Total Assessments', value: fmtNumber(assessments?.length ?? 0), sub: `${completed.length} completed`, color: '#818cf8', rgb: '129,140,248', icon: Database },
              { label: 'Running Now',        value: running,                              sub: `${failed} failed`,            color: '#22d3ee', rgb: '34,211,238',  icon: Activity },
              { label: 'Avg Exposure',       value: avgExposure,                          sub: 'across completed',            color: '#f97316', rgb: '249,115,22',  icon: Target },
              { label: 'Critical Findings',  value: fmtNumber(criticalCount),             sub: `${fmtNumber(totalFindings)} total`, color: '#ff4d6d', rgb: '255,77,109', icon: Zap },
            ].map((kpi) => (
              <div key={kpi.label} className="rounded-2xl p-[1px]"
                style={{ background: `linear-gradient(135deg, ${kpi.color} 0%, rgba(255,255,255,0.04) 25%, rgba(255,255,255,0.02) 100%)` }}>
                <div className="relative flex flex-col gap-3 overflow-hidden rounded-[15px] bg-black p-4">
                  {/* top glow line */}
                  <div className="pointer-events-none absolute inset-x-0 top-0 h-px"
                    style={{ background: `linear-gradient(90deg, transparent, rgba(${kpi.rgb},0.6), transparent)` }} />
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-semibold uppercase tracking-[0.16em] text-zinc-500">{kpi.label}</span>
                    <div className="flex h-7 w-7 items-center justify-center rounded-lg"
                      style={{ background: `rgba(${kpi.rgb},0.12)`, border: `1px solid rgba(${kpi.rgb},0.3)` }}>
                      <kpi.icon className="h-3.5 w-3.5"
                        style={{ color: kpi.color, filter: `drop-shadow(0 0 5px ${kpi.color})` }} />
                    </div>
                  </div>
                  <div className="font-mono text-3xl font-bold tabular-nums"
                    style={{ color: kpi.color, textShadow: `0 0 24px rgba(${kpi.rgb},0.5)` }}>
                    {kpi.value}
                  </div>
                  <div className="text-[10px] text-zinc-500">{kpi.sub}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Import zone */}
          <ImportDropZone />

          {/* Filters + Sort */}
          <div className="flex flex-wrap items-center gap-2 border-b pb-3"
            style={{ borderColor: 'rgba(99,102,241,0.15)' }}>
            <Filter className="h-3 w-3 text-indigo-500/60" />
            {STATUS_FILTERS.map(s => {
              const active = statusFilter === s
              const sc = s === 'ALL' ? '#818cf8' : STATUS_CONFIG[s]?.color ?? '#818cf8'
              return (
                <button key={s} onClick={() => setStatusFilter(s)}
                  className="rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] transition-all"
                  style={{
                    borderColor: active ? `${sc}50` : 'rgba(255,255,255,0.07)',
                    background:  active ? `${sc}14` : 'transparent',
                    color:       active ? sc : '#52525b',
                    boxShadow:   active ? `0 0 10px ${sc}25` : 'none',
                  }}>
                  {s === 'ALL' ? 'All' : s.toLowerCase()}
                </button>
              )
            })}
            <div className="mx-1 h-3 w-px bg-white/10" />
            <ArrowUpDown className="h-3 w-3 text-zinc-600" />
            <select
              value={sortKey}
              onChange={e => setSortKey(e.target.value as SortKey)}
              className="rounded-lg border border-white/[0.07] bg-black px-2.5 py-1.5 text-[10px] text-zinc-400 outline-none transition hover:border-white/15"
              style={{ appearance: 'none' }}>
              {SORT_OPTIONS.map(o => (
                <option key={o.id} value={o.id}>{o.label}</option>
              ))}
            </select>
            <div className="ml-auto font-mono text-xs text-zinc-600">
              <span className="text-indigo-400">{filtered.length}</span> / {assessments?.length ?? 0}
            </div>
          </div>

          {/* Loading */}
          {isLoading && (
            <div className="flex min-h-[240px] items-center justify-center border border-white/[0.07]">
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <Loader2 className="h-4 w-4 animate-spin text-indigo-400" /> Loading assessments…
              </div>
            </div>
          )}

          {/* Error */}
          {isError && (
            <div className="flex items-start gap-3 border border-red-500/18 bg-red-500/5 px-4 py-3 text-sm">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-400" />
              <div>
                <div className="text-xs font-semibold text-red-300">Could not load assessments</div>
                <div className="mt-0.5 text-[10px] text-red-300/50">{errDetail ?? 'Ensure the API is reachable.'}</div>
              </div>
            </div>
          )}

          {/* Empty */}
          {!isLoading && !isError && filtered.length === 0 && (
            <div className="flex min-h-[240px] flex-col items-center justify-center gap-4 border border-white/[0.07] bg-[#0a0a0a] p-10 text-center">
              <Search className="h-8 w-8 text-zinc-700" />
              <div>
                <div className="text-sm font-semibold text-zinc-400">
                  {assessments?.length ? 'Nothing matches' : 'No assessments yet'}
                </div>
                <p className="mt-1 text-xs text-zinc-600">
                  {assessments?.length ? 'Try clearing filters.' : 'Launch your first assessment to begin.'}
                </p>
              </div>
              <div className="flex gap-2">
                {assessments?.length ? (
                  <button onClick={() => { setSearch(''); setStatusFilter('ALL') }}
                    className="border border-white/[0.07] px-4 py-2 text-xs text-zinc-500 transition hover:text-zinc-300">
                    Reset
                  </button>
                ) : null}
                <button onClick={() => setShowNewModal(true)}
                  className="flex items-center gap-1.5 border border-indigo-500/30 bg-indigo-500/10 px-4 py-2 text-xs font-semibold text-indigo-300 transition hover:border-indigo-500/50">
                  <Plus className="h-3.5 w-3.5" /> New Assessment
                </button>
              </div>
            </div>
          )}

          {/* Cards grid */}
          {!isLoading && !isError && filtered.length > 0 && (
            <motion.div layout className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              <AnimatePresence>
                {filtered.map((a) => (
                  <AssessmentCard key={a.id} assessment={a} onSelect={() => setSelectedAssessmentId(a.id)} />
                ))}
              </AnimatePresence>
            </motion.div>
          )}
        </div>
      )}

      <AnimatePresence>
        {showNewModal && (
          <NewAssessmentModal
            onClose={() => setShowNewModal(false)}
            obfuscationEnabled={obfuscationEnabled}
            obfuscationTechnique={obfuscationTechnique}
            onObfuscationChange={setObfuscationEnabled}
            onTechniqueChange={setObfuscationTechnique}
            onCommandPlan={(target) => {
              setCommandTarget(target)
              setCommandLinuxOnly(false)
              setView('commands')
            }}
          />
        )}
        {selectedAssessmentId && (
          <AssessmentDetailDrawer
            assessmentId={selectedAssessmentId}
            onClose={() => setSelectedAssessmentId(null)}
          />
        )}
      </AnimatePresence>
    </div>
  )
}
