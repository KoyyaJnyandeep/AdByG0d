'use client'

import { copyText } from '@/lib/clipboard'
import React, { useState, useRef, useEffect } from 'react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Shield, AlertTriangle, ChevronRight, ExternalLink,
  GitBranch, FileText, CheckCircle2, Clock, User, Zap,
  ChevronDown, ChevronUp, Copy, Check, BookOpen, Wrench,
  Activity, Target, Eye, X,
} from 'lucide-react'
import { findingsApi } from '@/lib/api'
import { safeExternalUrl } from '@/lib/safeExternalUrl'
import { cn, statusColor, driftBadge, fmtDate, fmtDateTime, fmtConfidence, timeAgo } from '@/lib/utils'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { ScoreGauge } from '@/components/ui/ScoreGauge'
import type { Finding, EvidenceRecord, PathStep } from '@/lib/types'

type AffectedDisplay = {
  label: string
  detail?: string
}

function formatAffectedObject(obj: unknown): AffectedDisplay {
  if (obj == null) return { label: 'Unknown object' }
  if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
    return { label: String(obj) }
  }
  if (Array.isArray(obj)) {
    return { label: obj.map(item => formatAffectedObject(item).label).join(', ') }
  }
  if (typeof obj !== 'object') return { label: String(obj) }

  const record = obj as Record<string, unknown>
  const label = [
    record.template_name,
    record.ca_name,
    record.url,
    record.source_principal,
    record.trustee,
    record.right,
    record.name,
    record.id,
  ].find(value => typeof value === 'string' && value.trim()) as string | undefined

  const detailParts = [
    record.template_dn,
    record.dn,
    record.status_code != null ? `HTTP ${String(record.status_code)}` : undefined,
    Array.isArray(record.ekus) && record.ekus.length ? `EKU ${record.ekus.join(', ')}` : undefined,
    Array.isArray(record.enrollment_principals) && record.enrollment_principals.length
      ? `${record.enrollment_principals.length} enroll right(s)`
      : undefined,
    Array.isArray(record.write_rights) && record.write_rights.length
      ? `${record.write_rights.length} write right(s)`
      : undefined,
    record.collection_method,
  ].filter((value): value is string => typeof value === 'string' && value.length > 0)

  return {
    label: label ?? JSON.stringify(record),
    detail: detailParts.join(' · ') || undefined,
  }
}

function FindingDetailSkeleton() {
  return (
    <div className="flex-1 overflow-y-auto animate-pulse">
      {/* Header skeleton */}
      <div className="h-[52px] border-b border-border px-7 flex items-center gap-3">
        <div className="h-6 w-20 bg-surface-overlay rounded-md" />
        <div className="h-4 w-48 bg-surface-overlay rounded" />
        <div className="ml-auto flex gap-2">
          <div className="h-6 w-16 bg-surface-overlay rounded-full" />
          <div className="h-6 w-14 bg-surface-overlay rounded" />
        </div>
      </div>
      {/* Hero skeleton */}
      <div className="px-7 py-8 border-b border-border">
        <div className="flex items-start gap-5">
          <div className="flex-1">
            <div className="h-4 w-32 bg-surface-overlay rounded mb-4" />
            <div className="h-8 w-3/4 bg-surface-overlay rounded-xl mb-3" />
            <div className="h-8 w-1/2 bg-surface-overlay rounded-xl mb-4" />
            <div className="flex gap-4">
              {[...Array(4)].map((_, i) => <div key={i} className="h-4 w-24 bg-surface-overlay rounded" />)}
            </div>
          </div>
          <div className="w-24 h-24 bg-surface-overlay rounded-full" />
        </div>
        <div className="grid grid-cols-4 gap-px mt-5">
          {[...Array(4)].map((_, i) => <div key={i} className="h-20 bg-surface-overlay" />)}
        </div>
      </div>
      {/* Tabs skeleton */}
      <div className="h-12 border-b border-border px-7 flex items-center gap-1">
        {[...Array(4)].map((_, i) => <div key={i} className="h-5 w-20 bg-surface-overlay rounded mx-3" />)}
      </div>
      {/* Body skeleton */}
      <div className="px-7 py-7 space-y-5 max-w-[860px]">
        <div className="h-4 w-24 bg-surface-overlay rounded" />
        <div className="h-16 bg-surface-overlay rounded-xl" />
        <div className="h-4 w-24 bg-surface-overlay rounded" />
        <div className="h-24 bg-surface-overlay rounded-xl" />
        <div className="h-4 w-24 bg-surface-overlay rounded" />
        <div className="h-32 bg-surface-overlay rounded-xl" />
      </div>
    </div>
  )
}

function scoreColor(s: number): string {
  return s >= 85 ? '#ef4444' : s >= 65 ? '#f97316' : '#eab308'
}

function ScoreRing({ score }: { score?: number }) {
  if (score === undefined || score === null) return null
  return (
    <div className="flex-shrink-0">
      <ScoreGauge score={score} size="md" showLabel />
    </div>
  )
}

function SectionHeading({ icon, children }: { icon: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2.5 text-[10px] font-bold tracking-[0.12em] uppercase text-brand mb-3">
      <span className="text-xs" aria-hidden="true">{icon}</span>
      {children}
      <div className="flex-1 h-px" style={{
        background: 'linear-gradient(90deg, rgba(99,102,241,0.25) 0%, transparent 100%)',
      }} />
    </div>
  )
}

function CausalChain({ steps }: { steps: string[] }) {
  if (!steps?.length) return null
  return (
    <div className="relative pl-7">
      {/* Gradient vertical line */}
      <div className="absolute left-[9px] top-3 bottom-3 w-0.5" style={{
        background: 'linear-gradient(180deg, rgba(251,191,36,0.5) 0%, rgba(99,102,241,0.5) 50%, rgba(239,68,68,0.5) 100%)',
      }} />
      <div className="space-y-3">
        {steps.map((step, i) => {
          const isFirst = i === 0
          const isLast = i === steps.length - 1
          const nodeStyle = isFirst
            ? { background: 'rgba(251,191,36,0.15)', border: '1.5px solid rgba(251,191,36,0.5)', color: '#fbbf24' }
            : isLast
            ? { background: 'rgba(239,68,68,0.15)', border: '1.5px solid rgba(239,68,68,0.5)', color: '#f87171', boxShadow: '0 0 10px rgba(239,68,68,0.15)' }
            : { background: 'rgba(99,102,241,0.15)', border: '1.5px solid rgba(99,102,241,0.5)', color: '#818cf8' }
          return (
            <div key={i} className="relative flex items-start gap-3">
              <div className="absolute -left-7 top-0 w-[18px] h-[18px] rounded-full flex items-center justify-center text-[9px] font-black z-10 flex-shrink-0"
                style={nodeStyle}>
                {i + 1}
              </div>
              <p className={cn(
                'text-xs leading-relaxed pt-0.5',
                isLast ? 'text-critical font-medium' : 'text-text-secondary',
              )}>
                {step}
              </p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function AttackPath({ steps }: { steps: PathStep[] }) {
  if (!steps?.length) return (
    <div className="text-center py-8 text-text-tertiary text-xs">
      No attack path computed for this finding.
    </div>
  )
  return (
    <div className="flex items-center gap-1 flex-wrap py-1">
      {steps.map((step, i) => {
        const isDomainOrDC = step.entity_type === 'DOMAIN' || step.entity_type === 'DC'
        return (
          <div key={i} className="flex items-center gap-1">
            <div className="flex flex-col items-center gap-1">
              <div
                className="px-3 py-1.5 rounded-lg text-xs font-semibold font-mono max-w-[180px] truncate"
                style={isDomainOrDC ? {
                  background: 'rgba(239,68,68,0.1)',
                  border: '1px solid rgba(239,68,68,0.35)',
                  color: '#f87171',
                  boxShadow: '0 0 14px rgba(239,68,68,0.08)',
                } : {
                  background: 'rgba(251,191,36,0.08)',
                  border: '1px solid rgba(251,191,36,0.3)',
                  color: '#fbbf24',
                }}>
                {step.entity_label}
              </div>
              <span className="text-[9px] text-text-tertiary uppercase tracking-wide">{step.entity_type}</span>
            </div>
            {i < steps.length - 1 && (
              <div className="flex flex-col items-center gap-0.5 px-1 flex-shrink-0">
                <span className="text-text-tertiary text-xs">──▶</span>
                {step.edge_type && (
                  <span className="text-[8px] text-brand font-mono tracking-wide">
                    {step.edge_type.replace(/_/g, ' ')}
                  </span>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

function EvidencePanel({ evidence }: { evidence: EvidenceRecord[] }) {
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const copyRaw = (id: string, data: unknown) => {
    copyText(JSON.stringify(data, null, 2))
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  if (!evidence?.length) {
    return (
      <div className="text-center py-10 text-text-tertiary text-xs">
        No evidence records linked to this finding.
      </div>
    )
  }

  const badgeStyle = (ev: EvidenceRecord) => {
    if (ev.origin === 'SIMULATED')
      return { background: 'rgba(217,70,239,0.1)', border: '1px solid rgba(217,70,239,0.25)', color: '#e879f9' }
    if (ev.source_type === 'ldap')
      return { background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.25)', color: '#60a5fa' }
    if (ev.source_type === 'kerberos')
      return { background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.25)', color: '#fdba74' }
    if (ev.source_type === 'smb')
      return { background: 'rgba(234,179,8,0.1)', border: '1px solid rgba(234,179,8,0.25)', color: '#fde047' }
    return { background: 'rgba(71,85,105,0.15)', border: '1px solid rgba(71,85,105,0.3)', color: '#94a3b8' }
  }

  return (
    <div className="space-y-2">
      {evidence.map(ev => (
        <div key={ev.id} className="rounded-xl overflow-hidden transition-colors"
          style={{ background: 'rgba(13,16,24,0.8)', border: `1px solid ${expandedId === ev.id ? 'rgba(99,102,241,0.3)' : 'rgba(26,32,48,1)'}` }}>
          <button
            className="w-full flex items-center gap-3 p-4 hover:bg-white/[0.02] transition-colors text-left"
            onClick={() => setExpandedId(expandedId === ev.id ? null : ev.id)}
            aria-expanded={expandedId === ev.id}
          >
            <span className="px-2 py-0.5 rounded text-[9px] font-bold font-mono uppercase tracking-wide flex-shrink-0"
              style={badgeStyle(ev)}>
              {ev.origin.toLowerCase()} · {ev.source_type}
            </span>
            <div className="flex-1 min-w-0">
              <div className="text-xs font-semibold text-text-primary truncate">
                {ev.collection_method ?? 'Unknown method'}
              </div>
              <div className="text-[10px] text-text-tertiary mt-0.5">
                {ev.source_host && `${ev.source_host} · `}
                {fmtDateTime(ev.collected_at)}
                {' · '}Confidence: {fmtConfidence(ev.confidence)}
              </div>
            </div>
            {ev.is_corroborated && (
              <span className="text-[9px] font-semibold px-2 py-0.5 rounded flex-shrink-0"
                style={{ background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', color: '#4ade80' }}>
                Corroborated
              </span>
            )}
            {expandedId === ev.id
              ? <ChevronUp className="w-4 h-4 text-text-tertiary flex-shrink-0" />
              : <ChevronDown className="w-4 h-4 text-text-tertiary flex-shrink-0" />}
          </button>
          {expandedId === ev.id && (
            <div className="border-t border-border bg-background">
              <div className="flex items-center justify-between px-4 py-2 border-b border-border">
                <span className="text-[9px] text-text-tertiary font-bold uppercase tracking-widest">
                  Raw Evidence Data
                </span>
                <button
                  onClick={() => copyRaw(ev.id, ev.raw_data)}
                  className="flex items-center gap-1.5 px-2 py-1 rounded-lg hover:bg-surface-overlay transition-colors text-text-tertiary hover:text-text-primary text-xs"
                >
                  {copiedId === ev.id
                    ? <><Check className="w-3 h-3 text-low" /> Copied</>
                    : <><Copy className="w-3 h-3" /> Copy JSON</>}
                </button>
              </div>
              <pre className="p-4 text-xs font-mono text-text-secondary overflow-x-auto leading-relaxed">
                {JSON.stringify(ev.raw_data, null, 2)}
              </pre>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function RemediationSteps({ steps }: { steps: string[] }) {
  const [completed, setCompleted] = useState<Set<number>>(new Set())

  if (!steps?.length) return null

  const toggle = (i: number) => {
    const next = new Set(completed)
    if (next.has(i)) next.delete(i); else next.add(i)
    setCompleted(next)
  }

  const pct = Math.round((completed.size / steps.length) * 100)

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <div className="flex-1 h-0.5 rounded-full overflow-hidden bg-surface-overlay">
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{
              width: `${pct}%`,
              background: 'linear-gradient(90deg, #6366f1 0%, #22c55e 100%)',
            }}
          />
        </div>
        <span className="text-[10px] text-text-tertiary font-mono w-8 text-right">{pct}%</span>
      </div>
      <div className="space-y-2">
        {steps.map((step, i) => (
          <button
            key={i}
            onClick={() => toggle(i)}
            className={cn(
              'w-full flex items-start gap-3 p-3 rounded-xl text-left transition-all duration-150 border',
              completed.has(i)
                ? 'border-low/20'
                : 'border-transparent bg-white/[0.02] hover:border-border',
            )}
            style={completed.has(i) ? { background: 'rgba(34,197,94,0.04)' } : undefined}
          >
            <div className={cn(
              'mt-0.5 w-4 h-4 rounded-full border flex items-center justify-center flex-shrink-0 transition-all',
              completed.has(i)
                ? 'border-low bg-low/15 text-low'
                : 'border-border',
            )}>
              {completed.has(i) && <Check className="w-2.5 h-2.5" />}
            </div>
            <code className={cn(
              'text-xs font-mono leading-relaxed break-all',
              completed.has(i) ? 'text-text-tertiary line-through' : 'text-text-primary',
            )}>
              {step}
            </code>
          </button>
        ))}
      </div>
    </div>
  )
}

function ScoreBar({ label, value, max = 10 }: { label: string; value?: number; max?: number }) {
  if (value === undefined || value === null) return null
  const pct = Math.round((value / max) * 100)
  const barColor = pct >= 80 ? '#ef4444' : pct >= 60 ? '#f97316' : '#eab308'

  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-text-tertiary w-36 flex-shrink-0">{label}</span>
      <div className="flex-1 h-1 rounded-full overflow-hidden bg-surface-overlay">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${pct}%`, background: barColor }}
        />
      </div>
      <span className="text-xs font-mono text-text-secondary w-12 text-right">
        {value.toFixed(1)}{max === 1 ? '' : `/${max}`}
      </span>
    </div>
  )
}

const STATUS_OPTIONS = [
  { value: 'OPEN', label: 'Open', icon: AlertTriangle },
  { value: 'IN_REVIEW', label: 'In Review', icon: Eye },
  { value: 'REMEDIATED', label: 'Remediated', icon: CheckCircle2 },
  { value: 'ACCEPTED', label: 'Risk Accepted', icon: Shield },
  { value: 'FALSE_POSITIVE', label: 'False Positive', icon: X },
] as const

export default function FindingDetailPage() {
  const params = useParams()
  const router = useRouter()
  const queryClient = useQueryClient()
  const findingId = params.id as string

  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'remediation' | 'scoring'>('overview')
  const [showStatusDropdown, setShowStatusDropdown] = useState(false)

  const statusDropdownRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!showStatusDropdown) return
    const handleClick = (e: MouseEvent) => {
      if (statusDropdownRef.current && !statusDropdownRef.current.contains(e.target as Node)) {
        setShowStatusDropdown(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [showStatusDropdown])

  const { data: finding, isLoading, error } = useQuery<Finding>({
    queryKey: ['finding', findingId],
    queryFn: () => findingsApi.get(findingId),
    enabled: !!findingId,
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Partial<Finding> }) =>
      findingsApi.update(id, patch),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', findingId] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  const { data: evidenceRecords, isLoading: evidenceLoading } = useQuery<EvidenceRecord[]>({
    queryKey: ['finding-evidence', findingId],
    queryFn: () => findingsApi.evidence(findingId),
    enabled: !!findingId && activeTab === 'evidence',
    staleTime: 60_000,
  })

  if (isLoading) return <FindingDetailSkeleton />

  if (error || !finding) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-12 h-12 text-text-tertiary mx-auto mb-3" />
          <p className="text-text-primary font-medium mb-1">Finding not found</p>
          <p className="text-text-tertiary text-sm mb-4">
            {error instanceof Error ? error.message : 'Could not load this finding.'}
          </p>
          <button onClick={() => router.back()} className="btn-ghost text-sm">
            Go back
          </button>
        </div>
      </div>
    )
  }

  const drift = driftBadge(finding.drift_status)
  const complexityLabel: Record<string, string> = {
    trivial: 'Trivial fix', low: 'Low effort', medium: 'Medium effort', high: 'Complex fix',
  }

  return (
    <div className="flex-1 overflow-y-auto">
      {/* ── STICKY HEADER ── */}
      <div className="sticky top-0 z-20 border-b border-border px-7 h-[52px] flex items-center gap-2.5"
        style={{ background: 'rgba(7,9,15,0.85)', backdropFilter: 'blur(20px)' }}>
        <button
          onClick={() => router.back()}
          className="flex items-center gap-1.5 text-brand text-xs font-medium px-2.5 py-1 rounded-md border border-border hover:border-brand transition-colors"
          style={{ background: 'rgba(99,102,241,0.06)' }}
        >
          <ArrowLeft className="w-3 h-3" /> Findings
        </button>
        <ChevronRight className="w-3 h-3 text-text-tertiary" />
        <span className="text-text-tertiary text-xs font-mono truncate max-w-xs">
          {finding.finding_type}
        </span>
        <div className="ml-auto flex items-center gap-2">
          <div className="relative" ref={statusDropdownRef}>
            <button
              onClick={() => setShowStatusDropdown(!showStatusDropdown)}
              className={cn('flex items-center gap-1 rounded-full px-3 py-1 text-[10px] font-bold tracking-widest border', statusColor(finding.status))}
            >
              {finding.status.replace('_', ' ')}
              <ChevronDown className="w-3 h-3" />
            </button>
            {showStatusDropdown && (
              <div className="absolute right-0 top-full mt-1 w-44 bg-surface border border-border rounded-xl shadow-lg-dark py-1 z-50">
                {STATUS_OPTIONS.map(({ value, label, icon: Icon }) => (
                  <button
                    key={value}
                    onClick={() => {
                      updateMutation.mutate({ id: finding.id, patch: { status: value as Finding['status'] } })
                      setShowStatusDropdown(false)
                    }}
                    className={cn(
                      'w-full flex items-center gap-2.5 px-3 py-2 text-sm transition-colors',
                      finding.status === value
                        ? 'text-brand bg-brand/10'
                        : 'text-text-secondary hover:text-text-primary hover:bg-surface-overlay',
                    )}
                  >
                    <Icon className="w-3.5 h-3.5" />
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
          <SeverityBadge severity={finding.severity} />
        </div>
      </div>

      {/* ── HERO ── */}
      <div className="relative overflow-hidden border-b border-border"
        style={{
          background: 'linear-gradient(180deg, #0c0818 0%, #0a0d18 40%, #07090f 100%)',
        }}>
        {/* Ambient glow */}
        <div className="absolute inset-0 pointer-events-none" style={{
          background: [
            'radial-gradient(ellipse 60% 100% at 15% 60%, rgba(99,102,241,0.09) 0%, transparent 60%)',
            'radial-gradient(ellipse 50% 80% at 85% 20%, rgba(239,68,68,0.07) 0%, transparent 55%)',
          ].join(','),
        }} />
        {/* Grid scanlines */}
        <div className="absolute inset-0 pointer-events-none" style={{
          backgroundImage: [
            'linear-gradient(rgba(99,102,241,0.018) 1px, transparent 1px)',
            'linear-gradient(90deg, rgba(99,102,241,0.018) 1px, transparent 1px)',
          ].join(','),
          backgroundSize: '32px 32px',
        }} />

        <div className="relative z-10 px-7 pt-8">
          <div className="flex items-start gap-5">
            <div className="flex-1">
              {/* Provenance + module pill */}
              <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-semibold mb-3 tracking-wide"
                style={{ background: 'rgba(124,58,237,0.12)', border: '1px solid rgba(124,58,237,0.3)', color: '#a78bfa' }}>
                ⬟ {finding.origin.charAt(0) + finding.origin.slice(1).toLowerCase()}
                {' · '}{finding.module}
              </div>
              <h1 className="text-2xl font-black text-text-primary leading-tight mb-2"
                style={{ letterSpacing: '-0.02em' }}>
                {finding.title}
              </h1>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-text-tertiary">
                <span>First seen <span className="text-text-secondary font-medium">{fmtDate(finding.first_seen)}</span></span>
                <span className="text-border">·</span>
                <span><span className="text-text-secondary font-medium">{finding.affected_count}</span> affected</span>
                {drift && (
                  <>
                    <span className="text-border">·</span>
                    <span className={cn('px-1.5 py-0.5 rounded text-[9px] font-bold tracking-widest border', drift.class)}>
                      {drift.label.toUpperCase()}
                    </span>
                  </>
                )}
                {finding.fix_complexity && (
                  <>
                    <span className="text-border">·</span>
                    <span>{complexityLabel[finding.fix_complexity]}</span>
                  </>
                )}
              </div>
            </div>
            <ScoreRing score={finding.composite_score} />
          </div>

          {/* ── METRIC STRIP ── */}
          <div className="grid grid-cols-4 mt-5 border-t"
            style={{ borderColor: 'rgba(99,102,241,0.15)', background: 'rgba(0,0,0,0.2)' }}>
            {[
              {
                label: 'Score', icon: <Target className="w-4 h-4" />,
                value: finding.composite_score?.toFixed(1) ?? '—',
                sub: '0–100 risk score',
                valueStyle: { color: finding.composite_score != null ? scoreColor(finding.composite_score) : '#475569' },
                accentColor: '#ef4444',
              },
              {
                label: 'Confidence', icon: <Activity className="w-4 h-4" />,
                value: fmtConfidence(finding.confidence),
                sub: 'Evidence quality',
                valueStyle: { color: '#a78bfa' },
                accentColor: '#6366f1',
              },
              {
                label: 'Affected', icon: <User className="w-4 h-4" />,
                value: String(finding.affected_count),
                sub: 'Entities exposed',
                valueStyle: { color: '#f1f5f9' },
                accentColor: '#64748b',
              },
              {
                label: 'Effort', icon: <Wrench className="w-4 h-4" />,
                value: finding.fix_complexity ? complexityLabel[finding.fix_complexity].split(' ')[0] : '—',
                sub: 'To remediate',
                valueStyle: { color: '#22c55e' },
                accentColor: '#22c55e',
              },
            ].map((m, i) => (
              <div key={m.label} className={cn('px-5 py-3.5 relative', i < 3 && 'border-r border-border')}>
                <div className="absolute top-0 left-0 right-0 h-0.5" style={{ background: m.accentColor, opacity: 0.5 }} />
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[9px] text-text-tertiary uppercase tracking-widest font-semibold">{m.label}</span>
                  <span style={{ color: m.accentColor, opacity: 0.6 }}>{m.icon}</span>
                </div>
                <div className="text-2xl font-black" style={m.valueStyle}>{m.value}</div>
                <div className="text-[9px] text-text-tertiary mt-0.5">{m.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── STICKY TAB BAR ── */}
      <div className="flex items-center px-7 border-b border-border sticky z-30"
        style={{ top: '52px', background: 'rgba(7,9,15,0.7)', backdropFilter: 'blur(12px)' }}>
        {[
          { id: 'overview',     label: 'Overview',     icon: BookOpen },
          { id: 'evidence',     label: 'Evidence',     icon: Eye },
          { id: 'remediation',  label: 'Remediation',  icon: CheckCircle2 },
          { id: 'scoring',      label: 'Scoring',      icon: Zap },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id as typeof activeTab)}
            className={cn(
              'flex items-center gap-2 px-5 py-3.5 text-xs font-semibold border-b-2 transition-all duration-150 -mb-px tracking-wide',
              activeTab === id
                ? 'border-brand text-brand'
                : 'border-transparent text-text-tertiary hover:text-text-secondary',
            )}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      <div className="px-7 py-7 max-w-[860px]">

        {/* Tab: Overview */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Description */}
            <section className="mb-7">
              <SectionHeading icon="◈">Description</SectionHeading>
              <p className="text-sm text-text-secondary leading-relaxed max-w-2xl">
                {finding.description ?? 'No description available.'}
              </p>
            </section>

            {/* Root cause */}
            {finding.root_cause && (
              <section className="mb-7">
                <SectionHeading icon="⚠">Root Cause</SectionHeading>
                <div className="rounded-xl p-4 text-xs leading-relaxed font-mono text-text-secondary"
                  style={{
                    background: 'rgba(251,191,36,0.04)',
                    border: '1px solid rgba(251,191,36,0.12)',
                    borderLeft: '3px solid rgba(251,191,36,0.5)',
                  }}>
                  {finding.root_cause}
                </div>
              </section>
            )}

            {/* Causal chain */}
            {finding.causal_chain?.length > 0 && (
              <section className="mb-7">
                <SectionHeading icon="⟶">Attack Chain</SectionHeading>
                <div className="card rounded-xl p-5">
                  <CausalChain steps={finding.causal_chain} />
                </div>
              </section>
            )}

            {/* Attack path */}
            {finding.attack_path && finding.attack_path.length > 0 && (
              <section className="mb-7">
                <div className="flex items-center justify-between mb-3">
                  <SectionHeading icon="⤳">Attack Path</SectionHeading>
                  <Link
                    href={`/graph?assessment_id=${finding.assessment_id}&finding=${finding.id}`}
                    className="flex items-center gap-1.5 text-xs text-brand hover:text-brand/80 transition-colors ml-auto -mt-1"
                  >
                    <GitBranch className="w-3 h-3" />
                    View in Graph Explorer
                  </Link>
                </div>
                <div className="card rounded-xl p-4 overflow-x-auto">
                  <AttackPath steps={finding.attack_path} />
                </div>
              </section>
            )}

            {/* Affected objects */}
            {finding.affected_objects?.length > 0 && (
              <section className="mb-7">
                <SectionHeading icon="◎">
                  Affected Objects
                  <span className="text-text-tertiary font-normal normal-case tracking-normal ml-1">
                    ({finding.affected_count} total)
                  </span>
                </SectionHeading>
                <div className="flex flex-wrap gap-2">
                  {finding.affected_objects.map((obj, i) => {
                    const affected = formatAffectedObject(obj)
                    return (
                      <span key={i} title={affected.detail}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono transition-colors"
                        style={{
                          background: 'rgba(99,102,241,0.07)',
                          border: '1px solid rgba(99,102,241,0.2)',
                          color: '#a5b4fc',
                        }}>
                        <span className="w-1.5 h-1.5 rounded-full bg-brand flex-shrink-0" />
                        <span className="block max-w-[300px] truncate">{affected.label}</span>
                      </span>
                    )
                  })}
                  {finding.affected_count > finding.affected_objects.length && (
                    <span className="px-3 py-1.5 rounded-lg text-xs text-text-tertiary border border-border">
                      +{finding.affected_count - finding.affected_objects.length} more
                    </span>
                  )}
                </div>
              </section>
            )}

            {/* References */}
            {finding.references?.length > 0 && (
              <section className="mb-7">
                <SectionHeading icon="↗">References</SectionHeading>
                <div className="space-y-2">
                  {finding.references.map((ref, i) => {
                    const safeUrl = safeExternalUrl(ref)
                    if (!safeUrl) {
                      return (
                        <div key={i}
                          className="flex items-center gap-2.5 px-3 py-2 rounded-lg border border-border text-xs text-text-tertiary"
                          style={{ background: 'rgba(13,16,24,0.6)' }}>
                          <FileText className="w-3.5 h-3.5 flex-shrink-0" />
                          <span className="truncate">Unsupported reference hidden</span>
                        </div>
                      )
                    }
                    return (
                      <a key={i} href={safeUrl} target="_blank" rel="noopener noreferrer nofollow"
                        className="flex items-center gap-2.5 px-3 py-2 rounded-lg border border-border text-xs text-info hover:border-info/40 transition-colors group"
                        style={{ background: 'rgba(13,16,24,0.6)' }}>
                        <FileText className="w-3.5 h-3.5 flex-shrink-0" />
                        <span className="truncate">{ref}</span>
                        <ExternalLink className="w-3 h-3 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity ml-auto" />
                      </a>
                    )
                  })}
                </div>
                {((finding.mitre_attack_ids?.length ?? 0) > 0) && (
                  <div className="flex gap-2 mt-3 flex-wrap">
                    {(finding.mitre_attack_ids ?? []).map(t => (
                      <span key={t} className="px-2.5 py-1 rounded-md text-xs font-mono"
                        style={{ background: 'rgba(99,102,241,0.08)', border: '1px solid rgba(99,102,241,0.2)', color: '#818cf8' }}>
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </section>
            )}

            {/* CVEs */}
            {(finding.cve_ids?.length ?? 0) > 0 && (
              <section className="mb-7">
                <SectionHeading icon="⚑">CVE References</SectionHeading>
                <div className="flex gap-2 flex-wrap">
                  {(finding.cve_ids ?? []).map(cve => (
                    <span key={cve} className="px-2.5 py-1 rounded-md text-xs font-mono"
                      style={{ background: 'rgba(249,115,22,0.08)', border: '1px solid rgba(249,115,22,0.2)', color: '#fdba74' }}>
                      {cve}
                    </span>
                  ))}
                </div>
              </section>
            )}
          </div>
        )}

        {/* Tab: Evidence */}
        {activeTab === 'evidence' && (
          <div>
            <p className="text-xs text-text-tertiary mb-5">
              Raw evidence records collected during assessment that support this finding.
            </p>
            {evidenceLoading ? (
              <div className="space-y-2">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="h-16 rounded-xl animate-pulse" style={{ background: 'rgba(13,16,24,0.8)' }} />
                ))}
              </div>
            ) : (
              <EvidencePanel evidence={evidenceRecords ?? []} />
            )}
          </div>
        )}

        {/* Tab: Remediation */}
        {activeTab === 'remediation' && (
          <div className="space-y-6">
            {finding.remediation && (
              <section>
                <SectionHeading icon="◈">Remediation Summary</SectionHeading>
                <div className="card rounded-xl p-4">
                  <p className="text-sm text-text-secondary leading-relaxed">{finding.remediation}</p>
                </div>
              </section>
            )}
            {finding.remediation_steps?.length > 0 && (
              <section>
                <div className="flex items-center justify-between mb-3">
                  <SectionHeading icon="✓">Step-by-step Checklist</SectionHeading>
                  <Link
                    href={`/remediation?assessment_id=${finding.assessment_id}&finding=${finding.id}`}
                    className="flex items-center gap-1.5 text-xs text-brand hover:text-brand/80 transition-colors ml-4 -mt-1"
                  >
                    <Zap className="w-3 h-3" />
                    Open in Simulator
                  </Link>
                </div>
                <div className="card rounded-xl p-4">
                  <RemediationSteps steps={finding.remediation_steps} />
                </div>
              </section>
            )}
            {finding.waiver_reason && (
              <section>
                <SectionHeading icon="⚑">Risk Acceptance</SectionHeading>
                <div className="card rounded-xl p-4" style={{ borderLeft: '3px solid rgba(59,130,246,0.5)' }}>
                  <div className="flex items-start gap-3">
                    <Shield className="w-4 h-4 text-info flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm text-text-secondary">{finding.waiver_reason}</p>
                      {finding.waiver_expiry && (
                        <p className="text-xs text-text-tertiary mt-1 flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          Waiver expires {fmtDate(finding.waiver_expiry)}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </section>
            )}
          </div>
        )}

        {/* Tab: Scoring */}
        {activeTab === 'scoring' && (
          <div className="space-y-6">
            <section>
              <SectionHeading icon="◆">Score Breakdown</SectionHeading>
              <div className="card rounded-xl p-5 space-y-3">
                <ScoreBar label="Technical Severity" value={finding.technical_severity} max={10} />
                <ScoreBar label="Reachability" value={finding.reachability_score} max={1} />
                <ScoreBar label="Asset Criticality" value={finding.asset_criticality} max={1} />
                <ScoreBar label="Confidence" value={finding.confidence} max={1} />
                <div className="pt-3 border-t border-border flex items-center justify-between">
                  <span className="text-sm text-text-secondary font-semibold">Composite Score</span>
                  <span className={cn(
                    'text-4xl font-black',
                    (finding.composite_score ?? 0) >= 85 ? 'text-critical' :
                    (finding.composite_score ?? 0) >= 65 ? 'text-high' :
                    'text-medium',
                  )}>
                    {finding.composite_score?.toFixed(1) ?? '—'}
                  </span>
                </div>
              </div>
            </section>

            <section>
              <SectionHeading icon="⚑">Risk Factors</SectionHeading>
              <div className="grid grid-cols-2 gap-2.5">
                {[
                  { label: 'Crown Jewel Path', value: finding.attack_path?.some(s => s.entity_type === 'DOMAIN') },
                  { label: 'Tier-0 Direct', value: finding.is_tier0_direct },
                  { label: 'New Finding', value: finding.drift_status === 'new' },
                  { label: 'Regressed', value: finding.drift_status === 'regressed' },
                ].map(({ label, value }) => (
                  <div key={label} className="card rounded-xl p-3 flex items-center gap-3">
                    <div className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                      style={value
                        ? { background: '#ef4444', boxShadow: '0 0 6px rgba(239,68,68,0.4)' }
                        : { background: 'transparent', border: '1px solid rgba(71,85,105,0.5)' }}
                    />
                    <span className="text-xs text-text-secondary flex-1">{label}</span>
                    <span className={cn('text-xs font-bold', value ? 'text-critical' : 'text-text-tertiary')}>
                      {value ? 'Yes' : 'No'}
                    </span>
                  </div>
                ))}
              </div>
            </section>

            <section>
              <SectionHeading icon="≡">Metadata</SectionHeading>
              <div className="card rounded-xl overflow-hidden">
                {[
                  { key: 'Finding ID', val: finding.id, mono: true },
                  { key: 'Type', val: finding.finding_type, mono: true },
                  { key: 'Module', val: finding.module, mono: false },
                  { key: 'First seen', val: fmtDateTime(finding.first_seen), mono: false },
                  { key: 'Last seen', val: fmtDateTime(finding.last_seen), mono: false },
                  { key: 'Updated', val: timeAgo(finding.created_at), mono: false },
                ].map(({ key, val, mono }, i, arr) => (
                  <div key={key} className={cn('flex items-center justify-between px-4 py-2.5 text-xs', i < arr.length - 1 && 'border-b border-border')}>
                    <span className="text-text-tertiary">{key}</span>
                    <span className={cn('text-text-secondary', mono && 'font-mono')}>{val}</span>
                  </div>
                ))}
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  )
}
