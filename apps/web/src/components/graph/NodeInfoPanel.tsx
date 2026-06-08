'use client'

import { copyText } from '@/lib/clipboard'
import { useState, useMemo, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  X, Crown, Skull, Star, Crosshair, Workflow, GitBranch,
  Copy, Check, Pin, ExternalLink, Shield, AlertTriangle,
  Zap, Activity, ChevronDown, ChevronRight, Info,
} from 'lucide-react'
import { useRouter } from 'next/navigation'
import toast from 'react-hot-toast'

import { entitiesApi } from '@/lib/api'
import type { Entity, GraphEdge, GraphNode } from '@/lib/types'
import { cn, safeDateMs } from '@/lib/utils'
import { getId, nodeBaseColor, computeNodeReachability } from './engine/utils'
import { getLetter, EDGE_ABUSE, EDGE_MITRE } from './engine/constants'

function relativeTime(iso: string | undefined | null): string {
  if (!iso) return '—'
  const parsed = safeDateMs(iso)
  if (parsed === null) return iso
  const ms = Math.max(0, Date.now() - parsed)
  const days = Math.floor(ms / 86_400_000)
  if (days === 0) return 'Today'
  if (days === 1) return 'Yesterday'
  if (days < 30) return `${days}d ago`
  if (days < 365) return `${Math.floor(days / 30)}mo ago`
  return `${Math.floor(days / 365)}y ago`
}

function passwordAge(iso: string | undefined | null): { label: string; color: string } {
  if (!iso) return { label: 'Never set', color: '#ef4444' }
  const parsed = safeDateMs(iso)
  if (parsed === null) return { label: 'Unknown', color: '#71717a' }
  const days = Math.max(0, Math.floor((Date.now() - parsed) / 86_400_000))
  if (days > 365) return { label: `${days}d — STALE`, color: '#ef4444' }
  if (days > 180) return { label: `${days}d — aging`, color: '#f97316' }
  if (days > 90)  return { label: `${days}d`, color: '#eab308' }
  return { label: `${days}d`, color: '#22c55e' }
}

function edgeRiskColor(w: number): string {
  if (w >= 0.8) return '#ef4444'
  if (w >= 0.6) return '#f97316'
  if (w >= 0.4) return '#eab308'
  return '#52525b'
}

function CopyButton({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = useCallback(() => {
    copyText(value)
    setCopied(true)
    toast(`Copied ${label ?? 'value'}`, { duration: 900 })
    setTimeout(() => setCopied(false), 1500)
  }, [value, label])
  return (
    <button onClick={copy} title={`Copy ${label ?? value}`}
      className="ml-1.5 inline-flex items-center justify-center rounded p-1 text-zinc-600 hover:text-zinc-300 transition flex-shrink-0">
      {copied
        ? <Check className="h-3.5 w-3.5 text-green-400" />
        : <Copy className="h-3.5 w-3.5" />}
    </button>
  )
}

function MetaRow({ label, value, copyable }: { label: string; value?: string | null; copyable?: boolean }) {
  if (!value) return null
  return (
    <div className="flex items-start justify-between gap-3 py-2 border-b border-white/[0.05] last:border-0">
      <span className="text-xs uppercase tracking-wider text-zinc-500 flex-shrink-0 pt-0.5 w-16">{label}</span>
      <div className="flex items-center gap-0.5 min-w-0 flex-1 justify-end">
        <span className="text-sm text-zinc-200 truncate text-right" title={value}>{value}</span>
        {copyable && <CopyButton value={value} label={label} />}
      </div>
    </div>
  )
}

function EdgeTypeRow({ edgeType, count, maxRisk, expanded, onToggle }: {
  edgeType: string; count: number; maxRisk: number
  expanded: boolean; onToggle: () => void
}) {
  const abuse = EDGE_ABUSE[edgeType]
  const mitre = EDGE_MITRE[edgeType] ?? []
  const col = edgeRiskColor(maxRisk)

  return (
    <div className="rounded-xl border border-white/8 overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2.5 px-4 py-3 hover:bg-white/[0.04] transition text-left"
      >
        <span
          className="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide flex-shrink-0 max-w-[160px] truncate"
          style={{ borderColor: col + '50', color: col, backgroundColor: col + '15' }}
          title={edgeType.replace(/_/g, ' ')}
        >
          {edgeType.replace(/_/g, ' ')}
        </span>
        <span className="ml-auto text-sm text-zinc-400 flex-shrink-0 font-medium">{count}×</span>
        <div className="w-12 h-1.5 rounded-full bg-white/8 overflow-hidden flex-shrink-0">
          <div className="h-full rounded-full" style={{ width: `${maxRisk * 100}%`, backgroundColor: col }} />
        </div>
        {abuse
          ? (expanded
            ? <ChevronDown className="h-4 w-4 text-zinc-500 flex-shrink-0" />
            : <ChevronRight className="h-4 w-4 text-zinc-500 flex-shrink-0" />)
          : <span className="h-4 w-4 flex-shrink-0" />}
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-2.5 bg-black/40">
              {abuse ? (
                <>
                  <p className="text-sm text-zinc-300 leading-relaxed">{abuse.summary}</p>
                  <div className="rounded-lg border border-red-500/20 bg-red-500/8 px-3 py-2.5">
                    <div className="text-xs uppercase tracking-wider text-red-500/70 mb-1.5">Abuse</div>
                    <p className="text-sm text-red-300/90 leading-relaxed">{abuse.abuse}</p>
                  </div>
                  <div className="rounded-lg border border-yellow-500/15 bg-yellow-500/6 px-3 py-2.5">
                    <div className="text-xs uppercase tracking-wider text-yellow-500/60 mb-1.5">OpSec</div>
                    <p className="text-sm text-yellow-200/75 leading-relaxed">{abuse.opsec}</p>
                  </div>
                </>
              ) : (
                <p className="text-sm text-zinc-600 italic">No abuse reference for this edge type.</p>
              )}
              {mitre.length > 0 && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {mitre.map(t => (
                    <span key={t}
                      className="rounded-full border border-cyan-500/25 bg-cyan-500/8 px-3 py-0.5 text-xs text-cyan-400 font-mono">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-xs uppercase tracking-wider text-zinc-500 mb-2 font-medium">{children}</div>
  )
}

type Tab = 'overview' | 'intel' | 'details'

export function NodeInfoPanel({
  node, onClose, onSimRemediation, ownedNodes, highValueNodes, edges, allNodes,
  onOwned, onHighValue, onSetStart, onSetEnd, onFocus, onPin, pinnedNodes, assessmentId,
}: {
  node: GraphNode
  onClose: () => void
  onSimRemediation: (id: string) => void
  ownedNodes: Set<string>
  highValueNodes: Set<string>
  edges: GraphEdge[]
  allNodes: GraphNode[]
  onOwned: (id: string) => void
  onHighValue: (id: string) => void
  onSetStart: (n: GraphNode) => void
  onSetEnd: (n: GraphNode) => void
  onFocus: (n: GraphNode) => void
  onPin: (id: string) => void
  pinnedNodes: Set<string>
  assessmentId: string | null
}) {
  const router = useRouter()
  const [activeTab, setActiveTab] = useState<Tab>('overview')
  const [entityDetail, setEntityDetail] = useState<Entity | null>(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [expandedEdgeType, setExpandedEdgeType] = useState<string | null>(null)

  useEffect(() => {
    setActiveTab('overview')
    setEntityDetail(null)
    setExpandedEdgeType(null)
    setDetailLoading(false)
  }, [node.id])

  useEffect(() => {
    if (activeTab !== 'details' || entityDetail || detailLoading) return
    setDetailLoading(true)
    entitiesApi.get(node.id)
      .then(setEntityDetail)
      .catch(() => {})
      .finally(() => setDetailLoading(false))
  }, [activeTab, node.id, entityDetail, detailLoading])

  const color = nodeBaseColor(node)

  const inbound  = useMemo(() => edges.filter(e => getId(e.target) === node.id).length, [edges, node.id])
  const outbound = useMemo(() => edges.filter(e => getId(e.source) === node.id).length, [edges, node.id])
  const highRisk = useMemo(() => edges.filter(e =>
    (getId(e.source) === node.id || getId(e.target) === node.id) && (e.risk_weight ?? 0) >= 0.6
  ).length, [edges, node.id])

  const reach = useMemo(
    () => computeNodeReachability(allNodes, edges, node.id, ownedNodes),
    [allNodes, edges, node.id, ownedNodes],
  )

  const edgeTypeStats = useMemo(() => {
    const nodeEdges = edges.filter(e => getId(e.source) === node.id || getId(e.target) === node.id)
    const map = new Map<string, { count: number; maxRisk: number }>()
    for (const e of nodeEdges) {
      const t = e.edge_type
      const prev = map.get(t)
      if (!prev) map.set(t, { count: 1, maxRisk: e.risk_weight ?? 0 })
      else map.set(t, { count: prev.count + 1, maxRisk: Math.max(prev.maxRisk, e.risk_weight ?? 0) })
    }
    return [...map.entries()].sort((a, b) => b[1].maxRisk - a[1].maxRisk)
  }, [edges, node.id])

  const allMitre = useMemo(() => {
    const s = new Set<string>()
    for (const [type] of edgeTypeStats) {
      for (const t of (EDGE_MITRE[type] ?? [])) s.add(t)
    }
    return [...s]
  }, [edgeTypeStats])

  const criticalPathCount = useMemo(() =>
    edges.filter(e =>
      getId(e.source) === node.id &&
      allNodes.find(n => n.id === getId(e.target))?.tier === 0
    ).length,
    [edges, node.id, allNodes],
  )

  const isPinned = pinnedNodes.has(node.id)
  const isOwned  = ownedNodes.has(node.id)
  const isHV     = highValueNodes.has(node.id)

  const openFindings = useCallback(() => {
    if (!assessmentId) return
    router.push(`/findings?assessment_id=${assessmentId}&entity=${node.id}`)
  }, [router, assessmentId, node.id])

  const exportSubgraph = useCallback(() => {
    const nodeEdges = edges.filter(e => getId(e.source) === node.id || getId(e.target) === node.id)
    const neighbourIds = new Set<string>()
    nodeEdges.forEach(e => { neighbourIds.add(getId(e.source)); neighbourIds.add(getId(e.target)) })
    const subNodes = allNodes.filter(n => neighbourIds.has(n.id))
    const payload = { center: node, nodes: subNodes, edges: nodeEdges }
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `subgraph-${node.label.replace(/\s+/g, '-')}.json`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('Subgraph exported')
  }, [node, allNodes, edges])

  const TABS: { id: Tab; label: string; badge?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'intel',    label: 'Intel',    badge: edgeTypeStats.length },
    { id: 'details',  label: 'Details'  },
  ]

  return (
    <motion.div
      initial={{ opacity: 0, x: 18 }} animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 18 }} transition={{ duration: 0.22, ease: [0.23, 1, 0.32, 1] }}
      className="absolute bottom-4 left-4 z-40 w-[440px] rounded-2xl border border-white/10 bg-zinc-950/97 shadow-2xl backdrop-blur flex flex-col"
      style={{ maxHeight: 'calc(100% - 2rem)' }}
      role="complementary"
      aria-label={`Node details: ${node.label}`}
    >
      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="px-5 pt-5 pb-0 flex-shrink-0">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-3">
              <span
                className="inline-flex h-10 w-10 items-center justify-center rounded-xl text-sm font-bold font-mono flex-shrink-0"
                style={{ backgroundColor: color + '22', color, border: `1px solid ${color}30` }}
              >
                {getLetter(node.entity_type)}
              </span>
              <div className="min-w-0">
                <div className="font-semibold text-white truncate text-base leading-tight">{node.label}</div>
                <div className="mt-0.5 text-xs uppercase tracking-widest text-zinc-500">{node.entity_type}</div>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-1.5 flex-shrink-0 mt-0.5">
            <button
              onClick={() => onPin(node.id)}
              title={isPinned ? 'Unpin node' : 'Pin node'}
              aria-pressed={isPinned}
              className={cn(
                'rounded-lg p-1.5 transition',
                isPinned ? 'text-cyan-400 bg-cyan-400/12' : 'text-zinc-500 hover:text-white hover:bg-white/8',
              )}
            >
              <Pin className="h-4 w-4" />
            </button>
            <button onClick={onClose} aria-label="Close node details"
              className="rounded-lg p-1.5 text-zinc-500 hover:text-white hover:bg-white/8 transition">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Badges */}
        <div className="mt-3 flex flex-wrap gap-2">
          {node.tier !== undefined && (
            <span className="badge-pill border-red-500/30 bg-red-500/12 text-red-300 text-xs px-2.5 py-1">Tier {node.tier}</span>
          )}
          {node.is_crown_jewel && (
            <span className="badge-pill border-orange-500/30 bg-orange-500/12 text-orange-300 text-xs px-2.5 py-1">
              <Crown className="h-3 w-3" /> Crown Jewel
            </span>
          )}
          {node.is_admin_count && (
            <span className="badge-pill border-purple-500/30 bg-purple-500/12 text-purple-300 text-xs px-2.5 py-1">AdminCount</span>
          )}
          {isOwned && (
            <span className="badge-pill border-zinc-600/30 bg-zinc-600/12 text-zinc-300 text-xs px-2.5 py-1">☠ Owned</span>
          )}
          {isHV && (
            <span className="badge-pill border-yellow-500/30 bg-yellow-500/12 text-yellow-300 text-xs px-2.5 py-1">★ Hi-Value</span>
          )}
          {isPinned && (
            <span className="badge-pill border-cyan-500/30 bg-cyan-500/12 text-cyan-300 text-xs px-2.5 py-1">📌 Pinned</span>
          )}
        </div>

        {/* Tabs */}
        <div className="mt-4 flex border-b border-white/8">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex-1 py-2.5 text-sm font-medium transition-colors flex items-center justify-center gap-2',
                activeTab === tab.id
                  ? 'text-white border-b-2 border-cyan-400 -mb-px'
                  : 'text-zinc-500 hover:text-zinc-300',
              )}
            >
              {tab.label}
              {tab.badge !== undefined && tab.badge > 0 && (
                <span className={cn(
                  'rounded-full px-1.5 py-0.5 text-xs font-bold min-w-[20px] text-center',
                  activeTab === tab.id ? 'bg-cyan-400/20 text-cyan-300' : 'bg-white/8 text-zinc-500',
                )}>
                  {tab.badge}
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* ── Tab Content ─────────────────────────────────────────────── */}
      <div className="overflow-y-auto flex-1 px-5 py-4">

        {/* ════════════════ OVERVIEW ════════════════ */}
        {activeTab === 'overview' && (
          <div className="space-y-4">

            {/* 4-box stats */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Inbound',   value: inbound,              color: '#22d3ee' },
                { label: 'Outbound',  value: outbound,             color: '#a78bfa' },
                { label: 'High Risk', value: highRisk,             color: '#ef4444' },
                { label: 'T0 Reach',  value: reach.tier0Reachable, color: '#f97316' },
              ].map(s => (
                <div key={s.label} className="rounded-xl border border-white/8 bg-black/50 p-4 text-center">
                  <div className="text-3xl font-bold tabular-nums" style={{ color: s.color }}>{s.value}</div>
                  <div className="text-xs uppercase tracking-wider text-zinc-500 mt-1.5">{s.label}</div>
                </div>
              ))}
            </div>

            {/* Blast radius */}
            {(reach.tier0Reachable > 0 || reach.ownedReachable > 0 || reach.criticalEdgeCount > 0) && (
              <div className="rounded-xl border border-orange-500/20 bg-orange-500/6 px-4 py-3.5 space-y-2">
                <SectionLabel>Blast Radius</SectionLabel>
                {reach.hopsToNearestTier0 !== -1 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-400">Hops to nearest T0</span>
                    <span className="text-orange-400 font-bold tabular-nums">{reach.hopsToNearestTier0}</span>
                  </div>
                )}
                {reach.ownedReachable > 0 && (
                  <div className="flex justify-between text-sm">
                    <span className="text-zinc-400">Owned nodes reachable</span>
                    <span className="text-zinc-200 font-bold tabular-nums">{reach.ownedReachable}</span>
                  </div>
                )}
                <div className="flex justify-between text-sm">
                  <span className="text-zinc-400">Critical edges (≥80%)</span>
                  <span className="text-red-400 font-bold tabular-nums">{reach.criticalEdgeCount}</span>
                </div>
              </div>
            )}

            {/* Severity breakdown */}
            {node.severity_count && Object.values(node.severity_count).some(v => v > 0) && (
              <div className="rounded-xl border border-white/8 bg-black/50 px-4 py-3.5">
                <SectionLabel>Linked Findings</SectionLabel>
                <div className="flex gap-3 flex-wrap">
                  {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => {
                    const n2 = node.severity_count?.[sev] ?? 0
                    if (!n2) return null
                    const cols: Record<string, string> = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22d3ee' }
                    return (
                      <div key={sev} className="rounded-lg border border-white/8 bg-black/60 px-3 py-2 text-center min-w-[52px]">
                        <div className="text-xl font-bold tabular-nums" style={{ color: cols[sev] }}>{n2}</div>
                        <div className="text-xs uppercase text-zinc-500 mt-0.5">{sev}</div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Quick copy / export row */}
            <div className="grid grid-cols-3 gap-2">
              {[
                { label: 'Name',   icon: Copy,         onClick: () => { copyText(node.label); toast('Name copied', { duration: 900 }) } },
                { label: 'ID',     icon: Copy,         onClick: () => { copyText(node.id);    toast('ID copied',   { duration: 900 }) } },
                { label: 'Export', icon: ExternalLink,  onClick: exportSubgraph },
              ].map(b => (
                <button key={b.label} onClick={b.onClick}
                  className="flex items-center justify-center gap-1.5 rounded-xl border border-white/8 bg-black/50 py-2.5 text-sm text-zinc-400 hover:text-white hover:bg-white/[0.07] transition font-medium">
                  <b.icon className="h-3.5 w-3.5" /> {b.label}
                </button>
              ))}
            </div>

            {/* Primary actions */}
            <div className="grid grid-cols-2 gap-2.5">
              <button onClick={() => onOwned(node.id)}
                className={cn(
                  'flex items-center justify-center gap-2 rounded-xl border py-3 text-sm font-medium transition',
                  isOwned
                    ? 'border-zinc-500/40 bg-zinc-500/15 text-zinc-100 hover:bg-zinc-500/25'
                    : 'border-white/10 bg-black/50 text-zinc-300 hover:bg-white/[0.07]',
                )}>
                <Skull className="h-4 w-4" /> {isOwned ? 'Unown' : 'Owned'}
              </button>
              <button onClick={() => onHighValue(node.id)}
                className={cn(
                  'flex items-center justify-center gap-2 rounded-xl border py-3 text-sm font-medium transition',
                  isHV
                    ? 'border-yellow-500/40 bg-yellow-500/12 text-yellow-100 hover:bg-yellow-500/22'
                    : 'border-white/10 bg-black/50 text-zinc-300 hover:bg-white/[0.07]',
                )}>
                <Star className="h-4 w-4" /> {isHV ? 'Unmark' : 'Hi-Value'}
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2.5">
              <button onClick={() => onSetStart(node)}
                className="flex items-center justify-center gap-2 rounded-xl border border-green-500/30 bg-green-500/10 py-3 text-sm font-medium text-green-300 transition hover:bg-green-500/18">
                ▶ Start
              </button>
              <button onClick={() => onSetEnd(node)}
                className="flex items-center justify-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 py-3 text-sm font-medium text-red-300 transition hover:bg-red-500/18">
                ■ End
              </button>
            </div>

            <button onClick={() => onFocus(node)}
              className="w-full flex items-center justify-center gap-2.5 rounded-xl border border-purple-500/30 bg-purple-500/10 py-3 text-sm font-medium text-purple-300 transition hover:bg-purple-500/18">
              <Crosshair className="h-4 w-4" /> N-Hop Focus
            </button>

            <button onClick={() => onSimRemediation(node.id)}
              className="w-full flex items-center justify-center gap-2.5 rounded-xl bg-indigo-500/18 border border-indigo-500/35 py-3.5 text-sm font-semibold text-indigo-300 transition hover:bg-indigo-500/28">
              <Workflow className="h-4 w-4" /> Simulate Remediation
            </button>

            {assessmentId && (
              <button onClick={openFindings}
                className="w-full flex items-center justify-center gap-2.5 rounded-xl border border-cyan-500/25 bg-cyan-500/8 py-3 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/16">
                <GitBranch className="h-4 w-4" /> View Findings →
              </button>
            )}
          </div>
        )}

        {/* ════════════════ INTEL ════════════════ */}
        {activeTab === 'intel' && (
          <div className="space-y-4">
            {edgeTypeStats.length === 0 && (
              <div className="py-12 text-center text-sm text-zinc-600">
                <Info className="h-6 w-6 mx-auto mb-2.5 text-zinc-700" />
                No edges on this node
              </div>
            )}

            {edgeTypeStats.length > 0 && (
              <>
                {/* Summary */}
                <div className="grid grid-cols-3 gap-2.5">
                  {[
                    { label: 'Edge Types', value: edgeTypeStats.length,    color: '#a78bfa' },
                    { label: 'Critical',   value: reach.criticalEdgeCount, color: '#ef4444' },
                    { label: 'T0 Direct',  value: criticalPathCount,       color: '#f97316' },
                  ].map(s => (
                    <div key={s.label} className="rounded-xl border border-white/8 bg-black/50 p-3.5 text-center">
                      <div className="text-2xl font-bold tabular-nums" style={{ color: s.color }}>{s.value}</div>
                      <div className="text-xs uppercase tracking-wider text-zinc-500 mt-1">{s.label}</div>
                    </div>
                  ))}
                </div>

                {/* MITRE tags */}
                {allMitre.length > 0 && (
                  <div>
                    <SectionLabel>MITRE ATT&amp;CK</SectionLabel>
                    <div className="flex flex-wrap gap-2">
                      {allMitre.map(t => (
                        <span key={t}
                          className="rounded-full border border-cyan-500/25 bg-cyan-500/8 px-3 py-1 text-xs text-cyan-400 font-mono font-medium">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Risk flow */}
                <div className="rounded-xl border border-white/8 bg-black/50 px-4 py-3.5">
                  <SectionLabel>Risk Flow</SectionLabel>
                  <div className="space-y-2.5">
                    {[
                      { label: 'Inbound high-risk',  value: reach.inboundHighRisk,   color: '#22d3ee', icon: '↓' },
                      { label: 'Outbound high-risk', value: reach.outboundHighRisk,  color: '#a78bfa', icon: '↑' },
                      { label: 'Critical (≥80%)',    value: reach.criticalEdgeCount, color: '#ef4444', icon: '⚠' },
                    ].map(r => (
                      <div key={r.label} className="flex items-center gap-3">
                        <span className="text-sm w-5 text-center flex-shrink-0 font-bold" style={{ color: r.color }}>{r.icon}</span>
                        <span className="flex-1 text-sm text-zinc-400">{r.label}</span>
                        <span className="text-sm font-bold tabular-nums" style={{ color: r.color }}>{r.value}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Edge breakdown */}
                <div>
                  <SectionLabel>Edge Breakdown</SectionLabel>
                  <div className="space-y-2">
                    {edgeTypeStats.map(([type, stat]) => (
                      <EdgeTypeRow
                        key={type}
                        edgeType={type}
                        count={stat.count}
                        maxRisk={stat.maxRisk}
                        expanded={expandedEdgeType === type}
                        onToggle={() => setExpandedEdgeType(expandedEdgeType === type ? null : type)}
                      />
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* ════════════════ DETAILS ════════════════ */}
        {activeTab === 'details' && (
          <div className="space-y-4">
            {detailLoading && (
              <div className="py-12 flex items-center justify-center gap-3 text-sm text-zinc-500">
                <Activity className="h-5 w-5 animate-pulse text-cyan-400" /> Loading entity details…
              </div>
            )}

            {!detailLoading && !entityDetail && (
              <div className="py-10 text-center text-sm text-zinc-600">
                <Info className="h-6 w-6 mx-auto mb-2.5 text-zinc-700" />
                Entity details unavailable
              </div>
            )}

            {entityDetail && (
              <>
                {/* Status badges */}
                <div className="flex flex-wrap gap-2">
                  <span className={cn(
                    'badge-pill text-xs px-2.5 py-1',
                    entityDetail.is_enabled
                      ? 'border-green-500/30 bg-green-500/10 text-green-300'
                      : 'border-red-500/30 bg-red-500/10 text-red-300',
                  )}>
                    {entityDetail.is_enabled ? '● Enabled' : '● Disabled'}
                  </span>
                  {entityDetail.is_sensitive && (
                    <span className="badge-pill border-orange-500/30 bg-orange-500/10 text-orange-300 text-xs px-2.5 py-1">
                      <AlertTriangle className="h-3 w-3" /> Sensitive
                    </span>
                  )}
                  {entityDetail.is_protected_user && (
                    <span className="badge-pill border-blue-500/30 bg-blue-500/10 text-blue-300 text-xs px-2.5 py-1">
                      <Shield className="h-3 w-3" /> Protected
                    </span>
                  )}
                  {entityDetail.is_admin_count && (
                    <span className="badge-pill border-purple-500/30 bg-purple-500/10 text-purple-300 text-xs px-2.5 py-1">AdminCount</span>
                  )}
                </div>

                {/* Identity */}
                <div className="rounded-xl border border-white/8 bg-black/50 px-4 py-3.5">
                  <SectionLabel>Identity</SectionLabel>
                  <MetaRow label="SAM"    value={entityDetail.sam_account_name} copyable />
                  <MetaRow label="Domain" value={entityDetail.domain} />
                  <MetaRow label="DNS"    value={entityDetail.dns_hostname} copyable />
                  <MetaRow label="SID"    value={entityDetail.object_sid} copyable />
                  <MetaRow label="DN"     value={entityDetail.distinguished_name} copyable />
                </div>

                {/* Timestamps */}
                <div className="rounded-xl border border-white/8 bg-black/50 px-4 py-3.5">
                  <SectionLabel>Timestamps</SectionLabel>
                  <div className="py-2 flex justify-between items-center border-b border-white/[0.05]">
                    <span className="text-xs uppercase tracking-wider text-zinc-500">Last Logon</span>
                    <span className="text-sm text-zinc-200">{relativeTime(entityDetail.last_logon)}</span>
                  </div>
                  <div className="py-2 flex justify-between items-center border-b border-white/[0.05]">
                    <span className="text-xs uppercase tracking-wider text-zinc-500">Pwd Last Set</span>
                    {(() => {
                      const { label, color } = passwordAge(entityDetail.password_last_set)
                      return <span className="text-sm font-semibold" style={{ color }}>{label}</span>
                    })()}
                  </div>
                  {entityDetail.object_created && (
                    <div className="py-2 flex justify-between items-center">
                      <span className="text-xs uppercase tracking-wider text-zinc-500">Created</span>
                      <span className="text-sm text-zinc-400">{relativeTime(entityDetail.object_created)}</span>
                    </div>
                  )}
                </div>

                {/* Business context */}
                {(entityDetail.owner_team || (entityDetail.business_tags?.length ?? 0) > 0) && (
                  <div className="rounded-xl border border-white/8 bg-black/50 px-4 py-3.5">
                    <SectionLabel>Context</SectionLabel>
                    {entityDetail.owner_team && (
                      <div className="flex justify-between text-sm mb-2">
                        <span className="text-zinc-500">Owner Team</span>
                        <span className="text-zinc-200 font-medium">{entityDetail.owner_team}</span>
                      </div>
                    )}
                    {(entityDetail.business_tags?.length ?? 0) > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-1">
                        {entityDetail.business_tags.map(tag => (
                          <span key={tag}
                            className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-zinc-400">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Copy actions */}
                <div className="grid grid-cols-2 gap-2.5">
                  {entityDetail.object_sid && (
                    <button
                      onClick={() => { copyText(entityDetail.object_sid!); toast('SID copied', { duration: 900 }) }}
                      className="flex items-center justify-center gap-2 rounded-xl border border-white/8 bg-black/50 py-3 text-sm text-zinc-400 hover:text-white hover:bg-white/[0.07] transition font-medium"
                    >
                      <Copy className="h-3.5 w-3.5" /> Copy SID
                    </button>
                  )}
                  {entityDetail.distinguished_name && (
                    <button
                      onClick={() => { copyText(entityDetail.distinguished_name!); toast('DN copied', { duration: 900 }) }}
                      className="flex items-center justify-center gap-2 rounded-xl border border-white/8 bg-black/50 py-3 text-sm text-zinc-400 hover:text-white hover:bg-white/[0.07] transition font-medium"
                    >
                      <Copy className="h-3.5 w-3.5" /> Copy DN
                    </button>
                  )}
                </div>

                {assessmentId && (
                  <button onClick={openFindings}
                    className="w-full flex items-center justify-center gap-2.5 rounded-xl border border-cyan-500/25 bg-cyan-500/8 py-3 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/16">
                    <Zap className="h-4 w-4" /> View Findings for this Entity
                  </button>
                )}
              </>
            )}
          </div>
        )}
      </div>
    </motion.div>
  )
}
