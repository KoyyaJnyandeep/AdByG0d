'use client'

import { useMemo, useState } from 'react'
import { GitBranch, X } from 'lucide-react'
import { motion } from 'framer-motion'
import type { SavedGraphView, SnapshotSummary, PathNarration, AnomalyResult } from '@/lib/types'
import type { ColorMode } from './engine/types'
import { EDGE_ABUSE, COLOR_MODE_CONFIGS, TIER_LABELS } from './engine/constants'
import { computeAnalytics, findPath, getId } from './engine/utils'
import { edgeRiskColor } from './engine/constants'
import type { GraphEdge, GraphNode } from '@/lib/types'
import { cn } from '@/lib/utils'

export function PathFinderPanel({
  nodes, startNode, endNode, pathNodeIds, pathEdgeIds,
  onSetStart, onSetEnd, onFind, onClear,
  directedPaths, onDirectedToggle, onExplain,
}: {
  nodes: GraphNode[]; startNode: GraphNode | null; endNode: GraphNode | null
  pathNodeIds: Set<string>; pathEdgeIds: Set<string>
  onSetStart: (n: GraphNode | null) => void; onSetEnd: (n: GraphNode | null) => void
  onFind: () => void; onClear: () => void
  directedPaths: boolean; onDirectedToggle: () => void
  onExplain?: () => void
}) {
  const [sq, setSq] = useState(''), [eq, setEq] = useState('')
  const sRes = useMemo(() =>
    sq.length > 1 ? nodes.filter(n => n.label.toLowerCase().includes(sq.toLowerCase())).slice(0, 5) : []
  , [nodes, sq])
  const eRes = useMemo(() =>
    eq.length > 1 ? nodes.filter(n => n.label.toLowerCase().includes(eq.toLowerCase())).slice(0, 5) : []
  , [nodes, eq])

  const NodeInput = ({ node, query, setQuery, onSet, color, placeholder }: {
    node: GraphNode | null; query: string; setQuery: (v: string) => void
    onSet: (n: GraphNode | null) => void; color: string; placeholder: string
  }) => node ? (
    <div className="flex items-center justify-between rounded-xl border px-3 py-2"
      style={{ borderColor: color + '40', backgroundColor: color + '10' }}>
      <span className="text-[11px] font-medium truncate" style={{ color }}>{node.label}</span>
      <button onClick={() => { onSet(null); setQuery('') }} className="ml-2 text-zinc-500 hover:text-white">
        <X className="h-3 w-3" />
      </button>
    </div>
  ) : (
    <div className="relative">
      <input value={query} onChange={e => setQuery(e.target.value)} placeholder={placeholder}
        className="w-full rounded-xl border border-white/10 bg-black/60 px-3 py-2 text-[11px] text-white placeholder:text-zinc-600 outline-none focus:border-cyan-400/30 transition"
        style={{ caretColor: color }} />
      {(query.length > 1 ? (placeholder.includes('start') ? sRes : eRes) : []).length > 0 && (
        <div className="absolute top-full mt-1 w-full rounded-xl border border-white/10 bg-zinc-900/98 py-1 shadow-xl z-20">
          {(placeholder.includes('start') ? sRes : eRes).map(n => (
            <button key={n.id} onClick={() => { onSet(n); setQuery('') }}
              className="w-full px-3 py-1.5 text-left text-[11px] text-zinc-300 hover:bg-white/8 hover:text-white truncate">
              {n.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )

  return (
    <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      className="rounded-2xl border border-cyan-500/20 bg-black/95 p-4 shadow-2xl backdrop-blur">
      <div className="mb-3 text-[10px] uppercase tracking-[0.2em] text-cyan-400 font-bold flex items-center gap-1.5">
        <GitBranch className="h-3 w-3" /> Attack Path Finder
      </div>
      <div className="space-y-2">
        <div>
          <div className="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">Start Node</div>
          <NodeInput node={startNode} query={sq} setQuery={setSq} onSet={onSetStart} color="#22c55e" placeholder="Search start node…" />
        </div>
        <div>
          <div className="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">End Node</div>
          <NodeInput node={endNode} query={eq} setQuery={setEq} onSet={onSetEnd} color="#f87171" placeholder="Search end node…" />
        </div>
      </div>
      <div className="flex items-center gap-2 py-1">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={directedPaths}
            onChange={onDirectedToggle}
            className="h-3 w-3 accent-cyan-400"
          />
          <span className="text-[10px] text-zinc-400">Directed (respect edge direction)</span>
        </label>
      </div>
      <div className="mt-3 flex gap-2">
        <button onClick={onFind} disabled={!startNode || !endNode}
          className="flex-1 rounded-xl bg-cyan-500/18 border border-cyan-500/35 py-2 text-[11px] font-semibold text-cyan-300 transition hover:bg-cyan-500/28 disabled:opacity-40 disabled:pointer-events-none">
          Find Path
        </button>
        <button onClick={onClear}
          className="rounded-xl border border-white/10 bg-black/60 px-3 py-2 text-[11px] text-zinc-400 hover:text-white transition">
          Clear
        </button>
      </div>
      {pathNodeIds.size > 0 && (
        <div className="mt-2 text-[10px] text-cyan-400 text-center">
          {pathNodeIds.size} nodes · {pathEdgeIds.size} hops
        </div>
      )}
      {pathNodeIds.size > 0 && onExplain && (
        <button onClick={onExplain}
          className="w-full mt-2 rounded-xl border border-amber-500/35 bg-amber-500/10 py-1.5 text-[10px] text-amber-300 hover:bg-amber-500/20 transition">
          Explain This Path
        </button>
      )}
    </motion.div>
  )
}

export function EdgeDetailsPanel({ edge, nodes, onClose }: {
  edge: GraphEdge; nodes: GraphNode[]; onClose: () => void
}) {
  const src = nodes.find(n => n.id === getId(edge.source))
  const tgt = nodes.find(n => n.id === getId(edge.target))
  const info = EDGE_ABUSE[edge.edge_type]
  const w = edge.risk_weight ?? 0
  const riskColor = w >= 0.8 ? '#ef4444' : w >= 0.6 ? '#f97316' : w >= 0.4 ? '#eab308' : '#52525b'

  return (
    <motion.div
      initial={{ opacity: 0, x: 18 }} animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 18 }} transition={{ duration: 0.22 }}
      className="absolute bottom-4 right-16 z-40 w-80 rounded-2xl border border-white/10 bg-black/95 p-5 shadow-2xl backdrop-blur"
      role="complementary"
      aria-label={`Edge details: ${edge.edge_type}`}
    >
      <div className="flex items-start justify-between gap-2 mb-3">
        <div>
          <span className="inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider"
            style={{ borderColor: riskColor+'60', color: riskColor, backgroundColor: riskColor+'15' }}>
            {edge.edge_type}
          </span>
          <div className="mt-1.5 text-[10px] text-zinc-500">
            Risk: <span style={{ color: riskColor }} className="font-bold">{(w*100).toFixed(0)}%</span>
          </div>
        </div>
        <button onClick={onClose} aria-label="Close edge details"
          className="text-zinc-500 hover:text-white transition rounded-lg p-1 hover:bg-white/8">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="mb-3 flex items-center gap-2 rounded-xl border border-white/8 bg-black/60 px-3 py-2">
        <span className="truncate text-[11px] text-zinc-300 max-w-[100px]">{src?.label ?? getId(edge.source)}</span>
        <span className="text-zinc-600 text-xs flex-shrink-0">→</span>
        <span className="truncate text-right text-[11px] text-zinc-300 max-w-[100px]">{tgt?.label ?? getId(edge.target)}</span>
      </div>
      {info ? (
        <div className="space-y-3">
          <div>
            <div className="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">Description</div>
            <p className="text-[11px] text-zinc-300 leading-relaxed">{info.summary}</p>
          </div>
          <div>
            <div className="text-[9px] uppercase tracking-widest text-red-500/70 mb-1">Abuse Primitive</div>
            <p className="text-[11px] text-red-300/90 leading-relaxed">{info.abuse}</p>
          </div>
          <div>
            <div className="text-[9px] uppercase tracking-widest text-yellow-500/70 mb-1">OpSec / Detection</div>
            <p className="text-[11px] text-yellow-200/80 leading-relaxed">{info.opsec}</p>
          </div>
          <div className="flex items-center justify-between pt-1 border-t border-white/8">
            <span className="text-[9px] uppercase tracking-widest text-zinc-500">Risk Level</span>
            <span className="text-[10px] font-bold" style={{ color: riskColor }}>{info.risk}</span>
          </div>
        </div>
      ) : (
        <p className="text-[11px] text-zinc-500 italic">No abuse reference available for this edge type.</p>
      )}
    </motion.div>
  )
}

export function EdgeHoverTip({ edge, x, y, nodes, showProvenance }: {
  edge: GraphEdge; x: number; y: number; nodes: GraphNode[]
  showProvenance?: boolean
}) {
  const src = nodes.find(n => n.id === getId(edge.source))
  const tgt = nodes.find(n => n.id === getId(edge.target))
  const w = edge.risk_weight ?? 0
  const col = edgeRiskColor(w)
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      transition={{ duration: 0.08 }}
      className="pointer-events-none absolute z-50 rounded-xl border border-white/12 bg-zinc-950/95 px-3 py-2 shadow-xl"
      style={{ left: x + 14, top: y - 38 }}
    >
      <div className="flex items-center gap-2 text-[10px]">
        <span className="text-zinc-400 truncate max-w-[88px]">{src?.label ?? '?'}</span>
        <span className="rounded border px-1.5 py-0.5 font-bold uppercase text-[8px] tracking-wider"
          style={{ borderColor: col+'60', color: col, backgroundColor: col+'18' }}>
          {edge.edge_type}
        </span>
        <span className="text-zinc-400 truncate max-w-[88px]">{tgt?.label ?? '?'}</span>
      </div>
      <div className="mt-0.5 text-[9px] text-zinc-600">Click for abuse details · risk {(w*100).toFixed(0)}%</div>
      {showProvenance && edge.edge_provenance_type && (
        <div className="mt-0.5 flex items-center gap-1 text-[9px]">
          <span className={cn(
            'rounded-full px-1.5 py-0.5 font-semibold',
            edge.edge_provenance_type === 'collected' ? 'bg-green-500/20 text-green-400' :
            edge.edge_provenance_type === 'inferred'  ? 'bg-yellow-500/20 text-yellow-400' :
                                                         'bg-orange-500/20 text-orange-400'
          )}>
            {edge.edge_provenance_type}
          </span>
          <span className="text-zinc-600">confidence {((edge.edge_confidence ?? 1) * 100).toFixed(0)}%</span>
        </div>
      )}
    </motion.div>
  )
}

interface QueryResult { nodeIds?: Set<string>; edgeIds?: Set<string>; label: string }

export function PrebuiltQueriesPanel({ nodes, edges, ownedNodes, onResult, onClose }: {
  nodes: GraphNode[]; edges: GraphEdge[]; ownedNodes: Set<string>
  onResult: (r: QueryResult) => void; onClose: () => void
}) {
  const QUERIES = useMemo(() => [
    { id: 'das',        icon: '●', label: 'All Domain Admins',           desc: 'Tier-0 privileged nodes',
      run: () => ({ nodeIds: new Set(nodes.filter(n => n.tier===0).map(n => n.id)), label: 'Domain Admins' }) },
    { id: 'jewels',     icon: '◆', label: 'Crown Jewels',               desc: 'High-value critical assets',
      run: () => ({ nodeIds: new Set(nodes.filter(n => n.is_crown_jewel).map(n => n.id)), label: 'Crown Jewels' }) },
    { id: 'admincount', icon: '⬡', label: 'AdminCount = 1',             desc: 'Objects with AdminCount set',
      run: () => ({ nodeIds: new Set(nodes.filter(n => n.is_admin_count).map(n => n.id)), label: 'AdminCount=1' }) },
    { id: 'crit-edges', icon: '▲', label: 'Critical Risk Edges',        desc: 'Edges with risk ≥ 80%',
      run: () => ({ edgeIds: new Set(edges.filter(e => (e.risk_weight??0) >= 0.8).map(e => e.id)), label: 'Critical Edges' }) },
    { id: 'high-edges', icon: '△', label: 'High Risk Edges',            desc: 'Edges with risk ≥ 60%',
      run: () => ({ edgeIds: new Set(edges.filter(e => (e.risk_weight??0) >= 0.6).map(e => e.id)), label: 'High Risk Edges' }) },
    { id: 'dcsync',     icon: '⬡', label: 'DCSync Capable',             desc: 'Objects with DCSync rights',
      run: () => { const ids = new Set<string>(); edges.filter(e => e.edge_type==='DCSYNC').forEach(e => ids.add(getId(e.source))); return { nodeIds: ids, label: 'DCSync' } } },
    { id: 'genericall', icon: '◉', label: 'GenericAll Rights',          desc: 'Full control over AD objects',
      run: () => { const ids = new Set<string>(); edges.filter(e => e.edge_type==='GENERIC_ALL').forEach(e => ids.add(getId(e.source))); return { nodeIds: ids, label: 'GenericAll' } } },
    { id: 'delegation', icon: '⬡', label: 'Delegation Rights',          desc: 'AllowedToDelegate / AllowedToAct',
      run: () => { const ids = new Set<string>(); edges.filter(e => ['ALLOWED_TO_DELEGATE','ALLOWED_TO_ACT'].includes(e.edge_type)).forEach(e => ids.add(getId(e.source))); return { nodeIds: ids, label: 'Delegation' } } },
    { id: 'path-to-da', icon: '→', label: 'Shortest Path to DA',        desc: 'From any owned node to Tier-0',
      run: () => {
        const da = nodes.filter(n => n.tier===0)
        for (const ownId of ownedNodes) {
          for (const d of da) {
            if (ownId === d.id) continue
            const r = findPath(nodes, edges, ownId, d.id)
            if (r.pathNodeIds.size > 0) return { nodeIds: r.pathNodeIds, edgeIds: r.pathEdgeIds, label: 'Path to DA' }
          }
        }
        return { nodeIds: new Set<string>(), label: 'No path (mark owned nodes first)' }
      } },
    { id: 'write-dacl', icon: '✎', label: 'WriteDACL / WriteOwner',     desc: 'DACL manipulation rights',
      run: () => { const ids = new Set<string>(); edges.filter(e => ['WRITE_DACL','WRITE_OWNER'].includes(e.edge_type)).forEach(e => ids.add(getId(e.source))); return { nodeIds: ids, label: 'WriteDACL/WriteOwner' } } },
    { id: 'computers',  icon: '□', label: 'Privileged Computers',        desc: 'Tier 0-1 computers',
      run: () => ({ nodeIds: new Set(nodes.filter(n => n.entity_type==='COMPUTER' && (n.tier??5)<=1).map(n => n.id)), label: 'Privileged Computers' }) },
    { id: 'groups-t0',  icon: '○', label: 'Privileged Groups',          desc: 'Tier-0 group objects',
      run: () => ({ nodeIds: new Set(nodes.filter(n => n.entity_type==='GROUP' && n.tier===0).map(n => n.id)), label: 'Privileged Groups' }) },
  ], [nodes, edges, ownedNodes])

  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -12 }} transition={{ duration: 0.22 }}
      className="rounded-2xl border border-cyan-500/18 bg-black/95 shadow-2xl overflow-hidden backdrop-blur"
      style={{ width: 284 }}
      role="complementary"
      aria-label="Analysis queries"
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/8">
        <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-cyan-400">Analysis Queries</span>
        <button onClick={onClose} aria-label="Close queries" className="text-zinc-500 hover:text-white transition rounded-lg p-0.5 hover:bg-white/8">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="max-h-[440px] overflow-y-auto py-1">
        {QUERIES.map(q => (
          <button key={q.id} onClick={() => onResult(q.run())}
            className="w-full flex items-start gap-3 px-4 py-2.5 text-left hover:bg-white/5 transition group">
            <span className="flex-shrink-0 w-5 h-5 mt-0.5 text-center text-[11px] text-zinc-500 group-hover:text-zinc-400">{q.icon}</span>
            <div>
              <div className="text-[11px] font-semibold text-zinc-200 group-hover:text-white">{q.label}</div>
              <div className="text-[9px] text-zinc-600 mt-0.5">{q.desc}</div>
            </div>
          </button>
        ))}
      </div>
      <div className="px-4 py-2 border-t border-white/6">
        <p className="text-[9px] text-zinc-700">Results highlight matching nodes/edges in the graph.</p>
      </div>
    </motion.div>
  )
}

export function AnalyticsPanel({ nodes, edges, degreeMap, ownedNodes, highValueNodes, onClose }: {
  nodes: GraphNode[]; edges: GraphEdge[]; degreeMap: Map<string, number>
  ownedNodes: Set<string>; highValueNodes: Set<string>; onClose: () => void
}) {
  const stats = useMemo(() => computeAnalytics(nodes, edges, degreeMap), [nodes, edges, degreeMap])
  const edgeTypeCounts = useMemo(() => {
    const m = new Map<string, number>()
    for (const e of edges) m.set(e.edge_type, (m.get(e.edge_type) ?? 0) + 1)
    return [...m.entries()].sort((a, b) => b[1]-a[1]).slice(0, 8)
  }, [edges])

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.22 }}
      className="rounded-2xl border border-purple-500/18 bg-black/95 shadow-2xl overflow-hidden backdrop-blur"
      style={{ width: 284 }}
      role="complementary"
      aria-label="Graph analytics"
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/8">
        <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-purple-400">Graph Analytics</span>
        <button onClick={onClose} aria-label="Close analytics" className="text-zinc-500 hover:text-white transition rounded-lg p-0.5 hover:bg-white/8">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="p-4 space-y-4 max-h-[500px] overflow-y-auto">
        {/* Risk bar */}
        <div>
          <div className="flex justify-between text-[10px] mb-1.5">
            <span className="text-zinc-400">Attack Surface Score</span>
            <span className="font-bold text-red-400">{stats.riskScore}/100</span>
          </div>
          <div className="h-1.5 rounded-full bg-white/10 overflow-hidden" role="progressbar"
            aria-valuenow={stats.riskScore} aria-valuemin={0} aria-valuemax={100}>
            <motion.div className="h-full rounded-full bg-gradient-to-r from-yellow-500 to-red-500"
              initial={{ width: 0 }} animate={{ width: `${stats.riskScore}%` }} transition={{ duration: 0.6 }} />
          </div>
        </div>
        {/* Key metrics */}
        <div className="grid grid-cols-2 gap-2">
          {[
            { l: 'Nodes',       v: stats.nodes,            c: '#06b6d4' },
            { l: 'Edges',       v: stats.edges,            c: '#a78bfa' },
            { l: 'Avg Degree',  v: stats.avgDegree,        c: '#22d3ee' },
            { l: 'Max Degree',  v: stats.maxDegree,        c: '#f59e0b' },
            { l: 'Density',     v: stats.density,          c: '#6b7280' },
            { l: 'Crit Edges',  v: stats.critEdges,        c: '#ef4444' },
            { l: 'Tier-0',      v: stats.tier0,            c: '#ef4444' },
            { l: 'Crown Jewels',v: stats.crownJewels,      c: '#f97316' },
            { l: 'AdminCount',  v: stats.adminCounts,      c: '#8b5cf6' },
            { l: 'Owned',       v: ownedNodes.size,        c: '#71717a' },
            { l: 'High Value',  v: highValueNodes.size,    c: '#eab308' },
            { l: 'Total Risk',  v: stats.totalRisk,        c: '#f97316' },
          ].map(s => (
            <div key={s.l} className="rounded-xl border border-white/8 bg-black/60 p-2.5 text-center">
              <div className="text-sm font-bold" style={{ color: s.c }}>{s.v}</div>
              <div className="text-[8px] uppercase tracking-widest text-zinc-600 mt-0.5">{s.l}</div>
            </div>
          ))}
        </div>
        {/* Most connected */}
        <div className="rounded-xl border border-white/8 bg-black/60 p-3">
          <div className="text-[9px] uppercase tracking-widest text-zinc-500 mb-1">Most Connected</div>
          <div className="text-[11px] text-white font-semibold truncate">{stats.mostConnected}</div>
          <div className="text-[10px] text-zinc-500">{stats.mostConnectedDegree} connections</div>
        </div>
        {/* Top edge types */}
        <div>
          <div className="text-[9px] uppercase tracking-widest text-zinc-500 mb-2">Top Edge Types</div>
          <div className="space-y-1.5">
            {edgeTypeCounts.map(([type, count]) => (
              <div key={type} className="flex items-center gap-2">
                <div className="flex-1 text-[10px] text-zinc-400 truncate">{type}</div>
                <div className="w-16 h-1 rounded-full bg-white/10 overflow-hidden">
                  <div className="h-full rounded-full bg-purple-500/65"
                    style={{ width: `${(count/(edgeTypeCounts[0]?.[1]??1))*100}%` }} />
                </div>
                <div className="text-[9px] text-zinc-500 w-6 text-right">{count}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  )
}

export function ColorModeLegend({ mode }: { mode: ColorMode }) {
  if (mode === 'default') return null
  const cfg = COLOR_MODE_CONFIGS[mode]
  if (!cfg) return null
  return (
    <div className="absolute bottom-16 left-4 rounded-xl border border-white/10 bg-black/80 px-3 py-2.5 backdrop-blur">
      <div className="text-[8px] uppercase tracking-widest text-zinc-500 mb-1.5">{cfg.label}</div>
      {mode === 'tier' ? (
        <div className="space-y-1">
          {cfg.stops.map((c, i) => (
            <div key={i} className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full flex-shrink-0" style={{ backgroundColor: c }} />
              <span className="text-[9px] text-zinc-400">{TIER_LABELS[i]}</span>
            </div>
          ))}
        </div>
      ) : (
        <>
          <div className="h-2 w-32 rounded-full" style={{ background: `linear-gradient(to right, ${cfg.stops.join(',')})` }} />
          <div className="flex justify-between mt-1 text-[8px] text-zinc-500"><span>Low</span><span>High</span></div>
        </>
      )}
    </div>
  )
}

export function SimProgressBar({ alpha }: { alpha: number }) {
  if (alpha <= 0.02) return null
  const pct = Math.round((1 - alpha) * 100)
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="absolute top-0 left-0 right-0 h-0.5 z-10"
    >
      <motion.div
        className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500"
        style={{ width: `${pct}%` }}
        transition={{ duration: 0.1 }}
      />
    </motion.div>
  )
}

export function EdgeBundlePanel({
  bundle,
  nodes,
  onClose,
}: {
  bundle: { sourceId: string; targetId: string; edges: GraphEdge[] }
  nodes: GraphNode[]
  onClose: () => void
}) {
  const src = nodes.find(n => n.id === bundle.sourceId)
  const tgt = nodes.find(n => n.id === bundle.targetId)
  const byCategory = useMemo(() => {
    const ACL = ['GENERIC_ALL','WRITE_DACL','WRITE_OWNER','OWNS','FORCE_CHANGE_PASSWORD','ADD_MEMBER']
    const DELEG = ['ALLOWED_TO_DELEGATE','ALLOWED_TO_ACT','S4U2SELF']
    const CRED = ['DCSYNC','PASS_THE_HASH','PASS_THE_TICKET','PASS_THE_CERT']
    const LATERAL = ['ADMIN_TO','LOCAL_ADMIN','DCOM_EXEC','WMI_EXEC','SCM_EXEC','REMOTE_EXEC']
    return {
      'ACL Abuse': bundle.edges.filter(e => ACL.includes(e.edge_type)),
      'Delegation': bundle.edges.filter(e => DELEG.includes(e.edge_type)),
      'Credential Access': bundle.edges.filter(e => CRED.includes(e.edge_type)),
      'Lateral Movement': bundle.edges.filter(e => LATERAL.includes(e.edge_type)),
      'Other': bundle.edges.filter(e =>
        ![...ACL,...DELEG,...CRED,...LATERAL].includes(e.edge_type)
      ),
    }
  }, [bundle.edges])

  return (
    <motion.div
      initial={{ opacity: 0, x: 18 }} animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 18 }}
      className="absolute bottom-4 right-16 z-40 w-80 rounded-2xl border border-white/10 bg-black/95 p-5 shadow-2xl backdrop-blur"
    >
      <div className="flex items-start justify-between gap-2 mb-3">
        <div>
          <div className="text-[11px] font-bold text-white">
            {src?.label ?? bundle.sourceId} → {tgt?.label ?? bundle.targetId}
          </div>
          <div className="text-[9px] text-zinc-500 mt-0.5">{bundle.edges.length} relationship types</div>
        </div>
        <button onClick={onClose} className="text-zinc-500 hover:text-white transition rounded-lg p-1">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="space-y-2">
        {Object.entries(byCategory).filter(([,edges]) => edges.length > 0).map(([cat, edges]) => (
          <div key={cat} className="rounded-xl border border-white/8 bg-black/60 p-3">
            <div className="text-[9px] uppercase tracking-widest text-zinc-500 mb-1.5">{cat}</div>
            {edges.map(e => {
              const w = e.risk_weight ?? 0
              const col = edgeRiskColor(w)
              return (
                <div key={e.id} className="flex items-center gap-2 py-0.5">
                  <span className="inline-flex rounded border px-1.5 py-0.5 text-[8px] font-bold uppercase"
                    style={{ borderColor: col+'60', color: col, backgroundColor: col+'15' }}>
                    {e.edge_type}
                  </span>
                  <span className="text-[9px] text-zinc-500 ml-auto">{(w*100).toFixed(0)}%</span>
                </div>
              )
            })}
          </div>
        ))}
      </div>
      <div className="mt-3 pt-3 border-t border-white/8">
        <div className="flex items-center justify-between">
          <span className="text-[9px] uppercase tracking-widest text-zinc-500">Max risk on this hop</span>
          <span className="text-[11px] font-bold" style={{
            color: edgeRiskColor(bundle.edges.reduce((m, e) => Math.max(m, e.risk_weight ?? 0), 0))
          }}>
            {(bundle.edges.reduce((m, e) => Math.max(m, e.risk_weight ?? 0), 0) * 100).toFixed(0)}%
          </span>
        </div>
        <div className="text-[9px] text-zinc-600 mt-0.5">
          {bundle.edges.length} distinct abuse paths between these two objects
        </div>
      </div>
    </motion.div>
  )
}

export function SavedViewsPanel({
  views,
  onLoad,
  onSave,
  onDelete,
  onClose,
}: {
  views: SavedGraphView[]
  onLoad: (view: SavedGraphView) => void
  onSave: (name: string) => void
  onDelete: (id: string) => void
  onClose: () => void
}) {
  const [newName, setNewName] = useState('')
  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -12 }}
      className="rounded-2xl border border-cyan-500/18 bg-black/95 shadow-2xl overflow-hidden backdrop-blur"
      style={{ width: 260 }}
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/8">
        <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-cyan-400">Saved Views</span>
        <button onClick={onClose} className="text-zinc-500 hover:text-white transition rounded-lg p-0.5">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="p-3 border-b border-white/6">
        <div className="flex gap-2">
          <input
            value={newName} onChange={e => setNewName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && newName.trim()) { onSave(newName.trim()); setNewName('') } }}
            placeholder="View name…"
            className="flex-1 rounded-xl border border-white/10 bg-black/60 px-2 py-1.5 text-[11px] text-white outline-none placeholder:text-zinc-600"
          />
          <button
            onClick={() => { if (newName.trim()) { onSave(newName.trim()); setNewName('') } }}
            disabled={!newName.trim()}
            className="rounded-xl border border-cyan-500/35 bg-cyan-500/15 px-3 py-1.5 text-[11px] text-cyan-300 disabled:opacity-40"
          >
            Save
          </button>
        </div>
      </div>
      <div className="max-h-64 overflow-y-auto py-1">
        {views.length === 0 && (
          <div className="px-4 py-6 text-center text-[11px] text-zinc-600">No saved views yet</div>
        )}
        {views.map(v => (
          <div key={v.id} className="flex items-center gap-2 px-3 py-2 hover:bg-white/5 group">
            <button onClick={() => onLoad(v)} className="flex-1 text-left">
              <div className="text-[11px] font-semibold text-zinc-200 truncate">{v.name}</div>
              <div className="text-[9px] text-zinc-600">{new Date(v.created_at).toLocaleDateString()}</div>
            </button>
            <button onClick={() => onDelete(v.id)}
              className="opacity-0 group-hover:opacity-100 text-zinc-600 hover:text-red-400 transition rounded p-0.5">
              <X className="h-3 w-3" />
            </button>
          </div>
        ))}
      </div>
    </motion.div>
  )
}

export function SnapshotTimelinePanel({
  snapshots,
  activeDiff,
  onSelectDiff,
  onCreateSnapshot,
  onClose,
}: {
  snapshots: SnapshotSummary[]
  activeDiff: { fromId: string; toId: string } | null
  onSelectDiff: (fromId: string, toId: string) => void
  onCreateSnapshot: () => void
  onClose: () => void
}) {
  const [fromIdx, setFromIdx] = useState(0)
  const [toIdx, setToIdx] = useState(Math.min(1, snapshots.length - 1))

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 12 }}
      className="absolute bottom-4 left-1/2 -translate-x-1/2 z-40 rounded-2xl border border-white/10 bg-black/95 p-4 shadow-2xl backdrop-blur"
      style={{ width: 480 }}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-purple-400">Timeline</span>
        <div className="flex items-center gap-2">
          <button onClick={onCreateSnapshot}
            className="rounded-xl border border-white/10 bg-black/60 px-3 py-1 text-[10px] text-zinc-400 hover:text-white transition">
            + Snapshot
          </button>
          <button onClick={onClose} className="text-zinc-500 hover:text-white transition rounded-lg p-0.5">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
      {snapshots.length < 2 ? (
        <div className="text-center text-[11px] text-zinc-600 py-4">
          Create at least 2 snapshots to compare timelines.
        </div>
      ) : (
        <>
          <div className="flex items-center gap-3 mb-3">
            <div className="flex-1">
              <div className="text-[9px] text-zinc-500 mb-1">From</div>
              <select value={fromIdx} onChange={e => setFromIdx(Number(e.target.value))}
                className="w-full rounded-xl border border-white/10 bg-black/60 px-2 py-1.5 text-[11px] text-white outline-none">
                {snapshots.map((s, i) => (
                  <option key={s.id} value={i}>
                    {s.label ?? new Date(s.created_at).toLocaleString()} ({s.node_count}N/{s.edge_count}E)
                  </option>
                ))}
              </select>
            </div>
            <div className="text-zinc-600 mt-4">→</div>
            <div className="flex-1">
              <div className="text-[9px] text-zinc-500 mb-1">To</div>
              <select value={toIdx} onChange={e => setToIdx(Number(e.target.value))}
                className="w-full rounded-xl border border-white/10 bg-black/60 px-2 py-1.5 text-[11px] text-white outline-none">
                {snapshots.map((s, i) => (
                  <option key={s.id} value={i}>
                    {s.label ?? new Date(s.created_at).toLocaleString()} ({s.node_count}N/{s.edge_count}E)
                  </option>
                ))}
              </select>
            </div>
          </div>
          <button
            onClick={() => onSelectDiff(snapshots[fromIdx].id, snapshots[toIdx].id)}
            disabled={fromIdx === toIdx}
            className="w-full rounded-xl border border-purple-500/35 bg-purple-500/15 py-2 text-[11px] font-semibold text-purple-300 disabled:opacity-40 disabled:pointer-events-none transition hover:bg-purple-500/25"
          >
            Show Diff
          </button>
          {activeDiff && (
            <div className="mt-2 flex items-center justify-center gap-4 text-[9px]">
              <span className="flex items-center gap-1 text-green-400">
                <span className="inline-block w-2 h-2 rounded-full bg-green-400" /> Added
              </span>
              <span className="flex items-center gap-1 text-red-400">
                <span className="inline-block w-2 h-2 rounded-full bg-red-400" /> Removed
              </span>
            </div>
          )}
        </>
      )}
    </motion.div>
  )
}

export function NarrationPanel({
  narration,
  onExportPlaybook,
  onMonteCarlo,
  onClose,
}: {
  narration: PathNarration
  onExportPlaybook: (format: 'markdown' | 'navigator_json') => void
  onMonteCarlo: () => void
  onClose: () => void
}) {
  return (
    <motion.div
      initial={{ opacity: 0, x: 18 }} animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 18 }}
      className="absolute top-4 right-16 z-40 w-96 max-h-[80vh] rounded-2xl border border-white/10 bg-black/97 shadow-2xl backdrop-blur flex flex-col"
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/8 flex-shrink-0">
        <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-amber-400">Attack Path Narration</span>
        <button onClick={onClose} className="text-zinc-500 hover:text-white transition">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="overflow-y-auto flex-1 p-4 space-y-3">
        <div className="rounded-xl border border-white/8 bg-black/60 p-3">
          <div className="text-[10px] text-zinc-400">{narration.source} → {narration.target}</div>
          <div className="text-[11px] text-white mt-1">{narration.summary}</div>
        </div>
        {narration.steps.map(step => (
          <div key={step.hop} className="rounded-xl border border-white/8 bg-black/60 p-3">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[9px] font-bold text-amber-400 bg-amber-400/10 border border-amber-400/20 rounded-full px-2 py-0.5">HOP {step.hop}</span>
              {step.technique_id && <span className="text-[9px] text-zinc-500">{step.technique_id}</span>}
            </div>
            <div className="text-[11px] font-semibold text-zinc-200">{step.technique_name}</div>
            {step.tool && (
              <details className="mt-2">
                <summary className="text-[9px] text-cyan-400 cursor-pointer">Tool Command</summary>
                <pre className="mt-1 text-[9px] text-zinc-400 bg-black/60 rounded p-2 overflow-x-auto whitespace-pre-wrap">{step.tool}</pre>
              </details>
            )}
            {step.remediation && (
              <details className="mt-1">
                <summary className="text-[9px] text-green-400 cursor-pointer">Remediation</summary>
                <pre className="mt-1 text-[9px] text-zinc-400 bg-black/60 rounded p-2 overflow-x-auto whitespace-pre-wrap">{step.remediation}</pre>
              </details>
            )}
          </div>
        ))}
      </div>
      <div className="px-4 py-3 border-t border-white/8 flex gap-2 flex-shrink-0">
        <button onClick={() => onExportPlaybook('markdown')}
          className="flex-1 rounded-xl border border-amber-500/35 bg-amber-500/10 py-1.5 text-[10px] text-amber-300 hover:bg-amber-500/20 transition">
          Export Markdown
        </button>
        <button onClick={() => onExportPlaybook('navigator_json')}
          className="flex-1 rounded-xl border border-white/10 bg-black/60 py-1.5 text-[10px] text-zinc-400 hover:text-white transition">
          ATT&CK Navigator
        </button>
        <button onClick={onMonteCarlo}
          className="flex-1 rounded-xl border border-purple-500/35 bg-purple-500/10 py-1.5 text-[10px] text-purple-300 hover:bg-purple-500/20 transition">
          P(success)
        </button>
      </div>
    </motion.div>
  )
}

export function AnomalyFeedPanel({
  anomalies,
  onFocusNode,
  onClose,
}: {
  anomalies: AnomalyResult[]
  onFocusNode: (id: string) => void
  onClose: () => void
}) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -12 }}
      className="rounded-2xl border border-orange-500/18 bg-black/95 shadow-2xl overflow-hidden backdrop-blur"
      style={{ width: 284 }}
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/8">
        <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-orange-400">
          Anomaly Feed {anomalies.length > 0 && `(${anomalies.length})`}
        </span>
        <button onClick={onClose} className="text-zinc-500 hover:text-white transition rounded-lg p-0.5">
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="max-h-[440px] overflow-y-auto py-1">
        {anomalies.length === 0 && (
          <div className="px-4 py-8 text-center text-[11px] text-zinc-600">No anomalies detected</div>
        )}
        {anomalies.map((a, i) => (
          <button key={i} onClick={() => onFocusNode(a.node_id)}
            className="w-full flex items-start gap-3 px-4 py-2.5 text-left hover:bg-white/5 transition group">
            <span className={cn(
              'flex-shrink-0 mt-0.5 rounded-full px-1.5 py-0.5 text-[8px] font-bold',
              a.severity === 'HIGH' ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'
            )}>
              {a.severity}
            </span>
            <div className="min-w-0">
              <div className="text-[11px] font-semibold text-zinc-200 truncate">{a.node_label}</div>
              <div className="text-[9px] text-zinc-600 mt-0.5">
                {a.reason === 'outlier_degree'
                  ? `${a.degree} edges — ${a.z_score}σ above average for ${a.node_type}`
                  : `New ${a.edge_type} → ${a.target_label}`}
              </div>
            </div>
          </button>
        ))}
      </div>
    </motion.div>
  )
}
