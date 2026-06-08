'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  TreePine, ChevronDown, ChevronRight, Shield,
  Eye, Target, Lock, AlertTriangle, ArrowRight
} from 'lucide-react'
import { forestPivotApi } from '@/lib/api'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'
import type { ForestPivotTechnique, ForestPivotPath, ForestGraph } from '@/lib/types'

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-400 border-red-500/40 bg-red-500/10',
  HIGH: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  MEDIUM: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
  LOW: 'text-blue-400 border-blue-500/40 bg-blue-500/10',
}

const RISK_EDGE_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#6b7280',
}

function ForestTopologyDiagram({ graph }: { graph: ForestGraph }) {
  if (!graph.nodes.length) {
    return (
      <div className="flex items-center justify-center h-full text-zinc-600 text-sm">
        No forest topology data
      </div>
    )
  }

  const svgW = 600
  const svgH = 400

  return (
    <svg
      viewBox={`0 0 ${svgW} ${svgH}`}
      className="w-full h-full"
      style={{ background: 'transparent' }}
    >
      {graph.edges.map((edge, i) => {
        const src = graph.nodes.find(n => n.id === edge.source)
        const tgt = graph.nodes.find(n => n.id === edge.target)
        if (!src || !tgt) return null
        const color = RISK_EDGE_COLORS[edge.risk] ?? '#6b7280'
        const strokeDash = edge.transitive ? 'none' : '6 3'
        const midX = (src.x + tgt.x) / 2
        const midY = (src.y + tgt.y) / 2
        return (
          <g key={i}>
            <line
              x1={src.x} y1={src.y}
              x2={tgt.x} y2={tgt.y}
              stroke={color}
              strokeWidth={2}
              strokeDasharray={strokeDash}
              strokeOpacity={0.7}
            />
            <circle cx={midX} cy={midY} r={4} fill={color} fillOpacity={0.8} />
            <text x={midX + 6} y={midY - 4} fill={color} fontSize={9} opacity={0.8}>
              {edge.risk}
            </text>
          </g>
        )
      })}

      {graph.nodes.map(node => (
        <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
          <circle r={24} fill="#1f2937" stroke="#4b5563" strokeWidth={1.5} />
          {node.has_adcs && (
            <circle r={28} fill="none" stroke="#f59e0b" strokeWidth={1.5} strokeDasharray="3 2" />
          )}
          <text
            textAnchor="middle"
            dominantBaseline="middle"
            fill="#e5e7eb"
            fontSize={9}
            fontWeight={600}
          >
            {node.label.split('.')[0].substring(0, 10)}
          </text>
          <text
            y={36}
            textAnchor="middle"
            fill="#9ca3af"
            fontSize={8}
          >
            {node.label.length > 20 ? node.label.substring(0, 20) + '…' : node.label}
          </text>
          {node.has_adcs && (
            <text y={-32} textAnchor="middle" fill="#f59e0b" fontSize={8}>ADCS</text>
          )}
        </g>
      ))}

      <g transform="translate(10, 360)">
        {[
          { risk: 'CRITICAL', color: '#ef4444' },
          { risk: 'HIGH', color: '#f97316' },
          { risk: 'MEDIUM', color: '#eab308' },
          { risk: 'LOW', color: '#6b7280' },
        ].map((item, i) => (
          <g key={item.risk} transform={`translate(${i * 90}, 0)`}>
            <line x1={0} y1={5} x2={20} y2={5} stroke={item.color} strokeWidth={2} />
            <text x={24} y={9} fill="#9ca3af" fontSize={9}>{item.risk}</text>
          </g>
        ))}
        <g transform="translate(360, 0)">
          <line x1={0} y1={5} x2={20} y2={5} stroke="#6b7280" strokeWidth={2} strokeDasharray="6 3" />
          <text x={24} y={9} fill="#9ca3af" fontSize={9}>Non-transitive</text>
        </g>
      </g>
    </svg>
  )
}

function PivotPathCard({ path, selected, onClick }: {
  path: ForestPivotPath
  selected: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-lg border p-3 transition-all text-sm ${
        selected
          ? 'border-indigo-500/60 bg-indigo-500/10'
          : 'border-zinc-700/50 bg-zinc-900/40 hover:border-zinc-600'
      }`}
    >
      <div className="flex items-center gap-1.5 flex-wrap">
        {path.path.map((domain, i) => (
          <span key={i} className="flex items-center gap-1">
            <span className="text-xs font-mono text-zinc-300 bg-zinc-800 px-1.5 py-0.5 rounded">
              {domain.split('.')[0]}
            </span>
            {i < path.path.length - 1 && (
              <ArrowRight className="w-3 h-3 text-zinc-500" />
            )}
          </span>
        ))}
      </div>
      <div className="text-xs text-zinc-500 mt-1">{path.hops} hop{path.hops !== 1 ? 's' : ''}</div>
    </button>
  )
}

function TechniqueListItem({ technique, selected, onClick }: {
  technique: ForestPivotTechnique
  selected: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-lg border p-3 transition-all ${
        selected
          ? 'border-indigo-500/60 bg-indigo-500/10'
          : 'border-zinc-700/50 bg-zinc-900/40 hover:border-zinc-600'
      }`}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className={`text-xs px-1.5 py-0.5 rounded border ${SEVERITY_COLORS[technique.severity]}`}>
          {technique.severity}
        </span>
        {technique.cve && (
          <span className="text-xs text-orange-300 bg-orange-500/10 border border-orange-500/30 px-1.5 py-0.5 rounded ml-auto">
            {technique.cve}
          </span>
        )}
      </div>
      <div className="font-medium text-sm text-zinc-100">{technique.name}</div>
      {technique.mitre_id && (
        <div className="text-xs text-zinc-500 mt-0.5 font-mono">{technique.mitre_id}</div>
      )}
    </button>
  )
}

function TechniquePanel({ technique }: { technique: ForestPivotTechnique }) {
  const [stepsOpen, setStepsOpen] = useState(true)
  const [remOpen, setRemOpen] = useState(false)

  return (
    <motion.div
      key={technique.technique_id}
      initial={{ opacity: 0, x: 10 }}
      animate={{ opacity: 1, x: 0 }}
      className="space-y-4"
    >
      <div>
        <h3 className="font-bold text-zinc-100">{technique.name}</h3>
        <div className="flex items-center gap-2 mt-2 flex-wrap">
          <span className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_COLORS[technique.severity]}`}>
            {technique.severity}
          </span>
          {technique.mitre_id && (
            <span className="text-xs text-blue-300 font-mono bg-blue-500/10 border border-blue-500/30 px-2 py-0.5 rounded">
              MITRE {technique.mitre_id}
            </span>
          )}
          {technique.cve && (
            <span className="text-xs text-orange-300 bg-orange-500/10 border border-orange-500/30 px-2 py-0.5 rounded">
              {technique.cve}
            </span>
          )}
        </div>
      </div>

      {technique.opsec_notes && (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-3">
          <div className="flex items-center gap-2 text-yellow-400 mb-2 text-xs font-semibold uppercase tracking-wider">
            <Eye className="w-3.5 h-3.5" />
            OPSEC Notes
          </div>
          <p className="text-sm text-zinc-300">{technique.opsec_notes}</p>
        </div>
      )}

      <div className="rounded-lg border border-zinc-700/50 overflow-hidden">
        <button
          onClick={() => setStepsOpen(v => !v)}
          className="w-full flex items-center gap-2 px-4 py-3 text-sm font-semibold text-zinc-200 bg-zinc-800/50 hover:bg-zinc-800"
        >
          <Target className="w-4 h-4 text-red-400" />
          Attack Steps
          {stepsOpen ? <ChevronDown className="w-4 h-4 ml-auto" /> : <ChevronRight className="w-4 h-4 ml-auto" />}
        </button>
        <AnimatePresence>
          {stepsOpen && (
            <motion.ol
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="list-none space-y-2 p-4"
            >
              {technique.attack_steps.map((step, i) => (
                <li key={i} className="flex items-start gap-3 text-sm text-zinc-300">
                  <span className="mt-0.5 flex-shrink-0 w-5 h-5 rounded-full bg-red-500/20 text-red-400 text-xs flex items-center justify-center font-bold">
                    {i + 1}
                  </span>
                  {step}
                </li>
              ))}
            </motion.ol>
          )}
        </AnimatePresence>
      </div>

      <div className="rounded-lg border border-zinc-700/50 overflow-hidden">
        <button
          onClick={() => setRemOpen(v => !v)}
          className="w-full flex items-center gap-2 px-4 py-3 text-sm font-semibold text-zinc-200 bg-zinc-800/50 hover:bg-zinc-800"
        >
          <Shield className="w-4 h-4 text-green-400" />
          Remediation
          {remOpen ? <ChevronDown className="w-4 h-4 ml-auto" /> : <ChevronRight className="w-4 h-4 ml-auto" />}
        </button>
        <AnimatePresence>
          {remOpen && (
            <motion.ul
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="list-none space-y-2 p-4"
            >
              {technique.remediation_steps.map((step, i) => (
                <li key={i} className="flex items-start gap-3 text-sm text-zinc-300">
                  <Lock className="w-3.5 h-3.5 mt-0.5 text-green-400 flex-shrink-0" />
                  {step}
                </li>
              ))}
            </motion.ul>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  )
}

export default function ForestPivotingPage() {
  const { assessmentId } = useRouteAssessmentScope()
  const [selectedPath, setSelectedPath] = useState<number | null>(null)
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null)

  const { data: report, isLoading } = useQuery({
    queryKey: ['forest-pivot', assessmentId],
    queryFn: () => forestPivotApi.getReport(assessmentId!),
    enabled: !!assessmentId,
  })

  const techniques = report?.techniques ?? []
  const pivotPaths = report?.pivot_paths ?? []
  const graph = report?.graph ?? { nodes: [], edges: [] }
  const summary = report?.summary

  const activeTechnique =
    techniques.find(t => t.technique_id === selectedTechnique) ??
    techniques[0] ??
    null

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-zinc-500">
        <div className="animate-spin rounded-full w-8 h-8 border-2 border-indigo-500 border-t-transparent" />
      </div>
    )
  }

  if (!assessmentId) {
    return (
      <div className="flex items-center justify-center h-64 text-zinc-500">
        <div className="text-center">
          <TreePine className="w-10 h-10 mx-auto mb-3 text-zinc-600" />
          <p>Select an assessment to view forest pivoting analysis</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-5 h-full flex flex-col">
      <div className="flex items-center gap-3">
        <TreePine className="w-6 h-6 text-green-400" />
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Forest Pivoting</h1>
          <p className="text-sm text-zinc-500">Cross-forest attack topology and technique analysis</p>
        </div>
      </div>

      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: 'Techniques', value: summary.total_techniques, color: 'border-zinc-700 bg-zinc-900/50 text-zinc-100' },
            { label: 'Critical', value: summary.critical_count, color: 'border-red-500/40 bg-red-500/10 text-red-400' },
            { label: 'High', value: summary.high_count, color: 'border-orange-500/40 bg-orange-500/10 text-orange-400' },
            { label: 'Forests', value: summary.forest_count, color: 'border-green-500/40 bg-green-500/10 text-green-400' },
            { label: 'Pivot Paths', value: summary.pivot_paths_count, color: 'border-purple-500/40 bg-purple-500/10 text-purple-400' },
          ].map(s => (
            <div key={s.label} className={`rounded-lg border p-4 ${s.color}`}>
              <div className="text-2xl font-bold">{s.value}</div>
              <div className="text-sm mt-1 opacity-80">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-zinc-700/50 bg-zinc-900/30 p-3" style={{ height: 260 }}>
        <div className="text-xs text-zinc-500 mb-2 uppercase tracking-wider">Forest Trust Topology</div>
        <ForestTopologyDiagram graph={graph} />
      </div>

      <div className="flex-1 grid grid-cols-7 gap-4 min-h-0 overflow-hidden">
        <div className="col-span-2 flex flex-col overflow-hidden">
          <div className="text-xs text-zinc-500 uppercase tracking-wider mb-2">Pivot Paths ({pivotPaths.length})</div>
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {pivotPaths.length === 0 ? (
              <div className="text-center py-8 text-zinc-600 text-sm">No pivot paths detected</div>
            ) : (
              pivotPaths.map((p, i) => (
                <PivotPathCard
                  key={i}
                  path={p}
                  selected={selectedPath === i}
                  onClick={() => setSelectedPath(i)}
                />
              ))
            )}
          </div>
        </div>

        <div className="col-span-2 flex flex-col overflow-hidden">
          <div className="text-xs text-zinc-500 uppercase tracking-wider mb-2">Techniques ({techniques.length})</div>
          <div className="flex-1 overflow-y-auto space-y-2 pr-1">
            {techniques.length === 0 ? (
              <div className="text-center py-8 text-zinc-600 text-sm">No techniques detected</div>
            ) : (
              techniques.map(t => (
                <TechniqueListItem
                  key={t.technique_id}
                  technique={t}
                  selected={t.technique_id === (activeTechnique?.technique_id ?? '')}
                  onClick={() => setSelectedTechnique(t.technique_id)}
                />
              ))
            )}
          </div>
        </div>

        <div className="col-span-3 overflow-y-auto pl-2 border-l border-zinc-800">
          {activeTechnique ? (
            <TechniquePanel technique={activeTechnique} />
          ) : (
            <div className="flex items-center justify-center h-full text-zinc-600">
              <div className="text-center">
                <AlertTriangle className="w-8 h-8 mx-auto mb-2" />
                <p className="text-sm">Select a technique to view details</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
