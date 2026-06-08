'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ShieldAlert, ChevronDown, ChevronRight, AlertTriangle,
  Shield, Zap, Info, Target, Lock, Eye
} from 'lucide-react'
import { trustAbuseApi } from '@/lib/api'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'
import type { TrustAbuseTechnique, TrustAbuseChain } from '@/lib/types'

const SEVERITY_COLORS = {
  CRITICAL: 'text-red-400 border-red-500/40 bg-red-500/10',
  HIGH: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  MEDIUM: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
  LOW: 'text-blue-400 border-blue-500/40 bg-blue-500/10',
}

const TIER_LABELS: Record<number, string> = {
  1: 'T1 Standard',
  2: 'T2 Advanced',
  3: 'T3 Bleeding Edge',
}

const TIER_COLORS: Record<number, string> = {
  1: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  2: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  3: 'bg-red-500/20 text-red-300 border-red-500/30',
}

function StatTile({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className={`rounded-lg border p-4 ${color}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-sm mt-1 opacity-80">{label}</div>
    </div>
  )
}

function ChainCard({ chain }: { chain: TrustAbuseChain }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-lg border border-red-500/30 bg-red-500/5 p-4"
    >
      <div className="flex items-center gap-2 mb-2">
        <Zap className="w-4 h-4 text-red-400" />
        <span className="font-semibold text-red-300">{chain.name}</span>
        <span className={`ml-auto text-xs px-2 py-0.5 rounded border ${SEVERITY_COLORS[chain.severity]}`}>
          {chain.severity}
        </span>
      </div>
      <div className="flex items-center gap-2 flex-wrap mt-2">
        {chain.steps.map((step, i) => (
          <span key={step} className="flex items-center gap-1">
            <span className="text-xs text-zinc-400 bg-zinc-800 px-2 py-0.5 rounded font-mono">{step}</span>
            {i < chain.steps.length - 1 && <ChevronRight className="w-3 h-3 text-zinc-500" />}
          </span>
        ))}
      </div>
    </motion.div>
  )
}

function TechniqueCard({
  technique,
  selected,
  onClick,
}: {
  technique: TrustAbuseTechnique
  selected: boolean
  onClick: () => void
}) {
  return (
    <motion.button
      onClick={onClick}
      className={`w-full text-left rounded-lg border p-3 transition-all ${
        selected
          ? 'border-indigo-500/60 bg-indigo-500/10'
          : 'border-zinc-700/50 bg-zinc-900/40 hover:border-zinc-600'
      }`}
      whileHover={{ scale: 1.005 }}
    >
      <div className="flex items-center gap-2 mb-1">
        <span className={`text-xs px-1.5 py-0.5 rounded border ${TIER_COLORS[technique.tier] || TIER_COLORS[2]}`}>
          {TIER_LABELS[technique.tier] || `T${technique.tier}`}
        </span>
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
    </motion.button>
  )
}

function DetailPanel({ technique }: { technique: TrustAbuseTechnique }) {
  const [stepsOpen, setStepsOpen] = useState(true)
  const [remOpen, setRemOpen] = useState(false)

  return (
    <motion.div
      key={technique.technique_id}
      initial={{ opacity: 0, x: 12 }}
      animate={{ opacity: 1, x: 0 }}
      className="h-full overflow-y-auto space-y-4"
    >
      <div>
        <h2 className="text-lg font-bold text-zinc-100">{technique.name}</h2>
        <div className="flex items-center gap-2 mt-2 flex-wrap">
          <span className={`text-xs px-2 py-0.5 rounded border ${SEVERITY_COLORS[technique.severity]}`}>
            {technique.severity}
          </span>
          <span className={`text-xs px-2 py-0.5 rounded border ${TIER_COLORS[technique.tier] || TIER_COLORS[2]}`}>
            {TIER_LABELS[technique.tier]}
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

export default function TrustAbusePage() {
  const { assessmentId } = useRouteAssessmentScope()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [tierFilter, setTierFilter] = useState<number | null>(null)
  const [severityFilter, setSeverityFilter] = useState<string | null>(null)

  const { data: report, isLoading } = useQuery({
    queryKey: ['trust-abuse', assessmentId],
    queryFn: () => trustAbuseApi.getReport(assessmentId!),
    enabled: !!assessmentId,
  })

  const techniques = report?.techniques ?? []
  const chains = report?.chains ?? []
  const summary = report?.summary

  const filtered = techniques.filter(t => {
    if (tierFilter && t.tier !== tierFilter) return false
    if (severityFilter && t.severity !== severityFilter) return false
    return true
  })

  const selected = filtered.find(t => t.technique_id === selectedId) ?? filtered[0] ?? null

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
          <ShieldAlert className="w-10 h-10 mx-auto mb-3 text-zinc-600" />
          <p>Select an assessment to view trust abuse analysis</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6 h-full flex flex-col">
      <div className="flex items-center gap-3">
        <ShieldAlert className="w-6 h-6 text-red-400" />
        <div>
          <h1 className="text-xl font-bold text-zinc-100">Trust Abuse</h1>
          <p className="text-sm text-zinc-500">Active Directory trust exploitation catalogue</p>
        </div>
      </div>

      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <StatTile label="Techniques" value={summary.total_techniques} color="border-zinc-700 bg-zinc-900/50 text-zinc-100" />
          <StatTile label="Critical" value={summary.critical_count} color="border-red-500/40 bg-red-500/10 text-red-400" />
          <StatTile label="High" value={summary.high_count} color="border-orange-500/40 bg-orange-500/10 text-orange-400" />
          <StatTile label="Medium" value={summary.medium_count} color="border-yellow-500/40 bg-yellow-500/10 text-yellow-400" />
          <StatTile label="Chains" value={summary.chains_detected} color="border-purple-500/40 bg-purple-500/10 text-purple-400" />
        </div>
      )}

      {chains.length > 0 && (
        <div className="space-y-2">
          <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-2">
            <Zap className="w-4 h-4 text-red-400" />
            Attack Chains Detected
          </h2>
          {chains.map(c => <ChainCard key={c.chain_id} chain={c} />)}
        </div>
      )}

      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex gap-2">
          {[null, 1, 2, 3].map(tier => (
            <button
              key={String(tier)}
              onClick={() => setTierFilter(tier)}
              className={`text-xs px-3 py-1.5 rounded-full border transition-all ${
                tierFilter === tier
                  ? 'border-indigo-500 bg-indigo-500/20 text-indigo-300'
                  : 'border-zinc-700 text-zinc-400 hover:border-zinc-500'
              }`}
            >
              {tier === null ? 'All' : TIER_LABELS[tier]}
            </button>
          ))}
        </div>
        <select
          value={severityFilter ?? ''}
          onChange={e => setSeverityFilter(e.target.value || null)}
          className="text-xs bg-zinc-900 border border-zinc-700 rounded px-3 py-1.5 text-zinc-300"
        >
          <option value="">All Severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <span className="text-xs text-zinc-500 ml-auto">{filtered.length} techniques</span>
      </div>

      <div className="flex-1 grid grid-cols-5 gap-4 min-h-0 overflow-hidden">
        <div className="col-span-2 overflow-y-auto space-y-2 pr-1">
          {filtered.map(t => (
            <TechniqueCard
              key={t.technique_id}
              technique={t}
              selected={t.technique_id === (selected?.technique_id ?? '')}
              onClick={() => setSelectedId(t.technique_id)}
            />
          ))}
          {filtered.length === 0 && (
            <div className="text-center py-12 text-zinc-500">
              <Info className="w-8 h-8 mx-auto mb-2" />
              <p>No techniques match the current filters</p>
            </div>
          )}
        </div>

        <div className="col-span-3 overflow-hidden">
          {selected ? (
            <DetailPanel technique={selected} />
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
