'use client'

import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  Zap, CheckCircle2, ArrowRight, ChevronDown, ChevronUp,
  TrendingDown, AlertTriangle, Shield, Clock, Target, Loader2,
} from 'lucide-react'

import { findingsApi, remediationApi } from '@/lib/api'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { ProvenanceBadge } from '@/components/ui/ProvenanceBadge'
import { Finding } from '@/lib/types'
import { cn, fmtScore, moduleColor } from '@/lib/utils'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'

const COMPLEXITY_EFFORT: Record<string, string> = {
  trivial: '< 30 min', low: '1-2 hours', medium: '1-2 days', high: '1-2 weeks',
}

export function RemediationSimulator() {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const { assessment, assessmentId, routeFindingId } = useRouteAssessmentScope({ inferFromFinding: true })

  const { data: findingsData, isLoading } = useQuery({
    queryKey: ['remediation-findings', assessmentId],
    queryFn: () => findingsApi.list({ assessment_id: assessmentId!, page_size: 25, sort_by: 'composite_score', sort_desc: true }),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const findings = useMemo(
    () => (findingsData?.items ?? []).filter((f: Finding) => ['OPEN', 'IN_REVIEW', 'REGRESSED'].includes(f.status)).slice(0, 12),
    [findingsData],
  )

  const simulation = useMutation({
    mutationFn: () => remediationApi.simulate({ assessment_id: assessmentId!, finding_ids: Array.from(selected) }),
  })

  useEffect(() => {
    if (!routeFindingId || !findings.some((finding) => finding.id === routeFindingId)) return
    setSelected((current) => current.has(routeFindingId) ? current : new Set([...current, routeFindingId]))
    setExpandedId(routeFindingId)
  }, [findings, routeFindingId])

  const toggleSelect = (id: string) => {
    setSelected(curr => {
      const next = new Set(curr)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  if (!assessmentId && !isLoading) return (
    <div className="flex min-h-full items-center justify-center p-8 text-center text-zinc-400">
      <div>
        <Shield className="mx-auto h-12 w-12 opacity-30" />
        <div className="mt-4 text-lg font-medium text-zinc-200">No assessment data available</div>
        <div className="mt-2 text-sm">Run an assessment first so remediation simulation has real findings to work with.</div>
      </div>
    </div>
  )

  return (
    <div className="flex min-h-full flex-col page-bg">
      <div className="sticky top-0 z-20 border-b border-white/10 bg-black px-8 py-5">
        <div className="flex items-center justify-between gap-6">
          <div>
            <h1 className="text-2xl font-semibold text-white">Remediation Simulator</h1>
            <p className="mt-1 text-sm text-zinc-400">Select evidence-backed findings from {assessment?.domain ?? 'the selected assessment'} to model potential exposure reduction before you touch production. Results stay labeled as simulation.</p>
          </div>
          <button
            onClick={() => simulation.mutate()}
            disabled={!assessmentId || selected.size === 0 || simulation.isPending}
            className={cn('btn-primary text-sm', (!assessmentId || selected.size === 0 || simulation.isPending) && 'cursor-not-allowed opacity-50')}
          >
            {simulation.isPending
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Simulating...</>
              : <><Zap className="w-4 h-4" /> Simulate {selected.size > 0 ? `(${selected.size})` : ''}</>}
          </button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="flex-1 overflow-y-auto p-6 space-y-3">
          <div className="mb-4 text-sm font-medium text-zinc-300">Choose findings to include in the remediation model</div>
          {isLoading && (
            <div className="flex items-center gap-3 rounded-2xl border border-white/10 bg-black px-5 py-4 text-sm text-zinc-400">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading live findings...
            </div>
          )}
          {!isLoading && findings.length === 0 && (
            <div className="rounded-2xl border border-white/10 bg-black px-5 py-4 text-sm text-zinc-400">No open findings are currently available for remediation simulation.</div>
          )}
          {findings.map(finding => (
            <div key={finding.id} className={cn('rounded-[24px] border p-5 transition-all', selected.has(finding.id) ? 'border-cyan-400/30 bg-cyan-400/10' : 'border-white/10 bg-black hover:bg-white/[0.05]')}>
              <div className="flex items-start gap-4">
                <button
                  onClick={() => toggleSelect(finding.id)}
                  className={cn('mt-0.5 flex h-5 w-5 items-center justify-center rounded border-2 transition-all', selected.has(finding.id) ? 'border-cyan-300 bg-cyan-300 text-[#050816]' : 'border-zinc-600 text-transparent hover:border-cyan-300')}
                >
                  <CheckCircle2 className="h-3.5 w-3.5" />
                </button>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-3">
                    <SeverityBadge severity={finding.severity} />
                    <span className="text-sm font-medium text-white">{finding.title}</span>
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-zinc-400">
                    <ProvenanceBadge origin={finding.origin} className="text-[10px]" />
                    <span className="flex items-center gap-1"><Target className="w-3 h-3" /> Score: {fmtScore(finding.composite_score ?? 0)}</span>
                    <span className="flex items-center gap-1" style={{ color: moduleColor(finding.module) }}>● {finding.module}</span>
                    <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {COMPLEXITY_EFFORT[finding.fix_complexity || 'medium']}</span>
                    <span>{finding.affected_count} affected</span>
                  </div>
                  <button
                    onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
                    className="mt-3 flex items-center gap-1 text-xs text-zinc-400 transition-colors hover:text-zinc-200"
                  >
                    Remediation steps
                    {expandedId === finding.id ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                  </button>
                  {expandedId === finding.id && (
                    <div className="mt-3 space-y-2 border-l border-white/10 pl-4 text-xs text-zinc-300">
                      {(finding.remediation_steps ?? []).length > 0
                        ? finding.remediation_steps.map((step, i) => (
                            <div key={i} className="flex gap-2"><span className="text-zinc-500">{i + 1}.</span><span>{String(step)}</span></div>
                          ))
                        : <div>{finding.remediation || 'No remediation steps were recorded for this finding.'}</div>}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="w-96 border-l border-white/10 bg-black">
          <div className="border-b border-white/10 p-5">
            <div className="text-sm font-semibold text-white">Simulation Results</div>
            <div className="mt-1 text-xs text-zinc-400">{selected.size === 0 ? 'Select findings to model' : `${selected.size} live finding${selected.size === 1 ? '' : 's'} selected`}</div>
          </div>

          {simulation.isError && (
            <div className="mx-5 mb-1 flex items-center gap-2 rounded-lg border border-red-400/20 bg-red-400/10 p-3 text-sm text-red-300">
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              <span>Simulation failed — check connectivity and try again.</span>
            </div>
          )}

          {simulation.data ? (
            <div className="space-y-5 p-5">
              <div className="rounded-2xl border border-white/10 bg-black p-4 text-center">
                <div className="mb-3 flex items-center justify-center gap-2">
                  <ProvenanceBadge origin={simulation.data.origin} />
                  <span className="text-[11px] uppercase tracking-[0.2em] text-zinc-500">{simulation.data.mode.replaceAll('_', ' ')}</span>
                </div>
                <div className="text-xs uppercase tracking-[0.2em] text-zinc-500">Risk Reduction</div>
                <div className="mt-3 flex items-center justify-center gap-4">
                  <div>
                    <div className="text-3xl font-bold text-red-300">{assessment?.exposure_score?.toFixed?.(1) ?? '0.0'}</div>
                    <div className="text-xs text-zinc-500">Before</div>
                  </div>
                  <ArrowRight className="h-5 w-5 text-emerald-300" />
                  <div>
                    <div className="text-3xl font-bold text-emerald-300">{Math.max((assessment?.exposure_score ?? 0) - simulation.data.risk_reduction_pct, 0).toFixed(1)}</div>
                    <div className="text-xs text-zinc-500">Estimated After</div>
                  </div>
                </div>
                <div className="mt-3 inline-flex items-center gap-1.5 text-sm font-medium text-emerald-300"><TrendingDown className="h-4 w-4" /> −{simulation.data.risk_reduction_pct.toFixed(1)}%</div>
              </div>

              <div className="rounded-2xl border border-white/10 bg-black p-4 text-sm text-zinc-300">
                <div className="mb-3 text-xs text-zinc-500">{simulation.data.estimate_basis}</div>
                <div className="flex items-center justify-between"><span>Paths eliminated</span><span className="text-white">{simulation.data.paths_eliminated}</span></div>
                <div className="mt-2 flex items-center justify-between"><span>Paths remaining</span><span className="text-white">{simulation.data.paths_remaining}</span></div>
              </div>

              <div>
                <div className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Recommended Fix Order</div>
                <div className="space-y-2">
                  {simulation.data.fix_order.map((item: { finding_id: string; title: string; effort: string; impact: string }, i: number) => (
                    <div key={item.finding_id} className="flex items-center gap-3 rounded-2xl border border-white/10 bg-black p-3">
                      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-cyan-400/15 text-xs font-bold text-cyan-200">{i + 1}</span>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm font-medium text-white">{item.title}</div>
                        <div className="text-xs text-zinc-400">{item.effort}</div>
                      </div>
                      <span className="text-xs text-emerald-300">{item.impact}</span>
                    </div>
                  ))}
                </div>
              </div>

              {simulation.data.operational_impact?.length > 0 && (
                <div>
                  <div className="mb-3 text-xs font-semibold uppercase tracking-[0.2em] text-zinc-500">Operational Considerations</div>
                  <div className="space-y-2">
                    {simulation.data.operational_impact.map((impact: string, i: number) => (
                      <div key={i} className="flex items-start gap-2 rounded-2xl border border-yellow-400/15 bg-yellow-400/5 p-3 text-xs text-zinc-300">
                        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 text-yellow-300" />
                        <span>{impact}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex h-full flex-col items-center justify-center px-6 text-center text-zinc-400">
              <Zap className="mb-4 h-12 w-12 opacity-20" />
              <div className="text-sm font-medium">No simulation yet</div>
              <div className="mt-1 text-xs">Select evidence-backed findings and run a clearly labeled simulation to preview estimated remediation impact.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
