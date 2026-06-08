'use client'

import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { ArrowLeftRight, ArrowRight, CheckCircle2, FlaskConical, Loader2, Network, Shield, Sparkles, AlertTriangle, TrendingDown, TrendingUp } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { findingsApi, trustsApi, trustAbuseApi, type TrustEntry, type TrustSimOverride } from '@/lib/api'
import { cn, fmtNumber } from '@/lib/utils'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'

const DIRECTION_ICON = {
  BIDIRECTIONAL: ArrowLeftRight,
  INBOUND: ArrowRight,
  OUTBOUND: ArrowRight,
}

export default function TrustsPage() {
  const { assessmentId } = useRouteAssessmentScope()

  const { data: trusts = [], isLoading: trustsLoading } = useQuery({
    queryKey: ['trusts', assessmentId],
    queryFn: () => trustsApi.list(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: trustSummary } = useQuery({
    queryKey: ['trusts-summary', assessmentId],
    queryFn: () => trustsApi.summary(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: trustFindings } = useQuery({
    queryKey: ['trust-findings', assessmentId],
    queryFn: () => findingsApi.list({ assessment_id: assessmentId!, module: 'Trust', page_size: 25 }),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const trustAlerts = trustFindings?.items ?? []
  const sidFilteringOff = trustSummary?.sid_filtering_off ?? trusts.filter((t: TrustEntry) => !t.sid_filtering).length
  const selectiveAuthOff = trustSummary?.selective_auth_off ?? trusts.filter((t: TrustEntry) => !t.selective_auth).length
  const forestTrusts = trustSummary?.forest_trusts ?? trusts.filter((t: TrustEntry) => String(t.trust_type).includes('FOREST')).length

  // What-if simulator state
  const [simOverrides, setSimOverrides] = useState<Record<string, TrustSimOverride>>({})

  const simulateMutation = useMutation({
    mutationFn: () =>
      trustAbuseApi.simulate(assessmentId!, Object.values(simOverrides)),
  })

  function toggleSidFiltering(trustName: string, currentValue: boolean) {
    setSimOverrides((prev) => ({
      ...prev,
      [trustName]: { ...prev[trustName], trust_name: trustName, sid_filtering: !currentValue },
    }))
  }

  function toggleSelectiveAuth(trustName: string, currentValue: boolean) {
    setSimOverrides((prev) => ({
      ...prev,
      [trustName]: { ...prev[trustName], trust_name: trustName, selective_auth: !currentValue },
    }))
  }

  function resetSim() {
    setSimOverrides({})
    simulateMutation.reset()
  }

  const simResult = simulateMutation.data

  return (
    <AppShell>
      <div className="min-h-full page-bg p-8">
        <div className="mb-8 rounded-[28px] border border-white/10 bg-black p-8">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-medium text-cyan-200">
                <Network className="h-3.5 w-3.5" /> Trust Mapping
              </div>
              <h1 className="mt-4 text-3xl font-semibold text-white">Trusts & Hybrid</h1>
              <p className="mt-2 max-w-2xl text-sm text-zinc-400">
                Live trust relationship view derived from trust entities and trust-related findings. If the assessment has no trust data, this page now says so directly instead of fabricating a map.
              </p>
            </div>
          </div>
        </div>

        <div className="mb-8 grid gap-4 xl:grid-cols-4">
          {[
            { label: 'Total Trusts', value: fmtNumber(trusts.length), accent: 'var(--accent1)' },
            { label: 'SID Filtering Off', value: sidFilteringOff, accent: '#fb7185' },
            { label: 'Selective Auth Off', value: selectiveAuthOff, accent: '#facc15' },
            { label: 'Forest Trusts', value: forestTrusts, accent: '#a78bfa' },
          ].map((card) => (
            <div key={card.label} className="rounded-2xl border border-white/10 bg-black p-5">
              <div className="text-xs uppercase tracking-[0.22em] text-zinc-500">{card.label}</div>
              <div className="mt-3 text-3xl font-semibold text-white">{card.value}</div>
              <div className="mt-2 h-1.5 w-20 rounded-full" style={{ backgroundColor: `${card.accent}66` }} />
            </div>
          ))}
        </div>

        {trustsLoading && (
          <div className="mb-6 flex items-center gap-3 rounded-2xl border border-white/10 bg-black px-5 py-4 text-sm text-zinc-400">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading trust relationships...
          </div>
        )}

        {!trustsLoading && !assessmentId && (
          <div className="rounded-3xl border border-white/10 bg-black p-10 text-center">
            <Sparkles className="mx-auto h-12 w-12 text-zinc-500" />
            <h2 className="mt-4 text-xl font-semibold text-white">No assessment loaded</h2>
            <p className="mt-2 text-sm text-zinc-400">Run an assessment before reviewing trust posture.</p>
          </div>
        )}

        {!trustsLoading && assessmentId && trusts.length === 0 && (
          <div className="rounded-3xl border border-white/10 bg-black p-10 text-center">
            <Shield className="mx-auto h-12 w-12 text-zinc-500" />
            <h2 className="mt-4 text-xl font-semibold text-white">No trust entities returned</h2>
            <p className="mt-2 text-sm text-zinc-400">This assessment does not currently include trust objects or hybrid trust metadata.</p>
          </div>
        )}

        {trusts.length > 0 && (
          <div className="space-y-6">
            <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
              <div className="space-y-4">
                {trusts.map((trust) => {
                  const DirIcon = DIRECTION_ICON[trust.direction as keyof typeof DIRECTION_ICON] ?? ArrowRight
                  const riskColor = trust.risk === 'HIGH'
                    ? 'text-orange-300 bg-orange-500/10 border-orange-400/20'
                    : trust.risk === 'CRITICAL'
                      ? 'text-red-300 bg-red-500/10 border-red-400/20'
                      : trust.risk === 'MEDIUM'
                        ? 'text-yellow-300 bg-yellow-500/10 border-yellow-400/20'
                        : 'text-emerald-300 bg-emerald-500/10 border-emerald-400/20'

                  const ovr = simOverrides[trust.target] ?? {}
                  const simSidFiltering = ovr.sid_filtering ?? trust.sid_filtering
                  const simSelectiveAuth = ovr.selective_auth ?? trust.selective_auth
                  const hasOverride = Object.keys(ovr).length > 0

                  return (
                    <div key={trust.id} className={cn('rounded-[24px] border bg-black p-6 transition-colors', hasOverride ? 'border-violet-400/30' : 'border-white/10')}>
                      <div className="flex items-start gap-4">
                        <div className="rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-cyan-300"><Network className="h-5 w-5" /></div>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-3">
                            <span className="font-mono text-sm font-semibold text-white">{trust.source}</span>
                            <DirIcon className="h-4 w-4 text-zinc-500" />
                            <span className="font-mono text-sm font-semibold text-white">{trust.target}</span>
                            <span className={cn('ml-auto rounded-full border px-3 py-1 text-xs font-semibold', riskColor)}>{trust.risk}</span>
                          </div>
                          <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-zinc-400">
                            <span>{trust.trust_type}</span>
                            <span>·</span>
                            <span>{trust.direction}</span>
                            <span>·</span>
                            <span>{trust.transitive ? 'Transitive' : 'Non-transitive'}</span>
                          </div>
                          <div className="mt-4 flex flex-wrap gap-2">
                            <button
                              type="button"
                              onClick={() => toggleSidFiltering(trust.target, simSidFiltering)}
                              className={cn('rounded-full border px-3 py-1 text-xs transition-colors', simSidFiltering ? 'border-emerald-400/20 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20' : 'border-red-400/20 bg-red-500/10 text-red-300 hover:bg-red-500/20')}
                              title="Click to toggle in simulator"
                            >
                              {simSidFiltering ? <CheckCircle2 className="mr-1 inline h-3.5 w-3.5" /> : <AlertTriangle className="mr-1 inline h-3.5 w-3.5" />}
                              SID filtering {simSidFiltering ? 'enabled' : 'disabled'}
                              {ovr.sid_filtering !== undefined && <span className="ml-1 text-violet-300">(sim)</span>}
                            </button>
                            <button
                              type="button"
                              onClick={() => toggleSelectiveAuth(trust.target, simSelectiveAuth)}
                              className={cn('rounded-full border px-3 py-1 text-xs transition-colors', simSelectiveAuth ? 'border-emerald-400/20 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20' : 'border-yellow-400/20 bg-yellow-500/10 text-yellow-300 hover:bg-yellow-500/20')}
                              title="Click to toggle in simulator"
                            >
                              {simSelectiveAuth ? <CheckCircle2 className="mr-1 inline h-3.5 w-3.5" /> : <AlertTriangle className="mr-1 inline h-3.5 w-3.5" />}
                              selective auth {simSelectiveAuth ? 'on' : 'off'}
                              {ovr.selective_auth !== undefined && <span className="ml-1 text-violet-300">(sim)</span>}
                            </button>
                          </div>
                          <p className="mt-4 text-sm leading-6 text-zinc-400">{trust.notes}</p>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>

              <div className="space-y-6">
                <div className="rounded-[24px] border border-white/10 bg-black p-6">
                  <h2 className="text-lg font-semibold text-white">Trust findings</h2>
                  <div className="mt-4 space-y-3">
                    {trustAlerts.length > 0 ? trustAlerts.slice(0, 6).map((finding) => (
                      <div key={finding.id} className="rounded-2xl border border-white/10 bg-black p-4">
                        <div className="flex items-center justify-between gap-3">
                          <div className="text-sm font-medium text-white">{finding.title}</div>
                          <span className="rounded-full border border-white/10 px-2.5 py-1 text-xs text-zinc-300">{finding.severity}</span>
                        </div>
                        <div className="mt-2 text-xs text-zinc-400">{finding.module} · {finding.status}</div>
                      </div>
                    )) : (
                      <div className="rounded-2xl border border-white/10 bg-black p-4 text-sm text-zinc-400">No trust-specific findings were returned for the selected assessment.</div>
                    )}
                  </div>
                </div>

                <div className="rounded-[24px] border border-white/10 bg-black p-6">
                  <h2 className="text-lg font-semibold text-white">Operator notes</h2>
                  <div className="mt-4 space-y-3 text-sm text-zinc-300">
                    <div className="rounded-2xl border border-white/10 bg-black p-4">Trust risk posture is derived from live trust entities first, then enriched with trust findings when available.</div>
                    <div className="rounded-2xl border border-white/10 bg-black p-4">Missing trust data is now represented as an honest empty state instead of demo fallback content.</div>
                    <div className="rounded-2xl border border-white/10 bg-black p-4">SID filtering and selective authentication remain the highest-signal posture indicators in this view.</div>
                  </div>
                </div>
              </div>
            </div>

            {/* What-if Simulator Panel */}
            <div className="rounded-[28px] border border-violet-400/20 bg-black p-6">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="rounded-2xl border border-violet-400/20 bg-violet-400/10 p-2.5 text-violet-300">
                    <FlaskConical className="h-5 w-5" />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-white">What-if Simulator</h2>
                    <p className="text-xs text-zinc-400">Click SID filtering / selective auth badges above to stage changes, then run the simulation.</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {Object.keys(simOverrides).length > 0 && (
                    <button
                      type="button"
                      onClick={resetSim}
                      className="rounded-full border border-white/10 bg-black px-4 py-2 text-xs text-zinc-300 hover:bg-white/5"
                    >
                      Reset
                    </button>
                  )}
                  <button
                    type="button"
                    disabled={!assessmentId || simulateMutation.isPending}
                    onClick={() => simulateMutation.mutate()}
                    className="flex items-center gap-2 rounded-full bg-violet-600 px-5 py-2 text-sm font-medium text-white hover:bg-violet-500 disabled:opacity-50"
                  >
                    {simulateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FlaskConical className="h-4 w-4" />}
                    Run simulation
                  </button>
                </div>
              </div>

              {Object.keys(simOverrides).length > 0 && (
                <div className="mt-4 flex flex-wrap gap-2">
                  {Object.entries(simOverrides).map(([name, ovr]) => (
                    <div key={name} className="rounded-full border border-violet-400/20 bg-violet-400/10 px-3 py-1 text-xs text-violet-200">
                      <span className="font-mono">{name}</span>
                      {ovr.sid_filtering !== undefined && <span className="ml-1">· SID filtering → {ovr.sid_filtering ? 'on' : 'off'}</span>}
                      {ovr.selective_auth !== undefined && <span className="ml-1">· selective auth → {ovr.selective_auth ? 'on' : 'off'}</span>}
                    </div>
                  ))}
                </div>
              )}

              {simulateMutation.isError && (
                <div className="mt-4 flex items-center gap-2 rounded-xl border border-red-400/20 bg-red-400/10 p-3 text-sm text-red-300">
                  <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                  Simulation failed — check API connectivity and retry.
                </div>
              )}

              {simResult && (
                <div className="mt-6 space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                    {[
                      { label: 'Baseline techniques', value: simResult.baseline.technique_count },
                      { label: 'Simulated techniques', value: simResult.simulated.technique_count },
                      { label: 'Net technique change', value: simResult.delta.net_technique_change, signed: true },
                      { label: 'Pivot path change', value: simResult.delta.pivot_path_change, signed: true },
                    ].map((stat) => {
                      const isNeg = typeof stat.value === 'number' && stat.value < 0
                      const isPos = typeof stat.value === 'number' && stat.value > 0
                      return (
                        <div key={stat.label} className="rounded-2xl border border-white/10 bg-zinc-900/60 p-4">
                          <div className="text-xs text-zinc-500">{stat.label}</div>
                          <div className={cn('mt-2 flex items-center gap-2 text-2xl font-semibold', stat.signed ? (isNeg ? 'text-emerald-300' : isPos ? 'text-red-300' : 'text-white') : 'text-white')}>
                            {stat.signed && isNeg && <TrendingDown className="h-5 w-5" />}
                            {stat.signed && isPos && <TrendingUp className="h-5 w-5" />}
                            {stat.signed && stat.value > 0 ? `+${stat.value}` : stat.value}
                          </div>
                        </div>
                      )
                    })}
                  </div>

                  {simResult.delta.techniques_eliminated.length > 0 && (
                    <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/5 p-4">
                      <div className="text-xs font-medium text-emerald-300">Techniques eliminated by proposed changes</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {simResult.delta.techniques_eliminated.map((t) => (
                          <span key={t} className="rounded-full border border-emerald-400/20 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-200">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {simResult.delta.techniques_introduced.length > 0 && (
                    <div className="rounded-2xl border border-red-400/20 bg-red-400/5 p-4">
                      <div className="text-xs font-medium text-red-300">Techniques introduced by proposed changes</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {simResult.delta.techniques_introduced.map((t) => (
                          <span key={t} className="rounded-full border border-red-400/20 bg-red-500/10 px-3 py-1 text-xs text-red-200">{t}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {simResult.delta.techniques_eliminated.length === 0 && simResult.delta.techniques_introduced.length === 0 && (
                    <div className="rounded-2xl border border-white/10 bg-zinc-900/60 p-4 text-sm text-zinc-400">
                      The proposed changes have no effect on detected attack techniques.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </AppShell>
  )
}
