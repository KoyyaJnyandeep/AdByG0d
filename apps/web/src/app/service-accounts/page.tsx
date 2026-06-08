'use client'

import { useQuery } from '@tanstack/react-query'
import { AppShell } from '@/components/layout/AppShell'
import { serviceAccountsApi, type ServiceAccountEntry } from '@/lib/api'
import { Key, AlertTriangle, Clock, Shield, Loader2, Sparkles } from 'lucide-react'
import { cn, fmtDate, fmtNumber } from '@/lib/utils'
import { useRouteAssessmentScope } from '@/lib/useRouteAssessmentScope'

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-300 bg-red-500/10 border-red-400/20',
  HIGH: 'text-orange-300 bg-orange-500/10 border-orange-400/20',
  MEDIUM: 'text-yellow-300 bg-yellow-500/10 border-yellow-400/20',
  LOW: 'text-emerald-300 bg-emerald-500/10 border-emerald-400/20',
}

export default function ServiceAccountsPage() {
  const { assessment, assessmentId } = useRouteAssessmentScope()

  const { data: accounts = [], isLoading } = useQuery({
    queryKey: ['service-accounts', assessmentId],
    queryFn: () => serviceAccountsApi.list(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  const { data: summary } = useQuery({
    queryKey: ['service-accounts-summary', assessmentId],
    queryFn: () => serviceAccountsApi.summary(assessmentId!),
    enabled: !!assessmentId,
    staleTime: 60_000,
  })

  return (
    <AppShell>
      <div className="min-h-full page-bg p-8">
        <div className="mb-8 rounded-[28px] border border-white/10 bg-black p-8">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-medium text-cyan-200">
                <Key className="h-3.5 w-3.5" /> Service Identity Posture
              </div>
              <h1 className="mt-4 text-3xl font-semibold text-white">Service Accounts</h1>
              <p className="mt-2 max-w-2xl text-sm text-zinc-400">
                Track privileged service identities, delegation exposure, roastability, and password age from the latest assessment snapshot.
              </p>
            </div>
          </div>
        </div>

        <div className="mb-8 grid gap-4 xl:grid-cols-4">
          <div className="rounded-2xl border border-white/10 bg-black p-5">
            <div className="text-xs uppercase tracking-[0.22em] text-zinc-500">Accounts</div>
            <div className="mt-3 text-3xl font-semibold text-white">{fmtNumber(summary?.total ?? accounts.length)}</div>
            <div className="mt-2 text-sm text-zinc-400">{assessment?.domain ?? 'Selected assessment scope'}</div>
          </div>
          <div className="rounded-2xl border border-white/10 bg-black p-5">
            <div className="text-xs uppercase tracking-[0.22em] text-zinc-500">Privileged</div>
            <div className="mt-3 text-3xl font-semibold text-red-300">{fmtNumber(summary?.privileged ?? 0)}</div>
            <div className="mt-2 text-sm text-zinc-400">Admin or privileged group exposure</div>
          </div>
          <div className="rounded-2xl border border-white/10 bg-black p-5">
            <div className="text-xs uppercase tracking-[0.22em] text-zinc-500">Roastable</div>
            <div className="mt-3 text-3xl font-semibold text-orange-300">{fmtNumber(summary?.kerberoastable ?? 0)}</div>
            <div className="mt-2 text-sm text-zinc-400">Kerberoastable service identities</div>
          </div>
          <div className="rounded-2xl border border-white/10 bg-black p-5">
            <div className="text-xs uppercase tracking-[0.22em] text-zinc-500">Stale Passwords</div>
            <div className="mt-3 text-3xl font-semibold text-yellow-300">{fmtNumber(summary?.stale_password ?? 0)}</div>
            <div className="mt-2 text-sm text-zinc-400">Older than 180 days (backend threshold)</div>
          </div>
        </div>

        {isLoading && (
          <div className="flex min-h-[320px] items-center justify-center rounded-3xl border border-white/10 text-zinc-400">
            <div className="flex items-center gap-3 text-sm"><Loader2 className="w-5 h-5 animate-spin" /> Loading service accounts...</div>
          </div>
        )}

        {!isLoading && accounts.length === 0 && (
          <div className="rounded-3xl border border-white/10 bg-black p-10 text-center">
            <Sparkles className="mx-auto h-12 w-12 text-zinc-500" />
            <h2 className="mt-4 text-xl font-semibold text-white">No service accounts returned</h2>
            <p className="mt-2 text-sm text-zinc-400">This assessment does not currently expose service account entities.</p>
          </div>
        )}

        {!isLoading && accounts.length > 0 && (
          <div className="space-y-4">
            {accounts.map((account: ServiceAccountEntry) => (
              <div key={account.id} className="rounded-[24px] border border-white/10 bg-black p-5">
                <div className="flex items-start gap-4">
                  <div className="rounded-2xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-cyan-300"><Key className="h-5 w-5" /></div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="font-semibold text-white">{account.display_name || account.sam_account_name}</span>
                      <code className="font-mono text-xs text-zinc-500">{account.sam_account_name}</code>
                      <span className={cn('ml-auto rounded-full border px-3 py-1 text-xs font-semibold', RISK_COLORS[account.risk])}>{account.risk}</span>
                    </div>
                    <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-zinc-400">
                      {account.password_age_days > 0 && (
                        <span className="inline-flex items-center gap-1"><Clock className="h-3 w-3" /> Password age {account.password_age_days}d</span>
                      )}
                      {account.last_logon && <span>Last logon {fmtDate(account.last_logon)}</span>}
                      {account.tier !== undefined && account.tier !== null && <span>Tier {account.tier}</span>}
                    </div>
                    <div className="mt-4 flex flex-wrap gap-2">
                      {account.kerberoastable && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-orange-500/10 px-3 py-1 text-xs text-orange-300">
                          <AlertTriangle className="h-3 w-3" /> Kerberoastable
                        </span>
                      )}
                      {account.asrep_roastable && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-orange-500/10 px-3 py-1 text-xs text-orange-300">
                          <AlertTriangle className="h-3 w-3" /> AS-REP Roastable
                        </span>
                      )}
                      {account.unconstrained_delegation && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-3 py-1 text-xs text-red-300">
                          <AlertTriangle className="h-3 w-3" /> Unconstrained Delegation
                        </span>
                      )}
                      {account.in_privileged_group && account.privileged_groups.length === 0 && (
                        <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-3 py-1 text-xs text-red-300">
                          <Shield className="h-3 w-3" /> Privileged
                        </span>
                      )}
                      {account.privileged_groups.map(group => (
                        <span key={group} className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-3 py-1 text-xs text-red-300">
                          <Shield className="h-3 w-3" /> {group}
                        </span>
                      ))}
                      {account.spns.map(spn => (
                        <span key={spn} className="rounded-full bg-black px-3 py-1 font-mono text-xs text-zinc-300">{spn}</span>
                      ))}
                      {account.password_age_days > 180 && (
                        <span className="rounded-full bg-yellow-500/10 px-3 py-1 text-xs text-yellow-300">
                          Password stale ({account.password_age_days}d)
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </AppShell>
  )
}
