'use client'

import Link from 'next/link'
import { useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  BarChart3,
  Database,
  FileText,
  LogOut,
  RefreshCw,
  Server,
  Settings,
  ShieldCheck,
  User,
  Bot,
} from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { authApi, assessmentApi } from '@/lib/api'
import { fmtNumber } from '@/lib/utils'
import { AIProviderSettings } from '@/components/settings/AIProviderSettings'

type HealthResponse = {
  ok: boolean
  version?: string
}

function statusTone(ok: boolean) {
  return ok
    ? 'border-emerald-500/25 bg-emerald-500/8 text-emerald-300'
    : 'border-red-500/25 bg-red-500/8 text-red-300'
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-white/[0.08] bg-black/80">
      <div className="border-b border-white/[0.06] px-5 py-4">
        <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </section>
  )
}

function Metric({
  label,
  value,
  detail,
  icon: Icon,
}: {
  label: string
  value: string | number
  detail: string
  icon: typeof Activity
}) {
  return (
    <div className="rounded-lg border border-white/[0.07] bg-white/[0.02] p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">{label}</div>
          <div className="mt-2 text-2xl font-semibold text-zinc-100">{value}</div>
          <div className="mt-1 text-xs text-zinc-500">{detail}</div>
        </div>
        <div className="rounded-md border border-white/[0.08] bg-black p-2 text-cyan-300">
          <Icon className="h-4 w-4" />
        </div>
      </div>
    </div>
  )
}

export default function SettingsPage() {
  const queryClient = useQueryClient()
  const [cacheMessage, setCacheMessage] = useState('')

  const { data: currentUser, isLoading: loadingUser } = useQuery({
    queryKey: ['auth-me'],
    queryFn: () => authApi.me(),
    staleTime: 60_000,
  })

  const { data: assessments = [], refetch: refetchAssessments, isFetching: fetchingAssessments } = useQuery({
    queryKey: ['assessments-settings'],
    queryFn: () => assessmentApi.list({ limit: 100 }),
    staleTime: 60_000,
  })

  const { data: health, isError: healthError, refetch: refetchHealth, isFetching: fetchingHealth } = useQuery({
    queryKey: ['api-health'],
    queryFn: async () => {
      const response = await fetch('/api/health', { cache: 'no-store' })
      if (!response.ok) throw new Error('API health check failed')
      return response.json() as Promise<HealthResponse>
    },
    staleTime: 30_000,
  })

  const posture = useMemo(() => {
    const completed = assessments.filter((item) => item.status === 'COMPLETED')
    const running = assessments.filter((item) => item.status === 'RUNNING').length
    const failed = assessments.filter((item) => item.status === 'FAILED').length
    const averageExposure = completed.length
      ? Math.round(completed.reduce((sum, item) => sum + (item.exposure_score ?? 0), 0) / completed.length)
      : 0

    return {
      total: assessments.length,
      completed: completed.length,
      running,
      failed,
      averageExposure,
    }
  }, [assessments])

  const refreshAll = async () => {
    await Promise.all([refetchAssessments(), refetchHealth()])
  }

  const clearUiCache = async () => {
    queryClient.clear()
    setCacheMessage('Local UI cache cleared')
    window.setTimeout(() => setCacheMessage(''), 2500)
  }

  const signOut = async () => {
    await authApi.logout().catch(() => undefined)
    window.location.href = '/login'
  }

  const apiOnline = Boolean(health?.ok) && !healthError

  return (
    <AppShell>
      <main className="min-h-full bg-transparent p-5 md:p-7">
        <div className="mx-auto max-w-7xl space-y-5">
          <header className="flex flex-col gap-4 rounded-lg border border-white/[0.08] bg-black/85 px-5 py-5 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="mb-2 inline-flex items-center gap-2 rounded-md border border-cyan-400/20 bg-cyan-400/10 px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.16em] text-cyan-300">
                <Settings className="h-3.5 w-3.5" />
                Admin Console
              </div>
              <h1 className="text-2xl font-semibold tracking-tight text-zinc-100">Settings</h1>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={refreshAll}
                disabled={fetchingAssessments || fetchingHealth}
                className="inline-flex items-center gap-2 rounded-md border border-white/[0.08] bg-white/[0.03] px-3 py-2 text-sm text-zinc-300 transition hover:border-white/15 hover:bg-white/[0.06] disabled:opacity-50"
              >
                <RefreshCw className={`h-4 w-4 ${fetchingAssessments || fetchingHealth ? 'animate-spin' : ''}`} />
                Refresh
              </button>
              <button
                type="button"
                onClick={signOut}
                className="inline-flex items-center gap-2 rounded-md border border-red-400/25 bg-red-500/10 px-3 py-2 text-sm text-red-200 transition hover:bg-red-500/15"
              >
                <LogOut className="h-4 w-4" />
                Sign out
              </button>
            </div>
          </header>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <Metric label="API" value={apiOnline ? 'Online' : 'Offline'} detail={health?.version ? `Version ${health.version}` : 'Health check'} icon={Server} />
            <Metric label="Session" value={loadingUser ? 'Loading' : currentUser ? 'Active' : 'Missing'} detail={currentUser?.is_superadmin ? 'Superadmin' : 'Standard access'} icon={ShieldCheck} />
            <Metric label="Assessments" value={fmtNumber(posture.total)} detail={`${posture.running} running, ${posture.failed} failed`} icon={Database} />
            <Metric label="Avg Exposure" value={posture.averageExposure} detail={`${posture.completed} completed scans`} icon={BarChart3} />
          </div>

          {/* ── AI Provider Settings ── */}
          <section className="rounded-lg border border-white/[0.08] bg-black/80">
            <div className="border-b border-white/[0.06] px-5 py-4 flex items-center gap-2">
              <Bot className="h-4 w-4 text-orange-400" />
              <h2 className="text-sm font-semibold text-zinc-100">AI Providers</h2>
              <span className="ml-auto text-[10px] text-zinc-600 font-mono">Claude · GPT-4o · Ollama</span>
            </div>
            <div className="p-5">
              <AIProviderSettings />
            </div>
          </section>

          <div className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
            <div className="space-y-5">
              <Panel title="Access">
                <div className="space-y-3">
                  <div className="flex items-center justify-between gap-4 rounded-md border border-white/[0.07] bg-white/[0.02] px-4 py-3">
                    <div className="flex items-center gap-3">
                      <User className="h-4 w-4 text-cyan-300" />
                      <span className="text-sm text-zinc-400">Signed in as</span>
                    </div>
                    <span className="font-mono text-sm text-zinc-100">{currentUser?.username ?? 'Unknown'}</span>
                  </div>
                  <div className="flex items-center justify-between gap-4 rounded-md border border-white/[0.07] bg-white/[0.02] px-4 py-3">
                    <div className="flex items-center gap-3">
                      <ShieldCheck className="h-4 w-4 text-cyan-300" />
                      <span className="text-sm text-zinc-400">Role</span>
                    </div>
                    <span className="font-mono text-sm text-zinc-100">{currentUser?.is_superadmin ? 'Superadmin' : 'User'}</span>
                  </div>
                  <div className={`flex items-center justify-between gap-4 rounded-md border px-4 py-3 ${statusTone(Boolean(currentUser?.is_active))}`}>
                    <span className="text-sm">Account state</span>
                    <span className="font-mono text-sm">{currentUser?.is_active ? 'Active' : 'Inactive'}</span>
                  </div>
                </div>
              </Panel>

              <Panel title="Local Controls">
                <div className="space-y-3">
                  <button
                    type="button"
                    onClick={clearUiCache}
                    className="flex w-full items-center justify-between rounded-md border border-white/[0.08] bg-white/[0.03] px-4 py-3 text-left text-sm text-zinc-300 transition hover:border-white/15 hover:bg-white/[0.06]"
                  >
                    <span>Clear UI cache</span>
                    <RefreshCw className="h-4 w-4 text-zinc-500" />
                  </button>
                  {cacheMessage && <div className="text-xs text-emerald-300">{cacheMessage}</div>}
                </div>
              </Panel>
            </div>

            <div className="space-y-5">
              <Panel title="Operations">
                <div className="grid gap-3 sm:grid-cols-2">
                  {[
                    { href: '/assessments', label: 'Assessments', detail: 'Create, import, delete, and review scans', icon: Activity },
                    { href: '/reports', label: 'Reports', detail: 'Generate exports from completed work', icon: FileText },
                    { href: '/audit', label: 'Audit Ledger', detail: 'Review platform activity', icon: ShieldCheck },
                    { href: '/connectivity', label: 'Pivoting Layer', detail: 'Manage transport profiles', icon: Server },
                  ].map((item) => (
                    <Link
                      key={item.href}
                      href={item.href}
                      className="rounded-md border border-white/[0.08] bg-white/[0.02] p-4 transition hover:border-cyan-400/25 hover:bg-cyan-400/[0.04]"
                    >
                      <div className="flex items-center gap-3 text-sm font-medium text-zinc-100">
                        <item.icon className="h-4 w-4 text-cyan-300" />
                        {item.label}
                      </div>
                      <div className="mt-2 text-xs leading-5 text-zinc-500">{item.detail}</div>
                    </Link>
                  ))}
                </div>
              </Panel>

              <Panel title="Scan State">
                <div className="divide-y divide-white/[0.06] rounded-md border border-white/[0.07]">
                  {[
                    ['Total assessments', fmtNumber(posture.total)],
                    ['Completed', fmtNumber(posture.completed)],
                    ['Running', fmtNumber(posture.running)],
                    ['Failed', fmtNumber(posture.failed)],
                    ['Average exposure', String(posture.averageExposure)],
                  ].map(([label, value]) => (
                    <div key={label} className="flex items-center justify-between px-4 py-3 text-sm">
                      <span className="text-zinc-500">{label}</span>
                      <span className="font-mono text-zinc-100">{value}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            </div>
          </div>
        </div>
      </main>
    </AppShell>
  )
}
