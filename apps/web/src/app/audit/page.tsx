'use client'

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { History, Info, Loader2, Search, ShieldCheck } from 'lucide-react'

import { AppShell } from '@/components/layout/AppShell'
import { auditApi } from '@/lib/api'
import { cn, fmtDateTime } from '@/lib/utils'
import type { AuditLogEntry } from '@/lib/types'

function actionClass(action: string) {
  if (action.includes('DELETE') || action.includes('FAILED')) {
    return 'border-rose-500/20 bg-rose-500/10 text-rose-300'
  }
  if (action.includes('LOGIN') || action.includes('AUTH')) {
    return 'border-cyan-500/20 bg-cyan-500/10 text-cyan-300'
  }
  if (action.includes('REPORT') || action.includes('REMEDIATION') || action.includes('VALIDATION')) {
    return 'border-amber-500/20 bg-amber-500/10 text-amber-300'
  }
  return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
}

export default function AuditPage() {
  const [filter, setFilter] = useState('')

  const { data: logs = [], isLoading, isRefetching } = useQuery<AuditLogEntry[]>({
    queryKey: ['audit-logs'],
    queryFn: () => auditApi.list({ limit: 100 }),
    refetchInterval: 15_000,
    staleTime: 10_000,
  })

  const filteredLogs = useMemo(() => {
    const query = filter.trim().toLowerCase()
    if (!query) {
      return logs
    }

    return logs.filter((entry) => {
      const details = JSON.stringify(entry.details ?? {}).toLowerCase()
      return [entry.action, entry.resource_type, entry.resource_id, entry.ip_address, details]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query))
    })
  }, [filter, logs])

  return (
    <AppShell>
      <div className="min-h-full bg-black p-8">
        <div className="mb-8 flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-indigo-400/20 bg-indigo-400/10 px-3 py-1 text-xs font-medium text-indigo-200">
              <History className="h-3.5 w-3.5" /> Governance & Compliance
            </div>
            <h1 className="mt-4 text-3xl font-semibold tracking-tight text-white">Audit Ledger</h1>
            <p className="mt-2 max-w-2xl text-sm text-zinc-400">
              Live audit trail for authentication, mutating API operations, validation runs, and report or remediation actions.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="rounded-full border border-white/10 bg-black px-3 py-2 text-xs text-zinc-400">
              {filteredLogs.length} visible, {logs.length} total
            </div>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter actions, ids, IPs..."
                className="rounded-xl border border-white/10 bg-black py-2 pl-10 pr-4 text-sm text-white outline-none transition focus:border-indigo-500/50"
              />
            </div>
          </div>
        </div>

        <div className="overflow-hidden rounded-[28px] border border-white/10 bg-black">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="border-b border-white/10 bg-black">
                <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Timestamp</th>
                <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Action</th>
                <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Resource</th>
                <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Origin</th>
                <th className="px-6 py-4 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {isLoading ? (
                <tr>
                  <td colSpan={5} className="px-6 py-20 text-center text-zinc-500">
                    <div className="flex flex-col items-center gap-4">
                      <Loader2 className="h-6 w-6 animate-spin text-indigo-300" />
                      <span className="text-sm font-medium">Synchronizing audit records...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-20 text-center text-zinc-500">
                    <div className="flex flex-col items-center gap-4">
                      <ShieldCheck className="h-8 w-8 text-zinc-600" />
                      <div>
                        <div className="text-sm font-medium text-zinc-300">No audit entries yet</div>
                        <div className="mt-1 text-xs text-zinc-500">Mutating platform actions will appear here automatically.</div>
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="transition hover:bg-white/[0.02]">
                    <td className="whitespace-nowrap px-6 py-4">
                      <span className="text-xs font-mono text-zinc-400">
                        {fmtDateTime(log.created_at)}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className={cn('inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wider', actionClass(log.action))}>
                        {log.action.replaceAll('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-col">
                        <span className="text-xs font-semibold text-zinc-200">{log.resource_type || 'GLOBAL'}</span>
                        <span className="font-mono text-[10px] text-zinc-500">{log.resource_id || '—'}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-xs font-mono text-zinc-500">{log.ip_address || 'internal'}</span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex max-w-md items-center gap-2 text-xs text-zinc-400">
                        <Info className="h-3 w-3 flex-shrink-0 text-zinc-600" />
                        <span className="truncate">{JSON.stringify(log.details ?? {})}</span>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {isRefetching && !isLoading && (
          <div className="mt-4 text-right text-xs text-zinc-500">Refreshing audit feed...</div>
        )}
      </div>
    </AppShell>
  )
}
