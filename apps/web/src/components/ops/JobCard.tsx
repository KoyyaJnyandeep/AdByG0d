'use client'

import { useState } from 'react'
import { ChevronDown, ChevronUp, Square, Zap, CheckCircle, XCircle, Clock } from 'lucide-react'
import dynamic from 'next/dynamic'
import { cn, fmtTime } from '@/lib/utils'

const LiveOutputTerminal = dynamic(
  () => import('./LiveOutputTerminal'),
  { ssr: false }
)

interface Job {
  id: string
  technique_id: string
  target: string
  executor: string
  status: string
  opsec_profile: string
  created_at: string
  exit_code: number | null
}

interface JobCardProps {
  job: Job
  onKill?: (jobId: string) => void
}

const STATUS_ICON: Record<string, React.ReactNode> = {
  PENDING: <Clock size={14} className="text-amber-400" />,
  RUNNING: <Zap size={14} className="animate-pulse text-purple-400" />,
  COMPLETED: <CheckCircle size={14} className="text-emerald-400" />,
  FAILED: <XCircle size={14} className="text-rose-400" />,
  KILLED: <Square size={14} className="text-zinc-400" />,
}

export default function JobCard({ job, onKill }: JobCardProps) {
  const [expanded, setExpanded] = useState(job.status === 'RUNNING')

  return (
    <div
      className={cn(
        "mb-3 overflow-hidden rounded-xl border font-mono transition-colors",
        job.status === 'PENDING' && "border-amber-500/20 bg-amber-500/10",
        job.status === 'RUNNING' && "border-purple-500/20 bg-purple-500/10",
        job.status === 'COMPLETED' && "border-emerald-500/20 bg-emerald-500/10",
        job.status === 'FAILED' && "border-rose-500/20 bg-rose-500/10",
        job.status === 'KILLED' && "border-zinc-500/20 bg-zinc-500/10",
        !['PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'KILLED'].includes(job.status) && "border-purple-500/20 bg-[#140f28cc]"
      )}
    >
      <div
        className="flex cursor-pointer select-none items-center gap-2.5 p-3"
        onClick={() => setExpanded(e => !e)}
      >
        {STATUS_ICON[job.status] ?? <Clock size={14} />}
        <span className="text-[13px] font-semibold text-purple-400">
          {job.technique_id.toUpperCase()}
        </span>
        <span className="text-xs text-purple-200/50">
          → {job.target}
        </span>
        <span
          className={cn(
            "ml-auto rounded border px-1.5 py-0.5 text-[11px]",
            job.opsec_profile === 'LOUD' && "border-rose-500 text-rose-500",
            job.opsec_profile === 'BALANCED' && "border-amber-400 text-amber-400",
            job.opsec_profile === 'GHOST' && "border-emerald-400 text-emerald-400"
          )}
        >
          {job.opsec_profile}
        </span>
        {job.status === 'RUNNING' && onKill && (
          <button
            onClick={e => { e.stopPropagation(); onKill(job.id) }}
            className="ml-2 rounded border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] text-rose-500 transition-colors hover:bg-rose-500/25"
          >
            KILL
          </button>
        )}
        <span className="ml-2 text-[11px] text-purple-200/35">
          {fmtTime(job.created_at)}
        </span>
        {expanded ? <ChevronUp size={14} className="text-zinc-400" /> : <ChevronDown size={14} className="text-zinc-400" />}
      </div>
      {expanded && (
        <div className="h-80 border-t border-purple-500/15 bg-black">
          <LiveOutputTerminal jobId={job.id} />
        </div>
      )}
    </div>
  )
}
