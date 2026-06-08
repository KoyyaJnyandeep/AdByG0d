'use client'
import { Loader2, CheckCircle2, Bot } from 'lucide-react'

export interface SubAgentState {
  agent_id: string
  task: string
  status: string
  done: boolean
  summary?: string
}

export function SubAgentStatusRow({ agents }: { agents: SubAgentState[] }) {
  if (agents.length === 0) return null

  return (
    <div className="my-2 space-y-1">
      {agents.map(a => (
        <div
          key={a.agent_id}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-[11px]"
          style={{ background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.12)' }}
        >
          <Bot className="h-3 w-3 text-violet-400 shrink-0" />
          <span className="text-zinc-400 font-mono flex-1 truncate">{a.task}</span>
          {a.done ? (
            <>
              {a.summary && (
                <span className="text-emerald-400 truncate max-w-[160px]">{a.summary}</span>
              )}
              <CheckCircle2 className="h-3 w-3 text-emerald-400 shrink-0" />
            </>
          ) : (
            <>
              <span className="text-blue-400 truncate max-w-[120px]">{a.status}</span>
              <Loader2 className="h-3 w-3 text-blue-400 animate-spin shrink-0" />
            </>
          )}
        </div>
      ))}
    </div>
  )
}
