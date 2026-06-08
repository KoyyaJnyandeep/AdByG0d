'use client'
import { useState } from 'react'
import { ChevronDown, ChevronRight, Loader2, CheckCircle2, XCircle, Zap } from 'lucide-react'
import type { TraceItem } from '@/lib/agentEvents'

const TOOL_ICONS: Record<string, string> = {
  get_assessment_summary: '📋',
  list_findings: '🔍',
  get_entities: '👥',
  get_attack_paths: '🗺️',
  get_loot: '💎',
  get_graph_summary: '🕸️',
  execute_technique: '⚡',
  run_shell_command: '💻',
  crack_hashes: '🔓',
  parse_bloodhound: '🩸',
  simulate_attack_chain: '🎯',
  get_credential_intel: '🔑',
  save_to_memory: '💾',
  write_report_section: '📝',
  update_target_card: '📍',
  spawn_sub_agent: '🤖',
}

function TraceRow({ item }: { item: TraceItem }) {
  const [expanded, setExpanded] = useState(false)
  const hasArgs = Object.keys(item.args).length > 0
  const icon = TOOL_ICONS[item.tool] || '🔧'

  return (
    <div className="border-b border-white/5 last:border-0">
      <button
        onClick={() => hasArgs && setExpanded(e => !e)}
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-white/[0.03] transition-colors"
      >
        <span className="text-sm shrink-0">{icon}</span>
        <span className="text-xs text-zinc-300 font-mono flex-1 truncate">{item.tool}</span>
        {item.status === 'pending' && <Loader2 className="h-3 w-3 text-blue-400 animate-spin shrink-0" />}
        {item.status === 'done' && <CheckCircle2 className="h-3 w-3 text-emerald-400 shrink-0" />}
        {item.status === 'error' && <XCircle className="h-3 w-3 text-red-400 shrink-0" />}
        {item.duration_ms !== undefined && (
          <span className="text-[10px] text-zinc-600 shrink-0 font-mono">{item.duration_ms}ms</span>
        )}
        {hasArgs && (
          expanded
            ? <ChevronDown className="h-3 w-3 text-zinc-600 shrink-0" />
            : <ChevronRight className="h-3 w-3 text-zinc-600 shrink-0" />
        )}
      </button>
      {item.summary && (
        <p className="px-9 pb-1.5 text-[11px] text-zinc-500 font-mono truncate">{item.summary}</p>
      )}
      {expanded && hasArgs && (
        <pre className="px-9 pb-2 text-[10px] text-zinc-500 font-mono whitespace-pre-wrap break-all leading-relaxed">
          {JSON.stringify(item.args, null, 2)}
        </pre>
      )}
    </div>
  )
}

export function AgentTracePanel({
  items,
  isActive,
}: {
  items: TraceItem[]
  isActive: boolean
}) {
  const [collapsed, setCollapsed] = useState(false)
  if (items.length === 0) return null

  return (
    <div
      className="rounded-xl overflow-hidden my-2"
      style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      <button
        onClick={() => setCollapsed(c => !c)}
        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/[0.03] transition-colors"
      >
        <Zap className="h-3 w-3 text-violet-400 shrink-0" />
        <span className="text-[11px] font-semibold text-zinc-400 flex-1 text-left">
          {isActive ? 'N3mo is working…' : `${items.length} tool call${items.length !== 1 ? 's' : ''}`}
        </span>
        {isActive
          ? <Loader2 className="h-3 w-3 text-violet-400 animate-spin shrink-0" />
          : collapsed
            ? <ChevronRight className="h-3 w-3 text-zinc-600 shrink-0" />
            : <ChevronDown className="h-3 w-3 text-zinc-600 shrink-0" />
        }
      </button>
      {!collapsed && (
        <div>
          {items.map(item => <TraceRow key={item.id} item={item} />)}
        </div>
      )}
    </div>
  )
}
