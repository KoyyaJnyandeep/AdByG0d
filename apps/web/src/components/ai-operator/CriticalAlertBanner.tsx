'use client'
import { useState } from 'react'
import { AlertOctagon, X, ChevronDown } from 'lucide-react'
import type { CriticalAlertEvent } from '@/lib/agentEvents'

export function CriticalAlertBanner({
  alerts,
  onDismiss,
}: {
  alerts: CriticalAlertEvent[]
  onDismiss: (idx: number) => void
}) {
  const [expanded, setExpanded] = useState<number | null>(0)
  if (alerts.length === 0) return null

  return (
    <div className="mb-3 space-y-1.5">
      {alerts.map((alert, idx) => (
        <div
          key={idx}
          className="rounded-xl overflow-hidden"
          style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.3)' }}
        >
          <div className="flex items-center gap-2 px-3 py-2">
            <AlertOctagon className="h-4 w-4 text-red-400 shrink-0 animate-pulse" />
            <span className="text-sm font-bold text-red-300 flex-1 truncate">{alert.title}</span>
            <button
              onClick={() => setExpanded(expanded === idx ? null : idx)}
              className="text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              <ChevronDown
                className="h-3.5 w-3.5 transition-transform"
                style={{ transform: expanded === idx ? 'rotate(180deg)' : 'none' }}
              />
            </button>
            <button
              onClick={() => onDismiss(idx)}
              className="text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          {expanded === idx && (
            <div className="px-4 pb-3 space-y-1.5">
              <p className="text-xs text-zinc-400">{alert.detail}</p>
              <div
                className="text-xs text-red-300 font-mono px-2 py-1.5 rounded-lg leading-relaxed"
                style={{ background: 'rgba(239,68,68,0.08)' }}
              >
                → {alert.recommended_action}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
