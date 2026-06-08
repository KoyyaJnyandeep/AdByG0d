'use client'
import { useState, useEffect, useCallback } from 'react'
import { Shield, AlertTriangle, Check, X, Clock } from 'lucide-react'
import type { ApprovalRequiredEvent } from '@/lib/agentEvents'

const OPSEC_STYLES: Record<string, { bg: string; border: string; text: string }> = {
  QUIET:    { bg: 'rgba(52,211,153,0.08)',  border: 'rgba(52,211,153,0.25)',  text: '#34d399' },
  MEDIUM:   { bg: 'rgba(251,191,36,0.08)',  border: 'rgba(251,191,36,0.25)',  text: '#fbbf24' },
  LOUD:     { bg: 'rgba(249,115,22,0.08)',  border: 'rgba(249,115,22,0.25)',  text: '#f97316' },
  CRITICAL: { bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.25)',   text: '#ef4444' },
}

const TTL_SECONDS = 300

export function ApprovalCard({
  event,
  onApprove,
  onReject,
}: {
  event: ApprovalRequiredEvent
  onApprove: () => Promise<void>
  onReject: () => Promise<void>
}) {
  const [secondsLeft, setSecondsLeft] = useState(TTL_SECONDS)
  const [loading, setLoading] = useState<'approve' | 'reject' | null>(null)
  const colors = OPSEC_STYLES[event.opsec_rating] ?? OPSEC_STYLES.MEDIUM

  const handleReject = useCallback(async () => {
    if (loading) return
    setLoading('reject')
    try { await onReject() } finally { setLoading(null) }
  }, [loading, onReject])

  useEffect(() => {
    const interval = setInterval(() => {
      setSecondsLeft(s => {
        if (s <= 1) {
          clearInterval(interval)
          void handleReject()
          return 0
        }
        return s - 1
      })
    }, 1000)
    return () => clearInterval(interval)
  }, [handleReject])

  const formatTime = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`

  const handleApprove = async () => {
    if (loading) return
    setLoading('approve')
    try { await onApprove() } finally { setLoading(null) }
  }

  return (
    <div
      className="rounded-xl overflow-hidden my-3"
      style={{ background: colors.bg, border: `1px solid ${colors.border}` }}
    >
      {/* Header */}
      <div
        className="flex items-center gap-2 px-4 py-3 border-b"
        style={{ borderColor: colors.border }}
      >
        <Shield className="h-4 w-4 shrink-0" style={{ color: colors.text }} />
        <span className="text-sm font-bold flex-1" style={{ color: colors.text }}>
          N3mo wants to execute
        </span>
        <span
          className="text-[10px] font-bold px-2 py-0.5 rounded-full"
          style={{ background: colors.bg, border: `1px solid ${colors.border}`, color: colors.text }}
        >
          {event.opsec_rating}
        </span>
        <div className="flex items-center gap-1 text-[10px] text-zinc-500">
          <Clock className="h-3 w-3" />
          <span className="font-mono">{formatTime(secondsLeft)}</span>
        </div>
      </div>

      {/* Content */}
      <div className="px-4 py-3 space-y-2">
        <p className="text-sm text-zinc-200">{event.description}</p>
        <div
          className="rounded-lg px-3 py-2 font-mono text-[11px] text-zinc-400 leading-relaxed"
          style={{ background: 'rgba(0,0,0,0.3)' }}
        >
          <div><span className="text-zinc-600">tool: </span>{event.tool}</div>
          {Object.entries(event.args).map(([k, v]) => (
            <div key={k}>
              <span className="text-zinc-600">{k}: </span>
              {typeof v === 'object' ? JSON.stringify(v) : String(v)}
            </div>
          ))}
        </div>
        {event.opsec_note && (
          <div className="flex items-start gap-1.5 text-[11px] text-zinc-500">
            <AlertTriangle className="h-3 w-3 shrink-0 mt-0.5" style={{ color: colors.text }} />
            <span>{event.opsec_note}</span>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex gap-2 px-4 pb-3">
        <button
          onClick={() => void handleApprove()}
          disabled={!!loading}
          className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-bold transition-all disabled:opacity-50"
          style={{ background: 'rgba(52,211,153,0.12)', border: '1px solid rgba(52,211,153,0.35)', color: '#34d399' }}
        >
          <Check className="h-3.5 w-3.5" />
          {loading === 'approve' ? 'Approving…' : 'Approve'}
        </button>
        <button
          onClick={() => void handleReject()}
          disabled={!!loading}
          className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-bold transition-all disabled:opacity-50"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#ef4444' }}
        >
          <X className="h-3.5 w-3.5" />
          {loading === 'reject' ? 'Rejecting…' : 'Reject'}
        </button>
      </div>
    </div>
  )
}
