'use client'
import { useState, useEffect } from 'react'
import { BookOpen, Play, Loader2 } from 'lucide-react'
import { approvalApi } from '@/lib/approvalApi'

interface Playbook {
  filename: string
  name: string
  description: string
  step_count: number
}

export function PlaybookSelector({ onLaunch }: { onLaunch: (name: string) => void }) {
  const [open, setOpen] = useState(false)
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setLoading(true)
    setError(null)
    approvalApi.listPlaybooks()
      .then((d: unknown) => {
        const data = d as { playbooks?: Playbook[] }
        setPlaybooks(data.playbooks ?? [])
      })
      .catch(() => setError('Failed to load playbooks'))
      .finally(() => setLoading(false))
  }, [open])

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all"
        style={{
          background: 'rgba(167,139,250,0.08)',
          border: '1px solid rgba(167,139,250,0.2)',
          color: '#a78bfa',
        }}
      >
        <BookOpen className="h-3 w-3" />
        Playbooks
      </button>

      {open && (
        <div
          className="absolute bottom-full mb-2 left-0 w-72 rounded-xl overflow-hidden z-50"
          style={{ background: 'rgba(10,10,15,0.98)', border: '1px solid rgba(255,255,255,0.08)' }}
        >
          <div className="px-3 py-2 border-b border-white/5 text-[11px] font-bold text-zinc-400 uppercase tracking-wider">
            Select Playbook
          </div>

          {loading && (
            <div className="flex justify-center py-4">
              <Loader2 className="h-4 w-4 animate-spin text-zinc-500" />
            </div>
          )}

          {error && (
            <p className="px-3 py-3 text-[11px] text-red-400">{error}</p>
          )}

          {!loading && !error && playbooks.length === 0 && (
            <p className="px-3 py-3 text-[11px] text-zinc-600 leading-relaxed">
              No playbooks found. Add YAML files to{' '}
              <code className="text-zinc-500">~/.adbygod/playbooks/</code>
            </p>
          )}

          {!loading && !error && playbooks.map(pb => (
            <button
              key={pb.filename}
              onClick={() => {
                onLaunch(pb.name)
                setOpen(false)
              }}
              className="w-full text-left px-3 py-2.5 hover:bg-white/[0.04] transition-colors border-b border-white/5 last:border-0"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-semibold text-zinc-200 truncate">{pb.name}</span>
                <Play className="h-3 w-3 text-violet-400 shrink-0" />
              </div>
              <p className="text-[10px] text-zinc-600 mt-0.5">
                {pb.description || 'No description'} · {pb.step_count} step{pb.step_count !== 1 ? 's' : ''}
              </p>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
