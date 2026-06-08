'use client'
import { copyText } from '@/lib/clipboard'
import { useState } from 'react'
import { X, Copy, Check } from 'lucide-react'

export function HandoffBriefModal({
  content,
  onClose,
}: {
  content: string
  onClose: () => void
}) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await copyText(content)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.8)' }}
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div
        className="w-full max-w-2xl rounded-2xl overflow-hidden flex flex-col"
        style={{
          background: 'rgba(10,10,15,0.99)',
          border: '1px solid rgba(255,255,255,0.08)',
          maxHeight: '80vh',
        }}
      >
        {/* Header */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-white/5 shrink-0">
          <span className="text-sm font-bold text-zinc-200 flex-1">Operator Handoff Brief</span>
          <button
            onClick={() => void handleCopy()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-[11px] font-semibold transition-all"
            style={{
              background: 'rgba(96,165,250,0.08)',
              border: '1px solid rgba(96,165,250,0.2)',
              color: copied ? '#34d399' : '#60a5fa',
            }}
          >
            {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
          <button
            onClick={onClose}
            className="text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-4 py-4">
          <pre className="whitespace-pre-wrap text-xs text-zinc-300 font-mono leading-relaxed">
            {content}
          </pre>
        </div>
      </div>
    </div>
  )
}
