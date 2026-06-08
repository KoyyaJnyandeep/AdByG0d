'use client'
import { useState } from 'react'
import { FileText, ChevronDown } from 'lucide-react'

const SECTION_LABELS: Record<string, string> = {
  executive_summary: 'Executive Summary',
  attack_narrative: 'Attack Narrative',
  findings_detail: 'Findings Detail',
  attack_path_walkthrough: 'Attack Path Walkthrough',
  recommendations: 'Recommendations',
}

interface SectionData {
  content: string
  updated_at: string
}

export function ReportDraftPanel({
  sections,
}: {
  sections: Record<string, SectionData>
}) {
  const [activeSection, setActiveSection] = useState<string | null>(null)
  const keys = Object.keys(sections)
  if (keys.length === 0) return null

  return (
    <div
      className="rounded-xl overflow-hidden my-2"
      style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.06)' }}
    >
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/5">
        <FileText className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
        <span className="text-[11px] font-bold text-emerald-400">
          REPORT DRAFT ({keys.length} section{keys.length !== 1 ? 's' : ''})
        </span>
      </div>
      {keys.map(key => {
        const isOpen = activeSection === key
        return (
          <div key={key} className="border-b border-white/5 last:border-0">
            <button
              onClick={() => setActiveSection(isOpen ? null : key)}
              className="w-full flex items-center gap-2 px-3 py-2 hover:bg-white/[0.03] text-left transition-colors"
            >
              <span className="text-xs text-zinc-300 flex-1">
                {SECTION_LABELS[key] ?? key}
              </span>
              <span className="text-[10px] text-zinc-600 shrink-0 font-mono">
                {sections[key].content.length} chars
              </span>
              <ChevronDown
                className="h-3 w-3 text-zinc-600 shrink-0 transition-transform"
                style={{ transform: isOpen ? 'rotate(180deg)' : 'none' }}
              />
            </button>
            {isOpen && (
              <pre className="px-4 pb-3 text-[11px] text-zinc-400 font-mono whitespace-pre-wrap leading-relaxed">
                {sections[key].content.slice(0, 800)}
                {sections[key].content.length > 800 ? '\n…' : ''}
              </pre>
            )}
          </div>
        )
      })}
    </div>
  )
}
