'use client'

import { memo, type MouseEvent } from 'react'
import Link from 'next/link'
import { Finding } from '@/lib/types'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { ProvenanceBadge } from '@/components/ui/ProvenanceBadge'
import { fmtScore, fmtConfidence, moduleColor, cn } from '@/lib/utils'
import { Eye, Crosshair, Zap, Users } from 'lucide-react'

const driftClass: Record<string, string> = {
  new: 'text-[#fca5a5] bg-critical/10 border-critical/20',
  persistent: 'text-[#fde047] bg-medium/10 border-medium/20',
  regressed: 'text-[#fdba74] bg-high/10 border-high/20',
  resolved: 'text-[#86efac] bg-low/10 border-low/20',
}

const SEV_NEON: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
  INFO:     '#3b82f6',
}

export const TopFindingsList = memo(function TopFindingsList({ findings }: { findings: Finding[] }) {
  return (
    <div
      className="overflow-hidden relative"
      style={{
        background: '#000',
        border: '1px solid rgba(var(--brand-rgb),0.2)',
        borderRadius: '12px',
        backdropFilter: 'blur(12px)',
      }}
    >
      <table className="w-full">
        <thead>
          <tr style={{ borderBottom: '1px solid rgba(var(--brand-rgb),0.15)' }}>
            {['Severity','Finding','Module','Score','Confidence','Affected','Status','Drift','Actions'].map(col => (
              <th
                key={col}
                className={cn(
                  'px-4 py-3 text-left font-mono text-[10px] tracking-[0.12em] uppercase',
                  ['Score','Confidence','Affected'].includes(col) ? 'text-center' : ''
                )}
                style={{ color: 'rgba(var(--brand-rgb),0.55)' }}
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => {
            const neonColor = SEV_NEON[finding.severity] ?? 'var(--brand)'
            return (
              <tr
                key={finding.id}
                className="group transition-all duration-200"
                style={{
                  borderBottom: '1px solid rgba(var(--brand-rgb),0.07)',
                  borderLeft: `3px solid ${neonColor}`,
                }}
                onMouseEnter={e => {
                  const el = e.currentTarget as HTMLElement
                  el.style.transform = 'translateX(4px)'
                  el.style.background = `${neonColor}08`
                  el.style.boxShadow = `inset 0 0 24px ${neonColor}0a, -4px 0 12px ${neonColor}18`
                }}
                onMouseLeave={e => {
                  const el = e.currentTarget as HTMLElement
                  el.style.transform = ''
                  el.style.background = ''
                  el.style.boxShadow = ''
                }}
              >
                <td className="px-4 py-3.5">
                  <SeverityBadge severity={finding.severity} />
                </td>
                <td className="px-4 py-3.5">
                  <div className="flex flex-col gap-0.5">
                    <Link
                      href={`/findings/${finding.id}`}
                      className="text-sm font-medium line-clamp-1 transition-colors"
                      style={{ color: 'rgba(220,210,255,0.9)', textDecoration: 'none' }}
                      onMouseEnter={(e: MouseEvent) => { (e.currentTarget as HTMLElement).style.color = 'var(--brand-light)' }}
                      onMouseLeave={(e: MouseEvent) => { (e.currentTarget as HTMLElement).style.color = 'rgba(220,210,255,0.9)' }}
                    >
                      {finding.title}
                    </Link>
                    {finding.root_cause && (
                      <div className="text-xs font-mono line-clamp-1" style={{ color: 'rgba(var(--brand-rgb),0.4)' }}>
                        {finding.root_cause}
                      </div>
                    )}
                    <div className="mt-1">
                      <ProvenanceBadge origin={finding.origin} className="text-[10px]" />
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3.5">
                  <span className="text-xs font-medium px-2 py-1 rounded-lg" style={{
                    background: `${moduleColor(finding.module)}20`,
                    color: moduleColor(finding.module),
                  }}>
                    {finding.module}
                  </span>
                </td>
                <td className="px-4 py-3.5 text-center">
                  <span
                    className="text-sm font-bold tabular-nums font-mono"
                    style={{
                      color: neonColor,
                      textShadow: `0 0 8px ${neonColor}66`,
                    }}
                  >
                    {fmtScore(finding.composite_score ?? 0)}
                  </span>
                </td>
                <td className="px-4 py-3.5 text-center">
                  <span className="text-sm tabular-nums" style={{ color: 'rgba(200,190,240,0.55)' }}>
                    {fmtConfidence(finding.confidence)}
                  </span>
                </td>
                <td className="px-4 py-3.5 text-center">
                  <div className="flex items-center justify-center gap-1">
                    <Users className="w-3 h-3" style={{ color: 'rgba(var(--brand-rgb),0.4)' }} />
                    <span className="text-sm tabular-nums" style={{ color: 'rgba(200,190,240,0.55)' }}>
                      {finding.affected_count}
                    </span>
                  </div>
                </td>
                <td className="px-4 py-3.5">
                  <StatusBadge status={finding.status} />
                </td>
                <td className="px-4 py-3.5">
                  {finding.drift_status && (
                    <span className={cn(
                      'inline-flex text-[10px] font-medium px-1.5 py-0.5 rounded border capitalize',
                      driftClass[finding.drift_status] || 'text-text-tertiary'
                    )}>
                      {finding.drift_status}
                    </span>
                  )}
                </td>
                <td className="px-4 py-3.5">
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Link href={`/findings/${finding.id}`}
                      className="p-1.5 rounded-lg transition-colors"
                      style={{ color: 'rgba(var(--brand-rgb),0.5)' }}
                      onMouseEnter={(e: MouseEvent) => { (e.currentTarget as HTMLElement).style.color = 'var(--brand-light)' }}
                      onMouseLeave={(e: MouseEvent) => { (e.currentTarget as HTMLElement).style.color = 'rgba(var(--brand-rgb),0.5)' }}
                      title="View details"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </Link>
                    <Link href={`/graph?assessment_id=${finding.assessment_id}&highlight=${finding.id}`}
                      className="p-1.5 rounded-lg transition-colors"
                      style={{ color: 'rgba(var(--brand-rgb),0.5)' }}
                      onMouseEnter={(e: MouseEvent) => { (e.currentTarget as HTMLElement).style.color = 'var(--brand-light)' }}
                      onMouseLeave={(e: MouseEvent) => { (e.currentTarget as HTMLElement).style.color = 'rgba(var(--brand-rgb),0.5)' }}
                      title="View path"
                    >
                      <Crosshair className="w-3.5 h-3.5" />
                    </Link>
                    <Link href={`/remediation?assessment_id=${finding.assessment_id}&finding=${finding.id}`}
                      className="p-1.5 rounded-lg transition-colors"
                      style={{ color: 'rgba(var(--accent1-rgb),0.5)' }}
                      onMouseEnter={(e: MouseEvent) => { (e.currentTarget as HTMLElement).style.color = '#67e8f9' }}
                      onMouseLeave={(e: MouseEvent) => { (e.currentTarget as HTMLElement).style.color = 'rgba(var(--accent1-rgb),0.5)' }}
                      title="Simulate fix"
                    >
                      <Zap className="w-3.5 h-3.5" />
                    </Link>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
})
