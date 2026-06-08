'use client'

import { memo } from 'react'
import { moduleColor } from '@/lib/utils'

interface Props {
  liveCounts?: Record<string, number>
}

export const ModuleBreakdown = memo(function ModuleBreakdown({ liveCounts }: Props) {
  const modules = liveCounts && Object.keys(liveCounts).length > 0
    ? Object.entries(liveCounts)
        .map(([module, total]) => ({ module, total }))
        .sort((a, b) => b.total - a.total)
    : []

  if (modules.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-white/10 bg-black px-4 py-6 text-sm text-zinc-500">
        No module findings have been recorded for this assessment yet.
      </div>
    )
  }

  const maxVal = Math.max(...modules.map((m) => m.total), 1)

  // Split into two equal columns
  const half = Math.ceil(modules.length / 2)
  const col1 = modules.slice(0, half)
  const col2 = modules.slice(half)

  return (
    <div className="grid grid-cols-2 gap-x-6 gap-y-0">
      {[col1, col2].map((col, ci) => (
        <div key={ci} className="space-y-2">
          {col.map(({ module, total }) => {
            const pct = (total / maxVal) * 100
            const color = moduleColor(module)
            return (
              <div key={module} className="group">
                <div className="mb-1 flex items-center justify-between gap-2">
                  <span
                    className="truncate text-[11px] font-mono text-zinc-300 transition-colors group-hover:text-white"
                    title={module}
                  >
                    {module}
                  </span>
                  <span
                    className="shrink-0 font-mono text-[11px] font-bold tabular-nums"
                    style={{ color }}
                  >
                    {total}
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${pct}%`,
                      background: color,
                      opacity: 0.85,
                      boxShadow: `0 0 6px ${color}55`,
                    }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      ))}
    </div>
  )
})
