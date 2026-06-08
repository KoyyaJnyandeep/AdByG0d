import { DataOrigin } from '@/lib/types'
import { cn } from '@/lib/utils'

const ORIGIN_STYLES: Record<DataOrigin, string> = {
  COLLECTED: 'bg-emerald-500/10 border-emerald-400/25 text-emerald-200',
  IMPORTED: 'bg-cyan-500/10 border-cyan-400/25 text-cyan-200',
  INFERRED: 'bg-amber-500/10 border-amber-400/25 text-amber-200',
  SIMULATED: 'bg-fuchsia-500/10 border-fuchsia-400/25 text-fuchsia-200',
}

const ORIGIN_LABELS: Record<DataOrigin, string> = {
  COLLECTED: 'Collected',
  IMPORTED: 'Imported',
  INFERRED: 'Inferred',
  SIMULATED: 'Simulated',
}

export function ProvenanceBadge({ origin, className }: { origin: DataOrigin; className?: string }) {
  return (
    <span className={cn('inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-medium', ORIGIN_STYLES[origin], className)}>
      {ORIGIN_LABELS[origin]}
    </span>
  )
}
