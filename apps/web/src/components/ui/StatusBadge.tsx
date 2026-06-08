import { cn } from '@/lib/utils'
import { FindingStatus } from '@/lib/types'

const STATUS_STYLES: Record<FindingStatus, string> = {
  OPEN:          'bg-critical/10 border-critical/25 text-critical',
  IN_REVIEW:     'bg-medium/10 border-medium/25 text-[#fde047]',
  REMEDIATED:    'bg-low/10 border-low/25 text-[#86efac]',
  ACCEPTED:      'bg-info/10 border-info/25 text-[#93c5fd]',
  FALSE_POSITIVE:'bg-zinc-800 border-zinc-700 text-zinc-400',
  REGRESSED:     'bg-critical/10 border-critical/25 text-critical',
}

const STATUS_LABELS: Record<FindingStatus, string> = {
  OPEN: 'Open',
  IN_REVIEW: 'In Review',
  REMEDIATED: 'Remediated',
  ACCEPTED: 'Accepted',
  FALSE_POSITIVE: 'False Positive',
  REGRESSED: 'Regressed',
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={cn(
      'inline-flex items-center text-[11px] font-medium px-2 py-0.5 rounded border',
      STATUS_STYLES[status],
    )}>
      {STATUS_LABELS[status]}
    </span>
  )
}
