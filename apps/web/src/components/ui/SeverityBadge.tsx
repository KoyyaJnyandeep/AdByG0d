import { cn } from '@/lib/utils'
import { SeverityLevel } from '@/lib/types'

const SEV_STYLES: Record<SeverityLevel, string> = {
  CRITICAL: 'bg-critical/15 border-critical/30 text-critical',
  HIGH:     'bg-high/15 border-high/30 text-[#fdba74]',
  MEDIUM:   'bg-medium/15 border-medium/30 text-[#fde047]',
  LOW:      'bg-low/15 border-low/30 text-[#86efac]',
  INFO:     'bg-info/15 border-info/30 text-[#93c5fd]',
}

const SEV_DOT: Record<SeverityLevel, string> = {
  CRITICAL: 'bg-critical',
  HIGH:     'bg-high',
  MEDIUM:   'bg-medium',
  LOW:      'bg-low',
  INFO:     'bg-info',
}

interface SeverityBadgeProps {
  severity: SeverityLevel
  size?: 'sm' | 'md'
  dot?: boolean
  className?: string
}

export function SeverityBadge({ severity, size = 'md', dot = false, className }: SeverityBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 font-semibold uppercase tracking-wide border rounded',
        size === 'sm' ? 'text-[10px] px-1.5 py-0.5' : 'text-[11px] px-2 py-0.5',
        SEV_STYLES[severity],
        className,
      )}
    >
      {dot && <span className={cn('w-1.5 h-1.5 rounded-full', SEV_DOT[severity])} />}
      {severity}
    </span>
  )
}
