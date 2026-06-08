import { ReactNode, isValidElement } from 'react'
import { cn } from '@/lib/utils'
import { LucideIcon, TrendingUp, TrendingDown, Minus } from 'lucide-react'

interface MetricCardProps {
  label?: string
  title?: string
  value: string | number
  valueClass?: string
  delta?: number
  icon?: LucideIcon | ReactNode
  accentColor?: string
  subtitle?: string
  className?: string
  onClick?: () => void
}

export function MetricCard({
  label,
  title,
  value,
  valueClass,
  delta,
  icon,
  accentColor = 'var(--brand)',
  subtitle,
  className,
  onClick,
}: MetricCardProps) {
  const labelText = label ?? title ?? ''

  const renderIcon = () => {
    if (!icon) return null
    if (isValidElement(icon)) return icon
    if (typeof icon === 'function') {
      const IconComponent = icon as LucideIcon
      return <IconComponent className="w-4 h-4" style={{ color: accentColor }} />
    }
    return icon
  }

  return (
    <div
      className={cn('rounded-2xl p-5 flex flex-col gap-3 transition-all duration-200', className)}
      style={{
        background: '#000',
        border: `1px solid rgba(var(--brand-rgb),0.18)`,
        backdropFilter: 'blur(20px)',
        cursor: onClick ? 'pointer' : 'default',
      }}
      onClick={onClick}
      onMouseEnter={e => {
        if (onClick) {
          const el = e.currentTarget as HTMLElement
          el.style.borderColor = `rgba(var(--brand-rgb),0.35)`
          el.style.background = 'rgba(6,3,22,0.96)'
        }
      }}
      onMouseLeave={e => {
        if (onClick) {
          const el = e.currentTarget as HTMLElement
          el.style.borderColor = 'rgba(var(--brand-rgb),0.18)'
          el.style.background = 'rgba(4,2,16,0.92)'
        }
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <span
          className="text-sm font-medium tracking-wide"
          style={{ color: 'rgba(200,190,240,0.5)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem' }}
        >
          {labelText}
        </span>
        {icon && (
          <div
            className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: `${accentColor}18`, border: `1px solid ${accentColor}30` }}
          >
            {renderIcon()}
          </div>
        )}
      </div>
      <div>
        <div
          className={cn('text-3xl font-black tabular-nums tracking-tight', valueClass)}
          style={{ color: accentColor, textShadow: `0 0 20px ${accentColor}60`, fontFamily: 'JetBrains Mono, monospace' }}
        >
          {value}
        </div>
        {subtitle && (
          <div
            className="text-xs mt-0.5 tracking-wide"
            style={{ color: 'rgba(var(--brand-rgb),0.35)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}
          >
            {subtitle}
          </div>
        )}
      </div>
      {delta !== undefined && (
        <div
          className="flex items-center gap-1 text-xs font-medium"
          style={{
            color: delta > 0 ? '#fca5a5' : delta < 0 ? '#86efac' : 'rgba(var(--brand-rgb),0.4)',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '0.7rem',
          }}
        >
          {delta > 0
            ? <TrendingUp className="w-3 h-3" />
            : delta < 0
            ? <TrendingDown className="w-3 h-3" />
            : <Minus className="w-3 h-3" />
          }
          <span>
            {delta > 0 ? `+${delta}` : delta < 0 ? delta : '—'} vs previous
          </span>
        </div>
      )}
    </div>
  )
}
