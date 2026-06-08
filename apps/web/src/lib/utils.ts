import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { SeverityLevel, FindingStatus, EntityType } from './types'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export const SEVERITY_ORDER: Record<SeverityLevel, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4,
}

export const severityColor = (sev: SeverityLevel): string => {
  const map: Record<SeverityLevel, string> = {
    CRITICAL: 'text-critical',
    HIGH: 'text-high',
    MEDIUM: 'text-medium',
    LOW: 'text-low',
    INFO: 'text-info',
  }
  return map[sev] ?? 'text-text-secondary'
}

export const severityBg = (sev: SeverityLevel): string => {
  const map: Record<SeverityLevel, string> = {
    CRITICAL: 'bg-critical-bg border-critical-border text-critical-text',
    HIGH:     'bg-high-bg border-high-border text-high-text',
    MEDIUM:   'bg-medium-bg border-medium-border text-medium-text',
    LOW:      'bg-low-bg border-low-border text-low-text',
    INFO:     'bg-info-bg border-info-border text-info-text',
  }
  return map[sev] ?? ''
}

export const severityDot = (sev: SeverityLevel): string => {
  const map: Record<SeverityLevel, string> = {
    CRITICAL: 'bg-critical',
    HIGH: 'bg-high',
    MEDIUM: 'bg-medium',
    LOW: 'bg-low',
    INFO: 'bg-info',
  }
  return map[sev] ?? 'bg-zinc-500'
}

export const statusColor = (status: FindingStatus): string => {
  const map: Record<FindingStatus, string> = {
    OPEN: 'text-critical-text bg-critical-bg border-critical-border',
    IN_REVIEW: 'text-medium-text bg-medium-bg border-medium-border',
    REMEDIATED: 'text-low-text bg-low-bg border-low-border',
    ACCEPTED: 'text-info-text bg-info-bg border-info-border',
    FALSE_POSITIVE: 'text-text-secondary bg-surface border-border',
    REGRESSED: 'text-critical-text bg-critical-bg border-critical-border',
  }
  return map[status] ?? ''
}

export const driftBadge = (drift?: string) => {
  switch (drift) {
    case 'new': return { label: 'New', class: 'text-critical-text bg-critical-bg' }
    case 'regressed': return { label: 'Regressed', class: 'text-high-text bg-high-bg' }
    case 'persistent': return { label: 'Persistent', class: 'text-medium-text bg-medium-bg' }
    case 'resolved': return { label: 'Resolved', class: 'text-low-text bg-low-bg' }
    default: return null
  }
}

export const entityTypeIcon = (type: EntityType): string => {
  const map: Record<EntityType, string> = {
    USER: '👤',
    GROUP: '👥',
    COMPUTER: '🖥️',
    DOMAIN: '🌐',
    FOREST: '🌲',
    OU: '📁',
    GPO: '⚙️',
    SERVICE_ACCOUNT: '🔧',
    GMSA: '🔑',
    DMSA: '🔐',
    CA: '🏛️',
    CERT_TEMPLATE: '📜',
    TRUST: '🔗',
    SITE: '📍',
    DC: '🖧',
    UNKNOWN: '❓',
  }
  return map[type] ?? '❓'
}

export const entityTypeColor = (type: EntityType): string => {
  const map: Partial<Record<EntityType, string>> = {
    USER: '#8b5cf6',
    GROUP: '#06b6d4',
    COMPUTER: '#3b82f6',
    DOMAIN: '#f97316',
    DC: '#ef4444',
    GPO: '#84cc16',
    CA: '#ec4899',
    CERT_TEMPLATE: '#f59e0b',
    SERVICE_ACCOUNT: '#a855f7',
    GMSA: '#22d3ee',
    TRUST: '#14b8a6',
  }
  return map[type] ?? '#71717a'
}

export const scoreToSeverity = (score: number): SeverityLevel => {
  if (score >= 85) return 'CRITICAL'
  if (score >= 65) return 'HIGH'
  if (score >= 40) return 'MEDIUM'
  if (score >= 20) return 'LOW'
  return 'INFO'
}

export const scoreGradient = (score: number): string => {
  if (score >= 85) return 'from-red-600 to-red-400'
  if (score >= 65) return 'from-orange-600 to-orange-400'
  if (score >= 40) return 'from-yellow-600 to-yellow-400'
  if (score >= 20) return 'from-green-600 to-green-400'
  return 'from-blue-600 to-blue-400'
}

export const fmtNumber = (n: number): string => {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`
  return String(n)
}

export const fmtScore = (score: number): string => `${score.toFixed(1)}`

export const fmtConfidence = (confidence: number): string =>
  `${Math.round(confidence * 100)}%`

export function safeDateMs(dateStr: string | null | undefined): number | null {
  if (!dateStr) return null
  const hasTimezone = /[+-]\d{2}:?\d{2}$|Z$/.test(dateStr)
  const normalized = hasTimezone ? dateStr : `${dateStr}Z`
  const ms = new Date(normalized).getTime()
  return Number.isFinite(ms) ? ms : null
}

export const fmtDate = (dateStr: string): string => {
  try {
    if (!dateStr) return 'never'
    const ms = safeDateMs(dateStr)
    if (ms === null) return dateStr
    return new Date(ms).toLocaleDateString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
    })
  } catch {
    return dateStr
  }
}

export const fmtDateTime = (dateStr: string): string => {
  try {
    if (!dateStr) return 'never'
    const ms = safeDateMs(dateStr)
    if (ms === null) return dateStr
    return new Date(ms).toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return dateStr
  }
}

export const fmtTime = (
  dateStr: string | null | undefined,
  options?: Intl.DateTimeFormatOptions,
): string => {
  try {
    if (!dateStr) return ''
    const ms = safeDateMs(dateStr)
    if (ms === null) return dateStr
    return new Date(ms).toLocaleTimeString([], options)
  } catch {
    return dateStr ?? ''
  }
}

export const timeAgo = (dateStr: string): string => {
  if (!dateStr) return 'never'
  const ms = safeDateMs(dateStr)
  if (ms === null) return dateStr
  const diff = Date.now() - ms
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.floor(hrs / 24)
  if (days < 30) return `${days}d ago`
  return fmtDate(dateStr)
}

export const MODULE_COLORS: Record<string, string> = {
  'Domain Enumeration': '#06b6d4',
  'Kerberos': '#8b5cf6',
  'AD CS': '#ec4899',
  'ACL & Privilege Paths': '#f97316',
  'SMB & Remote Mgmt': '#3b82f6',
  'Password Hygiene': '#eab308',
  'Persistence Indicators': '#ef4444',
  'Service Accounts': '#22c55e',
  'Password Policy': '#a78bfa',
  'Domain Config': '#f59e0b',
  'Trusts': '#14b8a6',
  'Local Admin': '#fb923c',
}

export const moduleColor = (module: string): string =>
  MODULE_COLORS[module] ?? '#71717a'

export function getErrorDetail(error: unknown, fallback: string): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}
