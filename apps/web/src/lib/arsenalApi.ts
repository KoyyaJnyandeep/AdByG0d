import axios from 'axios'

function base() {
  const u = process.env.NEXT_PUBLIC_API_URL?.trim()
  return u ? `${u.replace(/\/$/, '')}/api/v1` : '/api/v1'
}

const api = axios.create({
  withCredentials: true,
  headers: { 'X-Requested-With': 'XMLHttpRequest' },
})

export interface CVE {
  arsenal_key?: string
  id: string
  name: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  cvss: number
  category: string
  description: string
  affected: string[]
  technique_id: string | null
  check_type: 'active' | 'passive' | 'version'
  poc_available: boolean
  check_cmd: string
  remediation: string
  tags: string[]
}

export interface ArsenalStats {
  total: number
  by_severity: Record<string, number>
  categories: number
}

export interface CheckResult {
  cve_id: string
  arsenal_key?: string
  verdict: 'VULNERABLE' | 'NOT_VULNERABLE' | 'UNKNOWN' | 'ERROR' | 'TIMEOUT' | 'SKIPPED' | 'TOOL_MISSING' | string
  name?: string
  severity?: string
}

export interface StreamLine {
  line: string
  type: 'output' | 'info' | 'warn' | 'error' | 'header' | 'separator' | 'verdict'
  cve_id?: string
  ts: string
}

export const arsenalApi = {
  async listCves(filters?: {
    severity?: string
    category?: string
    search?: string
    poc_only?: boolean
  }): Promise<{ cves: CVE[]; total: number }> {
    const params = new URLSearchParams()
    if (filters?.severity) params.set('severity', filters.severity)
    if (filters?.category) params.set('category', filters.category)
    if (filters?.search) params.set('search', filters.search)
    if (filters?.poc_only) params.set('poc_only', 'true')
    const r = await api.get(`${base()}/arsenal/cves?${params}`)
    return r.data
  },

  async getCve(id: string): Promise<CVE> {
    const r = await api.get(`${base()}/arsenal/cves/${encodeURIComponent(id)}`)
    return r.data
  },

  async getStats(): Promise<{ stats: ArsenalStats; categories: string[] }> {
    const r = await api.get(`${base()}/arsenal/stats`)
    return r.data
  },

  async runCheck(cve_id: string, params: Record<string, string> = {}, timeout = 60): Promise<{ job_id: string }> {
    const r = await api.post(`${base()}/arsenal/check`, { cve_id, params, timeout })
    return r.data
  },

  async runBatch(cve_ids: string[], params: Record<string, string> = {}, timeout = 60): Promise<{ job_id: string; total: number }> {
    const r = await api.post(`${base()}/arsenal/check-batch`, { cve_ids, params, timeout })
    return r.data
  },

  async getJob(job_id: string): Promise<{ status: string; results: CheckResult[] }> {
    const r = await api.get(`${base()}/arsenal/jobs/${job_id}`)
    return r.data
  },

  streamJob(job_id: string): EventSource {
    return new EventSource(`${base()}/arsenal/stream/${job_id}`, { withCredentials: true })
  },

  async listAssessments(): Promise<{ id: string; name: string; domain: string; dc_ip: string }[]> {
    const r = await api.get(`${base()}/arsenal/assessments-list`)
    return r.data
  },

  async targetFromAssessment(assessment_id: string): Promise<Record<string, string>> {
    const r = await api.get(`${base()}/arsenal/target-from-assessment/${assessment_id}`)
    return r.data
  },
}

export const SEVERITY_CONFIG = {
  CRITICAL: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.35)', glow: 'rgba(239,68,68,0.25)', label: 'CRITICAL' },
  HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.35)', glow: 'rgba(249,115,22,0.20)', label: 'HIGH' },
  MEDIUM:   { color: '#eab308', bg: 'rgba(234,179,8,0.12)',  border: 'rgba(234,179,8,0.32)',  glow: 'rgba(234,179,8,0.18)',  label: 'MEDIUM' },
  LOW:      { color: '#22d3ee', bg: 'rgba(34,211,238,0.10)', border: 'rgba(34,211,238,0.28)', glow: 'rgba(34,211,238,0.14)', label: 'LOW' },
} as const

export const VERDICT_CONFIG: Record<string, { color: string; label: string }> = {
  VULNERABLE:     { color: '#ef4444', label: 'VULNERABLE' },
  NOT_VULNERABLE: { color: '#22c55e', label: 'SAFE' },
  UNKNOWN:        { color: '#eab308', label: 'UNKNOWN' },
  ERROR:          { color: '#f97316', label: 'ERROR' },
  TIMEOUT:        { color: '#a78bfa', label: 'TIMEOUT' },
  SKIPPED:        { color: '#6b7280', label: 'SKIPPED' },
  TOOL_MISSING:   { color: '#f97316', label: 'NO TOOL' },
}
