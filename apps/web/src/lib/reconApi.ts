import axios from 'axios'
import { getApiBaseUrl } from './apiBase'

const api = axios.create({
  baseURL: getApiBaseUrl(),
  withCredentials: true,
  headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
})

api.interceptors.response.use(
  r => r,
  err => {
    if (err?.response?.status === 401 && typeof window !== 'undefined' && window.location.pathname !== '/login') {
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export interface ScanFinding {
  type: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  title: string
  detail: string
  finding_type: string
  mitre_id?: string
  mitre_name?: string
  tactic?: string
  cvss?: number
}

export interface ScanSummary {
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface ReconScan {
  scan_id: string
  assessment_id: string | null
  status: 'queued' | 'running' | 'completed' | 'failed'
  target_dc_ip: string | null
  domain: string | null
  started_at: string | null
  completed_at: string | null
  findings: ScanFinding[]
  summary: ScanSummary
}

export interface ScanListItem {
  scan_id: string
  assessment_id: string | null
  status: string
  domain: string | null
  created_at: string | null
  findings_count: number
  summary: ScanSummary
}

export const reconApi = {
  startScan: (payload: { assessment_id?: string; target_dc_ip: string; domain: string }) =>
    api.post<{ scan_id: string; status: string }>('/recon/scan', payload).then(r => r.data),

  getScan: (scanId: string) =>
    api.get<ReconScan>(`/recon/scan/${scanId}`).then(r => r.data),

  listScans: (assessmentId?: string) =>
    api.get<ScanListItem[]>('/recon/scans', {
      params: assessmentId ? { assessment_id: assessmentId } : {},
    }).then(r => r.data),
}

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ff4d6d',
  HIGH: '#ffa94d',
  MEDIUM: '#ffd166',
  LOW: '#51cf66',
  INFO: '#74c0fc',
}
