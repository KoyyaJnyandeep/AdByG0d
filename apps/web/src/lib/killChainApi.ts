import axios from 'axios'
import { getApiBaseUrl } from './apiBase'

const api = axios.create({
  baseURL: getApiBaseUrl(),
  withCredentials: true,
  headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
})

export interface KillChainPhase {
  phase_id: number
  label: string
  status: 'not_started' | 'partial' | 'complete'
  completion_pct: number
  techniques_run: string[]
  findings_count: number
}

export interface KillChainSuggestion {
  technique_id: string
  title: string
  reason: string
  mitre_id: string
  phase_id: number
}

export interface KillChainData {
  assessment_id: string | null
  phases: KillChainPhase[]
  suggestions: KillChainSuggestion[]
}

export const killChainApi = {
  get: (assessmentId?: string) =>
    api.get<KillChainData>('/kill-chain', {
      params: assessmentId ? { assessment_id: assessmentId } : {},
    }).then(r => r.data),
}

export const PHASE_STATUS_COLORS = {
  not_started: { bg: 'rgba(255,77,109,0.12)', border: '#ff4d6d', text: '#ff4d6d', label: 'Not Started' },
  partial:     { bg: 'rgba(255,209,102,0.12)', border: '#ffd166', text: '#ffd166', label: 'In Progress' },
  complete:    { bg: 'rgba(57,217,138,0.12)',  border: '#39d98a', text: '#39d98a', label: 'Complete' },
} as const
