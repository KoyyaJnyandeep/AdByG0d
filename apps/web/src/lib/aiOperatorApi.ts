import axios from 'axios'
import { getApiBaseUrl } from './apiBase'

const BASE = `${getApiBaseUrl()}/ai-operator`

const _client = axios.create({
  withCredentials: true,
  headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
})

export interface Suggestion {
  technique_id: string
  title: string
  reason: string
  expected_outcome: string
  mitre_id: string
  phase_id: number
  prerequisites_met: boolean
  auth_level_promotion: boolean
  requires_human_approval: boolean
}

export interface PlaybookEntry {
  technique_id: string
  title: string
  reason: string
  phase_id: number
  mitre_id: string
}

export interface PoolStatus {
  running: boolean
  session_id: string
  max_workers: number
  active_workers: number
  tasks_queued: number
  tasks_completed: number
  stop_requested: boolean
}

export interface AuditEntry {
  id: string
  action_type: string
  technique_id: string | null
  command_executed: string | null
  output_snippet: string | null
  reasoning: string | null
  phase_id: number | null
  worker_id: number | null
  created_at: string
}

export interface ProviderInfo {
  id: string
  name: string
  available: boolean
  models: string[]
  default_model: string
  local: boolean
  error: string | null
}

export interface ChatContextItem {
  type: 'output' | 'finding' | 'bloodhound' | 'hash' | 'text'
  label: string
  content: string
}

export interface AnalysisResult {
  summary: string
  severity: string
  key_findings: string[]
  credentials_found: string[]
  attack_paths_opened: string[]
  next_techniques: string[]
  mitre_ids: string[]
  opsec_notes: string
}

export interface TechniqueExplanation {
  what: string
  why_effective: string
  step_by_step: string[]
  prerequisites: string[]
  expected_output: string
  opsec_rating: string
  opsec_notes: string
  detection_indicators: string[]
  defensive_mitigations: string[]
  difficulty: string
  real_world_note: string
  error?: string
}

export const aiOperatorApi = {
  providers: () =>
    _client.get<ProviderInfo[]>(`${BASE}/providers`).then(r => r.data),

  providerStatus: (id: string) =>
    _client.get<ProviderInfo>(`${BASE}/providers/${id}`).then(r => r.data),

  suggest: (phaseScope: number[], excludedIds: string[], provider?: string, model?: string, apiKey?: string | null, baseUrl?: string | null) =>
    _client.post<Suggestion>(`${BASE}/suggest`, { phase_scope: phaseScope, excluded_ids: excludedIds, provider, model, api_key: apiKey || null, base_url: baseUrl || null }).then(r => r.data),

  playbook: (phaseScope: number[], excludedIds: string[], provider?: string, model?: string, apiKey?: string | null, baseUrl?: string | null) =>
    _client.post<{ playbook: PlaybookEntry[]; count: number }>(`${BASE}/playbook`, { phase_scope: phaseScope, excluded_ids: excludedIds, provider, model, api_key: apiKey || null, base_url: baseUrl || null }).then(r => r.data),

  autoRun: (maxParallelWorkers: number, phaseScope: number[]) =>
    _client.post<PoolStatus>(`${BASE}/auto-run`, { max_parallel_workers: maxParallelWorkers, phase_scope: phaseScope }).then(r => r.data),

  status: () => _client.get<PoolStatus>(`${BASE}/status`).then(r => r.data),
  stop: () => _client.post<{ status: string }>(`${BASE}/stop`).then(r => r.data),
  history: (limit = 50) => _client.get<AuditEntry[]>(`${BASE}/history`, { params: { limit } }).then(r => r.data),

  testProvider: (providerId: string, apiKey?: string, baseUrl?: string) =>
    _client.post<ProviderInfo>(`${BASE}/providers/${providerId}/test`, { api_key: apiKey || null, base_url: baseUrl || null }).then(r => r.data),

  chatStream: (
    message: string,
    history: { role: string; content: string }[],
    contextItems: ChatContextItem[],
    sessionCtx: Record<string, unknown> | null,
    provider: string | null,
    model: string | null,
    signal?: AbortSignal,
    apiKey?: string | null,
    baseUrl?: string | null,
  ): Promise<Response> =>
    fetch(`${BASE}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      credentials: 'include',
      signal,
      body: JSON.stringify({
        message, history, context_items: contextItems, session_ctx: sessionCtx,
        provider: provider || null, model: model || null,
        api_key: apiKey || null, base_url: baseUrl || null,
      }),
    }),

  analyze: (output: string, techniqueId?: string, provider?: string, model?: string, apiKey?: string | null, baseUrl?: string | null) =>
    _client.post<AnalysisResult>(`${BASE}/analyze`, { output, technique_id: techniqueId, provider, model, api_key: apiKey || null, base_url: baseUrl || null }).then(r => r.data),

  explain: (techniqueId: string, targetEnv?: Record<string, unknown>, provider?: string, model?: string) =>
    _client.post<TechniqueExplanation>(`${BASE}/explain`, { technique_id: techniqueId, target_env: targetEnv, provider, model }).then(r => r.data),

  generateReport: (findings: Record<string, unknown>[], sessionCtx?: Record<string, unknown>, severitySummary?: Record<string, unknown>, provider?: string, model?: string) =>
    _client.post<{ narrative: string }>(`${BASE}/generate-report`, { findings, session_ctx: sessionCtx, severity_summary: severitySummary, provider, model }).then(r => r.data),

  analyzeBloodHound: (data: Record<string, unknown>, provider?: string, model?: string) =>
    _client.post(`${BASE}/analyze-bloodhound`, { data, provider, model }).then(r => r.data),
}
