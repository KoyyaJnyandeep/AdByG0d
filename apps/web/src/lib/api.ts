import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios'
import { getApiBaseUrl } from './apiBase'
import {
  Assessment,
  DashboardData,
  CertTemplate,
  EntitySummary,
  ExposurePath,
  GraphSimulationResult,
  AuditLogEntry,
  AuthTokenResponse,
  CollectionModule,
  Entity,
  EntityIntelligence,
  EvidenceRecord,
  Finding,
  FindingsPage,
  GraphData,
  PathStep,
  PKISummary,
  PlatformUser,
  RemediationSimResult,
  ReportExportResponse,
  ReportPreview,
  WorkspaceOption,
  AttackCategoriesResponse,
  AttackFlowChainsResponse,
  ChokePointsResponse,
  ComputePathsResult,
  GraphMarkingsData,
  SavedGraphView,
  SnapshotSummary,
  SnapshotDiff,
  NLQueryResult,
  PathNarration,
  MonteCarloResult,
  AnomalyResult,
  AssessmentDiff,
} from './types'

const TOKEN_STORAGE_KEY = 'adbygod_token'
type QueryParams = Record<string, unknown>

function clearLegacyClientAuthArtifacts() {
  if (typeof window === 'undefined') {
    return
  }
  window.localStorage.removeItem(TOKEN_STORAGE_KEY)
}

function redirectToLogin() {
  if (typeof window === 'undefined') {
    return
  }
  if (window.location.pathname !== '/login') {
    window.location.href = '/login'
  }
}

const api = axios.create({
  baseURL: getApiBaseUrl(),
  timeout: 30_000,
  headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
  withCredentials: true,
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status
    const requestUrl = String(error?.config?.url ?? '')
    const isLoginRequest = requestUrl.includes('/auth/login')

    if (status === 401 && !isLoginRequest) {
      clearLegacyClientAuthArtifacts()
      redirectToLogin()
    }

    return Promise.reject(error)
  }
)

function unwrapData<T = unknown>(promise: Promise<AxiosResponse<T>>) {
  return promise.then((response) => response.data)
}

function get<T = unknown>(url: string, config?: AxiosRequestConfig) {
  return unwrapData(api.get<T>(url, config))
}

function post<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig) {
  return unwrapData(api.post<T>(url, data, config))
}

function patch<T = unknown>(url: string, data?: unknown, config?: AxiosRequestConfig) {
  return unwrapData(api.patch<T>(url, data, config))
}

function buildApiStreamUrl(path: string, params?: Record<string, string>) {
  const query = params ? `?${new URLSearchParams(params).toString()}` : ''
  return `${getApiBaseUrl()}${path}${query}`
}

export const authApi = {
  login: (data: { username: string; password: string }) =>
    post<AuthTokenResponse>('/auth/login', data),

  me: () =>
    get<PlatformUser>('/auth/me'),

  logout: async () => {
    clearLegacyClientAuthArtifacts()
    await api.post('/auth/logout')
  },
}

export const assessmentApi = {
  list: (params?: QueryParams) =>
    get<Assessment[]>('/assessments', { params }),

  get: (id: string) =>
    get<Assessment>(`/assessments/${id}`),

  create: (data: { name: string; domain: string; dc_ip?: string; collection_mode?: string; collection_config?: Record<string, unknown>; workspace_id?: string; connectivity_profile_id?: string }) =>
    post<Assessment>('/assessments', data),

  update: (id: string, data: { name?: string; domain?: string; dc_ip?: string; username?: string; password?: string }) =>
    patch<Assessment>(`/assessments/${id}`, data),

  delete: (id: string) =>
    api.delete(`/assessments/${id}`),

  stats: (id: string) =>
    get(`/assessments/${id}/stats`),

  dashboard: (id: string) =>
    get<DashboardData>(`/assessments/${id}/dashboard`),

  workspaces: () =>
    get<WorkspaceOption[]>('/assessments/workspaces'),
}

export const findingsApi = {
  list: (params?: QueryParams) =>
    get<FindingsPage>('/findings', { params }),

  get: (id: string) =>
    get<Finding>(`/findings/${id}`),

  // restrict to mutable fields only so callers can't accidentally
  // send id, assessment_id, created_at, etc. in the PATCH body
  update: (id: string, data: {
    status?: Finding['status']
    assigned_to?: string
    waiver_reason?: string
    waiver_expiry?: string
    waiver_owner?: string
  }) =>
    patch<Finding>(`/findings/${id}`, data),

  moduleSummary: (assessmentId: string) =>
    get('/findings/modules/summary', { params: { assessment_id: assessmentId } }),

  evidence: (findingId: string) =>
    get<EvidenceRecord[]>(`/findings/${findingId}/evidence`),
}

export const entitiesApi = {
  list: (params: { assessment_id: string; entity_type?: string; tier?: number; is_crown_jewel?: boolean; is_admin_count?: boolean; is_enabled?: boolean; search?: string; limit?: number; offset?: number }) =>
    get<Entity[]>('/entities', { params }),

  summary: (assessmentId: string) =>
    get<EntitySummary>('/entities/summary', { params: { assessment_id: assessmentId } }),

  intelligence: (assessmentId: string) =>
    get<EntityIntelligence>('/entities/intelligence', { params: { assessment_id: assessmentId } }),

  get: (id: string) =>
    get<Entity>(`/entities/${id}`),
}

export const graphApi = {
  getData: (assessmentId: string, params?: QueryParams) =>
    get<GraphData>(`/graph/${assessmentId}/data`, { params }),

  getPaths: (
    assessmentId: string,
    params: { source_id?: string; target_id?: string; algorithm?: 'bfs' | 'yen'; directed?: boolean; k?: number; max_paths?: number; limit?: number; tier?: number }
  ) => api.get<ExposurePath[]>(`/graph/${assessmentId}/paths`, { params }).then(r => r.data),

  getBlastRadius: (assessmentId: string) =>
    get(`/graph/${assessmentId}/blast-radius`),

  simulateRemoval: (assessmentId: string, edgeRemovals: { source: string; target: string }[]) =>
    post<GraphSimulationResult>(`/graph/${assessmentId}/simulate-removal`, edgeRemovals),

  computePaths: (assessmentId: string) =>
    post<ComputePathsResult>(`/graph/${assessmentId}/compute-paths`, {}),

  getCategories: (assessmentId: string) =>
    get<AttackCategoriesResponse>(`/graph/${assessmentId}/categories`),

  getChokePoints: (assessmentId: string) =>
    get<ChokePointsResponse>(`/graph/${assessmentId}/choke-points`),

  getAttackFlowChains: () =>
    get<AttackFlowChainsResponse>('/graph/attack-flow-chains'),

  getMarkings: (assessmentId: string) =>
    get<GraphMarkingsData>(`/graph/${assessmentId}/markings`),
  putMarkings: (assessmentId: string, body: Partial<GraphMarkingsData>) =>
    api.put<GraphMarkingsData>(`/graph/${assessmentId}/markings`, body).then(r => r.data),

  getViews: (assessmentId: string) =>
    get<{ views: SavedGraphView[] }>(`/graph/${assessmentId}/views`),
  createView: (assessmentId: string, name: string, config: SavedGraphView['config']) =>
    post<SavedGraphView>(`/graph/${assessmentId}/views`, { name, config }),
  deleteView: (assessmentId: string, viewId: string) =>
    api.delete(`/graph/${assessmentId}/views/${viewId}`),

  getSnapshots: (assessmentId: string) =>
    get<{ snapshots: SnapshotSummary[] }>(`/graph/${assessmentId}/snapshots`),
  createSnapshot: (assessmentId: string, label?: string) =>
    post<SnapshotSummary>(`/graph/${assessmentId}/snapshot`, { label }),
  getSnapshotDiff: (assessmentId: string, fromId: string, toId: string) =>
    get<SnapshotDiff>(`/graph/${assessmentId}/diff?from=${fromId}&to=${toId}`),

  nlQuery: (assessmentId: string, query: string) =>
    post<NLQueryResult>(`/graph/${assessmentId}/nl-query`, { query }),
  narratePath: (assessmentId: string, pathSteps: PathStep[], sourceLabel: string, targetLabel: string) =>
    post<PathNarration>(`/graph/${assessmentId}/narrate-path`, { path_steps: pathSteps, source_label: sourceLabel, target_label: targetLabel }),
  monteCarlo: (assessmentId: string, pathSteps: Partial<PathStep>[], iterations = 1000) =>
    post<MonteCarloResult>(`/graph/${assessmentId}/monte-carlo`, { path_steps: pathSteps, iterations }),
  getAnomalies: (assessmentId: string, daysBack = 7) =>
    get<{ anomalies: AnomalyResult[]; count: number }>(`/graph/${assessmentId}/anomalies?days_back=${daysBack}`),
  diffAssessment: (assessmentId: string, compareToId: string) =>
    get<AssessmentDiff>(`/graph/${assessmentId}/diff-assessment?compare_to=${compareToId}`),
  exportPlaybook: (assessmentId: string, pathSteps: Partial<PathStep>[], sourceLabel: string, targetLabel: string, format: 'markdown' | 'navigator_json' = 'markdown') =>
    post<{ format: string; content: string | object }>(`/graph/${assessmentId}/export-playbook`, { path_steps: pathSteps, source_label: sourceLabel, target_label: targetLabel, format }),
}

export const pkiApi = {
  templates: (assessmentId: string, vulnerableOnly?: boolean) =>
    get<CertTemplate[]>('/pki/templates', {
      params: { assessment_id: assessmentId, vulnerable_only: vulnerableOnly },
    }),

  summary: (assessmentId: string) =>
    get<PKISummary>('/pki/summary', { params: { assessment_id: assessmentId } }),
}

export const reportsApi = {
  preview: (assessmentId: string) =>
    get<ReportPreview>(`/reports/preview/${assessmentId}`),

  export: (data: { assessment_id: string; format: string; sections: string[] }) =>
    post<ReportExportResponse>('/reports/export', data, { timeout: 300_000 }),

  exportTechnique: (data: {
    technique_id: string
    title: string
    mitre_id: string
    risk_level: string
    description: string
  }) =>
    post('/reports/export-technique', data),
}

export const remediationApi = {
  candidates: (assessmentId: string) =>
    get(`/remediation/candidates/${assessmentId}`),

  simulate: (data: { assessment_id: string; finding_ids: string[]; simulate_edge_removal?: { source: string; target: string }[] }) =>
    post<RemediationSimResult>('/remediation/simulate', data),
}

export const collectionModulesApi = {
  list: () =>
    get<{ modules: CollectionModule[] }>('/modules').then((data) => data.modules),
}

export const auditApi = {
  list: (params?: { limit?: number; offset?: number; action?: string }) =>
    get<AuditLogEntry[]>('/audit', { params }),
}

export const importApi = {
  bloodhound: (assessmentId: string, file: File) => {
    const form = new FormData()
    form.append('file', file)
    return post<{ job_id: string; stream_token: string; assessment_id: string; filename: string; message: string }>(
      `/import/${assessmentId}/bloodhound`,
      form,
      { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 120_000 },
    )
  },

  bloodhoundAuto: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return post<{ job_id: string; stream_token: string; assessment_id: string; filename: string; message: string }>(
      `/import/bloodhound/auto`,
      form,
      { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 120_000 },
    )
  },

  collectorZip: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return post<{ job_id: string; stream_token: string; assessment_id: string; filename: string; message: string }>(
      `/import/collector-zip`,
      form,
      { headers: { 'Content-Type': 'multipart/form-data' }, timeout: 120_000 },
    )
  },
}

export const collectionApi = {
  ldap: (
    assessmentId: string,
    params: {
      dc_ip: string
      domain: string
      username: string
      password: string
      auth_method?: string
      use_ssl?: boolean
      port?: number
      enum_adcs?: boolean
      enum_trusts?: boolean
      enum_gpos?: boolean
      enum_acls?: boolean
      enum_gpo_acls?: boolean
      scan_sysvol?: boolean
      check_adcs_web?: boolean
      check_esc6?: boolean
      acl_include_inherited?: boolean
      acl_max_objects?: number
      obfuscation_enabled?: boolean
      obfuscation_technique?: number | string
      opsec_jitter_ms?: number
      opsec_shuffle_attrs?: boolean
    },
  ) =>
    post<{ job_id: string; stream_token: string; assessment_id: string; target: string; message: string }>(
      `/collection/ldap/${assessmentId}`,
      params,
    ),

  capabilities: () =>
    get('/collection/capabilities'),
}

export const jobsApi = {
  status: (jobId: string) =>
    get<{ job_id: string; active: boolean; status: string; done: boolean }>(`/jobs/status/${jobId}`),

  stream: (jobId: string, streamToken: string): EventSource => {
    return new EventSource(
      buildApiStreamUrl(`/jobs/stream/${jobId}`, { token: streamToken }),
      { withCredentials: true },
    )
  },
}

export const globalSearchApi = {
  search: (query: string, assessmentId?: string) =>
    get<{
      findings: { id: string; title: string; severity: string }[]
      entities: { id: string; label: string; entity_type: string }[]
    }>('/search', { params: { q: query, assessment_id: assessmentId } }),
}

export interface ADCommand {
  label: string
  command: string
  params: string[]
  platform: string
  execution_mode: 'argv' | 'manual'
}

export interface ADTechnique {
  id: string
  category: string
  title: string
  tool: string
  platform: string
  executable_on_linux: boolean
  description: string
  risk_level: string
  mitre_technique_id?: string
  requires_opt_in: boolean
  execution_supported: boolean
  execution_disabled_reason?: string | null
  commands: ADCommand[]
}

export interface ADCategory {
  name: string
  description: string
  technique_count: number
  linux_executable_count: number
}

export interface ADExecuteResult {
  technique_id: string
  command_label: string
  rendered_command: string
  stdout: string
  stderr: string
  exit_code: number
  tool_available: boolean
  execution_mode: string
}

export const adCommandsApi = {
  categories: () =>
    get<ADCategory[]>('/ad-commands/categories'),

  techniques: (params?: { category?: string; search?: string; linux_only?: boolean }) =>
    get<ADTechnique[]>('/ad-commands/techniques', { params }),

  list: <T = ADTechnique>(params?: { ids?: string }) =>
    get<T[]>('/ad-commands/list', { params }),

  technique: (id: string) =>
    get<ADTechnique>(`/ad-commands/techniques/${id}`),

  toolsAvailable: () =>
    get<Record<string, boolean>>('/ad-commands/tools/available'),

  execute: (techniqueId: string, commandIndex: number, params: Record<string, string>) =>
    post<ADExecuteResult>(`/ad-commands/execute/${techniqueId}`, {
      command_index: commandIndex,
      params,
    }, { timeout: 180_000 }),
}

export interface TrustEntry {
  id: string
  assessment_id: string
  source: string
  target: string
  trust_type: string
  direction: string
  sid_filtering: boolean
  selective_auth: boolean
  transitive: boolean
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  notes: string
  domain: string | null
  sam_account_name: string | null
  display_name: string | null
  created_at: string | null
}

export interface TrustSummary {
  assessment_id: string
  total_trusts: number
  sid_filtering_off: number
  selective_auth_off: number
  forest_trusts: number
  high_risk: number
  critical_risk: number
  trust_findings: number
  trusts: TrustEntry[]
}

export const trustsApi = {
  list: (assessmentId: string) =>
    get<TrustEntry[]>('/trusts', { params: { assessment_id: assessmentId } }),

  summary: (assessmentId: string) =>
    get<TrustSummary>('/trusts/summary', { params: { assessment_id: assessmentId } }),
}

export interface ServiceAccountEntry {
  id: string
  assessment_id: string
  sam_account_name: string
  display_name: string
  domain: string | null
  entity_type: string
  tier: number | null
  is_enabled: boolean
  is_admin_count: boolean
  is_sensitive: boolean
  spns: string[]
  kerberoastable: boolean
  asrep_roastable: boolean
  unconstrained_delegation: boolean
  constrained_delegation: boolean
  resource_based_delegation: boolean
  password_age_days: number
  password_last_set: string | null
  last_logon: string | null
  in_privileged_group: boolean
  privileged_groups: string[]
  risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  distinguished_name: string | null
  object_sid: string | null
}

export interface ServiceAccountSummary {
  assessment_id: string
  total: number
  privileged: number
  kerberoastable: number
  asrep_roastable: number
  unconstrained_delegation: number
  stale_password: number
  by_risk: Record<string, number>
  by_type: Record<string, number>
}

export const serviceAccountsApi = {
  list: (assessmentId: string, params?: { limit?: number; offset?: number }) =>
    get<ServiceAccountEntry[]>('/service-accounts', { params: { assessment_id: assessmentId, ...params } }),

  summary: (assessmentId: string) =>
    get<ServiceAccountSummary>('/service-accounts/summary', { params: { assessment_id: assessmentId } }),
}

export interface LootEntry {
  chain_id: string
  chain_name: string
  domain: string | null
  target: string | null
  loot_type: string
  items: string[]
  item_count: number
  created_at: string | null
  completed_at: string | null
}

export interface LootSummary {
  total_entries: number
  total_items: number
  chains_with_loot: number
  by_type: Record<string, number>
}

export interface LootHashIntelItem {
  id: string
  hash: string
  principal?: string | null
  source: string
  hash_type: string
  hashcat_mode: number
  john_format?: string | null
  crackable: boolean
  pass_the_hash_ready: boolean
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string
  notes: string
  chain_id?: string | null
  chain_name?: string | null
  loot_type?: string | null
}

export interface LootHashIntelHashesSection {
  items: LootHashIntelItem[]
  total: number
  total_hashes: number
  crackable: number
  crackable_hashes: number
  pass_the_hash_ready: number
  by_source: Record<string, number>
  by_hashcat_mode: Record<string, number>
}

export interface LootHashIntel {
  hashes: LootHashIntelItem[] | LootHashIntelHashesSection
  hash_items?: LootHashIntelItem[]
  total_hashes: number
  crackable_hashes: number
  pass_the_hash_ready: number
  by_source: Record<string, number>
  by_hashcat_mode: Record<string, number>
  tools: {
    hashcat?: { present: boolean; path?: string | null }
    john?: { present: boolean; path?: string | null }
    hashcat_available?: boolean
    hashcat_path?: string | null
    john_available?: boolean
    john_path?: string | null
    default_wordlist?: string | null
    wordlist_candidates: string[]
  }
  deep_dive: Array<{ name: string; signals: string[]; risk: string }>
}

export interface CrackJobResponse {
  job_id: string
  status: string
  tool?: string | null
  mode?: number | null
  wordlist?: string | null
  started_at?: number | null
  completed_at?: number | null
  error?: string | null
  output?: string[]
  cracked?: Array<{ hash: string; plaintext: string }>
}

export const lootApi = {
  list: (limit?: number) =>
    get<LootEntry[]>('/loot', { params: { limit } }),

  summary: () =>
    get<LootSummary>('/loot/summary'),

  hashIntel: () =>
    get<LootHashIntel>('/loot/hash-intel'),

  startCrack: (data: { hashes: string[]; hashcat_mode: number; wordlist?: string; tool?: string; acknowledge_authorized: boolean }) =>
    post<CrackJobResponse>('/loot/crack/start', data),

  crackJob: (jobId: string) =>
    get<CrackJobResponse>(`/loot/crack/${jobId}`),

  exportUrl: () => `${getApiBaseUrl()}/loot/export`,

  clearChain: (chainId: string) =>
    api.delete(`/loot/${chainId}`),

  addManualHash: (data: { hash: string; principal?: string; source?: string }) =>
    post<{ added: boolean; hash: LootHashIntelItem; chain_id: string }>('/loot/hash/manual', data),

  collectStream: (data: {
    techniques: string[]
    target: string
    domain: string
    username?: string
    password?: string
    hashes?: string
    dc_ip?: string
  }): Promise<Response> => {
    const url = `${getApiBaseUrl()}/loot/collect`
    return fetch(url, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: JSON.stringify(data),
    })
  },
}

import type {
  TrustAbuseReport,
  TrustAbuseTechnique,
  LMSummary,
  LMPath,
  LMTechnique,
  LMChain,
  ForestPivotReport,
  ForestPivotPath,
} from './types'

export interface TrustSimOverride {
  trust_name: string
  sid_filtering?: boolean
  selective_auth?: boolean
  direction?: string
}

export interface TrustSimResult {
  assessment_id: string
  simulation: boolean
  overrides_applied: number
  baseline: { technique_count: number; pivot_paths: number; techniques: string[] }
  simulated: { technique_count: number; pivot_paths: number; techniques: string[] }
  delta: {
    techniques_eliminated: string[]
    techniques_introduced: string[]
    net_technique_change: number
    pivot_path_change: number
  }
}

export const trustAbuseApi = {
  getReport: (assessmentId: string) =>
    get<TrustAbuseReport>('/trusts/abuse', { params: { assessment_id: assessmentId } }),

  getTechniques: (assessmentId: string) =>
    get<TrustAbuseTechnique[]>('/trusts/abuse/techniques', { params: { assessment_id: assessmentId } }),

  simulate: (assessmentId: string, overrides: TrustSimOverride[]) =>
    post<TrustSimResult>('/trusts/simulate', { overrides }, { params: { assessment_id: assessmentId } }),
}

export const lateralMovementApi = {
  getSummary: (assessmentId: string) =>
    get<LMSummary>('/lateral-movement/summary', { params: { assessment_id: assessmentId } }),

  getPaths: (assessmentId: string, technique?: string) =>
    get<LMPath[]>('/lateral-movement/paths', {
      params: { assessment_id: assessmentId, ...(technique ? { technique } : {}) },
    }),

  getTechniques: (assessmentId: string) =>
    get<LMTechnique[]>('/lateral-movement/techniques', { params: { assessment_id: assessmentId } }),

  getChains: (assessmentId: string) =>
    get<LMChain[]>('/lateral-movement/chains', { params: { assessment_id: assessmentId } }),
}

export const forestPivotApi = {
  getReport: (assessmentId: string) =>
    get<ForestPivotReport>('/trusts/forest-pivot', { params: { assessment_id: assessmentId } }),

  getPaths: (assessmentId: string) =>
    get<ForestPivotPath[]>('/trusts/forest-pivot/paths', { params: { assessment_id: assessmentId } }),
}

export { sessionApi } from './sessionApi'
export { toolCheckerApi } from './toolCheckerApi'
export { aiOperatorApi } from './aiOperatorApi'

export default api
