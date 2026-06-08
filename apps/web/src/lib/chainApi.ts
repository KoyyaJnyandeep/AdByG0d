import { getApiBaseUrl, getWsApiBaseUrl } from './apiBase'

function redirectToLogin() {
  if (typeof window !== 'undefined' && window.location.pathname !== '/login') {
    window.location.href = '/login'
  }
}

async function parseError(resp: Response) {
  let detail = resp.statusText
  try {
    const body = await resp.json()
    detail = body.detail ?? detail
  } catch {
    try {
      detail = await resp.text()
    } catch {
      /* ignore */
    }
  }
  return detail
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${getApiBaseUrl()}${path}`, {
    credentials: 'include',
    ...init,
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
  if (!resp.ok) {
    if (resp.status === 401) {
      redirectToLogin()
    }
    throw new Error(await parseError(resp))
  }
  if (resp.status === 204) {
    return undefined as T
  }
  return resp.json()
}

export interface ChainStep {
  index: number
  technique_id: string
  label: string
  description: string
  mitre: string
  edge_type: string
  src_label: string
  tgt_label: string
  target: string
  params: Record<string, string | boolean | number>
  is_manual?: boolean
}

export interface Chain {
  id: string
  name: string
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'STOPPED' | 'PAUSED'
  steps: ChainStep[]
  path_nodes: string[]
  current_step: number
  job_ids: string[]
  loot: Record<string, unknown>
  target: string | null
  domain: string | null
  target_label: string | null
  created_at: string
  started_at: string | null
  completed_at: string | null
}

export interface ChainRequest {
  assessment_id?: string | null
  target: string
  domain: string
  username?: string
  password?: string
  hashes?: string
  dc_ip?: string
  opsec_profile?: 'LOUD' | 'BALANCED' | 'GHOST'
  situation?: string
  path_id?: string | null
}

export interface ChainPreflightResult {
  ok: boolean
  target: string
  dc_ip: string
  ports: Record<string, boolean>
  ldap_bind: Record<string, unknown>
  errors: string[]
  warnings: string[]
}

export interface ChainEvent {
  chain_id: string
  event: string
  step?: number
  technique?: string
  label?: string
  job_id?: string
  target?: string
  stream?: string
  line?: string
  ts?: string
  exit_code?: number
  error?: string
  total_steps?: number
  message?: string
  // loot_captured event fields
  loot_type?: string
  value?: string
}

export async function resolveChain(req: ChainRequest): Promise<{ steps: ChainStep[]; path_nodes: string[]; step_count: number; all_paths: unknown[] }> {
  return fetchJson('/chains/resolve', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

export async function preflightChain(req: ChainRequest): Promise<ChainPreflightResult> {
  return fetchJson('/chains/preflight', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

export async function createChain(req: ChainRequest): Promise<Chain> {
  return fetchJson('/chains', {
    method: 'POST',
    body: JSON.stringify(req),
  })
}

export async function startChain(chainId: string): Promise<Chain> {
  return fetchJson(`/chains/${chainId}/start`, {
    method: 'POST',
  })
}

export async function stopChain(chainId: string): Promise<void> {
  await fetchJson(`/chains/${chainId}/stop`, {
    method: 'POST',
  })
}

export async function getChain(chainId: string): Promise<Chain> {
  return fetchJson(`/chains/${chainId}`)
}

export async function listChains(limit = 20): Promise<Chain[]> {
  return fetchJson(`/chains?limit=${limit}`)
}

export function connectChainWs(chainId: string, onEvent: (e: ChainEvent) => void): WebSocket {
  const url = `${getWsApiBaseUrl()}/chains/ws/${chainId}`
  const ws = new WebSocket(url)
  ws.onmessage = (msg) => {
    try { onEvent(JSON.parse(msg.data)) } catch { /* ignore malformed */ }
  }
  return ws
}

export interface ChainSituation {
  id: string
  label: string
  description: string
  example: string
  color: string
  icon: string
  credential_required: boolean
}

export interface PathStepPreview {
  technique_id: string
  label: string
  mitre: string
  description: string
  edge_type: string
  src_label: string
  tgt_label: string
  is_manual: boolean
  manual_prompt: string
  loot_produces: string | null
  loot_requires: string | null
}

export interface PathLibraryEntry {
  id: string
  name: string
  description: string
  confidence: number
  step_count: number
  tags: string[]
  situations: string[]
  steps_preview: PathStepPreview[]
}

export async function getSituations(): Promise<{ situations: ChainSituation[] }> {
  return fetchJson('/chains/situations')
}

export async function getLibrary(situation: string): Promise<{ situation: string; paths: PathLibraryEntry[]; total: number }> {
  return fetchJson(`/chains/library?situation=${encodeURIComponent(situation)}`)
}
