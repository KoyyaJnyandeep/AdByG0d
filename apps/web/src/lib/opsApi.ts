import { getApiBaseUrl } from './apiBase'

export interface Job {
  id: string
  technique_id: string
  target: string
  executor: string
  status: string
  opsec_profile: string
  created_at: string
  started_at?: string | null
  completed_at?: string | null
  exit_code: number | null
}

export interface ExecuteRequest {
  technique_id: string
  target: string
  params?: Record<string, string | boolean | number>
  opsec_profile?: 'LOUD' | 'BALANCED' | 'GHOST'
  assessment_id?: string
}

export interface TargetProfile {
  target: string
  domain: string
  username: string
  password: string
  dc_ip: string
}

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${getApiBaseUrl()}${path}`, {
    credentials: 'include',
    ...init,
    headers: {
      'X-Requested-With': 'XMLHttpRequest',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...init?.headers,
    },
  })
}

export async function executeJob(req: ExecuteRequest): Promise<Job> {
  const resp = await apiFetch('/ops/execute', {
    method: 'POST',
    body: JSON.stringify(req),
  })
  if (!resp.ok) throw new Error(await resp.text())
  return resp.json()
}

export async function listJobs(limit = 50): Promise<Job[]> {
  const resp = await apiFetch(`/ops/jobs?limit=${limit}`)
  if (!resp.ok) throw new Error(await resp.text())
  return resp.json()
}

export async function getJobOutput(jobId: string): Promise<Array<{ stream: string; line: string; ts: string }>> {
  const resp = await apiFetch(`/ops/jobs/${jobId}/output`)
  if (!resp.ok) return []
  return resp.json()
}

export async function killJob(jobId: string): Promise<void> {
  const resp = await apiFetch(`/ops/jobs/${jobId}`, { method: 'DELETE' })
  if (!resp.ok) throw new Error(await resp.text())
}

export async function getTargetProfile(): Promise<TargetProfile> {
  const resp = await apiFetch('/ops/profile')
  if (!resp.ok) return { target: '', domain: '', username: '', password: '', dc_ip: '' }
  return resp.json()
}

export async function saveTargetProfile(profile: TargetProfile): Promise<TargetProfile> {
  const resp = await apiFetch('/ops/profile', {
    method: 'PUT',
    body: JSON.stringify(profile),
  })
  if (!resp.ok) throw new Error(await resp.text())
  return resp.json()
}
