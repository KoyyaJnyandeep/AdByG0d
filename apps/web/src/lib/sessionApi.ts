import axios from 'axios'
import { getApiBaseUrl } from './apiBase'

const api = axios.create({
  baseURL: getApiBaseUrl(),
  withCredentials: true,
  headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
})

export type AuthLevel = 'anon' | 'authenticated' | 'local_admin' | 'domain_admin' | 'da_forest' | 'system'

export interface OperatorSession {
  id: string
  target_ip: string | null
  domain: string | null
  auth_level: AuthLevel
  commands_run: number
  findings_count: number
  machines_owned: number
  users_owned: number
  started_at: string
}

export interface SessionUpdateRequest {
  target_ip?: string
  domain?: string
  auth_level?: AuthLevel
  commands_delta?: number
  findings_delta?: number
  machines_delta?: number
  users_delta?: number
}

export const sessionApi = {
  get: () => api.get<OperatorSession>('/session').then(r => r.data),
  update: (body: SessionUpdateRequest) => api.post<OperatorSession>('/session/update', body).then(r => r.data),
  reset: () => api.post<OperatorSession>('/session/reset').then(r => r.data),
}
