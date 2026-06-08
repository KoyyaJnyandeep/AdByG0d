import api from './api'
import type { AxiosResponse } from 'axios'

export type ConnectivityMode = 'DIRECT' | 'SOCKS5' | 'CHISEL' | 'LIGOLO' | 'RELAY_AGENT' | 'MANAGED_SSH_SOCKS'
export type ProfileStatus = 'UNKNOWN' | 'ONLINE' | 'DEGRADED' | 'OFFLINE'

export interface ConnectivityProfile {
  id: string
  name: string
  mode: ConnectivityMode
  config: Record<string, unknown>
  is_default: boolean
  status: ProfileStatus
  last_tested_at: string | null
  last_latency_ms: number | null
  notes: string | null
  created_at: string
}

export interface ConnectivityTestResult {
  profile_id: string
  success: boolean
  status: ProfileStatus
  latency_ms: number | null
  error: string | null
  details: Record<string, { success: boolean; latency_ms: number | null; error: string | null }>
  capabilities: Record<string, boolean>
  readiness_pct: number
  open_ports: number[]
}

export interface ChiselServerStatus {
  running: boolean
  pid: number | null
  port: number | null
  client_cmd: string | null
  client_cmd_template: string | null
  connected_clients: number
}

export interface TunnelSession {
  id: string
  profile_id: string
  mode: string
  jumpbox_host: string
  jumpbox_port: number
  jumpbox_username: string
  local_host: string
  local_port: number
  process_pid: number | null
  status: string
  started_by: string
  started_at: string
  stopped_at: string | null
  last_healthcheck_at: string | null
  error_summary: string | null
  sanitized_command_preview: string
  metadata_json: Record<string, unknown>
  tunnel_endpoint: string | null
}

export interface LigoloStatus {
  running: boolean
  pid: number | null
  port: number | null
  tun_interface: string | null
  routes: string[]
  sessions: Record<string, unknown>[]
}

export interface ConnectivityStats {
  total: number
  online: number
  offline: number
  degraded: number
  unknown: number
  active_tunnels: number
  best_latency_ms: number | null
  total_open_ports: number
  modes_used: string[]
}

export interface ProbeHistoryEntry {
  target_host: string
  status: ProfileStatus
  latency_ms: number | null
  open_ports: number[]
  capabilities: Record<string, boolean>
  readiness_pct: number
  tested_at: string
}

function unwrap<T>(promise: Promise<AxiosResponse<T>>): Promise<T> {
  return promise.then((response) => response.data)
}

export const connectivityApi = {
  listProfiles: (): Promise<ConnectivityProfile[]> =>
    unwrap(api.get('/connectivity/profiles')),

  createProfile: (data: {
    name: string
    mode: ConnectivityMode
    config: Record<string, unknown>
    is_default?: boolean
    notes?: string
  }): Promise<ConnectivityProfile> =>
    unwrap(api.post('/connectivity/profiles', data)),

  getProfile: (id: string): Promise<ConnectivityProfile> =>
    unwrap(api.get('/connectivity/profiles/' + id)),

  updateProfile: (
    id: string,
    data: { name?: string; config?: Record<string, unknown>; is_default?: boolean; notes?: string }
  ): Promise<ConnectivityProfile> =>
    unwrap(api.patch('/connectivity/profiles/' + id, data)),

  deleteProfile: (id: string): Promise<void> =>
    unwrap(api.delete('/connectivity/profiles/' + id)),

  testProfile: (id: string, targetHost: string): Promise<ConnectivityTestResult> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/test', { target_host: targetHost })),

  chiselStart: (id: string): Promise<ChiselServerStatus> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/chisel/start')),

  chiselStop: (id: string): Promise<ChiselServerStatus> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/chisel/stop')),

  chiselStatus: (id: string): Promise<ChiselServerStatus> =>
    unwrap(api.get('/connectivity/profiles/' + id + '/chisel/status')),

  chiselLogs: (id: string): Promise<{ lines: string[] }> =>
    unwrap(api.get('/connectivity/profiles/' + id + '/chisel/logs')),

  ligoloStart: (id: string): Promise<LigoloStatus> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/ligolo/start')),

  ligoloStop: (id: string): Promise<LigoloStatus> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/ligolo/stop')),

  ligoloStatus: (id: string): Promise<LigoloStatus> =>
    unwrap(api.get('/connectivity/profiles/' + id + '/ligolo/status')),

  ligoloAddRoute: (id: string, cidr: string): Promise<{ routes: string[] }> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/ligolo/route', { cidr })),

  tunnelStart: (id: string, password?: string): Promise<TunnelSession> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/tunnel/start', { password })),

  tunnelStop: (id: string): Promise<TunnelSession> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/tunnel/stop')),

  tunnelStatus: (id: string): Promise<TunnelSession> =>
    unwrap(api.get('/connectivity/profiles/' + id + '/tunnel/status')),

  tunnelLogs: (id: string): Promise<{ lines: string[] }> =>
    unwrap(api.get('/connectivity/profiles/' + id + '/tunnel/logs')),

  getStats: (): Promise<ConnectivityStats> =>
    unwrap(api.get('/connectivity/stats')),

  cloneProfile: (id: string): Promise<ConnectivityProfile> =>
    unwrap(api.post('/connectivity/profiles/' + id + '/clone')),

  batchProbe: (ids: string[], targetHost: string): Promise<ConnectivityTestResult[]> =>
    Promise.all(ids.map(id => unwrap(api.post('/connectivity/profiles/' + id + '/test', { target_host: targetHost })))),

  exportProfile: (profile: ConnectivityProfile): void => {
    const safe = { ...profile, config: { ...profile.config } }
    const sensitiveKeys = ['auth_token', 'client_cmd', 'server_pid', 'ssh_key_path', 'probe_history', 'last_probe']
    sensitiveKeys.forEach(k => { if (k in safe.config) delete safe.config[k] })
    const blob = new Blob([JSON.stringify(safe, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `connectivity-profile-${profile.name.replace(/\s+/g, '-').toLowerCase()}.json`
    a.click()
    URL.revokeObjectURL(url)
  },

  ligoloLogs: (id: string): Promise<{ lines: string[] }> =>
    unwrap(api.get('/connectivity/profiles/' + id + '/ligolo/logs')),
}
