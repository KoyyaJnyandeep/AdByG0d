import api from './api'

const BASE = '/tool-checker'

export interface ToolResult {
  tool_name: string
  available: boolean
  version: string | null
  install_cmd: string
  phases: number[]
  checked_at: string | null
}

export const toolCheckerApi = {
  scan: () => api.post<{ status: string; message: string }>(`${BASE}/scan`).then(r => r.data),
  results: () => api.get<ToolResult[]>(`${BASE}/results`).then(r => r.data),
}
