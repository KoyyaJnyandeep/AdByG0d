import 'server-only'

import { cookies } from 'next/headers'

import type {
  Assessment,
  CollectionModule,
  DashboardData,
  FindingsPage,
  PlatformUser,
  WorkspaceOption,
} from './types'

type QueryValue = string | number | boolean | null | undefined
type QueryParams = Record<string, QueryValue>

export class ServerApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly detail: string
  ) {
    super(message)
    this.name = 'ServerApiError'
  }
}

export function isUnauthorizedServerApiError(error: unknown) {
  return (
    error instanceof ServerApiError && error.status === 401
  ) || (
    typeof error === 'object' &&
    error !== null &&
    'status' in error &&
    (error as { status?: unknown }).status === 401
  )
}

function getServerApiBaseUrl() {
  const rawBase =
    process.env.API_URL?.trim() ||
    process.env.NEXT_PUBLIC_API_URL?.trim() ||
    'http://127.0.0.1:8000'

  const normalized = rawBase.replace(/\/$/, '')
  return normalized.endsWith('/api/v1') ? normalized : `${normalized}/api/v1`
}

function buildUrl(path: string, params?: QueryParams) {
  const url = new URL(`${getServerApiBaseUrl()}${path}`)

  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === '') continue
      url.searchParams.set(key, String(value))
    }
  }

  return url.toString()
}

async function serverGet<T>(path: string, params?: QueryParams) {
  const cookieStore = await cookies()
  const response = await fetch(buildUrl(path, params), {
    method: 'GET',
    headers: {
      cookie: cookieStore.toString(),
      accept: 'application/json',
    },
    cache: 'no-store',
  })

  if (!response.ok) {
    const detail = await response.text()
    throw new ServerApiError(
      `Server API GET ${path} failed: ${response.status} ${detail}`,
      response.status,
      detail
    )
  }

  return response.json() as Promise<T>
}

export const serverAssessmentApi = {
  latest: () => serverGet<Assessment[]>('/assessments', { limit: 1 }),
  list: (limit = 100) => serverGet<Assessment[]>('/assessments', { limit }),
  dashboard: (assessmentId: string) => serverGet<DashboardData>(`/assessments/${assessmentId}/dashboard`),
  workspaces: () => serverGet<WorkspaceOption[]>('/assessments/workspaces'),
}

export const serverFindingsApi = {
  list: (assessmentId: string, pageSize = 500) =>
    serverGet<FindingsPage>('/findings', { assessment_id: assessmentId, page_size: pageSize }),
}

export const serverAuthApi = {
  me: () => serverGet<PlatformUser>('/auth/me'),
}

export const serverCollectionModulesApi = {
  list: async () => {
    const data = await serverGet<{ modules: CollectionModule[] }>('/modules')
    return data.modules
  },
}
