import { QueryClient } from '@tanstack/react-query'

function getErrorStatus(error: unknown) {
  const maybeError = error as {
    status?: unknown
    response?: { status?: unknown }
  }
  const status = maybeError?.response?.status ?? maybeError?.status
  return typeof status === 'number' ? status : undefined
}

function shouldRetryQuery(failureCount: number, error: unknown) {
  const status = getErrorStatus(error)
  if (status === 401 || status === 403 || status === 404) {
    return false
  }
  return failureCount < 1
}

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5 * 60 * 1000,
        gcTime: 10 * 60 * 1000,
        retry: shouldRetryQuery,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
      },
    },
  })
}
