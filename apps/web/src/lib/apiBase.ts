export function getApiBaseUrl() {
  const explicitBaseUrl = process.env.NEXT_PUBLIC_API_URL?.trim()
  if (explicitBaseUrl) {
    const normalized = normalizeLoopbackApiUrl(explicitBaseUrl)
    return normalized.endsWith('/api/v1') ? normalized : `${normalized}/api/v1`
  }
  if (typeof window !== 'undefined' && isLoopbackHost(window.location.hostname)) {
    return `${window.location.protocol}//${window.location.hostname}:8000/api/v1`
  }
  return '/api/v1'
}

export function getWsApiBaseUrl(explicitBaseUrl?: string) {
  const configured =
    explicitBaseUrl?.trim() ||
    process.env.NEXT_PUBLIC_WS_URL?.trim() ||
    process.env.NEXT_PUBLIC_API_URL?.trim()

  if (configured) {
    const normalized = configured.replace(/\/$/, '').replace(/^http/, 'ws')
    return normalized.endsWith('/api/v1') ? normalized : `${normalized}/api/v1`
  }

  if (typeof window === 'undefined') {
    return 'ws://127.0.0.1:8000/api/v1'
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${protocol}//${window.location.hostname}:8000/api/v1`
}

function normalizeLoopbackApiUrl(url: string) {
  const trimmed = url.replace(/\/$/, '')
  if (typeof window === 'undefined') return trimmed

  try {
    const parsed = new URL(trimmed)
    if (isLoopbackHost(parsed.hostname) && isLoopbackHost(window.location.hostname)) {
      parsed.hostname = window.location.hostname
      return parsed.toString().replace(/\/$/, '')
    }
  } catch {
    return trimmed
  }

  return trimmed
}

function isLoopbackHost(hostname: string) {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1'
}
