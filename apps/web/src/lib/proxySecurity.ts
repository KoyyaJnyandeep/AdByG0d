export const DEFAULT_API_ALLOWED_ORIGINS = [
  'http://127.0.0.1:8000',
  'http://localhost:8000',
  'http://0.0.0.0:8000',
]

export const HOP_BY_HOP_HEADERS = new Set([
  'host', 'connection', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade',
  'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for',
  'forwarded', 'origin', 'referer',
])

export function getBackendUrlFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return (
    env['API_URL'] ||
    env['NEXT_PUBLIC_API_URL'] ||
    'http://127.0.0.1:8000'
  ).replace(/\/$/, '')
}

export function allowedBackendOrigins(env: NodeJS.ProcessEnv = process.env): Set<string> {
  const configured = env['API_ALLOWED_ORIGINS']
  const values = configured
    ? configured.split(',').map((value) => value.trim()).filter(Boolean)
    : DEFAULT_API_ALLOWED_ORIGINS

  return new Set(values.map((value) => new URL(value).origin))
}

export function approvedBackendUrl(env: NodeJS.ProcessEnv = process.env): URL | null {
  let backend: URL
  try {
    backend = new URL(getBackendUrlFromEnv(env))
  } catch {
    return null
  }
  return allowedBackendOrigins(env).has(backend.origin) ? backend : null
}

export function safeProxyHeaders(requestHeaders: Headers): Headers {
  const headers = new Headers()
  requestHeaders.forEach((value, key) => {
    if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
      headers.set(key, value)
    }
  })
  return headers
}
