import { NextRequest, NextResponse } from 'next/server'
import { approvedBackendUrl, safeProxyHeaders } from '@/lib/proxySecurity'

// Abort slow backend requests and strip hop-by-hop headers before forwarding.
const PROXY_TIMEOUT_MS = 300_000

async function handleRequest(request: NextRequest) {
  const { pathname, search } = new URL(request.url)
  const backend = approvedBackendUrl()
  if (!backend) {
    return new NextResponse('Configured API backend origin is not approved', { status: 502 })
  }

  const url = `${backend.toString().replace(/\/$/, '')}${pathname}${search}`
  const headers = safeProxyHeaders(request.headers)

  const body = ['GET', 'HEAD'].includes(request.method)
    ? undefined
    : await request.arrayBuffer()

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS)

  let response: Response
  try {
    response = await fetch(url, {
      method: request.method,
      headers,
      body,
      redirect: 'manual',
      signal: controller.signal,
    })
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      return new NextResponse('Gateway Timeout', { status: 504 })
    }
    throw err
  } finally {
    clearTimeout(timer)
  }

  const nextResponse = new NextResponse(response.body, {
    status: response.status,
    statusText: response.statusText,
  })

  response.headers.forEach((value, key) => {
    if (key.toLowerCase() !== 'set-cookie') {
      nextResponse.headers.set(key, value)
    }
  })

  // Use getSetCookie() to avoid multi-value merging bug in Node.js Fetch
  const setCookies: string[] =
    typeof (response.headers as { getSetCookie?: () => string[] }).getSetCookie === 'function'
      ? (response.headers as { getSetCookie: () => string[] }).getSetCookie()
      : response.headers.get('set-cookie')
        ? [response.headers.get('set-cookie')!]
        : []

  for (const cookie of setCookies) {
    nextResponse.headers.append('set-cookie', cookie)
  }

  return nextResponse
}

export const GET = handleRequest
export const POST = handleRequest
export const PUT = handleRequest
export const PATCH = handleRequest
export const DELETE = handleRequest
