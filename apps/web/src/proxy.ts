import { NextResponse, type NextRequest } from 'next/server'

const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'adbygod_session'
const PUBLIC_ROUTE_PREFIXES = ['/login', '/health']

function base64UrlDecode(value: string) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64.padEnd(base64.length + ((4 - base64.length % 4) % 4), '=')
  return atob(padded)
}

// UX redirect helper only — checks JWT shape and expiry to avoid unnecessary round-trips to
// the login page, but does NOT verify the JWT signature. Backend APIs remain the real security
// boundary; a forged cookie is rejected there, not here.
function isUsableJwtCookie(value: string | undefined) {
  if (!value) {
    return false
  }

  const parts = value.split('.')
  if (parts.length !== 3) {
    return false
  }

  try {
    const payload = JSON.parse(base64UrlDecode(parts[1])) as { exp?: unknown; type?: unknown }
    if (payload.type !== 'access') {
      return false
    }

    if (typeof payload.exp === 'number') {
      const expiresAtMs = payload.exp * 1000
      if (expiresAtMs <= Date.now()) {
        return false
      }
    }
  } catch {
    return false
  }

  return true
}

function isPublicPath(pathname: string) {
  if (PUBLIC_ROUTE_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`))) {
    return true
  }

  if (pathname.startsWith('/api/')) {
    return true
  }

  return false
}

function nextDestination(request: NextRequest) {
  const destination = `${request.nextUrl.pathname}${request.nextUrl.search}`
  return destination.startsWith('/') && !destination.startsWith('//') ? destination : '/'
}

export function proxy(request: NextRequest) {
  if (isPublicPath(request.nextUrl.pathname)) {
    return NextResponse.next()
  }

  const authCookie = request.cookies.get(AUTH_COOKIE_NAME)?.value
  if (isUsableJwtCookie(authCookie)) {
    return NextResponse.next()
  }

  const loginUrl = new URL('/login', request.url)
  loginUrl.searchParams.set('next', nextDestination(request))
  const response = NextResponse.redirect(loginUrl)
  response.cookies.delete(AUTH_COOKIE_NAME)
  return response
}

export const config = {
  matcher: ['/((?!api/|_next/static|_next/image|favicon.ico|.*\\..*).*)'],
}
