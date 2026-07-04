import { NextRequest, NextResponse } from 'next/server'

// Vendor admin portal IP allowlist — fail-closed.
// ADMIN_IP_ALLOWLIST: comma-separated IPv4 addresses or CIDR ranges.
// Client IP is taken from Front Door's X-Azure-ClientIP header, with
// X-Forwarded-For fallback for direct Container App ingress.

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const p of parts) {
    const n = Number(p)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out = (out << 8) | n
  }
  return out >>> 0
}

function ipInCidr(ip: string, cidr: string): boolean {
  const [base, bitsStr] = cidr.includes('/') ? cidr.split('/') : [cidr, '32']
  const bits = Number(bitsStr)
  const ipInt = ipv4ToInt(ip)
  const baseInt = ipv4ToInt(base)
  if (ipInt === null || baseInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    // Non-IPv4 (e.g. IPv6) — fall back to exact string match
    return ip === base
  }
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return (ipInt & mask) === (baseInt & mask)
}

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl
  if (!pathname.startsWith('/admin')) return NextResponse.next()

  const allowlist = (process.env.ADMIN_IP_ALLOWLIST || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  const clientIp =
    request.headers.get('x-azure-clientip') ||
    (request.headers.get('x-forwarded-for') || '').split(',')[0].trim()

  const allowed =
    allowlist.length > 0 && !!clientIp && allowlist.some((entry) => ipInCidr(clientIp, entry))

  if (!allowed) {
    // Hide the portal's existence from unauthorized networks
    return new NextResponse('Not Found', { status: 404 })
  }
  return NextResponse.next()
}

export const config = {
  matcher: ['/admin/:path*', '/admin'],
}
