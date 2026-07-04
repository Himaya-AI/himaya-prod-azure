const ADMIN_TOKEN_KEY = 'sentinel_admin_token'
const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'https://app.himaya.ai'
const ADMIN_API_KEY = process.env.NEXT_PUBLIC_ADMIN_API_KEY || ''

export function isAdminAuthenticated(): boolean {
  if (typeof window === 'undefined') return false
  return !!localStorage.getItem(ADMIN_TOKEN_KEY)
}

export function getAdminToken(): string | null {
  if (typeof window === 'undefined') return null
  return localStorage.getItem(ADMIN_TOKEN_KEY)
}

export function setAdminToken(token: string): void {
  localStorage.setItem(ADMIN_TOKEN_KEY, token)
}

export function clearAdminToken(): void {
  localStorage.removeItem(ADMIN_TOKEN_KEY)
}

export const ADMIN_HEADERS = {
  'X-Admin-API-Key': ADMIN_API_KEY,
  'Content-Type': 'application/json',
}

export async function adminFetch(path: string, options: RequestInit = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...ADMIN_HEADERS,
      ...(options.headers || {}),
    },
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Request failed' }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}
