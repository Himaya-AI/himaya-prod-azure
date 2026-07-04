import axios, { AxiosError, AxiosRequestConfig } from 'axios'

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || '',
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,   // 15s default — prevents infinite hangs on cold containers
})

// Mark a request as retried so we don't retry forever.
interface RetryConfig extends AxiosRequestConfig {
  _retryCount?: number
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('sentinel_token')
    if (token) config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Track recent 401s to debounce — a single stale background poll shouldn't
// nuke the session if the user is mid-flow.
let last401At = 0
let pending401Count = 0

api.interceptors.response.use(
  (response) => {
    // Successful response — reset any 401 backoff (token is clearly valid).
    if (pending401Count > 0) {
      pending401Count = 0
      last401At = 0
    }
    return response
  },
  async (error: AxiosError) => {
    const config = (error.config || {}) as RetryConfig
    const status = error.response?.status
    // Transient-error retry for GET requests. Adnan 2026-06-17: dashboard
    // and Workspace Security panels sometimes load blank because a single
    // 502 / 503 / 504 / network blip during ECS task replacement gets
    // swallowed by the .catch{} blocks in the page. We now retry the GET
    // twice with backoff before giving up — 95% of these clear on retry.
    const isGet = (config.method || 'get').toLowerCase() === 'get'
    const isTransient = (
      status === 502 || status === 503 || status === 504 || status === 429 ||
      error.code === 'ECONNABORTED' ||
      error.code === 'ERR_NETWORK' ||
      (error.message || '').toLowerCase().includes('network')
    )
    if (isGet && isTransient && (config._retryCount ?? 0) < 2 && config.url) {
      config._retryCount = (config._retryCount ?? 0) + 1
      // exponential-ish backoff: 400ms, 1200ms
      await sleep(config._retryCount === 1 ? 400 : 1200)
      try {
        return await api.request(config)
      } catch (e) {
        // fall through to normal error handling
        error = e as AxiosError
      }
    }
    if (error.response?.status === 401 && typeof window !== 'undefined') {
      // Never kick the user mid-flow on auth pages.
      const path = window.location.pathname || ''
      if (path === '/login' || path.startsWith('/auth')) {
        return Promise.reject(error)
      }
      const now = Date.now()
      // Within a 5 sec window, require at least 2 consecutive 401s before
      // forcing logout. This filters out single stale background polls.
      if (now - last401At > 5000) {
        pending401Count = 1
      } else {
        pending401Count += 1
      }
      last401At = now
      // Only force logout after we have 2 401s in 5 sec, AND no successful
      // request in between.
      if (pending401Count >= 2) {
        localStorage.removeItem('sentinel_token')
        localStorage.removeItem('sentinel_user')
        window.location.href = '/login'
      }
      // Otherwise, let the caller handle the 401 (e.g. show "Connection
      // failed" in the modal) without losing the session.
    }
    return Promise.reject(error)
  }
)

export default api
