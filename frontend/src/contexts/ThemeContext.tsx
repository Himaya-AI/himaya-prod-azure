'use client'
/**
 * ThemeContext — per-user, persisted theme (dark | light).
 *
 * Key: `helios-theme-{userId}` when logged in, `helios-theme` as fallback.
 * Applied via data-theme on <html>. CSS variables in globals.css do the rest.
 *
 * Listens to storage events so multi-tab switches stay in sync.
 */
import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react'

type Theme = 'dark' | 'light'

interface ThemeCtx {
  theme: Theme
  setTheme: (t: Theme) => void
}

const ThemeContext = createContext<ThemeCtx>({ theme: 'dark', setTheme: () => {} })

function getThemeKey(): string {
  try {
    const raw = typeof window !== 'undefined' ? localStorage.getItem('sentinel_user') : null
    const user = raw ? JSON.parse(raw) : null
    return user?.id ? `helios-theme-${user.id}` : 'helios-theme'
  } catch {
    return 'helios-theme'
  }
}

function readSavedTheme(): Theme {
  try {
    const key = getThemeKey()
    const t = localStorage.getItem(key) as Theme | null
    // Also check the generic fallback key (set before login)
    return t || (localStorage.getItem('helios-theme') as Theme | null) || 'dark'
  } catch {
    return 'dark'
  }
}

function applyTheme(t: Theme) {
  if (typeof document !== 'undefined') {
    document.documentElement.setAttribute('data-theme', t)
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>('dark')

  // On mount, read saved theme and apply it (also handles post-login rehydration)
  useEffect(() => {
    const t = readSavedTheme()
    setThemeState(t)
    applyTheme(t)
  }, [])

  // If user logs in/out, re-apply the correct theme for the new user
  useEffect(() => {
    function onStorage(e: StorageEvent) {
      if (e.key === 'sentinel_user' || e.key === 'sentinel_token') {
        const t = readSavedTheme()
        setThemeState(t)
        applyTheme(t)
      }
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const setTheme = useCallback((t: Theme) => {
    setThemeState(t)
    applyTheme(t)
    try {
      const key = getThemeKey()
      localStorage.setItem(key, t)
      // Also write to generic key so inline script catches it before login resolves
      localStorage.setItem('helios-theme', t)
    } catch {}
  }, [])

  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  return useContext(ThemeContext)
}
