'use client'
/**
 * Lightweight toast system — theme-aware (data-theme="light" / "dark").
 * Uses inline styles so it responds to data-theme without Tailwind dark: variant.
 */
import { useEffect, useState, useCallback } from 'react'
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react'
import { useTheme } from '@/contexts/ThemeContext'

// ─── Types ────────────────────────────────────────────────────────────────────

type ToastKind = 'error' | 'success' | 'info'

interface ToastItem {
  id: string
  kind: ToastKind
  message: string
}

type Listener = (items: ToastItem[]) => void

// ─── Internal store (module-level singleton) ───────────────────────────────

let _items: ToastItem[] = []
const _listeners: Set<Listener> = new Set()

function _notify() {
  _listeners.forEach(l => l([..._items]))
}

function _push(kind: ToastKind, message: string, durationMs = 4500) {
  const id = Math.random().toString(36).slice(2)
  _items = [..._items, { id, kind, message }]
  _notify()
  setTimeout(() => {
    _items = _items.filter(t => t.id !== id)
    _notify()
  }, durationMs)
}

// ─── Public API ───────────────────────────────────────────────────────────────

export const toast = {
  error:   (msg: string, ms?: number) => _push('error',   msg, ms),
  success: (msg: string, ms?: number) => _push('success', msg, ms),
  info:    (msg: string, ms?: number) => _push('info',    msg, ms),
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

function useToasts() {
  const [items, setItems] = useState<ToastItem[]>([])

  useEffect(() => {
    setItems([..._items])
    _listeners.add(setItems)
    return () => { _listeners.delete(setItems) }
  }, [])

  const dismiss = useCallback((id: string) => {
    _items = _items.filter(t => t.id !== id)
    _notify()
  }, [])

  return { items, dismiss }
}

// ─── Theme-aware style config ─────────────────────────────────────────────────

type ThemeStyles = { bg: string; border: string; text: string; iconColor: string; barColor: string; dismissColor: string; dismissHover: string }

function getStyles(kind: ToastKind, light: boolean): ThemeStyles {
  if (light) {
    const base = { bg: '#ffffff', dismissColor: '#94a3b8', dismissHover: '#374151' }
    if (kind === 'error')   return { ...base, barColor: '#e94560', border: 'rgba(233,69,96,0.35)',  iconColor: '#dc2626', text: '#7f1d1d' }
    if (kind === 'success') return { ...base, barColor: '#16a34a', border: 'rgba(22,163,74,0.35)',  iconColor: '#15803d', text: '#14532d' }
    return                         { ...base, barColor: '#3b6ef6', border: 'rgba(59,110,246,0.35)', iconColor: '#2563eb', text: '#1e3a8a' }
  } else {
    const base = { bg: '#0d1b2e', dismissColor: '#64748b', dismissHover: '#cbd5e1' }
    if (kind === 'error')   return { ...base, barColor: '#e94560', border: 'rgba(233,69,96,0.30)',  iconColor: '#e94560', text: '#fca5a5' }
    if (kind === 'success') return { ...base, barColor: '#4ade80', border: 'rgba(74,222,128,0.30)', iconColor: '#4ade80', text: '#bbf7d0' }
    return                         { ...base, barColor: '#3b6ef6', border: 'rgba(59,110,246,0.30)', iconColor: '#3b6ef6', text: '#bfdbfe' }
  }
}

const ICONS: Record<ToastKind, React.ReactNode> = {
  error:   <AlertCircle  size={16} />,
  success: <CheckCircle2 size={16} />,
  info:    <Info         size={16} />,
}

// ─── Toaster component ────────────────────────────────────────────────────────

export function Toaster() {
  const { items, dismiss } = useToasts()
  const { theme } = useTheme()
  const isLight = theme === 'light'

  if (items.length === 0) return null

  return (
    <div
      aria-live="assertive"
      className="fixed top-5 right-5 z-[9999] flex flex-col gap-2 pointer-events-none"
      style={{ maxWidth: 400 }}
    >
      {items.map(t => {
        const s = getStyles(t.kind, isLight)
        return (
          <div
            key={t.id}
            className="pointer-events-auto relative flex items-start gap-3 rounded-xl px-4 py-3 animate-in slide-in-from-right-5 fade-in duration-200"
            style={{
              minWidth: 290,
              background: s.bg,
              border: `1px solid ${s.border}`,
              boxShadow: isLight
                ? '0 4px 20px rgba(0,0,0,0.12), 0 1px 4px rgba(0,0,0,0.08)'
                : '0 4px 24px rgba(0,0,0,0.5)',
            }}
          >
            {/* Left colour bar */}
            <div style={{
              position: 'absolute', left: 0, top: 0, bottom: 0, width: 4,
              background: s.barColor, borderRadius: '12px 0 0 12px',
            }} />

            {/* Icon */}
            <span style={{ color: s.iconColor, marginTop: 2, flexShrink: 0 }}>
              {ICONS[t.kind]}
            </span>

            {/* Message */}
            <p style={{ flex: 1, fontSize: 13, lineHeight: 1.45, fontWeight: 500, color: s.text }}>
              {t.message}
            </p>

            {/* Dismiss */}
            <button
              onClick={() => dismiss(t.id)}
              style={{ color: s.dismissColor, flexShrink: 0, marginTop: 2, background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
              aria-label="Dismiss"
            >
              <X size={14} />
            </button>
          </div>
        )
      })}
    </div>
  )
}
