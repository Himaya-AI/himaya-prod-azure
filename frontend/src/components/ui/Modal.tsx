'use client'
import { useEffect, ReactNode } from 'react'
import { X } from 'lucide-react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title?: string
  children: ReactNode
  size?: 'sm' | 'md' | 'lg'
}

export function Modal({ open, onClose, title, children, size = 'md' }: ModalProps) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  if (!open) return null

  const sizeClass = { sm: 'max-w-md', md: 'max-w-lg', lg: 'max-w-2xl' }[size]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      {/* Panel — uses CSS vars so it follows dark/light theme automatically */}
      <div className={`
        relative w-full ${sizeClass}
        bg-[var(--card)] border border-[var(--border)]
        rounded-xl shadow-2xl flex flex-col max-h-[90vh]
      `}>
        {title && (
          <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)] flex-shrink-0">
            <h2 className="text-base font-semibold text-[var(--foreground)]">{title}</h2>
            <button
              onClick={onClose}
              className="text-[var(--muted)] hover:text-[var(--foreground)] transition-colors p-1 rounded-md hover:bg-black/10"
            >
              <X size={18} />
            </button>
          </div>
        )}
        <div className="p-6 overflow-y-auto text-[var(--foreground)]">
          {children}
        </div>
      </div>
    </div>
  )
}
