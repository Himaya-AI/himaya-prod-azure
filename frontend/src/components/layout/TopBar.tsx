'use client'
import { HeadphonesIcon, Menu, BookOpen, ChevronDown, LifeBuoy } from 'lucide-react'
import { useState, useEffect, useRef } from 'react'
import { getUser } from '@/lib/auth'
import { t } from '@/lib/i18n'
import { useLang } from '@/lib/LangContext'
import { useSidebar } from '@/app/(dashboard)/layout'

export default function TopBar({ title }: { title?: string }) {
  const { lang, setLang, isRtl } = useLang()
  const [mounted, setMounted] = useState(false)
  const [resourcesOpen, setResourcesOpen] = useState(false)
  const resourcesRef = useRef<HTMLDivElement>(null)
  const { setMobileOpen } = useSidebar()

  useEffect(() => { setMounted(true) }, [])

  // Close the resources dropdown on outside click or Escape
  useEffect(() => {
    if (!resourcesOpen) return
    const onClick = (e: MouseEvent) => {
      if (resourcesRef.current && !resourcesRef.current.contains(e.target as Node)) {
        setResourcesOpen(false)
      }
    }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setResourcesOpen(false) }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [resourcesOpen])

  const user = mounted ? getUser() : null

  return (
    <header className={`fixed top-0 h-14 bg-[var(--background)]/95 backdrop-blur-md border-b border-[var(--border)] flex items-center justify-between px-5 z-30 ${
      isRtl ? 'right-0 lg:right-[220px] left-0' : 'left-0 lg:left-[220px] right-0'
    }`}>
      <div className={`flex items-center gap-3 ${isRtl ? 'flex-row-reverse' : ''}`}>
        {/* Hamburger — mobile only */}
        <button
          className="lg:hidden text-[var(--muted)] hover:text-[var(--foreground)] p-1.5 rounded-lg hover:bg-[var(--accent-subtle)] transition-all"
          onClick={() => setMobileOpen(true)}
          aria-label="Open menu"
        >
          <Menu size={20} />
        </button>
        {title && (
          <div className={`text-[14px] font-medium text-[var(--foreground)] ${isRtl ? 'text-right' : ''}`}>
            {title}
          </div>
        )}
      </div>
      <div className={`flex items-center gap-3 ${isRtl ? 'flex-row-reverse' : ''}`}>
        {mounted && user && (
          <span className="text-[13px] text-[var(--muted)] hidden md:block">
            {t(lang, 'hi')}, <span className="text-[var(--foreground)] font-medium">{user.name ?? user.email?.split('@')[0]}</span>
          </span>
        )}
        <button
          onClick={() => setLang(lang === 'en' ? 'ar' : 'en')}
          className="text-[12px] text-[var(--muted)] hover:text-[var(--foreground)] transition-all px-3 py-1.5 rounded-lg border border-[var(--border)] hover:border-[var(--border-strong)] hover:bg-[var(--card)] font-medium min-w-[40px]"
        >
          {lang === 'en' ? 'ع' : 'EN'}
        </button>
        <div className="relative" ref={resourcesRef}>
          <button
            onClick={() => setResourcesOpen((v) => !v)}
            className="flex items-center gap-1.5 text-[12px] text-[var(--muted)] hover:text-[var(--foreground)] transition-all px-3 py-1.5 rounded-lg border border-[var(--border)] hover:border-[var(--border-strong)] hover:bg-[var(--card)] font-medium"
            aria-haspopup="menu"
            aria-expanded={resourcesOpen}
            title={t(lang, 'resources')}
          >
            <LifeBuoy size={15} />
            <span className="hidden sm:inline">{t(lang, 'resources')}</span>
            <ChevronDown size={14} className={`transition-transform ${resourcesOpen ? 'rotate-180' : ''}`} />
          </button>
          {resourcesOpen && (
            <div
              role="menu"
              className={`absolute top-full mt-2 w-52 rounded-xl border border-[var(--border)] bg-[var(--card)] shadow-[var(--shadow-elevated)] py-1.5 z-40 ${
                isRtl ? 'left-0' : 'right-0'
              }`}
            >
              <a
                href="https://docs.himaya.ai"
                target="_blank"
                rel="noopener noreferrer"
                role="menuitem"
                onClick={() => setResourcesOpen(false)}
                className={`flex items-center gap-2.5 px-3.5 py-2 text-[13px] text-[var(--foreground)] hover:bg-[var(--accent-subtle)] transition-colors ${
                  isRtl ? 'flex-row-reverse text-right' : ''
                }`}
              >
                <BookOpen size={16} className="text-[var(--accent)] shrink-0" />
                <span>{t(lang, 'documentation')}</span>
              </a>
              <a
                href="https://support.himaya.ai"
                target="_blank"
                rel="noopener noreferrer"
                role="menuitem"
                onClick={() => setResourcesOpen(false)}
                className={`flex items-center gap-2.5 px-3.5 py-2 text-[13px] text-[var(--foreground)] hover:bg-[var(--accent-subtle)] transition-colors ${
                  isRtl ? 'flex-row-reverse text-right' : ''
                }`}
              >
                <HeadphonesIcon size={16} className="text-[var(--accent)] shrink-0" />
                <span>{t(lang, 'support')}</span>
              </a>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
