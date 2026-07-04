'use client'
import { HeadphonesIcon, Menu } from 'lucide-react'
import { useState, useEffect } from 'react'
import { getUser } from '@/lib/auth'
import { t } from '@/lib/i18n'
import { useLang } from '@/lib/LangContext'
import { useSidebar } from '@/app/(dashboard)/layout'

export default function TopBar({ title }: { title?: string }) {
  const { lang, setLang, isRtl } = useLang()
  const [mounted, setMounted] = useState(false)
  const { setMobileOpen } = useSidebar()

  useEffect(() => { setMounted(true) }, [])

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
        <a
          href="https://support.himaya.ai"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[var(--muted)] hover:text-[var(--foreground)] transition-all p-2 rounded-lg hover:bg-[var(--accent-subtle)]"
          title={t(lang, 'support')}
        >
          <HeadphonesIcon size={16} />
        </a>
      </div>
    </header>
  )
}
