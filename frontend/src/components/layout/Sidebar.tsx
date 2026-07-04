'use client'
import { useEffect, useState } from 'react'
import { usePathname } from 'next/navigation'
import { useSidebar } from '@/app/(dashboard)/layout'
import Link from 'next/link'
import Image from 'next/image'
import {
  LayoutDashboard, AlertTriangle, Search, Users, Settings,
  ClipboardList, Plug, LogOut, ShieldAlert, BookLock, ShieldCheck, ShieldBan,
  PenLine, MailWarning, Cloud
} from 'lucide-react'
import { clsx } from 'clsx'
import { getUser, logout } from '@/lib/auth'
import { t } from '@/lib/i18n'
import { useLang } from '@/lib/LangContext'

const navItems = [
  { href: '/dashboard',      icon: LayoutDashboard, key: 'dashboard' as const },
  { href: '/threats',        icon: AlertTriangle,    key: 'threats' as const },
  { href: '/quarantine',     icon: ShieldAlert,      key: 'quarantine' as const },
  { href: '/message-trace',  icon: Search,           key: 'messageTrace' as const },
  { href: '/people',         icon: Users,            key: 'people' as const },
  { href: '/policies',       icon: BookLock,         key: 'policies' as const },
  { href: '/compliance',     icon: ClipboardList,    key: 'compliance' as const },
  { href: '/posture',        icon: ShieldCheck,      key: 'posture' as const },
  { href: '/dlp',            icon: ShieldBan,        key: 'dlp' as const },
  { href: '/drafts',         icon: PenLine,          key: 'drafts' as const },
  { href: '/spam',           icon: MailWarning,      key: 'spam' as const },
  { href: '/saas-security',  icon: Cloud,            key: 'workspaceSecurity' as const },
  { href: '/onboarding',     icon: Plug,             key: 'integrations' as const },
  { href: '/settings',       icon: Settings,         key: 'settings' as const },
]

export default function Sidebar() {
  const { lang, isRtl } = useLang()
  const pathname = usePathname()
  const [mounted, setMounted] = useState(false)
  const [orgName, setOrgName] = useState<string | null>(null)
  const { mobileOpen } = useSidebar()

  useEffect(() => {
    setMounted(true)
    // Load org name for sidebar display
    import('@/lib/api').then(({ default: api }) => {
      api.get('/api/settings/org').then(r => {
        if (r.data?.name) setOrgName(r.data.name)
      }).catch(() => {})
    })
  }, [])

  const user = mounted ? getUser() : null
  const isEnterprise = ['enterprise', 'enterprise trial'].includes((user?.tier ?? '').toLowerCase())
  const displayName = user?.name ?? user?.full_name ?? 'User'
  const initials = displayName.split(' ').map((w: string) => w[0]).join('').slice(0, 2).toUpperCase()

  return (
    <aside className={clsx(
      'fixed top-0 bottom-0 w-[220px] flex flex-col bg-[var(--sidebar-bg)] border-r border-[var(--border)] z-40 transition-transform duration-200',
      isRtl ? 'right-0' : 'left-0',
      !mobileOpen && 'max-lg:-translate-x-full',
      mobileOpen && 'max-lg:translate-x-0',
      isRtl && !mobileOpen && 'max-lg:translate-x-full',
      isRtl && mobileOpen && 'max-lg:translate-x-0',
    )}>
      {/* Logo + org name */}
      <div className="flex flex-col px-4 pt-4 pb-4 border-b border-[var(--border)] flex-shrink-0">
        <div className="flex items-center justify-center bg-gradient-to-br from-[#1a1f3c] to-[#0d1224] rounded-xl px-3 py-2.5 border border-[#3b6ef6]/15">
          <Image src="/himaya-logo.png" alt="Himaya Helios" width={100} height={32} className="object-contain" />
        </div>
        {orgName && (
          <span className="text-[11px] text-[var(--muted)] truncate mt-2 text-center" title={orgName}>{orgName}</span>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 overflow-y-auto">
        <div className="px-3 space-y-1">
          {navItems.map(({ href, icon: Icon, key }) => {
            // Hide enterprise-only pages for non-enterprise orgs
            if (href === '/posture' && !isEnterprise) return null
            if (href === '/dlp' && !isEnterprise) return null
            if (href === '/drafts' && !isEnterprise) return null
            if (href === '/spam' && !isEnterprise) return null
            if (href === '/saas-security' && !isEnterprise) return null
            const active = pathname === href || (href !== '/dashboard' && pathname.startsWith(href))
            return (
              <Link
                key={href}
                href={href}
                className={clsx(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-[13px] font-medium transition-all',
                  isRtl && 'flex-row-reverse text-right',
                  active
                    ? 'bg-[var(--accent-subtle)] text-[var(--foreground)]'
                    : 'text-[var(--muted)] hover:text-[var(--foreground)] hover:bg-[var(--accent-subtle)]'
                )}
              >
                <Icon size={16} className={clsx(
                  'flex-shrink-0 transition-colors',
                  active ? 'text-[var(--accent)]' : 'text-current'
                )} />
                {t(lang, key)}
              </Link>
            )
          })}
        </div>
      </nav>

      {/* User */}
      <div className="p-4 border-t border-[var(--border)] flex-shrink-0">
        <div className={clsx('flex items-center gap-3', isRtl && 'flex-row-reverse')}>
          <div className="w-8 h-8 rounded-lg bg-[var(--accent-subtle)] flex items-center justify-center flex-shrink-0">
            <span className="text-[11px] font-semibold text-[var(--accent)]">{initials}</span>
          </div>
          <div className="flex-1 min-w-0">
            <div className={clsx('text-[13px] font-medium text-[var(--foreground)] truncate', isRtl && 'text-right')}>
              {displayName}
            </div>
            <div className={clsx('text-[11px] text-[var(--muted)] capitalize truncate', isRtl && 'text-right')}>
              {user?.role ?? 'admin'}
            </div>
          </div>
          <button
            onClick={logout}
            className="text-[var(--muted)] hover:text-[var(--danger)] p-1.5 rounded-lg hover:bg-[var(--danger-subtle)] transition-all flex-shrink-0"
            title={t(lang, 'signOut')}
          >
            <LogOut size={14} />
          </button>
        </div>
      </div>
    </aside>
  )
}
