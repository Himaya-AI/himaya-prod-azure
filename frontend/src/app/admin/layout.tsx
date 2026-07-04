'use client'
import { useEffect, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import Image from 'next/image'
import Link from 'next/link'
import { getAdminToken, clearAdminToken } from '@/lib/adminAuth'
import {
  LayoutDashboard, Building2, BarChart3, CreditCard,
  Settings, LogOut, ChevronRight, Shield,
} from 'lucide-react'

const navItems = [
  { href: '/admin/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/admin/orgs', icon: Building2, label: 'Organizations' },
  { href: '/admin/usage', icon: BarChart3, label: 'Usage Analytics' },
  { href: '/admin/billing', icon: CreditCard, label: 'Billing' },
  { href: '/admin/settings', icon: Settings, label: 'Settings' },
]

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const [authorized, setAuthorized] = useState(false)

  useEffect(() => {
    // Skip auth check for login page
    if (pathname === '/admin/login') {
      setAuthorized(true)
      return
    }
    const token = getAdminToken()
    if (!token) {
      router.replace('/admin/login')
    } else {
      setAuthorized(true)
    }
  }, [pathname, router])

  // Don't flash protected content while checking auth
  if (!authorized) return null

  // Login page gets no chrome
  if (pathname === '/admin/login') return <>{children}</>

  return (
    <div className="flex h-screen bg-[var(--background)] text-[var(--foreground)]" data-theme="dark">
      {/* Sidebar */}
      <div className="w-[220px] bg-[var(--card)] border-r border-[var(--border)] flex flex-col">
        {/* Logo */}
        <div className="px-5 py-5 border-b border-[var(--border)]">
          <Image
            src="/himaya-logo.png"
            alt="Himaya"
            width={110}
            height={36}
            className="object-contain brightness-0 invert mb-2"
          />
          <div className="flex items-center gap-2 mt-1">
            <Shield className="w-3 h-3 text-[var(--accent)]" />
            <span className="text-[10px] font-bold text-[var(--accent)] tracking-widest uppercase">Vendor Admin</span>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map((item) => {
            const active = pathname.startsWith(item.href)
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  active
                    ? 'bg-[var(--accent-subtle)] text-[var(--accent)]'
                    : 'text-[#9ca3af] hover:bg-[var(--card-hover)] hover:text-white'
                }`}
              >
                <item.icon className="w-4 h-4" />
                {item.label}
                {active && <ChevronRight className="w-3 h-3 ml-auto" />}
              </Link>
            )
          })}
        </nav>

        {/* Footer */}
        <div className="px-4 py-4 border-t border-[var(--border)]">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-8 h-8 rounded-full bg-[var(--accent)] flex items-center justify-center text-xs font-bold text-white">A</div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-white truncate">Adnan</p>
              <p className="text-xs text-[#9ca3af] truncate">adnan@himaya.ai</p>
            </div>
          </div>
          <button
            onClick={() => { clearAdminToken(); router.push('/admin/login') }}
            className="flex items-center gap-2 w-full px-3 py-2 text-xs text-[#9ca3af] hover:text-white hover:bg-[var(--card-hover)] rounded-lg transition-all"
          >
            <LogOut className="w-3 h-3" />
            Sign out
          </button>
        </div>
      </div>

      {/* Main content area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Vendor badge — always visible on non-login pages */}
        <div className="bg-[var(--accent-subtle)] border-b border-[var(--border)] px-4 py-1.5 flex items-center gap-2 flex-shrink-0">
          <span className="text-[10px] font-bold text-[var(--accent)] uppercase tracking-widest">Himaya Internal</span>
          <span className="text-[10px] text-[#9ca3af]">Vendor Admin Portal — Not for customer access</span>
        </div>

        {/* Top bar */}
        <header className="bg-[var(--card)] border-b border-[var(--border)] px-6 py-3 flex items-center justify-between flex-shrink-0">
          <div>
            <h1 className="text-sm font-semibold text-white">
              {navItems.find(n => pathname.startsWith(n.href))?.label || 'Admin'}
            </h1>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-[#9ca3af]">Himaya</span>
            <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
            <span className="text-xs text-green-400">All systems operational</span>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto bg-[var(--background)] p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
