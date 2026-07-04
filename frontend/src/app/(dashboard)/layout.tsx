'use client'
import { useEffect, useState, createContext, useContext } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import Sidebar from '@/components/layout/Sidebar'
import TopBar from '@/components/layout/TopBar'
import FalconAgent from '@/components/BluebirdAgent'
import { isAuthenticated } from '@/lib/auth'
import { LangProvider } from '@/lib/LangContext'

// Mobile sidebar context
export const SidebarContext = createContext<{
  mobileOpen: boolean
  setMobileOpen: (v: boolean) => void
}>({ mobileOpen: false, setMobileOpen: () => {} })

export function useSidebar() { return useContext(SidebarContext) }

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const [mounted, setMounted] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    setMounted(true)
    if (!isAuthenticated()) router.replace('/login')
  }, [router])

  // Close sidebar on route change
  useEffect(() => { setMobileOpen(false) }, [pathname])

  if (!mounted) {
    return (
      <div className="min-h-screen bg-[var(--background)] flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-[var(--accent)]/20 border-t-[var(--accent)] rounded-full animate-spin" />
      </div>
    )
  }

  if (!isAuthenticated()) return null

  return (
    <LangProvider>
      <SidebarContext.Provider value={{ mobileOpen, setMobileOpen }}>
        <div className="min-h-screen bg-[var(--background)]">
          {/* Mobile backdrop */}
          {mobileOpen && (
            <div
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 lg:hidden"
              onClick={() => setMobileOpen(false)}
            />
          )}
          <Sidebar />
          <TopBar />
          <main className="ltr:lg:ml-[220px] rtl:lg:mr-[220px] pt-14 min-h-screen overflow-x-hidden">
            <div className="p-4 sm:p-5 lg:p-6 max-w-7xl mx-auto w-full">
              {children}
            </div>
          </main>
          <FalconAgent />
        </div>
      </SidebarContext.Provider>
    </LangProvider>
  )
}
