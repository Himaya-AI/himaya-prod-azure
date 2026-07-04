import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Dashboard — Himaya Helios',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
