import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Message Trace — Himaya Helios',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
