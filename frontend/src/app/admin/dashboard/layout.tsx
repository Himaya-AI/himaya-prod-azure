import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Vendor Admin — Himaya',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
