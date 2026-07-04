import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'Compliance — Himaya',
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
