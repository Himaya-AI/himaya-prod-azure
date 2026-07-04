/**
 * Shared shell for all auth pages — logo, card, footer.
 */
import Image from 'next/image'

interface Props {
  children: React.ReactNode
  subtitle?: string
}

export default function AuthShell({ children, subtitle }: Props) {
  return (
    <div className="min-h-screen bg-[var(--background,#0c0c0e)] flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-[400px]">
        {/* Logo — gradient backdrop so white logo is always visible */}
        <div className="flex flex-col items-center mb-8">
          <div className="
            flex items-center justify-center
            bg-gradient-to-br from-[#1a1f3c] to-[#0d1224]
            rounded-2xl px-8 py-4 mb-3
            shadow-lg border border-[#3b6ef6]/20
          ">
            <Image
              src="/himaya-logo.png"
              alt="Himaya"
              width={140}
              height={46}
              className="object-contain"
            />
          </div>
          {subtitle && (
            <p className="text-[13px] text-[var(--muted,#52525b)]">{subtitle}</p>
          )}
        </div>

        {/* Card */}
        <div className="bg-[var(--card,#141417)] border border-[var(--border)] rounded-2xl p-7">
          {children}
        </div>

        {/* Footer */}
        <p className="text-center text-[11px] text-[var(--muted,#3f3f46)] mt-6">
          © 2026 Himaya Technologies Group Inc.
        </p>
      </div>
    </div>
  )
}
