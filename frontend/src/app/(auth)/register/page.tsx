'use client'
import Link from 'next/link'
import Image from 'next/image'

export default function RegisterPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0a0f1e] px-4">
      <div className="w-full max-w-md rounded-2xl border border-[#1a2744] bg-[#0d1b2e] p-10 text-center">
        <Image src="/himaya-logo.png" alt="Himaya" width={160} height={40} className="mx-auto mb-8" />
        <h1 className="text-xl font-bold text-white mb-3">Onboarding by invitation</h1>
        <p className="text-sm text-[#a1a1aa] leading-relaxed mb-8">
          Himaya accounts are provisioned by our team to ensure a secure,
          white-glove onboarding for every organization. Contact us and we&apos;ll
          get your workspace protected within one business day.
        </p>
        <a
          href="mailto:sales@himaya.ai?subject=Himaya%20Onboarding%20Request"
          className="inline-block rounded-lg bg-[#3b6ef6] px-8 py-3 text-sm font-semibold text-white hover:bg-[#2f5ad9] transition-colors"
        >
          Contact sales@himaya.ai
        </a>
        <p className="mt-8 text-xs text-[#52525b]">
          Already have an account?{' '}
          <Link href="/login" className="text-[#3b6ef6] hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  )
}
