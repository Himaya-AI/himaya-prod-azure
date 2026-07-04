'use client'
import { useState } from 'react'
import Link from 'next/link'
import AuthShell from '@/components/ui/AuthShell'
import Input from '@/components/ui/Input'
import Button from '@/components/ui/Button'
import api from '@/lib/api'

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await api.post('/api/auth/forgot-password', { email })
      setSent(true)
    } catch {
      setError('Something went wrong. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthShell subtitle="Reset your password">
      {sent ? (
        <div className="text-center space-y-4 py-2">
          <div className="text-3xl">✉️</div>
          <p className="text-[13px] font-medium text-[#d4d4d8]">Check your email</p>
          <p className="text-[12px] text-[#71717a]">
            If an account exists for <span className="text-[#a1a1aa]">{email}</span>, we sent a password reset link.
          </p>
          <Link href="/login" className="block text-[12px] text-[#3b6ef6] hover:underline mt-2">
            Back to sign in
          </Link>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          <p className="text-[13px] text-[#71717a] mb-1">
            Enter your work email and we'll send a reset link.
          </p>
          <Input
            label="Work Email"
            type="email"
            placeholder="you@company.com"
            value={email}
            onChange={e => setEmail(e.target.value)}
            required
          />
          {error && (
            <div className="px-3 py-2 rounded-lg bg-[#e03d4e]/10 border border-[#e03d4e]/20 text-[13px] text-[#fca5a5]">
              {error}
            </div>
          )}
          <Button type="submit" className="w-full" loading={loading}>
            Send Reset Link
          </Button>
          <Link href="/login" className="block text-center text-[12px] text-[#52525b] hover:text-[#a1a1aa] transition-colors mt-1">
            Back to sign in
          </Link>
        </form>
      )}
    </AuthShell>
  )
}
