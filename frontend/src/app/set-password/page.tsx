'use client'
import { useState, Suspense } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import AuthShell from '@/components/ui/AuthShell'
import Input from '@/components/ui/Input'
import Button from '@/components/ui/Button'

function SetPasswordForm() {
  const params = useSearchParams()
  const router = useRouter()
  const token = params.get('token') || ''
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [done, setDone] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (password !== confirm) { setError('Passwords do not match'); return }
    if (password.length < 8) { setError('Password must be at least 8 characters'); return }
    setLoading(true); setError('')
    try {
      const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || ''}/api/auth/set-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: password }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to set password')
      setDone(true)
      setTimeout(() => router.push('/login'), 2500)
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthShell subtitle={done ? 'Account activated' : 'Activate your account'}>
      {done ? (
        <div className="text-center py-4 space-y-3">
          <div className="w-10 h-10 rounded-full bg-white/[0.05] flex items-center justify-center mx-auto text-xl">✓</div>
          <p className="text-[13px] text-[#d4d4d8] font-medium">Password set successfully</p>
          <p className="text-[12px] text-[#71717a]">Redirecting to sign in…</p>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4">
          {!token && (
            <div className="px-3 py-2 rounded-lg bg-[#e03d4e]/10 border border-[#e03d4e]/20 text-[13px] text-[#fca5a5]">
              Invalid or expired activation link.
            </div>
          )}
          <Input
            label="New Password"
            type="password"
            placeholder="At least 8 characters"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />
          <Input
            label="Confirm Password"
            type="password"
            placeholder="Repeat password"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
            required
          />
          {error && (
            <div className="px-3 py-2 rounded-lg bg-[#e03d4e]/10 border border-[#e03d4e]/20 text-[13px] text-[#fca5a5]">
              {error}
            </div>
          )}
          <Button type="submit" className="w-full" loading={loading} disabled={!token}>
            Set Password & Activate
          </Button>
        </form>
      )}
    </AuthShell>
  )
}

export default function SetPasswordPage() {
  return <Suspense><SetPasswordForm /></Suspense>
}
