'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Image from 'next/image'
import { ArrowRight, RefreshCw } from 'lucide-react'
import { toast } from '@/components/ui/Toast'

export default function AdminLogin() {
  const router = useRouter()
  const [step, setStep] = useState<'credentials' | 'otp'>('credentials')
  const [email, setEmail] = useState('adnan@himaya.ai')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [loading, setLoading] = useState(false)
  const [resendCooldown, setResendCooldown] = useState(0)

  const API = process.env.NEXT_PUBLIC_API_URL || 'https://app.himaya.ai'

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const res = await fetch(`${API}/api/admin/auth/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Invalid credentials')
      setStep('otp'); startCooldown()
    } catch (err: unknown) { toast.error((err as Error).message) }
    finally { setLoading(false) }
  }

  const handleVerifyOtp = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const res = await fetch(`${API}/api/admin/auth/verify-otp`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Invalid OTP code')
      localStorage.setItem('sentinel_admin_token', data.access_token)
      router.push('/admin/dashboard')
    } catch (err: unknown) { toast.error((err as Error).message) }
    finally { setLoading(false) }
  }

  const startCooldown = () => {
    setResendCooldown(30)
    const t = setInterval(() => setResendCooldown(p => { if (p <= 1) { clearInterval(t); return 0 } return p - 1 }), 1000)
  }

  const handleResend = async () => {
    if (resendCooldown > 0) return
    await fetch(`${API}/api/admin/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
    startCooldown()
  }

  const inputClass = "w-full bg-[#1e1e24] border border-white/[0.08] rounded-lg px-4 py-2.5 text-[13px] text-[#e4e4e7] placeholder-[#52525b] focus:outline-none focus:border-[#3b6ef6]/60 transition-colors"

  return (
    <div className="min-h-screen bg-[#0c0c0e] flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-[380px]">
        {/* Logo */}
        <div className="flex flex-col items-center mb-7">
          <Image src="/himaya-logo.png" alt="Himaya" width={130} height={42} className="object-contain mb-4" />
          <span className="text-[11px] font-medium text-[#52525b] tracking-widest uppercase">Admin Portal</span>
        </div>

        <div className="bg-[#141417] border border-white/[0.07] rounded-2xl p-7">
          {step === 'credentials' ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <p className="text-[15px] font-semibold text-[#e4e4e7] mb-1">Sign in</p>
                <p className="text-[12px] text-[#52525b] mb-5">You'll receive a verification code by email.</p>
              </div>
              <div className="space-y-1">
                <label className="text-[12px] text-[#71717a]">Email</label>
                <input type="email" value={email} onChange={e => setEmail(e.target.value)} className={inputClass} required />
              </div>
              <div className="space-y-1">
                <label className="text-[12px] text-[#71717a]">Password</label>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)} className={inputClass} placeholder="••••••••" required />
              </div>
              <button type="submit" disabled={loading}
                className="w-full bg-[#3b6ef6] hover:bg-[#2f5de0] disabled:opacity-50 text-white text-[13px] font-medium py-2.5 rounded-lg flex items-center justify-center gap-2 transition-colors mt-1">
                {loading ? 'Sending code…' : <><span>Continue</span><ArrowRight size={14} /></>}
              </button>
            </form>
          ) : (
            <form onSubmit={handleVerifyOtp} className="space-y-4">
              <div>
                <p className="text-[15px] font-semibold text-[#e4e4e7] mb-1">Check your email</p>
                <p className="text-[12px] text-[#52525b] mb-5">6-digit code sent to <span className="text-[#a1a1aa]">{email}</span></p>
              </div>
              <input
                type="text" value={otp}
                onChange={e => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="w-full bg-[#1e1e24] border border-white/[0.08] rounded-lg px-4 py-3.5 text-[22px] font-bold text-[#e4e4e7] text-center tracking-[0.6em] focus:outline-none focus:border-[#3b6ef6]/60 transition-colors"
                placeholder="000000" maxLength={6} required
              />
              <button type="submit" disabled={loading || otp.length !== 6}
                className="w-full bg-[#3b6ef6] hover:bg-[#2f5de0] disabled:opacity-50 text-white text-[13px] font-medium py-2.5 rounded-lg flex items-center justify-center gap-2 transition-colors">
                {loading ? 'Verifying…' : <><span>Verify & Sign In</span><ArrowRight size={14} /></>}
              </button>
              <div className="flex items-center justify-between pt-1">
                <button type="button" onClick={() => { setStep('credentials'); setOtp('') }}
                  className="text-[12px] text-[#52525b] hover:text-[#a1a1aa] transition-colors">
                  ← Back
                </button>
                <button type="button" onClick={handleResend} disabled={resendCooldown > 0}
                  className="text-[12px] text-[#52525b] hover:text-[#a1a1aa] disabled:opacity-40 flex items-center gap-1.5 transition-colors">
                  <RefreshCw size={11} />
                  {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : 'Resend code'}
                </button>
              </div>
            </form>
          )}
        </div>

        <p className="text-center text-[11px] text-[#3f3f46] mt-5">
          © 2026 Himaya Technologies Group Inc.
        </p>
      </div>
    </div>
  )
}
