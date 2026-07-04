'use client'
import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import Image from 'next/image'
import Input from '@/components/ui/Input'
import Button from '@/components/ui/Button'
import api from '@/lib/api'
import { setToken, setUser } from '@/lib/auth'

const GULF_COUNTRIES = ['Saudi Arabia', 'United Arab Emirates', 'Kuwait', 'Qatar', 'Bahrain', 'Oman']

export default function RegisterPage() {
  const router = useRouter()
  const [form, setForm] = useState({ company: '', email: '', password: '', country: '' })
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [apiError, setApiError] = useState('')
  const [loading, setLoading] = useState(false)

  const validate = () => {
    const e: Record<string, string> = {}
    if (!form.company) e.company = 'Company name is required'
    if (!form.email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) e.email = 'Enter a valid email address'
    if (form.password.length < 8) e.password = 'Password must be at least 8 characters'
    if (!form.country) e.country = 'Please select a country'
    setErrors(e)
    return Object.keys(e).length === 0
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!validate()) return
    setApiError('')
    setLoading(true)
    try {
      // Derive domain from the work email (e.g. adnan@company.com → company.com)
      const domain = form.email.split('@')[1] ?? ''
      const res = await api.post('/api/auth/register', {
        org_name: form.company,
        domain,
        email: form.email,
        password: form.password,
        name: form.email.split('@')[0],
        country: form.country,
      })
      setToken(res.data.access_token)
      try {
        const me = await api.get('/api/auth/me')
        setUser(me.data)
      } catch {}
      router.push('/onboarding')
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } } }
      setApiError(axiosErr?.response?.data?.detail ?? 'Registration failed. Please try again.')
    }
    setLoading(false)
  }

  const update = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm(prev => ({ ...prev, [k]: e.target.value }))

  return (
    <div className="min-h-screen bg-[#1a1a2e] flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <Image src="/himaya-logo.png" alt="Himaya Helios" width={160} height={54} className="object-contain mb-4" />
          <h1 className="text-xl font-bold text-white">Create Account</h1>
          <p className="text-gray-400 text-sm mt-1">AI Email Security for Gulf Enterprises</p>
        </div>

        <div className="bg-[#16213e] border border-[#0f3460]/50 rounded-2xl p-8">
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              id="company"
              label="Company Name"
              placeholder="Acme Corp"
              value={form.company}
              onChange={update('company')}
              error={errors.company}
            />
            <Input
              id="email"
              label="Work Email"
              type="email"
              placeholder="you@company.com"
              value={form.email}
              onChange={update('email')}
              error={errors.email}
            />
            <Input
              id="password"
              label="Password"
              type="password"
              placeholder="Min. 8 characters"
              value={form.password}
              onChange={update('password')}
              error={errors.password}
            />
            <div className="space-y-1.5">
              <label htmlFor="country" className="block text-sm font-medium text-slate-300">Country</label>
              <select
                id="country"
                value={form.country}
                onChange={update('country')}
                className="w-full px-3 py-2 bg-[#1a1a2e] border border-[#0f3460] rounded-lg text-slate-100 text-sm focus:outline-none focus:ring-2 focus:ring-[#e94560] focus:border-transparent"
              >
                <option value="">Select country...</option>
                {GULF_COUNTRIES.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              {errors.country && <p className="text-xs text-red-400">{errors.country}</p>}
            </div>

            {apiError && (
              <div className="px-3 py-2 rounded-lg bg-red-900/30 border border-red-700/40 text-sm text-red-400">
                {apiError}
              </div>
            )}

            <Button type="submit" className="w-full mt-2" loading={loading}>
              Create Account
            </Button>
          </form>

          <p className="text-center text-sm text-slate-500 mt-5">
            Already have an account?{' '}
            <Link href="/login" className="text-[#e94560] hover:underline">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  )
}
