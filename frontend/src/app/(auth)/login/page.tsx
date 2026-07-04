'use client'
import { useState, useEffect, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import AuthShell from '@/components/ui/AuthShell'
import Input from '@/components/ui/Input'
import Button from '@/components/ui/Button'
import api from '@/lib/api'
import { setToken, setUser } from '@/lib/auth'
import { getLang, setLangGlobal, type Lang } from '@/lib/i18n'
import { toast } from '@/components/ui/Toast'

const LOGIN_STRINGS = {
  en: {
    subtitle: 'Sign in to view your email security workspace',
    emailLabel: 'Email',
    emailPlaceholder: 'you@company.com',
    passwordLabel: 'Password',
    signIn: 'Sign in',
    forgotPassword: 'Forgot password?',
    langToggle: 'العربية',
    invalidCreds: 'Invalid email or password.',
    privacyPolicy: 'Privacy Policy',
    termsOfService: 'Terms of Service',
    legalPrefix: 'By signing in, you agree to our',
    legalAnd: 'and',
  },
  ar: {
    subtitle: 'سجّل دخولك للوصول إلى بيئة أمان البريد الإلكتروني',
    emailLabel: 'البريد الإلكتروني',
    emailPlaceholder: 'you@company.com',
    passwordLabel: 'كلمة المرور',
    signIn: 'تسجيل الدخول',
    forgotPassword: 'نسيت كلمة المرور؟',
    langToggle: 'English',
    invalidCreds: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.',
    privacyPolicy: 'سياسة الخصوصية',
    termsOfService: 'شروط الخدمة',
    legalPrefix: 'بتسجيل الدخول، فإنك توافق على',
    legalAnd: 'و',
  },
}

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [lang, setLang] = useState<Lang>('en')

  useEffect(() => {
    const saved = getLang()
    setLang(saved)
    document.documentElement.setAttribute('dir', saved === 'ar' ? 'rtl' : 'ltr')
    document.documentElement.setAttribute('lang', saved)

    const handler = (e: Event) => {
      const l = (e as CustomEvent<Lang>).detail
      setLang(l)
    }
    window.addEventListener('lang-change', handler)
    return () => window.removeEventListener('lang-change', handler)
  }, [])

  const s = LOGIN_STRINGS[lang]

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const res = await api.post('/api/auth/login', { email, password })
      setToken(res.data.access_token)
      try {
        const me = await api.get('/api/auth/me')
        setUser(me.data)
        // Apply this user's saved theme immediately after login
        const uid = me.data?.id
        const key = uid ? `helios-theme-${uid}` : 'helios-theme'
        const saved = localStorage.getItem(key) || localStorage.getItem('helios-theme') || 'dark'
        document.documentElement.setAttribute('data-theme', saved)
        localStorage.setItem('helios-theme', saved) // keep generic key in sync
      } catch {}
      router.push('/dashboard')
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } } }
      toast.error(axiosErr?.response?.data?.detail ?? s.invalidCreds, 7000)
    }
    setLoading(false)
  }

  return (
    <AuthShell subtitle={s.subtitle}>
      <form onSubmit={handleSubmit} className="space-y-4" dir={lang === 'ar' ? 'rtl' : 'ltr'}>
        <Input
          label={s.emailLabel}
          type="email"
          placeholder={s.emailPlaceholder}
          value={email}
          onChange={e => setEmail(e.target.value)}
          required
          autoComplete="email"
        />
        <Input
          label={s.passwordLabel}
          type="password"
          placeholder="••••••••"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
          autoComplete="current-password"
        />

        <Button type="submit" className="w-full" loading={loading}>
          {s.signIn}
        </Button>
      </form>

      <div className={`flex items-center justify-between mt-5 ${lang === 'ar' ? 'flex-row-reverse' : ''}`}>
        <Link href="/forgot-password" className="text-[12px] text-[#52525b] hover:text-[#a1a1aa] transition-colors">
          {s.forgotPassword}
        </Link>
        <button
          type="button"
          onClick={() => {
            const next = lang === 'ar' ? 'en' : 'ar'
            setLangGlobal(next)
          }}
          className="text-[12px] text-[#52525b] hover:text-[#a1a1aa] transition-colors"
        >
          {s.langToggle}
        </button>
      </div>

      {/* Legal links */}
      <p className={`mt-6 text-center text-[11px] text-[#3f3f46] leading-relaxed ${lang === 'ar' ? 'dir-rtl' : ''}`}>
        {s.legalPrefix}{' '}
        <Link href="/legal/terms" className="text-[#52525b] hover:text-[#a1a1aa] underline underline-offset-2 transition-colors">
          {s.termsOfService}
        </Link>
        {' '}{s.legalAnd}{' '}
        <Link href="/legal/privacy" className="text-[#52525b] hover:text-[#a1a1aa] underline underline-offset-2 transition-colors">
          {s.privacyPolicy}
        </Link>
        {' '}of Himaya Technologies Group Inc.
      </p>
    </AuthShell>
  )
}
