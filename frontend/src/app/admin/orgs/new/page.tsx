'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { adminFetch } from '@/lib/adminAuth'
import { ArrowLeft, Building2, Copy, Check } from 'lucide-react'

const GULF_COUNTRIES = ['Saudi Arabia', 'UAE', 'Kuwait', 'Qatar', 'Bahrain', 'Oman', 'Jordan', 'Egypt']
const PLANS = [
  { value: 'starter', label: 'Starter — up to 50 mailboxes', rate: 8.00 },
  { value: 'professional', label: 'Professional — up to 500 mailboxes', rate: 8.00 },
  { value: 'enterprise', label: 'Enterprise — unlimited mailboxes', rate: 7.50 },
]

interface ProvisionResult {
  org_id: string
  org_name: string
  admin_email: string
  temp_password?: string
  activation_url: string
  onboarding_url: string
}

export default function NewOrg() {
  const router = useRouter()
  const [form, setForm] = useState({
    org_name: '', domain: '', plan: 'starter', country: 'Saudi Arabia',
    mailbox_limit: '100', billing_rate_usd: '8.00', contact_name: '', contact_email: '',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<ProvisionResult | null>(null)
  const [copied, setCopied] = useState<string | null>(null)

  function set(k: string, v: string) { setForm(f => ({ ...f, [k]: v })) }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const data = await adminFetch('/api/admin/orgs', {
        method: 'POST',
        body: JSON.stringify({
          ...form,
          mailbox_limit: parseInt(form.mailbox_limit),
          billing_rate_usd: parseFloat(form.billing_rate_usd),
        }),
      })
      setResult(data)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function copyToClipboard(text: string, key: string) {
    await navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 2000)
  }

  if (result) {
    return (
      <div className="max-w-2xl mx-auto space-y-6">
        <div className="bg-green-900/20 border border-green-700 rounded-xl p-6">
          <h2 className="text-green-300 font-bold text-lg mb-1">✓ Customer Provisioned Successfully</h2>
          <p className="text-green-400 text-sm">Share these credentials with your customer securely.</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          <h3 className="text-white font-semibold">Onboarding Credentials</h3>
          {[
            { label: 'Organization ID', value: result.org_id, key: 'org_id' },
            { label: 'Admin Login Email', value: result.admin_email, key: 'email' },
            { label: 'Activation URL', value: result.activation_url, key: 'activation' },
            { label: 'Onboarding URL', value: result.onboarding_url, key: 'url' },
          ].filter(item => !!item.value).map(({ label, value, key }) => (
            <div key={key} className="flex items-center justify-between bg-gray-800 rounded-lg px-4 py-3">
              <div>
                <p className="text-gray-400 text-xs mb-1">{label}</p>
                <p className="text-white text-sm font-mono">{value}</p>
              </div>
              <button
                onClick={() => copyToClipboard(value, key)}
                className="p-2 rounded text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
              >
                {copied === key ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          ))}
        </div>
        <div className="flex gap-3">
          <Link href="/admin/orgs" className="flex-1 bg-gray-800 hover:bg-gray-700 text-white text-center py-3 rounded-lg text-sm transition-colors">
            View All Organizations
          </Link>
          <Link href={`/admin/orgs/${result.org_id}`} className="flex-1 bg-purple-600 hover:bg-purple-700 text-white text-center py-3 rounded-lg text-sm transition-colors">
            View Customer Details
          </Link>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/admin/orgs" className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors">
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div>
          <h1 className="text-white text-2xl font-bold">Provision New Customer</h1>
          <p className="text-gray-400 text-sm mt-0.5">Create a new tenant and generate onboarding credentials</p>
        </div>
      </div>

      {error && <div className="bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-300 text-sm">{error}</div>}

      <form onSubmit={handleSubmit} className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
        <div className="flex items-center gap-3 pb-4 border-b border-gray-800">
          <div className="w-8 h-8 bg-purple-600 rounded-lg flex items-center justify-center">
            <Building2 className="w-4 h-4 text-white" />
          </div>
          <h2 className="text-white font-semibold">Organization Details</h2>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2">
            <label className="text-gray-400 text-sm mb-1.5 block">Organization Name *</label>
            <input required value={form.org_name} onChange={e => set('org_name', e.target.value)}
              placeholder="Acme Fintech LLC"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-purple-500" />
          </div>
          <div className="col-span-2">
            <label className="text-gray-400 text-sm mb-1.5 block">Primary Domain *</label>
            <input required value={form.domain} onChange={e => set('domain', e.target.value)}
              placeholder="acmefintech.com"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-purple-500" />
            <p className="text-gray-600 text-xs mt-1">Admin account will be created as admin@{form.domain || 'domain.com'}</p>
          </div>
          <div>
            <label className="text-gray-400 text-sm mb-1.5 block">Country</label>
            <select value={form.country} onChange={e => set('country', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-purple-500">
              {GULF_COUNTRIES.map(c => <option key={c}>{c}</option>)}
            </select>
          </div>
          <div>
            <label className="text-gray-400 text-sm mb-1.5 block">Plan</label>
            <select value={form.plan} onChange={e => { set('plan', e.target.value); set('billing_rate_usd', String(PLANS.find(p => p.value === e.target.value)?.rate || 8)) }}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-purple-500">
              {PLANS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
          </div>
          <div>
            <label className="text-gray-400 text-sm mb-1.5 block">Mailbox Limit</label>
            <input type="number" value={form.mailbox_limit} onChange={e => set('mailbox_limit', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-purple-500" />
          </div>
          <div>
            <label className="text-gray-400 text-sm mb-1.5 block">Billing Rate ($/mailbox/mo)</label>
            <input type="number" step="0.01" value={form.billing_rate_usd} onChange={e => set('billing_rate_usd', e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-purple-500" />
            <p className="text-gray-600 text-xs mt-1">
              Est. MRR: ${(parseInt(form.mailbox_limit || '0') * parseFloat(form.billing_rate_usd || '0')).toFixed(2)}/mo
            </p>
          </div>
        </div>

        <div className="pt-4 border-t border-gray-800">
          <h3 className="text-white text-sm font-semibold mb-4">Contact Information</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-gray-400 text-sm mb-1.5 block">Contact Name *</label>
              <input required value={form.contact_name} onChange={e => set('contact_name', e.target.value)}
                placeholder="Ahmed Al-Rashid"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-purple-500" />
            </div>
            <div>
              <label className="text-gray-400 text-sm mb-1.5 block">Contact Email *</label>
              <input required type="email" value={form.contact_email} onChange={e => set('contact_email', e.target.value)}
                placeholder="ahmed@acmefintech.com"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-white text-sm placeholder-gray-500 focus:outline-none focus:border-purple-500" />
            </div>
          </div>
        </div>

        <button type="submit" disabled={loading}
          className="w-full bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-white font-semibold py-3 rounded-lg transition-colors text-sm">
          {loading ? 'Provisioning...' : 'Provision Customer'}
        </button>
      </form>
    </div>
  )
}
