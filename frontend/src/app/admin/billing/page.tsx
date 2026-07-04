'use client'
import { useEffect, useState } from 'react'
import { adminFetch } from '@/lib/adminAuth'
import { Download, FileText, DollarSign } from 'lucide-react'

export default function AdminBilling() {
  const [records, setRecords] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [selectedPeriod, setSelectedPeriod] = useState('')

  const now = new Date()
  const currentPeriod = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`

  const periods = Array.from({ length: 6 }, (_, i) => {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1)
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`
  })

  useEffect(() => {
    adminFetch('/api/admin/billing').then(setRecords).catch(() => []).finally(() => setLoading(false))
  }, [])

  async function generateAll() {
    setGenerating(true)
    let count = 0
    for (const r of records) {
      if (r.billing_status === 'pending') {
        await adminFetch(`/api/admin/billing/${r.org_id}/invoice`, { method: 'POST' }).catch(() => {})
        count++
      }
    }
    alert(`Generated ${count} invoices`)
    const data = await adminFetch('/api/admin/billing').catch(() => [])
    setRecords(data)
    setGenerating(false)
  }

  function exportCSV() {
    const header = ['Org Name', 'Plan', 'Mailboxes', 'Emails Scanned', 'Rate', 'Amount Due', 'Status', 'Period']
    const rows = records.map(r => [
      r.org_name, r.plan, r.mailboxes, r.emails_scanned_mtd,
      r.rate_per_mailbox_usd, r.amount_due_usd, r.billing_status, r.billing_period,
    ])
    const csv = [header, ...rows].map(r => r.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `billing-${currentPeriod}.csv`; a.click()
    URL.revokeObjectURL(url)
  }

  const totalMRR = records.reduce((s, r) => s + (r.amount_due_usd || r.base_amount_usd || 0), 0)
  const pendingCount = records.filter(r => r.billing_status === 'pending').length

  if (loading) return <div className="flex items-center justify-center h-64"><div className="w-8 h-8 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" /></div>

  return (
    <div className="space-y-7">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-white text-2xl font-bold">Billing Management</h1>
          <p className="text-gray-400 text-sm mt-1">Current billing period: <span className="text-white font-mono">{currentPeriod}</span></p>
        </div>
        <div className="flex gap-3">
          <button onClick={exportCSV} className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white px-4 py-2 rounded-lg text-sm">
            <Download className="w-4 h-4" />
            Export CSV
          </button>
          <button onClick={generateAll} disabled={generating || pendingCount === 0}
            className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent)] disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm">
            <FileText className="w-4 h-4" />
            {generating ? 'Generating...' : `Generate All Invoices (${pendingCount})`}
          </button>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <div className="flex items-center gap-3">
            <DollarSign className="w-5 h-5 text-green-400" />
            <div>
              <p className="text-gray-400 text-xs">Total This Month</p>
              <p className="text-white text-xl font-bold">${totalMRR.toLocaleString('en-US', { minimumFractionDigits: 2 })}</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-gray-400 text-xs">Pending Invoices</p>
          <p className="text-yellow-300 text-xl font-bold">{pendingCount}</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <p className="text-gray-400 text-xs">Total Orgs Billed</p>
          <p className="text-white text-xl font-bold">{records.length}</p>
        </div>
      </div>

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-gray-800">
              <tr>
                {['Org Name', 'Plan', 'Mailboxes', 'Emails Scanned', 'Rate/Mailbox', 'Base Amount', 'Amount Due', 'Status'].map(h => (
                  <th key={h} className="text-left text-gray-400 text-xs uppercase tracking-wide px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {records.map((r, i) => (
                <tr key={i} className="hover:bg-gray-800/50">
                  <td className="px-4 py-3 text-white text-sm font-medium">{r.org_name}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${
                      r.plan === 'enterprise' ? 'bg-[var(--accent)]/20 text-[var(--accent)] border-[var(--accent)]' :
                      r.plan === 'professional' ? 'bg-blue-500/20 text-blue-300 border-blue-700' :
                      'bg-gray-500/20 text-gray-300 border-gray-600'
                    }`}>{r.plan}</span>
                  </td>
                  <td className="px-4 py-3 text-gray-300 text-sm">{r.mailboxes}</td>
                  <td className="px-4 py-3 text-gray-300 text-sm">{(r.emails_scanned_mtd || 0).toLocaleString()}</td>
                  <td className="px-4 py-3 text-gray-400 text-sm font-mono">${r.rate_per_mailbox_usd?.toFixed(2)}</td>
                  <td className="px-4 py-3 text-gray-300 text-sm font-mono">${r.base_amount_usd?.toFixed(2)}</td>
                  <td className="px-4 py-3 text-green-300 text-sm font-mono font-bold">${(r.amount_due_usd || r.base_amount_usd || 0).toFixed(2)}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${
                      r.billing_status === 'paid' ? 'bg-green-500/20 text-green-300 border-green-700' :
                      r.billing_status === 'invoiced' ? 'bg-blue-500/20 text-blue-300 border-blue-700' :
                      r.billing_status === 'overdue' ? 'bg-red-500/20 text-red-300 border-red-700' :
                      'bg-yellow-500/20 text-yellow-300 border-yellow-700'
                    }`}>{r.billing_status}</span>
                  </td>
                </tr>
              ))}
              {records.length === 0 && <tr><td colSpan={8} className="px-4 py-10 text-center text-gray-600">No billing records</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
