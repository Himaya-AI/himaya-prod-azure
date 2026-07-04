'use client'
import { useEffect, useState } from 'react'
import { adminFetch } from '@/lib/adminAuth'
import { Mail, TrendingUp, Shield } from 'lucide-react'

export default function AdminUsage() {
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    adminFetch('/api/admin/usage').then(setStats).catch(() => {}).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="flex items-center justify-center h-64"><div className="w-8 h-8 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" /></div>

  const allOrgs = stats?.top_orgs_by_volume || []

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-white text-2xl font-bold">Platform Usage Analytics</h1>
        <p className="text-gray-400 text-sm mt-1">Aggregated email volume and threat detection across all tenants</p>
      </div>

      {/* Big numbers */}
      <div className="grid grid-cols-3 gap-5">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
          <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center mx-auto mb-3">
            <Mail className="w-5 h-5 text-white" />
          </div>
          <p className="text-white text-3xl font-bold">{(stats?.total_emails_scanned_all_time || 0).toLocaleString()}</p>
          <p className="text-gray-400 text-sm mt-1">Total Emails Scanned (All Time)</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
          <div className="w-10 h-10 bg-[var(--accent)] rounded-lg flex items-center justify-center mx-auto mb-3">
            <TrendingUp className="w-5 h-5 text-white" />
          </div>
          <p className="text-white text-3xl font-bold">{(stats?.total_emails_scanned_mtd || 0).toLocaleString()}</p>
          <p className="text-gray-400 text-sm mt-1">This Month (MTD)</p>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 text-center">
          <div className="w-10 h-10 bg-red-600 rounded-lg flex items-center justify-center mx-auto mb-3">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <p className="text-white text-3xl font-bold">{(stats?.total_threats_detected_mtd || 0).toLocaleString()}</p>
          <p className="text-gray-400 text-sm mt-1">Threats Caught (MTD)</p>
        </div>
      </div>

      {/* Top orgs table */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-white font-semibold">All Organizations by Volume</h2>
          <span className="text-gray-500 text-sm">{allOrgs.length} orgs</span>
        </div>
        <table className="w-full">
          <thead className="border-b border-gray-800">
            <tr>
              {['#', 'Org Name', 'Plan', 'Emails MTD', 'Share'].map(h => (
                <th key={h} className="text-left text-gray-400 text-xs uppercase tracking-wide px-5 py-3">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {allOrgs.map((org: any, i: number) => {
              const pct = stats.total_emails_scanned_mtd > 0 ? (org.emails_mtd / stats.total_emails_scanned_mtd * 100) : 0
              return (
                <tr key={i} className="hover:bg-gray-800/50">
                  <td className="px-5 py-3 text-gray-600 text-sm">{i + 1}</td>
                  <td className="px-5 py-3 text-white text-sm font-medium">{org.org_name}</td>
                  <td className="px-5 py-3">
                    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${
                      org.plan === 'enterprise' ? 'bg-[var(--accent)]/20 text-[var(--accent)] border-[var(--accent)]' :
                      org.plan === 'professional' ? 'bg-blue-500/20 text-blue-300 border-blue-700' :
                      'bg-gray-500/20 text-gray-300 border-gray-600'
                    }`}>{org.plan}</span>
                  </td>
                  <td className="px-5 py-3 text-gray-300 text-sm font-mono">{org.emails_mtd.toLocaleString()}</td>
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-gray-800 rounded-full h-1.5 w-24">
                        <div className="bg-[var(--accent)] h-1.5 rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                      <span className="text-gray-500 text-xs">{pct.toFixed(1)}%</span>
                    </div>
                  </td>
                </tr>
              )
            })}
            {allOrgs.length === 0 && <tr><td colSpan={5} className="px-5 py-10 text-center text-gray-600">No data yet</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}
