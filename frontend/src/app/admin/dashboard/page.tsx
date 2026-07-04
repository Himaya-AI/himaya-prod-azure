'use client'
import { useEffect, useState, useCallback } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { adminFetch } from '@/lib/adminAuth'
import {
  Building2, Mail, Shield, DollarSign, Inbox,
  RefreshCw, Cloud, AlertCircle, PauseCircle,
  PlayCircle, Eye, Zap, TrendingUp,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface UsageStats {
  total_orgs: number
  total_emails_scanned_mtd: number
  total_threats_detected_mtd: number
  total_mrr_usd: number
  top_orgs_by_volume?: { org_name: string; plan: string; emails_mtd: number }[]
  daily_volume_30d?: { date: string; emails_scanned: number; threats_detected: number }[]
}

interface Org {
  org_id: string
  name: string
  domain: string
  plan: string
  status: string
  inboxes_onboarded: number
  emails_processed_mtd: number
  monthly_bill_usd: number
  auto_triage_enabled: boolean
  created_at: string
}

interface AwsCosts {
  total_mtd_usd: number | null
  period_start?: string
  period_end?: string
  by_service: { service: string; cost_usd: number }[]
  error?: string
  source?: string
}

// ─── Badge helpers ────────────────────────────────────────────────────────────

const STATUS_BADGE: Record<string, string> = {
  active:     'bg-green-500/15  text-green-300  border-green-500/40',
  suspended:  'bg-red-500/15    text-red-300    border-red-500/40',
  trial:      'bg-amber-500/15  text-amber-300  border-amber-500/40',
  offboarded: 'bg-slate-500/15  text-slate-300  border-slate-500/40',
}

const PLAN_BADGE: Record<string, string> = {
  enterprise:   'bg-[var(--accent)]/15 text-[var(--accent)] border-[var(--accent)]/40',
  professional: 'bg-blue-500/15   text-blue-300   border-blue-500/40',
  starter:      'bg-slate-500/15  text-slate-300  border-slate-500/40',
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({
  icon: Icon, label, value, sub, color, loading,
}: {
  icon: React.ElementType; label: string; value: string; sub?: string; color: string; loading?: boolean
}) {
  return (
    <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-5">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <p className="text-[#a0a0c0] text-sm font-medium">{label}</p>
          {loading ? (
            <div className="h-8 w-24 bg-[#1a1a28] rounded animate-pulse mt-1" />
          ) : (
            <p className="text-white text-2xl font-bold tracking-tight mt-1 truncate">{value}</p>
          )}
          {sub && <p className="text-[#6060a0] text-xs mt-1">{sub}</p>}
        </div>
        <div className={`w-10 h-10 ${color} rounded-lg flex items-center justify-center flex-shrink-0`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function AdminDashboard() {
  const router = useRouter()
  const [usage, setUsage] = useState<UsageStats | null>(null)
  const [orgs, setOrgs] = useState<Org[]>([])
  const [awsCosts, setAwsCosts] = useState<AwsCosts | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState('')
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date())
  const [suspending, setSuspending] = useState<string | null>(null)

  const fetchAll = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true)
    else setLoading(true)
    try {
      const [usageData, orgsData, costsData] = await Promise.all([
        adminFetch('/api/admin/usage'),
        adminFetch('/api/admin/orgs?limit=100'),
        adminFetch('/api/admin/aws-costs').catch(() => null),
      ])
      setUsage(usageData)
      setOrgs(Array.isArray(orgsData) ? orgsData : [])
      setAwsCosts(costsData)
      setLastRefresh(new Date())
      setError('')
    } catch (e: any) {
      setError(e.message || 'Failed to load dashboard data')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => {
    fetchAll()
    const interval = setInterval(() => fetchAll(true), 60_000)
    return () => clearInterval(interval)
  }, [fetchAll])

  async function handleSuspend(orgId: string, currentStatus: string) {
    const isSuspended = currentStatus === 'suspended'
    const msg = isSuspended
      ? 'Reactivate this organization?'
      : 'Suspend this organization? All users will be deactivated.'
    if (!confirm(msg)) return
    setSuspending(orgId)
    try {
      await adminFetch(
        `/api/admin/orgs/${orgId}/${isSuspended ? 'reactivate' : 'suspend'}`,
        { method: 'POST' },
      )
      await fetchAll(true)
    } catch {
      alert(isSuspended ? 'Failed to reactivate' : 'Failed to suspend')
    }
    setSuspending(null)
  }

  // Derived
  const totalInboxes = orgs.reduce((s, o) => s + (o.inboxes_onboarded || 0), 0)
  const planCounts = orgs.reduce((acc, o) => {
    acc[o.plan] = (acc[o.plan] || 0) + 1
    return acc
  }, {} as Record<string, number>)
  const maxPlanCount = Math.max(...Object.values(planCounts), 1)

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-white text-2xl font-bold tracking-tight">Command Center</h1>
          <p className="text-[#a0a0c0] text-sm mt-0.5">
            Himaya · Live platform overview
            <span className="text-[#6060a0] ml-2">
              · Updated {lastRefresh.toLocaleTimeString()}
            </span>
          </p>
        </div>
        <button
          onClick={() => fetchAll(true)}
          disabled={refreshing}
          className="flex items-center gap-2 px-3 py-2 bg-[#1a1a28] border border-[#2a2a3a] text-[#a0a0c0] hover:text-white hover:bg-[#2a2a3a] rounded-lg text-sm transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-300 flex items-center gap-2 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* 5 stat cards */}
      <div className="grid grid-cols-2 xl:grid-cols-5 gap-4">
        <StatCard
          icon={Building2}
          label="Active Orgs"
          value={String(usage?.total_orgs ?? orgs.filter(o => o.status === 'active').length)}
          sub="Customer tenants"
          color="bg-[var(--accent)]/20 text-[var(--accent)]"
        />
        <StatCard
          icon={Inbox}
          label="Total Inboxes"
          value={totalInboxes.toLocaleString()}
          sub="Onboarded mailboxes"
          color="bg-blue-500/20 text-blue-300"
        />
        <StatCard
          icon={Mail}
          label="Emails MTD"
          value={(usage?.total_emails_scanned_mtd ?? 0).toLocaleString()}
          sub="Processed this month"
          color="bg-blue-500/20 text-blue-300"
        />
        <StatCard
          icon={Shield}
          label="Threats MTD"
          value={(usage?.total_threats_detected_mtd ?? 0).toLocaleString()}
          sub="Detected &amp; blocked"
          color="bg-red-500/20 text-red-300"
        />
        <StatCard
          icon={DollarSign}
          label="Est. MRR"
          value={`$${(usage?.total_mrr_usd ?? 0).toLocaleString('en-US', { minimumFractionDigits: 0 })}`}
          sub="Monthly recurring revenue"
          color="bg-green-500/20 text-green-300"
        />
      </div>

      {/* AWS costs + plan breakdown */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* AWS Costs */}
        <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-white font-semibold flex items-center gap-2">
              <Cloud className="w-4 h-4 text-[var(--accent)]" />
              AWS Infrastructure Costs
            </h2>
            {awsCosts?.source === 'aws_cost_explorer' ? (
              <span className="flex items-center gap-1 px-2 py-0.5 bg-green-500/10 border border-green-700 text-green-400 rounded text-xs font-medium">
                <span className="w-1.5 h-1.5 bg-green-400 rounded-full" />
                Live · Cost Explorer
              </span>
            ) : (
              <span className="px-2 py-0.5 bg-amber-500/10 border border-amber-500/40 text-amber-300 rounded text-xs">
                Estimated
              </span>
            )}
          </div>

          {awsCosts ? (
            <>
              <div className="mb-4">
                <p className="text-[#a0a0c0] text-xs mb-1">Month-to-Date Total</p>
                <p className="text-white text-3xl font-bold">
                  {awsCosts.total_mtd_usd != null
                    ? `$${awsCosts.total_mtd_usd.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
                    : '—'}
                </p>
                {awsCosts.period_start && (
                  <p className="text-[#6060a0] text-xs mt-1">
                    {awsCosts.period_start} → {awsCosts.period_end}
                  </p>
                )}
              </div>

              {awsCosts.error ? (
                <p className="text-amber-300 text-sm flex items-center gap-2 bg-amber-500/10 rounded-lg px-3 py-2">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  Cost Explorer not configured
                </p>
              ) : (
                <div className="space-y-2">
                  {awsCosts.by_service.slice(0, 5).map(svc => (
                    <div key={svc.service} className="flex items-center justify-between text-sm">
                      <span className="text-[#a0a0c0] truncate mr-3" style={{ maxWidth: '70%' }}>{svc.service}</span>
                      <span className="text-white font-mono font-medium flex-shrink-0">
                        ${svc.cost_usd.toFixed(2)}
                      </span>
                    </div>
                  ))}
                  {awsCosts.by_service.length === 0 && (
                    <p className="text-[#6060a0] text-sm">No cost data yet this month</p>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="h-32 flex items-center justify-center text-[#6060a0] text-sm">
              Loading AWS costs…
            </div>
          )}
        </div>

        {/* Orgs by Plan */}
        <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-6">
          <h2 className="text-white font-semibold flex items-center gap-2 mb-4">
            <TrendingUp className="w-4 h-4 text-[var(--accent)]" />
            Orgs by Plan
          </h2>
          <div className="space-y-4">
            {(['enterprise', 'professional', 'starter'] as const).map(plan => {
              const count = planCounts[plan] || 0
              const pct = Math.round((count / Math.max(orgs.length, 1)) * 100)
              const barColor: Record<string, string> = {
                enterprise: 'bg-[var(--accent)]',
                professional: 'bg-blue-500',
                starter: 'bg-slate-500',
              }
              return (
                <div key={plan}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${PLAN_BADGE[plan]}`}>
                      {plan}
                    </span>
                    <span className="text-white text-sm font-bold">
                      {count} org{count !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <div className="h-2 bg-[#1a1a28] rounded-full overflow-hidden">
                    <div
                      className={`h-full ${barColor[plan]} rounded-full transition-all duration-500`}
                      style={{ width: `${(count / maxPlanCount) * 100}%` }}
                    />
                  </div>
                  <p className="text-[#6060a0] text-xs mt-0.5">{pct}% of all orgs</p>
                </div>
              )
            })}
          </div>
          <div className="mt-6 pt-4 border-t border-[#2a2a3a] space-y-1">
            {[
              { label: 'Total orgs', value: String(orgs.length), color: 'text-white' },
              { label: 'Active', value: String(orgs.filter(o => o.status === 'active').length), color: 'text-green-400' },
              { label: 'Suspended', value: String(orgs.filter(o => o.status === 'suspended').length), color: 'text-red-400' },
            ].map(row => (
              <div key={row.label} className="flex items-center justify-between text-sm">
                <span className="text-[#a0a0c0]">{row.label}</span>
                <span className={`font-bold ${row.color}`}>{row.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Customer orgs table */}
      <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-[#2a2a3a] flex items-center justify-between">
          <h2 className="text-white font-semibold">Customer Orgs</h2>
          <Link
            href="/admin/orgs/new"
            className="text-sm px-3 py-1.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-lg transition-colors"
          >
            + New Org
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-[#0f0f1a] border-b border-[#2a2a3a]">
              <tr>
                {['Org Name', 'Plan', 'Status', 'Inboxes', 'Emails MTD', 'Est. Cost', 'Auto-Triage', 'View'].map(h => (
                  <th
                    key={h}
                    className="text-left text-[#a0a0c0] text-xs font-medium uppercase tracking-wide px-4 py-3 whitespace-nowrap"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2a2a3a]">
              {orgs.map(org => (
                <tr key={org.org_id} className="hover:bg-[#1a1a28]/40 transition-colors">
                  <td className="px-4 py-3">
                    <button
                      onClick={() => router.push(`/admin/orgs/${org.org_id}`)}
                      className="text-white text-sm font-medium hover:text-[var(--accent)] transition-colors text-left"
                    >
                      {org.name}
                    </button>
                    <p className="text-[#6060a0] text-xs font-mono">{org.domain}</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${PLAN_BADGE[org.plan] ?? PLAN_BADGE.starter}`}>
                      {org.plan}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${STATUS_BADGE[org.status] ?? STATUS_BADGE.active}`}>
                      {org.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[#d0d0f0] text-sm">
                    {(org.inboxes_onboarded ?? 0).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-[#d0d0f0] text-sm">
                    {(org.emails_processed_mtd ?? 0).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-green-300 text-sm font-mono">
                    ${(org.monthly_bill_usd ?? 0).toFixed(2)}
                  </td>
                  <td className="px-4 py-3">
                    {org.auto_triage_enabled ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-green-500/20 text-green-300 text-xs font-medium">
                        <Zap className="w-3 h-3" /> ON
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-[#2a2a3a]/40 text-[#6060a0] text-xs">
                        OFF
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <Link
                        href={`/admin/orgs/${org.org_id}`}
                        className="p-1.5 rounded text-[#a0a0c0] hover:text-white hover:bg-[#2a2a3a] transition-colors"
                        title="View"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </Link>
                      {org.status === 'active' ? (
                        <button
                          onClick={() => handleSuspend(org.org_id, org.status)}
                          disabled={suspending === org.org_id}
                          className="p-1.5 rounded text-[#a0a0c0] hover:text-red-400 hover:bg-[#2a2a3a] transition-colors disabled:opacity-40"
                          title="Suspend"
                        >
                          <PauseCircle className="w-3.5 h-3.5" />
                        </button>
                      ) : org.status === 'suspended' ? (
                        <button
                          onClick={() => handleSuspend(org.org_id, org.status)}
                          disabled={suspending === org.org_id}
                          className="p-1.5 rounded text-[#a0a0c0] hover:text-green-400 hover:bg-[#2a2a3a] transition-colors disabled:opacity-40"
                          title="Reactivate"
                        >
                          <PlayCircle className="w-3.5 h-3.5" />
                        </button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))}
              {orgs.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-[#6060a0]">
                    No organizations yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
