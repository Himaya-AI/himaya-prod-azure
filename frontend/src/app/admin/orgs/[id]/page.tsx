'use client'
import { useEffect, useState, useCallback } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { adminFetch } from '@/lib/adminAuth'
import {
  ArrowLeft, Building2, Activity, Settings,
  Shield, CheckCircle2, AlertCircle,
  RefreshCw, Zap, ChevronLeft, ChevronRight,
  FlaskConical, Trash2, PlayCircle, PauseCircle,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface OrgMetrics {
  org_id: string
  org_name: string
  plan: string
  status: string
  contact_email: string
  inboxes_onboarded: number
  groups_count: number
  shared_mailboxes_count: number
  emails_processed_total: number
  emails_processed_mtd: number
  threats_detected_mtd: number
  quarantined_mtd: number
  auto_triage_enabled: boolean
  auto_triage_last_run: number | null
  integrations: {
    provider: string
    status: string
    mailbox_count: number
    last_sync_at: string | null
  }[]
  cost_usd_mtd: number
  created_at: string | null
}

interface OrgDetail {
  org_id: string
  name: string
  domain: string
  plan: string
  status: string
  country: string
  mailbox_count: number
  mailbox_limit: number
  billing_rate_usd: number
  contact_email: string
  contact_name: string
  suspended_at: string | null
  created_at: string | null
  users: unknown[]
  usage_history: unknown[]
  billing_history: unknown[]
}

interface AuditItem {
  id: string
  event_type: string
  timestamp: string
  sender: string
  recipient: string
  threat_type: string
  risk_score: number
  action: string
  auto_triage_verdict: string | null
  auto_triage_confidence: number | null
  neo4j_queried: boolean
  details: Record<string, unknown>
}

type Tab = 'overview' | 'audit' | 'account'

// ─── Badges ───────────────────────────────────────────────────────────────────

const PLAN_BADGE: Record<string, string> = {
  enterprise:   'bg-[var(--accent)]/20 text-[var(--accent)] border-[var(--accent)]',
  professional: 'bg-blue-500/20   text-blue-300   border-blue-700',
  starter:      'bg-slate-500/15  text-slate-300   border-slate-500/40',
}
const STATUS_BADGE: Record<string, string> = {
  active:     'bg-green-500/20 text-green-300 border-green-700',
  suspended:  'bg-red-500/20   text-red-300   border-red-700',
  offboarded: 'bg-slate-500/15  text-slate-300  border-slate-500/40',
}
const EVENT_BADGE: Record<string, string> = {
  AUTO_TRIAGE:     'bg-orange-500/20 text-orange-400',
  QUARANTINE:      'bg-red-500/20    text-red-400',
  THREAT_DETECTED: 'bg-yellow-500/20 text-yellow-400',
  CLEAN_PASS:      'bg-green-500/20  text-green-400',
  SPAM:            'bg-amber-500/20  text-amber-400',
}

const AUDIT_PAGE_SIZE = 50

// ─── Metric Card ─────────────────────────────────────────────────────────────

function MetricCard({ label, value, sub, color }: {
  label: string; value: string; sub?: string; color?: string
}) {
  return (
    <div className="bg-[#1a1a28]/60 border border-[#2a2a3a] rounded-xl p-4">
      <p className="text-[#a0a0c0] text-xs font-medium">{label}</p>
      <p className={`text-xl font-bold mt-0.5 ${color ?? 'text-white'}`}>{value}</p>
      {sub && <p className="text-[#6060a0] text-xs mt-0.5">{sub}</p>}
    </div>
  )
}

// ─── Overview Tab ─────────────────────────────────────────────────────────────

function OverviewTab({ metrics, metricsError, org }: {
  metrics: OrgMetrics | null
  metricsError: boolean
  org: OrgDetail
}) {
  if (metricsError) {
    return (
      <div className="border border-red-800 bg-red-900/10 rounded-xl p-6 text-red-300 flex items-center gap-3">
        <AlertCircle className="w-5 h-5 flex-shrink-0" />
        <div>
          <p className="font-semibold">Metrics unavailable</p>
          <p className="text-sm text-red-400 mt-0.5">The metrics endpoint returned an error. Organization data is still accessible via other tabs.</p>
        </div>
      </div>
    )
  }

  if (!metrics) {
    return (
      <div className="flex items-center justify-center h-32 text-[#6060a0]">
        <div className="w-6 h-6 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin mr-3" />
        Loading metrics…
      </div>
    )
  }

  const costBreakdown = [
    {
      label: 'Base compute',
      formula: `${metrics.emails_processed_mtd.toLocaleString()} emails × $0.0008`,
      value: (metrics.emails_processed_mtd * 0.0008).toFixed(2),
    },
    {
      label: 'LLM classification',
      formula: `${metrics.threats_detected_mtd.toLocaleString()} threats × $0.002`,
      value: (metrics.threats_detected_mtd * 0.002).toFixed(2),
    },
    {
      label: 'Auto-triage analysis',
      formula: `${metrics.quarantined_mtd.toLocaleString()} quarantined × $0.001`,
      value: (metrics.quarantined_mtd * 0.001).toFixed(2),
    },
  ]

  return (
    <div className="space-y-6">
      {/* Org info grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
        {([
          ['Organization', org.name],
          ['Domain', org.domain],
          ['Country', org.country || '—'],
          ['Admin Email', org.contact_email || metrics.contact_email || '—'],
          ['Contact Name', org.contact_name || '—'],
          ['Created', org.created_at
            ? new Date(org.created_at).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
            : '—'],
        ] as [string, string][]).map(([k, v]) => (
          <div key={k} className="bg-[#111118] border border-[#2a2a3a] rounded-lg px-4 py-3">
            <p className="text-[#6060a0] text-xs">{k}</p>
            <p className="text-white text-sm font-medium mt-0.5 truncate" title={v}>{v}</p>
          </div>
        ))}
      </div>

      {/* 6 metric cards */}
      <div>
        <h3 className="text-white font-semibold text-sm mb-3">Live Metrics (MTD)</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
          <MetricCard label="Inboxes" value={metrics.inboxes_onboarded.toLocaleString()} />
          <MetricCard label="Groups / DLs" value={metrics.groups_count.toLocaleString()} />
          <MetricCard label="Shared Mailboxes" value={metrics.shared_mailboxes_count.toLocaleString()} />
          <MetricCard label="Emails MTD" value={metrics.emails_processed_mtd.toLocaleString()} />
          <MetricCard label="Threats MTD" value={metrics.threats_detected_mtd.toLocaleString()} color="text-red-300" />
          <MetricCard label="Quarantined MTD" value={metrics.quarantined_mtd.toLocaleString()} color="text-orange-300" />
        </div>
      </div>

      {/* Cost card */}
      <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-white font-semibold text-sm">Cost MTD</h3>
          <span className="text-green-300 text-xl font-bold font-mono">${metrics.cost_usd_mtd.toFixed(2)}</span>
        </div>
        <div className="space-y-2">
          {costBreakdown.map(row => (
            <div key={row.label} className="flex items-center justify-between text-sm">
              <div>
                <span className="text-[#d0d0f0]">{row.label}</span>
                <span className="text-[#6060a0] ml-2 text-xs font-mono">{row.formula}</span>
              </div>
              <span className="text-white font-mono">${row.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Integration cards */}
      <div>
        <h3 className="text-white font-semibold text-sm mb-3">Integrations</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {(['google', 'm365'] as const).map(provider => {
            const integration = metrics.integrations.find(i => i.provider === provider)
            return (
              <div key={provider} className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-white font-medium text-sm">
                    {provider === 'google' ? '🔵 Google Workspace' : '🟦 Microsoft 365'}
                  </span>
                  {integration ? (
                    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${
                      integration.status === 'active'
                        ? 'bg-green-500/20 text-green-300 border-green-700'
                        : 'bg-red-500/20 text-red-300 border-red-700'
                    }`}>
                      {integration.status}
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded border text-xs text-[#6060a0] border-[#2a2a3a]">
                      Not connected
                    </span>
                  )}
                </div>
                {integration && (
                  <div className="space-y-1 text-xs text-[#a0a0c0]">
                    <p>Mailboxes: <span className="text-white font-medium">{integration.mailbox_count}</span></p>
                    <p>Last sync: <span className="text-white">
                      {integration.last_sync_at ? new Date(integration.last_sync_at).toLocaleString() : 'Never'}
                    </span></p>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Auto-triage */}
      <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className={`w-4 h-4 ${metrics.auto_triage_enabled ? 'text-orange-400' : 'text-[#6060a0]'}`} />
            <span className="text-white font-medium text-sm">Auto-Triage (Himaya Analysis)</span>
          </div>
          <span className={`px-2 py-0.5 rounded border text-xs font-medium ${
            metrics.auto_triage_enabled
              ? 'bg-orange-500/20 text-orange-300 border-orange-700'
              : 'bg-slate-500/15 text-slate-300 border-slate-500/40'
          }`}>
            {metrics.auto_triage_enabled ? 'Enabled' : 'Disabled'}
          </span>
        </div>
        {metrics.auto_triage_last_run && (
          <p className="text-[#6060a0] text-xs mt-2">
            Last run: {new Date(metrics.auto_triage_last_run * 1000).toLocaleString()}
          </p>
        )}
      </div>
    </div>
  )
}

// ─── Audit Trail Tab ──────────────────────────────────────────────────────────

function AuditTrailTab({ orgId }: { orgId: string }) {
  const [items, setItems] = useState<AuditItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [eventTypeFilter, setEventTypeFilter] = useState('')
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const params = new URLSearchParams({
        limit: String(AUDIT_PAGE_SIZE),
        offset: String((page - 1) * AUDIT_PAGE_SIZE),
      })
      if (eventTypeFilter) params.set('event_type', eventTypeFilter)
      const data = await adminFetch(`/api/admin/orgs/${orgId}/audit-trail?${params}`)
      setItems(data.items ?? [])
      setTotal(data.total ?? 0)
    } catch (e: any) {
      setError(e.message || 'Failed to load audit trail')
    }
    setLoading(false)
  }, [orgId, page, eventTypeFilter])

  useEffect(() => { load() }, [load])
  useEffect(() => { setPage(1) }, [eventTypeFilter])

  const totalPages = Math.max(1, Math.ceil(total / AUDIT_PAGE_SIZE))
  const rangeStart = total === 0 ? 0 : (page - 1) * AUDIT_PAGE_SIZE + 1
  const rangeEnd = Math.min(page * AUDIT_PAGE_SIZE, total)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-center">
        <select
          value={eventTypeFilter}
          onChange={e => setEventTypeFilter(e.target.value)}
          className="bg-[#111118] border border-[#2a2a3a] rounded-lg px-3 py-2 text-[#d0d0f0] text-sm focus:outline-none focus:border-[var(--accent)]"
        >
          <option value="">All Event Types</option>
          <option value="AUTO_TRIAGE">Auto-Triage</option>
          <option value="QUARANTINE">Quarantine</option>
          <option value="THREAT_DETECTED">Threat Detected</option>
          <option value="CLEAN_PASS">Clean Pass</option>
          <option value="SPAM">Spam</option>
        </select>
        <button
          onClick={() => load()}
          className="flex items-center gap-1.5 px-3 py-2 bg-[#1a1a28] hover:bg-[#2a2a3a] text-[#d0d0f0] rounded-lg text-sm transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
        <span className="text-[#6060a0] text-sm">{total.toLocaleString()} total events</span>
      </div>

      {error && (
        <div className="bg-red-900/20 border border-red-700 rounded-xl p-3 text-red-300 text-sm flex items-center gap-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="w-6 h-6 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-[#2a2a3a]">
                <tr>
                  {['Time', 'Event', 'Sender', 'Recipient', 'Type', 'Score', 'Action', 'Verdict', 'Neo4j'].map(h => (
                    <th
                      key={h}
                      className="text-left text-[#a0a0c0] text-xs font-medium uppercase tracking-wide px-3 py-3 whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-[#2a2a3a]">
                {items.map(item => (
                  <tr key={item.id} className="hover:bg-[#1a1a28]/40 transition-colors">
                    <td className="px-3 py-2.5 text-[#a0a0c0] text-xs whitespace-nowrap">
                      {item.timestamp ? new Date(item.timestamp).toLocaleString() : '—'}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap ${EVENT_BADGE[item.event_type] ?? EVENT_BADGE.THREAT_DETECTED}`}>
                        {item.event_type}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-[#d0d0f0] text-xs max-w-[140px] truncate" title={item.sender}>
                      {item.sender || '—'}
                    </td>
                    <td className="px-3 py-2.5 text-[#d0d0f0] text-xs max-w-[140px] truncate" title={item.recipient}>
                      {item.recipient || '—'}
                    </td>
                    <td className="px-3 py-2.5 text-[#a0a0c0] text-xs whitespace-nowrap">
                      {item.threat_type || '—'}
                    </td>
                    <td className="px-3 py-2.5 text-sm font-mono">
                      <span className={
                        item.risk_score >= 90 ? 'text-red-400' :
                        item.risk_score >= 70 ? 'text-orange-400' :
                        item.risk_score >= 40 ? 'text-yellow-400' :
                        'text-green-400'
                      }>
                        {item.risk_score ?? '—'}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 text-[#a0a0c0] text-xs whitespace-nowrap">
                      {item.action || '—'}
                    </td>
                    <td className="px-3 py-2.5">
                      {item.auto_triage_verdict ? (
                        <div className="flex flex-col gap-0.5">
                          <span className="text-orange-300 text-xs font-medium">{item.auto_triage_verdict}</span>
                          {item.auto_triage_confidence != null && (
                            <span className="text-xs text-[#6060a0]">
                              {Math.round(item.auto_triage_confidence * 100)}% conf.
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-[#6060a0] text-xs">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      {item.neo4j_queried ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                      ) : (
                        <span className="text-[#6060a0] text-xs">—</span>
                      )}
                    </td>
                  </tr>
                ))}
                {items.length === 0 && (
                  <tr>
                    <td colSpan={9} className="px-4 py-12 text-center text-[#6060a0]">
                      No audit events found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-[#2a2a3a]">
          <p className="text-[#a0a0c0] text-sm">
            {total > 0 ? `${rangeStart}–${rangeEnd} of ${total.toLocaleString()}` : '0 events'}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="p-1.5 rounded text-[#a0a0c0] hover:text-white hover:bg-[#2a2a3a] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="p-1.5 rounded text-[#a0a0c0] hover:text-white hover:bg-[#2a2a3a] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Account Management Tab ───────────────────────────────────────────────────

function AccountTab({ org, onRefresh }: { org: OrgDetail; onRefresh: () => void }) {
  const router = useRouter()
  const [actionLoading, setActionLoading] = useState(false)
  const [planValue, setPlanValue] = useState(org.plan)
  const [savingPlan, setSavingPlan] = useState(false)
  const [deleteTyped, setDeleteTyped] = useState('')
  const [showDeleteZone, setShowDeleteZone] = useState(false)
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; msg: string } | null>(null)
  const [injectLoading, setInjectLoading] = useState(false)
  const [injectResult, setInjectResult] = useState<any>(null)

  function notify(type: 'success' | 'error', msg: string) {
    setNotification({ type, msg })
    setTimeout(() => setNotification(null), 6000)
  }

  async function doSavePlan() {
    setSavingPlan(true)
    try {
      await adminFetch(`/api/admin/orgs/${org.org_id}`, {
        method: 'PUT',
        body: JSON.stringify({ plan: planValue }),
      })
      notify('success', `Plan updated to ${planValue}`)
      onRefresh()
    } catch (e: any) {
      notify('error', e.message || 'Failed to update plan')
    }
    setSavingPlan(false)
  }

  async function doSuspend() {
    if (!confirm('Suspend this org? All users will lose access.')) return
    setActionLoading(true)
    try {
      await adminFetch(`/api/admin/orgs/${org.org_id}/suspend`, { method: 'POST' })
      notify('success', 'Organization suspended')
      onRefresh()
    } catch (e: any) {
      notify('error', e.message || 'Failed to suspend')
    }
    setActionLoading(false)
  }

  async function doReactivate() {
    setActionLoading(true)
    try {
      await adminFetch(`/api/admin/orgs/${org.org_id}/reactivate`, { method: 'POST' })
      notify('success', 'Organization reactivated')
      onRefresh()
    } catch (e: any) {
      notify('error', e.message || 'Failed to reactivate')
    }
    setActionLoading(false)
  }

  async function doResendActivation() {
    setActionLoading(true)
    try {
      const res = await adminFetch(`/api/admin/orgs/${org.org_id}/resend-activation`, { method: 'POST' })
      notify('success', `Activation email sent to ${res.email} (valid 72h)`)
    } catch (e: any) {
      notify('error', e.message || 'Failed to resend activation')
    }
    setActionLoading(false)
  }

  async function doInjectThreats() {
    setInjectLoading(true)
    setInjectResult(null)
    try {
      const res = await adminFetch(`/api/admin/orgs/${org.org_id}/inject-test-threats`, { method: 'POST' })
      setInjectResult(res)
    } catch (e: any) {
      notify('error', e.message || 'Inject failed')
    }
    setInjectLoading(false)
  }

  async function doDelete() {
    if (deleteTyped !== org.name) return
    setActionLoading(true)
    try {
      await adminFetch(`/api/admin/orgs/${org.org_id}`, { method: 'DELETE' })
      router.replace('/admin/orgs')
    } catch (e: any) {
      notify('error', e.message || 'Failed to delete org')
      setActionLoading(false)
    }
  }

  return (
    <div className="space-y-4 max-w-2xl">
      {notification && (
        <div className={`p-3 rounded-xl border text-sm flex items-center gap-2 ${
          notification.type === 'success'
            ? 'bg-green-900/20 border-green-700 text-green-300'
            : 'bg-red-900/20 border-red-700 text-red-300'
        }`}>
          {notification.type === 'success'
            ? <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            : <AlertCircle className="w-4 h-4 flex-shrink-0" />}
          {notification.msg}
        </div>
      )}

      {/* Plan selector */}
      <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-5">
        <h3 className="text-white font-semibold mb-1">Plan</h3>
        <p className="text-[#a0a0c0] text-sm mb-4">Change the subscription plan for this organization.</p>
        <div className="flex items-center gap-3">
          <select
            value={planValue}
            onChange={e => setPlanValue(e.target.value)}
            className="bg-[#1a1a28] border border-[#2a2a3a] text-white text-sm rounded-lg px-3 py-2 focus:outline-none focus:border-[var(--accent)]"
          >
            <option value="starter">Starter</option>
            <option value="professional">Professional</option>
            <option value="enterprise">Enterprise</option>
          </select>
          <button
            onClick={doSavePlan}
            disabled={savingPlan || planValue === org.plan}
            className="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent)] disabled:opacity-50 text-white rounded-lg text-sm transition-colors"
          >
            {savingPlan ? 'Saving…' : 'Save Plan'}
          </button>
        </div>
      </div>

      {/* Resend activation */}
      <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-5">
        <h3 className="text-white font-semibold mb-1">Resend Activation Email</h3>
        <p className="text-[#a0a0c0] text-sm mb-4">
          Generate a fresh activation link (72h validity) and re-send the welcome email.
        </p>
        <button
          onClick={doResendActivation}
          disabled={actionLoading}
          className="px-4 py-2 bg-[#1a1a28] border border-[#2a2a3a] hover:bg-[#2a2a3a] disabled:opacity-50 text-white rounded-lg text-sm transition-colors"
        >
          {actionLoading ? 'Sending…' : 'Resend Activation Email'}
        </button>
      </div>

      {/* Inject test threats */}
      <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-1">
          <FlaskConical className="w-4 h-4 text-[var(--accent)]" />
          <h3 className="text-white font-semibold">Inject Test Threats</h3>
        </div>
        <p className="text-[#a0a0c0] text-sm mb-4">
          Inject 4 simulated threat emails (BEC, phishing, malware, credential harvesting) directly into the processing pipeline for QA testing.
        </p>
        <button
          onClick={doInjectThreats}
          disabled={injectLoading}
          className="flex items-center gap-2 px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-50 text-white rounded-lg text-sm transition-colors"
        >
          {injectLoading ? (
            <>
              <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              Injecting…
            </>
          ) : (
            'Inject Test Threats'
          )}
        </button>
        {injectResult && (
          <div className="mt-3 bg-[#1a1a28] rounded-lg p-3 text-xs">
            <p className="text-green-300 font-medium mb-2">
              Injected {injectResult.injected} / {injectResult.results?.length ?? 0}
            </p>
            {injectResult.results?.map((r: any, i: number) => (
              <div key={i} className={`flex justify-between py-0.5 ${r.error ? 'text-red-400' : 'text-[#d0d0f0]'}`}>
                <span className="truncate mr-4">{r.label}</span>
                <span className="font-mono text-right flex-shrink-0">
                  {r.error ? r.error.slice(0, 40) : (r.threat_type || r.status)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Suspend / Reactivate */}
      {org.status === 'active' ? (
        <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-5">
          <h3 className="text-white font-semibold mb-1">Suspend Organization</h3>
          <p className="text-[#a0a0c0] text-sm mb-4">
            Immediately deactivate all users and revoke access. Can be reactivated later.
          </p>
          <button
            onClick={doSuspend}
            disabled={actionLoading}
            className="flex items-center gap-2 px-4 py-2 bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white rounded-lg text-sm transition-colors"
          >
            <PauseCircle className="w-4 h-4" />
            {actionLoading ? 'Suspending…' : 'Suspend Organization'}
          </button>
        </div>
      ) : org.status === 'suspended' ? (
        <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl p-5">
          <h3 className="text-white font-semibold mb-1">Reactivate Organization</h3>
          <p className="text-[#a0a0c0] text-sm mb-4">Restore platform access for all users.</p>
          <button
            onClick={doReactivate}
            disabled={actionLoading}
            className="flex items-center gap-2 px-4 py-2 bg-green-700 hover:bg-green-600 disabled:opacity-50 text-white rounded-lg text-sm transition-colors"
          >
            <PlayCircle className="w-4 h-4" />
            {actionLoading ? 'Reactivating…' : 'Reactivate Organization'}
          </button>
        </div>
      ) : null}

      {/* Danger zone — Delete requires typing org name */}
      <div className="bg-[#111118] border border-red-900 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-1">
          <Trash2 className="w-4 h-4 text-red-400" />
          <h3 className="text-red-400 font-semibold">Danger Zone — Offboard Organization</h3>
        </div>
        <p className="text-[#a0a0c0] text-sm mb-4">
          Soft-delete this organization. Data is retained for 90 days, then permanently purged. This cannot be undone.
        </p>

        {!showDeleteZone ? (
          <button
            onClick={() => setShowDeleteZone(true)}
            className="px-4 py-2 bg-red-900/50 border border-red-800 hover:bg-red-900 text-red-300 rounded-lg text-sm transition-colors"
          >
            Offboard Organization
          </button>
        ) : (
          <div className="space-y-3">
            <p className="text-red-300 text-sm font-medium">
              Type <span className="font-mono font-bold">{org.name}</span> to confirm deletion:
            </p>
            <input
              value={deleteTyped}
              onChange={e => setDeleteTyped(e.target.value)}
              placeholder={org.name}
              className="w-full bg-[#1a1a28] border border-[#2a2a3a] rounded-lg px-3 py-2 text-white text-sm placeholder-[#6060a0] focus:outline-none focus:border-red-600"
            />
            <div className="flex gap-2">
              <button
                onClick={doDelete}
                disabled={deleteTyped !== org.name || actionLoading}
                className="px-4 py-2 bg-red-700 hover:bg-red-600 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-sm transition-colors"
              >
                {actionLoading ? 'Deleting…' : 'Confirm Offboard'}
              </button>
              <button
                onClick={() => { setShowDeleteZone(false); setDeleteTyped('') }}
                className="px-4 py-2 bg-[#1a1a28] border border-[#2a2a3a] hover:bg-[#2a2a3a] text-white rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function OrgDetail() {
  const { id } = useParams<{ id: string }>()
  const [org, setOrg] = useState<OrgDetail | null>(null)
  const [metrics, setMetrics] = useState<OrgMetrics | null>(null)
  const [metricsError, setMetricsError] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [tab, setTab] = useState<Tab>('overview')

  const load = useCallback(async () => {
    setError('')
    setMetricsError(false)
    try {
      const orgData = await adminFetch(`/api/admin/orgs/${id}`)
      setOrg(orgData)

      // Fetch metrics separately — gracefully handle 500
      try {
        const metricsData = await adminFetch(`/api/admin/orgs/${id}/metrics`)
        setMetrics(metricsData)
      } catch {
        setMetricsError(true)
        setMetrics(null)
      }
    } catch (e: any) {
      setError(e.message || 'Failed to load organization')
    }
    setLoading(false)
  }, [id])

  useEffect(() => { load() }, [load])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (error || !org) {
    return (
      <div className="bg-red-900/20 border border-red-700 rounded-xl p-6 text-red-300 flex items-center gap-2">
        <AlertCircle className="w-5 h-5 flex-shrink-0" />
        {error || 'Organization not found'}
      </div>
    )
  }

  const TABS: { key: Tab; label: string; icon: React.ElementType }[] = [
    { key: 'overview', label: 'Overview', icon: Building2 },
    { key: 'audit', label: 'Audit Trail', icon: Activity },
    { key: 'account', label: 'Account Management', icon: Settings },
  ]

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-start gap-3">
        <Link
          href="/admin/orgs"
          className="p-2 rounded-lg text-[#a0a0c0] hover:text-white hover:bg-[#1a1a28] transition-colors mt-0.5"
        >
          <ArrowLeft className="w-4 h-4" />
        </Link>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-white text-2xl font-bold truncate">{org.name}</h1>
            <span className={`px-2 py-0.5 rounded border text-xs font-medium ${STATUS_BADGE[org.status] ?? STATUS_BADGE.active}`}>
              {org.status}
            </span>
            <span className={`px-2 py-0.5 rounded border text-xs font-medium ${PLAN_BADGE[org.plan] ?? PLAN_BADGE.starter}`}>
              {org.plan}
            </span>
          </div>
          <p className="text-[#a0a0c0] text-sm mt-0.5 font-mono">{org.domain}</p>
        </div>
        <button
          onClick={() => load()}
          className="p-2 rounded-lg text-[#a0a0c0] hover:text-white hover:bg-[#1a1a28] transition-colors"
          title="Refresh"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Tabs — purple active indicator */}
      <div className="flex gap-1 border-b border-[#2a2a3a]">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors border-b-2 -mb-px ${
              tab === key
                ? 'border-[var(--accent)] text-[var(--accent)]'
                : 'border-transparent text-[#a0a0c0] hover:text-white'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'overview' && (
        <OverviewTab metrics={metrics} metricsError={metricsError} org={org} />
      )}
      {tab === 'audit' && <AuditTrailTab orgId={id as string} />}
      {tab === 'account' && <AccountTab org={org} onRefresh={load} />}
    </div>
  )
}
