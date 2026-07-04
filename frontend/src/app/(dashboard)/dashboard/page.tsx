'use client'
import { useEffect, useState, useCallback } from 'react'
import MetricCard from '@/components/dashboard/MetricCard'
import ThreatFeed from '@/components/dashboard/ThreatFeed'
import TrendChart from '@/components/dashboard/TrendChart'
import AtRiskEmployees, { TopTargetedGroups } from '@/components/dashboard/AtRiskEmployees'
import ThreatMap from '@/components/dashboard/ThreatMap'
import api from '@/lib/api'
import type { DashboardSummary, TrendDataPoint } from '@/lib/types'
import {
  Shield, Lock, CheckSquare, RefreshCw, AlertTriangle,
  Zap, Brain, TrendingUp, Target, BookOpen, Info, X, ArrowRight,
} from 'lucide-react'
import { useRouter } from 'next/navigation'

const SYNC_INTERVAL_MS = 2 * 60 * 1000 // 2 minutes

// ─── Threat Type Breakdown ────────────────────────────────────────────────────

function ThreatTypeBreakdown({ data, loading }: { data: Record<string, number>; loading: boolean }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0)
  const sorted = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 5)

  const COLOR_MAP: Record<string, string> = {
    BEC: '#e94560', PHISHING: '#f97316', MALWARE: '#ef4444',
    IMPERSONATION: '#a855f7', SPAM: '#6b7280', SUPPLY_CHAIN: '#0ea5e9',
    GOV_IMPERSONATION: '#f59e0b', ACCOUNT_TAKEOVER: '#ec4899',
    CREDENTIAL_HARVESTING: '#14b8a6', LOOKALIKE_DOMAIN: '#84cc16',
  }

  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl p-5 h-full">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-[13px] font-semibold text-white flex items-center gap-2">
          <AlertTriangle size={14} className="text-[#e94560]" /> Email Classification Type
        </h3>
        {!loading && Object.keys(data).length > 0 && (
          <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 border border-red-500/20 text-red-400">
            <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
            Live
          </span>
        )}
      </div>
      {loading ? (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-8 animate-pulse bg-white/[0.04] rounded" />
          ))}
        </div>
      ) : sorted.length === 0 ? (
        <p className="text-[12px] text-slate-500 italic">No potential threats detected yet</p>
      ) : (
        <div className="space-y-2.5">
          {sorted.map(([type, count]) => {
            const pct = total > 0 ? Math.round((count / total) * 100) : 0
            const color = COLOR_MAP[type] ?? '#3b6ef6'
            return (
              <div key={type}>
                <div className="flex items-center justify-between text-[12px] mb-1">
                  <span className="text-slate-300 font-medium">{type}</span>
                  <span className="text-slate-500">{count} ({pct}%)</span>
                </div>
                <div className="h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${pct}%`, backgroundColor: color }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Rule Usage & Top Hit Policies Panel ─────────────────────────────────────

interface RuleUsageData {
  total_evaluations: number
  active_policies: number
  top_policies: Array<{
    id: string
    name: string
    action: string
    status: string
    hit_count: number
  }>
}

const ACTION_COLOR: Record<string, string> = {
  QUARANTINE: '#3b6ef6',
  BLOCK_DELETE: '#e94560',
  DELIVER_WITH_BANNER: '#f59e0b',
  HOLD_FOR_REVIEW: '#a855f7',
  ALLOW: '#22c55e',
  ALERT_ONLY: '#6b7280',
}

function RuleUsagePanel() {
  const router = useRouter()
  const [data, setData] = useState<RuleUsageData | null>(null)
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const fetch = useCallback(async () => {
    try {
      const res = await api.get('/api/dashboard/rule-usage')
      setData(res.data)
      setLastUpdated(new Date())
    } catch {
      // silent
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    fetch()
    const id = setInterval(fetch, 60_000)
    return () => clearInterval(id)
  }, [fetch])

  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl p-5 h-full">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-[13px] font-semibold text-white flex items-center gap-2">
          <BookOpen size={14} className="text-[#3b6ef6]" /> Rule Usage & Top Hit Policies
        </h3>
        <div className="flex items-center gap-2">
          {lastUpdated && (
            <div className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 border border-red-500/20 text-red-400">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              Live
            </div>
          )}
          <button
            onClick={() => router.push('/policies')}
            className="flex items-center gap-1 text-[10px] text-[#3b6ef6] hover:text-blue-300 transition-colors"
          >
            View Rules <ArrowRight size={10} />
          </button>
        </div>
      </div>

      {loading ? (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-8 animate-pulse bg-white/[0.04] rounded" />
          ))}
        </div>
      ) : !data || data.top_policies.length === 0 ? (
        <div>
          <div className="flex gap-4 mb-3">
            <div className="text-center">
              <div className="text-xl font-bold text-[#3b6ef6]">{data?.active_policies ?? 0}</div>
              <div className="text-[10px] text-slate-500">Active Rules</div>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-slate-400">{data?.total_evaluations ?? 0}</div>
              <div className="text-[10px] text-slate-500">Total Evaluations</div>
            </div>
          </div>
          <p className="text-[12px] text-slate-500 italic">No policy hits recorded yet</p>
        </div>
      ) : (
        <div className="space-y-2">
          {/* Summary row */}
          <div className="flex flex-wrap gap-3 mb-3">
            <div className="flex items-center gap-1.5">
              <Target size={11} className="text-[#3b6ef6]" />
              <span className="text-[11px] text-slate-400">
                <span className="font-bold text-white">{data.active_policies}</span> active rules
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <TrendingUp size={11} className="text-emerald-400" />
              <span className="text-[11px] text-slate-400">
                <span className="font-bold text-white">{data.total_evaluations.toLocaleString()}</span> total evaluations
              </span>
            </div>
          </div>

          {data.top_policies.map((policy, i) => {
            const maxHits = data.top_policies[0]?.hit_count || 1
            const pct = Math.round((policy.hit_count / maxHits) * 100)
            const color = ACTION_COLOR[policy.action] ?? '#6b7280'
            return (
              <div key={policy.id}>
                <div className="flex items-center justify-between text-[11px] mb-1">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-[10px] font-bold text-slate-600 w-3">{i + 1}</span>
                    <span className="text-slate-300 font-medium truncate max-w-[80px] sm:max-w-[120px]" title={policy.name}>{policy.name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold shrink-0" style={{ background: color + '20', color }}>
                      {policy.action?.replace('_', ' ')}
                    </span>
                  </div>
                  <span className="text-slate-500 shrink-0 ml-1">{policy.hit_count.toLocaleString()}</span>
                </div>
                <div className="h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${pct}%`, backgroundColor: color }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Risk Score Tile (AI-powered, 24h cache) ─────────────────────────────────

interface RiskScoreData {
  score: number
  risk_level: string
  explanation: string
  key_factors: string[]
  evaluated_at: string
  next_evaluation_hours: number
  ai_powered: boolean
}

function RiskScoreTile() {
  const [data, setData] = useState<RiskScoreData | null>(null)
  const [loading, setLoading] = useState(true)
  const [showInfo, setShowInfo] = useState(false)

  useEffect(() => {
    api.get('/api/dashboard/ai-risk-score')
      .then(r => setData(r.data))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const score = data?.score ?? 0
  const level = data?.risk_level ?? 'low'
  // Colour maps to both numeric score AND named risk level (new scoring returns guarded/elevated)
  const color = (level === 'critical' || score >= 80) ? '#e94560'
    : (level === 'high' || score >= 60) ? '#f97316'
    : (level === 'elevated' || score >= 40) ? '#f59e0b'
    : (level === 'guarded' || score >= 20) ? '#eab308'
    : '#22c55e'

  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl p-5 relative">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] text-slate-500 flex items-center gap-1.5">
          <Brain size={11} className="text-[#3b6ef6]" />
          Risk Score
        </span>
        <button
          onClick={() => setShowInfo(v => !v)}
          className="text-slate-600 hover:text-slate-400 transition-colors"
          title="How this score is calculated"
        >
          <Info size={13} />
        </button>
      </div>

      {loading ? (
        <div className="h-12 animate-pulse bg-white/[0.04] rounded" />
      ) : (
        <div>
          <div className="flex items-end gap-2">
            <span className="text-3xl font-bold" style={{ color }}>{score}</span>
            <span className="text-[11px] text-slate-500 mb-1">/100</span>
            <span className="ml-auto text-[10px] font-semibold uppercase px-2 py-1 rounded-full" style={{ background: color + '20', color }}>
              {level}
            </span>
          </div>
          {data?.explanation && !showInfo && (
            <p className="text-[11px] text-slate-500 mt-2 leading-relaxed line-clamp-2">{data.explanation}</p>
          )}
        </div>
      )}

      {/* Info popover */}
      {showInfo && data && (
        <div className="absolute right-0 top-full mt-2 z-20 w-72 bg-[#1a1a20] border border-white/[0.12] rounded-xl p-4 shadow-2xl">
          <p className="text-[11px] font-semibold text-slate-300 mb-2">How this score is calculated</p>
          <p className="text-[11px] text-slate-400 leading-relaxed mb-3">{data.explanation}</p>
          {data.key_factors?.length > 0 && (
            <div>
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wide mb-1.5">Key factors</p>
              <ul className="space-y-1">
                {data.key_factors.map((f, i) => (
                  <li key={i} className="flex items-start gap-1.5 text-[11px] text-slate-400">
                    <span className="text-[#3b6ef6] mt-0.5">·</span> {f}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="text-[10px] text-slate-600 mt-3 pt-2 border-t border-white/[0.06]">
            Reflects <strong>residual risk</strong> after mitigating controls. High threat volume with strong policies scores lower than low volume with no policies. Re-evaluates every 24h.
          </p>
          <button onClick={() => setShowInfo(false)} className="absolute top-2 right-2 text-slate-600 hover:text-slate-400">
            <X size={11} />
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Sync Indicator ──────────────────────────────────────────────────────────

function SyncIndicator({ lastSync, syncing }: { lastSync: Date | null; syncing: boolean }) {
  if (!lastSync) return null
  const timeStr = lastSync.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  return (
    <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
      <RefreshCw size={11} className={syncing ? 'animate-spin text-[#3b6ef6]' : 'text-slate-600'} />
      {syncing ? 'Syncing…' : `Last sync: ${timeStr}`}
    </div>
  )
}

// ─── Main Dashboard Page ──────────────────────────────────────────────────────

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null)
  const [trends, setTrends] = useState<TrendDataPoint[]>([])
  const [threatBreakdown, setThreatBreakdown] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState('')
  const [lastSync, setLastSync] = useState<Date | null>(null)

  const load = useCallback(async (isBackground = false) => {
    if (isBackground) setSyncing(true)
    else setLoading(true)
    try {
      const [s, t] = await Promise.all([
        api.get('/api/dashboard/summary'),
        api.get('/api/dashboard/trends'),
      ])
      setSummary(s.data)
      setTrends(t.data ?? [])
      if (s.data?.threat_type_breakdown) {
        setThreatBreakdown(s.data.threat_type_breakdown)
      }
      setLastSync(new Date())
      if (!isBackground) setError('')
    } catch {
      if (!isBackground) setError('Failed to load dashboard data')
    }
    if (isBackground) setSyncing(false)
    else setLoading(false)
  }, [])

  useEffect(() => { load(false) }, [load])

  useEffect(() => {
    const id = setInterval(() => load(true), SYNC_INTERVAL_MS)
    return () => clearInterval(id)
  }, [load])

  // NOTE: All hooks MUST be called before any conditional return below.
  // Previously these were declared after the `if (error) return ...` early
  // exit, which violated the Rules of Hooks. When a transient API error
  // flipped `error` truthy on first render, the hook count changed between
  // renders and React threw the minified error #300 ("Rendered fewer hooks
  // than expected"), crashing the whole dashboard page.
  const [investigatingCount, setInvestigatingCount] = useState(0)
  useEffect(() => {
    const fetchInv = () => api.get('/api/threats/stats/investigating')
      .then(r => setInvestigatingCount(r.data?.investigating ?? 0)).catch(() => {})
    fetchInv()
    const iv = setInterval(fetchInv, 30000)
    return () => clearInterval(iv)
  }, [])
  const activeThreats = investigatingCount || (summary?.active_threats ?? 0)

  if (error) {
    return (
      <div className="flex items-center justify-center h-64 text-red-400 text-sm">{error}</div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Dashboard</h1>
        <div className="flex items-center gap-3">
          <SyncIndicator lastSync={lastSync} syncing={syncing} />
          <button
            onClick={() => load(true)}
            disabled={syncing}
            className="text-[11px] flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/[0.07] text-slate-400 hover:text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw size={11} className={syncing ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* Metric cards — row 1 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Potential Threats This Week"
          value={loading ? '—' : (summary?.threats_this_week ?? summary?.total_threats_week ?? 0)}
          accent="red"
          icon={<Shield size={18} />}
          loading={loading}
        />
        <MetricCard
          label="Quarantined Today"
          value={loading ? '—' : (summary?.quarantined_today ?? 0)}
          accent="amber"
          icon={<Lock size={18} />}
          loading={loading}
        />
        <MetricCard
          label="Active Potential Threats"
          value={loading ? '—' : activeThreats}
          sublabel="Awaiting analyst review"
          accent="red"
          icon={<AlertTriangle size={18} />}
          loading={loading}
        />
        <MetricCard
          label="Compliance Score"
          value={loading ? '—' : `${summary?.compliance_score ?? 0}%`}
          sublabel="Across all frameworks"
          accent="green"
          icon={<CheckSquare size={18} />}
          loading={loading}
        />
      </div>

      {/* Metric cards — row 2 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          label="Potential Threats This Month"
          value={loading ? '—' : (summary?.total_threats_month ?? 0)}
          sublabel="Last 30 days"
          accent="red"
          icon={<Shield size={18} />}
          loading={loading}
        />
        <MetricCard
          label="Potential Threats Today"
          value={loading ? '—' : (summary?.total_threats_today ?? 0)}
          sublabel="Detected in last 24h"
          accent="amber"
          icon={<Zap size={18} />}
          loading={loading}
        />
        <MetricCard
          label="Top Threat Type"
          value={loading ? '—' : (summary?.top_threat_type ?? 'None')}
          sublabel="Most common this period"
          accent="red"
          icon={<AlertTriangle size={18} />}
          loading={loading}
        />
        {/* Risk Score tile */}
        <div className="lg:col-span-1">
          <RiskScoreTile />
        </div>
      </div>

      {/* Global Threat Intelligence — full width */}
      <ThreatMap />

      {/* Middle row: Email Classification (1/5) | Rule Usage (2/5) | 30-Day Trend (2/5) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="md:col-span-2 lg:col-span-1 min-w-0">
          <ThreatTypeBreakdown data={threatBreakdown} loading={loading} />
        </div>
        <div className="md:col-span-1 lg:col-span-2 min-w-0">
          <RuleUsagePanel />
        </div>
        <div className="md:col-span-1 lg:col-span-2 min-w-0">
          <TrendChart data={trends} loading={loading} />
        </div>
      </div>

      {/* Bottom row: Top Targeted Groups + At-Risk Employees (live) | Threat Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">
        <div className="lg:col-span-2 space-y-4">
          <TopTargetedGroups />
          <AtRiskEmployees standalone={true} />
        </div>
        <div className="lg:col-span-1">
          <ThreatFeed />
        </div>
      </div>
    </div>
  )
}
