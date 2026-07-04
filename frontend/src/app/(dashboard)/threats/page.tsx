'use client'
import { useEffect, useState, useCallback } from 'react'
import ThreatTable from '@/components/threats/ThreatTable'
import BulkActions from '@/components/threats/BulkActions'
import type { Threat, PaginatedResponse } from '@/lib/types'
import api from '@/lib/api'
import Button from '@/components/ui/Button'
import { ChevronLeft, ChevronRight, X, Filter, Search, Calendar, TrendingUp, Zap, Loader2, ClipboardList, CheckCircle, AlertTriangle, Ban, MessageSquare, Shield } from 'lucide-react'
import { clsx } from 'clsx'

// ── Filter Definitions ────────────────────────────────────────────────────────

const SEVERITY_OPTIONS = [
  { value: 'all',      label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high',     label: 'High' },
  { value: 'medium',   label: 'Medium' },
  { value: 'low',      label: 'Low' },
]

const TYPE_OPTIONS = [
  { value: 'all',                   label: 'All Types',           color: 'slate' },
  { value: 'bec',                   label: 'BEC',                 color: 'red',    tip: 'Business Email Compromise' },
  { value: 'vec',                   label: 'VEC',                 color: 'orange', tip: 'Vendor/Supplier Compromise' },
  { value: 'phishing',              label: 'Phishing',            color: 'amber',  tip: 'Credential harvesting / fake login' },
  { value: 'credential_harvesting', label: 'Cred Theft',          color: 'amber',  tip: 'Dedicated credential theft forms' },
  { value: 'malware',               label: 'Malware',             color: 'red',    tip: 'Malicious attachments or links' },
  { value: 'account_takeover',      label: 'ATO',                 color: 'purple', tip: 'Account Takeover indicators' },
  { value: 'impersonation',         label: 'Impersonation',       color: 'blue',   tip: 'Display-name / colleague spoofing' },
  { value: 'gov_impersonation',     label: 'Gov. Impersonation',  color: 'blue',   tip: 'Government entity impersonation' },
  { value: 'fake_invoice',          label: 'Fake Invoice',        color: 'orange', tip: 'Fraudulent invoice / payment request' },
  { value: 'lookalike_domain',      label: 'Lookalike Domain',    color: 'yellow', tip: 'Typosquat / lookalike domain' },
  { value: 'supply_chain',          label: 'Supply Chain',        color: 'teal',   tip: 'Compromised legitimate vendor account' },
  { value: 'social_engineering',    label: 'Social Engineering',  color: 'pink',   tip: 'Broad social engineering' },
  { value: 'spam',                  label: 'Spam',                color: 'slate',  tip: 'Unsolicited bulk email' },
  { value: 'dlp_draft',             label: 'DLP — Draft',          color: 'amber',  tip: 'Sensitive content detected in a draft email' },
]

const STATUS_OPTIONS = [
  { value: 'all',            label: 'All Statuses' },
  { value: 'new',            label: 'New' },
  { value: 'investigating',  label: 'Investigating' },
  { value: 'quarantined',    label: 'Quarantined' },
  { value: 'released',       label: 'Released' },
  { value: 'false_positive', label: 'False Positive' },
]

const DATE_QUICK = [
  { label: '24h',    key: '24h',  ms: 86_400_000 },
  { label: '7 days', key: '7d',   ms: 7 * 86_400_000 },
  { label: '30 days',key: '30d',  ms: 30 * 86_400_000 },
  { label: '90 days',key: '90d',  ms: 90 * 86_400_000 },
]

// ── Colour maps ───────────────────────────────────────────────────────────────
const TYPE_COLOR_MAP: Record<string, string> = {
  red:    'bg-red-900/30 border-red-700/40 text-red-300 hover:bg-red-900/50',
  orange: 'bg-orange-900/30 border-orange-700/40 text-orange-300 hover:bg-orange-900/50',
  amber:  'bg-amber-900/30 border-amber-700/40 text-amber-300 hover:bg-amber-900/50',
  purple: 'bg-purple-900/30 border-purple-700/40 text-purple-300 hover:bg-purple-900/50',
  blue:   'bg-blue-900/30 border-blue-700/40 text-blue-300 hover:bg-blue-900/50',
  yellow: 'bg-yellow-900/20 border-yellow-700/40 text-yellow-300 hover:bg-yellow-900/40',
  teal:   'bg-teal-900/30 border-teal-700/40 text-teal-300 hover:bg-teal-900/50',
  pink:   'bg-pink-900/30 border-pink-700/40 text-pink-300 hover:bg-pink-900/50',
  slate:  'bg-slate-800/40 border-slate-600/40 text-slate-400 hover:bg-slate-800/60',
}
const ACTIVE_TYPE_MAP: Record<string, string> = {
  red:    'bg-red-700/50 border-red-500 text-red-200',
  orange: 'bg-orange-700/50 border-orange-500 text-orange-200',
  amber:  'bg-amber-700/50 border-amber-500 text-amber-200',
  purple: 'bg-purple-700/50 border-purple-500 text-purple-200',
  blue:   'bg-blue-700/50 border-blue-500 text-blue-200',
  yellow: 'bg-yellow-700/40 border-yellow-500 text-yellow-200',
  teal:   'bg-teal-700/50 border-teal-500 text-teal-200',
  pink:   'bg-pink-700/50 border-pink-500 text-pink-200',
  slate:  'bg-slate-700/60 border-slate-400 text-slate-200',
}

function Pill({ label, active, onClick, color = 'slate', tip }: {
  label: string; active: boolean; onClick: (e: React.MouseEvent) => void; color?: string; tip?: string
}) {
  return (
    <button
      title={tip}
      onClick={onClick}
      className={clsx(
        'px-2.5 py-1 rounded-full text-xs font-medium border transition-all whitespace-nowrap',
        active ? (ACTIVE_TYPE_MAP[color] ?? ACTIVE_TYPE_MAP.slate) : (TYPE_COLOR_MAP[color] ?? TYPE_COLOR_MAP.slate),
      )}
    >
      {label}
    </button>
  )
}

/**
 * FilterRow — supports both single-select and multi-select.
 * Hold Cmd (Mac) or Ctrl (Windows/Linux) while clicking to add/remove a value
 * without deselecting others. Single click without modifier replaces selection.
 */
function FilterRow<T extends string>({
  label, options, value, onChange, colorKey, multiValues, onMultiChange,
}: {
  label: string
  options: { value: T; label: string; color?: string; tip?: string }[]
  value: T
  onChange: (v: T) => void
  colorKey?: 'color'
  multiValues?: T[]
  onMultiChange?: (vs: T[]) => void
}) {
  const isMultiMode = multiValues !== undefined && onMultiChange !== undefined
  return (
    <div className="flex items-start gap-3">
      <span className="text-[11px] text-slate-500 font-medium uppercase tracking-wide mt-1.5 w-16 flex-shrink-0">{label}</span>
      <div className="flex flex-wrap gap-1.5">
        {options.map(opt => {
          const isActive = isMultiMode
            ? (multiValues!.includes(opt.value) || (multiValues!.length === 0 && opt.value === 'all'))
            : value === opt.value
          return (
            <Pill
              key={opt.value}
              label={opt.label}
              active={isActive}
              onClick={(e: React.MouseEvent) => {
                if (isMultiMode && onMultiChange) {
                  if (e.metaKey || e.ctrlKey) {
                    // Toggle this value in multi-select
                    if (opt.value === 'all') {
                      onMultiChange([])
                    } else {
                      const next = multiValues!.includes(opt.value)
                        ? multiValues!.filter(v => v !== opt.value)
                        : [...multiValues!.filter(v => v !== 'all'), opt.value]
                      onMultiChange(next)
                    }
                  } else {
                    // Normal click = single select (replaces)
                    onMultiChange(opt.value === 'all' ? [] : [opt.value])
                  }
                } else {
                  onChange(opt.value)
                }
              }}
              color={colorKey ? (opt as any)[colorKey] : 'slate'}
              tip={isMultiMode ? ((opt as any).tip ? `${(opt as any).tip} — Cmd/Ctrl+click to multi-select` : 'Cmd/Ctrl+click to multi-select') : (opt as any).tip}
            />
          )
        })}
        {isMultiMode && multiValues!.length > 1 && (
          <span className="text-[10px] text-slate-600 mt-1 self-center">{multiValues!.length} selected</span>
        )}
      </div>
    </div>
  )
}

const inputCls = 'w-full px-3 py-2 rounded-lg bg-[#0d1b2a] border border-[#0f3460]/60 text-slate-200 text-sm placeholder-slate-600 focus:outline-none focus:border-[#e94560]/50 transition-colors'

// ── Page ──────────────────────────────────────────────────────────────────────
export default function ThreatsPage() {
  const [threats, setThreats] = useState<Threat[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [selected, setSelected] = useState<string[]>([])
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [autoTriageOn, setAutoTriageOn] = useState(false)
  const [autoTriageRunning, setAutoTriageRunning] = useState(false)
  const [autoTriageResult, setAutoTriageResult] = useState<string | null>(null)
  const [autoTriageStatus, setAutoTriageStatus] = useState<{ last_run?: number; last_processed?: number; running?: boolean } | null>(null)
  const [showAudit, setShowAudit] = useState(false)
  const [auditItems, setAuditItems] = useState<any[]>([])
  const [auditLoading, setAuditLoading] = useState(false)
  const [showRunNowModal, setShowRunNowModal] = useState(false)

  // System health
  const [systemHealth, setSystemHealth] = useState<{
    auto_triage_enabled: boolean
    recent_threats_24h: number
    deepseek_reachable: boolean
    dlp_active: boolean
    status: string
  } | null>(null)

  useEffect(() => {
    api.get('/api/threats/system-health')
      .then(r => setSystemHealth(r.data))
      .catch(() => {})
  }, [])

  const fetchAudit = async () => {
    setAuditLoading(true)
    try {
      const r = await api.get('/api/threats/auto-triage/audit?limit=500')
      setAuditItems(r.data?.items ?? [])
    } catch { /* silent */ }
    setAuditLoading(false)
  }

  const openAudit = () => {
    setShowAudit(true)
    fetchAudit()
  }

  // Core filters
  const [filters, setFilters] = useState({
    severity: 'all',
    type: 'all',
    status: 'all',
  })
  const [multiTypes, setMultiTypes] = useState<string[]>([])

  // Advanced filters (mirrors message trace)
  const [sender, setSender] = useState('')
  const [recipient, setRecipient] = useState('')
  const [keyword, setKeyword] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [minScore, setMinScore] = useState('')
  const [maxScore, setMaxScore] = useState('')
  const [activeDateQuick, setActiveDateQuick] = useState('')

  const hasActiveFilters =
    filters.severity !== 'all' || filters.type !== 'all' || filters.status !== 'all' ||
    multiTypes.length > 0 ||
    sender || recipient || keyword || dateFrom || dateTo || minScore || maxScore

  const clearFilters = () => {
    setFilters({ severity: 'all', type: 'all', status: 'all' })
    setMultiTypes([])
    setSender(''); setRecipient(''); setKeyword('')
    setDateFrom(''); setDateTo(''); setMinScore(''); setMaxScore('')
    setActiveDateQuick('')
    setPage(1)
  }

  const fetchAutoTriageStatus = async () => {
    try {
      const r = await api.get('/api/threats/auto-triage/status')
      setAutoTriageOn(!!r.data?.enabled)
      setAutoTriageStatus({
        last_run: r.data?.last_run,
        last_processed: r.data?.last_processed,
        running: r.data?.running,
      })
    } catch {
      // non-fatal
    }
  }

  const toggleAutoTriage = async (newEnabled: boolean) => {
    setAutoTriageOn(newEnabled)
    try {
      await api.post('/api/threats/auto-triage/toggle', { enabled: newEnabled })
      if (newEnabled) {
        setAutoTriageResult('Himaya Analysis started — investigating threats every 2 min')
      } else {
        setAutoTriageResult('Agent stopped')
        setAutoTriageStatus(null)
      }
    } catch {
      setAutoTriageOn(!newEnabled) // revert on error
      setAutoTriageResult('Toggle failed')
    }
  }

  const runAutoTriage = async () => {
    setAutoTriageRunning(true)
    setAutoTriageResult(null)
    try {
      const r = await api.post('/api/threats/auto-triage')
      setAutoTriageResult(r.data?.message ?? 'Auto-triage complete')
      load()
    } catch {
      setAutoTriageResult('Auto-triage failed')
    }
    setAutoTriageRunning(false)
  }

  // On mount: fetch auto-triage status; poll every 30s when agent is on
  useEffect(() => {
    fetchAutoTriageStatus()
  }, [])

  useEffect(() => {
    if (!autoTriageOn) return
    const interval = setInterval(fetchAutoTriageStatus, 30_000)
    return () => clearInterval(interval)
  }, [autoTriageOn])

  const setFilter = <K extends keyof typeof filters>(k: K, v: string) => {
    setFilters(f => ({ ...f, [k]: v }))
    setPage(1)
  }

  const applyDateQuick = (key: string, ms: number) => {
    const from = new Date(Date.now() - ms)
    setDateFrom(from.toISOString().slice(0, 16))
    setDateTo('')
    setActiveDateQuick(key)
    setPage(1)
  }

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const params: Record<string, string | number> = { page, size: 20 }
      if (filters.severity !== 'all') params.severity = filters.severity
      if (multiTypes.length > 0)      params.threat_type = multiTypes.map(t => t.toUpperCase()).join(',')
      else if (filters.type !== 'all')  params.threat_type = filters.type.toUpperCase()
      if (filters.status !== 'all')   params.status = filters.status
      if (sender)    params.sender = sender
      if (recipient) params.recipient = recipient
      if (keyword)   params.keyword = keyword
      if (dateFrom)  params.date_from = new Date(dateFrom).toISOString()
      if (dateTo)    params.date_to = new Date(dateTo).toISOString()
      if (minScore)  params.min_score = Number(minScore)
      if (maxScore)  params.max_score = Number(maxScore)
      const res = await api.get<PaginatedResponse<Threat>>('/api/threats', { params })
      setThreats(res.data.items ?? [])
      setTotal(res.data.total ?? 0)
    } catch {
      setError('Failed to load threats')
    }
    setLoading(false)
  }, [page, filters, sender, recipient, keyword, dateFrom, dateTo, minScore, maxScore])

  useEffect(() => { load() }, [load])

  const selectAll = () => {
    setSelected(selected.length === threats.length ? [] : threats.map(t => t.id))
  }

  const bulkAction = async (action: string) => {
    try {
      await Promise.all(selected.map(id => api.post(`/api/threats/${id}/${action}`)))
      setSelected([])
      load()
    } catch {}
  }

  const totalPages = Math.ceil(total / 20)

  return (
    <>
    <div className="space-y-5">
      {/* System Health Banner */}
      {systemHealth && (
        <div className="flex flex-wrap items-center gap-3 bg-[#0d1b2e] border border-[#1a2d5a]/40 rounded-xl px-4 py-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide mr-1">System Health</span>
          <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-medium ${
            systemHealth.deepseek_reachable
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
              : 'bg-amber-500/10 border-amber-500/20 text-amber-400'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              systemHealth.deepseek_reachable ? 'bg-emerald-400' : 'bg-amber-400'
            }`} />
            AI Engine: {systemHealth.deepseek_reachable ? 'Online' : 'Fallback (Claude)'}
          </span>
          <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-medium ${
            systemHealth.auto_triage_enabled
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
              : 'bg-slate-500/10 border-slate-500/20 text-slate-400'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              systemHealth.auto_triage_enabled ? 'bg-emerald-400' : 'bg-slate-400'
            }`} />
            Auto Triage: {systemHealth.auto_triage_enabled ? 'On' : 'Off'}
          </span>
          <span className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-medium ${
            systemHealth.dlp_active
              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
              : 'bg-slate-500/10 border-slate-500/20 text-slate-400'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              systemHealth.dlp_active ? 'bg-emerald-400' : 'bg-slate-400'
            }`} />
            DLP: {systemHealth.dlp_active ? 'Active' : 'Idle'}
          </span>
          <span className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border font-medium bg-blue-500/10 border-blue-500/20 text-blue-400">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
            Threats (24h): {systemHealth.recent_threats_24h}
          </span>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Threat Queue</h1>
        </div>
        {/* Auto-Triage Toggle */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Auto Triage</span>
            <button
              onClick={() => toggleAutoTriage(!autoTriageOn)}
              className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors ${autoTriageOn ? 'bg-green-500' : 'bg-slate-700'}`}
            >
              <span className={`pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform ${autoTriageOn ? 'translate-x-4' : 'translate-x-0'}`} />
            </button>
            {autoTriageOn && (
              <span className="flex items-center gap-1 text-[11px] text-green-400 font-medium">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
                Agent Active
              </span>
            )}
          </div>
          {autoTriageOn && (
            <button
              onClick={() => setShowRunNowModal(true)}
              disabled={autoTriageRunning}
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg bg-green-500/10 hover:bg-green-500/20 text-green-400 border border-green-500/30 transition-colors disabled:opacity-50"
            >
              {autoTriageRunning ? <Loader2 size={12} className="animate-spin" /> : <Zap size={12} />}
              {autoTriageRunning ? 'Running…' : 'Run Now'}
            </button>
          )}
          {autoTriageStatus?.last_run && autoTriageOn && (
            <span className="text-[11px] text-slate-500">
              Last: {new Date(autoTriageStatus.last_run * 1000).toLocaleTimeString()}
              {autoTriageStatus.last_processed !== undefined && ` · ${autoTriageStatus.last_processed} processed`}
            </span>
          )}
          {autoTriageResult && (
            <span className="text-[11px] text-slate-400 max-w-[200px] truncate">{autoTriageResult}</span>
          )}
          {/* Audit trail button */}
          <button
            onClick={openAudit}
            title="View auto-triage audit trail"
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg bg-[#0f3460]/40 hover:bg-[#0f3460]/70 text-slate-400 hover:text-slate-200 border border-[#0f3460]/50 transition-colors"
          >
            <ClipboardList size={12} />
            Audit Trail
          </button>
        </div>
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white border border-slate-700 hover:border-slate-500 px-2.5 py-1.5 rounded-lg transition-colors"
          >
            <X size={12} /> Clear all filters
          </button>
        )}
      </div>

      {/* Filter Panel */}
      <div className="bg-[#0d1b2e] border border-[#1a2d5a]/40 rounded-xl px-4 py-3 space-y-3">
        {/* Type pills */}
        <FilterRow label="Type" options={TYPE_OPTIONS} value={filters.type} onChange={v => { setMultiTypes([]); setFilter('type', v) }} colorKey="color"
          multiValues={multiTypes as any}
          onMultiChange={(vs: any) => { setMultiTypes(vs); setFilters(f => ({...f, type: 'all'})); setPage(1) }}
        />
        <div className="border-t border-[#1a2d5a]/30" />
        {/* Severity + Status */}
        <div className="flex flex-wrap gap-4">
          <FilterRow label="Severity" options={SEVERITY_OPTIONS} value={filters.severity} onChange={v => setFilter('severity', v)} />
          <FilterRow label="Status" options={STATUS_OPTIONS} value={filters.status} onChange={v => setFilter('status', v)} />
        </div>

        {/* Date quick picks */}
        <div className="border-t border-[#1a2d5a]/30 pt-2 flex items-center gap-2 flex-wrap">
          <span className="text-[11px] text-slate-500 font-medium uppercase tracking-wide w-16 flex-shrink-0">
            <Calendar size={11} className="inline mr-1" />Date
          </span>
          {DATE_QUICK.map(q => (
            <button
              key={q.key}
              onClick={() => applyDateQuick(q.key, q.ms)}
              className={clsx(
                'px-2.5 py-1 rounded-full text-xs font-medium border transition-all',
                activeDateQuick === q.key
                  ? 'bg-[#0f3460] border-[#3b6ef6] text-blue-300'
                  : 'bg-slate-800/40 border-slate-600/40 text-slate-400 hover:bg-slate-800/60'
              )}
            >
              Last {q.label}
            </button>
          ))}

          {/* Advanced toggle */}
          <button
            onClick={() => setShowAdvanced(v => !v)}
            className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300 ml-auto transition-colors"
          >
            <Filter size={11} /> {showAdvanced ? 'Hide' : 'More'} filters
          </button>
        </div>

        {/* Advanced filters — mirrors Message Trace */}
        {showAdvanced && (
          <div className="border-t border-[#1a2d5a]/30 pt-3 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] text-slate-500 font-medium uppercase tracking-wide mb-1 block">Sender</label>
              <input
                className={inputCls}
                placeholder="sender@domain.com"
                value={sender}
                onChange={e => { setSender(e.target.value); setPage(1) }}
              />
            </div>
            <div>
              <label className="text-[11px] text-slate-500 font-medium uppercase tracking-wide mb-1 block">Recipient</label>
              <input
                className={inputCls}
                placeholder="recipient@yourcompany.com"
                value={recipient}
                onChange={e => { setRecipient(e.target.value); setPage(1) }}
              />
            </div>
            <div>
              <label className="text-[11px] text-slate-500 font-medium uppercase tracking-wide mb-1 block">Keyword</label>
              <input
                className={inputCls}
                placeholder="Search sender, recipient, subject..."
                value={keyword}
                onChange={e => { setKeyword(e.target.value); setPage(1) }}
              />
            </div>
            <div>
              <label className="text-[11px] text-slate-500 font-medium uppercase tracking-wide mb-1 block">Date From</label>
              <input
                type="datetime-local"
                className={inputCls}
                value={dateFrom}
                onChange={e => { setDateFrom(e.target.value); setActiveDateQuick(''); setPage(1) }}
              />
            </div>
            <div>
              <label className="text-[11px] text-slate-500 font-medium uppercase tracking-wide mb-1 block">Date To</label>
              <input
                type="datetime-local"
                className={inputCls}
                value={dateTo}
                onChange={e => { setDateTo(e.target.value); setActiveDateQuick(''); setPage(1) }}
              />
            </div>
            <div className="flex gap-2">
              <div className="flex-1">
                <label className="text-[11px] text-slate-500 font-medium uppercase tracking-wide mb-1 block">
                  <TrendingUp size={10} className="inline mr-1" />Min Score
                </label>
                <input
                  type="number" min={0} max={100}
                  className={inputCls}
                  placeholder="0"
                  value={minScore}
                  onChange={e => { setMinScore(e.target.value); setPage(1) }}
                />
              </div>
              <div className="flex-1">
                <label className="text-[11px] text-slate-500 font-medium uppercase tracking-wide mb-1 block">Max Score</label>
                <input
                  type="number" min={0} max={100}
                  className={inputCls}
                  placeholder="100"
                  value={maxScore}
                  onChange={e => { setMaxScore(e.target.value); setPage(1) }}
                />
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bulk actions */}
      <BulkActions
        count={selected.length}
        onQuarantine={() => bulkAction('quarantine')}
        onRelease={() => bulkAction('release')}
        onFalsePositive={() => bulkAction('false-positive')}
        onClear={() => setSelected([])}
      />

      {error ? (
        <div className="text-center text-red-400 py-10 text-sm">{error}</div>
      ) : (
        <div className="bg-[#16213e] border border-[#0f3460]/50 rounded-xl overflow-hidden">
          <ThreatTable
            threats={threats}
            selected={selected}
            onSelect={(id) => setSelected(prev =>
              prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
            )}
            onSelectAll={selectAll}
            loading={loading}
          />

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-[#0f3460]/30">
              <span className="text-xs text-slate-500">
                Page {page} of {totalPages} · {total.toLocaleString()} total
              </span>
              <div className="flex gap-2">
                <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
                  <ChevronLeft size={14} />
                </Button>
                <Button size="sm" variant="ghost" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>
                  <ChevronRight size={14} />
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>

    {/* ── Run Now Confirmation Modal ─────────────────────────────────────── */}
    {showRunNowModal && (
      <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
        <div className="bg-[#0d1b2a] border border-[#0f3460] rounded-2xl p-6 w-full max-w-md shadow-2xl">
          <h2 className="text-white font-semibold text-base mb-2">Run Auto-Triage Now?</h2>
          <p className="text-slate-400 text-sm leading-relaxed mb-6">
            This will immediately analyse all unresolved threats in the queue and apply actions (quarantine, flag, dismiss). This cannot be undone.
          </p>
          <div className="flex justify-end gap-3">
            <button
              onClick={() => setShowRunNowModal(false)}
              className="px-4 py-2 text-sm font-medium rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={() => { setShowRunNowModal(false); runAutoTriage() }}
              className="px-4 py-2 text-sm font-medium rounded-lg bg-green-600 hover:bg-green-500 text-white transition-colors"
            >
              Run Now
            </button>
          </div>
        </div>
      </div>
    )}

    {/* ── Auto-Triage Audit Trail Slide-Over ────────────────────────────────── */}
    {showAudit && (
      <>
        <div className="fixed inset-0 bg-black/50 z-40" onClick={() => setShowAudit(false)} />
        <div className="fixed right-0 top-0 bottom-0 w-[560px] max-w-full bg-[#0d1b2e] border-l border-[#1a2744] z-50 flex flex-col overflow-hidden">

          {/* Header */}
          <div className="flex items-center justify-between px-5 py-4 border-b border-[#1a2744] flex-shrink-0">
            <div className="flex items-center gap-2">
              <ClipboardList size={16} className="text-[#3b6ef6]" />
              <span className="font-semibold text-white text-sm">Himaya Analysis — Audit Trail</span>
              {auditItems.length > 0 && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-[#3b6ef6]/20 text-[#3b6ef6] border border-[#3b6ef6]/30">
                  {auditItems.length}{auditItems.length >= 500 ? '+' : ''}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <button onClick={fetchAudit} disabled={auditLoading}
                className="text-[11px] px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white transition-colors disabled:opacity-50">
                {auditLoading ? 'Refreshing...' : 'Refresh'}
              </button>
              <button onClick={() => setShowAudit(false)} className="text-slate-400 hover:text-white transition-colors">
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto">
            {auditLoading && auditItems.length === 0 ? (
              <div className="flex items-center justify-center py-16 text-slate-500 text-sm gap-2">
                <Loader2 size={16} className="animate-spin" /> Loading audit trail...
              </div>
            ) : auditItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 gap-3 text-center px-8">
                <ClipboardList size={32} className="text-slate-700" />
                <p className="text-slate-400 text-sm font-medium">No Himaya Analysis records yet</p>
                <p className="text-slate-500 text-xs">Enable the agent and Himaya Analysis will start investigating threats. Results appear here.</p>
              </div>
            ) : (
              <div className="divide-y divide-[#1a2744]/50">
                {auditItems.map((item: any) => {
                  const VERDICT_CFG: Record<string, { color: string; bg: string; label: string }> = {
                    QUARANTINE:   { color: '#ef4444', bg: 'rgba(239,68,68,0.10)',  label: 'Quarantined' },
                    MARK_AS_SPAM: { color: '#f59e0b', bg: 'rgba(245,158,11,0.10)', label: 'Marked Spam' },
                    ESCALATE:     { color: '#f97316', bg: 'rgba(249,115,22,0.10)', label: 'Escalated' },
                    DISMISS:      { color: '#22c55e', bg: 'rgba(34,197,94,0.10)',  label: 'Dismissed' },
                  }
                  const vcfg = VERDICT_CFG[item.verdict as string] ?? { color: '#6b7280', bg: 'rgba(107,114,128,0.10)', label: item.verdict ?? 'Unknown' }
                  const conf = item.confidence != null ? Math.round(item.confidence * 100) : null
                  const triagedAt = item.triaged_at ? new Date(item.triaged_at).toLocaleString() : null

                  return (
                    <div key={item.threat_id} className="px-5 py-4 hover:bg-white/[0.02] transition-colors">
                      {/* Verdict + sender */}
                      <div className="flex items-start justify-between gap-3 mb-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-bold flex-shrink-0"
                            style={{ background: vcfg.bg, color: vcfg.color }}>
                            {vcfg.label}
                          </span>
                          <span className="text-[12px] text-slate-300 font-medium truncate">
                            {item.sender_domain ?? item.sender ?? 'Unknown sender'}
                          </span>
                        </div>
                        {conf != null && (
                          <span className="flex-shrink-0 text-[11px] font-bold" style={{ color: vcfg.color }}>
                            {conf}%
                          </span>
                        )}
                      </div>

                      {/* Subject */}
                      {item.subject && (
                        <p className="text-[11px] text-slate-400 mb-2 truncate">Subject: {item.subject}</p>
                      )}

                      {/* Reasoning */}
                      {item.reasoning && (
                        <div className="bg-[#0a1628] rounded-lg px-3 py-2 mb-2 border border-[#1a2744]/50">
                          <p className="text-[11px] text-slate-300 leading-relaxed">{item.reasoning}</p>
                        </div>
                      )}

                      {/* Key evidence */}
                      {Array.isArray(item.key_evidence) && item.key_evidence.length > 0 && (
                        <div className="space-y-1 mb-2">
                          {item.key_evidence.map((ev: string, i: number) => (
                            <div key={i} className="flex items-start gap-1.5 text-[10px] text-slate-400">
                              <span className="text-[#3b6ef6] mt-0.5 flex-shrink-0">·</span>
                              <span>{ev}</span>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Signal tags */}
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {item.vt_domain_malicious > 0 && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                            VT: {item.vt_domain_malicious} engines flagged domain
                          </span>
                        )}
                        {item.vt_url_malicious > 0 && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                            VT: {item.vt_url_malicious} engines flagged URL
                          </span>
                        )}
                        {Array.isArray(item.feed_matches) && item.feed_matches.map((f: string) => (
                          <span key={f} className="text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                            IOC: {f}
                          </span>
                        ))}
                        {item.graph_prior_emails > 0 && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                            {item.graph_prior_emails} prior emails from sender
                          </span>
                        )}
                        {item.attachment_risk && item.attachment_risk !== 'none' && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                            Attachment: {item.attachment_risk}
                          </span>
                        )}
                      </div>

                      {/* Footer */}
                      <div className="flex items-center justify-between mt-2">
                        <div className="flex items-center gap-2">
                          {item.threat_type && item.threat_type !== 'CLEAN' && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-400">{item.threat_type}</span>
                          )}
                          {item.original_risk_score != null && (
                            <span className="text-[10px] text-slate-500">Risk {item.original_risk_score}/100</span>
                          )}
                        </div>
                        <span className="text-[10px] text-slate-600">{triagedAt ?? '—'}</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>
      </>
    )}
    </>
  )
}