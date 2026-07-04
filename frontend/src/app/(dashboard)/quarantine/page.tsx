'use client'
import { useEffect, useState, useCallback, useRef } from 'react'
import {
  ShieldAlert, RefreshCw, X, AlertTriangle, CheckCircle,
  Ban, Flag, ChevronLeft, ChevronRight, Shield
} from 'lucide-react'
import api from '@/lib/api'
import SandboxPanel from '@/components/threats/SandboxPanel'
import { toast } from '@/components/ui/Toast'

// ─── Types ──────────────────────────────────────────────────────────────────

interface QuarantineItem {
  id: string
  sender: string
  sender_domain: string
  recipient_email: string
  threat_type: string
  risk_score: number
  graph_score: number
  content_score: number
  reputation_score: number
  status: string
  action_taken: string
  ai_explanation_en: string
  threat_indicators: string[] | null
  sama_controls: string[] | null
  nca_controls: string[] | null
  false_positive: boolean
  detected_at: string
  resolved_at: string | null
}

interface Stats {
  total_quarantined: number
  released_today: number
  false_positives: number
  high_risk_blocked: number
  by_threat_type: Record<string, number>
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const THREAT_COLORS: Record<string, string> = {
  phishing:      'bg-orange-500/20 text-orange-400 border-orange-500/30',
  bec:           'bg-red-500/20 text-red-400 border-red-500/30',
  malware:       'bg-purple-500/20 text-purple-400 border-purple-500/30',
  spam:          'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  impersonation: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
}

const STATUS_COLORS: Record<string, string> = {
  quarantined:   'bg-orange-500/20 text-orange-300',
  resolved:      'bg-green-500/20 text-green-300',
  false_positive:'bg-slate-500/20 text-slate-300',
  new:           'bg-blue-500/20 text-blue-300',
  open:          'bg-blue-500/20 text-blue-300',
}

const STATUS_LABELS: Record<string, string> = {
  quarantined:   'Quarantined',
  resolved:      'Resolved',
  false_positive:'False Positive',
  new:           'Pending',
  open:          'Open',
}

function threatBadge(type: string) {
  const cls = THREAT_COLORS[type] ?? 'bg-slate-500/20 text-slate-400 border-slate-500/30'
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium border ${cls}`}>
      {type?.toUpperCase() ?? 'UNKNOWN'}
    </span>
  )
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#eab308' : '#22c55e'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs tabular-nums" style={{ color }}>{score}</span>
    </div>
  )
}

function ScoreRow({ label, value }: { label: string; value: number }) {
  const color = value >= 80 ? '#ef4444' : value >= 60 ? '#f97316' : value >= 40 ? '#eab308' : '#22c55e'
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-xs text-[#a1a1aa] w-28">{label}</span>
      <div className="flex-1 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${value}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs tabular-nums w-8 text-right" style={{ color }}>{value}</span>
    </div>
  )
}

function fmt(iso: string | null) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) +
    ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
}

// ─── Stat Card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, accent }: {
  label: string; value: number; icon: React.ElementType; accent: string
}) {
  return (
    <div className="bg-[#0d1b2e] border border-[#1a2744] rounded-xl p-4 flex items-center gap-4">
      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${accent}`}>
        <Icon size={18} />
      </div>
      <div>
        <div className="text-xl font-bold text-white tabular-nums">{value}</div>
        <div className="text-xs text-[#a1a1aa]">{label}</div>
      </div>
    </div>
  )
}

// ─── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({
  item, onClose, onAction,
}: {
  item: QuarantineItem
  onClose: () => void
  onAction: (id: string, action: 'release' | 'block-permanently' | 'mark-as-spam' | 'report-fp') => Promise<void>
}) {
  // sandboxOpen state removed — using SandboxPanel component directly
  const [acting, setActing] = useState(false)
  const [actionTaken, setActionTaken] = useState<string | null>(null)

  async function act(action: 'release' | 'block-permanently' | 'mark-as-spam' | 'report-fp') {
    if (actionTaken) return  // already acted — prevent double-fire
    setActing(true)
    setActionTaken(action)
    await onAction(item.id, action)
    setActing(false)
  }

  return (
    <>
      {/* Overlay */}
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />

      {/* Drawer */}
      <div className="fixed right-0 top-0 bottom-0 w-[480px] max-w-full bg-[#0d1b2e] border-l border-[#1a2744] z-50 flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1a2744] flex-shrink-0">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-[#3b6ef6]" />
            <span className="font-semibold text-white text-sm">Quarantine Detail</span>
          </div>
          <button onClick={onClose} className="text-[#71717a] hover:text-white transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
          {/* Meta */}
          <div className="space-y-2">
            <h3 className="text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Email Metadata</h3>
            <div className="bg-[#0a0f1e] rounded-lg p-3 space-y-2 text-xs">
              {[
                ['Sender', item.sender],
                ['Domain', item.sender_domain],
                ['Recipient', item.recipient_email],
                ['Detected', fmt(item.detected_at)],
                ['Action', item.action_taken],
                ['Status', item.status],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-2">
                  <span className="text-[#71717a] w-20 flex-shrink-0">{k}</span>
                  <span className="text-[#e4e4e7] text-right break-all">{v || '—'}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Threat type + risk */}
          <div className="flex items-center gap-3">
            {threatBadge(item.threat_type)}
            <RiskBar score={item.risk_score} />
          </div>

          {/* Score Breakdown */}
          <div className="space-y-2">
            <h3 className="text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Score Breakdown</h3>
            <div className="bg-[#0a0f1e] rounded-lg p-3 space-y-2.5">
              <ScoreRow label="Graph Score" value={item.graph_score ?? 0} />
              <ScoreRow label="Content Score" value={item.content_score ?? 0} />
              <ScoreRow label="Reputation Score" value={item.reputation_score ?? 0} />
              <ScoreRow label="Overall Risk" value={item.risk_score ?? 0} />
            </div>
          </div>

          {/* AI Explanation */}
          {item.ai_explanation_en && (
            <div className="space-y-2">
              <h3 className="text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">AI Analysis</h3>
              <div className="bg-[#0a0f1e] rounded-lg p-3 text-xs text-[#a1a1aa] leading-relaxed">
                {item.ai_explanation_en}
              </div>
            </div>
          )}

          {/* Threat Indicators */}
          {item.threat_indicators && item.threat_indicators.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Threat Indicators</h3>
              <div className="flex flex-wrap gap-1.5">
                {item.threat_indicators.map((ind, i) => (
                  <span key={i} className="px-2 py-1 text-xs bg-red-500/10 text-red-400 border border-red-500/20 rounded-md">
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* SAMA/NCA Controls */}
          {((item.sama_controls && item.sama_controls.length > 0) || (item.nca_controls && item.nca_controls.length > 0)) && (
            <div className="space-y-2">
              <h3 className="text-xs font-medium text-[#a1a1aa] uppercase tracking-wider">Regulatory Controls</h3>
              <div className="bg-[#0a0f1e] rounded-lg p-3 space-y-2 text-xs">
                {item.sama_controls && item.sama_controls.length > 0 && (
                  <div>
                    <span className="text-[#71717a]">SAMA: </span>
                    <span className="text-[#e4e4e7]">{item.sama_controls.join(', ')}</span>
                  </div>
                )}
                {item.nca_controls && item.nca_controls.length > 0 && (
                  <div>
                    <span className="text-[#71717a]">NCA: </span>
                    <span className="text-[#e4e4e7]">{item.nca_controls.join(', ')}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Sandbox */}
          <div className="mt-2">
            <SandboxPanel threatId={item.id} />
          </div>
        </div>

        {/* Actions Footer */}
        <div className="px-5 py-4 border-t border-[#1a2744] flex gap-2 flex-shrink-0 flex-wrap">
          {([
            { action: 'release' as const,           label: 'Release',       color: 'green',  title: '' },
            { action: 'block-permanently' as const,  label: 'Block → Trash', color: 'red',    title: 'Move to Gmail Trash permanently' },
            { action: 'mark-as-spam' as const,       label: 'Spam',          color: 'yellow', title: 'Move to Gmail Spam folder' },
            { action: 'report-fp' as const,          label: 'False Pos.',    color: 'slate',  title: 'Mark as false positive — tunes future analysis' },
          ] as const).map(({ action, label, color, title }) => {
            const isChosen = actionTaken === action
            const isDisabled = acting || (actionTaken !== null && !isChosen)
            return (
              <button
                key={action}
                disabled={isDisabled}
                onClick={() => act(action)}
                title={title}
                className={[
                  'flex-1 py-2 rounded-lg text-sm font-medium transition-colors',
                  color === 'green'  ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30'   : '',
                  color === 'red'    ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'         : '',
                  color === 'yellow' ? 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30' : '',
                  color === 'slate'  ? 'bg-slate-500/20 text-slate-400 hover:bg-slate-500/30'   : '',
                  isChosen ? 'ring-1 ring-white/30' : '',
                  isDisabled && !isChosen ? 'opacity-30 cursor-not-allowed' : '',
                ].join(' ')}
              >
                {acting && isChosen ? '...' : label}
              </button>
            )
          })}
        </div>
      </div>


    </>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const THREAT_TYPES = [
  'all',
  'phishing',
  'bec',
  'malware',
  'spam',
  'impersonation',
  'social_engineering',
  'credential_harvesting',
  'executive_impersonation',
  'ransomware',
  'data_exfiltration',
  'invoice_fraud',
  'suspicious',
  'unknown',
]

export default function QuarantinePage() {
  const [items, setItems] = useState<QuarantineItem[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<QuarantineItem | null>(null)
  const [filters, setFilters] = useState({
    sender: '', recipient: '', date_from: '', date_to: '', threat_type: 'all', status: 'unresolved'
  })
  const intervalRef = useRef<NodeJS.Timeout | null>(null)

  const loadStats = useCallback(async () => {
    try {
      const res = await api.get<Stats>('/api/quarantine/stats')
      setStats(res.data)
    } catch {}
  }, [])

  const loadItems = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string | number> = { page, page_size: 20 }
      if (filters.sender) params.sender = filters.sender
      if (filters.recipient) params.recipient = filters.recipient
      if (filters.date_from) params.date_from = filters.date_from + 'T00:00:00'
      if (filters.date_to) params.date_to = filters.date_to + 'T23:59:59'
      if (filters.threat_type !== 'all') params.threat_type = filters.threat_type
      if (filters.status && filters.status !== 'all') params.status = filters.status
      const res = await api.get('/api/quarantine', { params })
      setItems(res.data.items ?? [])
      setTotal(res.data.total ?? 0)
    } catch {}
    setLoading(false)
  }, [page, filters])

  const refresh = useCallback(() => {
    loadItems()
    loadStats()
  }, [loadItems, loadStats])

  useEffect(() => {
    refresh()
    intervalRef.current = setInterval(refresh, 30000)
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [refresh])

  const ACTION_LABELS: Record<string, string> = {
    'release': 'Email released to inbox successfully',
    'block-permanently': 'Email blocked and moved to trash',
    'mark-as-spam': 'Email marked as spam',
    'report-fp': 'Marked as false positive — analysis will be improved',
  }

  async function handleAction(id: string, action: 'release' | 'block-permanently' | 'mark-as-spam' | 'report-fp') {
    // Optimistically remove from UI immediately for better UX
    setItems(prev => prev.filter(item => item.id !== id))
    setTotal(prev => Math.max(0, prev - 1))
    if (selected?.id === id) setSelected(null)
    try {
      const r = await api.post(`/api/quarantine/${id}/${action}`)
      if (r.data?.gmail_moved === false && action !== 'report-fp') {
        console.warn(`Action ${action} recorded but Gmail physical move failed — DWD may need configuration`)
      }
      toast.success(ACTION_LABELS[action] ?? 'Action completed successfully', 5000)
      // Background refresh to sync server state
      loadStats()
    } catch (e: any) {
      const msg = e?.response?.data?.detail ?? `Failed to ${action}`
      toast.error(msg, 6000)
      // Restore by reloading
      refresh()
    }
  }

  const totalPages = Math.ceil(total / 20)

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-semibold text-[var(--foreground)]">
            Quarantine
          </h1>

        </div>
        <button
          onClick={refresh}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-[#a1a1aa] hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg transition-colors"
        >
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <StatCard label="Total Quarantined" value={stats.total_quarantined} icon={ShieldAlert} accent="bg-[#3b6ef6]/20 text-[#3b6ef6]" />
          <StatCard label="Released Today" value={stats.released_today} icon={CheckCircle} accent="bg-green-500/20 text-green-400" />
          <StatCard label="False Positives" value={stats.false_positives} icon={Flag} accent="bg-slate-500/20 text-slate-400" />
          <StatCard label="High-Risk Blocked" value={stats.high_risk_blocked} icon={Ban} accent="bg-red-500/20 text-red-400" />
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-end">
        {[
          { key: 'sender' as const, placeholder: 'Sender…' },
          { key: 'recipient' as const, placeholder: 'Recipient…' },
        ].map(({ key, placeholder }) => (
          <input
            key={key}
            value={filters[key]}
            onChange={e => { setFilters(f => ({ ...f, [key]: e.target.value })); setPage(1) }}
            placeholder={placeholder}
            className="px-3 py-2 bg-[#0d1b2e] border border-[#1a2744] rounded-lg text-sm text-[#e4e4e7] placeholder-[#52525b] focus:outline-none focus:ring-1 focus:ring-[#3b6ef6]"
          />
        ))}
        <input
          type="date"
          value={filters.date_from}
          onChange={e => { setFilters(f => ({ ...f, date_from: e.target.value })); setPage(1) }}
          className="px-3 py-2 bg-[#0d1b2e] border border-[#1a2744] rounded-lg text-sm text-[#e4e4e7] focus:outline-none focus:ring-1 focus:ring-[#3b6ef6]"
        />
        <input
          type="date"
          value={filters.date_to}
          onChange={e => { setFilters(f => ({ ...f, date_to: e.target.value })); setPage(1) }}
          className="px-3 py-2 bg-[#0d1b2e] border border-[#1a2744] rounded-lg text-sm text-[#e4e4e7] focus:outline-none focus:ring-1 focus:ring-[#3b6ef6]"
        />
        <select
          value={filters.status}
          onChange={e => { setFilters(f => ({ ...f, status: e.target.value })); setPage(1) }}
          className="px-3 py-2 bg-[#0d1b2e] border border-[#1a2744] rounded-lg text-sm text-[#e4e4e7] focus:outline-none focus:ring-1 focus:ring-[#3b6ef6]"
        >
          <option value="unresolved">Unresolved</option>
          <option value="all">All Statuses</option>
          <option value="quarantined">Quarantined</option>
          <option value="new">Pending (New)</option>
          <option value="resolved">Resolved</option>
        </select>
        <select
          value={filters.threat_type}
          onChange={e => { setFilters(f => ({ ...f, threat_type: e.target.value })); setPage(1) }}
          className="px-3 py-2 bg-[#0d1b2e] border border-[#1a2744] rounded-lg text-sm text-[#e4e4e7] focus:outline-none focus:ring-1 focus:ring-[#3b6ef6]"
        >
          {THREAT_TYPES.map(t => <option key={t} value={t}>{t === 'all' ? 'All Types' : t.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</option>)}
        </select>
        <button
          onClick={() => { setFilters({ sender: '', recipient: '', date_from: '', date_to: '', threat_type: 'all', status: 'unresolved' }); setPage(1) }}
          className="px-3 py-2 text-xs text-[#a1a1aa] hover:text-white bg-white/5 border border-white/10 rounded-lg transition-colors"
        >
          Clear
        </button>
      </div>

      {/* Table */}
      <div className="bg-[#0d1b2e] border border-[#1a2744] rounded-xl overflow-hidden">
        {loading ? (
          <div className="text-center text-[#a1a1aa] py-16 text-sm">Loading…</div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
            <div className="w-16 h-16 rounded-full bg-[#3b6ef6]/10 flex items-center justify-center">
              <Shield size={28} className="text-[#3b6ef6]/50" />
            </div>
            <div>
              <p className="text-white font-medium">No quarantined emails</p>
              <p className="text-sm text-[#a1a1aa] mt-1">Everything looks clean — no emails match the current filters.</p>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1a2744] text-[#71717a] text-xs font-medium">
                  {['Date/Time', 'Sender', 'Recipient', 'Threat Type', 'Risk Score', 'Action Taken', 'Status', 'Actions'].map(h => (
                    <th key={h} className="text-left px-4 py-3 whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {items.map((item, i) => (
                  <tr
                    key={item.id}
                    onClick={() => setSelected(item)}
                    className={`border-b border-[#1a2744]/50 cursor-pointer hover:bg-white/[0.02] transition-colors ${
                      i % 2 === 0 ? '' : 'bg-white/[0.01]'
                    }`}
                  >
                    <td className="px-4 py-3 text-[#a1a1aa] whitespace-nowrap text-xs">{fmt(item.detected_at)}</td>
                    <td className="px-4 py-3 text-[#e4e4e7] max-w-[160px] truncate" title={item.sender}>{item.sender}</td>
                    <td className="px-4 py-3 text-[#a1a1aa] max-w-[160px] truncate" title={item.recipient_email}>{item.recipient_email}</td>
                    <td className="px-4 py-3">{threatBadge(item.threat_type)}</td>
                    <td className="px-4 py-3"><RiskBar score={item.risk_score} /></td>
                    <td className="px-4 py-3 text-[#a1a1aa] text-xs">{item.action_taken}</td>
                    <td className="px-4 py-3">
                      <span className={`px-2 py-0.5 rounded-full text-xs ${STATUS_COLORS[item.status] ?? 'bg-slate-500/20 text-slate-400'}`}>
                        {STATUS_LABELS[item.status] ?? item.status}
                      </span>
                    </td>
                    <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                      <div className="flex gap-1.5 flex-wrap">
                        <button
                          onClick={() => handleAction(item.id, 'release')}
                          className="px-2 py-1 text-xs rounded bg-green-500/20 text-green-400 hover:bg-green-500/30 transition-colors"
                        >Release</button>
                        <button
                          onClick={() => handleAction(item.id, 'block-permanently')}
                          className="px-2 py-1 text-xs rounded bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
                          title="Move to Trash"
                        >Block</button>
                        <button
                          onClick={() => handleAction(item.id, 'mark-as-spam')}
                          className="px-2 py-1 text-xs rounded bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30 transition-colors"
                        >Spam</button>
                        <button
                          onClick={() => handleAction(item.id, 'report-fp')}
                          className="px-2 py-1 text-xs rounded bg-slate-500/20 text-slate-400 hover:bg-slate-500/30 transition-colors"
                          title="Tunes future analysis"
                        >FP</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-[#1a2744]/50">
            <span className="text-xs text-[#71717a]">Page {page} of {totalPages}</span>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage(p => p - 1)}
                className="p-1.5 rounded bg-white/5 hover:bg-white/10 disabled:opacity-30 transition-colors"
              >
                <ChevronLeft size={14} className="text-[#a1a1aa]" />
              </button>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage(p => p + 1)}
                className="p-1.5 rounded bg-white/5 hover:bg-white/10 disabled:opacity-30 transition-colors"
              >
                <ChevronRight size={14} className="text-[#a1a1aa]" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Drawer */}
      {selected && (
        <DetailPanel
          item={selected}
          onClose={() => setSelected(null)}
          onAction={handleAction}
        />
      )}
    </div>
  )
}
