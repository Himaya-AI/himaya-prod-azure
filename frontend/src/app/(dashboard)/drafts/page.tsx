'use client'
import { useEffect, useState, useCallback, useRef } from 'react'
import {
  PenLine, RefreshCw, AlertTriangle, CheckCircle2, ShieldAlert,
  Clock, ChevronLeft, ChevronRight, X, FileText, Mail, User,
  Info, Filter,
} from 'lucide-react'
import api from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface DraftStats {
  total_analyzed: number
  clean: number
  sensitive: number
  critical: number
  pending: number
  last_scan_at: string | null
}

interface DraftEvent {
  id: string
  message_id: string
  provider: string
  owner_email: string
  subject: string | null
  body_preview: string | null
  recipients: string[]
  has_attachment: boolean
  attachment_names: string[]
  dlp_classification: string | null
  dlp_categories: string[]
  dlp_score: number
  dlp_explanation: string | null
  last_modified_at: string | null
  analyzed_at: string | null
}

// ── Theme constants ───────────────────────────────────────────────────────────

const CLASS_STYLES: Record<string, string> = {
  CLEAN:     'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  SENSITIVE: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
  CRITICAL:  'bg-red-500/10 border-red-500/20 text-red-400',
  PENDING:   'bg-slate-500/10 border-slate-500/20 text-slate-400',
}

const CLASS_ICONS: Record<string, React.ReactNode> = {
  CLEAN:     <CheckCircle2 size={10} />,
  SENSITIVE: <AlertTriangle size={10} />,
  CRITICAL:  <ShieldAlert size={10} />,
  PENDING:   <Clock size={10} />,
}

function ClassBadge({ cls }: { cls: string | null }) {
  const key = cls || 'PENDING'
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${CLASS_STYLES[key] || CLASS_STYLES.PENDING}`}>
      {CLASS_ICONS[key] || <Clock size={10} />}
      {key}
    </span>
  )
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 70 ? 'bg-red-500' : score >= 40 ? 'bg-amber-500' : 'bg-emerald-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.min(score, 100)}%` }} />
      </div>
      <span className="text-xs text-[var(--muted)]">{score}</span>
    </div>
  )
}

function fmt(ts: string | null): string {
  if (!ts) return '—'
  return new Date(ts).toLocaleString()
}

// ── Detail Drawer ─────────────────────────────────────────────────────────────

function DetailDrawer({ draft, onClose }: { draft: DraftEvent; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/40" onClick={onClose} />
      <div className="w-[480px] bg-[#141417] border-l border-white/10 flex flex-col h-full overflow-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-white/10">
          <div className="flex items-center gap-2">
            <PenLine size={16} className="text-indigo-400" />
            <span className="font-semibold text-sm text-white">Draft Details</span>
          </div>
          <button onClick={onClose} className="text-[var(--muted)] hover:text-white transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4 text-sm">
          {/* Classification */}
          <div className="flex items-center justify-between">
            <ClassBadge cls={draft.dlp_classification} />
            <ScoreBar score={draft.dlp_score} />
          </div>

          {/* Subject */}
          <div className="bg-white/5 rounded-lg p-3">
            <div className="text-[11px] text-[var(--muted)] mb-1 uppercase tracking-wide">Subject</div>
            <div className="text-white font-medium">{draft.subject || '(No Subject)'}</div>
          </div>

          {/* Meta */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-1 flex items-center gap-1">
                <User size={10} /> Owner
              </div>
              <div className="text-white text-xs truncate">{draft.owner_email}</div>
            </div>
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-1 uppercase tracking-wide">Provider</div>
              <div className="text-white text-xs uppercase">{draft.provider}</div>
            </div>
          </div>

          {/* Recipients */}
          {draft.recipients.length > 0 && (
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-2 flex items-center gap-1">
                <Mail size={10} /> Recipients
              </div>
              <div className="flex flex-wrap gap-1">
                {draft.recipients.map((r, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded text-[11px] bg-white/10 text-[var(--muted)]">{r}</span>
                ))}
              </div>
            </div>
          )}

          {/* Categories */}
          {draft.dlp_categories.length > 0 && (
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-2 uppercase tracking-wide">DLP Categories</div>
              <div className="flex flex-wrap gap-1">
                {draft.dlp_categories.map((c, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded text-[11px] bg-amber-500/10 border border-amber-500/20 text-amber-400">{c}</span>
                ))}
              </div>
            </div>
          )}

          {/* Explanation */}
          {draft.dlp_explanation && (
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-2 flex items-center gap-1">
                <Info size={10} /> DLP Explanation
              </div>
              <p className="text-[var(--muted)] text-xs leading-relaxed">{draft.dlp_explanation}</p>
            </div>
          )}

          {/* Body Preview */}
          {draft.body_preview && (
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-2 flex items-center gap-1">
                <FileText size={10} /> Body Preview
              </div>
              <p className="text-[var(--muted)] text-xs leading-relaxed line-clamp-10">{draft.body_preview}</p>
            </div>
          )}

          {/* Timestamps */}
          <div className="grid grid-cols-2 gap-3 text-[11px] text-[var(--muted)]">
            <div>
              <div className="mb-0.5 uppercase tracking-wide">Last Modified</div>
              <div>{fmt(draft.last_modified_at)}</div>
            </div>
            <div>
              <div className="mb-0.5 uppercase tracking-wide">Analyzed</div>
              <div>{fmt(draft.analyzed_at)}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function DraftsPage() {
  const [stats, setStats] = useState<DraftStats | null>(null)
  const [items, setItems] = useState<DraftEvent[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const PAGE_SIZE = 25

  const [classFilter, setClassFilter] = useState('')
  const [ownerFilter, setOwnerFilter] = useState('')
  const [providerFilter, setProviderFilter] = useState('')
  const [sortBy, setSortBy] = useState<'analyzed_at' | 'last_modified_at'>('last_modified_at')
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc')

  const [scanning, setScanning] = useState(false)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<DraftEvent | null>(null)

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchStats = useCallback(async () => {
    try {
      const res = await api.get('/api/drafts/stats')
      setStats(res.data)
    } catch (e) {
      console.error('Draft stats error', e)
    }
  }, [])

  const fetchItems = useCallback(async (p = page) => {
    setLoading(true)
    try {
      const params: Record<string, string | number> = { page: p, page_size: PAGE_SIZE }
      if (classFilter) params.classification = classFilter
      if (ownerFilter) params.owner_email = ownerFilter
      if (providerFilter) params.provider = providerFilter
      params.sort_by = sortBy
      params.sort_order = sortOrder
      const res = await api.get('/api/drafts', { params })
      setItems(res.data.items || [])
      setTotal(res.data.total || 0)
    } catch (e) {
      console.error('Draft items error', e)
    } finally {
      setLoading(false)
    }
  }, [page, classFilter, ownerFilter, sortBy, sortOrder])

  const handleScan = async () => {
    setScanning(true)
    try {
      await api.post('/api/drafts/scan')
      await Promise.all([fetchStats(), fetchItems(1)])
      setPage(1)
    } catch (e) {
      console.error('Draft scan error', e)
    } finally {
      setScanning(false)
    }
  }

  useEffect(() => {
    fetchStats()
    fetchItems(1)
    setPage(1)
  }, [classFilter, ownerFilter, providerFilter, sortBy, sortOrder])

  useEffect(() => {
    fetchItems(page)
  }, [page])

  // Auto-refresh every 60s
  useEffect(() => {
    intervalRef.current = setInterval(() => {
      fetchStats()
      fetchItems()
    }, 60_000)
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [fetchStats, fetchItems])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  return (
    <div className="flex flex-col h-full bg-[#0c0c0e] text-white">
      {selected && <DetailDrawer draft={selected} onClose={() => setSelected(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-white/10 flex-shrink-0">
        <div>
          <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Draft Analysis</h1>
        </div>
        <button
          onClick={handleScan}
          disabled={scanning}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-sm font-medium transition-colors"
        >
          <RefreshCw size={14} className={scanning ? 'animate-spin' : ''} />
          {scanning ? 'Scanning…' : 'Scan Now'}
        </button>
      </div>

      <div className="flex-1 overflow-auto">
        <div className="p-6 space-y-5">

          {/* Stats Cards */}
          {stats && (
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {[
                { label: 'Total Analyzed', value: stats.total_analyzed, color: 'text-white' },
                { label: 'Clean', value: stats.clean, color: 'text-emerald-400' },
                { label: 'Sensitive', value: stats.sensitive, color: 'text-amber-400' },
                { label: 'Critical', value: stats.critical, color: 'text-red-400' },
                { label: 'Pending', value: stats.pending, color: 'text-slate-400' },
              ].map((s) => (
                <div key={s.label} className="bg-[#141417] border border-white/10 rounded-xl p-4">
                  <div className="text-[11px] text-[var(--muted)] mb-1 uppercase tracking-wide">{s.label}</div>
                  <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                </div>
              ))}
            </div>
          )}

          {/* Filters */}
          <div className="flex flex-wrap gap-3 items-center">
            <div className="flex items-center gap-2">
              <Filter size={14} className="text-[var(--muted)]" />
              <span className="text-xs text-[var(--muted)]">Filters:</span>
            </div>
            <select
              value={providerFilter}
              onChange={(e) => { setProviderFilter(e.target.value); setPage(1) }}
              className="px-3 py-1.5 rounded-lg bg-[#141417] border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500/50"
            >
              <option value="">All Sources</option>
              <option value="gmail">Gmail</option>
              <option value="m365">Outlook (M365)</option>
            </select>
            <select
              value={classFilter}
              onChange={(e) => { setClassFilter(e.target.value); setPage(1) }}
              className="px-3 py-1.5 rounded-lg bg-[#141417] border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500/50"
            >
              <option value="">All Classifications</option>
              <option value="CLEAN">Clean</option>
              <option value="SENSITIVE">Sensitive</option>
              <option value="CRITICAL">Critical</option>
              <option value="PENDING">Pending</option>
            </select>
            <input
              type="text"
              placeholder="Filter by owner email…"
              value={ownerFilter}
              onChange={(e) => { setOwnerFilter(e.target.value); setPage(1) }}
              className="px-3 py-1.5 rounded-lg bg-[#141417] border border-white/10 text-sm text-white placeholder-[var(--muted)] focus:outline-none focus:border-indigo-500/50 w-56"
            />
            <select
              value={`${sortBy}:${sortOrder}`}
              onChange={(e) => {
                const [sb, so] = e.target.value.split(':') as ['analyzed_at' | 'last_modified_at', 'desc' | 'asc']
                setSortBy(sb); setSortOrder(so); setPage(1)
              }}
              className="px-3 py-1.5 rounded-lg bg-[#141417] border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500/50"
            >
              <option value="analyzed_at:desc">Analyzed (Newest First)</option>
              <option value="analyzed_at:asc">Analyzed (Oldest First)</option>
              <option value="last_modified_at:desc">Last Modified (Newest First)</option>
              <option value="last_modified_at:asc">Last Modified (Oldest First)</option>
            </select>
            {(classFilter || ownerFilter || providerFilter) && (
              <button
                onClick={() => { setClassFilter(''); setOwnerFilter(''); setProviderFilter(''); setPage(1) }}
                className="text-xs text-[var(--muted)] hover:text-white transition-colors flex items-center gap-1"
              >
                <X size={12} /> Clear
              </button>
            )}
          </div>

          {/* Responsive Card/Table Layout */}
          <div className="bg-[#141417] border border-white/10 rounded-xl overflow-hidden">
            {/* Desktop Table - hidden on small screens */}
            <div className="hidden lg:block">
              <table className="w-full text-sm table-fixed">
                <thead>
                  <tr className="border-b border-white/10 bg-white/5">
                    <th className="px-3 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide w-[15%]">Owner</th>
                    <th className="px-3 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide w-[20%]">Subject</th>
                    <th className="px-3 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide w-[12%]">Class</th>
                    <th className="px-3 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide w-[10%]">Score</th>
                    <th className="px-3 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide w-[20%]">Categories</th>
                    <th className="px-3 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide w-[12%]">Modified</th>
                    <th className="px-3 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide w-[11%]">Analyzed</th>
                  </tr>
                </thead>
                <tbody>
                  {loading && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-[var(--muted)]">
                        <RefreshCw size={16} className="animate-spin inline mr-2" />Loading…
                      </td>
                    </tr>
                  )}
                  {!loading && items.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-12 text-center">
                        <PenLine size={32} className="mx-auto mb-3 text-[var(--muted)] opacity-40" />
                        <p className="text-[var(--muted)] text-sm">No draft events found.</p>
                        <p className="text-[var(--muted)] text-xs mt-1">Click "Scan Now" to analyze drafts.</p>
                      </td>
                    </tr>
                  )}
                  {!loading && items.map((item) => (
                    <tr
                      key={item.id}
                      onClick={() => setSelected(item)}
                      className="border-b border-white/5 hover:bg-white/5 cursor-pointer transition-colors"
                    >
                      <td className="px-3 py-3 text-xs text-[var(--muted)] truncate" title={item.owner_email}>{item.owner_email.split('@')[0]}</td>
                      <td className="px-3 py-3">
                        <span className="text-white text-xs truncate block" title={item.subject || '(No Subject)'}>{item.subject || '(No Subject)'}</span>
                      </td>
                      <td className="px-3 py-3"><ClassBadge cls={item.dlp_classification} /></td>
                      <td className="px-3 py-3"><ScoreBar score={item.dlp_score} /></td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-1">
                          {item.dlp_categories.slice(0, 2).map((c, i) => (
                            <span key={i} className="px-1 py-0.5 rounded text-[9px] bg-amber-500/10 text-amber-400 border border-amber-500/20 truncate max-w-[80px]" title={c}>{c.replace('credential_', '').replace('financial_', '').replace('pii_', '')}</span>
                          ))}
                          {item.dlp_categories.length > 2 && (
                            <span className="text-[9px] text-[var(--muted)]">+{item.dlp_categories.length - 2}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-3 text-[10px] text-[var(--muted)]">{fmt(item.last_modified_at).split(',')[0]}</td>
                      <td className="px-3 py-3 text-[10px] text-[var(--muted)]">{fmt(item.analyzed_at).split(',')[0]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile/Tablet Card Layout */}
            <div className="lg:hidden divide-y divide-white/5">
              {loading && (
                <div className="px-4 py-8 text-center text-[var(--muted)]">
                  <RefreshCw size={16} className="animate-spin inline mr-2" />Loading…
                </div>
              )}
              {!loading && items.length === 0 && (
                <div className="px-4 py-12 text-center">
                  <PenLine size={32} className="mx-auto mb-3 text-[var(--muted)] opacity-40" />
                  <p className="text-[var(--muted)] text-sm">No draft events found.</p>
                </div>
              )}
              {!loading && items.map((item) => (
                <div
                  key={item.id}
                  onClick={() => setSelected(item)}
                  className="p-4 hover:bg-white/5 cursor-pointer transition-colors"
                >
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-white font-medium truncate">{item.subject || '(No Subject)'}</div>
                      <div className="text-xs text-[var(--muted)] truncate mt-0.5">{item.owner_email}</div>
                    </div>
                    <ClassBadge cls={item.dlp_classification} />
                  </div>
                  <div className="flex items-center gap-4 mt-2">
                    <ScoreBar score={item.dlp_score} />
                    <div className="flex flex-wrap gap-1 flex-1">
                      {item.dlp_categories.slice(0, 2).map((c, i) => (
                        <span key={i} className="px-1 py-0.5 rounded text-[9px] bg-amber-500/10 text-amber-400 border border-amber-500/20">{c.split('_').pop()}</span>
                      ))}
                      {item.dlp_categories.length > 2 && (
                        <span className="text-[9px] text-[var(--muted)]">+{item.dlp_categories.length - 2}</span>
                      )}
                    </div>
                    <span className="text-[10px] text-[var(--muted)] whitespace-nowrap">{fmt(item.analyzed_at).split(',')[0]}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-white/10">
                <span className="text-xs text-[var(--muted)]">
                  {total} total · page {page} of {totalPages}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 disabled:opacity-30 transition-colors"
                  >
                    <ChevronLeft size={14} />
                  </button>
                  <button
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                    disabled={page === totalPages}
                    className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 disabled:opacity-30 transition-colors"
                  >
                    <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Last scan */}
          {stats?.last_scan_at && (
            <p className="text-xs text-[var(--muted)] text-right">
              Last scan: {fmt(stats.last_scan_at)}
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
