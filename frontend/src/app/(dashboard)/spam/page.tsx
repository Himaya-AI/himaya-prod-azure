'use client'
import React, { useEffect, useState, useCallback, useRef } from 'react'
import {
  MailWarning, RefreshCw, AlertTriangle, CheckCircle, Trash2,
  ArrowUpFromLine, ChevronLeft, ChevronRight, X, Plus, Settings,
  Shield, Filter, ToggleLeft, ToggleRight, Edit2, Zap,
  ChevronDown, ChevronUp, Info, Eye,
} from 'lucide-react'
import api from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SpamStats {
  total: number
  spam: number
  marketing: number
  bulk: number
  phishing_spam: number
  released_today: number
}

interface SpamItem {
  id: string
  message_id: string
  provider: string
  owner_email: string
  subject: string | null
  body_preview: string | null
  sender: string
  sender_domain: string
  recipients: string[]
  has_attachment: boolean
  classification: string
  spam_score: number
  is_released: boolean
  released_at: string | null
  released_by: string | null
  received_at: string | null
  synced_at: string | null
}

interface SpamRule {
  id: string
  name: string
  description: string | null
  enabled: boolean
  rule_type: string
  match_value: string
  action: string
  hit_count: number
  last_hit_at: string | null
  created_at: string | null
  updated_at: string | null
}

type SpamTab = 'inbox' | 'rules'

// ── Theme helpers ─────────────────────────────────────────────────────────────

const CLASS_STYLES: Record<string, string> = {
  SPAM:          'bg-red-500/10 border-red-500/20 text-red-400',
  MARKETING:     'bg-blue-500/10 border-blue-500/20 text-blue-400',
  BULK:          'bg-orange-500/10 border-orange-500/20 text-orange-400',
  PHISHING_SPAM: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
}

function ClassBadge({ cls }: { cls: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${CLASS_STYLES[cls] || CLASS_STYLES.SPAM}`}>
      {cls === 'PHISHING_SPAM' ? <AlertTriangle size={10} /> : <MailWarning size={10} />}
      {cls.replace('_', ' ')}
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

// ── Spam Detail Drawer ─────────────────────────────────────────────────────────────

function SpamDetailDrawer({ item, onClose, onRelease, onDelete }: {
  item: SpamItem
  onClose: () => void
  onRelease: () => void
  onDelete: () => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/40" onClick={onClose} />
      <div className="w-[500px] bg-[#141417] border-l border-white/10 flex flex-col h-full overflow-auto">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-white/10 flex-shrink-0">
          <div className="flex items-center gap-2">
            <MailWarning size={16} className="text-red-400" />
            <span className="font-semibold text-sm text-white">Spam Details</span>
          </div>
          <button onClick={onClose} className="text-[var(--muted)] hover:text-white transition-colors">
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-4 flex-1 overflow-auto">
          {/* Classification & Score */}
          <div className="flex items-center justify-between">
            <ClassBadge cls={item.classification} />
            <ScoreBar score={item.spam_score} />
          </div>

          {/* Subject */}
          <div className="bg-white/5 rounded-lg p-3">
            <div className="text-[11px] text-[var(--muted)] mb-1 uppercase tracking-wide">Subject</div>
            <div className="text-white font-medium text-sm">{item.subject || '(No Subject)'}</div>
          </div>

          {/* Sender */}
          <div className="bg-white/5 rounded-lg p-3">
            <div className="text-[11px] text-[var(--muted)] mb-1 uppercase tracking-wide">From</div>
            <div className="text-white text-sm">{item.sender}</div>
            <div className="text-[var(--muted)] text-xs mt-0.5">{item.sender_domain}</div>
          </div>

          {/* Meta Grid */}
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-1 uppercase tracking-wide">Owner</div>
              <div className="text-white text-xs truncate">{item.owner_email}</div>
            </div>
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-1 uppercase tracking-wide">Provider</div>
              <div className="text-white text-xs uppercase">{item.provider}</div>
            </div>
          </div>

          {/* Recipients */}
          {item.recipients.length > 0 && (
            <div className="bg-white/5 rounded-lg p-3">
              <div className="text-[11px] text-[var(--muted)] mb-2 uppercase tracking-wide">To</div>
              <div className="flex flex-wrap gap-1">
                {item.recipients.map((r, i) => (
                  <span key={i} className="px-1.5 py-0.5 rounded text-[11px] bg-white/10 text-[var(--muted)]">{r}</span>
                ))}
              </div>
            </div>
          )}

          {/* Body Preview */}
          <div className="bg-white/5 rounded-lg p-3">
            <div className="text-[11px] text-[var(--muted)] mb-2 uppercase tracking-wide">Email Body</div>
            <div className="bg-[#0d0d12] rounded-lg p-3 max-h-[300px] overflow-auto">
              {item.body_preview ? (
                <p className="text-[var(--muted)] text-xs leading-relaxed whitespace-pre-wrap">
                  {item.body_preview}
                </p>
              ) : (
                <p className="text-[var(--muted)] text-xs italic">No preview available</p>
              )}
            </div>
          </div>

          {/* Timestamps */}
          <div className="grid grid-cols-2 gap-3 text-[11px] text-[var(--muted)]">
            <div>
              <div className="mb-0.5 uppercase tracking-wide">Received</div>
              <div>{fmt(item.received_at)}</div>
            </div>
            <div>
              <div className="mb-0.5 uppercase tracking-wide">Synced</div>
              <div>{fmt(item.synced_at)}</div>
            </div>
          </div>

          {/* Status */}
          {item.is_released && (
            <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-3">
              <div className="flex items-center gap-2 text-emerald-400 text-sm">
                <CheckCircle size={14} />
                <span>Released to inbox</span>
              </div>
              <div className="text-[11px] text-[var(--muted)] mt-1">
                {item.released_by && `By ${item.released_by} · `}{fmt(item.released_at)}
              </div>
            </div>
          )}
        </div>

        {/* Actions Footer */}
        {!item.is_released && (
          <div className="p-4 border-t border-white/10 flex gap-3 flex-shrink-0">
            <button
              onClick={onRelease}
              className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium transition-colors"
            >
              <ArrowUpFromLine size={14} />
              Release to Inbox
            </button>
            <button
              onClick={onDelete}
              className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600/30 text-sm font-medium transition-colors"
            >
              <Trash2 size={14} />
              Delete
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Confirm Modal ─────────────────────────────────────────────────────────────

function ConfirmModal({
  title, message, onConfirm, onCancel, confirmLabel = 'Confirm', danger = false
}: {
  title: string; message: string; onConfirm: () => void; onCancel: () => void;
  confirmLabel?: string; danger?: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#141417] border border-white/10 rounded-xl p-6 w-80 shadow-2xl">
        <h3 className="text-base font-semibold text-white mb-2">{title}</h3>
        <p className="text-sm text-[var(--muted)] mb-5">{message}</p>
        <div className="flex gap-3 justify-end">
          <button onClick={onCancel} className="px-3 py-1.5 rounded-lg text-sm bg-white/10 hover:bg-white/20 transition-colors">Cancel</button>
          <button
            onClick={onConfirm}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${danger ? 'bg-red-600 hover:bg-red-500' : 'bg-indigo-600 hover:bg-indigo-500'}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Rule Form Modal ───────────────────────────────────────────────────────────

interface RuleFormData {
  name: string
  description: string
  rule_type: string
  match_value: string
  action: string
  enabled: boolean
}

function RuleFormModal({
  initial, onSave, onClose
}: {
  initial?: Partial<RuleFormData>; onSave: (data: RuleFormData) => Promise<void>; onClose: () => void;
}) {
  const [form, setForm] = useState<RuleFormData>({
    name: initial?.name || '',
    description: initial?.description || '',
    rule_type: initial?.rule_type || 'SENDER_DOMAIN',
    match_value: initial?.match_value || '',
    action: initial?.action || 'MOVE_TO_INBOX',
    enabled: initial?.enabled ?? true,
  })
  const [saving, setSaving] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    try { await onSave(form) } finally { setSaving(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end">
      <div className="flex-1 bg-black/40" onClick={onClose} />
      <div className="w-[420px] bg-[#141417] border-l border-white/10 h-full overflow-auto flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-white/10">
          <span className="font-semibold text-sm text-white">{initial ? 'Edit Rule' : 'Add Rule'}</span>
          <button onClick={onClose} className="text-[var(--muted)] hover:text-white"><X size={18} /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4 flex-1">
          <div>
            <label className="block text-xs text-[var(--muted)] mb-1">Rule Name *</label>
            <input
              required value={form.name} onChange={(e) => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="e.g. Block marketing emails"
              className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-sm text-white placeholder-[var(--muted)] focus:outline-none focus:border-indigo-500/50"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--muted)] mb-1">Description</label>
            <textarea
              value={form.description} onChange={(e) => setForm(f => ({ ...f, description: e.target.value }))}
              rows={2}
              className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-sm text-white placeholder-[var(--muted)] focus:outline-none focus:border-indigo-500/50 resize-none"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--muted)] mb-1">Rule Type *</label>
            <select
              value={form.rule_type} onChange={(e) => setForm(f => ({ ...f, rule_type: e.target.value }))}
              className="w-full px-3 py-2 rounded-lg bg-[#141417] border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500/50"
            >
              <option value="SENDER_EMAIL">Sender Email</option>
              <option value="SENDER_DOMAIN">Sender Domain</option>
              <option value="SUBJECT_CONTAINS">Subject Contains</option>
              <option value="BODY_CONTAINS">Body Contains</option>
              <option value="CLASSIFICATION">Classification</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-[var(--muted)] mb-1">Match Value *</label>
            <input
              required value={form.match_value} onChange={(e) => setForm(f => ({ ...f, match_value: e.target.value }))}
              placeholder="e.g. newsletters.example.com"
              className="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 text-sm text-white placeholder-[var(--muted)] focus:outline-none focus:border-indigo-500/50"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--muted)] mb-1">Action *</label>
            <select
              value={form.action} onChange={(e) => setForm(f => ({ ...f, action: e.target.value }))}
              className="w-full px-3 py-2 rounded-lg bg-[#141417] border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500/50"
            >
              <option value="MOVE_TO_INBOX">Move to Inbox</option>
              <option value="DELETE">Delete</option>
              <option value="FLAG">Flag</option>
            </select>
          </div>
          <div className="flex items-center justify-between">
            <label className="text-xs text-[var(--muted)]">Enabled</label>
            <button
              type="button"
              onClick={() => setForm(f => ({ ...f, enabled: !f.enabled }))}
              className={`transition-colors ${form.enabled ? 'text-indigo-400' : 'text-[var(--muted)]'}`}
            >
              {form.enabled ? <ToggleRight size={28} /> : <ToggleLeft size={28} />}
            </button>
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 px-3 py-2 rounded-lg text-sm bg-white/10 hover:bg-white/20 transition-colors">
              Cancel
            </button>
            <button
              type="submit" disabled={saving}
              className="flex-1 px-3 py-2 rounded-lg text-sm font-medium bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 transition-colors"
            >
              {saving ? 'Saving…' : 'Save Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Test Result Popover ───────────────────────────────────────────────────────

function TestResult({ result, onClose }: { result: { matched_count: number; sample_subjects: string[] }; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-[#141417] border border-white/10 rounded-xl p-5 w-80 shadow-2xl">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-semibold text-white">Rule Test Results</span>
          <button onClick={onClose} className="text-[var(--muted)] hover:text-white"><X size={16} /></button>
        </div>
        <div className="text-2xl font-bold text-white mb-1">{result.matched_count}</div>
        <div className="text-xs text-[var(--muted)] mb-3">matching spam items</div>
        {result.sample_subjects.length > 0 && (
          <div>
            <div className="text-[11px] text-[var(--muted)] mb-2 uppercase tracking-wide">Sample subjects</div>
            <ul className="space-y-1">
              {result.sample_subjects.map((s, i) => (
                <li key={i} className="text-xs text-[var(--muted)] truncate bg-white/5 rounded px-2 py-1">{s}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Tab: Spam Inbox ───────────────────────────────────────────────────────────

function SpamInboxTab() {
  const [stats, setStats] = useState<SpamStats | null>(null)
  const [items, setItems] = useState<SpamItem[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const PAGE_SIZE = 25

  const [classFilter, setClassFilter] = useState('')
  const [ownerFilter, setOwnerFilter] = useState('')
  const [showReleased, setShowReleased] = useState(false)
  const [sortBy, setSortBy] = useState<'received_at' | 'synced_at'>('received_at')
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc')

  const [syncing, setSyncing] = useState(false)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<string[]>([])

  const [confirmRelease, setConfirmRelease] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const [confirmBulkRelease, setConfirmBulkRelease] = useState(false)
  const [confirmBulkDelete, setConfirmBulkDelete] = useState(false)
  const [selectedItem, setSelectedItem] = useState<SpamItem | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchStats = useCallback(async () => {
    try {
      const res = await api.get('/api/spam/stats')
      setStats(res.data)
    } catch (e) { console.error(e) }
  }, [])

  const fetchItems = useCallback(async (p = page) => {
    setLoading(true)
    try {
      const params: Record<string, string | number | boolean> = { page: p, page_size: PAGE_SIZE }
      if (classFilter) params.classification = classFilter
      if (ownerFilter) params.owner_email = ownerFilter
      if (showReleased) params.is_released = true
      params.sort_by = sortBy
      params.sort_order = sortOrder
      const res = await api.get('/api/spam/items', { params })
      setItems(res.data.items || [])
      setTotal(res.data.total || 0)
    } catch (e) { console.error(e) } finally { setLoading(false) }
  }, [page, classFilter, ownerFilter, showReleased])

  const handleSync = async () => {
    setSyncing(true)
    try {
      await api.post('/api/spam/sync')
      await Promise.all([fetchStats(), fetchItems(1)])
      setPage(1)
    } catch (e) { console.error(e) } finally { setSyncing(false) }
  }

  const doRelease = async (id: string) => {
    try { await api.post(`/api/spam/items/${id}/release`) } catch (e) { console.error(e) }
    await Promise.all([fetchStats(), fetchItems()])
  }

  const doDelete = async (id: string) => {
    try { await api.post(`/api/spam/items/${id}/delete`) } catch (e) { console.error(e) }
    await Promise.all([fetchStats(), fetchItems()])
  }

  const doBulkRelease = async () => {
    await Promise.all(selected.map(id => api.post(`/api/spam/items/${id}/release`).catch(() => {})))
    setSelected([])
    await Promise.all([fetchStats(), fetchItems()])
  }

  const doBulkDelete = async () => {
    await Promise.all(selected.map(id => api.post(`/api/spam/items/${id}/delete`).catch(() => {})))
    setSelected([])
    await Promise.all([fetchStats(), fetchItems()])
  }

  useEffect(() => { fetchStats(); fetchItems(1); setPage(1) }, [classFilter, ownerFilter, showReleased, sortBy, sortOrder])
  useEffect(() => { fetchItems(page) }, [page])
  useEffect(() => {
    intervalRef.current = setInterval(() => { fetchStats(); fetchItems() }, 60_000)
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [fetchStats, fetchItems])

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const allSelected = items.length > 0 && items.every(i => selected.includes(i.id))

  const toggleAll = () => {
    if (allSelected) setSelected([])
    else setSelected(items.map(i => i.id))
  }

  const toggleOne = (id: string) => {
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])
  }

  return (
    <div className="space-y-5">
      {/* Detail drawer */}
      {selectedItem && (
        <SpamDetailDrawer
          item={selectedItem}
          onClose={() => setSelectedItem(null)}
          onRelease={() => {
            setConfirmRelease(selectedItem.id)
          }}
          onDelete={() => {
            setConfirmDelete(selectedItem.id)
          }}
        />
      )}

      {/* Confirm modals */}
      {confirmRelease && (
        <ConfirmModal
          title="Release Message" message="Move this message to inbox?"
          confirmLabel="Release" onConfirm={() => { doRelease(confirmRelease); setConfirmRelease(null); setSelectedItem(null) }}
          onCancel={() => setConfirmRelease(null)}
        />
      )}
      {confirmDelete && (
        <ConfirmModal
          title="Delete Message" message="Permanently delete this message? This cannot be undone."
          confirmLabel="Delete" danger onConfirm={() => { doDelete(confirmDelete); setConfirmDelete(null); setSelectedItem(null) }}
          onCancel={() => setConfirmDelete(null)}
        />
      )}
      {confirmBulkRelease && (
        <ConfirmModal
          title="Bulk Release" message={`Release ${selected.length} selected messages to inbox?`}
          confirmLabel="Release All" onConfirm={() => { doBulkRelease(); setConfirmBulkRelease(false) }}
          onCancel={() => setConfirmBulkRelease(false)}
        />
      )}
      {confirmBulkDelete && (
        <ConfirmModal
          title="Bulk Delete" message={`Permanently delete ${selected.length} selected messages?`}
          confirmLabel="Delete All" danger onConfirm={() => { doBulkDelete(); setConfirmBulkDelete(false) }}
          onCancel={() => setConfirmBulkDelete(false)}
        />
      )}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
          {[
            { label: 'Total', value: stats.total, color: 'text-white' },
            { label: 'Spam', value: stats.spam, color: 'text-red-400' },
            { label: 'Marketing', value: stats.marketing, color: 'text-blue-400' },
            { label: 'Phishing', value: stats.phishing_spam, color: 'text-purple-400' },
            { label: 'Bulk', value: stats.bulk, color: 'text-orange-400' },
            { label: 'Released Today', value: stats.released_today, color: 'text-emerald-400' },
          ].map((s) => (
            <div key={s.label} className="bg-[#141417] border border-white/10 rounded-xl p-3">
              <div className="text-[10px] text-[var(--muted)] mb-1 uppercase tracking-wide">{s.label}</div>
              <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Toolbar */}
      <div className="flex flex-wrap gap-3 items-center justify-between">
        <div className="flex flex-wrap gap-3 items-center">
          <div className="flex items-center gap-2">
            <Filter size={14} className="text-[var(--muted)]" />
          </div>
          <select
            value={classFilter} onChange={(e) => { setClassFilter(e.target.value); setPage(1) }}
            className="px-3 py-1.5 rounded-lg bg-[#141417] border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500/50"
          >
            <option value="">All Types</option>
            <option value="SPAM">Spam</option>
            <option value="MARKETING">Marketing</option>
            <option value="BULK">Bulk</option>
            <option value="PHISHING_SPAM">Phishing Spam</option>
          </select>
          <input
            type="text" placeholder="Filter by owner…" value={ownerFilter}
            onChange={(e) => { setOwnerFilter(e.target.value); setPage(1) }}
            className="px-3 py-1.5 rounded-lg bg-[#141417] border border-white/10 text-sm text-white placeholder-[var(--muted)] focus:outline-none focus:border-indigo-500/50 w-48"
          />
          <button
            onClick={() => setShowReleased(r => !r)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm border transition-colors ${showReleased ? 'bg-indigo-500/10 border-indigo-500/30 text-indigo-400' : 'bg-white/5 border-white/10 text-[var(--muted)]'}`}
          >
            {showReleased ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
            Show Released
          </button>
          <select
            value={`${sortBy}:${sortOrder}`}
            onChange={(e) => {
              const [sb, so] = e.target.value.split(':') as ['received_at' | 'synced_at', 'desc' | 'asc']
              setSortBy(sb); setSortOrder(so); setPage(1)
            }}
            className="px-3 py-1.5 rounded-lg bg-[#141417] border border-white/10 text-sm text-white focus:outline-none focus:border-indigo-500/50"
          >
            <option value="received_at:desc">Received (Newest First)</option>
            <option value="received_at:asc">Received (Oldest First)</option>
            <option value="synced_at:desc">Synced (Newest First)</option>
          </select>
          {(classFilter || ownerFilter) && (
            <button onClick={() => { setClassFilter(''); setOwnerFilter(''); setPage(1) }} className="text-xs text-[var(--muted)] hover:text-white flex items-center gap-1">
              <X size={12} /> Clear
            </button>
          )}
        </div>
        <div className="flex gap-2 items-center">
          {selected.length > 0 && (
            <>
              <button
                onClick={() => setConfirmBulkRelease(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm bg-emerald-600/20 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-600/30 transition-colors"
              >
                <ArrowUpFromLine size={13} /> Release ({selected.length})
              </button>
              <button
                onClick={() => setConfirmBulkDelete(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600/30 transition-colors"
              >
                <Trash2 size={13} /> Delete ({selected.length})
              </button>
            </>
          )}
          <button
            onClick={handleSync} disabled={syncing}
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-sm font-medium transition-colors"
          >
            <RefreshCw size={13} className={syncing ? 'animate-spin' : ''} />
            {syncing ? 'Syncing…' : 'Sync Now'}
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[#141417] border border-white/10 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/5">
                <th className="px-3 py-3 w-10">
                  <input type="checkbox" checked={allSelected} onChange={toggleAll}
                    className="rounded border-white/20 bg-transparent" />
                </th>
                {['Sender', 'Subject', 'Owner', 'Classification', 'Score', 'Received', 'Actions'].map(h => (
                  <th key={h} className="px-3 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-[var(--muted)]">
                  <RefreshCw size={16} className="animate-spin inline mr-2" />Loading…
                </td></tr>
              )}
              {!loading && items.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-12 text-center">
                  <MailWarning size={32} className="mx-auto mb-3 text-[var(--muted)] opacity-40" />
                  <p className="text-[var(--muted)] text-sm">No spam items found.</p>
                  <p className="text-[var(--muted)] text-xs mt-1">Click "Sync Now" to fetch spam from mailboxes.</p>
                </td></tr>
              )}
              {!loading && items.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => setSelectedItem(item)}
                  className={`border-b border-white/5 hover:bg-white/5 transition-colors cursor-pointer ${item.is_released ? 'opacity-50' : ''}`}
                >
                  <td className="px-3 py-3">
                    <input type="checkbox" checked={selected.includes(item.id)} onChange={() => toggleOne(item.id)}
                      className="rounded border-white/20 bg-transparent" />
                  </td>
                  <td className="px-3 py-3 text-xs text-[var(--muted)] max-w-[140px]">
                    <div className="truncate">{item.sender}</div>
                    <div className="text-[10px] opacity-60">{item.sender_domain}</div>
                  </td>
                  <td className="px-3 py-3 max-w-[200px]">
                    <span className="text-white text-xs truncate block">{item.subject || '(No Subject)'}</span>
                    {item.is_released && (
                      <span className="text-[10px] text-emerald-400 flex items-center gap-0.5 mt-0.5">
                        <CheckCircle size={9} /> Released
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-3 text-xs text-[var(--muted)] truncate max-w-[130px]">{item.owner_email}</td>
                  <td className="px-3 py-3"><ClassBadge cls={item.classification} /></td>
                  <td className="px-3 py-3"><ScoreBar score={item.spam_score} /></td>
                  <td className="px-3 py-3 text-xs text-[var(--muted)] whitespace-nowrap">{fmt(item.received_at)}</td>
                  <td className="px-3 py-3">
                    {!item.is_released && (
                      <div className="flex gap-1.5">
                        <button
                          onClick={(e) => { e.stopPropagation(); setConfirmRelease(item.id) }}
                          title="Release to inbox"
                          className="p-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 transition-colors"
                        >
                          <ArrowUpFromLine size={13} />
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); setConfirmDelete(item.id) }}
                          title="Delete permanently"
                          className="p-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors"
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-white/10">
            <span className="text-xs text-[var(--muted)]">{total} total · page {page} of {totalPages}</span>
            <div className="flex gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 disabled:opacity-30 transition-colors">
                <ChevronLeft size={14} />
              </button>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                className="p-1.5 rounded-lg bg-white/5 hover:bg-white/10 disabled:opacity-30 transition-colors">
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Tab: Anti-Spam Rules ──────────────────────────────────────────────────────

function AntiSpamRulesTab() {
  const [rules, setRules] = useState<SpamRule[]>([])
  const [loading, setLoading] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [editRule, setEditRule] = useState<SpamRule | null>(null)
  const [deleteRule, setDeleteRule] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ matched_count: number; sample_subjects: string[] } | null>(null)
  const [testing, setTesting] = useState<string | null>(null)

  const fetchRules = async () => {
    setLoading(true)
    try {
      const res = await api.get('/api/spam/rules')
      setRules(res.data || [])
    } catch (e) { console.error(e) } finally { setLoading(false) }
  }

  useEffect(() => { fetchRules() }, [])

  const handleSaveNew = async (data: { name: string; description: string; rule_type: string; match_value: string; action: string; enabled: boolean }) => {
    await api.post('/api/spam/rules', data)
    setShowForm(false)
    await fetchRules()
  }

  const handleSaveEdit = async (data: { name: string; description: string; rule_type: string; match_value: string; action: string; enabled: boolean }) => {
    if (!editRule) return
    await api.patch(`/api/spam/rules/${editRule.id}`, data)
    setEditRule(null)
    await fetchRules()
  }

  const handleDelete = async (id: string) => {
    await api.delete(`/api/spam/rules/${id}`)
    setDeleteRule(null)
    await fetchRules()
  }

  const handleToggle = async (rule: SpamRule) => {
    await api.patch(`/api/spam/rules/${rule.id}`, { enabled: !rule.enabled })
    await fetchRules()
  }

  const handleTest = async (rule: SpamRule) => {
    setTesting(rule.id)
    try {
      const res = await api.post('/api/spam/rules/test', { rule_type: rule.rule_type, match_value: rule.match_value })
      setTestResult(res.data)
    } catch (e) { console.error(e) } finally { setTesting(null) }
  }

  return (
    <div className="space-y-5">
      {showForm && <RuleFormModal onSave={handleSaveNew} onClose={() => setShowForm(false)} />}
      {editRule && <RuleFormModal initial={{ ...editRule, description: editRule.description ?? undefined }} onSave={handleSaveEdit} onClose={() => setEditRule(null)} />}
      {deleteRule && (
        <ConfirmModal
          title="Delete Rule" message="Delete this rule permanently?"
          confirmLabel="Delete" danger
          onConfirm={() => handleDelete(deleteRule)}
          onCancel={() => setDeleteRule(null)}
        />
      )}
      {testResult && <TestResult result={testResult} onClose={() => setTestResult(null)} />}

      <div className="flex items-center justify-between">
        <p className="text-sm text-[var(--muted)]">
          Define rules to automatically act on matching spam — whitelist senders, auto-release marketing, etc.
        </p>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-sm font-medium transition-colors"
        >
          <Plus size={14} /> Add Rule
        </button>
      </div>

      <div className="bg-[#141417] border border-white/10 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 bg-white/5">
                {['Name', 'Type', 'Match Value', 'Action', 'Status', 'Hit Count', 'Last Hit', 'Actions'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-[11px] font-semibold text-[var(--muted)] uppercase tracking-wide whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-[var(--muted)]">
                  <RefreshCw size={16} className="animate-spin inline mr-2" />Loading…
                </td></tr>
              )}
              {!loading && rules.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-12 text-center">
                  <Shield size={32} className="mx-auto mb-3 text-[var(--muted)] opacity-40" />
                  <p className="text-[var(--muted)] text-sm">No rules yet.</p>
                  <p className="text-[var(--muted)] text-xs mt-1">Click "Add Rule" to create your first anti-spam rule.</p>
                </td></tr>
              )}
              {!loading && rules.map((rule) => (
                <tr key={rule.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                  <td className="px-4 py-3">
                    <div className="text-white text-xs font-medium">{rule.name}</div>
                    {rule.description && <div className="text-[10px] text-[var(--muted)] mt-0.5 truncate max-w-[160px]">{rule.description}</div>}
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 rounded text-[11px] bg-white/10 text-[var(--muted)] font-mono">{rule.rule_type}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-[var(--muted)] font-mono max-w-[140px] truncate">{rule.match_value}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded-full text-[11px] border ${rule.action === 'MOVE_TO_INBOX' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
                      {rule.action.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => handleToggle(rule)} className={`transition-colors ${rule.enabled ? 'text-indigo-400' : 'text-[var(--muted)]'}`}>
                      {rule.enabled ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
                    </button>
                  </td>
                  <td className="px-4 py-3 text-xs text-[var(--muted)]">{rule.hit_count}</td>
                  <td className="px-4 py-3 text-xs text-[var(--muted)] whitespace-nowrap">{fmt(rule.last_hit_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1.5">
                      <button
                        onClick={() => handleTest(rule)}
                        disabled={testing === rule.id}
                        title="Test rule against existing spam"
                        className="p-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 transition-colors disabled:opacity-50"
                      >
                        {testing === rule.id ? <RefreshCw size={12} className="animate-spin" /> : <Zap size={12} />}
                      </button>
                      <button
                        onClick={() => setEditRule(rule)}
                        title="Edit rule"
                        className="p-1.5 rounded-lg bg-white/10 hover:bg-white/20 text-[var(--muted)] transition-colors"
                      >
                        <Edit2 size={12} />
                      </button>
                      <button
                        onClick={() => setDeleteRule(rule.id)}
                        title="Delete rule"
                        className="p-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition-colors"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function SpamPage() {
  const [tab, setTab] = useState<SpamTab>('inbox')

  return (
    <div className="flex flex-col h-full bg-[#0c0c0e] text-white">
      {/* Header */}
      <div className="px-6 py-4 border-b border-white/10 flex-shrink-0">
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Spam Center</h1>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 px-6 pt-4 border-b border-white/10 flex-shrink-0">
        {([
          { id: 'inbox', label: 'Spam Inbox', icon: <MailWarning size={14} /> },
          { id: 'rules', label: 'Anti-Spam Rules', icon: <Shield size={14} /> },
        ] as const).map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px ${
              tab === t.id
                ? 'border-indigo-500 text-white'
                : 'border-transparent text-[var(--muted)] hover:text-white'
            }`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-6">
        {tab === 'inbox' ? <SpamInboxTab /> : <AntiSpamRulesTab />}
      </div>
    </div>
  )
}
