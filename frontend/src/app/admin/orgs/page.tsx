'use client'
import { useEffect, useState, useCallback } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { adminFetch } from '@/lib/adminAuth'
import {
  Plus, Search, Eye, PauseCircle, PlayCircle,
  Trash2, ChevronLeft, ChevronRight, Zap, AlertCircle,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

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
  contact_email?: string
  created_at: string
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

const PAGE_SIZE = 20

// ─── Delete confirm dialog ────────────────────────────────────────────────────

function DeleteDialog({
  orgName,
  onConfirm,
  onCancel,
  loading,
}: {
  orgName: string
  onConfirm: () => void
  onCancel: () => void
  loading: boolean
}) {
  const [input, setInput] = useState('')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#111118] border border-red-800 rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <div className="flex items-center gap-2 mb-1">
          <Trash2 className="w-4 h-4 text-red-400" />
          <h2 className="text-white font-semibold">Delete Organization</h2>
        </div>
        <p className="text-[#a0a0c0] text-sm mb-4">
          This will permanently offboard <span className="text-white font-medium">{orgName}</span>. Data is retained for 90 days before purge.
        </p>
        <p className="text-red-400 text-sm mb-2">
          Type <span className="font-mono font-bold text-red-300">{orgName}</span> to confirm:
        </p>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder={orgName}
          className="w-full bg-[#1a1a28] border border-[#2a2a3a] rounded-lg px-3 py-2 text-white text-sm placeholder-[#6060a0] focus:outline-none focus:border-red-600 mb-4"
          autoFocus
        />
        <div className="flex gap-3 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 bg-[#1a1a28] border border-[#2a2a3a] hover:bg-[#2a2a3a] text-white rounded-lg text-sm transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={input !== orgName || loading}
            className="px-4 py-2 bg-red-700 hover:bg-red-600 disabled:opacity-40 disabled:cursor-not-allowed text-white rounded-lg text-sm transition-colors"
          >
            {loading ? 'Deleting…' : 'Delete Organization'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Main ─────────────────────────────────────────────────────────────────────

export default function AdminOrgs() {
  const router = useRouter()
  const [allOrgs, setAllOrgs] = useState<Org[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [planFilter, setPlanFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(1)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Org | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const data = await adminFetch('/api/admin/orgs')
      setAllOrgs(Array.isArray(data) ? data : [])
    } catch (e: any) {
      setError(e.message || 'Failed to load organizations')
    }
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  // Client-side filter
  const filtered = allOrgs.filter(o => {
    if (planFilter && o.plan !== planFilter) return false
    if (statusFilter && o.status !== statusFilter) return false
    if (search) {
      const q = search.toLowerCase()
      if (!o.name.toLowerCase().includes(q) && !o.domain.toLowerCase().includes(q)) return false
    }
    return true
  })

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  const rangeStart = filtered.length === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const rangeEnd = Math.min(page * PAGE_SIZE, filtered.length)

  // Reset page on filter change
  useEffect(() => { setPage(1) }, [search, planFilter, statusFilter])

  async function handleSuspend(orgId: string) {
    if (!confirm('Suspend this organization? All users will be deactivated.')) return
    setActionLoading(orgId)
    try {
      await adminFetch(`/api/admin/orgs/${orgId}/suspend`, { method: 'POST' })
      // Optimistic update
      setAllOrgs(prev => prev.map(o => o.org_id === orgId ? { ...o, status: 'suspended' } : o))
    } catch {
      alert('Failed to suspend')
    }
    setActionLoading(null)
  }

  async function handleReactivate(orgId: string) {
    setActionLoading(orgId)
    try {
      await adminFetch(`/api/admin/orgs/${orgId}/reactivate`, { method: 'POST' })
      setAllOrgs(prev => prev.map(o => o.org_id === orgId ? { ...o, status: 'active' } : o))
    } catch {
      alert('Failed to reactivate')
    }
    setActionLoading(null)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setActionLoading(deleteTarget.org_id)
    try {
      await adminFetch(`/api/admin/orgs/${deleteTarget.org_id}`, { method: 'DELETE' })
      setAllOrgs(prev => prev.filter(o => o.org_id !== deleteTarget.org_id))
      setDeleteTarget(null)
    } catch {
      alert('Failed to delete organization')
    }
    setActionLoading(null)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-white text-2xl font-bold">Organizations</h1>
          <p className="text-[#a0a0c0] text-sm mt-1">
            {filtered.length} of {allOrgs.length} customer tenant{allOrgs.length !== 1 ? 's' : ''}
          </p>
        </div>
        <Link
          href="/admin/orgs/new"
          className="flex items-center gap-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Organization
        </Link>
      </div>

      {error && (
        <div className="bg-red-900/20 border border-red-700 rounded-xl p-4 text-red-300 flex items-center gap-2 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6060a0]" />
          <input
            placeholder="Search by name or domain…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="bg-[#1a1a28] border border-[#2a2a3a] rounded-lg pl-9 pr-4 py-2 text-[#e0e0ff] text-sm placeholder-[#6060a0] focus:outline-none focus:ring-[var(--accent)]/50 focus:border-[var(--accent)] w-64"
          />
        </div>
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-[#111118] border border-[#2a2a3a] rounded-lg px-3 py-2 text-[#d0d0f0] text-sm focus:outline-none focus:border-[var(--accent)]"
        >
          <option value="">All Status</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="trial">Trial</option>
          <option value="offboarded">Offboarded</option>
        </select>
        <select
          value={planFilter}
          onChange={e => setPlanFilter(e.target.value)}
          className="bg-[#111118] border border-[#2a2a3a] rounded-lg px-3 py-2 text-[#d0d0f0] text-sm focus:outline-none focus:border-[var(--accent)]"
        >
          <option value="">All Plans</option>
          <option value="starter">Starter</option>
          <option value="professional">Professional</option>
          <option value="enterprise">Enterprise</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-[#111118] border border-[#2a2a3a] rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-48">
            <div className="w-6 h-6 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-[#2a2a3a] bg-[#111118]/80">
                <tr>
                  {['Org Name', 'Domain', 'Plan', 'Status', 'Inboxes', 'Emails MTD', 'Cost MTD', 'Auto-Triage', 'Created', 'Actions'].map(h => (
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
                {paginated.map(org => (
                  <tr key={org.org_id} className="hover:bg-[#1a1a28]/40 transition-colors group">
                    <td className="px-4 py-3">
                      <button
                        onClick={() => router.push(`/admin/orgs/${org.org_id}`)}
                        className="text-white text-sm font-medium hover:text-[var(--accent)] transition-colors text-left"
                      >
                        {org.name}
                      </button>
                    </td>
                    <td className="px-4 py-3 text-[#a0a0c0] text-sm font-mono">{org.domain}</td>
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
                        <span className="text-[#6060a0] text-xs">OFF</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-[#6060a0] text-xs whitespace-nowrap">
                      {org.created_at ? new Date(org.created_at).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <Link
                          href={`/admin/orgs/${org.org_id}`}
                          className="p-1.5 rounded text-[#a0a0c0] hover:text-white hover:bg-[#2a2a3a] transition-colors"
                          title="View Details"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </Link>
                        {org.status === 'active' ? (
                          <button
                            onClick={() => handleSuspend(org.org_id)}
                            disabled={actionLoading === org.org_id}
                            className="p-1.5 rounded text-[#a0a0c0] hover:text-red-400 hover:bg-[#2a2a3a] transition-colors disabled:opacity-40"
                            title="Suspend"
                          >
                            <PauseCircle className="w-3.5 h-3.5" />
                          </button>
                        ) : org.status === 'suspended' ? (
                          <button
                            onClick={() => handleReactivate(org.org_id)}
                            disabled={actionLoading === org.org_id}
                            className="p-1.5 rounded text-[#a0a0c0] hover:text-green-400 hover:bg-[#2a2a3a] transition-colors disabled:opacity-40"
                            title="Reactivate"
                          >
                            <PlayCircle className="w-3.5 h-3.5" />
                          </button>
                        ) : null}
                        <button
                          onClick={() => setDeleteTarget(org)}
                          className="p-1.5 rounded text-[#a0a0c0] hover:text-red-400 hover:bg-[#2a2a3a] transition-colors opacity-0 group-hover:opacity-100"
                          title="Delete"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {paginated.length === 0 && (
                  <tr>
                    <td colSpan={10} className="px-4 py-12 text-center text-[#6060a0]">
                      {search || planFilter || statusFilter
                        ? 'No organizations match your filters'
                        : 'No organizations yet'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-[#2a2a3a]">
            <p className="text-[#a0a0c0] text-sm">
              {rangeStart}–{rangeEnd} of {filtered.length}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-1.5 rounded text-[#a0a0c0] hover:text-white hover:bg-[#2a2a3a] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-[#a0a0c0] text-sm px-2">
                {page} / {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-1.5 rounded text-[#a0a0c0] hover:text-white hover:bg-[#2a2a3a] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Delete confirmation dialog */}
      {deleteTarget && (
        <DeleteDialog
          orgName={deleteTarget.name}
          onConfirm={handleDelete}
          onCancel={() => setDeleteTarget(null)}
          loading={actionLoading === deleteTarget.org_id}
        />
      )}
    </div>
  )
}
