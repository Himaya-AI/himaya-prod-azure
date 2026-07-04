'use client'
import React, { useEffect, useState } from 'react'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import { Badge } from '@/components/ui/Badge'
import api from '@/lib/api'
import type { Employee } from '@/lib/types'
import { Search, ShieldAlert, Star, Info, ChevronDown, ChevronUp, Users, TrendingUp, Shield, Mail, Hash } from 'lucide-react'

// ── Email Groups / Distribution Lists ─────────────────────────────────────────

interface EmailGroup {
  id: string
  email: string
  name: string
  description: string
  member_count: number
  members: string[]
  threat_hits: number
  provider: string
  is_shared_mailbox?: boolean
}

function EmailGroupsPanel() {
  const [groups, setGroups] = useState<EmailGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(true)
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null)

  useEffect(() => {
    api.get('/api/people/groups')
      .then(r => setGroups(r.data?.items ?? []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  if (!loading && groups.length === 0) return null

  const totalThreatHits = groups.reduce((s, g) => s + (g.threat_hits || 0), 0)

  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex items-center gap-2">
          <Mail size={14} className="text-[#3b6ef6]" />
          <span className="text-[13px] font-semibold text-white">Email Groups & Distribution Lists</span>
          {!loading && (
            <span className="text-[11px] text-slate-500">· {groups.length} group{groups.length !== 1 ? 's' : ''}</span>
          )}
          {totalThreatHits > 0 && (
            <span className="ml-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-red-500/15 text-red-400">
              {totalThreatHits} threat hit{totalThreatHits !== 1 ? 's' : ''}
            </span>
          )}
        </div>
        {expanded ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />}
      </button>

      {expanded && (
        <div className="border-t border-white/[0.05]">
          {loading ? (
            <div className="p-5 space-y-3">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="h-10 animate-pulse bg-white/[0.04] rounded" />
              ))}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/[0.05] text-[#71717a] text-xs font-medium">
                    <th className="text-left px-5 py-3">Group Name</th>
                    <th className="text-left px-5 py-3">Email Address</th>
                    <th className="text-left px-5 py-3">Members</th>
                    <th className="text-left px-5 py-3">Threat Hits</th>
                    <th className="text-left px-5 py-3">Provider</th>
                    <th className="text-left px-5 py-3">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.map((g) => (
                    <React.Fragment key={g.id}>
                    <tr
                      key={g.id}
                      className="border-b border-white/[0.03] hover:bg-white/[0.01] transition-colors cursor-pointer"
                      onClick={() => setExpandedGroup(expandedGroup === g.id ? null : g.id)}
                    >
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${g.is_shared_mailbox ? 'bg-amber-500/10' : 'bg-[#3b6ef6]/10'}`}>
                            <Users size={12} className={g.is_shared_mailbox ? 'text-amber-400' : 'text-[#3b6ef6]'} />
                          </div>
                          <div className="flex flex-col">
                            <div className="flex items-center gap-1.5">
                              <span className="text-[13px] font-medium text-[#e4e4e7]">{g.name}</span>
                              {g.is_shared_mailbox && (
                                <span className="px-1.5 py-0 rounded text-[9px] font-semibold bg-amber-500/10 text-amber-500 uppercase tracking-wide">Shared</span>
                              )}
                            </div>
                          </div>
                          {(g.members?.length ?? 0) > 0 && (
                            expandedGroup === g.id
                              ? <ChevronUp size={11} className="text-slate-600 ml-1" />
                              : <ChevronDown size={11} className="text-slate-600 ml-1" />
                          )}
                        </div>
                      </td>
                      <td className="px-5 py-3 text-[12px] font-mono text-[#71717a]">{g.email}</td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-1 text-[12px] text-slate-300">
                          <Hash size={11} className="text-slate-600" />
                          {Math.max(g.member_count || 0, g.members?.length ?? 0) || '—'}
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        {(g.threat_hits ?? 0) > 0 ? (
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/15 text-red-400">
                            {g.threat_hits}
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-600">0</span>
                        )}
                      </td>
                      <td className="px-5 py-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          g.provider === 'google' ? 'bg-blue-500/10 text-blue-400' : 'bg-purple-500/10 text-purple-400'
                        }`}>
                          {g.provider === 'google' ? 'Google Workspace' : 'Microsoft 365'}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-[11px] text-[#71717a] max-w-[200px] truncate">
                        {g.is_shared_mailbox ? 'Shared Mailbox' : (g.description || '—')}
                      </td>
                    </tr>
                    {expandedGroup === g.id && (
                      <tr key={`${g.id}-members`} className="bg-[#0e0e11]">
                        <td colSpan={6} className="px-8 py-3">
                          {(g.members?.length ?? 0) > 0 ? (
                            <>
                              <div className="text-[11px] text-slate-500 mb-2 font-medium">
                                {g.is_shared_mailbox ? 'DELEGATES / MEMBERS' : 'MEMBERS'} ({g.members!.length}{g.member_count > g.members!.length ? ` of ${g.member_count}` : ''})
                              </div>
                              <div className="flex flex-wrap gap-1.5">
                                {g.members!.map(m => (
                                  <span key={m} className="px-2 py-0.5 rounded bg-white/[0.04] text-[11px] font-mono text-slate-400">
                                    {m}
                                  </span>
                                ))}
                                {g.member_count > g.members!.length && (
                                  <span className="px-2 py-0.5 rounded bg-white/[0.04] text-[11px] text-slate-600">
                                    +{g.member_count - g.members!.length} more
                                  </span>
                                )}
                              </div>
                            </>
                          ) : (
                            <div className="text-[11px] text-slate-600 italic">No members found</div>
                          )}
                        </td>
                      </tr>
                    )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function riskVariant(score: number) {
  if (score >= 80) return 'danger'
  if (score >= 60) return 'warning'
  if (score >= 40) return 'info'
  return 'success'
}

function riskLabel(score: number) {
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 40) return 'Medium'
  return 'Low'
}

// ── VIP Criteria Callout ───────────────────────────────────────────────────────
function VipCriteriaPanel({ expanded, onToggle }: { expanded: boolean; onToggle: () => void }) {
  return (
    <div className="bg-amber-900/10 border border-amber-600/20 rounded-xl overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-amber-900/10 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Star size={13} className="text-amber-400 fill-amber-400" />
          <span className="text-[13px] font-semibold text-amber-300">VIP Designation Criteria</span>
          <span className="text-[11px] text-amber-600">· click to {expanded ? 'hide' : 'learn more'}</span>
        </div>
        {expanded ? <ChevronUp size={13} className="text-amber-600" /> : <ChevronDown size={13} className="text-amber-600" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 grid grid-cols-1 md:grid-cols-3 gap-3 border-t border-amber-600/10">
          {/* Threshold 1: Executive title */}
          <div className="bg-[#141417] border border-white/[0.06] rounded-xl p-3.5">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-6 h-6 rounded-lg bg-amber-500/10 flex items-center justify-center">
                <Shield size={12} className="text-amber-400" />
              </div>
              <span className="text-[12px] font-semibold text-slate-200">Executive Title</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed mb-2">
              User has a C-suite or senior leadership job title recognized by Helios.
            </p>
            <div className="flex flex-wrap gap-1">
              {['CEO', 'CFO', 'CTO', 'CISO', 'COO', 'Director', 'VP', 'Head of', 'President', 'Partner'].map(t => (
                <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-amber-900/20 text-amber-400 border border-amber-700/30 font-mono">
                  {t}
                </span>
              ))}
            </div>
          </div>

          {/* Threshold 2: Threat count */}
          <div className="bg-[#141417] border border-white/[0.06] rounded-xl p-3.5">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-6 h-6 rounded-lg bg-red-500/10 flex items-center justify-center">
                <ShieldAlert size={12} className="text-red-400" />
              </div>
              <span className="text-[12px] font-semibold text-slate-200">High-Value Target</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              User has received <span className="text-amber-300 font-semibold">10 or more threats</span> in the past 30 days — indicating they are being actively targeted and require elevated protection.
            </p>
          </div>

          {/* Threshold 3: Manual flag */}
          <div className="bg-[#141417] border border-white/[0.06] rounded-xl p-3.5">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-6 h-6 rounded-lg bg-blue-500/10 flex items-center justify-center">
                <Star size={12} className="text-blue-400" />
              </div>
              <span className="text-[12px] font-semibold text-slate-200">Manually Designated</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              VIP flag was manually set by an administrator. This overrides automatic detection and applies regardless of title or threat count.
            </p>
          </div>

          <div className="md:col-span-3 px-1">
            <p className="text-[11px] text-slate-500 leading-relaxed">
              <span className="text-amber-400 font-medium">VIP effect:</span> VIP users receive priority investigation, enhanced monitoring, and higher-priority alerts. Their emails are analysed first in the processing queue.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Stats Row ──────────────────────────────────────────────────────────────────
function StatsRow({ employees }: { employees: Employee[] }) {
  const total = employees.length
  const vip = employees.filter(e => e.is_vip).length
  const highRisk = employees.filter(e => (e.risk_score ?? 0) >= 60).length
  const withThreats = employees.filter(e => (e.threats_30d ?? 0) > 0).length

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {[
        { label: 'Total Users', value: total, icon: <Users size={14} />, color: 'text-[#3b6ef6]' },
        { label: 'VIP Users', value: vip, icon: <Star size={14} className="fill-amber-400" />, color: 'text-amber-400' },
        { label: 'High Risk (60+)', value: highRisk, icon: <TrendingUp size={14} />, color: 'text-red-400' },
        { label: 'Active Threats (30d)', value: withThreats, icon: <ShieldAlert size={14} />, color: 'text-orange-400' },
      ].map(({ label, value, icon, color }) => (
        <div key={label} className="bg-[#141417] border border-white/[0.06] rounded-xl p-3.5 flex items-center gap-3">
          <span className={color}>{icon}</span>
          <div>
            <p className="text-[11px] text-slate-500">{label}</p>
            <p className={`text-xl font-bold ${color}`}>{value}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

export default function PeoplePage() {
  const [employees, setEmployees] = useState<Employee[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filterVip, setFilterVip] = useState(false)
  const [filterHighRisk, setFilterHighRisk] = useState(false)
  const [error, setError] = useState('')
  const [showVipInfo, setShowVipInfo] = useState(false)
  const [togglingVip, setTogglingVip] = useState<string | null>(null)

  const loadEmployees = () => {
    api.get('/api/people')
      .then(r => setEmployees(Array.isArray(r.data) ? r.data : (r.data?.items ?? [])))
      .catch(() => setError('Failed to load employees'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { loadEmployees() }, [])

  const toggleVip = async (empId: string) => {
    setTogglingVip(empId)
    try {
      await api.post(`/api/people/${empId}/vip`)
      // Optimistically update local state
      setEmployees(prev => prev.map(e => e.id === empId ? { ...e, is_vip: !e.is_vip } : e))
    } catch {
      // revert via full reload
      loadEmployees()
    }
    setTogglingVip(null)
  }

  const filtered = employees.filter(e => {
    if (filterVip && !e.is_vip) return false
    if (filterHighRisk && (e.risk_score ?? 0) < 60) return false
    if (search) {
      const s = search.toLowerCase()
      return e.name?.toLowerCase().includes(s) || e.email?.toLowerCase().includes(s)
    }
    return true
  })

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">People & Inbox Risk</h1>
      </div>

      {/* Stats */}
      {!loading && employees.length > 0 && <StatsRow employees={employees} />}

      {/* VIP criteria callout */}
      <VipCriteriaPanel expanded={showVipInfo} onToggle={() => setShowVipInfo(v => !v)} />

      {/* Email Groups & Distribution Lists */}
      <EmailGroupsPanel />

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            placeholder="Search by name or email…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-[#141417] border border-white/[0.07] rounded-lg text-[13px] text-slate-300 placeholder-slate-600 focus:outline-none focus:border-[#3b6ef6]/50 transition-colors"
          />
        </div>
        <button
          onClick={() => setFilterVip(v => !v)}
          className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-[12px] font-medium border transition-all ${
            filterVip
              ? 'bg-amber-500/15 border-amber-500/40 text-amber-300'
              : 'bg-[#141417] border-white/[0.07] text-slate-400 hover:text-slate-200'
          }`}
        >
          <Star size={12} className={filterVip ? 'fill-amber-400 text-amber-400' : ''} />
          VIP only
        </button>
        <button
          onClick={() => setFilterHighRisk(v => !v)}
          className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-[12px] font-medium border transition-all ${
            filterHighRisk
              ? 'bg-red-900/20 border-red-700/40 text-red-300'
              : 'bg-[#141417] border-white/[0.07] text-slate-400 hover:text-slate-200'
          }`}
        >
          <TrendingUp size={12} />
          High risk only
        </button>
        {(search || filterVip || filterHighRisk) && (
          <button
            onClick={() => { setSearch(''); setFilterVip(false); setFilterHighRisk(false) }}
            className="text-[11px] text-slate-500 hover:text-slate-300 transition-colors"
          >
            Clear filters
          </button>
        )}
        <span className="text-[11px] text-slate-600 ml-auto">
          {filtered.length} of {employees.length} users
        </span>
      </div>

      {error && <div className="text-red-400 text-sm">{error}</div>}

      {/* Table */}
      <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th>Name / Email</Th>
              <Th>Risk Score</Th>
              <Th>Threats (30 Days)</Th>
              <Th>Last Threat</Th>
              <Th>VIP</Th>
            </Tr>
          </Thead>
          <Tbody>
            {loading ? (
              [...Array(6)].map((_, i) => (
                <Tr key={i}>
                  {[...Array(5)].map((_, j) => (
                    <Td key={j}><div className="h-4 animate-pulse bg-white/[0.04] rounded w-24" /></Td>
                  ))}
                </Tr>
              ))
            ) : filtered.map(emp => (
              <Tr key={emp.id}>
                <Td>
                  <div className="flex items-center gap-2">
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span className="font-medium text-[#e4e4e7] text-[13px]">{emp.name || emp.email}</span>
                        {emp.is_vip && (
                          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30 uppercase tracking-wide">
                            <Star size={8} className="fill-amber-400" /> VIP
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-[#71717a] font-mono">{emp.email}</div>
                    </div>
                  </div>
                </Td>
                <Td>
                  <div className="flex items-center gap-2">
                    <Badge variant={riskVariant(emp.risk_score ?? 0)}>
                      {emp.risk_score ?? 0}
                    </Badge>
                    <span className={`text-[10px] font-medium ${
                      (emp.risk_score ?? 0) >= 80 ? 'text-red-400' :
                      (emp.risk_score ?? 0) >= 60 ? 'text-amber-400' :
                      (emp.risk_score ?? 0) >= 40 ? 'text-blue-400' : 'text-emerald-400'
                    }`}>
                      {riskLabel(emp.risk_score ?? 0)}
                    </span>
                  </div>
                </Td>
                <Td>
                  {(emp.threats_30d ?? 0) > 0 ? (
                    <div className="flex items-center gap-1.5">
                      <ShieldAlert size={13} className="text-red-400" />
                      <span className="text-red-300 font-semibold text-[13px]">{emp.threats_30d}</span>
                      {(emp.threats_30d ?? 0) >= 10 && (
                        <span className="text-[9px] text-amber-400 border border-amber-700/40 px-1 py-0.5 rounded bg-amber-900/20 font-semibold">
                          VIP eligible
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="text-[#52525b] text-[13px]">—</span>
                  )}
                </Td>
                <Td className="text-[11px] text-[#71717a]">
                  {emp.last_threat_at
                    ? new Date(emp.last_threat_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
                    : '—'}
                </Td>
                <Td>
                  <button
                    onClick={() => toggleVip(emp.id)}
                    disabled={togglingVip === emp.id}
                    title={emp.is_vip ? 'Remove VIP designation' : 'Tag as VIP'}
                    className={`flex items-center gap-1 px-2 py-1 rounded-lg text-[11px] font-semibold border transition-all ${
                      emp.is_vip
                        ? 'bg-amber-500/15 border-amber-500/40 text-amber-400 hover:bg-amber-500/25'
                        : 'bg-white/[0.04] border-white/[0.07] text-slate-500 hover:text-amber-400 hover:border-amber-500/30'
                    } disabled:opacity-50`}
                  >
                    <Star size={10} className={emp.is_vip ? 'fill-amber-400 text-amber-400' : ''} />
                    {togglingVip === emp.id ? '…' : emp.is_vip ? 'VIP ✓' : 'Tag VIP'}
                  </button>
                </Td>
              </Tr>
            ))}
            {!loading && filtered.length === 0 && (
              <Tr>
                <Td colSpan={5} className="text-center text-[#52525b] py-12 text-[13px]">
                  {search || filterVip || filterHighRisk ? 'No users match the active filters.' : 'No employees found.'}
                </Td>
              </Tr>
            )}
          </Tbody>
        </Table>
      </div>
    </div>
  )
}
