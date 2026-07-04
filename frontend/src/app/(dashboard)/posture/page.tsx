'use client'
import { useEffect, useState, useCallback } from 'react'
import { Shield, AlertTriangle, CheckCircle2, RefreshCw, Trash2, ExternalLink, Info, ChevronDown, ChevronUp, Mail, Inbox, ArrowRight, XCircle, Eye, EyeOff, Forward, Zap } from 'lucide-react'
import Button from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import api from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface OAuthApp {
  id: string
  name: string
  description?: string
  provider: 'm365' | 'google'
  scopes: string[]
  granted_by?: string
  granted_at?: string
  risk: 'high' | 'medium' | 'low'
  risk_reasons: string[]
  can_revoke: boolean
}

interface InboxRule {
  id: string
  name: string
  mailbox: string
  provider: 'm365' | 'google'
  enabled: boolean
  conditions: string
  actions: string
  risk: 'high' | 'medium' | 'low'
  risk_reasons: string[]
  created_at?: string
}

interface ForwardRule {
  id: string
  mailbox: string
  provider: 'm365' | 'google'
  forward_to: string
  is_external: boolean
  risk: 'high' | 'medium' | 'low'
}

interface PostureSummary {
  posture_score: number
  high_risk_apps: number
  high_risk_rules: number
  external_forwards: number
  total_apps: number
  total_rules: number
  total_forwards: number
  last_scanned?: string
}

type Tab = 'apps' | 'rules' | 'forwards'

const RISK_COLOR: Record<string, string> = {
  high: 'text-red-400',
  medium: 'text-amber-400',
  low: 'text-emerald-400',
}
const RISK_BG: Record<string, string> = {
  high: 'bg-red-500/10 border-red-500/20 text-red-400',
  medium: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
  low: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
}

function ScoreRing({ score }: { score: number }) {
  const r = 36
  const circ = 2 * Math.PI * r
  const fill = (score / 100) * circ
  const color = score >= 80 ? '#4ade80' : score >= 60 ? '#fbbf24' : '#f87171'
  return (
    <div className="relative w-24 h-24 flex items-center justify-center">
      <svg width="96" height="96" className="-rotate-90">
        <circle cx="48" cy="48" r={r} fill="none" stroke="#1e1e24" strokeWidth="8" />
        <circle
          cx="48" cy="48" r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={`${fill} ${circ - fill}`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 1s ease' }}
        />
      </svg>
      <div className="absolute text-center">
        <div className="text-2xl font-bold" style={{ color }}>{score}</div>
        <div className="text-[10px] text-[#71717a] -mt-0.5">/ 100</div>
      </div>
    </div>
  )
}

function RiskBadge({ risk }: { risk: 'high' | 'medium' | 'low' }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${RISK_BG[risk]}`}>
      {risk === 'high' ? <AlertTriangle size={10} /> : risk === 'medium' ? <Info size={10} /> : <CheckCircle2 size={10} />}
      {risk.charAt(0).toUpperCase() + risk.slice(1)}
    </span>
  )
}

function ProviderBadge({ provider }: { provider: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold ${
      provider === 'm365' ? 'bg-purple-900/40 text-purple-300' : 'bg-blue-900/40 text-blue-300'
    }`}>
      {provider === 'm365' ? 'M365' : 'Google'}
    </span>
  )
}

// ── OAuth Apps Tab ─────────────────────────────────────────────────────────────
function AppsTab({ apps, loading, onRevoke, revoking }: {
  apps: OAuthApp[]
  loading: boolean
  onRevoke: (app: OAuthApp) => void
  revoking: string | null
}) {
  const [expanded, setExpanded] = useState<string | null>(null)

  if (loading) return <LoadingSkeleton rows={5} cols={6} />

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-3 px-4 py-3 bg-[#3b6ef6]/[0.06] border border-[#3b6ef6]/20 rounded-xl text-[12px] text-[#93b4fd]">
        <Info size={13} className="mt-0.5 flex-shrink-0" />
        <span>These are third-party apps with OAuth access to your organization's mailboxes. High-risk apps have permissions that could be used to read, send, or delete email at scale.</span>
      </div>
      <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th>Application</Th>
              <Th>Provider</Th>
              <Th>Scopes</Th>
              <Th>Granted By</Th>
              <Th>Risk</Th>
              <Th></Th>
            </Tr>
          </Thead>
          <Tbody>
            {apps.length === 0 && (
              <Tr><Td colSpan={6} className="text-center text-[#71717a] py-10 text-[13px]">No OAuth apps found</Td></Tr>
            )}
            {apps.map(app => (
              <>
                <Tr key={app.id}>
                  <Td>
                    <div className="font-medium text-[var(--foreground)] text-[13px]">{app.name}</div>
                    {app.description && <div className="text-[11px] text-[#71717a] mt-0.5 max-w-xs truncate">{app.description}</div>}
                  </Td>
                  <Td><ProviderBadge provider={app.provider} /></Td>
                  <Td className="max-w-[200px]">
                    <div className="flex flex-wrap gap-1">
                      {app.scopes.slice(0, 2).map(s => (
                        <span key={s} className="text-[10px] font-mono bg-[#1e1e24] border border-white/[0.07] rounded px-1.5 py-0.5 text-[#a1a1aa] break-all">{s.length > 30 ? s.split('.').pop() || s : s}</span>
                      ))}
                      {app.scopes.length > 2 && (
                        <span className="text-[10px] text-[#71717a] whitespace-nowrap">+{app.scopes.length - 2} more</span>
                      )}
                    </div>
                  </Td>
                  <Td className="text-[12px] text-[#71717a] max-w-[120px] truncate" title={app.granted_by || ''}>{app.granted_by || '—'}</Td>
                  <Td><RiskBadge risk={app.risk} /></Td>
                  <Td>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setExpanded(expanded === app.id ? null : app.id)}
                        className="text-[11px] text-[#71717a] hover:text-white transition-colors"
                      >
                        {expanded === app.id ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                      {app.can_revoke && (
                        <button
                          onClick={() => onRevoke(app)}
                          disabled={revoking === app.id}
                          className="text-[11px] text-red-400/70 hover:text-red-400 px-2 py-1 rounded hover:bg-red-500/10 transition-colors disabled:opacity-50"
                        >
                          {revoking === app.id ? 'Revoking…' : 'Revoke'}
                        </button>
                      )}
                    </div>
                  </Td>
                </Tr>
                {expanded === app.id && (
                  <Tr key={`${app.id}-detail`}>
                    <Td colSpan={6} className="bg-[#0d0d10] border-t border-white/[0.05]">
                      <div className="px-2 py-3 space-y-2">
                        <div className="text-[11px] font-semibold text-[#71717a] uppercase tracking-wide mb-2">Risk Reasons</div>
                        {app.risk_reasons.length === 0
                          ? <p className="text-[12px] text-[#52525b]">No specific risk factors flagged.</p>
                          : app.risk_reasons.map((r, i) => (
                            <div key={i} className="flex items-start gap-2 text-[12px] text-[#d4d4d8]">
                              <AlertTriangle size={12} className={`mt-0.5 flex-shrink-0 ${RISK_COLOR[app.risk]}`} />
                              {r}
                            </div>
                          ))
                        }
                        <div className="text-[11px] font-semibold text-[#71717a] uppercase tracking-wide mt-3 mb-1">All Scopes</div>
                        <div className="flex flex-wrap gap-1">
                          {app.scopes.map(s => (
                            <span key={s} className="text-[10px] font-mono bg-[#1e1e24] border border-white/[0.07] rounded px-2 py-0.5 text-[#a1a1aa]">{s}</span>
                          ))}
                        </div>
                      </div>
                    </Td>
                  </Tr>
                )}
              </>
            ))}
          </Tbody>
        </Table>
      </div>
    </div>
  )
}

// ── Inbox Rules Tab ────────────────────────────────────────────────────────────
function RulesTab({ rules, loading, onDelete, deleting }: {
  rules: InboxRule[]
  loading: boolean
  onDelete: (rule: InboxRule) => void
  deleting: string | null
}) {
  if (loading) return <LoadingSkeleton rows={5} cols={7} />

  const high = rules.filter(r => r.risk === 'high')

  return (
    <div className="space-y-3">
      <div className="flex items-start gap-3 px-4 py-3 bg-amber-500/[0.06] border border-amber-500/20 rounded-xl text-[12px] text-amber-300">
        <AlertTriangle size={13} className="mt-0.5 flex-shrink-0" />
        <span>Suspicious inbox rules can be used by attackers to hide their activity, auto-forward sensitive emails, or silently delete security alerts. High-risk rules need immediate review.</span>
      </div>
      {high.length > 0 && (
        <div className="flex items-center gap-2 text-[12px] text-red-400">
          <AlertTriangle size={12} />
          <span>{high.length} high-risk rule{high.length !== 1 ? 's' : ''} found — review immediately</span>
        </div>
      )}
      <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th>Rule Name</Th>
              <Th>Mailbox</Th>
              <Th>Provider</Th>
              <Th>Conditions → Actions</Th>
              <Th>Status</Th>
              <Th>Risk</Th>
              <Th></Th>
            </Tr>
          </Thead>
          <Tbody>
            {rules.length === 0 && (
              <Tr><Td colSpan={7} className="text-center text-[#71717a] py-10 text-[13px]">No inbox rules found</Td></Tr>
            )}
            {rules.map(rule => (
              <Tr key={rule.id} className={rule.risk === 'high' ? 'bg-red-500/[0.03]' : ''}>
                <Td className="font-medium text-[var(--foreground)] text-[13px] max-w-[160px]"><div className="truncate" title={rule.name}>{rule.name}</div></Td>
                <Td className="text-[12px] text-[#71717a] max-w-[150px]"><div className="truncate" title={rule.mailbox}>{rule.mailbox}</div></Td>
                <Td><ProviderBadge provider={rule.provider} /></Td>
                <Td className="text-[11px] text-[#a1a1aa] max-w-[220px]">
                  <div className="truncate">{rule.conditions}</div>
                  <div className="flex items-center gap-1 text-[10px] text-[#52525b] mt-0.5">
                    <ArrowRight size={9} />
                    <span className="truncate">{rule.actions}</span>
                  </div>
                </Td>
                <Td>
                  <Badge variant={rule.enabled ? 'warning' : 'neutral'}>
                    {rule.enabled ? 'Active' : 'Disabled'}
                  </Badge>
                </Td>
                <Td>
                  <RiskBadge risk={rule.risk} />
                  {rule.risk_reasons.length > 0 && (
                    <div className="text-[10px] text-[#71717a] mt-0.5 max-w-[140px]">
                      {rule.risk_reasons[0]}
                    </div>
                  )}
                </Td>
                <Td>
                  <button
                    onClick={() => onDelete(rule)}
                    disabled={deleting === rule.id}
                    className="text-[11px] text-red-400/70 hover:text-red-400 px-2 py-1 rounded hover:bg-red-500/10 transition-colors disabled:opacity-50"
                  >
                    {deleting === rule.id ? 'Deleting…' : 'Delete'}
                  </button>
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </div>
    </div>
  )
}

// ── Forwarding Rules Tab ───────────────────────────────────────────────────────
function ForwardsTab({ forwards, loading }: { forwards: ForwardRule[]; loading: boolean }) {
  if (loading) return <LoadingSkeleton rows={4} cols={5} />

  const external = forwards.filter(f => f.is_external)

  return (
    <div className="space-y-3">
      {external.length > 0 && (
        <div className="flex items-start gap-3 px-4 py-3 bg-red-500/[0.06] border border-red-500/20 rounded-xl text-[12px] text-red-300">
          <AlertTriangle size={13} className="mt-0.5 flex-shrink-0" />
          <span><strong>{external.length} mailbox{external.length !== 1 ? 'es are' : ' is'} auto-forwarding to external addresses.</strong> This is a critical exfiltration signal — review immediately and disable if unexpected.</span>
        </div>
      )}
      {external.length === 0 && !loading && (
        <div className="flex items-start gap-3 px-4 py-3 bg-emerald-500/[0.06] border border-emerald-500/20 rounded-xl text-[12px] text-emerald-300">
          <CheckCircle2 size={13} className="mt-0.5 flex-shrink-0" />
          <span>No external auto-forwarding rules detected. ✓</span>
        </div>
      )}
      <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th>Mailbox</Th>
              <Th>Provider</Th>
              <Th>Forwarding To</Th>
              <Th>Destination</Th>
              <Th>Risk</Th>
            </Tr>
          </Thead>
          <Tbody>
            {forwards.length === 0 && (
              <Tr><Td colSpan={5} className="text-center text-[#71717a] py-10 text-[13px]">No auto-forwarding rules found</Td></Tr>
            )}
            {forwards.map(fwd => (
              <Tr key={fwd.id} className={fwd.is_external ? 'bg-red-500/[0.03]' : ''}>
                <Td className="text-[13px] font-medium text-[var(--foreground)]">{fwd.mailbox}</Td>
                <Td><ProviderBadge provider={fwd.provider} /></Td>
                <Td className="text-[13px] font-mono text-[#a1a1aa]">{fwd.forward_to}</Td>
                <Td>
                  <Badge variant={fwd.is_external ? 'danger' : 'neutral'}>
                    {fwd.is_external ? 'External' : 'Internal'}
                  </Badge>
                </Td>
                <Td><RiskBadge risk={fwd.risk} /></Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </div>
    </div>
  )
}

function LoadingSkeleton({ rows, cols }: { rows: number; cols: number }) {
  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
      <Table>
        <Thead><Tr>{[...Array(cols)].map((_, i) => <Th key={i}><div className="h-3 w-16 bg-white/[0.05] rounded animate-pulse" /></Th>)}</Tr></Thead>
        <Tbody>
          {[...Array(rows)].map((_, i) => (
            <Tr key={i}>{[...Array(cols)].map((_, j) => <Td key={j}><div className="h-4 bg-white/[0.04] rounded animate-pulse w-20" /></Td>)}</Tr>
          ))}
        </Tbody>
      </Table>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function PosturePage() {
  const [tab, setTab] = useState<Tab>('apps')
  const [summary, setSummary] = useState<PostureSummary | null>(null)
  const [apps, setApps] = useState<OAuthApp[]>([])
  const [rules, setRules] = useState<InboxRule[]>([])
  const [forwards, setForwards] = useState<ForwardRule[]>([])
  const [loadingSummary, setLoadingSummary] = useState(true)
  const [aiScore, setAiScore] = useState<{ score: number; label: string; reasoning: string } | null>(null)
  const [loadingAiScore, setLoadingAiScore] = useState(false)
  const [loadingApps, setLoadingApps] = useState(false)
  const [loadingRules, setLoadingRules] = useState(false)
  const [loadingForwards, setLoadingForwards] = useState(false)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [deletingRule, setDeletingRule] = useState<string | null>(null)
  const [scanning, setScanning] = useState(false)
  const [confirmRevoke, setConfirmRevoke] = useState<OAuthApp | null>(null)
  const [confirmDeleteRule, setConfirmDeleteRule] = useState<InboxRule | null>(null)
  const [toast, setToast] = useState<{ type: 'success' | 'error'; msg: string } | null>(null)
  const [sortRisk, setSortRisk] = useState<'desc' | 'asc'>('desc')
  const [filterProvider, setFilterProvider] = useState<'all' | 'm365' | 'google'>('all')

  const RISK_ORDER: Record<string, number> = { high: 3, medium: 2, low: 1 }
  const filterAndSort = <T extends { risk: string; provider?: string }>(items: T[]) => {
    const filtered = filterProvider === 'all' ? items : items.filter(a => a.provider === filterProvider)
    return [...filtered].sort((a, b) =>
      sortRisk === 'desc'
        ? (RISK_ORDER[b.risk] ?? 0) - (RISK_ORDER[a.risk] ?? 0)
        : (RISK_ORDER[a.risk] ?? 0) - (RISK_ORDER[b.risk] ?? 0)
    )
  }
  // Keep backward-compat alias
  const sortByRisk = filterAndSort

  const showToast = (type: 'success' | 'error', msg: string) => {
    setToast({ type, msg })
    setTimeout(() => setToast(null), 4000)
  }

  const fetchSummary = useCallback(async () => {
    setLoadingSummary(true)
    try {
      const r = await api.get('/api/posture/summary')
      setSummary(r.data)
    } catch { setSummary(null) }
    setLoadingSummary(false)
  }, [])

  const fetchAiScore = useCallback(async () => {
    setLoadingAiScore(true)
    try {
      const r = await api.get('/api/posture/ai-score')
      if (r.data?.score != null) setAiScore(r.data)
    } catch { /* non-fatal */ }
    setLoadingAiScore(false)
  }, [])

  const fetchApps = useCallback(async () => {
    setLoadingApps(true)
    try {
      const r = await api.get('/api/posture/apps')
      setApps(Array.isArray(r.data) ? r.data : [])
    } catch { setApps([]) }
    setLoadingApps(false)
  }, [])

  const fetchRules = useCallback(async () => {
    setLoadingRules(true)
    try {
      const r = await api.get('/api/posture/inbox-rules')
      setRules(Array.isArray(r.data) ? r.data : [])
    } catch { setRules([]) }
    setLoadingRules(false)
  }, [])

  const fetchForwards = useCallback(async () => {
    setLoadingForwards(false)
    try {
      const r = await api.get('/api/posture/forwards')
      setForwards(Array.isArray(r.data) ? r.data : [])
    } catch { setForwards([]) }
    setLoadingForwards(false)
  }, [])

  useEffect(() => { fetchSummary() }, [fetchSummary])
  useEffect(() => { fetchAiScore() }, [fetchAiScore])
  useEffect(() => { fetchApps() }, [fetchApps])
  useEffect(() => { fetchRules() }, [fetchRules])
  useEffect(() => { fetchForwards() }, [fetchForwards])

  const triggerScan = async () => {
    setScanning(true)
    try {
      await api.post('/api/posture/scan')
      showToast('success', 'Posture scan started — results will update in ~30 seconds.')
      setTimeout(async () => {
        await Promise.all([fetchSummary(), fetchApps(), fetchRules(), fetchForwards()])
        setScanning(false)
      }, 30000)
    } catch {
      showToast('error', 'Scan failed to start.')
      setScanning(false)
    }
  }

  const revokeApp = async (app: OAuthApp) => {
    setRevoking(app.id)
    setConfirmRevoke(null)
    try {
      await api.delete(`/api/posture/apps/${app.id}`)
      setApps(prev => prev.filter(a => a.id !== app.id))
      showToast('success', `Revoked access for ${app.name}`)
      fetchSummary()
    } catch {
      showToast('error', `Failed to revoke ${app.name}`)
    }
    setRevoking(null)
  }

  const deleteRule = async (rule: InboxRule) => {
    setDeletingRule(rule.id)
    setConfirmDeleteRule(null)
    try {
      await api.delete(`/api/posture/inbox-rules/${rule.id}?mailbox=${encodeURIComponent(rule.mailbox)}&provider=${rule.provider}`)
      setRules(prev => prev.filter(r => r.id !== rule.id))
      showToast('success', `Deleted rule "${rule.name}"`)
      fetchSummary()
    } catch {
      showToast('error', `Failed to delete rule "${rule.name}"`)
    }
    setDeletingRule(null)
  }

  const TAB_CONFIG: { key: Tab; label: string; icon: React.ReactNode; count?: number; danger?: boolean }[] = [
    { key: 'apps',     label: 'OAuth Apps',     icon: <Zap size={13} />,     count: summary?.total_apps,     danger: (summary?.high_risk_apps ?? 0) > 0 },
    { key: 'rules',    label: 'Inbox Rules',    icon: <Inbox size={13} />,   count: summary?.total_rules,    danger: (summary?.high_risk_rules ?? 0) > 0 },
    { key: 'forwards', label: 'Auto-Forwarding', icon: <Forward size={13} />, count: summary?.total_forwards, danger: (summary?.external_forwards ?? 0) > 0 },
  ]

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Inbox Posture</h1>
        </div>
        <Button size="sm" variant="ghost" loading={scanning} onClick={triggerScan}>
          <RefreshCw size={13} className={scanning ? 'animate-spin' : ''} />
          {scanning ? 'Scanning…' : 'Scan Now'}
        </Button>
      </div>

      {/* Toast */}
      {toast && (
        <div className={`flex items-center gap-2 px-4 py-3 rounded-xl text-[13px] border ${
          toast.type === 'success'
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
            : 'bg-red-500/10 border-red-500/20 text-red-400'
        }`}>
          {toast.type === 'success' ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
          {toast.msg}
        </div>
      )}

      {/* Posture Score + Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="col-span-2 lg:col-span-1 bg-[#141417] border border-white/[0.07] rounded-xl p-5 flex items-center gap-4">
          {loadingAiScore && !aiScore
            ? <div className="w-24 h-24 rounded-full bg-white/[0.04] animate-pulse" />
            : <ScoreRing score={aiScore?.score ?? summary?.posture_score ?? 0} />
          }
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <div className="text-[13px] font-semibold text-[#a1a1aa]">Posture Score</div>
              {aiScore?.label && (
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold ${
                  aiScore.label === 'Excellent' ? 'bg-emerald-500/20 text-emerald-400' :
                  aiScore.label === 'Good' ? 'bg-blue-500/20 text-blue-400' :
                  aiScore.label === 'Fair' ? 'bg-amber-500/20 text-amber-400' :
                  'bg-red-500/20 text-red-400'
                }`}>{aiScore.label}</span>
              )}
            </div>
            {aiScore?.reasoning
              ? <div className="text-[11px] text-[#71717a] mt-1 max-w-[150px] leading-relaxed line-clamp-3">{aiScore.reasoning}</div>
              : <div className="text-[11px] text-[#52525b] mt-1">{loadingAiScore ? 'Analysing…' : 'No scan yet'}</div>
            }
            {summary?.last_scanned && (
              <div className="text-[10px] text-[#3f3f46] mt-2">
                {new Date(summary.last_scanned).toLocaleString()}
              </div>
            )}
          </div>
        </div>
        {[
          { label: 'High-Risk Apps', value: summary?.high_risk_apps ?? 0, total: summary?.total_apps ?? 0, icon: <Zap size={14} />, danger: true },
          { label: 'High-Risk Rules', value: summary?.high_risk_rules ?? 0, total: summary?.total_rules ?? 0, icon: <Inbox size={14} />, danger: true },
          { label: 'External Forwards', value: summary?.external_forwards ?? 0, total: summary?.total_forwards ?? 0, icon: <Forward size={14} />, danger: true },
        ].map(({ label, value, total, icon, danger }) => (
          <div key={label} className={`bg-[#141417] border rounded-xl p-4 ${danger && value > 0 ? 'border-red-500/20' : 'border-white/[0.07]'}`}>
            <div className="flex items-center gap-2 text-[#71717a] mb-2">
              {icon}
              <span className="text-[11px] font-medium uppercase tracking-wide">{label}</span>
            </div>
            {loadingSummary
              ? <div className="h-7 w-12 bg-white/[0.04] rounded animate-pulse" />
              : <div className={`text-2xl font-bold ${value > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{value}</div>
            }
            <div className="text-[11px] text-[#52525b] mt-0.5">{total} total</div>
          </div>
        ))}
      </div>

      {/* Tabs + sort control */}
      <div className="flex items-center justify-between border-b border-white/[0.06]">
        <div className="flex gap-0.5">
          {TAB_CONFIG.map(({ key, label, icon, count, danger }) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={`flex items-center gap-2 px-4 py-2.5 text-[13px] font-medium border-b-2 transition-all ${
                tab === key ? 'border-[#3b6ef6] text-white' : 'border-transparent text-[#71717a] hover:text-[#a1a1aa]'
              }`}
            >
              {icon}
              {label}
              {count !== undefined && (
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-bold ${
                  danger ? 'bg-red-500/20 text-red-400' : 'bg-white/[0.06] text-[#71717a]'
                }`}>
                  {count}
                </span>
              )}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2 mb-1">
          {/* Provider filter */}
          <div className="flex items-center gap-0.5 bg-[#0d0d10] border border-white/[0.07] rounded-lg p-0.5">
            {(['all', 'm365', 'google'] as const).map(p => (
              <button
                key={p}
                onClick={() => setFilterProvider(p)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-all ${
                  filterProvider === p
                    ? 'bg-[#1e1e24] text-white'
                    : 'text-[#52525b] hover:text-[#a1a1aa]'
                }`}
              >
                {p === 'all' ? 'All' : p === 'm365' ? 'Microsoft' : 'Google'}
              </button>
            ))}
          </div>
          {/* Risk sort */}
          <button
            onClick={() => setSortRisk(s => s === 'desc' ? 'asc' : 'desc')}
            className="flex items-center gap-1.5 text-[12px] text-[#71717a] hover:text-white px-3 py-1.5 rounded-lg border border-white/[0.07] hover:border-white/[0.15] transition-all"
          >
            <AlertTriangle size={11} />
            Risk: {sortRisk === 'desc' ? 'High → Low' : 'Low → High'}
            {sortRisk === 'desc' ? <ChevronDown size={11} /> : <ChevronUp size={11} />}
          </button>
        </div>
      </div>

      {/* Tab Content */}
      {tab === 'apps' && (
        <AppsTab apps={sortByRisk(apps)} loading={loadingApps} onRevoke={a => setConfirmRevoke(a)} revoking={revoking} />
      )}
      {tab === 'rules' && (
        <RulesTab rules={sortByRisk(rules)} loading={loadingRules} onDelete={r => setConfirmDeleteRule(r)} deleting={deletingRule} />
      )}
      {tab === 'forwards' && (
        <ForwardsTab forwards={sortByRisk(forwards)} loading={loadingForwards} />
      )}

      {/* Confirm Revoke Modal */}
      {confirmRevoke && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#141417] border border-white/[0.08] rounded-2xl p-6 max-w-md w-full mx-4 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <AlertTriangle size={18} className="text-red-400 mt-0.5 flex-shrink-0" />
              <div>
                <div className="text-[15px] font-semibold text-white">Revoke App Access</div>
                <p className="text-[13px] text-[#a1a1aa] mt-1">
                  Revoke OAuth access for <strong className="text-white">{confirmRevoke.name}</strong>?
                  This will immediately remove their ability to access your organization's mailboxes.
                  The app may stop working for users who installed it.
                </p>
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="ghost" onClick={() => setConfirmRevoke(null)}>Cancel</Button>
              <button
                onClick={() => revokeApp(confirmRevoke)}
                className="px-3 py-1.5 rounded-lg text-[13px] font-semibold bg-red-600 text-white hover:bg-red-500 transition-colors"
              >
                Revoke Access
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Delete Rule Modal */}
      {confirmDeleteRule && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[#141417] border border-white/[0.08] rounded-2xl p-6 max-w-md w-full mx-4 space-y-4 shadow-xl">
            <div className="flex items-start gap-3">
              <Trash2 size={18} className="text-red-400 mt-0.5 flex-shrink-0" />
              <div>
                <div className="text-[15px] font-semibold text-white">Delete Inbox Rule</div>
                <p className="text-[13px] text-[#a1a1aa] mt-1">
                  Delete rule <strong className="text-white">"{confirmDeleteRule.name}"</strong> from <strong className="text-white">{confirmDeleteRule.mailbox}</strong>?
                  This cannot be undone.
                </p>
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button variant="ghost" onClick={() => setConfirmDeleteRule(null)}>Cancel</Button>
              <button
                onClick={() => deleteRule(confirmDeleteRule)}
                className="px-3 py-1.5 rounded-lg text-[13px] font-semibold bg-red-600 text-white hover:bg-red-500 transition-colors"
              >
                Delete Rule
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
