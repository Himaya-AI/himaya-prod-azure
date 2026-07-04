'use client'
import { useEffect, useState, useRef } from 'react'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { RefreshCw, Users, Zap, ArrowRight } from 'lucide-react'
import { useRouter } from 'next/navigation'
import api from '@/lib/api'
import type { AtRiskEmployee } from '@/lib/types'

// ─── Top Targeted Groups panel ────────────────────────────────────────────────

interface AtRiskGroup {
  id: string
  email: string
  name: string
  group_type: string
  threat_count: number
  last_threat_at: string | null
}

export function TopTargetedGroups() {
  const router = useRouter()
  const [groups, setGroups] = useState<AtRiskGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const fetchGroups = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const res = await api.get('/api/dashboard/at-risk-groups')
      setGroups(res.data ?? [])
      setLastUpdated(new Date())
    } catch {
      // silent fail
    }
    if (!silent) setLoading(false)
  }

  useEffect(() => {
    fetchGroups(false)
    const id = setInterval(() => fetchGroups(true), 60_000)
    return () => clearInterval(id)
  }, [])

  const typeBadge = (gt: string) => {
    const label = gt === 'shared' ? 'SHARED' : gt === 'dl' ? 'DL' : 'GROUP'
    const color = gt === 'shared' ? '#0ea5e9' : gt === 'dl' ? '#a855f7' : '#3b6ef6'
    return (
      <span
        className="text-[9px] font-bold px-1.5 py-0.5 rounded"
        style={{ background: color + '22', color }}
      >
        {label}
      </span>
    )
  }

  const totalThreats = groups.reduce((s, g) => s + (g.threat_count || 0), 0)

  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-[13px] font-semibold text-white flex items-center gap-2">
          <Users size={13} className="text-[#3b6ef6]" />
          Top Targeted Groups &amp; Shared Inboxes
        </h3>
        <div className="flex items-center gap-2">
          {!loading && totalThreats > 0 && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 border border-red-500/20 text-red-400">
              <span className="w-1 h-1 rounded-full bg-red-400 animate-pulse" />
              {totalThreats} hits
            </span>
          )}
          {lastUpdated && (
            <div className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 border border-red-500/20 text-red-400">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              Live
            </div>
          )}
          <button
            onClick={() => router.push('/people')}
            className="flex items-center gap-1 text-[10px] text-[#3b6ef6] hover:text-blue-300 transition-colors"
          >
            View People <ArrowRight size={10} />
          </button>
        </div>
      </div>
      {loading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-8 animate-pulse bg-white/[0.04] rounded" />
          ))}
        </div>
      ) : groups.length === 0 ? (
        <p className="text-[12px] text-slate-500 italic py-2">No group targeting data yet — groups appear here once they receive threats</p>
      ) : (
        <div className="space-y-1">
          {groups.slice(0, 5).map((g, i) => (
            <div key={g.id} className="flex items-center gap-2 py-1.5 border-b border-white/[0.04] last:border-0">
              <div className="text-[10px] font-bold text-slate-600 w-4 shrink-0">{i + 1}</div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-[12px] font-semibold text-slate-200 truncate">{g.name}</span>
                  {typeBadge(g.group_type)}
                </div>
                <div className="text-[10px] text-slate-500 truncate">{g.email}</div>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="text-[11px] font-bold px-2 py-0.5 rounded-full"
                  style={{ background: g.threat_count > 0 ? 'rgba(239,68,68,0.12)' : 'rgba(255,255,255,0.05)', color: g.threat_count > 0 ? '#f87171' : '#6b7280' }}>
                  {g.threat_count} {g.threat_count === 1 ? 'hit' : 'hits'}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

interface Props {
  employees?: AtRiskEmployee[]
  loading?: boolean
  /** If true, component manages its own data fetching + live polling */
  standalone?: boolean
}

function riskVariant(score: number) {
  if (score >= 80) return 'danger'
  if (score >= 60) return 'warning'
  if (score >= 40) return 'info'
  return 'success'
}

const POLL_MS = 60_000 // refresh every 60s

export default function AtRiskEmployees({ employees: propEmployees, loading: propLoading, standalone = true }: Props) {
  const router = useRouter()
  const [employees, setEmployees] = useState<AtRiskEmployee[]>(propEmployees ?? [])
  const [loading, setLoading] = useState(propLoading ?? true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [live, setLive] = useState(false)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Sync from props when used in non-standalone mode
  useEffect(() => {
    if (!standalone && propEmployees !== undefined) {
      setEmployees(propEmployees)
    }
  }, [propEmployees, standalone])

  useEffect(() => {
    if (!standalone && propLoading !== undefined) {
      setLoading(propLoading)
    }
  }, [propLoading, standalone])

  const [totalMailboxes, setTotalMailboxes] = useState<number>(0)

  const fetchData = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const res = await api.get('/api/dashboard/at-risk-employees')
      const raw = res.data
      // API returns either {total_mailboxes, employees: [...]} or a plain array (legacy)
      const list = Array.isArray(raw) ? raw : (raw?.employees ?? [])
      setTotalMailboxes(Array.isArray(raw) ? 0 : (raw?.total_mailboxes ?? 0))
      const data = list.map((r: Record<string, unknown>) => ({
        id: (r.user_id ?? r.id) as string,
        name: (r.name ?? r.email) as string,
        email: r.email as string,
        department: r.department as string,
        risk_score: (r.risk_score ?? 0) as number,
        threats_30d: (r.threat_count ?? r.threats_30d ?? 0) as number,
        last_threat_at: r.last_threat_at as string | null,
      }))
      setEmployees(data)
      setLastUpdated(new Date())
      setLive(true)
    } catch {
      // silent fail on background polls
    }
    if (!silent) setLoading(false)
  }

  useEffect(() => {
    if (!standalone) return
    fetchData(false)
    pollRef.current = setInterval(() => fetchData(true), POLL_MS)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [standalone])

  const displayed = employees.slice(0, 10)
  const liveCount = employees.length

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 flex-wrap">
            <CardTitle>Top At-Risk Employees</CardTitle>
            {!loading && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#e94560]/10 border border-[#e94560]/20 text-[#e94560]">
                <span className="w-1.5 h-1.5 rounded-full bg-[#e94560] animate-pulse" />
                {liveCount} at risk
              </span>
            )}
            {totalMailboxes > 0 && !loading && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-[#3b6ef6]/10 border border-[#3b6ef6]/20 text-[#3b6ef6]">
                {totalMailboxes} inboxes monitored
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {live && lastUpdated && (
              <div className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 border border-red-500/20 text-red-400">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
                Live
              </div>
            )}
            <button
              onClick={() => router.push('/people')}
              className="flex items-center gap-1 text-[10px] text-[#3b6ef6] hover:text-blue-300 transition-colors"
            >
              View Inboxes <ArrowRight size={10} />
            </button>
          </div>
        </div>
      </CardHeader>
      {loading ? (
        <div className="space-y-3">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-10 animate-pulse bg-[#0f3460]/20 rounded" />
          ))}
        </div>
      ) : (
        <div className="space-y-2">
          {displayed.map((emp, i) => (
            <div key={emp.id} className="flex items-center gap-3 py-2">
              <div className="text-xs text-slate-600 w-4">{i + 1}</div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-slate-200 truncate">{emp.name}</div>
                <div className="text-xs text-slate-500 truncate">{emp.department ?? emp.email}</div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500">{emp.threats_30d ?? 0} threats</span>
                <Badge variant={riskVariant(emp.risk_score)}>{emp.risk_score}</Badge>
              </div>
            </div>
          ))}
          {displayed.length === 0 && (
            <div className="text-sm text-slate-500 text-center py-4">No data available</div>
          )}
        </div>
      )}
    </Card>
  )
}
