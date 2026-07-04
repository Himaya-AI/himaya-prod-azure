'use client'
import React, { useEffect, useState, useCallback, useRef } from 'react'
import {
  Shield, ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2,
  RefreshCw, Lock, Trash2, Send, ChevronDown, ChevronUp,
  Copy, Settings, FileWarning, Inbox, ClipboardList,
  Plus, X, Info, Zap, Filter, ChevronLeft, ChevronRight,
  TrendingUp, TrendingDown, Activity, BarChart3, PieChart,
  Clock, Eye, Ban, CircleDot, ArrowUpRight, ArrowDownRight,
  User, CreditCard, Key, Scale, MailX, Undo2, Pause, XCircle,
} from 'lucide-react'
import Button from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import api from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface DLPStats {
  total_events_today: number
  held_today: number
  blocked_today: number
  top_policy: string | null
  active_policies: number
  // Extended analytics
  total_events_week?: number
  risk_distribution?: { low: number; medium: number; high: number; critical: number }
  action_distribution?: { allow: number; warn: number; hold: number; block: number }
  category_breakdown?: { category: string; count: number }[]
  trend?: { date: string; events: number; blocked: number }[]
}

interface DLPPolicy {
  id: string
  name: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  enabled: boolean
  detect_pii: boolean
  detect_financial: boolean
  detect_credentials: boolean
  detect_itar: boolean
  detect_bulk_exfil: boolean
  custom_keywords: string[]
  custom_regex: string[]
  action: 'ALLOW' | 'WARN' | 'HOLD' | 'BLOCK'
  notify_sender: boolean
  notify_manager_email: string | null
  external_only: boolean
  created_at: string | null
  m365_rule_id?: string | null
  last_synced_at?: string | null
  sync_status?: 'not_synced' | 'synced' | 'error'
  gsuite_rule_id?: string | null
  gsuite_last_synced_at?: string | null
  gsuite_sync_status?: 'not_synced' | 'synced' | 'error'
}

interface DLPQueueItem {
  id: string
  event_id: string
  status: string
  expires_at: string | null
  created_at: string | null
  sender_email: string | null
  subject: string | null
  risk_level: string
  action_taken: string
  categories_found: string[]
}

interface DLPEvent {
  id: string
  policy_id: string | null
  sender_email: string | null
  recipient_emails: string[]
  subject: string | null
  body_preview: string | null
  risk_level: string
  action_taken: string
  categories_found: string[]
  matched_patterns: string[]
  confidence: number | null
  reviewed_by: string | null
  reviewed_at: string | null
  review_action: string | null
  created_at: string | null
}

type Tab = 'overview' | 'policies' | 'queue' | 'logs' | 'settings'

// ── One-Click DLP Setup Types ─────────────────────────────────────────────────

interface DLPSetupConfig {
  scan_outbound: boolean
  scan_inbound: boolean
  action_pii: 'warn' | 'hold' | 'block' | 'recall'
  action_financial: 'warn' | 'hold' | 'block' | 'recall'
  action_credentials: 'warn' | 'hold' | 'block' | 'recall'
  action_legal: 'warn' | 'hold' | 'block' | 'recall'
  notify_sender: boolean
  notify_admin: boolean
  admin_emails: string[]
}

interface DLPSetupStatus {
  enabled: boolean
  config: DLPSetupConfig | null
  enabled_at: string | null
}

// ── Theme constants ───────────────────────────────────────────────────────────

const RISK_BG: Record<string, string> = {
  low:      'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  medium:   'bg-amber-500/10 border-amber-500/20 text-amber-400',
  high:     'bg-red-500/10 border-red-500/20 text-red-400',
  critical: 'bg-red-900/30 border-red-500/40 text-red-300',
}
const ACTION_BG: Record<string, string> = {
  ALLOW: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  WARN:  'bg-amber-500/10 border-amber-500/20 text-amber-400',
  HOLD:  'bg-orange-500/10 border-orange-500/20 text-orange-400',
  BLOCK: 'bg-red-500/10 border-red-500/20 text-red-400',
}

const RISK_COLORS: Record<string, string> = {
  low: '#10b981',
  medium: '#f59e0b',
  high: '#f97316',
  critical: '#ef4444',
}

const ACTION_COLORS: Record<string, string> = {
  allow: '#10b981',
  warn: '#f59e0b',
  hold: '#f97316',
  block: '#ef4444',
}

// ── Utility components ────────────────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${RISK_BG[level] || RISK_BG.low}`}>
      {level === 'critical' || level === 'high'
        ? <AlertTriangle size={10} />
        : level === 'medium'
        ? <Info size={10} />
        : <CheckCircle2 size={10} />}
      {level?.toUpperCase() || 'LOW'}
    </span>
  )
}

function ActionBadge({ action }: { action: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${ACTION_BG[action] || ACTION_BG.ALLOW}`}>
      {action === 'BLOCK' ? <ShieldAlert size={10} /> :
       action === 'HOLD'  ? <Lock size={10} /> :
       action === 'WARN'  ? <AlertTriangle size={10} /> :
       <CheckCircle2 size={10} />}
      {action}
    </span>
  )
}

function LoadingSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="h-12 bg-white/[0.03] rounded-lg animate-pulse" />
      ))}
    </div>
  )
}

function UpgradePrompt() {
  return (
    <div className="flex flex-col items-center justify-center py-24 gap-6">
      <div className="w-16 h-16 rounded-full bg-[#3b6ef6]/10 flex items-center justify-center">
        <Lock size={28} className="text-[#3b6ef6]" />
      </div>
      <div className="text-center max-w-md">
        <h2 className="text-xl font-semibold text-[var(--foreground)] mb-2">
          Data Loss Prevention — Enterprise Feature
        </h2>
        <p className="text-[14px] text-[#71717a] leading-relaxed">
          DLP protects your organization from accidental or intentional data leakage
          through email. Upgrade to the Enterprise plan to enable AI-powered classification,
          policy enforcement, and held-email review.
        </p>
      </div>
      <a
        href="mailto:sales@himaya.ai?subject=Enterprise Upgrade — DLP"
        className="px-6 py-2.5 bg-[#3b6ef6] hover:bg-[#2d5fe0] text-white text-[14px] font-medium rounded-lg transition-colors"
      >
        Contact Sales to Upgrade
      </a>
    </div>
  )
}

// ── Ring Chart Component ──────────────────────────────────────────────────────

function RingChart({ data, size = 120, strokeWidth = 12, centerLabel, centerValue }: {
  data: { label: string; value: number; color: string }[]
  size?: number
  strokeWidth?: number
  centerLabel?: string
  centerValue?: string | number
}) {
  const total = data.reduce((sum, d) => sum + d.value, 0)
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  let accumulated = 0

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="transform -rotate-90">
        {/* Background ring */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth={strokeWidth}
        />
        {/* Data segments */}
        {data.map((segment, i) => {
          const percentage = total > 0 ? segment.value / total : 0
          const strokeDasharray = `${circumference * percentage} ${circumference}`
          const strokeDashoffset = -circumference * accumulated
          accumulated += percentage
          return (
            <circle
              key={i}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={segment.color}
              strokeWidth={strokeWidth}
              strokeDasharray={strokeDasharray}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              className="transition-all duration-500"
            />
          )
        })}
      </svg>
      {/* Center text */}
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {centerValue !== undefined && (
          <span className="text-2xl font-bold text-[var(--foreground)]">{centerValue}</span>
        )}
        {centerLabel && (
          <span className="text-[11px] text-[#71717a]">{centerLabel}</span>
        )}
      </div>
    </div>
  )
}

// ── Bar Chart Component ───────────────────────────────────────────────────────

function BarChart({ data, height = 160, barWidth = 24 }: {
  data: { label: string; value: number; color?: string }[]
  height?: number
  barWidth?: number
}) {
  const maxValue = Math.max(...data.map(d => d.value), 1)
  
  return (
    <div className="flex items-end gap-2 justify-between" style={{ height }}>
      {data.map((item, i) => (
        <div key={i} className="flex flex-col items-center gap-1">
          <span className="text-[10px] text-[#71717a] font-medium">{item.value}</span>
          <div
            className="rounded-t transition-all duration-500"
            style={{
              width: barWidth,
              height: `${Math.max((item.value / maxValue) * (height - 40), 4)}px`,
              backgroundColor: item.color || '#3b6ef6',
            }}
          />
          <span className="text-[10px] text-[#71717a] truncate max-w-[40px]">{item.label}</span>
        </div>
      ))}
    </div>
  )
}

// ── Mini Trend Sparkline ──────────────────────────────────────────────────────

function Sparkline({ data, color = '#3b6ef6', height = 32, width = 80 }: {
  data: number[]
  color?: string
  height?: number
  width?: number
}) {
  if (data.length < 2) return null
  const max = Math.max(...data)
  const min = Math.min(...data)
  const range = max - min || 1
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width
    const y = height - ((v - min) / range) * height
    return `${x},${y}`
  }).join(' ')

  return (
    <svg width={width} height={height} className="overflow-visible">
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

// ── Overview Tab ──────────────────────────────────────────────────────────────

function OverviewTab({ stats, events, loading }: {
  stats: DLPStats | null
  events: DLPEvent[]
  loading: boolean
}) {
  // Use backend stats for distributions (30-day aggregations)
  const riskDist = stats?.risk_distribution ?? { low: 0, medium: 0, high: 0, critical: 0 }
  const actionDist = stats?.action_distribution ?? { allow: 0, warn: 0, hold: 0, block: 0 }
  const topCategories = stats?.category_breakdown?.slice(0, 6) ?? []

  // Calculate totals from backend distributions
  const totalEvents = Object.values(riskDist).reduce((sum, n) => sum + n, 0)
  const blockedEvents = actionDist.block + actionDist.hold
  const blockRate = totalEvents > 0 ? Math.round((blockedEvents / totalEvents) * 100) : 0

  // Use backend trend data, or create placeholder from today's count
  const trendData = stats?.trend?.length
    ? stats.trend.map(t => t.events)
    : [0, 0, 0, 0, 0, 0, stats?.total_events_today ?? 0]
  const weekTotal = stats?.total_events_week ?? trendData.reduce((a, b) => a + b, 0)
  // No prev week data yet, show neutral
  const weekChange = 0

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="h-32 bg-white/[0.03] rounded-xl animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-64 bg-white/[0.03] rounded-xl animate-pulse" />
          <div className="h-64 bg-white/[0.03] rounded-xl animate-pulse" />
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Key Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Events */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-[#3b6ef6]/10 border border-[#3b6ef6]/20 flex items-center justify-center">
              <Activity size={18} className="text-[#3b6ef6]" />
            </div>
            <div className="flex items-center gap-1 text-[11px]">
              {weekChange >= 0 ? (
                <>
                  <ArrowUpRight size={12} className="text-amber-400" />
                  <span className="text-amber-400">+{weekChange}%</span>
                </>
              ) : (
                <>
                  <ArrowDownRight size={12} className="text-emerald-400" />
                  <span className="text-emerald-400">{weekChange}%</span>
                </>
              )}
            </div>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {stats?.total_events_today ?? 0}
          </div>
          <div className="text-[12px] text-[#71717a]">Events Today</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06] flex items-center justify-between">
            <span className="text-[11px] text-[#71717a]">Last 7 days</span>
            <Sparkline data={trendData} color="#3b6ef6" />
          </div>
        </div>

        {/* Blocked / Held */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
              <Ban size={18} className="text-red-400" />
            </div>
            <div className="px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20">
              <span className="text-[11px] font-semibold text-red-400">{blockRate}%</span>
            </div>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {(stats?.blocked_today ?? 0) + (stats?.held_today ?? 0)}
          </div>
          <div className="text-[12px] text-[#71717a]">Blocked + Held</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06] flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-[11px] text-[#71717a]">{stats?.blocked_today ?? 0} blocked</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-orange-500" />
              <span className="text-[11px] text-[#71717a]">{stats?.held_today ?? 0} held</span>
            </div>
          </div>
        </div>

        {/* Active Policies */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <ShieldCheck size={18} className="text-emerald-400" />
            </div>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {stats?.active_policies ?? 0}
          </div>
          <div className="text-[12px] text-[#71717a]">Active Policies</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06]">
            <span className="text-[11px] text-[#71717a]">
              {stats?.top_policy ? `Top: ${stats.top_policy}` : 'No policy triggered yet'}
            </span>
          </div>
        </div>

        {/* Queue Status */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
              <Clock size={18} className="text-amber-400" />
            </div>
            {(stats?.held_today ?? 0) > 0 && (
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-amber-500" />
              </span>
            )}
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {stats?.held_today ?? 0}
          </div>
          <div className="text-[12px] text-[#71717a]">Pending Review</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06]">
            <span className="text-[11px] text-[#71717a]">Emails awaiting approval</span>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <PieChart size={15} className="text-[#3b6ef6]" />
            Risk Distribution
          </h3>
          <div className="flex items-center justify-between">
            <RingChart
              data={[
                { label: 'Low', value: riskDist.low, color: RISK_COLORS.low },
                { label: 'Medium', value: riskDist.medium, color: RISK_COLORS.medium },
                { label: 'High', value: riskDist.high, color: RISK_COLORS.high },
                { label: 'Critical', value: riskDist.critical, color: RISK_COLORS.critical },
              ]}
              size={140}
              strokeWidth={16}
              centerValue={totalEvents}
              centerLabel="Total"
            />
            <div className="flex-1 ml-6 space-y-2">
              {[
                { label: 'Low Risk', value: riskDist.low, color: RISK_COLORS.low },
                { label: 'Medium Risk', value: riskDist.medium, color: RISK_COLORS.medium },
                { label: 'High Risk', value: riskDist.high, color: RISK_COLORS.high },
                { label: 'Critical', value: riskDist.critical, color: RISK_COLORS.critical },
              ].map((item, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-[12px] text-[#a1a1aa]">{item.label}</span>
                  </div>
                  <span className="text-[12px] font-semibold text-[var(--foreground)]">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Action Distribution */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <BarChart3 size={15} className="text-[#3b6ef6]" />
            Actions Taken
          </h3>
          <BarChart
            data={[
              { label: 'Allow', value: actionDist.allow, color: ACTION_COLORS.allow },
              { label: 'Warn', value: actionDist.warn, color: ACTION_COLORS.warn },
              { label: 'Hold', value: actionDist.hold, color: ACTION_COLORS.hold },
              { label: 'Block', value: actionDist.block, color: ACTION_COLORS.block },
            ]}
            height={140}
            barWidth={40}
          />
        </div>
      </div>

      {/* Top Categories */}
      <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
          <FileWarning size={15} className="text-[#3b6ef6]" />
          Top Detection Categories
        </h3>
        {topCategories.length === 0 ? (
          <div className="flex items-center justify-center py-8 text-[#71717a] text-[13px]">
            No categories detected yet. DLP events will appear here once emails are scanned.
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {topCategories.map((cat, i) => (
              <div key={i} className="flex items-center justify-between bg-white/[0.03] rounded-lg p-3 border border-white/[0.05]">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-[#3b6ef6]" />
                  <span className="text-[12px] text-[#a1a1aa] truncate max-w-[100px]" title={cat.category.replace(/_/g, ' ')}>
                    {cat.category.replace(/_/g, ' ')}
                  </span>
                </div>
                <span className="text-[12px] font-semibold text-[var(--foreground)]">{cat.count}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Activity */}
      <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
          <Eye size={15} className="text-[#3b6ef6]" />
          Recent Activity
        </h3>
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-3">
            <div className="w-12 h-12 rounded-full bg-white/[0.03] flex items-center justify-center">
              <Activity size={20} className="text-[#71717a]" />
            </div>
            <div className="text-center">
              <p className="text-[13px] text-[#71717a] mb-1">No DLP events yet</p>
              <p className="text-[11px] text-[#52525b]">
                Events will appear here when outbound emails are scanned by DLP policies.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            {events.slice(0, 5).map(e => (
              <div key={e.id} className="flex items-center gap-3 p-3 bg-white/[0.02] rounded-lg border border-white/[0.04] hover:bg-white/[0.04] transition-colors">
                <div className={`w-2 h-2 rounded-full ${
                  e.risk_level === 'critical' ? 'bg-red-500' :
                  e.risk_level === 'high' ? 'bg-orange-500' :
                  e.risk_level === 'medium' ? 'bg-amber-500' :
                  'bg-emerald-500'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[12px] font-medium text-[var(--foreground)] truncate">
                      {e.subject || '(No subject)'}
                    </span>
                    <RiskBadge level={e.risk_level} />
                    <ActionBadge action={e.action_taken} />
                  </div>
                  <div className="text-[11px] text-[#71717a] truncate">
                    From: {e.sender_email || 'Unknown'}
                  </div>
                </div>
                <span className="text-[10px] text-[#52525b] whitespace-nowrap">
                  {e.created_at ? new Date(e.created_at).toLocaleTimeString() : '—'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── New Policy Modal ──────────────────────────────────────────────────────────

const BLANK_POLICY: Omit<DLPPolicy, 'id' | 'created_at'> = {
  name: '', severity: 'medium', enabled: true,
  detect_pii: true, detect_financial: true, detect_credentials: true,
  detect_itar: false, detect_bulk_exfil: true,
  custom_keywords: [], custom_regex: [],
  action: 'WARN', notify_sender: false, notify_manager_email: null, external_only: false,
}

function PolicyModal({ onClose, onSave }: { onClose: () => void; onSave: (p: typeof BLANK_POLICY) => Promise<void> }) {
  const [form, setForm] = useState({ ...BLANK_POLICY })
  const [saving, setSaving] = useState(false)
  const [kwInput, setKwInput] = useState('')
  const [rxInput, setRxInput] = useState('')
  const [error, setError] = useState('')

  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  const addKw = () => {
    if (!kwInput.trim()) return
    set('custom_keywords', [...form.custom_keywords, kwInput.trim()])
    setKwInput('')
  }
  const removeKw = (i: number) => set('custom_keywords', form.custom_keywords.filter((_, idx) => idx !== i))
  const addRx = () => {
    if (!rxInput.trim()) return
    set('custom_regex', [...form.custom_regex, rxInput.trim()])
    setRxInput('')
  }
  const removeRx = (i: number) => set('custom_regex', form.custom_regex.filter((_, idx) => idx !== i))

  const submit = async () => {
    if (!form.name.trim()) { setError('Policy name is required'); return }
    setSaving(true); setError('')
    try { await onSave(form) } catch (e: unknown) { setError(String(e)) } finally { setSaving(false) }
  }

  const CheckRow = ({ label, field }: { label: string; field: keyof typeof form }) => (
    <label className="flex items-center gap-3 cursor-pointer group">
      <input
        type="checkbox"
        checked={!!form[field]}
        onChange={e => set(field, e.target.checked)}
        className="w-4 h-4 rounded border-white/20 bg-[#1a1a24] accent-[#3b6ef6] cursor-pointer"
      />
      <span className="text-[13px] text-[#a1a1aa] group-hover:text-white transition-colors">{label}</span>
    </label>
  )

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-[#13131a] border border-white/[0.08] rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-5 border-b border-white/[0.06]">
          <h2 className="text-[16px] font-semibold text-[var(--foreground)]">New DLP Policy</h2>
          <button onClick={onClose} className="text-[#71717a] hover:text-white transition-colors"><X size={18} /></button>
        </div>

        <div className="p-5 space-y-5">
          {/* Name + severity */}
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="text-[12px] text-[#71717a] mb-1.5 block">Policy Name *</label>
              <input
                className="w-full bg-[#0d0d12] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] placeholder-[#4a4a5a] focus:outline-none focus:border-[#3b6ef6]/50"
                placeholder="e.g. Block outbound credit cards"
                value={form.name}
                onChange={e => set('name', e.target.value)}
              />
            </div>
            <div>
              <label className="text-[12px] text-[#71717a] mb-1.5 block">Severity</label>
              <select
                className="w-full bg-[#0d0d12] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] focus:outline-none focus:border-[#3b6ef6]/50"
                value={form.severity}
                onChange={e => set('severity', e.target.value)}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
            <div>
              <label className="text-[12px] text-[#71717a] mb-1.5 block">Enabled</label>
              <label className="flex items-center gap-2 mt-2 cursor-pointer">
                <input type="checkbox" checked={form.enabled} onChange={e => set('enabled', e.target.checked)} className="w-4 h-4 accent-[#3b6ef6]" />
                <span className="text-[13px] text-[#a1a1aa]">Policy active</span>
              </label>
            </div>
          </div>

          {/* Detection categories */}
          <div>
            <label className="text-[12px] text-[#71717a] mb-3 block">Detect Categories</label>
            <div className="grid grid-cols-2 gap-2">
              <CheckRow label="PII (SSN, passport, IBAN, credit card)" field="detect_pii" />
              <CheckRow label="Financial data (SWIFT, routing, account #)" field="detect_financial" />
              <CheckRow label="Credentials (API keys, passwords, tokens)" field="detect_credentials" />
              <CheckRow label="ITAR / Export-controlled content" field="detect_itar" />
              <CheckRow label="Bulk exfiltration (20+ recipients)" field="detect_bulk_exfil" />
              <CheckRow label="External recipients only" field="external_only" />
            </div>
          </div>

          {/* Action */}
          <div>
            <label className="text-[12px] text-[#71717a] mb-3 block">Action</label>
            <div className="flex gap-3 flex-wrap">
              {(['ALLOW', 'WARN', 'HOLD', 'BLOCK'] as const).map(a => (
                <label key={a} className="flex items-center gap-2 cursor-pointer">
                  <input type="radio" name="action" value={a} checked={form.action === a} onChange={() => set('action', a)} className="accent-[#3b6ef6]" />
                  <span className={`text-[13px] font-medium ${
                    a === 'ALLOW' ? 'text-emerald-400' :
                    a === 'WARN'  ? 'text-amber-400' :
                    a === 'HOLD'  ? 'text-orange-400' :
                    'text-red-400'
                  }`}>{a}</span>
                </label>
              ))}
            </div>
            <p className="text-[11px] text-[#71717a] mt-2">
              {form.action === 'ALLOW' ? 'Allow delivery, no notification.' :
               form.action === 'WARN'  ? 'Deliver with DLP warning header — sender notified if enabled.' :
               form.action === 'HOLD'  ? 'Hold for security review before delivery.' :
               'Permanently block — message is not delivered.'}
            </p>
          </div>

          {/* Notifications */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <CheckRow label="Notify sender when triggered" field="notify_sender" />
            </div>
            <div>
              <label className="text-[12px] text-[#71717a] mb-1.5 block">Manager notification email</label>
              <input
                className="w-full bg-[#0d0d12] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] placeholder-[#4a4a5a] focus:outline-none focus:border-[#3b6ef6]/50"
                placeholder="security@company.com"
                value={form.notify_manager_email || ''}
                onChange={e => set('notify_manager_email', e.target.value || null)}
              />
            </div>
          </div>

          {/* Custom keywords */}
          <div>
            <label className="text-[12px] text-[#71717a] mb-1.5 block">Custom Keywords</label>
            <div className="flex gap-2 mb-2">
              <input
                className="flex-1 bg-[#0d0d12] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] placeholder-[#4a4a5a] focus:outline-none focus:border-[#3b6ef6]/50"
                placeholder="classified, project-x, top secret"
                value={kwInput}
                onChange={e => setKwInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addKw()}
              />
              <button onClick={addKw} className="px-3 py-2 bg-[#1e1e2c] border border-white/[0.08] rounded-lg text-[#71717a] hover:text-white transition-colors"><Plus size={14} /></button>
            </div>
            <div className="flex flex-wrap gap-1">
              {form.custom_keywords.map((kw, i) => (
                <span key={i} className="flex items-center gap-1 text-[11px] px-2 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">
                  {kw}
                  <button onClick={() => removeKw(i)} className="text-[#71717a] hover:text-red-400"><X size={10} /></button>
                </span>
              ))}
            </div>
          </div>

          {/* Custom regex */}
          <div>
            <label className="text-[12px] text-[#71717a] mb-1.5 block">Custom Regex Patterns</label>
            <div className="flex gap-2 mb-2">
              <input
                className="flex-1 bg-[#0d0d12] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] font-mono text-[var(--foreground)] placeholder-[#4a4a5a] focus:outline-none focus:border-[#3b6ef6]/50"
                placeholder="\b[A-Z]{2}\d{6}\b"
                value={rxInput}
                onChange={e => setRxInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addRx()}
              />
              <button onClick={addRx} className="px-3 py-2 bg-[#1e1e2c] border border-white/[0.08] rounded-lg text-[#71717a] hover:text-white transition-colors"><Plus size={14} /></button>
            </div>
            <div className="flex flex-wrap gap-1">
              {form.custom_regex.map((rx, i) => (
                <span key={i} className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">
                  {rx}
                  <button onClick={() => removeRx(i)} className="text-[#71717a] hover:text-red-400"><X size={10} /></button>
                </span>
              ))}
            </div>
          </div>

          {error && <p className="text-[12px] text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">{error}</p>}
        </div>

        <div className="flex justify-end gap-3 p-5 border-t border-white/[0.06]">
          <button onClick={onClose} className="px-4 py-2 text-[13px] text-[#71717a] hover:text-white transition-colors">Cancel</button>
          <button
            onClick={submit}
            disabled={saving}
            className="px-5 py-2 bg-[#3b6ef6] hover:bg-[#2d5fe0] disabled:opacity-50 text-white text-[13px] font-medium rounded-lg transition-colors flex items-center gap-2"
          >
            {saving && <RefreshCw size={13} className="animate-spin" />}
            Create Policy
          </button>
        </div>
      </div>
    </div>
  )
}

// ── M365 Sync Button ────────────────────────────────────────────────

function SyncM365Button({ policy, onSync }: { policy: DLPPolicy; onSync: (id: string) => Promise<void> }) {
  const [syncing, setSyncing] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const handleSync = async () => {
    setSyncing(true)
    setToast(null)
    try {
      await onSync(policy.id)
      setToast('Synced!')
    } catch {
      setToast('Failed')
    } finally {
      setSyncing(false)
      setTimeout(() => setToast(null), 3000)
    }
  }

  const isSynced = policy.sync_status === 'synced'
  const hasError = policy.sync_status === 'error'

  return (
    <div className="flex items-center gap-1.5">
      <button
        onClick={handleSync}
        disabled={syncing}
        className={`flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border font-medium transition-colors ${
          isSynced
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20'
            : hasError
            ? 'bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20'
            : 'bg-[#0078d4]/10 border-[#0078d4]/30 text-[#0078d4] hover:bg-[#0078d4]/20'
        } disabled:opacity-50`}
        title={isSynced ? `Synced to M365${policy.last_synced_at ? ` · ${new Date(policy.last_synced_at).toLocaleDateString()}` : ''}` : 'Push to M365 as transport rule'}
      >
        {syncing ? (
          <RefreshCw size={9} className="animate-spin" />
        ) : (
          <span className="font-bold text-[9px]">M365</span>
        )}
        {syncing ? 'Syncing…' : isSynced ? '✓ Synced' : hasError ? '⚠ Retry' : 'Sync'}
      </button>
      {toast && (
        <span className={`text-[10px] font-medium ${
          toast === 'Synced!' ? 'text-emerald-400' : 'text-red-400'
        }`}>{toast}</span>
      )}
    </div>
  )
}

// ── GSuite Sync Button ──────────────────────────────────────────────

function SyncGSuiteButton({ policy, onSync }: { policy: DLPPolicy; onSync: (id: string) => Promise<void> }) {
  const [syncing, setSyncing] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const handleSync = async () => {
    setSyncing(true)
    setToast(null)
    try {
      await onSync(policy.id)
      setToast('Synced!')
    } catch {
      setToast('Failed')
    } finally {
      setSyncing(false)
      setTimeout(() => setToast(null), 3000)
    }
  }

  const isSynced = policy.gsuite_sync_status === 'synced'
  const hasError = policy.gsuite_sync_status === 'error'

  return (
    <div className="flex items-center gap-1.5">
      <button
        onClick={handleSync}
        disabled={syncing}
        className={`flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border font-medium transition-colors ${
          isSynced
            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20'
            : hasError
            ? 'bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20'
            : 'bg-[#4285F4]/10 border-[#4285F4]/30 text-[#4285F4] hover:bg-[#4285F4]/20'
        } disabled:opacity-50`}
        title={isSynced ? `Synced to GSuite${policy.gsuite_last_synced_at ? ` · ${new Date(policy.gsuite_last_synced_at).toLocaleDateString()}` : ''}` : 'Push to Google Workspace as content compliance rule'}
      >
        {syncing ? (
          <RefreshCw size={9} className="animate-spin" />
        ) : (
          <span className="font-bold text-[9px]">GWS</span>
        )}
        {syncing ? 'Syncing…' : isSynced ? '✓ Synced' : hasError ? '⚠ Retry' : 'Sync'}
      </button>
      {toast && (
        <span className={`text-[10px] font-medium ${
          toast === 'Synced!' ? 'text-emerald-400' : 'text-red-400'
        }`}>{toast}</span>
      )}
    </div>
  )
}

// ── Policies Tab ──────────────────────────────────────────────────────────────

function PoliciesTab({ policies, loading, onDelete, onToggle, onSyncM365, onSyncGSuite }: {
  policies: DLPPolicy[]
  loading: boolean
  onDelete: (id: string) => void
  onToggle: (id: string, enabled: boolean) => void
  onSyncM365: (id: string) => Promise<void>
  onSyncGSuite: (id: string) => Promise<void>
}) {
  if (loading) return <LoadingSkeleton rows={4} />
  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
      <Table>
        <Thead>
          <Tr>
            <Th>Policy Name</Th>
            <Th>Severity</Th>
            <Th>Detects</Th>
            <Th>Action</Th>
            <Th>Status</Th>
            <Th>Cloud Sync</Th>
            <Th></Th>
          </Tr>
        </Thead>
        <Tbody>
          {policies.length === 0 && (
            <Tr><Td colSpan={6} className="text-center text-[#71717a] py-12 text-[13px]">
              No DLP policies configured. Create one to start protecting your organization.
            </Td></Tr>
          )}
          {policies.map(p => (
            <Tr key={p.id}>
              <Td>
                <div className="font-medium text-[var(--foreground)] text-[13px]">{p.name}</div>
                {p.external_only && <span className="text-[10px] text-[#71717a]">External only</span>}
              </Td>
              <Td><RiskBadge level={p.severity} /></Td>
              <Td>
                <div className="flex flex-wrap gap-1">
                  {p.detect_pii && <span className="text-[10px] px-1.5 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">PII</span>}
                  {p.detect_financial && <span className="text-[10px] px-1.5 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">Financial</span>}
                  {p.detect_credentials && <span className="text-[10px] px-1.5 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">Credentials</span>}
                  {p.detect_itar && <span className="text-[10px] px-1.5 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">ITAR</span>}
                  {p.detect_bulk_exfil && <span className="text-[10px] px-1.5 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">Bulk</span>}
                </div>
              </Td>
              <Td><ActionBadge action={p.action} /></Td>
              <Td>
                <button
                  onClick={() => onToggle(p.id, !p.enabled)}
                  className={`text-[11px] px-2 py-0.5 rounded-full border font-medium transition-colors ${
                    p.enabled
                      ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20'
                      : 'bg-white/[0.04] border-white/10 text-[#71717a] hover:bg-white/[0.08]'
                  }`}
                >
                  {p.enabled ? 'Enabled' : 'Disabled'}
                </button>
              </Td>
              <Td>
                <div className="flex items-center gap-2">
                  <SyncM365Button policy={p} onSync={onSyncM365} />
                  <SyncGSuiteButton policy={p} onSync={onSyncGSuite} />
                </div>
              </Td>
              <Td>
                <button
                  onClick={() => onDelete(p.id)}
                  className="p-1.5 text-[#71717a] hover:text-red-400 rounded hover:bg-red-500/10 transition-colors"
                  title="Delete policy"
                >
                  <Trash2 size={13} />
                </button>
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>
    </div>
  )
}

// ── Queue Tab ─────────────────────────────────────────────────────────────────

function QueueTab({ queue, loading, onRelease, onBlock, releasing, blocking }: {
  queue: DLPQueueItem[]
  loading: boolean
  onRelease: (id: string) => void
  onBlock: (id: string) => void
  releasing: string | null
  blocking: string | null
}) {
  const [expanded, setExpanded] = useState<string | null>(null)
  if (loading) return <LoadingSkeleton rows={4} />
  return (
    <div>
      <div className="flex items-center gap-2 mb-3 text-[12px] text-[#93b4fd] bg-[#3b6ef6]/[0.06] border border-[#3b6ef6]/20 rounded-xl px-4 py-3">
        <Info size={13} />
        <span>Held emails await human review. Auto-refreshes every 30s. Held items expire after 4 hours.</span>
      </div>
      <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th></Th>
              <Th>Sender</Th>
              <Th>Subject</Th>
              <Th>Risk</Th>
              <Th>Categories</Th>
              <Th>Expires</Th>
              <Th>Actions</Th>
            </Tr>
          </Thead>
          <Tbody>
            {queue.length === 0 && (
              <Tr><Td colSpan={7} className="text-center text-[#71717a] py-12 text-[13px]">
                No emails currently held for review ✓
              </Td></Tr>
            )}
            {queue.map(item => (
              <React.Fragment key={item.id}>
                <Tr className="cursor-pointer hover:bg-white/[0.02]" onClick={() => setExpanded(expanded === item.id ? null : item.id)}>
                  <Td className="w-6">
                    {expanded === item.id ? <ChevronUp size={12} className="text-[#71717a]" /> : <ChevronDown size={12} className="text-[#71717a]" />}
                  </Td>
                  <Td className="text-[12px] text-[var(--foreground)] max-w-[140px] truncate" title={item.sender_email || ''}>
                    {item.sender_email || '—'}
                  </Td>
                  <Td className="text-[12px] text-[#a1a1aa] max-w-[180px] truncate" title={item.subject || ''}>
                    {item.subject || '(no subject)'}
                  </Td>
                  <Td><RiskBadge level={item.risk_level} /></Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {(item.categories_found || []).slice(0, 3).map(c => (
                        <span key={c} className="text-[10px] px-1.5 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">
                          {c.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </Td>
                  <Td className="text-[11px] text-[#71717a]">
                    {item.expires_at ? new Date(item.expires_at).toLocaleTimeString() : '—'}
                  </Td>
                  <Td onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => onRelease(item.id)}
                        disabled={releasing === item.id || blocking === item.id}
                        className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-emerald-400 border border-emerald-500/20 rounded-lg hover:bg-emerald-500/10 transition-colors disabled:opacity-50"
                      >
                        {releasing === item.id ? <RefreshCw size={10} className="animate-spin" /> : <Send size={10} />}
                        Release
                      </button>
                      <button
                        onClick={() => onBlock(item.id)}
                        disabled={releasing === item.id || blocking === item.id}
                        className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-red-400 border border-red-500/20 rounded-lg hover:bg-red-500/10 transition-colors disabled:opacity-50"
                      >
                        {blocking === item.id ? <RefreshCw size={10} className="animate-spin" /> : <ShieldAlert size={10} />}
                        Block
                      </button>
                    </div>
                  </Td>
                </Tr>
                {expanded === item.id && (
                  <Tr>
                    <Td colSpan={7} className="bg-[#0d0d12] px-6 py-3">
                      <div className="text-[11px] text-[#71717a] mb-1 font-medium uppercase tracking-wide">Body Preview</div>
                      <p className="text-[12px] text-[#a1a1aa] leading-relaxed whitespace-pre-wrap">
                        {(item as DLPQueueItem & { body_preview?: string }).body_preview || '— No preview available —'}
                      </p>
                    </Td>
                  </Tr>
                )}
              </React.Fragment>
            ))}
          </Tbody>
        </Table>
      </div>
    </div>
  )
}

// ── Logs Tab ──────────────────────────────────────────────────────────────────

function LogsTab({ events, loading, total, page, pageSize, onPage, onFilter, riskFilter, actionFilter }: {
  events: DLPEvent[]
  loading: boolean
  total: number
  page: number
  pageSize: number
  onPage: (p: number) => void
  onFilter: (risk: string, action: string) => void
  riskFilter: string
  actionFilter: string
}) {
  const totalPages = Math.ceil(total / pageSize)
  const [expanded, setExpanded] = useState<string | null>(null)
  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-3">
        <Filter size={13} className="text-[#71717a]" />
        <select
          className="bg-[#13131a] border border-white/[0.08] rounded-lg px-3 py-1.5 text-[12px] text-[#a1a1aa] focus:outline-none focus:border-[#3b6ef6]/50"
          value={riskFilter}
          onChange={e => onFilter(e.target.value, actionFilter)}
        >
          <option value="">All Risks</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
        <select
          className="bg-[#13131a] border border-white/[0.08] rounded-lg px-3 py-1.5 text-[12px] text-[#a1a1aa] focus:outline-none focus:border-[#3b6ef6]/50"
          value={actionFilter}
          onChange={e => onFilter(riskFilter, e.target.value)}
        >
          <option value="">All Actions</option>
          <option value="ALLOW">ALLOW</option>
          <option value="WARN">WARN</option>
          <option value="HOLD">HOLD</option>
          <option value="BLOCK">BLOCK</option>
        </select>
        <span className="text-[11px] text-[#71717a] ml-auto">{total} events</span>
      </div>

      {loading ? <LoadingSkeleton rows={8} /> : (
        <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
          <Table>
            <Thead>
              <Tr>
                <Th></Th>
                <Th>Time</Th>
                <Th>Sender</Th>
                <Th>Subject</Th>
                <Th>Risk</Th>
                <Th>Action</Th>
                <Th>Categories</Th>
                <Th>Reviewed</Th>
              </Tr>
            </Thead>
            <Tbody>
              {events.length === 0 && (
                <Tr><Td colSpan={8} className="text-center text-[#71717a] py-12 text-[13px]">No events found</Td></Tr>
              )}
              {events.map(e => {
                const categories = Array.isArray(e.categories_found) ? e.categories_found.filter(Boolean) : []
                const patterns = Array.isArray(e.matched_patterns) ? e.matched_patterns.filter(Boolean) : []
                return (
                  <React.Fragment key={e.id}>
                    <Tr className="cursor-pointer hover:bg-white/[0.02]" onClick={() => setExpanded(expanded === e.id ? null : e.id)}>
                      <Td className="w-6">
                        {expanded === e.id ? <ChevronUp size={12} className="text-[#71717a]" /> : <ChevronDown size={12} className="text-[#71717a]" />}
                      </Td>
                      <Td className="text-[11px] text-[#71717a] whitespace-nowrap">
                        {e.created_at ? new Date(e.created_at).toLocaleString() : '—'}
                      </Td>
                      <Td className="text-[12px] text-[var(--foreground)] max-w-[130px] truncate" title={e.sender_email || ''}>
                        {e.sender_email || '—'}
                      </Td>
                      <Td className="text-[12px] text-[#a1a1aa] max-w-[150px] truncate" title={e.subject || ''}>
                        {e.subject || '(no subject)'}
                      </Td>
                      <Td><RiskBadge level={e.risk_level} /></Td>
                      <Td><ActionBadge action={e.action_taken} /></Td>
                      <Td>
                        <div className="flex flex-wrap gap-1">
                          {categories.slice(0, 2).map((c, idx) => (
                            <span key={`${c}-${idx}`} className="text-[10px] px-1.5 py-0.5 bg-[#1e1e2c] border border-white/[0.07] rounded text-[#a1a1aa]">
                              {String(c).replace(/_/g, ' ')}
                            </span>
                          ))}
                          {categories.length > 2 && (
                            <span className="text-[10px] text-[#71717a]">+{categories.length - 2}</span>
                          )}
                        </div>
                      </Td>
                      <Td className="text-[11px] text-[#71717a]">
                        {e.review_action ? (
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                            e.review_action === 'release' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
                          }`}>
                            {e.review_action}
                          </span>
                        ) : '—'}
                      </Td>
                    </Tr>
                    {expanded === e.id && (
                      <Tr>
                        <Td colSpan={8} className="bg-[#0d0d12] px-6 py-3">
                          <div className="text-[11px] text-[#71717a] mb-1 font-medium uppercase tracking-wide">Body Preview</div>
                          <p className="text-[12px] text-[#a1a1aa] leading-relaxed whitespace-pre-wrap mb-2">
                            {e.body_preview || '— No preview available —'}
                          </p>
                          {patterns.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              <span className="text-[11px] text-[#71717a] mr-1">Matched:</span>
                              {patterns.map((p, idx) => (
                                <span key={`${p}-${idx}`} className="text-[10px] px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 rounded text-red-400">
                                  {String(p).replace(/_/g, ' ')}
                                </span>
                              ))}
                            </div>
                          )}
                        </Td>
                      </Tr>
                    )}
                  </React.Fragment>
                )
              })}
            </Tbody>
          </Table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => onPage(page - 1)}
            disabled={page === 1}
            className="p-1.5 text-[#71717a] hover:text-white disabled:opacity-40 transition-colors"
          >
            <ChevronLeft size={15} />
          </button>
          <span className="text-[12px] text-[#71717a]">Page {page} of {totalPages}</span>
          <button
            onClick={() => onPage(page + 1)}
            disabled={page === totalPages}
            className="p-1.5 text-[#71717a] hover:text-white disabled:opacity-40 transition-colors"
          >
            <ChevronRight size={15} />
          </button>
        </div>
      )}
    </div>
  )
}

// ── Guide Modal ─────────────────────────────────────────────────────────────

type GuideType = 'm365' | 'gmail' | null

function GuideModal({ type, onClose }: { type: GuideType; onClose: () => void }) {
  const [copied, setCopied] = useState<string | null>(null)
  if (!type) return null

  const isM365 = type === 'm365'

  const steps = isM365 ? [
    {
      n: 1, title: 'How it works',
      body: 'Helios DLP intercepts outbound email by acting as an SMTP smart host (relay). Your Exchange tenant routes outbound mail through a Helios-managed gateway before it reaches the internet. No transport rule can POST to an HTTP endpoint natively — the connector approach is required.',
    },
    {
      n: 2, title: 'Prerequisites',
      body: 'Your Himaya account team provisions a DLP Gateway for your tenant. Contact support@himaya.ai to request activation. You will receive:\n• A gateway FQDN (e.g. dlp-gateway.himaya.ai)\n• A TLS certificate fingerprint to verify\n• Your org\'s DLP webhook secret',
    },
    {
      n: 3, title: 'Create an outbound connector in Exchange Admin',
      body: 'Go to admin.exchange.microsoft.com → Mail flow → Connectors → + Add a connector.\n\nFrom: Office 365\nTo: Partner organization\nName: Helios DLP Gateway\n\nRouting: Route email through these smart hosts → add the gateway FQDN provided by Himaya.\n\nSecurity: Always use TLS → Issued by a trusted CA.',
    },
    {
      n: 4, title: 'Create a transport rule to use the connector',
      body: 'Mail flow → Rules → + Add a rule → Create a new rule.\n\nApply this rule if: The sender is located → Inside the organization\nAND the recipient is located → Outside the organization.\n\nDo the following: Redirect the message to → the following connector → select "Helios DLP Gateway".',
    },
    {
      n: 5, title: 'How blocking works',
      body: 'When Helios DLP classifies an email as HOLD or BLOCK, the gateway returns a 5xx SMTP rejection. Exchange generates an NDR to the sender automatically. ALLOW and WARN emails are delivered normally.',
    },
    {
      n: 6, title: 'Test it',
      body: 'Once the connector is active, use the Test Classification button in Settings to verify the pipeline. Or send an outbound email containing a test SSN (123-45-6789) to an external address — it should appear in the DLP Queue within seconds.',
    },
  ] : [
    {
      n: 1, title: 'How it works',
      body: 'Helios DLP intercepts outbound Gmail by acting as an SMTP relay (smart host). Gmail\'s content compliance rules can\'t POST to HTTP endpoints — the correct integration is routing outbound mail through a Helios-managed SMTP gateway that inspects and optionally rejects messages.',
    },
    {
      n: 2, title: 'Prerequisites',
      body: 'Your Himaya account team provisions a DLP Gateway for your domain. Contact support@himaya.ai to request activation. You will receive:\n• A gateway SMTP address (e.g. dlp-gateway.himaya.ai:25)\n• Your org\'s DLP webhook secret\n• An allowlisted sender IP range',
    },
    {
      n: 3, title: 'Add a Gmail routing rule',
      body: 'Go to admin.google.com → Apps → Google Workspace → Gmail → Routing.\n\nScroll to "Routing" → Configure.\n\nMessages to affect: Outbound\n\nAlso deliver to: Add more recipients → Advanced → Change route → Add route:\nSMTP server: dlp-gateway.himaya.ai\nPort: 25\nRequire secure transport (TLS): checked',
    },
    {
      n: 4, title: 'How blocking works',
      body: 'When Helios DLP classifies an email as HOLD or BLOCK, the gateway returns a 5xx SMTP rejection. Gmail generates a bounce to the sender. ALLOW and WARN emails are delivered normally through the relay.',
    },
    {
      n: 5, title: 'Test it',
      body: 'Once routing is active, use the Test Classification button in Settings to verify the pipeline. Or send an outbound email from your domain containing "SSN: 123-45-6789" to an external address — it should appear in the DLP Queue.',
    },
  ]

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-[#13131a] border border-white/[0.08] rounded-2xl w-full max-w-xl max-h-[85vh] overflow-y-auto shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between p-5 border-b border-white/[0.06]">
          <h2 className="text-[15px] font-semibold text-[var(--foreground)] flex items-center gap-2">
            <ClipboardList size={15} className="text-[#3b6ef6]" />
            {isM365 ? 'Microsoft 365 — DLP Integration' : 'Google Workspace — DLP Integration'}
          </h2>
          <button onClick={onClose} className="text-[#71717a] hover:text-white transition-colors"><X size={18} /></button>
        </div>
        <div className="p-5 space-y-4">
          {steps.map(step => (
            <div key={step.n} className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-[#3b6ef6]/20 border border-[#3b6ef6]/30 text-[#3b6ef6] text-[11px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">
                {step.n}
              </div>
              <div className="flex-1">
                <div className="text-[13px] font-medium text-[var(--foreground)] mb-1">{step.title}</div>
                <p className="text-[12px] text-[#71717a] leading-relaxed whitespace-pre-line">{step.body}</p>

              </div>
            </div>
          ))}
        </div>
        <div className="flex justify-end p-5 border-t border-white/[0.06]">
          <button onClick={onClose} className="px-4 py-2 bg-[#3b6ef6] hover:bg-[#2d5fe0] text-white text-[13px] font-medium rounded-lg transition-colors">Got it</button>
        </div>
      </div>
    </div>
  )
}

// ── Quick Setup Tab (One-Click DLP) ───────────────────────────────────────────────

function QuickSetupTab({ onEnable }: { onEnable: () => void }) {
  const [status, setStatus] = useState<DLPSetupStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [enabling, setEnabling] = useState(false)
  const [disabling, setDisabling] = useState(false)
  const [config, setConfig] = useState<DLPSetupConfig>({
    scan_outbound: true,
    scan_inbound: false,
    action_pii: 'warn',
    action_financial: 'warn',
    action_credentials: 'block',
    action_legal: 'hold',
    notify_sender: true,
    notify_admin: true,
    admin_emails: [],
  })
  const [adminEmail, setAdminEmail] = useState('')

  useEffect(() => {
    loadStatus()
  }, [])

  const loadStatus = async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/dlp/setup/status')
      setStatus(r.data)
      if (r.data.config) {
        setConfig(r.data.config)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  const handleEnable = async () => {
    setEnabling(true)
    try {
      await api.post('/api/dlp/setup/enable', config)
      await loadStatus()
      onEnable()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to enable DLP'
      alert('Error: ' + errorMessage)
    } finally {
      setEnabling(false)
    }
  }

  const handleDisable = async () => {
    if (!confirm('Are you sure you want to disable DLP protection?')) return
    setDisabling(true)
    try {
      await api.post('/api/dlp/setup/disable')
      await loadStatus()
    } catch {
      // ignore
    } finally {
      setDisabling(false)
    }
  }

  const handleUpdateConfig = async () => {
    try {
      await api.put('/api/dlp/setup/config', config)
      await loadStatus()
    } catch {
      // ignore
    }
  }

  const addAdminEmail = () => {
    if (adminEmail && !config.admin_emails.includes(adminEmail)) {
      setConfig({ ...config, admin_emails: [...config.admin_emails, adminEmail] })
      setAdminEmail('')
    }
  }

  const removeAdminEmail = (email: string) => {
    setConfig({ ...config, admin_emails: config.admin_emails.filter(e => e !== email) })
  }

  if (loading) {
    return <LoadingSkeleton rows={3} />
  }

  // If DLP is already enabled, show status and config
  if (status?.enabled) {
    return (
      <div className="space-y-5 max-w-2xl">
        {/* Status Card */}
        <div className="bg-gradient-to-br from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-xl p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-xl bg-emerald-500/20 flex items-center justify-center">
                <ShieldCheck size={24} className="text-emerald-400" />
              </div>
              <div>
                <h3 className="text-[15px] font-semibold text-emerald-400">DLP Protection Active</h3>
                <p className="text-[12px] text-[#a1a1aa] mt-0.5">
                  Enabled {status.enabled_at ? new Date(status.enabled_at).toLocaleDateString() : 'recently'}
                </p>
              </div>
            </div>
            <button
              onClick={handleDisable}
              disabled={disabling}
              className="text-[12px] text-red-400 hover:text-red-300 transition-colors"
            >
              {disabling ? 'Disabling...' : 'Disable'}
            </button>
          </div>
          <div className="mt-4 grid grid-cols-2 gap-3">
            <div className="bg-black/20 rounded-lg p-3">
              <div className="text-[11px] text-[#71717a] mb-1">Scanning</div>
              <div className="text-[13px] text-[var(--foreground)]">
                {config.scan_outbound && 'Outbound'}
                {config.scan_outbound && config.scan_inbound && ' + '}
                {config.scan_inbound && 'Inbound'}
                {!config.scan_outbound && !config.scan_inbound && 'None'}
              </div>
            </div>
            <div className="bg-black/20 rounded-lg p-3">
              <div className="text-[11px] text-[#71717a] mb-1">Credentials Policy</div>
              <div className="text-[13px] text-[var(--foreground)] capitalize">{config.action_credentials}</div>
            </div>
          </div>
        </div>

        {/* Configuration */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4">Configuration</h3>
          
          {/* Scanning options */}
          <div className="space-y-3 mb-5">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.scan_outbound}
                onChange={e => setConfig({ ...config, scan_outbound: e.target.checked })}
                className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
              />
              <span className="text-[13px] text-[var(--foreground)]">Scan outbound emails</span>
            </label>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.scan_inbound}
                onChange={e => setConfig({ ...config, scan_inbound: e.target.checked })}
                className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
              />
              <span className="text-[13px] text-[var(--foreground)]">Scan inbound emails</span>
            </label>
          </div>

          {/* Action settings */}
          <div className="grid grid-cols-2 gap-4 mb-5">
            {[
              { key: 'action_pii', label: 'PII Detection', Icon: User },
              { key: 'action_financial', label: 'Financial Data', Icon: CreditCard },
              { key: 'action_credentials', label: 'Credentials/Secrets', Icon: Key },
              { key: 'action_legal', label: 'Legal/Confidential', Icon: Scale },
            ].map(({ key, label, Icon }) => (
              <div key={key}>
                <label className="text-[11px] text-[#71717a] mb-1 flex items-center gap-1.5">
                  <Icon size={12} /> {label}
                </label>
                <select
                  value={config[key as keyof DLPSetupConfig] as string}
                  onChange={e => setConfig({ ...config, [key]: e.target.value })}
                  className="w-full bg-[#0d0d12] border border-white/[0.07] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] focus:outline-none focus:border-[#3b6ef6]/50"
                >
                  <option value="warn">Warn</option>
                  <option value="hold">Hold for Review</option>
                  <option value="block">Block</option>
                  <option value="recall">Block + Auto-Recall</option>
                </select>
              </div>
            ))}
          </div>

          {/* Notifications */}
          <div className="space-y-3 mb-5 pt-4 border-t border-white/[0.06]">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.notify_sender}
                onChange={e => setConfig({ ...config, notify_sender: e.target.checked })}
                className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
              />
              <span className="text-[13px] text-[var(--foreground)]">Notify sender on violation</span>
            </label>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.notify_admin}
                onChange={e => setConfig({ ...config, notify_admin: e.target.checked })}
                className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
              />
              <span className="text-[13px] text-[var(--foreground)]">Notify admins on violation</span>
            </label>
          </div>

          {/* Admin emails */}
          {config.notify_admin && (
            <div className="pt-4 border-t border-white/[0.06]">
              <label className="text-[11px] text-[#71717a] mb-2 block">Admin notification emails</label>
              <div className="flex gap-2 mb-2">
                <input
                  type="email"
                  value={adminEmail}
                  onChange={e => setAdminEmail(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addAdminEmail()}
                  placeholder="admin@company.com"
                  className="flex-1 bg-[#0d0d12] border border-white/[0.07] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] placeholder-[#52525b] focus:outline-none focus:border-[#3b6ef6]/50"
                />
                <button
                  onClick={addAdminEmail}
                  className="px-3 py-2 bg-white/[0.05] border border-white/[0.07] rounded-lg text-[13px] text-[#71717a] hover:text-white hover:bg-white/[0.08] transition-colors"
                >
                  Add
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {config.admin_emails.map(email => (
                  <span key={email} className="inline-flex items-center gap-1.5 px-2 py-1 bg-white/[0.05] border border-white/[0.07] rounded-lg text-[12px] text-[#a1a1aa]">
                    {email}
                    <button onClick={() => removeAdminEmail(email)} className="text-[#71717a] hover:text-white">
                      <X size={12} />
                    </button>
                  </span>
                ))}
              </div>
            </div>
          )}

          <button
            onClick={handleUpdateConfig}
            className="mt-5 px-4 py-2 bg-[#3b6ef6] hover:bg-[#2d5fe0] text-white text-[13px] font-medium rounded-lg transition-colors"
          >
            Save Changes
          </button>
        </div>
      </div>
    )
  }

  // DLP not enabled - show setup wizard
  return (
    <div className="max-w-2xl space-y-6">
      {/* Hero Card */}
      <div className="bg-gradient-to-br from-[#3b6ef6]/10 to-[#6366f1]/10 border border-[#3b6ef6]/20 rounded-2xl p-8 text-center">
        <div className="w-16 h-16 rounded-2xl bg-[#3b6ef6]/20 flex items-center justify-center mx-auto mb-4">
          <Shield size={32} className="text-[#3b6ef6]" />
        </div>
        <h2 className="text-xl font-semibold text-[var(--foreground)] mb-2">Enable Data Loss Prevention</h2>
        <p className="text-[14px] text-[#a1a1aa] mb-6 max-w-md mx-auto">
          Protect your organization from accidental data leaks. Helios automatically scans emails
          for sensitive data using your existing email integration — no complex routing required.
        </p>
        
        {/* Benefits */}
        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            { icon: Zap, label: 'One-Click Setup', desc: 'Works with your existing integration' },
            { icon: Shield, label: 'AI-Powered', desc: 'Falcon DataEye classification' },
            { icon: Eye, label: 'Real-Time', desc: 'Scans during email sync' },
          ].map(({ icon: Icon, label, desc }) => (
            <div key={label} className="p-4 bg-black/20 rounded-xl">
              <Icon size={18} className="text-[#3b6ef6] mx-auto mb-2" />
              <div className="text-[12px] font-medium text-[var(--foreground)]">{label}</div>
              <div className="text-[11px] text-[#71717a]">{desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Configuration */}
      <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4">Configure Protection</h3>
        
        {/* What to scan */}
        <div className="space-y-3 mb-5">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.scan_outbound}
              onChange={e => setConfig({ ...config, scan_outbound: e.target.checked })}
              className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
            />
            <div>
              <span className="text-[13px] text-[var(--foreground)]">Scan outbound emails</span>
              <p className="text-[11px] text-[#71717a]">Prevent sensitive data from leaving your organization</p>
            </div>
          </label>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.scan_inbound}
              onChange={e => setConfig({ ...config, scan_inbound: e.target.checked })}
              className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
            />
            <div>
              <span className="text-[13px] text-[var(--foreground)]">Scan inbound emails</span>
              <p className="text-[11px] text-[#71717a]">Detect sensitive data received from external senders</p>
            </div>
          </label>
        </div>

        {/* Actions per category */}
        <div className="pt-4 border-t border-white/[0.06]">
          <div className="text-[12px] text-[#71717a] mb-3">What to do when sensitive data is detected:</div>
          <div className="grid grid-cols-2 gap-4">
            {[
              { key: 'action_pii', label: 'Personal Info (SSN, IDs)', Icon: User },
              { key: 'action_financial', label: 'Financial Data', Icon: CreditCard },
              { key: 'action_credentials', label: 'Credentials & Secrets', Icon: Key },
              { key: 'action_legal', label: 'Legal & Confidential', Icon: Scale },
            ].map(({ key, label, Icon }) => (
              <div key={key} className="bg-[#0d0d12] border border-white/[0.07] rounded-lg p-3">
                <label className="text-[12px] text-[#a1a1aa] mb-2 flex items-center gap-2">
                  <Icon size={14} className="text-[#71717a]" /> {label}
                </label>
                <select
                  value={config[key as keyof DLPSetupConfig] as string}
                  onChange={e => setConfig({ ...config, [key]: e.target.value })}
                  className="w-full bg-[#13131a] border border-white/[0.07] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] focus:outline-none focus:border-[#3b6ef6]/50"
                >
                  <option value="warn">Warn (log only)</option>
                  <option value="hold">Hold for Review</option>
                  <option value="block">Block</option>
                  <option value="recall">Block + Auto-Recall</option>
                </select>
              </div>
            ))}
          </div>
        </div>

        {/* Notifications */}
        <div className="pt-4 mt-4 border-t border-white/[0.06]">
          <div className="text-[12px] text-[#71717a] mb-3">Notifications:</div>
          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.notify_sender}
                onChange={e => setConfig({ ...config, notify_sender: e.target.checked })}
                className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
              />
              <span className="text-[13px] text-[var(--foreground)]">Notify sender when their email is flagged</span>
            </label>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.notify_admin}
                onChange={e => setConfig({ ...config, notify_admin: e.target.checked })}
                className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
              />
              <span className="text-[13px] text-[var(--foreground)]">Notify admins about violations</span>
            </label>
          </div>
        </div>
      </div>

      {/* Enable button */}
      <button
        onClick={handleEnable}
        disabled={enabling || (!config.scan_outbound && !config.scan_inbound)}
        className="w-full py-3 bg-[#3b6ef6] hover:bg-[#2d5fe0] disabled:opacity-50 disabled:cursor-not-allowed text-white text-[14px] font-semibold rounded-xl transition-colors flex items-center justify-center gap-2"
      >
        {enabling ? (
          <><RefreshCw size={16} className="animate-spin" /> Enabling DLP...</>
        ) : (
          <><ShieldCheck size={16} /> Enable DLP Protection</>
        )}
      </button>

      <p className="text-[11px] text-[#52525b] text-center">
        DLP scanning uses your existing email integration. No additional configuration required.
      </p>
    </div>
  )
}

// ── Settings Tab ───────────────────────────────────────────────────────────

function SettingsTab({ onConfigChange }: { onConfigChange?: () => void }) {
  const [status, setStatus] = useState<DLPSetupStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [enabling, setEnabling] = useState(false)
  const [disabling, setDisabling] = useState(false)
  const [engineStatus, setEngineStatus] = useState<'checking' | 'ok' | 'offline'>('checking')
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<{ action: string; risk: string; categories: string[]; explanation: string } | null>(null)
  const [config, setConfig] = useState<DLPSetupConfig>({
    scan_outbound: true,
    scan_inbound: false,
    action_pii: 'warn',
    action_financial: 'warn',
    action_credentials: 'block',
    action_legal: 'hold',
    notify_sender: true,
    notify_admin: true,
    admin_emails: [],
  })
  const [adminEmail, setAdminEmail] = useState('')

  useEffect(() => {
    loadStatus()
    api.get('/api/dlp/engine/status')
      .then(r => setEngineStatus(r.data?.llm_status === 'loaded' ? 'ok' : 'offline'))
      .catch(() => setEngineStatus('offline'))
  }, [])

  const loadStatus = async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/dlp/setup/status')
      setStatus(r.data)
      if (r.data.config) {
        setConfig(r.data.config)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  const handleEnable = async () => {
    setEnabling(true)
    try {
      await api.post('/api/dlp/setup/enable', config)
      await loadStatus()
      onConfigChange?.()
    } catch {
      // ignore
    } finally {
      setEnabling(false)
    }
  }

  const handleDisable = async () => {
    if (!confirm('Are you sure you want to disable DLP protection?')) return
    setDisabling(true)
    try {
      await api.post('/api/dlp/setup/disable')
      await loadStatus()
    } catch {
      // ignore
    } finally {
      setDisabling(false)
    }
  }

  const handleUpdateConfig = async () => {
    try {
      await api.put('/api/dlp/setup/config', config)
      await loadStatus()
    } catch {
      // ignore
    }
  }

  const addAdminEmail = () => {
    if (adminEmail && !config.admin_emails.includes(adminEmail)) {
      setConfig({ ...config, admin_emails: [...config.admin_emails, adminEmail] })
      setAdminEmail('')
    }
  }

  const removeAdminEmail = (email: string) => {
    setConfig({ ...config, admin_emails: config.admin_emails.filter(e => e !== email) })
  }

  const runTest = async () => {
    setTesting(true)
    setTestResult(null)
    try {
      const r = await api.post('/api/dlp/classify', {
        sender: 'test@himaya.ai',
        recipients: ['external-test@gmail.com'],
        subject: 'DLP Test — Synthetic Sensitive Email',
        body: 'This is a synthetic test from Helios DLP. Test SSN: 123-45-6789. Wire transfer to IBAN GB29NWBK60161331926819 for $50,000.',
        provider: 'm365',
      })
      setTestResult({
        action: r.data.action,
        risk: r.data.risk_level,
        categories: r.data.categories || [],
        explanation: r.data.explanation || '',
      })
    } catch {
      setTestResult({ action: 'ERROR', risk: 'unknown', categories: [], explanation: 'Test request failed — check backend logs.' })
    } finally {
      setTesting(false)
    }
  }

  if (loading) {
    return <LoadingSkeleton rows={4} />
  }

  return (
    <div className="space-y-5 max-w-2xl">
      {/* DLP Protection Status */}
      {status?.enabled ? (
        <div className="bg-gradient-to-br from-emerald-500/10 to-emerald-500/5 border border-emerald-500/20 rounded-xl p-5">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-500/20 flex items-center justify-center">
                <ShieldCheck size={20} className="text-emerald-400" />
              </div>
              <div>
                <h3 className="text-[14px] font-semibold text-emerald-400">DLP Protection Active</h3>
                <p className="text-[11px] text-[#a1a1aa] mt-0.5">
                  Scanning {config.scan_outbound ? 'outbound' : ''}{config.scan_outbound && config.scan_inbound ? ' + ' : ''}{config.scan_inbound ? 'inbound' : ''} emails
                </p>
              </div>
            </div>
            <button
              onClick={handleDisable}
              disabled={disabling}
              className="text-[11px] text-red-400 hover:text-red-300 transition-colors px-2 py-1 rounded hover:bg-red-500/10"
            >
              {disabling ? 'Disabling...' : 'Disable'}
            </button>
          </div>
        </div>
      ) : (
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-[#3b6ef6]/10 flex items-center justify-center">
                <Shield size={20} className="text-[#3b6ef6]" />
              </div>
              <div>
                <h3 className="text-[14px] font-semibold text-[var(--foreground)]">DLP Protection Disabled</h3>
                <p className="text-[11px] text-[#71717a] mt-0.5">
                  Enable to scan emails for sensitive data
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Falcon DataEye Engine status */}
      <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-3 flex items-center gap-2">
          <Zap size={14} className="text-[#3b6ef6]" />
          Falcon DataEye Engine
        </h3>
        <div className="flex items-center gap-3">
          <div className={`w-2 h-2 rounded-full ${
            engineStatus === 'ok' ? 'bg-emerald-400' :
            engineStatus === 'offline' ? 'bg-red-400' :
            'bg-amber-400 animate-pulse'
          }`} />
          <span className="text-[12px] text-[#a1a1aa]">
            {engineStatus === 'ok' ? 'Active' :
             engineStatus === 'offline' ? 'Offline — pattern-matching mode' :
             'Checking...'}
          </span>
        </div>
      </div>

      {/* Configuration */}
      <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-4">DLP Configuration</h3>
        
        {/* Scanning options */}
        <div className="space-y-3 mb-5">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.scan_outbound}
              onChange={e => setConfig({ ...config, scan_outbound: e.target.checked })}
              className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
            />
            <div>
              <span className="text-[13px] text-[var(--foreground)]">Scan outbound emails</span>
              <span className="ml-2 text-[10px] px-1.5 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 rounded">Recommended</span>
              <p className="text-[11px] text-[#71717a] mt-0.5">Detect sensitive data leaving your organization</p>
            </div>
          </label>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.scan_inbound}
              onChange={e => setConfig({ ...config, scan_inbound: e.target.checked })}
              className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
            />
            <div>
              <span className="text-[13px] text-[var(--foreground)]">Scan inbound emails</span>
              <p className="text-[11px] text-[#71717a] mt-0.5">Flag incoming emails containing sensitive data patterns</p>
            </div>
          </label>
        </div>

        {/* Action settings */}
        <div className="grid grid-cols-2 gap-4 mb-5">
          {[
            { key: 'action_pii', label: 'PII Detection', Icon: User },
            { key: 'action_financial', label: 'Financial Data', Icon: CreditCard },
            { key: 'action_credentials', label: 'Credentials', Icon: Key },
            { key: 'action_legal', label: 'Legal/Confidential', Icon: Scale },
          ].map(({ key, label, Icon }) => (
            <div key={key}>
              <label className="text-[11px] text-[#71717a] mb-1 flex items-center gap-1.5">
                <Icon size={11} /> {label}
              </label>
              <select
                value={config[key as keyof DLPSetupConfig] as string}
                onChange={e => setConfig({ ...config, [key]: e.target.value })}
                className="w-full bg-[#0d0d12] border border-white/[0.07] rounded-lg px-3 py-2 text-[12px] text-[var(--foreground)] focus:outline-none focus:border-[#3b6ef6]/50"
              >
                <option value="warn">Warn</option>
                <option value="hold">Hold for Review</option>
                <option value="block">Block</option>
                <option value="recall">Block + Auto-Recall</option>
              </select>
            </div>
          ))}
        </div>

        {/* Notifications */}
        <div className="space-y-3 pt-4 border-t border-white/[0.06]">
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.notify_sender}
              onChange={e => setConfig({ ...config, notify_sender: e.target.checked })}
              className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
            />
            <span className="text-[12px] text-[var(--foreground)]">Notify sender on violation</span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer">
            <input
              type="checkbox"
              checked={config.notify_admin}
              onChange={e => setConfig({ ...config, notify_admin: e.target.checked })}
              className="w-4 h-4 rounded border-white/20 bg-white/5 text-[#3b6ef6] focus:ring-[#3b6ef6]/50"
            />
            <span className="text-[12px] text-[var(--foreground)]">Notify admins on violation</span>
          </label>
        </div>

        {/* Admin emails */}
        {config.notify_admin && (
          <div className="pt-4 mt-4 border-t border-white/[0.06]">
            <label className="text-[11px] text-[#71717a] mb-2 block">Admin notification emails</label>
            <div className="flex gap-2 mb-2">
              <input
                type="email"
                value={adminEmail}
                onChange={e => setAdminEmail(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addAdminEmail()}
                placeholder="admin@company.com"
                className="flex-1 bg-[#0d0d12] border border-white/[0.07] rounded-lg px-3 py-2 text-[12px] text-[var(--foreground)] placeholder-[#52525b] focus:outline-none focus:border-[#3b6ef6]/50"
              />
              <button
                onClick={addAdminEmail}
                className="px-3 py-2 bg-white/[0.05] border border-white/[0.07] rounded-lg text-[12px] text-[#71717a] hover:text-white hover:bg-white/[0.08] transition-colors"
              >
                Add
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {config.admin_emails.map(email => (
                <span key={email} className="inline-flex items-center gap-1.5 px-2 py-1 bg-white/[0.05] border border-white/[0.07] rounded-lg text-[11px] text-[#a1a1aa]">
                  {email}
                  <button onClick={() => removeAdminEmail(email)} className="text-[#71717a] hover:text-white">
                    <X size={10} />
                  </button>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Save / Enable buttons */}
        <div className="flex gap-3 mt-5 pt-4 border-t border-white/[0.06]">
          {status?.enabled ? (
            <button
              onClick={handleUpdateConfig}
              className="px-4 py-2 bg-[#3b6ef6] hover:bg-[#2d5fe0] text-white text-[12px] font-medium rounded-lg transition-colors"
            >
              Save Changes
            </button>
          ) : (
            <button
              onClick={handleEnable}
              disabled={enabling || (!config.scan_outbound && !config.scan_inbound)}
              className="flex items-center gap-2 px-4 py-2 bg-[#3b6ef6] hover:bg-[#2d5fe0] disabled:opacity-50 text-white text-[12px] font-medium rounded-lg transition-colors"
            >
              {enabling ? <RefreshCw size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
              {enabling ? 'Enabling...' : 'Enable DLP Protection'}
            </button>
          )}
        </div>
      </div>

      {/* Test the pipeline */}
      <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-1 flex items-center gap-2">
          <Zap size={15} className="text-[#3b6ef6]" />
          Test Classification
        </h3>
        <p className="text-[12px] text-[#71717a] mb-4">
          Send a synthetic test email through the DLP pipeline to verify everything is working.
        </p>
        <button
          onClick={runTest}
          disabled={testing}
          className="flex items-center gap-2 px-4 py-2 bg-[#3b6ef6] hover:bg-[#2d5fe0] disabled:opacity-50 text-white text-[13px] font-medium rounded-lg transition-colors"
        >
          {testing ? <RefreshCw size={13} className="animate-spin" /> : <Send size={13} />}
          {testing ? 'Running test...' : 'Run Test Email'}
        </button>
        {testResult && (
          <div className={`mt-4 p-4 rounded-xl border text-[12px] ${
            testResult.action === 'BLOCK' || testResult.action === 'HOLD'
              ? 'bg-red-500/[0.06] border-red-500/20'
              : testResult.action === 'WARN'
              ? 'bg-amber-500/[0.06] border-amber-500/20'
              : 'bg-emerald-500/[0.06] border-emerald-500/20'
          }`}>
            <div className="flex items-center gap-2 mb-2">
              <ActionBadge action={testResult.action} />
              <RiskBadge level={testResult.risk} />
              {testResult.action !== 'ERROR' && (
                <span className="text-[11px] text-emerald-400 font-medium">Pipeline OK ✓</span>
              )}
            </div>
            {testResult.categories.length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2">
                {testResult.categories.map(c => (
                  <span key={c} className="text-[10px] px-1.5 py-0.5 bg-white/[0.05] border border-white/[0.08] rounded text-[#a1a1aa]">
                    {c.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            )}
            <p className="text-[#71717a]">{testResult.explanation}</p>
          </div>
        )}
      </div>

    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

const TABS: { key: Tab; label: string; icon: React.ElementType }[] = [
  { key: 'overview', label: 'Overview',  icon: BarChart3 },
  { key: 'policies', label: 'Policies',  icon: ShieldCheck },
  { key: 'queue',    label: 'Queue',     icon: Inbox },
  { key: 'logs',     label: 'Logs',      icon: ClipboardList },
  { key: 'settings', label: 'Settings',  icon: Settings },
]

export default function DLPPage() {
  const [tab, setTab] = useState<Tab>('overview')
  const [isEnterprise, setIsEnterprise] = useState<boolean | null>(null)

  // Stats
  const [stats, setStats] = useState<DLPStats | null>(null)
  const [statsLoading, setStatsLoading] = useState(true)

  // Policies
  const [policies, setPolicies] = useState<DLPPolicy[]>([])
  const [policiesLoading, setPoliciesLoading] = useState(false)
  const [showNewPolicy, setShowNewPolicy] = useState(false)

  // Queue
  const [queue, setQueue] = useState<DLPQueueItem[]>([])
  const [queueLoading, setQueueLoading] = useState(false)
  const [releasing, setReleasing] = useState<string | null>(null)
  const [blocking, setBlocking] = useState<string | null>(null)
  const queueIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Logs
  const [events, setEvents] = useState<DLPEvent[]>([])
  const [eventsLoading, setEventsLoading] = useState(false)
  const [eventsTotal, setEventsTotal] = useState(0)
  const [eventsPage, setEventsPage] = useState(1)
  const [riskFilter, setRiskFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')

  // ── Check enterprise tier ─────────────────────────────────────────────────
  useEffect(() => {
    api.get('/api/dlp/stats')
      .then(() => setIsEnterprise(true))
      .catch(e => {
        if (e.response?.status === 403) setIsEnterprise(false)
        else setIsEnterprise(true) // assume enterprise on other errors
      })
  }, [])

  // ── Load stats ────────────────────────────────────────────────────────────
  const loadStats = useCallback(async () => {
    if (isEnterprise === false) return
    setStatsLoading(true)
    try {
      const r = await api.get('/api/dlp/stats')
      setStats(r.data)
    } catch {
      // ignore
    } finally {
      setStatsLoading(false)
    }
  }, [isEnterprise])

  useEffect(() => { if (isEnterprise) loadStats() }, [isEnterprise, loadStats])

  // ── Load policies ─────────────────────────────────────────────────────────
  const loadPolicies = useCallback(async () => {
    setPoliciesLoading(true)
    try {
      const r = await api.get('/api/dlp/policies')
      setPolicies(r.data)
    } catch { /* ignore */ } finally { setPoliciesLoading(false) }
  }, [])

  useEffect(() => { if ((tab === 'policies' || tab === 'overview') && isEnterprise) loadPolicies() }, [tab, isEnterprise, loadPolicies])

  // ── Load queue ────────────────────────────────────────────────────────────
  const loadQueue = useCallback(async () => {
    setQueueLoading(true)
    try {
      const r = await api.get('/api/dlp/queue')
      setQueue(r.data)
    } catch { /* ignore */ } finally { setQueueLoading(false) }
  }, [])

  useEffect(() => {
    if (tab === 'queue' && isEnterprise) {
      loadQueue()
      queueIntervalRef.current = setInterval(loadQueue, 30000)
    }
    return () => { if (queueIntervalRef.current) clearInterval(queueIntervalRef.current) }
  }, [tab, isEnterprise, loadQueue])

  // ── Load events ───────────────────────────────────────────────────────────
  const loadEvents = useCallback(async (p = eventsPage, risk = riskFilter, action = actionFilter) => {
    setEventsLoading(true)
    try {
      const params: Record<string, string | number> = { page: p, page_size: 50 }
      if (risk) params.risk_level = risk
      if (action) params.action = action
      const r = await api.get('/api/dlp/events', { params })
      setEvents(r.data.events || [])
      setEventsTotal(r.data.total || 0)
    } catch { /* ignore */ } finally { setEventsLoading(false) }
  }, [eventsPage, riskFilter, actionFilter])

  useEffect(() => { if ((tab === 'logs' || tab === 'overview') && isEnterprise) loadEvents() }, [tab, isEnterprise, loadEvents])

  // ── Handlers ──────────────────────────────────────────────────────────────

  const handleCreatePolicy = async (form: typeof BLANK_POLICY) => {
    await api.post('/api/dlp/policies', form)
    setShowNewPolicy(false)
    loadPolicies()
    loadStats()
  }

  const handleDeletePolicy = async (id: string) => {
    if (!confirm('Delete this policy?')) return
    await api.delete(`/api/dlp/policies/${id}`)
    loadPolicies()
    loadStats()
  }

  const handleTogglePolicy = async (id: string, enabled: boolean) => {
    await api.patch(`/api/dlp/policies/${id}`, { enabled })
    loadPolicies()
  }

  const handleSyncM365 = async (id: string) => {
    await api.post(`/api/dlp/policies/${id}/sync-m365`)
    loadPolicies()
  }

  const handleSyncGSuite = async (id: string) => {
    await api.post(`/api/dlp/policies/${id}/sync-gsuite`)
    loadPolicies()
  }

  const handleRelease = async (id: string) => {
    setReleasing(id)
    try {
      await api.post(`/api/dlp/queue/${id}/release`)
      loadQueue()
      loadStats()
    } finally { setReleasing(null) }
  }

  const handleBlock = async (id: string) => {
    setBlocking(id)
    try {
      await api.post(`/api/dlp/queue/${id}/block`)
      loadQueue()
      loadStats()
    } finally { setBlocking(null) }
  }

  const handleFilter = (risk: string, action: string) => {
    setRiskFilter(risk)
    setActionFilter(action)
    setEventsPage(1)
    loadEvents(1, risk, action)
  }

  const handlePage = (p: number) => {
    setEventsPage(p)
    loadEvents(p)
  }

  // ── Enterprise gate ───────────────────────────────────────────────────────
  if (isEnterprise === false) return (
    <div className="min-h-screen bg-[#0d0d12] p-6">
      <UpgradePrompt />
    </div>
  )

  return (
    <div className="min-h-screen bg-[#0d0d12]">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-[18px] font-semibold text-[var(--foreground)]">
            Data Loss Prevention
          </h1>
        </div>
        <div className="flex items-center gap-3">
          {tab === 'policies' && (
            <button
              onClick={() => setShowNewPolicy(true)}
              className="flex items-center gap-2 px-4 py-2 bg-[#3b6ef6] hover:bg-[#2d5fe0] text-white text-[13px] font-medium rounded-lg transition-colors"
            >
              <Plus size={14} />
              New Policy
            </button>
          )}
          <button
            onClick={() => { loadStats(); if (tab === 'policies') loadPolicies(); if (tab === 'queue') loadQueue(); if (tab === 'logs' || tab === 'overview') loadEvents(); }}
            className="p-2 text-[#71717a] hover:text-white border border-white/[0.08] rounded-lg hover:bg-white/[0.04] transition-colors"
            title="Refresh"
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 bg-[#13131a] border border-white/[0.06] rounded-xl p-1 mb-5 w-fit">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-[13px] font-medium transition-all ${
              tab === key
                ? 'bg-[#3b6ef6]/15 text-[var(--foreground)]'
                : 'text-[#71717a] hover:text-[var(--foreground)] hover:bg-white/[0.04]'
            }`}
          >
            <Icon size={13} className={tab === key ? 'text-[#3b6ef6]' : 'text-current'} />
            {label}
            {key === 'queue' && queue.length > 0 && (
              <span className="ml-1 text-[10px] font-bold bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded-full px-1.5 py-0.5">
                {queue.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'overview' && (
        <OverviewTab
          stats={stats}
          events={events}
          loading={statsLoading || eventsLoading}
        />
      )}
      {tab === 'policies' && (
        <PoliciesTab
          policies={policies}
          loading={policiesLoading}
          onDelete={handleDeletePolicy}
          onToggle={handleTogglePolicy}
          onSyncM365={handleSyncM365}
          onSyncGSuite={handleSyncGSuite}
        />
      )}
      {tab === 'queue' && (
        <QueueTab
          queue={queue}
          loading={queueLoading}
          onRelease={handleRelease}
          onBlock={handleBlock}
          releasing={releasing}
          blocking={blocking}
        />
      )}
      {tab === 'logs' && (
        <LogsTab
          events={events}
          loading={eventsLoading}
          total={eventsTotal}
          page={eventsPage}
          pageSize={50}
          onPage={handlePage}
          onFilter={handleFilter}
          riskFilter={riskFilter}
          actionFilter={actionFilter}
        />
      )}
      {tab === 'settings' && <SettingsTab onConfigChange={loadStats} />}

      {/* New Policy Modal */}
      {showNewPolicy && (
        <PolicyModal
          onClose={() => setShowNewPolicy(false)}
          onSave={handleCreatePolicy}
        />
      )}
    </div>
  )
}
