'use client'
import { useState, useEffect, useCallback } from 'react'
import {
  Search, Download, RefreshCw, ChevronLeft, ChevronRight, Copy, X,
  CheckCircle, AlertTriangle, Shield, Clock, Filter, Eye, Sparkles,
  Brain, Users, Globe, Lock, Unlock, AlertOctagon, Link2, Paperclip, ShieldCheck,
} from 'lucide-react'
import api from '@/lib/api'
import { clsx } from 'clsx'
import { safeFormat, safeParseDate } from '@/lib/dateUtils'

// ─── Types ───────────────────────────────────────────────────────────────────

interface TraceResult {
  id: string
  message_id: string | null
  sender: string | null
  sender_domain: string | null
  recipient: string | null
  subject: string | null
  subject_hash: string | null
  threat_type: string | null
  risk_score: number | null
  status: string | null
  action_taken: string | null
  detected_at: string | null
  email_received_at: string | null
  auth_results: Record<string, string> | null
  graph_score: number | null
  content_score: number | null
  reputation_score: number | null
  ai_explanation_en: string | null
  threat_indicators: string[] | null
  sama_controls: string[] | null
  nca_controls: string[] | null
}

interface Pagination {
  total: number; page: number; page_size: number; total_pages: number
}
interface Stats {
  total_messages: number; by_action: Record<string, number>; by_threat_type: Record<string, number>
}
interface EmailFlowStep {
  stage: string; timestamp: string; status: 'ok' | 'flagged' | 'blocked'; detail: string
  vt_signals?: string[]; whois_signals?: string[]; dns_signals?: string[]; all_rep_indicators?: string[]
  llm_confidence?: number | null; llm_classification?: string | null; llm_model?: string | null; inconclusive?: boolean
}
interface ReputationIntel {
  score: number; indicators: string[]
  vt_signals: string[]; whois_signals: string[]; dns_signals: string[]
  spf_pass: boolean | null; dkim_pass: boolean | null; dmarc_pass: boolean | null
}
interface DlpSummary {
  event_id: string
  risk_level: string
  action_taken: string
  categories_found: string[]
  matched_patterns: string[]
  confidence: number | null
  score: number
  label: string
  scanned_at: string | null
}
interface EnrichedDetail extends TraceResult {
  email_flow: EmailFlowStep[]; similar_threats_count: number; recipient_threat_history: number
  reputation_intel?: ReputationIntel
  dlp?: DlpSummary | null
  llm_confidence?: number | null
  llm_classification?: string | null
  llm_model?: string | null
}

// ─── Helpers / constants ──────────────────────────────────────────────────────

const THREAT_COLORS: Record<string, string> = {
  BEC: 'bg-red-900/50 text-red-300 border-red-700/50',
  PHISHING: 'bg-orange-900/50 text-orange-300 border-orange-700/50',
  GOV_IMP: 'bg-purple-900/50 text-purple-300 border-purple-700/50',
  VENDOR_IMP: 'bg-pink-900/50 text-pink-300 border-pink-700/50',
  MALWARE: 'bg-red-900/70 text-red-200 border-red-600/50',
  SPAM: 'bg-yellow-900/50 text-yellow-300 border-yellow-700/50',
  CLEAN: 'bg-green-900/50 text-green-300 border-green-700/50',
  BENIGN: 'bg-green-900/50 text-green-300 border-green-700/50',
}
const HELIOS_COLORS: Record<string, string> = {
  CLEAN: 'bg-green-900/50 text-green-300 border-green-700/50',
  FLAGGED_LOW: 'bg-yellow-900/50 text-yellow-300 border-yellow-700/50',
  FLAGGED_HIGH: 'bg-orange-900/50 text-orange-300 border-orange-700/50',
  QUARANTINED: 'bg-red-900/50 text-red-300 border-red-700/50',
  QUARANTINE: 'bg-red-900/50 text-red-300 border-red-700/50',
  BLOCK_DELETE: 'bg-red-900/70 text-red-200 border-red-600/50',
  DELIVER: 'bg-green-900/50 text-green-300 border-green-700/50',
  BANNER: 'bg-blue-900/50 text-blue-300 border-blue-700/50',
  HOLD: 'bg-yellow-900/50 text-yellow-300 border-yellow-700/50',
}
const HELIOS_LABELS: Record<string, string> = {
  CLEAN: 'Clean', DELIVER: 'Clean',
  FLAGGED_LOW: 'Flagged', BANNER: 'Flagged', HOLD: 'Flagged',
  FLAGGED_HIGH: 'High Risk',
  QUARANTINED: 'Quarantined', QUARANTINE: 'Quarantined', BLOCK_DELETE: 'Quarantined', BLOCK: 'Quarantined',
}
function riskColor(s: number | null) {
  if (s === null) return 'text-slate-400'
  return s <= 30 ? 'text-green-400' : s <= 70 ? 'text-amber-400' : 'text-red-400'
}
function ScoreBar({ label, value }: { label: string; value: number | null }) {
  const pct = value ?? 0
  return (
    <div>
      <div className="flex justify-between text-xs mb-1">
        <span className="text-slate-400">{label}</span>
        <span className={riskColor(value)}>{pct}</span>
      </div>
      <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={clsx('h-full rounded-full', pct <= 30 ? 'bg-green-500' : pct <= 70 ? 'bg-amber-500' : 'bg-red-500')} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
function Badge({ label, colorClass }: { label: string; colorClass: string }) {
  return <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border', colorClass)}>{label}</span>
}
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
      className="ml-1 text-slate-500 hover:text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity">
      {copied ? <CheckCircle size={12} className="text-green-400" /> : <Copy size={12} />}
    </button>
  )
}

// ─── Email Flow Timeline ──────────────────────────────────────────────────────

const DOT: Record<string, string> = { ok: '#4ade80', flagged: '#fbbf24', blocked: '#e94560' }
const FLOW_BG: Record<string, string> = {
  ok: 'bg-green-900/20 border-green-700/30',
  flagged: 'bg-amber-900/20 border-amber-700/30',
  blocked: 'bg-red-900/20 border-red-700/30',
}
const FLOW_LBL: Record<string, string> = { ok: 'text-green-400', flagged: 'text-amber-400', blocked: 'text-red-400' }

function RepSignalPill({ label, color }: { label: string; color: string }) {
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border ${color}`}>
      {label}
    </span>
  )
}

function EmailFlowTimeline({ steps }: { steps: EmailFlowStep[] }) {
  return (
    <ol className="space-y-0">
      {steps.map((step, i) => {
        const isRepStep = step.stage === 'Sender Reputation Check'
        const hasVT = isRepStep && step.vt_signals && step.vt_signals.length > 0
        const hasWHOIS = isRepStep && step.whois_signals && step.whois_signals.length > 0
        const hasDNS = isRepStep && step.dns_signals && step.dns_signals.length > 0
        const hasSignals = hasVT || hasWHOIS || hasDNS
        return (
          <li key={i} className="flex gap-3">
            <div className="flex flex-col items-center">
              <div className="w-3 h-3 rounded-full flex-shrink-0 mt-1" style={{ backgroundColor: DOT[step.status] }} />
              {i < steps.length - 1 && <div className="w-0.5 flex-1 min-h-[24px] bg-[#0f3460]/60 mt-1" />}
            </div>
            <div className={clsx('flex-1 mb-4 rounded-lg p-3 border', FLOW_BG[step.status])}>
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className={clsx('text-xs font-semibold', FLOW_LBL[step.status])}>{step.stage}</span>
                {step.timestamp && (
                  <span className="text-xs text-slate-500 flex-shrink-0">{safeFormat(step.timestamp, 'HH:mm:ss')}</span>
                )}
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">{step.detail}</p>
              {hasSignals && (
                <div className="mt-2 space-y-1.5">
                  {hasVT && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-[10px] text-slate-500 font-semibold w-14 flex-shrink-0">VirusTotal</span>
                      {step.vt_signals!.map((s, j) => (
                        <RepSignalPill key={j} label={s.replace(/_/g, ' ')} color={
                          s.includes('malicious') ? 'bg-red-900/40 text-red-300 border-red-700/40' :
                          s.includes('suspicious') ? 'bg-orange-900/40 text-orange-300 border-orange-700/40' :
                          s.includes('trusted') ? 'bg-green-900/40 text-green-300 border-green-700/40' :
                          'bg-slate-800 text-slate-400 border-slate-700'
                        } />
                      ))}
                    </div>
                  )}
                  {hasWHOIS && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-[10px] text-slate-500 font-semibold w-14 flex-shrink-0">WHOIS</span>
                      {step.whois_signals!.map((s, j) => (
                        <RepSignalPill key={j} label={s.replace(/_/g, ' ')} color={
                          s.includes('new') ? 'bg-red-900/40 text-red-300 border-red-700/40' :
                          s.includes('young') ? 'bg-orange-900/40 text-orange-300 border-orange-700/40' :
                          s.includes('established') ? 'bg-green-900/40 text-green-300 border-green-700/40' :
                          'bg-slate-800 text-slate-400 border-slate-700'
                        } />
                      ))}
                    </div>
                  )}
                  {hasDNS && (
                    <div className="flex flex-wrap items-center gap-1">
                      <span className="text-[10px] text-slate-500 font-semibold w-14 flex-shrink-0">DNS</span>
                      {step.dns_signals!.map((s, j) => (
                        <RepSignalPill key={j} label={s.replace(/_/g, ' ')} color={
                          s.startsWith('no_') || s.includes('fail') ? 'bg-orange-900/40 text-orange-300 border-orange-700/40' :
                          s.includes('pass') ? 'bg-green-900/40 text-green-300 border-green-700/40' :
                          'bg-slate-800 text-slate-400 border-slate-700'
                        } />
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </li>
        )
      })}
    </ol>
  )
}

// ─── URL / Attachment helpers ─────────────────────────────────────────────────

/** Defang a URL for safe display */
function defang(url: string): string {
  return url
    .replace(/^https/i, 'hxxps')
    .replace(/^http/i, 'hxxp')
    .replace(/\./g, '[.]')
}

/** Safely flatten threat_indicators regardless of whether it was stored as array or dict */
function flattenIndicators(raw: unknown): string[] {
  if (!raw) return []
  if (Array.isArray(raw)) return raw.filter(x => typeof x === 'string') as string[]
  if (typeof raw === 'object') {
    // dict format: {"content": [...], "graph": [...], "reputation": [...]}
    return Object.values(raw as Record<string, unknown>)
      .flatMap(v => Array.isArray(v) ? v.filter(x => typeof x === 'string') : []) as string[]
  }
  return []
}

/** Convert a raw indicator string to a short pill-friendly label */
function toIndicatorLabel(ind: string): string {
  const keyPart = ind.split(':')[0]
  const clean = keyPart.replace(/_/g, ' ').replace(/\s+/g, ' ').trim()
  const capped = clean.charAt(0).toUpperCase() + clean.slice(1)
  return capped.length > 32 ? capped.slice(0, 30) + '…' : capped
}

/** Safely coerce a value to a string array */
function toStringArray(raw: unknown): string[] {
  if (!raw) return []
  if (Array.isArray(raw)) return raw.map(String)
  return []
}

/** Extract URLs and attachments from a TraceResult */
function extractTraceArtifacts(row: TraceResult) {
  const any = row as any
  // SAFETY: threat_indicators may be a dict {"content":[...],"graph":[...],...} not an array
  const indicators: string[] = flattenIndicators(row.threat_indicators)
  const urls: { url: string; malicious?: boolean; suspicious?: boolean }[] = []
  const attachments: { name: string; dangerous?: boolean }[] = []

  // Pull top-level arrays from detail endpoint (populated from score_breakdown)
  const suspiciousUrls: string[] = toStringArray(any.suspicious_urls)
  const maliciousUrls: string[] = toStringArray(any.malicious_urls)
  const suspAttachments: string[] = toStringArray(any.suspicious_attachments)
  // all_attachments: every filename regardless of danger level
  const allAttachments: string[] = toStringArray(any.all_attachments)

  maliciousUrls.forEach(u => urls.push({ url: u, malicious: true }))
  suspiciousUrls.filter(u => !maliciousUrls.includes(u)).forEach(u => urls.push({ url: u, suspicious: true }))

  // Merge all_attachments + suspicious_attachments, marking dangerous ones
  const seenAtt = new Set<string>()
  suspAttachments.forEach(n => { seenAtt.add(n); attachments.push({ name: n, dangerous: true }) })
  allAttachments.forEach(n => { if (!seenAtt.has(n)) attachments.push({ name: n, dangerous: false }) })

  // Also parse from threat_indicators strings like "dangerous_attachment:file.exe"
  for (const ind of indicators) {
    if (typeof ind !== 'string') continue
    if (ind.startsWith('dangerous_attachment:')) {
      ind.replace('dangerous_attachment:', '').split(',').forEach(n => {
        const name = n.trim()
        if (name && !attachments.find(a => a.name === name)) attachments.push({ name, dangerous: true })
      })
    }
  }

  return { urls, attachments }
}

// ─── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({ row: initialRow, onClose, onRowUpdated }: {
  row: TraceResult; onClose: () => void; onRowUpdated: (updated: TraceResult) => void
}) {
  const [row, setRow] = useState(initialRow)
  const [detail, setDetail] = useState<EnrichedDetail | null>(null)
  const [detailLoading, setDetailLoading] = useState(true)
  const [detailError, setDetailError] = useState<string | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [actionMsg, setActionMsg] = useState<string | null>(null)
  const [completedAction, setCompletedAction] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setDetailLoading(true); setDetail(null); setDetailError(null)
    const fetch = async (attempt = 0) => {
      try {
        const res = await api.get(`/api/message-trace/${row.id}/detail`, { timeout: 15000 })
        if (!cancelled) { setDetail(res.data); setDetailError(null) }
      } catch (err: any) {
        if (!cancelled && attempt === 0 && (err?.code === 'ECONNABORTED' || !err?.response)) {
          await new Promise(r => setTimeout(r, 1200))
          return fetch(1)
        }
        if (!cancelled) {
          setDetailError(err?.code === 'ECONNABORTED'
            ? 'Analysis timed out — backend may be busy. Click retry.'
            : 'Could not load enriched detail.')
        }
      } finally {
        if (!cancelled) setDetailLoading(false)
      }
    }
    fetch()
    return () => { cancelled = true }
  }, [row.id])

  const d = detail ?? row
  const isQuarantined = ['QUARANTINED', 'QUARANTINE', 'BLOCK_DELETE', 'BLOCK'].includes(row.action_taken ?? '')

  const doAction = async (action: string, label: string) => {
    if (completedAction) return  // already acted — prevent double-fire
    setActionLoading(action)
    setActionMsg(null)
    try {
      const res = await api.post(`/api/message-trace/${row.id}/action`, { action })
      const updated = { ...row }
      if (action === 'quarantine') { updated.action_taken = 'QUARANTINED'; updated.status = 'quarantined' }
      if (action === 'release')    { updated.action_taken = 'CLEAN';       updated.status = 'resolved' }
      if (action === 'false_positive') { updated.action_taken = 'CLEAN'; updated.status = 'false_positive'; updated.threat_type = 'CLEAN' }
      setRow(updated)
      onRowUpdated(updated)
      setCompletedAction(action)
      setActionMsg(`✓ ${label} applied`)
      // Refresh detail
      const r2 = await api.get(`/api/message-trace/${row.id}/detail`, { timeout: 15000 })
      setDetail(r2.data)
    } catch (e: any) {
      setActionMsg(`Failed: ${e?.response?.data?.detail ?? e.message}`)
    } finally {
      setActionLoading(null)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-xl bg-[#0d1b2a] border-l border-[#0f3460]/60 h-full overflow-y-auto shadow-2xl"
        onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#0f3460]/50 sticky top-0 bg-[#0d1b2a] z-10">
          <div>
            <h2 className="text-base font-semibold text-white">Message Details</h2>
            <p className="text-xs text-slate-500 mt-0.5 font-mono break-all leading-relaxed">{d.message_id ?? d.id}</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors"><X size={18} /></button>
        </div>

        <div className="px-6 py-5 space-y-6">

          {/* Metadata */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Message Metadata</h3>
            <div className="space-y-2 text-sm">
              {d.subject && (
                <div className="flex gap-3">
                  <span className="text-slate-500 w-24 flex-shrink-0">Subject</span>
                  <span className="text-slate-200 break-all">{d.subject}</span>
                </div>
              )}
              {([['Sender', d.sender], ['Recipient', d.recipient], ['Domain', d.sender_domain]] as [string, string | null][]).map(([k, v]) => (
                <div key={k} className="flex gap-3">
                  <span className="text-slate-500 w-24 flex-shrink-0">{k}</span>
                  <span className="text-slate-200 break-all font-mono text-xs">{v || '—'}</span>
                </div>
              ))}
              <div className="flex gap-3">
                <span className="text-slate-500 w-24 flex-shrink-0">Delivered</span>
                <span className="text-slate-200 text-xs">
                  {d.email_received_at ? safeFormat(d.email_received_at, 'PPpp')
                    : d.detected_at ? safeFormat(d.detected_at, 'PPpp') + ' (est.)' : '—'}
                </span>
              </div>
              <div className="flex gap-3">
                <span className="text-slate-500 w-24 flex-shrink-0">Analysed</span>
                <span className="text-slate-400 text-xs">{safeFormat(d.detected_at, 'PPpp')}</span>
              </div>
              <div className="flex gap-3">
                <span className="text-slate-500 w-24 flex-shrink-0">Classification</span>
                {d.threat_type && d.threat_type !== 'CLEAN'
                  ? <Badge label={d.threat_type} colorClass={THREAT_COLORS[d.threat_type] ?? 'bg-slate-700 text-slate-300 border-slate-600'} />
                  : <span className="text-green-400 text-xs font-medium">Clean</span>}
              </div>
              <div className="flex gap-3">
                <span className="text-slate-500 w-24 flex-shrink-0">Helios Status</span>
                {d.action_taken
                  ? <Badge label={HELIOS_LABELS[d.action_taken] ?? d.action_taken} colorClass={HELIOS_COLORS[d.action_taken] ?? 'bg-slate-700 text-slate-300 border-slate-600'} />
                  : <span className="text-slate-400">—</span>}
              </div>
            </div>
          </section>

          {/* Auth */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Email Authentication</h3>
            {!d.auth_results ? (
              <p className="text-xs text-slate-500 italic">Authentication headers not available — re-sync to extract.</p>
            ) : (
              <>
                <div className="grid grid-cols-3 gap-2 mb-2">
                  {(['spf', 'dkim', 'dmarc'] as const).map(proto => {
                    const val = (d.auth_results as any)?.[proto] ?? 'N/A'
                    const isPass = val === 'pass'; const isFail = val === 'fail' || val === 'softfail'
                    return (
                      <div key={proto} className={clsx('rounded-lg p-3 border flex flex-col gap-1 items-center',
                        isPass ? 'bg-green-900/20 border-green-700/40' :
                        isFail ? 'bg-red-900/20 border-red-700/40' : 'bg-slate-800/40 border-slate-700/40')}>
                        <span className="text-xs text-slate-400 font-semibold uppercase tracking-widest">{proto}</span>
                        <span className={clsx('text-sm font-bold uppercase',
                          isPass ? 'text-green-400' : isFail ? 'text-red-400' : 'text-slate-600')}>{val}</span>
                      </div>
                    )
                  })}
                </div>
                {(d.auth_results as any)?.sender_ip && (
                  <div className="flex items-center gap-2 px-1 flex-wrap">
                    <Globe size={12} className="text-slate-500 shrink-0" />
                    <span className="text-xs text-slate-500">Sender IP:</span>
                    <span className="text-xs font-mono text-slate-300">{(d.auth_results as any).sender_ip}</span>
                    {(d.auth_results as any)?.sender_country && (
                      <span className="flex items-center gap-1 text-xs text-slate-400 bg-slate-800/60 border border-slate-700/40 rounded px-1.5 py-0.5">
                        {(d.auth_results as any).sender_country_code && (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img
                            src={`https://flagcdn.com/16x12/${((d.auth_results as any).sender_country_code as string).toLowerCase()}.png`}
                            alt={(d.auth_results as any).sender_country_code}
                            width={16} height={12}
                            className="rounded-sm"
                          />
                        )}
                        {(d.auth_results as any).sender_country}
                      </span>
                    )}
                  </div>
                )}
              </>
            )}
          </section>

          {/* Email Flow */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Email Flow</h3>
            {detailLoading ? (
              <div className="flex items-center gap-2 text-slate-500 text-sm py-4">
                <RefreshCw size={14} className="animate-spin" /> Loading flow…
              </div>
            ) : detailError ? (
              <div className="rounded-lg bg-slate-800/60 border border-slate-700/40 p-4">
                <p className="text-xs text-slate-400 mb-3">{detailError}</p>
                <button onClick={() => {
                  setDetailLoading(true); setDetailError(null)
                  api.get(`/api/message-trace/${row.id}/detail`, { timeout: 15000 })
                    .then(r => setDetail(r.data))
                    .catch(() => setDetailError('Still timing out. Try again shortly.'))
                    .finally(() => setDetailLoading(false))
                }} className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-[#0f3460]/60 hover:bg-[#0f3460] text-slate-300 transition-colors">
                  <RefreshCw size={11} /> Retry
                </button>
              </div>
            ) : detail?.email_flow?.length ? (
              <EmailFlowTimeline steps={detail.email_flow} />
            ) : (
              <p className="text-slate-500 text-sm">Flow data unavailable</p>
            )}
          </section>

          {/* AI Assessment */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">AI Threat Assessment</h3>
            <div className={clsx(
              'rounded-lg p-4 border',
              detail?.email_flow?.find(s => s.stage === 'AI Classification')?.inconclusive
                ? 'border-amber-700/40 bg-amber-900/10'
                : 'border-[#3b6ef6]/30 bg-[#3b6ef6]/5'
            )}>
              <div className="flex items-center gap-2 mb-2">
                <Sparkles size={14} className={detail?.email_flow?.find(s => s.stage === 'AI Classification')?.inconclusive ? 'text-amber-400' : 'text-[#3b6ef6]'} />
                <span className={clsx('text-xs font-semibold', detail?.email_flow?.find(s => s.stage === 'AI Classification')?.inconclusive ? 'text-amber-400' : 'text-[#3b6ef6]')}>
                  Helios AI Analysis
                  {detail?.email_flow?.find(s => s.stage === 'AI Classification')?.inconclusive && (
                    <span className="ml-2 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-900/40 text-amber-300 border border-amber-700/40">INCONCLUSIVE</span>
                  )}
                </span>
                {(() => {
                  const aiStep = detail?.email_flow?.find(s => s.stage === 'AI Classification')
                  const conf = aiStep?.llm_confidence
                  if (conf == null) return null
                  return (
                    <span className="ml-auto text-[10px] text-slate-500">
                      {Math.round(conf * 100)}% confidence
                    </span>
                  )
                })()}
              </div>
              {d.ai_explanation_en
                ? <p className="text-sm text-slate-300 leading-relaxed">{d.ai_explanation_en}</p>
                : (() => {
                    const aiStep = detail?.email_flow?.find(s => s.stage === 'AI Classification')
                    if (aiStep?.inconclusive) {
                      return <p className="text-sm text-amber-200/80 leading-relaxed">{aiStep.detail}</p>
                    }
                    return <p className="text-sm text-slate-500 italic">Analysis pending…</p>
                  })()}
              {(() => {
                const aiStep = detail?.email_flow?.find(s => s.stage === 'AI Classification')
                if (!aiStep?.llm_classification) return null
                return (
                  <div className="mt-2 flex gap-2 flex-wrap">
                    <span className="text-[10px] text-slate-500">Raw classification:</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {aiStep.llm_classification}
                    </span>
                    {/* Model name hidden from customers — internal implementation detail */}
                  </div>
                )
              })()}
            </div>
          </section>

          {/* Scores */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Detection Scores</h3>
            <div className="space-y-3 bg-[#16213e] rounded-lg p-4 border border-[#0f3460]/40">
              <ScoreBar label="Graph Score" value={d.graph_score} />
              <ScoreBar label="Content Score" value={d.content_score} />
              <ScoreBar label="Reputation Score" value={d.reputation_score} />
              <div className="pt-1 border-t border-[#0f3460]/40 flex justify-between text-xs">
                <span className="text-slate-400 font-medium">Overall Risk</span>
                <span className={clsx('font-bold text-sm', riskColor(d.risk_score))}>{d.risk_score ?? '—'}</span>
              </div>
            </div>
          </section>

          {/* DLP Classification */}
          {(() => {
            const dlp = detail?.dlp
            if (!dlp) return null
            const dlpColors: Record<string, string> = {
              low: 'text-green-400 border-green-700/40 bg-green-900/10',
              medium: 'text-amber-400 border-amber-700/40 bg-amber-900/10',
              high: 'text-orange-400 border-orange-700/40 bg-orange-900/10',
              critical: 'text-red-400 border-red-700/40 bg-red-900/10',
            }
            const dlpActionColors: Record<string, string> = {
              ALLOW: 'text-green-400 bg-green-900/30 border-green-700/40',
              WARN: 'text-amber-400 bg-amber-900/30 border-amber-700/40',
              HOLD: 'text-orange-400 bg-orange-900/30 border-orange-700/40',
              BLOCK: 'text-red-400 bg-red-900/30 border-red-700/40',
            }
            const colorClass = dlpColors[dlp.risk_level] ?? 'text-slate-400 border-slate-700 bg-slate-800/20'
            const actionColor = dlpActionColors[dlp.action_taken] ?? 'text-slate-400 bg-slate-800 border-slate-700'
            return (
              <section>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">DLP Classification</h3>
                <div className={clsx('rounded-lg p-4 border', colorClass)}>
                  <div className="flex items-center gap-2 mb-3">
                    <Lock size={13} className="opacity-70" />
                    <span className="text-xs font-semibold">Data Loss Prevention</span>
                    <span className={clsx('ml-auto text-[10px] font-bold px-1.5 py-0.5 rounded border', actionColor)}>
                      {dlp.action_taken}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs mb-3">
                    <div>
                      <span className="text-slate-500 block">Risk Level</span>
                      <span className="font-semibold capitalize">{dlp.risk_level}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">DLP Score</span>
                      <span className="font-semibold">{dlp.score}/100</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Content Label</span>
                      <span className="font-semibold">{dlp.label}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Confidence</span>
                      <span className="font-semibold">{dlp.confidence != null ? `${Math.round(dlp.confidence * 100)}%` : '—'}</span>
                    </div>
                  </div>
                  {dlp.categories_found.length > 0 && (
                    <div className="mb-2">
                      <span className="text-[10px] text-slate-500 block mb-1">Categories Detected</span>
                      <div className="flex flex-wrap gap-1">
                        {dlp.categories_found.map((cat, i) => (
                          <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700">{cat}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {dlp.matched_patterns.length > 0 && (
                    <div>
                      <span className="text-[10px] text-slate-500 block mb-1">Matched Patterns</span>
                      <div className="flex flex-wrap gap-1">
                        {dlp.matched_patterns.map((pat, i) => (
                          <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/20 text-red-300 border border-red-700/30">{pat}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </section>
            )
          })()}

          {/* Reputation Intelligence — VT / WHOIS / DNS */}
          {(() => {
            const ri = (d as any).reputation_intel as ReputationIntel | undefined
            if (!ri) return null
            const hasVT = ri.vt_signals?.length > 0
            const hasWHOIS = ri.whois_signals?.length > 0
            const hasDNS = ri.dns_signals?.length > 0
            const hasAuth = ri.spf_pass !== null || ri.dkim_pass !== null || ri.dmarc_pass !== null
            if (!hasVT && !hasWHOIS && !hasDNS && !hasAuth) return null
            return (
              <section>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Reputation Intelligence</h3>
                <div className="space-y-2 bg-[#16213e] rounded-lg p-3 border border-[#0f3460]/40">
                  {hasAuth && (
                    <div className="flex flex-wrap gap-2 pb-2 border-b border-[#0f3460]/30">
                      {(['spf', 'dkim', 'dmarc'] as const).map(k => {
                        const pass = ri[`${k}_pass` as keyof ReputationIntel] as boolean | null
                        if (pass === null) return null
                        return (
                          <span key={k} className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${
                            pass ? 'bg-green-900/30 text-green-300 border-green-700/40' : 'bg-red-900/30 text-red-300 border-red-700/40'
                          }`}>{k.toUpperCase()} {pass ? 'PASS' : 'FAIL'}</span>
                        )
                      })}
                    </div>
                  )}
                  {hasVT && (
                    <div className="flex flex-wrap items-start gap-1">
                      <span className="text-[10px] text-slate-500 font-semibold w-16 flex-shrink-0 pt-0.5">VirusTotal</span>
                      <div className="flex flex-wrap gap-1">
                        {ri.vt_signals.map((s, i) => (
                          <RepSignalPill key={i} label={s.replace(/_/g, ' ')} color={
                            s.includes('malicious') ? 'bg-red-900/40 text-red-300 border-red-700/40' :
                            s.includes('suspicious') ? 'bg-orange-900/40 text-orange-300 border-orange-700/40' :
                            s.includes('trusted') ? 'bg-green-900/40 text-green-300 border-green-700/40' :
                            'bg-slate-800 text-slate-400 border-slate-700'
                          } />
                        ))}
                      </div>
                    </div>
                  )}
                  {hasWHOIS && (
                    <div className="flex flex-wrap items-start gap-1">
                      <span className="text-[10px] text-slate-500 font-semibold w-16 flex-shrink-0 pt-0.5">WHOIS</span>
                      <div className="flex flex-wrap gap-1">
                        {ri.whois_signals.map((s, i) => (
                          <RepSignalPill key={i} label={s.replace(/_/g, ' ')} color={
                            s.includes('new') ? 'bg-red-900/40 text-red-300 border-red-700/40' :
                            s.includes('young') ? 'bg-orange-900/40 text-orange-300 border-orange-700/40' :
                            s.includes('established') ? 'bg-green-900/40 text-green-300 border-green-700/40' :
                            'bg-slate-800 text-slate-400 border-slate-700'
                          } />
                        ))}
                      </div>
                    </div>
                  )}
                  {hasDNS && (
                    <div className="flex flex-wrap items-start gap-1">
                      <span className="text-[10px] text-slate-500 font-semibold w-16 flex-shrink-0 pt-0.5">DNS</span>
                      <div className="flex flex-wrap gap-1">
                        {ri.dns_signals.map((s, i) => (
                          <RepSignalPill key={i} label={s.replace(/_/g, ' ')} color={
                            s.startsWith('no_') || s.includes('fail') ? 'bg-orange-900/40 text-orange-300 border-orange-700/40' :
                            s.includes('pass') ? 'bg-green-900/40 text-green-300 border-green-700/40' :
                            'bg-slate-800 text-slate-400 border-slate-700'
                          } />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </section>
            )
          })()}

          {/* Indicators */}
          {(() => {
            const indicators = flattenIndicators(d.threat_indicators)
            return indicators.length > 0 ? (
            <section>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Threat Indicators</h3>
              <div className="flex flex-wrap gap-2">
                {indicators.map((ind, i) => (
                  <span key={i} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-900/30 text-amber-300 border border-amber-700/40" title={ind}>
                    <AlertTriangle size={10} className="shrink-0" /> {toIndicatorLabel(ind)}
                  </span>
                ))}
              </div>
            </section>
            ) : null
          })()}

          {/* Links & Attachments */}
          {(() => {
            const { urls, attachments } = extractTraceArtifacts(d)
            if (urls.length === 0 && attachments.length === 0) return null
            const sectionTitle = attachments.length > 0 && urls.length === 0
              ? 'Attachments'
              : urls.length > 0 && attachments.length === 0
              ? 'Links'
              : 'Links & Attachments'
            return (
              <section>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">{sectionTitle}</h3>
                <div className="space-y-4">
                  {urls.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1.5 text-xs text-slate-500 font-semibold mb-2">
                        <Link2 size={11} /> URLs ({urls.length})
                      </div>
                      <div className="space-y-1.5">
                        {urls.map((u, i) => (
                          <div key={i} className="flex items-start gap-2">
                            {u.malicious
                              ? <AlertTriangle size={11} className="text-red-400 mt-0.5 flex-shrink-0" />
                              : <ShieldCheck size={11} className="text-amber-400 mt-0.5 flex-shrink-0" />
                            }
                            <code className={clsx('text-xs font-mono break-all leading-relaxed', u.malicious ? 'text-red-300' : 'text-amber-300')}>
                              {defang(u.url)}
                            </code>
                            {u.malicious && (
                              <span className="flex-shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40">VT: malicious</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {attachments.length > 0 && (
                    <div>
                      <div className="flex items-center gap-1.5 text-xs text-slate-500 font-semibold mb-2">
                        <Paperclip size={11} /> Attachments ({attachments.length})
                      </div>
                      <div className="space-y-1">
                        {attachments.map((a, i) => (
                          <div key={i} className="flex items-center gap-2">
                            {a.dangerous
                              ? <AlertTriangle size={11} className="text-red-400 flex-shrink-0" />
                              : <Paperclip size={11} className="text-slate-400 flex-shrink-0" />}
                            <code className={clsx('text-xs font-mono', a.dangerous ? 'text-red-300' : 'text-slate-300')}>{a.name}</code>
                            {a.dangerous && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40">dangerous</span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </section>
            )
          })()}

          {/* Compliance */}
          {((d.sama_controls?.length ?? 0) > 0 || (d.nca_controls?.length ?? 0) > 0) && (
            <section>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Compliance Controls Triggered</h3>
              <div className="grid grid-cols-2 gap-4">
                {d.sama_controls && d.sama_controls.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-500 mb-1.5">SAMA</p>
                    <div className="flex flex-wrap gap-1">
                      {d.sama_controls.map((c, i) => <span key={i} className="px-2 py-0.5 rounded text-xs bg-blue-900/40 text-blue-300 border border-blue-700/40">{c}</span>)}
                    </div>
                  </div>
                )}
                {d.nca_controls && d.nca_controls.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-500 mb-1.5">NCA</p>
                    <div className="flex flex-wrap gap-1">
                      {d.nca_controls.map((c, i) => <span key={i} className="px-2 py-0.5 rounded text-xs bg-purple-900/40 text-purple-300 border border-purple-700/40">{c}</span>)}
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          {/* Sender Intelligence */}
          {!detailLoading && detail && (
            <section>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Sender Intelligence</h3>
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-[#16213e] rounded-lg p-3 border border-[#0f3460]/40 flex flex-col gap-1">
                  <div className="flex items-center gap-1.5 text-xs text-slate-500"><Globe size={12} /> Domain activity</div>
                  <span className={clsx('text-2xl font-bold', detail.similar_threats_count > 5 ? 'text-red-400' : detail.similar_threats_count > 0 ? 'text-amber-400' : 'text-green-400')}>
                    {detail.similar_threats_count}
                  </span>
                  <span className="text-xs text-slate-500">
                    {detail.similar_threats_count === 0
                      ? 'No prior threats from this domain in 30 days'
                      : `other emails from ${d.sender_domain ?? 'this domain'} in last 30 days`}
                  </span>
                </div>
                <div className="bg-[#16213e] rounded-lg p-3 border border-[#0f3460]/40 flex flex-col gap-1">
                  <div className="flex items-center gap-1.5 text-xs text-slate-500"><Users size={12} /> Recipient exposure</div>
                  <span className={clsx('text-2xl font-bold', detail.recipient_threat_history > 10 ? 'text-red-400' : detail.recipient_threat_history > 3 ? 'text-amber-400' : 'text-green-400')}>
                    {detail.recipient_threat_history}
                  </span>
                  <span className="text-xs text-slate-500">
                    {detail.recipient_threat_history === 0
                      ? 'No prior threats to this recipient in 90 days'
                      : `emails scanned to ${d.recipient ?? 'this recipient'} in last 90 days`}
                  </span>
                </div>
              </div>
            </section>
          )}

          {/* Actions */}
          <section className="pt-2">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Analyst Actions</h3>
            <p className="text-xs text-slate-500 mb-3">
              Actions are applied immediately and feed back into Helios AI to improve future detections.
            </p>

            {actionMsg && (
              <div className={clsx('text-xs px-3 py-2 rounded mb-3', actionMsg.startsWith('✓')
                ? 'bg-green-900/30 text-green-300 border border-green-700/30'
                : 'bg-red-900/30 text-red-300 border border-red-700/30')}>
                {actionMsg}
              </div>
            )}

            <div className="grid grid-cols-1 gap-2">
              {/* Quarantine OR Release — shown based on current state */}
              {isQuarantined ? (
                <button
                  disabled={!!actionLoading || (completedAction !== null && completedAction !== 'release')}
                  onClick={() => doAction('release', 'Released from Quarantine')}
                  className={clsx('w-full px-4 py-2.5 rounded-lg text-sm font-medium bg-green-900/20 hover:bg-green-900/40 text-green-300 border border-green-700/40 transition-colors text-left flex items-center gap-2',
                    completedAction !== null && completedAction !== 'release' ? 'opacity-30 cursor-not-allowed' : '',
                    completedAction === 'release' ? 'ring-1 ring-green-400/40' : '')}>
                  {actionLoading === 'release' ? <RefreshCw size={14} className="animate-spin" /> : <Unlock size={14} className="text-green-400" />}
                  Release from Quarantine
                  <span className="ml-auto text-xs text-green-600">Restore to inbox</span>
                </button>
              ) : (
                <button
                  disabled={!!actionLoading || (completedAction !== null && completedAction !== 'quarantine')}
                  onClick={() => doAction('quarantine', 'Quarantined')}
                  className={clsx('w-full px-4 py-2.5 rounded-lg text-sm font-medium bg-orange-900/20 hover:bg-orange-900/40 text-orange-300 border border-orange-700/40 transition-colors text-left flex items-center gap-2',
                    completedAction !== null && completedAction !== 'quarantine' ? 'opacity-30 cursor-not-allowed' : '',
                    completedAction === 'quarantine' ? 'ring-1 ring-orange-400/40' : '')}>
                  {actionLoading === 'quarantine' ? <RefreshCw size={14} className="animate-spin" /> : <Lock size={14} className="text-orange-400" />}
                  Quarantine Email
                  <span className="ml-auto text-xs text-orange-600">Removes from inbox</span>
                </button>
              )}

              <button
                disabled={!!actionLoading || (completedAction !== null && completedAction !== 'block_sender')}
                onClick={() => doAction('block_sender', 'Sender Blocked')}
                className={clsx('w-full px-4 py-2.5 rounded-lg text-sm font-medium bg-red-900/20 hover:bg-red-900/40 text-red-300 border border-red-700/40 transition-colors text-left flex items-center gap-2',
                  completedAction !== null && completedAction !== 'block_sender' ? 'opacity-30 cursor-not-allowed' : '',
                  completedAction === 'block_sender' ? 'ring-1 ring-red-400/40' : '')}>
                {actionLoading === 'block_sender' ? <RefreshCw size={14} className="animate-spin" /> : <AlertOctagon size={14} className="text-red-400" />}
                Block Sender
                <span className="ml-auto text-xs text-red-600">Creates policy rule</span>
              </button>

              {row.status !== 'false_positive' && (
                <button
                  disabled={!!actionLoading || (completedAction !== null && completedAction !== 'false_positive')}
                  onClick={() => doAction('false_positive', 'Marked as False Positive')}
                  className={clsx('w-full px-4 py-2.5 rounded-lg text-sm font-medium bg-[#3b6ef6]/10 hover:bg-[#3b6ef6]/20 text-blue-300 border border-[#3b6ef6]/30 transition-colors text-left flex items-center gap-2',
                    completedAction !== null && completedAction !== 'false_positive' ? 'opacity-30 cursor-not-allowed' : '',
                    completedAction === 'false_positive' ? 'ring-1 ring-blue-400/40' : '')}>
                  {actionLoading === 'false_positive' ? <RefreshCw size={14} className="animate-spin" /> : <Brain size={14} className="text-[#3b6ef6]" />}
                  Mark as False Positive
                  <span className="ml-auto text-xs text-blue-600">Trains AI model</span>
                </button>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function MessageTracePage() {
  const [keyword, setKeyword] = useState('')
  const [subject, setSubject] = useState('')
  const [sender, setSender] = useState('')
  const [recipient, setRecipient] = useState('')
  const [senderDomain, setSenderDomain] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [threatType, setThreatType] = useState('')
  const [actionTaken, setActionTaken] = useState('')
  const [status, setStatus] = useState('')
  const [minScore, setMinScore] = useState('')
  const [maxScore, setMaxScore] = useState('')
  const [authFail, setAuthFail] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)

  const [results, setResults] = useState<TraceResult[]>([])
  const [pagination, setPagination] = useState<Pagination>({ total: 0, page: 1, page_size: 50, total_pages: 0 })
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(false)
  const [selectedRow, setSelectedRow] = useState<TraceResult | null>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

  const buildParams = useCallback((p = page, ps = pageSize) => {
    const params: Record<string, string> = { page: String(p), page_size: String(ps) }
    if (keyword)     params.keyword = keyword
    if (subject)     params.subject_keyword = subject
    if (sender)      params.sender = sender
    if (recipient)   params.recipient = recipient
    if (senderDomain) params.sender_domain = senderDomain
    if (dateFrom)    params.date_from = dateFrom
    if (dateTo)      params.date_to = dateTo
    if (threatType)  params.threat_type = threatType
    if (actionTaken) params.action_taken = actionTaken
    if (status)      params.status = status
    if (minScore)    params.min_score = minScore
    if (maxScore)    params.max_score = maxScore
    if (authFail)    params.auth_fail = authFail
    return new URLSearchParams(params).toString()
  }, [keyword, subject, sender, recipient, senderDomain, dateFrom, dateTo, threatType, actionTaken, status, minScore, maxScore, authFail, page, pageSize])

  const fetchResults = useCallback(async (p = page, ps = pageSize) => {
    setLoading(true)
    try {
      const res = await api.get(`/api/message-trace?${buildParams(p, ps)}`)
      setResults(res.data.results ?? [])
      setPagination(res.data.pagination ?? { total: 0, page: p, page_size: ps, total_pages: 0 })
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [buildParams, page, pageSize])

  const fetchStats = useCallback(async () => {
    try { const r = await api.get('/api/message-trace/stats'); setStats(r.data) } catch {}
  }, [])

  useEffect(() => { fetchStats() }, [fetchStats])
  useEffect(() => { fetchResults(page, pageSize) }, [page, pageSize])
  useEffect(() => {
    const t = setTimeout(() => fetchResults(1, pageSize), 400)
    return () => clearTimeout(t)
  }, [keyword, subject, sender, recipient, senderDomain, dateFrom, dateTo, threatType, actionTaken, status, minScore, maxScore, authFail])
  useEffect(() => {
    const t = setInterval(() => { fetchResults(page, pageSize); fetchStats() }, 30000)
    return () => clearInterval(t)
  }, [fetchResults, fetchStats, page, pageSize])

  const handleSearch = () => { setPage(1); fetchResults(1, pageSize) }
  const handleClear = () => {
    setKeyword(''); setSender(''); setRecipient(''); setSenderDomain('')
    setDateFrom(''); setDateTo(''); setSubject('')
    setThreatType(''); setActionTaken(''); setStatus(''); setMinScore(''); setMaxScore(''); setAuthFail('')
    setPage(1)
  }
  const applyQuickFilter = (filter: string) => {
    setKeyword(''); setSender(''); setRecipient(''); setSenderDomain('')
    setDateFrom(''); setDateTo(''); setSubject('')
    setThreatType(''); setActionTaken(''); setStatus(''); setMinScore(''); setMaxScore(''); setAuthFail('')
    setPage(1)
    const now = new Date()
    if (filter === 'quarantined') setActionTaken('QUARANTINED')
    else if (filter === 'flagged') setActionTaken('FLAGGED_HIGH')
    else if (filter === 'bec') setThreatType('BEC')
    else if (filter === 'phishing') setThreatType('PHISHING')
    else if (filter === '24h') setDateFrom(new Date(now.getTime() - 86400000).toISOString())
    else if (filter === '7d') setDateFrom(new Date(now.getTime() - 7 * 86400000).toISOString())
    else if (filter === '30d') setDateFrom(new Date(now.getTime() - 30 * 86400000).toISOString())
  }

  const exportCSV = async () => {
    try {
      const qs = buildParams()
      const res = await api.get(`/api/message-trace/export?format=csv&${qs}`, { responseType: 'blob' })
      const url = URL.createObjectURL(new Blob([res.data], { type: 'text/csv' }))
      const a = document.createElement('a')
      a.href = url; a.download = 'helios-message-trace.csv'; a.click()
      URL.revokeObjectURL(url)
    } catch (e) { console.error('Export failed', e) }
  }

  const statItems = stats ? [
    { label: 'Total Scanned', value: stats.total_messages, color: 'text-blue-400' },
    { label: 'Quarantined',   value: (stats.by_action?.QUARANTINED ?? 0) + (stats.by_action?.QUARANTINE ?? 0) + (stats.by_action?.BLOCK_DELETE ?? 0), color: 'text-red-400' },
    { label: 'Flagged',       value: (stats.by_action?.FLAGGED_HIGH ?? 0) + (stats.by_action?.FLAGGED_LOW ?? 0) + (stats.by_action?.HOLD ?? 0), color: 'text-orange-400' },
    { label: 'Clean',         value: (stats.by_action?.CLEAN ?? 0) + (stats.by_action?.DELIVER ?? 0), color: 'text-green-400' },
  ] : []

  const inputCls = 'w-full px-3 py-2 rounded-lg bg-[#0d1b2a] border border-[#0f3460]/60 text-slate-200 text-sm placeholder-slate-600 focus:outline-none focus:border-[#e94560]/50 transition-colors'

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Message Trace</h1>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-xs text-[#4ade80] bg-[#4ade80]/10 border border-[#4ade80]/20 px-2.5 py-1 rounded-full">
            <span className="w-1.5 h-1.5 rounded-full bg-[#4ade80] animate-pulse inline-block" /> Live
          </span>
          <button onClick={() => { fetchResults(page, pageSize); fetchStats() }}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm bg-[#16213e] hover:bg-[#0f3460] text-slate-300 border border-[#0f3460]/60 transition-colors">
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {statItems.map(({ label, value, color }) => (
            <div key={label} className="bg-[#16213e] rounded-xl p-4 border border-[#0f3460]/40">
              <p className="text-xs text-slate-500 mb-1">{label}</p>
              <p className={clsx('text-2xl font-bold', color)}>{value.toLocaleString()}</p>
            </div>
          ))}
        </div>
      )}

      {/* Search Panel */}
      <div className="bg-[#16213e] rounded-xl border border-[#0f3460]/40 p-5">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-3">
          <input className={clsx(inputCls, 'col-span-full')}
            placeholder="Search by sender, recipient, subject, or domain"
            value={keyword} onChange={e => setKeyword(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSearch()} />
          <input className={inputCls} placeholder="Subject contains" value={subject}
            onChange={e => setSubject(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSearch()} />
          <input className={inputCls} placeholder="Sender email or domain" value={sender}
            onChange={e => setSender(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSearch()} />
          <input className={inputCls} placeholder="Recipient email" value={recipient}
            onChange={e => setRecipient(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSearch()} />
        </div>

        <div className="flex items-center gap-2 mb-3">
          <button onClick={() => setShowAdvanced(v => !v)}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors">
            <Filter size={13} /> {showAdvanced ? 'Hide' : 'Show'} Advanced Filters
          </button>
        </div>

        {showAdvanced && (
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-3 mb-3 pt-3 border-t border-[#0f3460]/40">
            <div>
              <label className="text-xs text-slate-500 mb-1 block">Date From</label>
              <input type="datetime-local" className={inputCls} value={dateFrom} onChange={e => setDateFrom(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1 block">Date To</label>
              <input type="datetime-local" className={inputCls} value={dateTo} onChange={e => setDateTo(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1 block">Classification</label>
              <select className={clsx(inputCls, 'cursor-pointer')} value={threatType} onChange={e => setThreatType(e.target.value)}>
                <option value="">All</option>
                {[
                  'BEC','VEC','PHISHING','CREDENTIAL_HARVESTING','MALWARE',
                  'ACCOUNT_TAKEOVER','IMPERSONATION','GOV_IMPERSONATION',
                  'LOOKALIKE_DOMAIN','SUPPLY_CHAIN','FAKE_INVOICE',
                  'SOCIAL_ENGINEERING','SPAM','CLEAN'
                ].map(t => <option key={t} value={t}>{t.replace(/_/g,' ')}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1 block">Helios Status</label>
              <select className={clsx(inputCls, 'cursor-pointer')} value={actionTaken} onChange={e => setActionTaken(e.target.value)}>
                <option value="">All</option>
                {[
                  ['CLEAN','✓ Clean'],
                  ['FLAGGED_LOW','⚑ Flagged (Low)'],
                  ['FLAGGED_HIGH','⚑ Flagged (High)'],
                  ['QUARANTINED','⊘ Quarantined'],
                  ['MARKED_SPAM','⚠ Marked Spam'],
                  ['BLOCK_DELETE','✕ Blocked & Deleted'],
                  ['HIMAYA_FLAGGED','◈ Himaya-Flagged'],
                  ['HELIOS_ALERT','◉ Helios-Alert'],
                ].map(([v,l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1 block">Min Risk Score</label>
              <input type="number" min={0} max={100} className={inputCls} placeholder="0" value={minScore} onChange={e => setMinScore(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1 block">Max Risk Score</label>
              <input type="number" min={0} max={100} className={inputCls} placeholder="100" value={maxScore} onChange={e => setMaxScore(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-slate-500 mb-1 block">Auth Failure</label>
              <select className={clsx(inputCls, 'cursor-pointer')} value={authFail} onChange={e => setAuthFail(e.target.value)}>
                <option value="">Any</option>
                <option value="any_fail">Any Auth Failure</option>
                <option value="dkim_fail">DKIM Failed</option>
                <option value="spf_fail">SPF Failed</option>
                <option value="dmarc_fail">DMARC Failed</option>
              </select>
            </div>
          </div>
        )}

        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={handleSearch}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-[#e94560] hover:bg-[#c73652] text-white transition-colors">
            <Search size={14} /> Search
          </button>
          <button onClick={handleClear}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-[#0d1b2a] hover:bg-[#0f3460] text-slate-300 border border-[#0f3460]/60 transition-colors">
            <X size={14} /> Clear
          </button>
          <button onClick={exportCSV}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm bg-[#0d1b2a] hover:bg-[#0f3460] text-slate-300 border border-[#0f3460]/60 transition-colors">
            <Download size={14} /> Export CSV
          </button>
        </div>
      </div>

      {/* Quick Filter Pills */}
      <div className="flex items-center gap-2 flex-wrap">
        {[
          { label: 'All', key: 'all' }, { label: 'Quarantined', key: 'quarantined' },
          { label: 'Flagged', key: 'flagged' }, { label: 'BEC', key: 'bec' },
          { label: 'Phishing', key: 'phishing' }, { label: 'Last 24h', key: '24h' },
          { label: 'Last 7 days', key: '7d' }, { label: 'Last 30 days', key: '30d' },
        ].map(({ label, key }) => (
          <button key={key}
            onClick={() => key === 'all' ? handleClear() : applyQuickFilter(key)}
            className="px-3 py-1.5 rounded-full text-xs font-medium bg-[#16213e] hover:bg-[#0f3460] text-slate-300 border border-[#0f3460]/60 transition-colors">
            {label}
          </button>
        ))}
        <span className="text-xs text-slate-500 ml-auto">{pagination.total.toLocaleString()} results</span>
      </div>

      {/* Table */}
      <div className="bg-[#16213e] rounded-xl border border-[#0f3460]/40 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-16 text-slate-400">
            <RefreshCw size={18} className="animate-spin mr-2" /> Loading…
          </div>
        ) : results.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <Search size={36} className="text-slate-600 mb-4" />
            <p className="text-slate-300 font-medium">No messages found</p>
            <p className="text-slate-500 text-sm mt-2 max-w-sm">Try adjusting your filters or date range.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#0f3460]/40">
                  {['Delivered', 'Sender', 'Recipient', 'Domain', 'Classification', 'Risk', 'Helios Status', ''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {results.map(row => (
                  <tr key={row.id}
                    className="border-b border-[#0f3460]/20 hover:bg-[#0d1b2a]/60 transition-colors cursor-pointer group"
                    onClick={() => setSelectedRow(row)}>
                    <td className="px-4 py-3 text-slate-400 whitespace-nowrap text-xs">
                      {(() => {
                        const ts = row.email_received_at || row.detected_at
                        const d = safeParseDate(ts)
                        if (!d) return '—'
                        return (
                          <span className="flex flex-col gap-0.5">
                            <span className="text-slate-300">{safeFormat(d, 'MMM d, yyyy')}</span>
                            <span className="text-slate-500">{safeFormat(d, 'HH:mm:ss')}</span>
                          </span>
                        )
                      })()}
                    </td>
                    <td className="px-4 py-3 text-slate-200 max-w-[200px]">
                      <div className="flex items-center group/copy">
                        <span className="truncate text-xs">{row.sender ?? '—'}</span>
                        {row.sender && <CopyButton text={row.sender} />}
                      </div>
                      {row.subject && (
                        <span className="block truncate text-[11px] text-slate-400 mt-0.5" title={row.subject}>{row.subject}</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-300 text-xs max-w-[160px]">
                      <span className="truncate block">{row.recipient ?? '—'}</span>
                    </td>
                    <td className="px-4 py-3 text-xs">
                      <span className="text-slate-300">{row.sender_domain ?? '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      {row.threat_type && row.threat_type !== 'CLEAN'
                        ? <Badge label={row.threat_type} colorClass={THREAT_COLORS[row.threat_type] ?? 'bg-slate-700 text-slate-300 border-slate-600'} />
                        : <span className="text-green-400 text-xs">Clean</span>}
                    </td>
                    <td className="px-4 py-3">
                      <span className={clsx('font-bold text-base', riskColor(row.risk_score))}>{row.risk_score ?? '—'}</span>
                    </td>
                    <td className="px-4 py-3">
                      {row.action_taken
                        ? <Badge label={HELIOS_LABELS[row.action_taken] ?? row.action_taken} colorClass={HELIOS_COLORS[row.action_taken] ?? 'bg-slate-700 text-slate-300 border-slate-600'} />
                        : <span className="text-slate-500 text-xs">—</span>}
                    </td>
                    <td className="px-4 py-3">
                      <button onClick={e => { e.stopPropagation(); setSelectedRow(row) }}
                        className="flex items-center gap-1 px-2.5 py-1.5 rounded text-xs bg-[#0f3460]/60 hover:bg-[#0f3460] text-slate-300 transition-colors whitespace-nowrap">
                        <Eye size={12} /> Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {!loading && results.length > 0 && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-400">
              {((pagination.page - 1) * pagination.page_size) + 1}–{Math.min(pagination.page * pagination.page_size, pagination.total)} of {pagination.total.toLocaleString()}
            </span>
            <select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}
              className="text-xs px-2 py-1 rounded bg-[#16213e] border border-[#0f3460]/60 text-slate-300">
              {[25, 50, 100, 200].map(n => <option key={n} value={n}>{n} / page</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs bg-[#16213e] hover:bg-[#0f3460] text-slate-300 border border-[#0f3460]/60 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
              <ChevronLeft size={14} /> Prev
            </button>
            <span className="text-xs text-slate-400 px-2">Page {pagination.page} of {pagination.total_pages}</span>
            <button disabled={page >= pagination.total_pages} onClick={() => setPage(p => p + 1)}
              className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs bg-[#16213e] hover:bg-[#0f3460] text-slate-300 border border-[#0f3460]/60 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}

      {selectedRow && (
        <DetailPanel
          row={selectedRow}
          onClose={() => setSelectedRow(null)}
          onRowUpdated={updated => {
            setResults(prev => prev.map(r => r.id === updated.id ? updated : r))
            setSelectedRow(updated)
          }}
        />
      )}
    </div>
  )
}
