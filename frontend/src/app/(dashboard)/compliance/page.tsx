'use client'
import { useEffect, useState, useRef } from 'react'
import ControlsTable from '@/components/compliance/ControlsTable'
import Button from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import api from '@/lib/api'
import type { ComplianceControl } from '@/lib/types'
import { useTheme } from '@/contexts/ThemeContext'
import {
  FileText, Download, RefreshCw, ShieldCheck, AlertTriangle,
  TrendingUp, CheckCircle2, XCircle, Minus, ChevronDown, ChevronUp,
  Globe2, Flag, Shield, Search, Filter,
} from 'lucide-react'

const FRAMEWORKS = [
  'SAMA_CSF', 'NCA_ECC', 'UAE_NESA', 'CBUAE',
  'NIST_CSF', 'HIPAA', 'SOC2', 'CCPA',
  'GDPR', 'ISO_27001', 'DORA', 'NIS2',
] as const
type Framework = typeof FRAMEWORKS[number]

const LABELS: Record<Framework, string> = {
  SAMA_CSF: 'SAMA CSF',
  NCA_ECC: 'NCA ECC',
  UAE_NESA: 'UAE NESA',
  CBUAE: 'CBUAE',
  NIST_CSF: 'NIST CSF',
  HIPAA: 'HIPAA',
  SOC2: 'SOC 2',
  CCPA: 'CCPA',
  GDPR: 'GDPR',
  ISO_27001: 'ISO 27001',
  DORA: 'DORA',
  NIS2: 'NIS 2',
}

const FRAMEWORK_REGION: Record<Framework, 'Gulf' | 'US' | 'EU'> = {
  SAMA_CSF: 'Gulf', NCA_ECC: 'Gulf', UAE_NESA: 'Gulf', CBUAE: 'Gulf',
  NIST_CSF: 'US', HIPAA: 'US', SOC2: 'US', CCPA: 'US',
  GDPR: 'EU', ISO_27001: 'EU', DORA: 'EU', NIS2: 'EU',
}

const FRAMEWORK_DESC: Record<Framework, string> = {
  SAMA_CSF: 'Saudi Arabian Monetary Authority Cyber Security Framework',
  NCA_ECC: 'National Cybersecurity Authority Essential Cybersecurity Controls',
  UAE_NESA: 'UAE National Electronic Security Authority',
  CBUAE: 'Central Bank of the UAE Cybersecurity Framework',
  NIST_CSF: 'NIST Cybersecurity Framework — US federal security standard',
  HIPAA: 'Health Insurance Portability and Accountability Act — PHI / ePHI protections',
  SOC2: 'SOC 2 Trust Services Criteria — security, availability, confidentiality',
  CCPA: 'California Consumer Privacy Act — US consumer data rights & breach obligations',
  GDPR: 'EU General Data Protection Regulation — data privacy & breach notification',
  ISO_27001: 'ISO/IEC 27001 — International information security management standard',
  DORA: 'EU Digital Operational Resilience Act — ICT risk management for financial entities',
  NIS2: 'EU Network and Information Security Directive 2 — critical infrastructure cybersecurity',
}

interface AiSummary {
  headline: string
  findings: string[]
  recommendations: string[]
  risk_level: 'low' | 'medium' | 'high' | 'critical'
}

function generateAiSummary(controls: ComplianceControl[], framework: Framework, pct: number): AiSummary {
  const nonCompliant = controls.filter(c => c.status === 'non_compliant')
  const partial = controls.filter(c => c.status === 'partial')
  const compliant = controls.filter(c => c.status === 'compliant')
  const total = controls.length

  const risk_level: AiSummary['risk_level'] =
    pct >= 85 ? 'low' : pct >= 65 ? 'medium' : pct >= 40 ? 'high' : 'critical'

  const headline = pct >= 85
    ? `${LABELS[framework]} compliance is strong at ${pct}%. Minor gaps remain in ${nonCompliant.length} control${nonCompliant.length !== 1 ? 's' : ''}.`
    : pct >= 65
    ? `${LABELS[framework]} compliance stands at ${pct}% with ${partial.length + nonCompliant.length} controls requiring attention.`
    : `${LABELS[framework]} compliance is below threshold at ${pct}%. Immediate remediation of ${nonCompliant.length} non-compliant controls is recommended.`

  const findings: string[] = []

  if (compliant.length > 0) {
    findings.push(`${compliant.length} of ${total} controls are fully compliant — demonstrating a solid foundation in email security governance.`)
  }
  if (nonCompliant.length > 0) {
    const names = nonCompliant.slice(0, 3).map(c => (c as any).control_name_en ?? c.name_en ?? c.control_id).join(', ')
    findings.push(`${nonCompliant.length} non-compliant control${nonCompliant.length !== 1 ? 's' : ''} identified: ${names}${nonCompliant.length > 3 ? `, and ${nonCompliant.length - 3} more` : ''}.`)
  }
  if (partial.length > 0) {
    findings.push(`${partial.length} control${partial.length !== 1 ? 's are' : ' is'} partially implemented — evidence collection or configuration completion is required.`)
  }
  if (total === 0) {
    findings.push('No control data loaded. Ensure the compliance scanner has been run after connecting your email provider.')
  }

  const recommendations: string[] = []
  if (nonCompliant.length > 0) {
    recommendations.push(`Prioritize remediation of the ${nonCompliant.length} non-compliant control${nonCompliant.length !== 1 ? 's' : ''} — these represent the highest regulatory risk.`)
  }
  if (partial.length > 0) {
    recommendations.push(`Complete evidence collection for ${partial.length} partially implemented control${partial.length !== 1 ? 's' : ''} to move them to fully compliant.`)
  }
  if (pct < 80) {
    recommendations.push('Schedule a compliance review with your security team to address gaps before the next regulatory assessment period.')
  }
  if (pct >= 80) {
    recommendations.push('Maintain current compliance posture and set up automated evidence collection to sustain your score.')
  }
  recommendations.push('Generate and archive this compliance report as evidence for your next regulatory audit.')

  return { headline, findings, recommendations, risk_level }
}

const RISK_COLORS: Record<string, string> = {
  low: 'text-emerald-400 bg-emerald-900/20 border-emerald-700/30',
  medium: 'text-amber-400 bg-amber-900/20 border-amber-700/30',
  high: 'text-orange-400 bg-orange-900/20 border-orange-700/30',
  critical: 'text-red-400 bg-red-900/20 border-red-700/30',
}

const REGION_LABELS: Record<'Gulf' | 'US' | 'EU', { icon: React.ReactNode; label: string }> = {
  Gulf: { icon: <Globe2 size={11} />, label: 'Gulf / MENA Frameworks' },
  US:   { icon: <Flag size={11} />,   label: 'US Compliance Standards' },
  EU:   { icon: <Shield size={11} />, label: 'EU / UK Frameworks' },
}

// ── Theme-aware inline status banner ────────────────────────────────────────
function StatusBanner({ kind, isLight, children }: {
  kind: 'success' | 'error' | 'info'
  isLight: boolean
  children: React.ReactNode
}) {
  const cfg = {
    success: {
      bg:     isLight ? 'rgba(22,163,74,0.08)'   : 'rgba(74,222,128,0.07)',
      border: isLight ? 'rgba(22,163,74,0.35)'   : 'rgba(74,222,128,0.25)',
      icon:   isLight ? '#15803d' : '#4ade80',
      text:   isLight ? '#14532d' : '#bbf7d0',
    },
    error: {
      bg:     isLight ? 'rgba(220,38,38,0.07)'   : 'rgba(239,68,68,0.10)',
      border: isLight ? 'rgba(220,38,38,0.30)'   : 'rgba(239,68,68,0.30)',
      icon:   isLight ? '#dc2626' : '#f87171',
      text:   isLight ? '#7f1d1d' : '#fca5a5',
    },
    info: {
      bg:     isLight ? 'rgba(59,110,246,0.07)'  : 'rgba(59,110,246,0.10)',
      border: isLight ? 'rgba(59,110,246,0.30)'  : 'rgba(59,110,246,0.25)',
      icon:   isLight ? '#2563eb' : '#93b4fd',
      text:   isLight ? '#1e3a8a' : '#bfdbfe',
    },
  }[kind]

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '12px 16px', borderRadius: 12,
      background: cfg.bg, border: `1px solid ${cfg.border}`,
      fontSize: 13, color: cfg.text,
      boxShadow: isLight ? '0 1px 4px rgba(0,0,0,0.06)' : 'none',
    }}>
      {children}
    </div>
  )
}

export default function CompliancePage() {
  const { theme } = useTheme()
  const isLight = theme === 'light'
  const [activeTab, setActiveTab] = useState<Framework>('SAMA_CSF')
  const [controls, setControls] = useState<ComplianceControl[]>([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [generateError, setGenerateError] = useState('')
  const [generateSuccess, setGenerateSuccess] = useState(false)
  const [summary, setSummary] = useState<Record<Framework, number>>({} as Record<Framework, number>)
  const [showAi, setShowAi] = useState(true)
  const [assessing, setAssessing] = useState(false)
  const [assessSuccess, setAssessSuccess] = useState(false)
  const [assessError, setAssessError] = useState('')
  const [assessingAll, setAssessingAll] = useState(false)
  const [reportFormat, setReportFormat] = useState<'html' | 'pdf'>('pdf')
  const [showFormatMenu, setShowFormatMenu] = useState(false)
  const formatMenuRef = useRef<HTMLDivElement>(null)
  // New: search + status filter for the controls list
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'compliant' | 'partial' | 'non_compliant' | 'not_started'>('all')
  // New: trend series for the active framework (last 90d)
  const [trend, setTrend] = useState<Array<{ t: string; score: number }>>([])

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (formatMenuRef.current && !formatMenuRef.current.contains(e.target as Node)) {
        setShowFormatMenu(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  // Deduplicate controls by control_id, keeping the first occurrence
  const deduplicateControls = (items: ComplianceControl[]): ComplianceControl[] => {
    const seen = new Set<string>()
    return items.filter(c => {
      const key = c.control_id
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }

  useEffect(() => {
    setLoading(true)
    setGenerateError('')
    setGenerateSuccess(false)
    api.get(`/api/compliance/controls?framework=${activeTab}`)
      .then(async r => {
        const data = r.data
        const items = Array.isArray(data) ? data : (data?.items ?? [])
        // Deduplicate to prevent duplicate controls from showing
        setControls(deduplicateControls(items))

        // Auto-trigger assessment if no statuses exist yet (all "not_started")
        const allNotStarted = items.length > 0 && items.every(
          (c: { status: string }) => !c.status || c.status === 'not_started'
        )
        if (allNotStarted) {
          try {
            const assessRes = await api.post('/api/compliance/assess', { framework: activeTab })
            // Reload with fresh data
            const fresh = await api.get(`/api/compliance/controls?framework=${activeTab}`)
            const freshData = fresh.data
            setControls(deduplicateControls(Array.isArray(freshData) ? freshData : (freshData?.items ?? [])))
            // Refresh summary
            const sr = await api.get('/api/compliance/summary')
            setSummary(sr.data ?? {})
          } catch {
            // auto-assess failed silently, user can click Assess Now manually
          }
        }
      })
      .catch(() => setControls([]))
      .finally(() => setLoading(false))
  }, [activeTab])

  useEffect(() => {
    api.get('/api/compliance/summary')
      .then(r => setSummary(r.data ?? {}))
      .catch(() => {})
  }, [])

  // Load score history for the active framework (drives the sparkline)
  useEffect(() => {
    api.get(`/api/compliance/history?framework=${activeTab}&days=90`)
      .then(r => {
        const series = r.data?.series?.[activeTab] ?? []
        setTrend(series.map((p: { t: string; score: number }) => ({ t: p.t, score: p.score })))
      })
      .catch(() => setTrend([]))
  }, [activeTab, assessSuccess])

  const compliant = controls.filter(c => c.status === 'compliant').length
  const partial = controls.filter(c => c.status === 'partial').length
  const nonCompliant = controls.filter(c => c.status === 'non_compliant').length
  const pct = controls.length ? Math.round((compliant + partial * 0.5) / controls.length * 100) : (summary[activeTab] ?? 0)

  // Apply client-side search + status filter on top of the loaded controls.
  // (Backend also accepts these as query params — we filter client-side so the
  // KPI tiles above keep showing the framework total.)
  const visibleControls = controls.filter(c => {
    if (statusFilter !== 'all' && c.status !== statusFilter) return false
    if (searchTerm.trim()) {
      const needle = searchTerm.trim().toLowerCase()
      const hay = `${c.control_id} ${(c as any).control_name_en ?? c.name_en ?? ''} ${c.name_ar ?? ''}`.toLowerCase()
      if (!hay.includes(needle)) return false
    }
    return true
  })

  const aiSummary = generateAiSummary(controls, activeTab, pct)

  const assessNow = async () => {
    setAssessing(true)
    setAssessError('')
    setAssessSuccess(false)
    try {
      await api.post('/api/compliance/assess', { framework: activeTab })
      setAssessSuccess(true)
      setTimeout(() => setAssessSuccess(false), 5000)
      // Reload controls with fresh assessment
      const r = await api.get(`/api/compliance/controls?framework=${activeTab}`)
      const data = r.data
      setControls(Array.isArray(data) ? data : (data?.items ?? []))
      // Reload summary
      const sr = await api.get('/api/compliance/summary')
      setSummary(sr.data ?? {})
    } catch (e: any) {
      setAssessError(e?.response?.data?.detail ?? 'Assessment failed. Please try again.')
    }
    setAssessing(false)
  }

  const assessAll = async () => {
    setAssessingAll(true)
    setAssessError('')
    try {
      for (const fw of FRAMEWORKS) {
        try {
          await api.post('/api/compliance/assess', { framework: fw })
        } catch {
          // continue with next framework even if one fails
        }
      }
      setAssessSuccess(true)
      setTimeout(() => setAssessSuccess(false), 5000)
      // Reload current tab controls
      const r = await api.get(`/api/compliance/controls?framework=${activeTab}`)
      const data = r.data
      setControls(Array.isArray(data) ? data : (data?.items ?? []))
      // Reload summary
      const sr = await api.get('/api/compliance/summary')
      setSummary(sr.data ?? {})
    } catch (e: any) {
      setAssessError(e?.response?.data?.detail ?? 'Assess All failed. Please try again.')
    }
    setAssessingAll(false)
  }

  const generateReport = async (fmt?: 'html' | 'pdf') => {
    const format = fmt ?? reportFormat
    setGenerating(true)
    setGenerateError('')
    setGenerateSuccess(false)
    try {
      const res = await api.post('/api/compliance/report/generate', {
        framework: activeTab,
        format,
        date_from: new Date(Date.now() - 90 * 86400000).toISOString().slice(0, 10),
        date_to: new Date().toISOString().slice(0, 10),
      }, { timeout: 120000 })  // 2 min — Claude + PDF/HTML generation can take 30-60s

      const reportId = res.data?.report_id
      if (!reportId) throw new Error('No report ID returned')

      // Poll for completion (max 40s)
      let ready = false
      for (let i = 0; i < 20; i++) {
        await new Promise(r => setTimeout(r, 2000))
        try {
          const poll = await api.get(`/api/compliance/report/${reportId}/status`)
          if (poll.data?.status === 'ready' || poll.data?.status === 'complete') {
            ready = true
            break
          }
        } catch {
          // status endpoint might not exist — fall through to direct download
          ready = true
          break
        }
      }

      // Direct download
      const apiBase = process.env.NEXT_PUBLIC_API_URL || 'https://app.himaya.ai'
      const downloadUrl = `${apiBase}/api/compliance/report/${reportId}`

      // Fetch as blob so we handle auth headers
      const token = typeof window !== 'undefined' ? localStorage.getItem('sentinel_token') : null
      const blobRes = await fetch(downloadUrl, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!blobRes.ok) throw new Error(`Download failed: ${blobRes.status}`)

      const blob = await blobRes.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `Himaya-Himaya-${LABELS[activeTab]}-Compliance-Report.${format}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      setGenerateSuccess(true)
      setTimeout(() => setGenerateSuccess(false), 5000)
    } catch (e: any) {
      setGenerateError(e?.message || 'Report generation failed. Please try again.')
    }
    setGenerating(false)
  }

  return (
    <div className="space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Compliance Center</h1>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" loading={assessingAll} onClick={assessAll}>
            {assessingAll
              ? <><RefreshCw size={13} className="animate-spin" /> Assessing All…</>
              : <><ShieldCheck size={13} /> Assess All</>}
          </Button>
          <Button size="sm" variant="secondary" loading={assessing} onClick={assessNow}>
            {assessing ? <><RefreshCw size={13} className="animate-spin" /> Assessing…</> : <><ShieldCheck size={13} /> Assess Now</>}
          </Button>
          {/* Split Report button - all Himaya blue */}
          <div className="relative flex" ref={formatMenuRef}>
            <button
              onClick={() => generateReport()}
              disabled={generating}
              className="inline-flex items-center gap-1.5 text-[12px] font-medium px-3 py-1.5 bg-[#3b6ef6] hover:bg-[#2d5fe0] disabled:opacity-50 text-white rounded-l-lg border-r border-r-white/20 transition-colors"
            >
              {generating
                ? <><RefreshCw size={13} className="animate-spin" /> Generating…</>
                : <><FileText size={13} /> Generate {reportFormat.toUpperCase()}</>}
            </button>
            <button
              onClick={() => setShowFormatMenu(v => !v)}
              className="flex items-center px-2 bg-[#3b6ef6] hover:bg-[#2d5fe0] rounded-r-lg border-l border-l-white/20 transition-colors"
              title="Choose report format"
            >
              <ChevronDown size={12} className="text-white" />
            </button>
            {showFormatMenu && (
              <div className="absolute right-0 top-full mt-1 z-50 bg-[#1a1f3c] border border-white/[0.1] rounded-xl shadow-xl overflow-hidden w-40">
                <button
                  className={`w-full text-left px-4 py-2.5 text-[13px] hover:bg-white/[0.06] transition-colors ${reportFormat === 'pdf' ? 'text-white font-semibold' : 'text-slate-300'}`}
                  onClick={() => { setReportFormat('pdf'); setShowFormatMenu(false) }}
                >
                  <FileText size={12} className="inline mr-2 text-slate-400" />
                  Download PDF
                </button>
                <button
                  className={`w-full text-left px-4 py-2.5 text-[13px] hover:bg-white/[0.06] transition-colors ${reportFormat === 'html' ? 'text-white font-semibold' : 'text-slate-300'}`}
                  onClick={() => { setReportFormat('html'); setShowFormatMenu(false) }}
                >
                  <Download size={12} className="inline mr-2 text-slate-400" />
                  Download HTML
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Assessment status */}
      {assessSuccess && (
        <StatusBanner kind="success" isLight={isLight}>
          <CheckCircle2 size={14} /> Assessment complete — controls updated with latest findings.
        </StatusBanner>
      )}
      {assessError && (
        <StatusBanner kind="error" isLight={isLight}>
          <AlertTriangle size={14} /> {assessError}
        </StatusBanner>
      )}

      {/* Report generate / download status */}
      {generateSuccess && (
        <StatusBanner kind="success" isLight={isLight}>
          <CheckCircle2 size={14} />
          <span>
            <strong>{reportFormat.toUpperCase()} report ready.</strong>{' '}
            Check your Downloads folder.
          </span>
        </StatusBanner>
      )}
      {generateError && (
        <StatusBanner kind="error" isLight={isLight}>
          <AlertTriangle size={14} /> {generateError}
        </StatusBanner>
      )}

      {/* Framework tabs — Gulf, US, EU regions */}
      {(['Gulf', 'US', 'EU'] as const).map(region => (
        <div key={region}>
          <p className="text-[10px] font-semibold text-slate-600 uppercase tracking-widest mb-2 px-1 flex items-center gap-1.5">
            {REGION_LABELS[region].icon}
            {REGION_LABELS[region].label}
          </p>
          <div className="flex gap-1.5 flex-wrap">
            {FRAMEWORKS.filter(f => FRAMEWORK_REGION[f] === region).map(f => (
              <button
                key={f}
                onClick={() => setActiveTab(f)}
                className={`flex flex-col px-4 py-2.5 rounded-xl text-sm transition-all ${
                  activeTab === f
                    ? 'bg-[#e94560] text-white shadow-lg shadow-[#e94560]/20'
                    : 'bg-[#141417] text-slate-400 hover:text-white border border-white/[0.06] hover:border-white/[0.12]'
                }`}
              >
                <span className="font-semibold text-[13px]">{LABELS[f]}</span>
                {summary[f] != null && (
                  <span className={`text-[10px] font-medium mt-0.5 ${activeTab === f ? 'text-white/70' : 'text-slate-600'}`}>
                    {summary[f]}% compliant
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      ))}

      {/* Compliance score banner */}
      <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
        <div className="p-5 flex items-center gap-6">
          {/* Score ring */}
          <div className="relative flex-shrink-0">
            <svg width="80" height="80" viewBox="0 0 80 80" className="-rotate-90">
              <circle cx="40" cy="40" r="32" fill="none" stroke="#1e1e24" strokeWidth="8" />
              <circle
                cx="40" cy="40" r="32" fill="none"
                stroke={pct >= 80 ? '#4ade80' : pct >= 60 ? '#fbbf24' : '#f87171'}
                strokeWidth="8"
                strokeDasharray={`${(pct / 100) * 201} 201`}
                strokeLinecap="round"
                className="transition-all duration-700"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-[17px] font-bold text-white">{pct}%</span>
            </div>
          </div>

          <div className="flex-1">
            <div className="flex items-baseline gap-2 mb-1">
              <h2 className="text-base font-bold text-white">{LABELS[activeTab]} Compliance</h2>
              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border uppercase tracking-wide ${RISK_COLORS[aiSummary.risk_level]}`}>
                {aiSummary.risk_level} risk
              </span>
              {/* 90-day trend sparkline (only if we have history) */}
              {trend.length >= 2 && (
                <div className="ml-auto flex items-center gap-2 text-[10px] text-slate-500">
                  <span>90d trend</span>
                  <svg width="90" height="22" viewBox="0 0 90 22">
                    {(() => {
                      const xs = trend.map((_, i) => (i / (trend.length - 1)) * 88 + 1)
                      const min = Math.min(...trend.map(p => p.score))
                      const max = Math.max(...trend.map(p => p.score))
                      const range = Math.max(1, max - min)
                      const ys = trend.map(p => 20 - ((p.score - min) / range) * 18)
                      const d = xs.map((x, i) => `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${ys[i].toFixed(1)}`).join(' ')
                      const last = trend[trend.length - 1].score
                      const first = trend[0].score
                      const colour = last >= first ? '#4ade80' : '#f87171'
                      return (
                        <>
                          <path d={d} stroke={colour} strokeWidth="1.5" fill="none" />
                          <circle cx={xs[xs.length - 1]} cy={ys[ys.length - 1]} r="2" fill={colour} />
                        </>
                      )
                    })()}
                  </svg>
                  <span className={trend[trend.length - 1].score >= trend[0].score ? 'text-emerald-400' : 'text-red-400'}>
                    {trend[trend.length - 1].score >= trend[0].score ? '↗' : '↘'} {Math.abs(trend[trend.length - 1].score - trend[0].score)}%
                  </span>
                </div>
              )}
            </div>
            <p className="text-[12px] text-slate-500 mb-3">{FRAMEWORK_DESC[activeTab]}</p>
            {/* Progress breakdown */}
            <div className="flex items-center gap-5">
              <div className="flex items-center gap-1.5 text-[12px]">
                <CheckCircle2 size={13} className="text-emerald-400" />
                <span className="text-slate-300 font-medium">{compliant}</span>
                <span className="text-slate-500">compliant</span>
              </div>
              <div className="flex items-center gap-1.5 text-[12px]">
                <Minus size={13} className="text-amber-400" />
                <span className="text-slate-300 font-medium">{partial}</span>
                <span className="text-slate-500">partial</span>
              </div>
              <div className="flex items-center gap-1.5 text-[12px]">
                <XCircle size={13} className="text-red-400" />
                <span className="text-slate-300 font-medium">{nonCompliant}</span>
                <span className="text-slate-500">non-compliant</span>
              </div>
              <div className="ml-auto text-[11px] text-slate-500">
                {controls.length} total controls
              </div>
            </div>
          </div>
        </div>

        {/* Score bar */}
        <div className="h-1.5 bg-[#1e1e24]">
          <div
            className="h-full transition-all duration-700"
            style={{
              width: `${pct}%`,
              background: pct >= 80
                ? 'linear-gradient(90deg, #4ade80, #22d3ee)'
                : pct >= 60
                ? 'linear-gradient(90deg, #fbbf24, #f97316)'
                : 'linear-gradient(90deg, #f87171, #e94560)',
            }}
          />
        </div>
      </div>

      {/* AI Analysis Summary */}
      {controls.length > 0 && (
        <div className="bg-[#0d1628] border border-[#1a2d5a]/50 rounded-xl overflow-hidden">
          <button
            onClick={() => setShowAi(v => !v)}
            className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-white/[0.02] transition-colors"
          >
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 rounded-md bg-[#3b6ef6]/20 flex items-center justify-center">
                <TrendingUp size={11} className="text-[#3b6ef6]" />
              </div>
              <span className="text-[13px] font-semibold text-white">AI Analysis & Findings</span>
              <span className="text-[11px] text-slate-500">· Himaya Compliance Intelligence</span>
            </div>
            {showAi ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
          </button>

          {showAi && (
            <div className="px-5 pb-5 space-y-4 border-t border-[#1a2d5a]/30">
              {/* Headline */}
              <div className="mt-4 px-4 py-3 bg-[#0a1628] rounded-xl border border-[#1a2744]">
                <p className="text-[13px] text-slate-200 leading-relaxed font-medium">{aiSummary.headline}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Key Findings */}
                <div>
                  <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                    <ShieldCheck size={11} /> Key Findings
                  </h4>
                  <ul className="space-y-2">
                    {aiSummary.findings.map((f, i) => (
                      <li key={i} className="flex items-start gap-2 text-[12px] text-slate-300 leading-relaxed">
                        <span className="flex-shrink-0 w-4 h-4 rounded-full bg-[#3b6ef6]/15 text-[#3b6ef6] text-[9px] font-bold flex items-center justify-center mt-0.5">
                          {i + 1}
                        </span>
                        {f}
                      </li>
                    ))}
                  </ul>
                </div>

                {/* Recommendations */}
                <div>
                  <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2.5 flex items-center gap-1.5">
                    <TrendingUp size={11} /> Recommendations
                  </h4>
                  <ul className="space-y-2">
                    {aiSummary.recommendations.map((r, i) => (
                      <li key={i} className="flex items-start gap-2 text-[12px] text-slate-300 leading-relaxed">
                        <span className="flex-shrink-0 text-[#4ade80] mt-0.5">→</span>
                        {r}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="flex items-center gap-2 pt-1 border-t border-[#1a2d5a]/30">
                <span className="text-[10px] text-slate-600">
                  Analysis generated from live compliance data · {new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}
                </span>
                <button
                  onClick={() => generateReport()}
                  disabled={generating}
                  className="ml-auto flex items-center gap-1.5 text-[11px] text-[#3b6ef6] hover:text-blue-300 transition-colors disabled:opacity-50"
                >
                  <Download size={11} /> Export full {reportFormat.toUpperCase()} report
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Controls table */}
      <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-white/[0.05] flex flex-wrap items-center gap-3">
          <h3 className="text-[13px] font-semibold text-white">{LABELS[activeTab]} Controls</h3>
          <span className="text-[11px] text-slate-500">
            {visibleControls.length}{visibleControls.length !== controls.length ? ` of ${controls.length}` : ''} controls
          </span>

          {/* Search */}
          <div className="ml-auto flex items-center gap-2">
            <div className="relative">
              <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                placeholder="Search control id or name…"
                className="pl-7 pr-3 py-1.5 text-[12px] bg-[#0d1018] border border-white/[0.08] rounded-lg text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-[#3b6ef6]/60 w-56"
              />
            </div>
            {/* Status filter chips */}
            <div className="flex items-center gap-1 text-[11px]">
              {(['all', 'compliant', 'partial', 'non_compliant', 'not_started'] as const).map(s => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-2.5 py-1.5 rounded-md border transition-colors ${
                    statusFilter === s
                      ? 'bg-[#3b6ef6]/15 border-[#3b6ef6]/40 text-[#a8c0ff]'
                      : 'bg-transparent border-white/[0.06] text-slate-500 hover:text-slate-300 hover:border-white/[0.12]'
                  }`}
                  title={s === 'all' ? 'Show all controls' : `Show only ${s.replace('_', ' ')}`}
                >
                  {s === 'all' ? 'All' : s.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>
        </div>
        {loading ? (
          <div className="p-5 space-y-3">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-11 animate-pulse bg-white/[0.03] rounded-lg" />
            ))}
          </div>
        ) : controls.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            <ShieldCheck size={28} className="mx-auto mb-3 opacity-30" />
            <p className="text-[13px]">No controls loaded for {LABELS[activeTab]}.</p>
            <p className="text-[12px] text-slate-600 mt-1">Connect your email provider and run a baseline scan first.</p>
          </div>
        ) : visibleControls.length === 0 ? (
          <div className="text-center py-12 text-slate-500">
            <Filter size={28} className="mx-auto mb-3 opacity-30" />
            <p className="text-[13px]">No controls match the current filter.</p>
            <button
              onClick={() => { setSearchTerm(''); setStatusFilter('all') }}
              className="text-[11px] text-[#3b6ef6] hover:text-blue-300 mt-2"
            >Clear filters</button>
          </div>
        ) : (
          <ControlsTable controls={visibleControls} />
        )}
      </div>
    </div>
  )
}
