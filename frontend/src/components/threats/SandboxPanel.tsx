'use client'
import { useState, useEffect, useRef } from 'react'
import { FlaskConical, AlertTriangle, CheckCircle, XCircle, Loader2,
  ChevronDown, ChevronUp, ExternalLink, Shield, Monitor, StopCircle, Clock } from 'lucide-react'
import api from '@/lib/api'
import { clsx } from 'clsx'

interface UrlScreenshot {
  url: string
  final_url: string
  screenshot_b64: string | null
  page_title: string
  risk_score: number
  risk_indicators: string[]
  redirect_chain: string[]
  has_login_form: boolean
  phishing_keywords: string[]
}

interface SandboxResult {
  job_id: string
  threat_id: string
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'INCONCLUSIVE' | 'ERROR'
  risk_score: number
  confidence: number
  behavior_summary_en: string
  behavior_summary_ar: string
  iocs: { ips: string[]; domains: string[]; files: string[]; urls: string[] }
  mitre_techniques: string[]
  network_activity: boolean
  persistence_attempted: boolean
  data_exfiltration_attempted: boolean
  analyzed_at: string
  url_screenshots?: UrlScreenshot[]
}

interface SandboxSession {
  session_id: string
  status: 'launching' | 'starting' | 'booting' | 'ready' | 'terminated' | 'error' | 'not_configured'
  streaming_url?: string
  public_ip?: string
  timeout_at?: string
  message?: string
  setup_required?: boolean
}

interface Props {
  threatId: string
  targetUrl?: string
}

const VERDICT_CONFIG = {
  MALICIOUS:    { color: 'text-red-400',    bg: 'bg-red-900/30 border-red-700/40',      icon: XCircle,       label: 'MALICIOUS' },
  SUSPICIOUS:   { color: 'text-amber-400',  bg: 'bg-amber-900/30 border-amber-700/40',  icon: AlertTriangle, label: 'SUSPICIOUS' },
  CLEAN:        { color: 'text-green-400',  bg: 'bg-green-900/30 border-green-700/40',  icon: CheckCircle,   label: 'CLEAN' },
  INCONCLUSIVE: { color: 'text-slate-400',  bg: 'bg-slate-800/40 border-slate-600/40',  icon: AlertTriangle, label: 'INCONCLUSIVE' },
  ERROR:        { color: 'text-slate-500',  bg: 'bg-slate-800/30 border-slate-700/30',  icon: XCircle,       label: 'ERROR' },
}

function ScreenshotCard({ s }: { s: UrlScreenshot }) {
  const [expanded, setExpanded] = useState(false)
  const riskColor = s.risk_score >= 70 ? 'text-red-400 border-red-700/40 bg-red-900/20'
    : s.risk_score >= 40 ? 'text-amber-400 border-amber-700/40 bg-amber-900/20'
    : 'text-green-400 border-green-700/40 bg-green-900/20'

  return (
    <div className="border border-[#1a2d5a]/60 rounded-lg overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between px-3 py-2 bg-[#0d1b2a] cursor-pointer"
        onClick={() => setExpanded(v => !v)}
      >
        <div className="flex-1 min-w-0">
          <p className="text-xs font-mono text-slate-300 truncate">{s.final_url || s.url}</p>
          {s.page_title && <p className="text-xs text-slate-500 truncate">{s.page_title}</p>}
        </div>
        <div className="flex items-center gap-2 ml-3 flex-shrink-0">
          {s.has_login_form && (
            <span className="text-xs px-1.5 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-700/30">
              Login form
            </span>
          )}
          <span className={clsx('text-xs px-1.5 py-0.5 rounded border font-bold', riskColor)}>
            {s.risk_score}
          </span>
          {expanded ? <ChevronUp size={14} className="text-slate-500" /> : <ChevronDown size={14} className="text-slate-500" />}
        </div>
      </div>

      {expanded && (
        <div className="bg-[#060f1a] p-3 space-y-3">
          {/* Screenshot */}
          {s.screenshot_b64 ? (
            <div>
              <p className="text-xs text-slate-500 mb-1.5">Browser screenshot (isolated environment)</p>
              <div className="rounded overflow-hidden border border-[#1a2d5a]/40">
                <img
                  src={`data:image/png;base64,${s.screenshot_b64}`}
                  alt={`Screenshot of ${s.url}`}
                  className="w-full object-top"
                  style={{ maxHeight: '360px', objectFit: 'cover', objectPosition: 'top' }}
                />
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2 py-4 text-xs text-slate-500 justify-center border border-dashed border-[#1a2d5a]/40 rounded">
              <Shield size={14} /> Screenshot not available
            </div>
          )}

          {/* Redirect chain */}
          {s.redirect_chain.length > 1 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">Redirect chain</p>
              <div className="space-y-0.5">
                {s.redirect_chain.map((u, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-xs">
                    {i > 0 && <span className="text-slate-600">↳</span>}
                    <span className={clsx('font-mono truncate', i === s.redirect_chain.length - 1 ? 'text-amber-300' : 'text-slate-400')}>
                      {u}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Risk indicators */}
          {s.risk_indicators.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">Risk indicators</p>
              <div className="flex flex-wrap gap-1.5">
                {s.risk_indicators.map((ind, i) => (
                  <span key={i} className="text-xs px-2 py-0.5 rounded bg-red-900/30 text-red-300 border border-red-700/30">
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Phishing keywords */}
          {s.phishing_keywords.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">Phishing language detected</p>
              <div className="flex flex-wrap gap-1.5">
                {s.phishing_keywords.map((kw, i) => (
                  <span key={i} className="text-xs px-2 py-0.5 rounded bg-amber-900/30 text-amber-300 border border-amber-700/30 italic">
                    "{kw}"
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function SandboxPanel({ threatId, targetUrl }: Props) {
  const [state, setState] = useState<'idle' | 'queued' | 'polling' | 'done' | 'error'>('idle')
  const [jobId, setJobId] = useState<string | null>(null)
  const [result, setResult] = useState<SandboxResult | null>(null)
  const [autoDetonation, setAutoDetonation] = useState<UrlScreenshot[] | null>(null)
  const [expanded, setExpanded] = useState(true)
  const [activeTab, setActiveTab] = useState<'auto' | 'interactive'>('auto')
  const [session, setSession] = useState<SandboxSession | null>(null)
  const [sessionLoading, setSessionLoading] = useState(false)
  const pollRef = useRef<NodeJS.Timeout | null>(null)
  const sessionPollRef = useRef<NodeJS.Timeout | null>(null)

  // Check for auto-detonation results from initial processing
  useEffect(() => {
    api.get(`/api/sandbox/detonation/${threatId}`)
      .then(r => {
        if (r.data.status === 'complete' && r.data.results?.length > 0) {
          setAutoDetonation(r.data.results)
        }
      })
      .catch(() => {})
  }, [threatId])

  const submit = async () => {
    setState('queued')
    try {
      const res = await api.post('/api/sandbox/analyze', {
        threat_id: threatId,
        job_type: 'url',
        target: targetUrl || '',
      })
      setJobId(res.data.job_id)
      setState('polling')
    } catch {
      setState('error')
    }
  }

  // Launch interactive EC2 session
  const launchSession = async () => {
    setSessionLoading(true)
    try {
      const res = await api.post('/api/sandbox/session', { threat_id: threatId })
      setSession(res.data)
      // Start polling for ready status
      sessionPollRef.current = setInterval(async () => {
        if (!res.data.session_id) return
        try {
          const s = await api.get(`/api/sandbox/session/${res.data.session_id}/status`)
          setSession(s.data)
          if (s.data.status === 'ready' || s.data.status === 'terminated' || s.data.status === 'error') {
            if (sessionPollRef.current) clearInterval(sessionPollRef.current)
          }
        } catch {}
      }, 15000)
    } catch (e: any) {
      setSession({ session_id: '', status: 'error', message: e?.message || 'Failed to launch session' })
    } finally {
      setSessionLoading(false)
    }
  }

  const endSession = async () => {
    if (!session?.session_id) return
    if (sessionPollRef.current) clearInterval(sessionPollRef.current)
    try {
      await api.post(`/api/sandbox/session/${session.session_id}/end`)
      setSession(prev => prev ? { ...prev, status: 'terminated' } : null)
    } catch {}
  }

  useEffect(() => () => {
    if (sessionPollRef.current) clearInterval(sessionPollRef.current)
  }, [])

  const SESSION_STATUS_STEPS = [
    { key: 'launching', label: 'Allocating isolated EC2 instance' },
    { key: 'starting',  label: 'Instance starting — loading OS' },
    { key: 'booting',   label: 'Installing desktop + noVNC' },
    { key: 'ready',     label: 'Session ready' },
  ]
  const sessionStepIdx = SESSION_STATUS_STEPS.findIndex(s => s.key === session?.status)

  useEffect(() => {
    if (state !== 'polling' || !jobId) return
    const poll = async () => {
      try {
        const res = await api.get(`/api/sandbox/results/${jobId}`)
        if (res.data.status === 'complete') {
          setResult(res.data.result)
          setState('done')
          if (pollRef.current) clearInterval(pollRef.current)
        }
      } catch {}
    }
    pollRef.current = setInterval(poll, 8000)
    poll()
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [state, jobId])

  const cfg = result ? VERDICT_CONFIG[result.verdict] ?? VERDICT_CONFIG.INCONCLUSIVE : null

  return (
    <div className="border border-[#1a2d5a]/60 rounded-xl bg-[#0d1b2a] overflow-hidden">
      {/* Header + Tabs */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#1a2d5a]/40">
        <div className="flex items-center gap-1">
          <button
            onClick={() => setActiveTab('auto')}
            className={clsx('flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
              activeTab === 'auto' ? 'bg-[#e94560]/20 text-[#e94560] border border-[#e94560]/30' : 'text-slate-400 hover:text-slate-200')}
          >
            <FlaskConical size={13} /> Auto Analysis
          </button>
          <button
            onClick={() => setActiveTab('interactive')}
            className={clsx('flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors',
              activeTab === 'interactive' ? 'bg-[#3b6ef6]/20 text-[#3b6ef6] border border-[#3b6ef6]/30' : 'text-slate-400 hover:text-slate-200')}
          >
            <Monitor size={13} /> Live Session
          </button>
        </div>
        <div className="flex items-center gap-2">
          {state === 'idle' && (
            <button
              onClick={submit}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-[#e94560]/20 hover:bg-[#e94560]/30 text-[#e94560] border border-[#e94560]/30 transition-colors"
            >
              Run Analysis
            </button>
          )}
          {(state === 'queued' || state === 'polling') && (
            <div className="flex items-center gap-2 text-xs text-amber-400">
              <Loader2 size={13} className="animate-spin" />
              Analysing… (~30s)
            </div>
          )}
          {state === 'done' && cfg && (
            <div className="flex items-center gap-2">
              <span className={clsx('text-xs font-bold px-2 py-0.5 rounded border', cfg.bg, cfg.color)}>
                {cfg.label}
              </span>
              <button onClick={() => setExpanded(v => !v)} className="text-slate-500 hover:text-slate-300">
                {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </button>
            </div>
          )}
          {state === 'error' && <span className="text-xs text-red-400">Submission failed</span>}
        </div>
      </div>

      <div className="px-4 py-3 space-y-4">
        {/* ── Auto Analysis Tab content ── */}
        {/* Auto-detonation results (from initial processing) */}
        {activeTab === 'auto' && autoDetonation && autoDetonation.length > 0 && state === 'idle' && (
          <div>
            <p className="text-xs text-slate-400 mb-2 font-medium">
              URLs automatically detonated during initial analysis
            </p>
            <div className="space-y-2">
              {autoDetonation.map((s, i) => <ScreenshotCard key={i} s={s} />)}
            </div>
            <div className="mt-3 pt-3 border-t border-[#1a2d5a]/30">
              <p className="text-xs text-slate-500 mb-2">
                Run a full sandbox analysis for deeper behavioural insight and MITRE ATT&CK mapping:
              </p>
              <button
                onClick={submit}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-[#e94560]/20 hover:bg-[#e94560]/30 text-[#e94560] border border-[#e94560]/30 transition-colors"
              >
                Full Sandbox Analysis
              </button>
            </div>
          </div>
        )}

        {/* Idle with no auto-detonation */}
        {activeTab === 'auto' && state === 'idle' && (!autoDetonation || autoDetonation.length === 0) && (
          <p className="text-xs text-slate-500">
            Detonate suspicious links in an isolated headless browser. Captures screenshots, redirect chains,
            credential harvesting forms, and MITRE ATT&CK techniques.
          </p>
        )}

        {/* Progress during analysis */}
        {activeTab === 'auto' && (state === 'queued' || state === 'polling') && (
          <div className="space-y-2">
            {[
              ['✓', 'text-green-400', 'Launching isolated headless Chromium browser'],
              ['✓', 'text-green-400', 'Enabling network traffic monitoring'],
              [<Loader2 size={10} className="animate-spin text-amber-400 mt-0.5 inline-block" />, '', 'Visiting URLs and capturing screenshots'],
              ['○', 'text-slate-600', 'Analysing page behaviour and risk indicators'],
              ['○', 'text-slate-600', 'AI threat classification + MITRE mapping'],
            ].map(([icon, cls, text], i) => (
              <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                <span className={cls as string}>{icon}</span>
                <span>{text as string}</span>
              </div>
            ))}
          </div>
        )}

        {/* Full analysis result */}
        {/* ── Interactive Session Tab ── */}
        {activeTab === 'interactive' && (
          <div className="space-y-3">
            {!session && (
              <>
                <p className="text-xs text-slate-400">
                  Spins up an isolated EC2 instance with a monitored Linux desktop. Opens the email in
                  Firefox inside the sandbox — links are fully clickable, network activity is logged.
                  Session auto-terminates after {30} minutes.
                </p>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  {[
                    ['Desktop', 'Isolated desktop', 'No access to production systems'],
                    ['Network', 'Network monitored', 'All DNS + TCP activity logged'],
                    ['Timer', '30 min sessions', 'Auto-terminates, EC2 billed per use'],
                  ].map(([, title, desc]) => (
                    <div key={title} className="bg-[#060f1a] rounded-lg p-2 border border-[#1a2d5a]/40">
                      <div className="font-medium text-slate-300 text-xs mb-0.5">{title}</div>
                      <div className="text-slate-500 text-[11px]">{desc}</div>
                    </div>
                  ))}
                </div>
                <button
                  onClick={launchSession}
                  disabled={sessionLoading}
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium bg-[#3b6ef6]/20 hover:bg-[#3b6ef6]/30 text-[#3b6ef6] border border-[#3b6ef6]/30 transition-colors disabled:opacity-50"
                >
                  {sessionLoading ? <Loader2 size={14} className="animate-spin" /> : <Monitor size={14} />}
                  Launch Interactive Session
                </button>
              </>
            )}

            {session && session.status === 'not_configured' && (
              <div className="rounded-lg bg-amber-900/20 border border-amber-700/30 p-4">
                <p className="text-xs text-amber-300 font-medium mb-1">Infrastructure setup required</p>
                <p className="text-xs text-amber-400/70 leading-relaxed">{session.message}</p>
                <p className="text-xs text-slate-500 mt-2">
                  Set <code className="bg-black/30 px-1 rounded">SANDBOX_AMI_ID</code>,{' '}
                  <code className="bg-black/30 px-1 rounded">SANDBOX_SG_ID</code>, and{' '}
                  <code className="bg-black/30 px-1 rounded">SANDBOX_SUBNET_ID</code> in ECS task env vars.
                </p>
              </div>
            )}

            {session && ['launching', 'starting', 'booting'].includes(session.status) && (
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-xs text-amber-400 mb-3">
                  <Loader2 size={13} className="animate-spin" />
                  Setting up isolated sandbox environment…
                </div>
                {SESSION_STATUS_STEPS.map((step, i) => (
                  <div key={step.key} className="flex items-center gap-2 text-xs">
                    {i < sessionStepIdx ? (
                      <CheckCircle size={13} className="text-green-400 flex-shrink-0" />
                    ) : i === sessionStepIdx ? (
                      <Loader2 size={13} className="animate-spin text-amber-400 flex-shrink-0" />
                    ) : (
                      <div className="w-3.5 h-3.5 rounded-full border border-slate-600 flex-shrink-0" />
                    )}
                    <span className={i <= sessionStepIdx ? 'text-slate-300' : 'text-slate-600'}>
                      {step.label}
                    </span>
                  </div>
                ))}
                <p className="text-xs text-slate-500 pt-1">
                  Typically ready in 2-4 minutes. Page auto-updates.
                </p>
              </div>
            )}

            {session && session.status === 'ready' && session.streaming_url && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs text-green-400">
                    <CheckCircle size={13} /> Session ready · {session.public_ip}
                  </div>
                  <div className="flex items-center gap-2">
                    {session.timeout_at && (
                      <div className="flex items-center gap-1 text-xs text-slate-500">
                        <Clock size={11} />
                        Ends {new Date(session.timeout_at).toLocaleTimeString()}
                      </div>
                    )}
                    <button
                      onClick={endSession}
                      className="flex items-center gap-1 px-2.5 py-1 rounded text-xs bg-red-900/30 text-red-300 border border-red-700/30 hover:bg-red-900/50 transition-colors"
                    >
                      <StopCircle size={11} /> End Session
                    </button>
                  </div>
                </div>

                {/* Session launcher — noVNC opens in a new tab to avoid HTTPS/HTTP mixed-content restrictions */}
                <div className="rounded-lg border border-green-700/30 bg-green-900/10 p-4 space-y-3">
                  <div className="flex items-start gap-3">
                    <Monitor size={32} className="text-green-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-sm font-medium text-green-300 mb-1">
                        Sandbox desktop is ready
                      </p>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        The isolated EC2 desktop is running with the email loaded in Firefox.
                        Click below to open the live session — it launches in a new browser tab
                        (required because the sandbox uses HTTP on port 6080).
                      </p>
                    </div>
                  </div>

                  <a
                    href={session.streaming_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-2 w-full py-3 rounded-lg text-sm font-semibold bg-green-600/20 hover:bg-green-600/30 text-green-300 border border-green-600/40 transition-colors"
                  >
                    <ExternalLink size={15} /> Open Live Sandbox Session
                  </a>

                  <div className="grid grid-cols-3 gap-2 text-xs text-slate-500">
                    <div className="flex items-center gap-1">
                      <span className="text-green-500">●</span> TigerVNC running
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-green-500">●</span> noVNC streaming
                    </div>
                    <div className="flex items-center gap-1">
                      <span className="text-green-500">●</span> tcpdump logging
                    </div>
                  </div>
                  <p className="text-[11px] text-slate-600">
                    Connection: <code className="font-mono">{session.streaming_url}</code>
                  </p>
                </div>

                <p className="text-xs text-slate-500">
                  ⚠️ Isolated environment — no access to production systems. All network activity
                  is logged and uploaded to S3 when session ends.
                </p>
              </div>
            )}

            {session && session.status === 'terminated' && (
              <div className="rounded-lg bg-slate-800/40 border border-slate-700/30 p-4 text-center">
                <p className="text-sm text-slate-300 font-medium mb-1">Session terminated</p>
                <p className="text-xs text-slate-500 mb-3">EC2 instance destroyed. Activity logs saved.</p>
                <button
                  onClick={() => setSession(null)}
                  className="px-4 py-1.5 rounded text-xs bg-[#3b6ef6]/20 text-[#3b6ef6] border border-[#3b6ef6]/30 hover:bg-[#3b6ef6]/30 transition-colors"
                >
                  Launch New Session
                </button>
              </div>
            )}

            {session && session.status === 'error' && (
              <div className="rounded-lg bg-red-900/20 border border-red-700/30 p-4">
                <p className="text-xs text-red-400 font-semibold mb-1.5">Session launch failed</p>
                {session.message?.includes('AccessDenied') ? (
                  <div className="space-y-2">
                    <p className="text-xs text-red-300">
                      AWS AccessDeniedException — the backend IAM role lacks ECS permissions.
                    </p>
                    <div className="bg-black/30 rounded p-2.5 text-[11px] font-mono text-slate-400 space-y-0.5">
                      <div>Required: <span className="text-amber-300">ecs:RunTask</span></div>
                      <div>Required: <span className="text-amber-300">iam:PassRole</span> (on task execution role)</div>
                      <div>Cluster: <span className="text-slate-300">himaya</span></div>
                    </div>
                    <p className="text-[11px] text-slate-500 leading-relaxed">
                      Attach <code className="bg-black/20 px-0.5 rounded">AmazonECSTaskExecutionRolePolicy</code> to the backend task role and ensure <code className="bg-black/20 px-0.5 rounded">iam:PassRole</code> is granted for the sandbox task execution role.
                    </p>
                  </div>
                ) : (
                  <p className="text-xs text-red-300">{session.message || 'Session failed to start'}</p>
                )}
                <button onClick={() => setSession(null)} className="text-xs text-red-400 hover:underline mt-3">Try again</button>
              </div>
            )}
          </div>
        )}

        {activeTab === 'auto' && state === 'done' && result && expanded && cfg && (
          <div className="space-y-4">
            {/* Verdict */}
            <div className={clsx('flex items-center justify-between p-3 rounded-lg border', cfg.bg)}>
              <div className="flex items-center gap-2">
                <cfg.icon size={18} className={cfg.color} />
                <span className={clsx('font-bold text-sm', cfg.color)}>{result.verdict}</span>
              </div>
              <div className="text-right">
                <div className="text-xs text-slate-400">Risk Score</div>
                <div className={clsx('text-2xl font-bold', cfg.color)}>{result.risk_score}</div>
              </div>
              <div className="text-right">
                <div className="text-xs text-slate-400">Confidence</div>
                <div className="text-sm font-semibold text-slate-200">{Math.round(result.confidence * 100)}%</div>
              </div>
            </div>

            {/* URL screenshots from this analysis */}
            {result.url_screenshots && result.url_screenshots.length > 0 && (
              <div>
                <p className="text-xs text-slate-400 font-medium mb-2">URL Detonation — Browser Screenshots</p>
                <div className="space-y-2">
                  {result.url_screenshots.map((s, i) => <ScreenshotCard key={i} s={s} />)}
                </div>
              </div>
            )}

            {/* Behaviour summary */}
            <div>
              <div className="text-xs font-semibold text-slate-400 uppercase mb-1">Behaviour Summary</div>
              <p className="text-sm text-slate-300 leading-relaxed">{result.behavior_summary_en}</p>
            </div>

            {/* Flags */}
            <div className="flex flex-wrap gap-2">
              {result.network_activity && (
                <span className="px-2 py-1 text-xs rounded bg-orange-900/30 text-orange-300 border border-orange-700/30">
                  Network Activity
                </span>
              )}
              {result.persistence_attempted && (
                <span className="px-2 py-1 text-xs rounded bg-red-900/30 text-red-300 border border-red-700/30">
                  Persistence Attempted
                </span>
              )}
              {result.data_exfiltration_attempted && (
                <span className="px-2 py-1 text-xs rounded bg-purple-900/30 text-purple-300 border border-purple-700/30">
                  Exfiltration Attempted
                </span>
              )}
            </div>

            {/* MITRE */}
            {result.mitre_techniques?.length > 0 && (
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase mb-2">MITRE ATT&CK</div>
                <div className="flex flex-wrap gap-2">
                  {result.mitre_techniques.map(t => (
                    <a key={t}
                      href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                      target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-blue-900/30 text-blue-300 border border-blue-700/30 hover:bg-blue-900/50 transition-colors"
                    >
                      {t} <ExternalLink size={10} />
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* IOCs */}
            {(result.iocs?.ips?.length > 0 || result.iocs?.domains?.length > 0 || result.iocs?.urls?.length > 0) && (
              <div>
                <div className="text-xs font-semibold text-slate-400 uppercase mb-2">Indicators of Compromise</div>
                <div className="space-y-1.5">
                  {[['IPs', result.iocs.ips, 'text-red-300'], ['Domains', result.iocs.domains, 'text-amber-300'], ['URLs', result.iocs.urls, 'text-orange-300']].map(([label, items, cls]) =>
                    (items as string[]).length > 0 && (
                      <div key={label as string}>
                        <span className="text-xs text-slate-500 mr-2">{label as string}:</span>
                        {(items as string[]).map(v => (
                          <span key={v} className={clsx('text-xs font-mono mr-2 break-all', cls as string)}>{v}</span>
                        ))}
                      </div>
                    )
                  )}
                </div>
              </div>
            )}

            <div className="text-xs text-slate-600 border-t border-[#0f3460]/20 pt-2">
              Analysed {result.analyzed_at ? new Date(result.analyzed_at).toLocaleString() : 'recently'} · isolated browser terminated
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
