'use client'
import { useState } from 'react'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { SeverityBadge, StatusBadge, TypeBadge } from './ThreatBadge'
import Button from '@/components/ui/Button'
import type { Threat } from '@/lib/types'
import { format, formatDistanceToNow } from 'date-fns'
import { Shield, CheckCircle, XCircle, BrainCircuit, Clock, Link2, Paperclip, AlertTriangle, ShieldCheck, Globe, Mail, Server, Info, Tag } from 'lucide-react'
import api from '@/lib/api'
import { useRouter } from 'next/navigation'
import SandboxPanel from './SandboxPanel'
import { clsx } from 'clsx'

/** Defang a URL for safe display: https://evil.com → hxxps://evil[.]com */
function defang(url: string): string {
  return url
    .replace(/^https/i, 'hxxps')
    .replace(/^http/i, 'hxxp')
    .replace(/\./g, '[.]')
}

/** Extract URLs and attachments from threat_indicators */
function extractArtifacts(threat: Threat) {
  const indicators = (threat as any).threat_indicators ?? {}
  const contentIndicators: string[] = indicators.content ?? []
  const urls: { url: string; vt_hits?: number; suspicious?: boolean; malicious?: boolean }[] = []
  const attachments: { name: string; dangerous?: boolean }[] = []

  // Pull from score_breakdown or nested link_result if available
  const scoreBreakdown = (threat as any).score_breakdown ?? {}

  // Parse indicator strings like "suspicious_urls:3", "malicious_urls_detected:2", "dangerous_attachment:file.exe"
  for (const ind of contentIndicators) {
    if (typeof ind !== 'string') continue
    if (ind.startsWith('dangerous_attachment:')) {
      const names = ind.replace('dangerous_attachment:', '').split(',')
      names.forEach(n => attachments.push({ name: n.trim(), dangerous: true }))
    }
  }

  // Pull actual URL lists — stored in score_breakdown and also surfaced at top level
  const sbContent = scoreBreakdown ?? {}
  const suspiciousUrls: string[] = (threat as any).suspicious_urls ?? sbContent.suspicious_urls ?? []
  const maliciousUrls: string[] = (threat as any).malicious_urls ?? sbContent.malicious_urls ?? []
  // Attachment names from top-level field
  const sbAttachments: string[] = (threat as any).suspicious_attachments ?? sbContent.suspicious_attachments ?? []
  sbAttachments.forEach(n => { if (!attachments.find(a => a.name === n)) attachments.push({ name: n, dangerous: true }) })
  maliciousUrls.forEach(u => urls.push({ url: u, malicious: true }))
  suspiciousUrls.filter(u => !maliciousUrls.includes(u)).forEach(u => urls.push({ url: u, suspicious: true }))

  return { urls, attachments }
}

interface Props { threat: Threat }

function ScoreBar({ label, value }: { label: string; value: number }) {
  // Scores may come as 0-100 integers or 0-1 floats — normalise to 0-100
  const pct = Math.min(100, Math.round(value > 1 ? value : value * 100))
  const color = pct >= 80 ? 'bg-red-500' : pct >= 60 ? 'bg-amber-500' : 'bg-blue-500'
  return (
    <div>
      <div className="flex justify-between text-xs text-slate-400 mb-1">
        <span>{label}</span><span>{pct}</span>
      </div>
      <div className="h-2 bg-[#0f3460]/40 rounded-full">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

export default function ThreatDetail({ threat }: Props) {
  const router = useRouter()
  const [loading, setLoading] = useState<string | null>(null)
  const [status, setStatus] = useState(threat.status)

  const doAction = async (action: string, newStatus: typeof threat.status) => {
    setLoading(action)
    try {
      await api.post(`/api/threats/${threat.id}/${action}`)
      setStatus(newStatus)
    } catch {}
    setLoading(null)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <TypeBadge type={threat.type} />
            <SeverityBadge severity={threat.severity} />
            <StatusBadge status={status} />
          </div>
          <h1 className="text-xl font-bold text-white">{threat.subject || 'No Subject'}</h1>
          <div className="text-sm text-slate-400 mt-1">
            From <span className="text-slate-300">{threat.sender}</span> → <span className="text-slate-300">{threat.recipient}</span>
          </div>
          <div className="text-xs text-slate-500 mt-0.5">
            {threat.received_at ? formatDistanceToNow(new Date(threat.received_at), { addSuffix: true }) : ''}
          </div>
        </div>
        <div className="flex gap-2">
          {/* Quarantine: disabled if already quarantined or blocked */}
          <Button
            size="sm" variant="secondary"
            loading={loading === 'quarantine'}
            disabled={['quarantined','QUARANTINED','BLOCK_DELETE','blocked'].includes(status ?? '')}
            onClick={() => doAction('quarantine', 'quarantined')}
            title={['quarantined','QUARANTINED','BLOCK_DELETE','blocked'].includes(status ?? '') ? 'Already quarantined' : 'Move to quarantine'}
          >
            <Shield size={13} /> Quarantine
          </Button>
          {/* Release: disabled if already released/clean/false-positive */}
          <Button
            size="sm" variant="ghost"
            loading={loading === 'release'}
            disabled={['released','CLEAN','false_positive','FALSE_POSITIVE'].includes(status ?? '')}
            onClick={() => doAction('release', 'released')}
            title={['released','CLEAN'].includes(status ?? '') ? 'Already released' : 'Release to inbox'}
          >
            <CheckCircle size={13} /> Release
          </Button>
          {/* False Positive: disabled if already marked */}
          <Button
            size="sm" variant="ghost"
            loading={loading === 'false-positive'}
            disabled={['false_positive','FALSE_POSITIVE'].includes(status ?? '')}
            onClick={() => doAction('false-positive', 'false_positive')}
            title={['false_positive','FALSE_POSITIVE'].includes(status ?? '') ? 'Already marked as false positive' : 'Mark as false positive'}
          >
            <XCircle size={13} /> False Positive
          </Button>
        </div>
      </div>

      {/* Email Details Row */}
      {(() => {
        const anyThreat = threat as any
        const authResults = anyThreat.auth_results ?? {}
        const messageId = anyThreat.message_id ?? null
        const senderIp = authResults.sender_ip ?? null
        const hasAuth = Object.keys(authResults).length > 0
        const { urls, attachments } = extractArtifacts(threat)
        const hasDetails = hasAuth || messageId || senderIp || urls.length > 0 || attachments.length > 0

        if (!hasDetails) return null
        return (
          <div className="grid grid-cols-2 gap-4">
            {/* Email Header Info */}
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2"><Mail size={14} className="text-slate-400" /> Email Headers</CardTitle></CardHeader>
              <div className="space-y-3">
                {messageId && (
                  <div>
                    <span className="text-xs text-slate-500 block mb-0.5">Message-ID</span>
                    <code className="text-xs font-mono text-slate-300 break-all">{messageId}</code>
                  </div>
                )}
                {senderIp && (
                  <div className="flex items-center gap-2">
                    <Server size={12} className="text-slate-500 flex-shrink-0" />
                    <span className="text-xs text-slate-500">Sender IP:</span>
                    <code className="text-xs font-mono text-slate-300">{senderIp}</code>
                  </div>
                )}
                {hasAuth && (
                  <div>
                    <span className="text-xs text-slate-500 block mb-2">Authentication</span>
                    <div className="grid grid-cols-3 gap-2">
                      {(['spf', 'dkim', 'dmarc'] as const).map(proto => {
                        const val = authResults[proto] ?? 'N/A'
                        const isPass = val === 'pass'
                        const isFail = val === 'fail' || val === 'softfail'
                        return (
                          <div key={proto} className={clsx(
                            'rounded-lg p-2 border flex flex-col items-center gap-1',
                            isPass ? 'bg-green-900/20 border-green-700/40' :
                            isFail ? 'bg-red-900/20 border-red-700/40' : 'bg-slate-800/40 border-slate-700/40'
                          )}>
                            <span className="text-[10px] text-slate-400 font-semibold uppercase tracking-widest">{proto}</span>
                            <span className={clsx('text-xs font-bold uppercase',
                              isPass ? 'text-green-400' : isFail ? 'text-red-400' : 'text-slate-500'
                            )}>{val}</span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            </Card>

            {/* Links & Attachments */}
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2"><Info size={14} className="text-slate-400" /> Links & Attachments</CardTitle></CardHeader>
              <div className="space-y-3">
                {urls.length > 0 ? (
                  <div>
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 mb-2">
                      <Link2 size={11} /> URLs ({urls.length})
                    </div>
                    <div className="space-y-1.5 max-h-32 overflow-y-auto pr-1">
                      {urls.map((u, i) => (
                        <div key={i} className="flex items-start gap-1.5">
                          {u.malicious
                            ? <AlertTriangle size={11} className="text-red-400 mt-0.5 flex-shrink-0" />
                            : <ShieldCheck size={11} className="text-amber-400 mt-0.5 flex-shrink-0" />
                          }
                          <code className={clsx('text-xs font-mono break-all leading-snug', u.malicious ? 'text-red-300' : 'text-amber-300')}>
                            {defang(u.url)}
                          </code>
                          {u.malicious && (
                            <span className="flex-shrink-0 text-[9px] px-1 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40">VT:malicious</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 italic">No URLs extracted</p>
                )}
                {attachments.length > 0 && (
                  <div className="border-t border-[#0f3460]/30 pt-3">
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 mb-2">
                      <Paperclip size={11} /> Attachments ({attachments.length})
                    </div>
                    <div className="space-y-1">
                      {attachments.map((a, i) => (
                        <div key={i} className="flex items-center gap-1.5">
                          <AlertTriangle size={11} className="text-red-400 flex-shrink-0" />
                          <code className="text-xs font-mono text-red-300">{a.name}</code>
                          {a.dangerous && (
                            <span className="text-[9px] px-1 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40">dangerous</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </Card>
          </div>
        )
      })()}

      {/* Email Body Preview */}
      {(threat as any).email_body_preview && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Mail size={14} className="text-slate-400" /> Email Body Preview
            </CardTitle>
          </CardHeader>
          <div className="bg-[#060d1a] border border-[#0f3460]/40 rounded-lg p-4">
            <pre className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap font-sans break-words max-h-64 overflow-y-auto">
              {(threat as any).email_body_preview}
            </pre>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-3 gap-4">
        {/* AI Explanation */}
        <Card className="col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><BrainCircuit size={16} className="text-[#e94560]" /> AI Analysis</CardTitle>
          </CardHeader>
          <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap">{threat.ai_explanation_en || 'No AI explanation available.'}</p>

          {/* URLs + Attachments extracted from this email */}
          {(() => {
            const { urls, attachments } = extractArtifacts(threat)
            if (urls.length === 0 && attachments.length === 0) return null
            return (
              <div className="mt-4 pt-4 border-t border-[#0f3460]/40 space-y-3">
                {urls.length > 0 && (
                  <div>
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 mb-2">
                      <Link2 size={12} /> URLs extracted ({urls.length})
                    </div>
                    <div className="space-y-1">
                      {urls.map((u, i) => (
                        <div key={i} className="flex items-start gap-2 group">
                          {u.malicious
                            ? <AlertTriangle size={12} className="text-red-400 mt-0.5 flex-shrink-0" />
                            : <ShieldCheck size={12} className="text-amber-400 mt-0.5 flex-shrink-0" />
                          }
                          <code className={`text-xs font-mono break-all leading-relaxed ${u.malicious ? 'text-red-300' : 'text-amber-300'}`}>
                            {defang(u.url)}
                          </code>
                          {u.malicious && (
                            <span className="flex-shrink-0 text-[10px] px-1.5 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40">
                              VT: malicious
                            </span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {attachments.length > 0 && (
                  <div>
                    <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 mb-2">
                      <Paperclip size={12} /> Attachments ({attachments.length})
                    </div>
                    <div className="space-y-2">
                      {attachments.map((a, i) => {
                        const ext = a.name.split('.').pop()?.toLowerCase() ?? ''
                        const isMacro = ['doc','docx','xls','xlsx','ppt','pptx','xlsm','docm'].includes(ext)
                        const isExe = ['exe','bat','ps1','sh','vbs','hta','cmd','com'].includes(ext)
                        return (
                          <div key={i} className="border border-red-700/30 rounded-lg p-2.5 bg-red-900/10">
                            <div className="flex items-center gap-2">
                              <Paperclip size={12} className="text-red-400 flex-shrink-0" />
                              <code className="text-xs font-mono text-red-300 flex-1 break-all">{a.name}</code>
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/50 text-red-300 border border-red-700/40 shrink-0">
                                {isExe ? '⚠ executable' : isMacro ? '⚠ macro-capable' : 'attachment'}
                              </span>
                            </div>
                            <div className="mt-1 text-[10px] text-slate-500">
                              {isExe ? 'Cannot preview — open in Sandbox to observe behaviour safely' :
                               isMacro ? 'Office macro file — open in Sandbox to check for malicious macros' :
                               'Open in Sandbox to inspect in an isolated environment'}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )
          })()}
        </Card>

        {/* Score Breakdown */}
        <Card>
          <CardHeader><CardTitle>Score Breakdown</CardTitle></CardHeader>
          <div className="space-y-4">
            <ScoreBar label="Graph Score" value={threat.graph_score ?? 0} />
            <ScoreBar label="Content Score" value={threat.content_score ?? 0} />
            <ScoreBar label="Reputation Score" value={threat.reputation_score ?? 0} />
            <div className="pt-2 border-t border-[#0f3460]/30">
              <ScoreBar label="Overall Score" value={threat.overall_score ?? 0} />
            </div>
          </div>
        </Card>
      </div>

      {/* Threat Indicator Pills — derived from live auth_results + threat_indicators */}
      {(() => {
        const anyThreat = threat as any
        const authResults = anyThreat.auth_results ?? {}
        const indicators: { label: string; variant: 'danger' | 'warning' | 'pass' | 'neutral' }[] = []

        // Auth indicators — driven from auth_results (source of truth, not indicator strings)
        const authFields = [
          { key: 'spf', label: 'SPF' },
          { key: 'dkim', label: 'DKIM' },
          { key: 'dmarc', label: 'DMARC' },
        ]
        for (const { key, label } of authFields) {
          const val = authResults[key]
          if (!val || val === 'none' || val === 'N/A') continue
          if (val === 'pass') indicators.push({ label: `${label}: Pass`, variant: 'pass' })
          else if (val === 'fail') indicators.push({ label: `${label}: Fail`, variant: 'danger' })
          else if (val === 'softfail') indicators.push({ label: `${label}: SoftFail`, variant: 'warning' })
          else indicators.push({ label: `${label}: ${val}`, variant: 'neutral' })
        }

        // Helper: turn a raw indicator string into a short pill label
        const toLabel = (ind: string): string => {
          // Take only the key part before any colon (e.g. "ceo_impersonation:Adnan Ahmed" → "ceo impersonation")
          const keyPart = ind.split(':')[0]
          const clean = keyPart.replace(/_/g, ' ').replace(/\s+/g, ' ').trim()
          // Capitalise first letter, truncate to 32 chars
          const capped = clean.charAt(0).toUpperCase() + clean.slice(1)
          return capped.length > 32 ? capped.slice(0, 30) + '…' : capped
        }

        // Content indicators
        const contentInds: string[] = (anyThreat.threat_indicators?.content ?? [])
        for (const ind of contentInds) {
          if (typeof ind !== 'string') continue
          if (/^(spf|dkim|dmarc)_/i.test(ind)) continue
          indicators.push({ label: toLabel(ind), variant: 'warning' })
        }

        // Reputation indicators
        const repInds: string[] = (anyThreat.threat_indicators?.reputation ?? [])
        for (const ind of repInds) {
          if (typeof ind !== 'string') continue
          if (/^(spf|dkim|dmarc)_/i.test(ind)) continue
          indicators.push({ label: toLabel(ind), variant: ind.includes('blacklist') || ind.includes('malicious') ? 'danger' : 'warning' })
        }

        // Graph indicators
        const graphInds: string[] = (anyThreat.threat_indicators?.graph ?? [])
        for (const ind of graphInds) {
          if (typeof ind !== 'string') continue
          indicators.push({ label: toLabel(ind), variant: 'neutral' })
        }

        if (indicators.length === 0) return null

        const variantStyles = {
          danger:  'bg-red-900/30 text-red-300 border-red-700/40',
          warning: 'bg-amber-900/20 text-amber-300 border-amber-700/30',
          pass:    'bg-green-900/20 text-green-300 border-green-700/30',
          neutral: 'bg-slate-800/60 text-slate-400 border-slate-700/30',
        }

        return (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Tag size={14} className="text-slate-400" /> Threat Indicators
              </CardTitle>
            </CardHeader>
            <div className="flex flex-wrap gap-2">
              {indicators.map((ind, i) => (
                <span
                  key={i}
                  className={`inline-flex items-center text-[11px] font-semibold px-2.5 py-1 rounded-full border uppercase tracking-wide ${variantStyles[ind.variant]}`}
                >
                  {ind.label}
                </span>
              ))}
            </div>
          </Card>
        )
      })()}

      {/* Compliance Controls */}
      {((threat.sama_controls?.length ?? 0) > 0 || (threat.nca_controls?.length ?? 0) > 0) && (
        <Card>
          <CardHeader><CardTitle>Regulatory Controls Triggered</CardTitle></CardHeader>
          <div className="flex flex-wrap gap-2">
            {threat.sama_controls?.map(c => (
              <span key={c} className="px-2 py-1 text-xs rounded bg-blue-900/40 text-blue-300 border border-blue-700/30">SAMA: {c}</span>
            ))}
            {threat.nca_controls?.map(c => (
              <span key={c} className="px-2 py-1 text-xs rounded bg-purple-900/40 text-purple-300 border border-purple-700/30">NCA: {c}</span>
            ))}
          </div>
        </Card>
      )}

      {/* Sandbox Analysis */}
      <SandboxPanel
        threatId={threat.id}
        targetUrl={(threat as any).indicators?.find((i: any) => i.type === 'url')?.value}
      />

      {/* Timeline */}
      {threat.timeline?.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="flex items-center gap-2"><Clock size={15} /> Event Timeline</CardTitle></CardHeader>
          <div className="space-y-3">
            {threat.timeline.map((ev, i) => (
              <div key={i} className="flex gap-3 text-sm">
                <div className="text-xs text-slate-500 whitespace-nowrap pt-0.5 w-32 flex-shrink-0">
                  {ev.timestamp ? formatDistanceToNow(new Date(ev.timestamp), { addSuffix: true }) : ''}
                </div>
                <div>
                  <span className="font-medium text-slate-200">{ev.action}</span>
                  {ev.actor && <span className="text-slate-500"> by {ev.actor}</span>}
                  {ev.details && <div className="text-xs text-slate-500 mt-0.5">{ev.details}</div>}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
