import { useState } from 'react'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import { Badge } from '@/components/ui/Badge'
import {
  ChevronDown, ChevronUp, CheckCircle2, AlertTriangle, XCircle, Info,
  Sparkles, Activity, Shield, Mail, AlertCircle,
} from 'lucide-react'
import type { ComplianceControl } from '@/lib/types'

// Extended shape returned by the upgraded /api/compliance/controls endpoint
interface EvidenceSummary {
  integrations_active?: string[]
  policies_active?: number
  threats_90d?: number
  quarantined_90d?: number
  avg_risk_score?: number
  threats_by_type?: Record<string, number>
  assessed_at?: string
}

interface ControlWithExtras extends ComplianceControl {
  notes?: string
  description_en?: string
  description_ar?: string
  rationale?: string | null
  evidence_summary?: EvidenceSummary | null
  last_assessed_at?: string | null
}

interface Props { controls: ControlWithExtras[] }

function statusVariant(s: string) {
  if (s === 'compliant') return 'success'
  if (s === 'partial') return 'warning'
  if (s === 'non_compliant') return 'danger'
  return 'neutral'
}

function statusIcon(s: string) {
  if (s === 'compliant') return <CheckCircle2 size={14} className="text-emerald-400" />
  if (s === 'partial') return <AlertTriangle size={14} className="text-amber-400" />
  if (s === 'non_compliant') return <XCircle size={14} className="text-red-400" />
  return <Info size={14} className="text-slate-400" />
}

// Fallback rationale only used when the backend hasn't filled `rationale` yet
// (e.g. legacy data from before this migration). The backend now writes a
// real, signal-grounded explanation during /api/compliance/assess.
function fallbackExplanation(control: ControlWithExtras): string {
  const controlName =
    (control as { control_name_en?: string }).control_name_en ?? control.name_en ?? control.control_id
  if (control.status === 'compliant') {
    return `Control "${controlName}" is met by current Helios monitoring.`
  }
  if (control.status === 'partial') {
    return `Control "${controlName}" is partially implemented. Run "Assess Now" to refresh evidence.`
  }
  if (control.status === 'non_compliant') {
    return `Control "${controlName}" is not currently met. ${control.notes || 'Review remediation steps below.'}`
  }
  return control.notes || 'Click "Assess Now" to evaluate this control against your live evidence.'
}

// Remediation hints — kept locally because they don't depend on tenant data.
function generateRemediation(control: ControlWithExtras): string[] {
  if (control.status === 'compliant') {
    return ['Keep monitoring; archive evidence on each report run.']
  }
  const controlId = control.control_id.toLowerCase()
  const ev = (control as any).evidence_type as string | undefined

  if (controlId.includes('mfa') || controlId.includes('auth') || ev === 'authentication') {
    return [
      'Enable MFA for all users in Entra ID → Security → MFA',
      'Configure Conditional Access to require MFA',
      'Move service accounts to certificate or managed-identity auth',
    ]
  }
  if (controlId.includes('encrypt') || controlId.includes('crypto') || ev === 'data_protection') {
    return [
      'Confirm TLS 1.2+ is enforced on Exchange Online connectors',
      'Enable Microsoft Purview Message Encryption (OME)',
      'Apply sensitivity labels with encryption for confidential content',
    ]
  }
  if (controlId.includes('access') || controlId.includes('rbac') || ev === 'access_control') {
    return [
      'Review admin role assignments in Entra ID',
      'Enable Privileged Identity Management (PIM) for admin roles',
      'Enforce least-privilege on shared-mailbox delegations',
    ]
  }
  if (controlId.includes('log') || controlId.includes('audit') || ev === 'monitoring') {
    return [
      'Enable unified audit logging in M365 Compliance Center',
      'Set audit retention to at least 90 days',
      'Forward audit log to SIEM (Sentinel / Splunk)',
    ]
  }
  if (controlId.includes('dlp') || ev === 'data_protection') {
    return [
      'Create DLP policy in Microsoft Purview covering email + Teams + SharePoint',
      'Add sensitive-info types relevant to your region (PII, PHI, payment)',
      'Turn on policy tips so users see DLP blocks at compose time',
    ]
  }
  if (ev === 'incident_response') {
    return [
      'Create a quarantine policy in Helios → Policies',
      'Define an escalation path in Settings → Notifications',
      'Run a tabletop exercise quarterly and log it in the evidence pack',
    ]
  }
  if (ev === 'risk_management') {
    return [
      'Activate at least 2 active risk policies (phishing + DLP minimum)',
      'Review policy hit counts weekly in the Policies tab',
    ]
  }
  if (ev === 'training') {
    return [
      'Procure a security-awareness training platform (KnowBe4, Hoxhunt, Curricula)',
      'Run quarterly simulated phishing campaigns',
      'Track completion rate per employee',
    ]
  }
  return [
    'Review the control description in the framework documentation',
    'Implement the missing technical controls in the M365 admin center',
    'Re-run "Assess Now" to refresh the score',
  ]
}

// Tiny stat tile used inside the per-control evidence panel.
function SignalTile({ icon, label, value, tone }: {
  icon: React.ReactNode
  label: string
  value: string | number
  tone?: 'emerald' | 'amber' | 'red' | 'slate'
}) {
  const toneCls = {
    emerald: 'text-emerald-300 border-emerald-700/30 bg-emerald-900/10',
    amber:   'text-amber-300   border-amber-700/30   bg-amber-900/10',
    red:     'text-red-300     border-red-700/30     bg-red-900/10',
    slate:   'text-slate-300   border-white/[0.08]   bg-white/[0.02]',
  }[tone ?? 'slate']
  return (
    <div className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-[11px] ${toneCls}`}>
      <span className="opacity-80">{icon}</span>
      <span className="text-slate-400">{label}</span>
      <span className="font-semibold ml-auto">{value}</span>
    </div>
  )
}

function formatWhen(iso?: string | null): string {
  if (!iso) return 'never'
  try {
    const d = new Date(iso)
    const ago = Date.now() - d.getTime()
    if (ago < 60_000) return 'just now'
    if (ago < 3_600_000) return `${Math.round(ago / 60_000)} min ago`
    if (ago < 86_400_000) return `${Math.round(ago / 3_600_000)} h ago`
    return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
  } catch {
    return iso
  }
}

export default function ControlsTable({ controls }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null)
  const hasNameAr = controls.some(c => c.name_ar && c.name_ar.trim())

  return (
    <div className="overflow-x-auto">
      <Table>
        <Thead>
          <Tr>
            <Th className="w-8"></Th>
            <Th>Control ID</Th>
            <Th>Control Name</Th>
            {hasNameAr && <Th>Name (AR)</Th>}
            <Th>Status</Th>
            <Th>Last Assessed</Th>
            <Th>Evidence</Th>
          </Tr>
        </Thead>
        <Tbody>
          {controls.map(c => {
            const isExpanded = expanded === c.id
            const controlName =
              (c as { control_name_en?: string }).control_name_en ?? c.name_en ?? c.control_id
            const rationale = (c.rationale && c.rationale.trim()) || fallbackExplanation(c)
            const ev = c.evidence_summary || {}
            const integrations = ev.integrations_active ?? []
            const colSpanWide = (hasNameAr ? 7 : 6)

            return (
              <>
                <Tr
                  key={c.id}
                  className="cursor-pointer hover:bg-white/[0.02] transition-colors"
                  onClick={() => setExpanded(isExpanded ? null : c.id)}
                >
                  <Td className="w-8">
                    {isExpanded
                      ? <ChevronUp size={14} className="text-slate-400" />
                      : <ChevronDown size={14} className="text-slate-400" />
                    }
                  </Td>
                  <Td className="font-mono text-xs text-slate-400">{c.control_id}</Td>
                  <Td className="text-sm">{controlName}</Td>
                  {hasNameAr && <Td className="text-sm text-right" dir="rtl">{c.name_ar}</Td>}
                  <Td>
                    <div className="flex items-center gap-1.5">
                      {statusIcon(c.status)}
                      <Badge variant={statusVariant(c.status)}>{c.status.replace('_', ' ')}</Badge>
                    </div>
                  </Td>
                  <Td className="text-xs text-slate-500">{formatWhen(c.last_assessed_at)}</Td>
                  <Td className="text-xs text-slate-400">{c.evidence_count || 0} items</Td>
                </Tr>

                {/* Expanded detail row */}
                {isExpanded && (
                  <Tr key={`${c.id}-detail`}>
                    <Td colSpan={colSpanWide} className="bg-white/[0.02] border-t-0">
                      <div className="p-4 space-y-4">
                        {/* Description (if backend supplied one) */}
                        {c.description_en && (
                          <div className="text-[12px] text-slate-400 leading-relaxed border-l-2 border-slate-700 pl-3">
                            {c.description_en}
                          </div>
                        )}

                        {/* Backend rationale — the source of truth */}
                        <div className="flex items-start gap-2">
                          <Sparkles size={14} className="text-[#3b6ef6] mt-0.5 flex-shrink-0" />
                          <div className="flex-1">
                            <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-1">
                              Why this score
                            </div>
                            <p className="text-[13px] text-slate-300 leading-relaxed">
                              {rationale}
                            </p>
                          </div>
                        </div>

                        {/* Live signals from the backend evidence_summary */}
                        {c.evidence_summary && (
                          <div className="pt-2 border-t border-white/[0.05]">
                            <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-2 flex items-center gap-1.5">
                              <Activity size={11} /> Live Evidence Signals
                            </div>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                              <SignalTile
                                icon={<Shield size={11} />}
                                label="Integrations"
                                value={integrations.length ? integrations.join(', ') : 'none'}
                                tone={integrations.length ? 'emerald' : 'red'}
                              />
                              <SignalTile
                                icon={<Mail size={11} />}
                                label="Emails (90d)"
                                value={ev.threats_90d ?? 0}
                                tone="slate"
                              />
                              <SignalTile
                                icon={<AlertCircle size={11} />}
                                label="Quarantined"
                                value={ev.quarantined_90d ?? 0}
                                tone={(ev.quarantined_90d ?? 0) > 0 ? 'amber' : 'slate'}
                              />
                              <SignalTile
                                icon={<Shield size={11} />}
                                label="Active policies"
                                value={ev.policies_active ?? 0}
                                tone={(ev.policies_active ?? 0) > 0 ? 'emerald' : 'red'}
                              />
                            </div>
                          </div>
                        )}

                        {/* Remediation steps (only for non-compliant/partial) */}
                        {c.status !== 'compliant' && (
                          <div className="flex items-start gap-2 pt-2 border-t border-white/[0.05]">
                            <Info size={14} className="text-amber-400 mt-0.5 flex-shrink-0" />
                            <div>
                              <div className="text-[11px] uppercase tracking-wider text-slate-500 font-semibold mb-2">
                                Recommended Actions
                              </div>
                              <ol className="list-decimal list-inside space-y-1.5">
                                {generateRemediation(c).map((step, i) => (
                                  <li key={i} className="text-[12px] text-slate-400">{step}</li>
                                ))}
                              </ol>
                            </div>
                          </div>
                        )}
                      </div>
                    </Td>
                  </Tr>
                )}
              </>
            )
          })}
          {controls.length === 0 && (
            <Tr><Td colSpan={(hasNameAr ? 7 : 6)} className="text-center text-slate-500 py-8">No controls data</Td></Tr>
          )}
        </Tbody>
      </Table>
    </div>
  )
}
