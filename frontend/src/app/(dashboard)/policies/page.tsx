'use client'
import { useEffect, useState } from 'react'
import { Badge } from '@/components/ui/Badge'
import Button from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import Input from '@/components/ui/Input'
import api from '@/lib/api'
import { Plus, Layers, Play, Pause, Zap, CheckCircle2, AlertTriangle, Info, Pencil, Trash2, Globe, ShieldCheck, Scale, Building2, ClipboardList } from 'lucide-react'
import { toast } from '@/components/ui/Toast'

// ─── Shared style constants (module-level — no re-creation on render) ─────────
const _labelClass = 'block text-[12px] font-medium text-[#71717a] mb-1'
const _inputClass = 'w-full bg-[#1e1e24] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] text-[#e4e4e7] focus:outline-none focus:border-[#3b6ef6]/50'
const _selectClass = `${_inputClass} cursor-pointer`

interface Policy {
  id: string
  name: string
  description?: string
  priority: number
  status: string
  action: string
  conditions: Record<string, unknown>
  action_config?: Record<string, unknown>
  hit_count?: number
}

interface ApiTemplate {
  id: string
  name: string
  description: string
  action: string
  conditions: Record<string, unknown>
  action_config?: Record<string, unknown>
  frameworks?: string[]
}

const ACTIONS = [
  { value: 'BLOCK',      label: 'Block',      desc: 'Send to trash, alert admin + recipient + sender' },
  { value: 'QUARANTINE', label: 'Quarantine', desc: 'Move to Himaya-Quarantine, alert admin + recipient' },
  { value: 'ALERT',      label: 'Alert',      desc: 'Deliver but flag and alert admin' },
  { value: 'TAG',        label: 'Tag',        desc: 'Add warning banner, deliver normally' },
  { value: 'ALLOW',      label: 'Allow',      desc: 'Always allow — bypass AI detection' },
]

const THREAT_TYPES = [
  'BEC',                 // Business Email Compromise
  'VEC',                 // Vendor/Supplier Email Compromise
  'PHISHING',            // Generic credential harvesting / fake login
  'CREDENTIAL_HARVESTING', // Dedicated credential theft (VPN, portal)
  'GOV_IMPERSONATION',   // Fake government entity (ZATCA, GOSI, MoF)
  'IMPERSONATION',       // Executive / colleague display-name spoof
  'MALWARE',             // Malicious attachments or malware links
  'LOOKALIKE_DOMAIN',    // Typosquat / lookalike domain
  'ACCOUNT_TAKEOVER',    // Compromised account indicators
  'SUPPLY_CHAIN',        // Supply chain / trusted-vendor abuse
  'FAKE_INVOICE',        // Fraudulent invoice / payment request
  'SOCIAL_ENGINEERING',  // Broad social manipulation
  'SPAM',                // Unsolicited bulk email
]

const ATTACHMENT_TYPE_OPTIONS = [
  { value: '.exe', label: '.exe — Executable' },
  { value: '.vbs', label: '.vbs — VBScript' },
  { value: '.js',  label: '.js — JavaScript' },
  { value: '.ps1', label: '.ps1 — PowerShell' },
  { value: '.bat', label: '.bat — Batch file' },
  { value: '.cmd', label: '.cmd — Command file' },
  { value: '.msi', label: '.msi — Installer' },
  { value: '.docm', label: '.docm — Macro-enabled Word' },
  { value: '.xlsm', label: '.xlsm — Macro-enabled Excel' },
  { value: '.pptm', label: '.pptm — Macro-enabled PowerPoint' },
  { value: '.jar',  label: '.jar — Java Archive' },
  { value: '.zip',  label: '.zip — ZIP Archive' },
  { value: '.rar',  label: '.rar — RAR Archive' },
  { value: '.pdf',  label: '.pdf — PDF Document' },
  { value: '.iso',  label: '.iso — Disk Image' },
]

// ─── Advanced Rule Parser (module-level) ─────────────────────────────────────

interface ParsedRule {
  action: string
  conditions: Record<string, unknown>
  summary: string
  error?: string
}

function parseAdvancedRule(text: string): ParsedRule | null {
  const trimmed = text.trim()
  if (!trimmed) return null

  const VALID_ACTIONS = ['BLOCK', 'QUARANTINE', 'ALERT', 'TAG', 'ALLOW']
  let action = ''
  for (const a of VALID_ACTIONS) {
    if (trimmed.toUpperCase().startsWith(a + ' ') || trimmed.toUpperCase() === a) {
      action = a
      break
    }
  }
  if (!action) {
    return { action: '', conditions: {}, summary: '', error: 'Rule must start with: BLOCK, QUARANTINE, ALERT, TAG, or ALLOW' }
  }

  const afterAction = trimmed.slice(action.length).trim()
  const ifMatch = afterAction.match(/^if\s+(.+)$/i)
  if (!ifMatch) {
    return { action, conditions: {}, summary: '', error: 'Expected "if" after action — e.g. BLOCK if sender is x@y.com' }
  }

  const condStr = ifMatch[1]

  // Parse a single condition token
  function parseOneCond(cond: string): { field: string; value: string | number | boolean } | null {
    const c = cond.trim()
    if (!c) return null

    // risk_score > 70 etc.
    const riskMatch = c.match(/^risk_score\s*(>=|<=|>|<)\s*(\d+)$/i)
    if (riskMatch) {
      const op = riskMatch[1]
      const val = parseInt(riskMatch[2], 10)
      if (op === '>') return { field: 'risk_score_min', value: val + 1 }
      if (op === '>=') return { field: 'risk_score_min', value: val }
      if (op === '<') return { field: 'risk_score_max', value: val - 1 }
      if (op === '<=') return { field: 'risk_score_max', value: val }
    }

    // subject contains "..."
    const subjectMatch = c.match(/^subject\s+contains\s+["']?(.+?)["']?\s*$/i)
    if (subjectMatch) {
      return { field: 'subject_contains', value: subjectMatch[1].replace(/^["']|["']$/g, '') }
    }

    // has_attachment / has_link
    if (/^has_attachment$/i.test(c)) return { field: 'has_attachment', value: true }
    if (/^has_link$/i.test(c)) return { field: 'has_link', value: true }

    // field is value
    const isMatch = c.match(/^(\w+(?:_\w+)*)\s+is\s+["']?(.+?)["']?\s*$/i)
    if (isMatch) {
      let field = isMatch[1].toLowerCase()
      const value = isMatch[2].replace(/^["']|["']$/g, '')
      // Normalize aliases
      if (field === 'sender') field = 'sender_email'
      if (field === 'recipient') field = 'recipient_email'
      return { field, value }
    }

    return null
  }

  const conditions: Record<string, unknown> = {}

  // Split by AND (AND has higher precedence — process AND groups first)
  const andParts = condStr.split(/\s+AND\s+/i)

  for (const andPart of andParts) {
    const orParts = andPart.split(/\s+OR\s+/i)

    if (orParts.length === 1) {
      const parsed = parseOneCond(orParts[0])
      if (parsed) {
        conditions[parsed.field] = parsed.value
      }
    } else {
      const parsedList = orParts
        .map(p => parseOneCond(p))
        .filter((x): x is { field: string; value: string | number | boolean } => x !== null)

      if (parsedList.length === 0) continue

      const firstField = parsedList[0].field
      const allSameField = parsedList.every(p => p.field === firstField)

      if (allSameField) {
        // Same field → store as array (OR matching)
        const values = parsedList.map(p => p.value)
        conditions[firstField] = values.length === 1 ? values[0] : values
      } else {
        // Different fields → $or
        const orConds = parsedList.map(p => ({ [p.field]: p.value }))
        const existing$or = (conditions['$or'] as Record<string, unknown>[] | undefined) ?? []
        conditions['$or'] = [...existing$or, ...orConds]
      }
    }
  }

  if (Object.keys(conditions).length === 0) {
    return { action, conditions: {}, summary: '', error: 'Could not parse any conditions — check your syntax' }
  }

  // Generate human-readable summary
  const parts: string[] = []
  for (const [k, v] of Object.entries(conditions)) {
    if (k === '$or') {
      const orParts = (v as Record<string, unknown>[]).map(c =>
        Object.entries(c).map(([k2, v2]) => `${k2}=${v2}`).join(', ')
      )
      parts.push(`(${orParts.join(' OR ')})`)
    } else if (Array.isArray(v)) {
      parts.push(`${k} in [${(v as unknown[]).join(', ')}]`)
    } else {
      parts.push(`${k}=${v}`)
    }
  }
  const summary = `${action} when: ${parts.join(' AND ')}`

  return { action, conditions, summary }
}

// ─────────────────────────────────────────────────────────────────────────────

function statusVariant(s: string): 'success' | 'info' | 'warning' | 'neutral' {
  const map: Record<string, 'success' | 'info' | 'warning' | 'neutral'> = {
    active: 'success', shadow: 'info', paused: 'warning', draft: 'neutral'
  }
  return map[s] ?? 'neutral'
}

const emptyForm = {
  name: '',
  description: '',
  priority: 100,
  action: 'QUARANTINE',
  // Conditions
  sender_email: '',
  sender_domain: '',
  recipient_email: '',
  recipient_domain: '',
  threat_type: '',
  risk_score_min: '',
  has_attachment: false,
  attachment_types: [] as string[],
  has_link: false,
  keywords: '',
  subject_contains: '',
  notify_admin: true,
}

type FormState = typeof emptyForm

// ─── PolicyFormContent — MUST live outside PoliciesPage ─────────────────────
// Defining a component function inside another component causes React to remount
// it on every parent render, which steals focus from inputs on each keystroke.
interface PolicyFormProps {
  form: FormState
  f: (k: keyof FormState, v: unknown) => void
  error: string
  saving: boolean
  isEdit: boolean
  onCancel: () => void
  onSubmit: () => void
  toggleAttachmentType: (type: string) => void
  builderTab?: 'visual' | 'advanced'
  setBuilderTab?: (tab: 'visual' | 'advanced') => void
  advancedText?: string
  setAdvancedText?: (text: string) => void
}

function PolicyFormContent({
  form, f, error, saving, isEdit, onCancel, onSubmit, toggleAttachmentType,
  builderTab, setBuilderTab, advancedText, setAdvancedText,
}: PolicyFormProps) {
  const isAdvanced = !isEdit && builderTab === 'advanced'
  const parsed = isAdvanced ? parseAdvancedRule(advancedText || '') : null

  return (
    <div className="space-y-5">
      {/* Tab selector — only for new policy */}
      {!isEdit && (
        <div className="flex gap-1 bg-[#1a1a20] border border-white/[0.06] rounded-lg p-1">
          <button
            onClick={() => setBuilderTab?.('visual')}
            className={`flex-1 py-1.5 text-[12px] font-medium rounded-md transition-colors ${
              builderTab === 'visual'
                ? 'bg-[#3b6ef6] text-white shadow'
                : 'text-[#71717a] hover:text-[#a1a1aa]'
            }`}
          >
            Visual Builder
          </button>
          <button
            onClick={() => setBuilderTab?.('advanced')}
            className={`flex-1 py-1.5 text-[12px] font-medium rounded-md transition-colors ${
              builderTab === 'advanced'
                ? 'bg-[#3b6ef6] text-white shadow'
                : 'text-[#71717a] hover:text-[#a1a1aa]'
            }`}
          >
            Advanced Builder
          </button>
        </div>
      )}

      {/* Common fields — always shown */}
      <div className="grid grid-cols-2 gap-4">
        <div className="col-span-2">
          <Input label="Policy Name *" value={form.name} onChange={e => f('name', e.target.value)} placeholder="e.g. Block external BEC attempts" />
        </div>
        <div className="col-span-2">
          <label className={_labelClass}>Description</label>
          <input className={_inputClass} value={form.description} onChange={e => f('description', e.target.value)} placeholder="What does this policy do?" />
        </div>
        <div>
          <label className={_labelClass}>Priority (lower = first)</label>
          <input type="number" className={_inputClass} value={form.priority} onChange={e => f('priority', e.target.value)} min={1} max={999} />
        </div>
        {/* Action selector only in visual mode (advanced mode derives action from rule text) */}
        {(isEdit || builderTab === 'visual') && (
          <div>
            <label className={_labelClass}>Action *</label>
            <select className={_selectClass} value={form.action} onChange={e => f('action', e.target.value)}>
              {ACTIONS.map(a => <option key={a.value} value={a.value}>{a.label} — {a.desc}</option>)}
            </select>
          </div>
        )}
      </div>

      {/* ── Advanced Builder ── */}
      {isAdvanced ? (
        <div className="space-y-3">
          <div className="border-t border-white/[0.06] pt-4">
            <p className="text-[12px] font-semibold text-[#a1a1aa] uppercase tracking-wide mb-3">
              Policy Rule
            </p>
            <textarea
              className={`${_inputClass} font-mono text-[12px] h-28 resize-none leading-relaxed`}
              value={advancedText || ''}
              onChange={e => setAdvancedText?.(e.target.value)}
              placeholder={
                'BLOCK if sender is evil@domain.com OR sender is attacker@other.com\n' +
                'QUARANTINE if threat_type is phishing AND risk_score > 70\n' +
                'ALERT if sender_domain is malicious.ru OR sender_domain is phish.xyz'
              }
              spellCheck={false}
            />
            <p className="text-[11px] text-[#52525b] mt-2">
              Syntax: <span className="text-[#71717a] font-mono">ACTION if FIELD is VALUE OR FIELD is VALUE AND risk_score &gt; N</span>
              <br />
              Fields: <span className="text-[#71717a]">sender, sender_domain, recipient, recipient_domain, threat_type, risk_score, subject contains, attachment_type, has_attachment, has_link</span>
            </p>
          </div>

          {/* Real-time parsed preview */}
          {advancedText && advancedText.trim() && (
            <div className={`rounded-lg p-3 border text-[12px] ${
              parsed?.error
                ? 'bg-red-900/10 border-red-700/30'
                : 'bg-[#1a1a20] border-white/[0.06]'
            }`}>
              {parsed?.error ? (
                <p className="text-red-400 flex items-center gap-1.5">
                  <AlertTriangle size={12} /> {parsed.error}
                </p>
              ) : parsed ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 size={12} className="text-emerald-400 flex-shrink-0" />
                    <p className="text-[#a1a1aa] font-medium">{parsed.summary}</p>
                  </div>
                  <pre className="text-[11px] text-[#71717a] bg-black/30 rounded p-2 overflow-x-auto whitespace-pre-wrap">
                    {JSON.stringify({ action: parsed.action, conditions: parsed.conditions }, null, 2)}
                  </pre>
                </div>
              ) : null}
            </div>
          )}

          {/* notify_admin for advanced mode */}
          <label className="flex items-center gap-2 text-[13px] text-[#a1a1aa] cursor-pointer">
            <input type="checkbox" checked={form.notify_admin} onChange={e => f('notify_admin', e.target.checked)} className="accent-[#3b6ef6]" />
            Notify admin on match
          </label>
        </div>
      ) : (
        /* ── Visual Builder ── */
        <div className="border-t border-white/[0.06] pt-4">
          <p className="text-[12px] font-semibold text-[#a1a1aa] uppercase tracking-wide mb-3">
            Conditions <span className="text-[#52525b] font-normal normal-case">(AND logic — leave blank to skip)</span>
          </p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={_labelClass}>Sender Email</label>
              <input className={_inputClass} value={form.sender_email} onChange={e => f('sender_email', e.target.value)} placeholder="ceo@fakecorp.com" />
            </div>
            <div>
              <label className={_labelClass}>Sender Domain</label>
              <input className={_inputClass} value={form.sender_domain} onChange={e => f('sender_domain', e.target.value)} placeholder="fakecorp.com" />
            </div>
            <div>
              <label className={_labelClass}>Recipient Email</label>
              <input className={_inputClass} value={form.recipient_email} onChange={e => f('recipient_email', e.target.value)} placeholder="cfo@yourcompany.com" />
            </div>
            <div>
              <label className={_labelClass}>Recipient Domain</label>
              <input className={_inputClass} value={form.recipient_domain} onChange={e => f('recipient_domain', e.target.value)} placeholder="yourcompany.com" />
            </div>
            <div>
              <label className={_labelClass}>Threat Type</label>
              <select className={_selectClass} value={form.threat_type} onChange={e => f('threat_type', e.target.value)}>
                <option value="">— Any —</option>
                {THREAT_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <label className={_labelClass}>Min Risk Score (0-100)</label>
              <input type="number" className={_inputClass} value={form.risk_score_min} onChange={e => f('risk_score_min', e.target.value)} placeholder="e.g. 70" min={0} max={100} />
            </div>
            <div className="col-span-2">
              <label className={_labelClass}>Subject Contains (comma-separated)</label>
              <input className={_inputClass} value={form.subject_contains} onChange={e => f('subject_contains', e.target.value)} placeholder="invoice, urgent, wire transfer" />
            </div>
            <div className="col-span-2">
              <label className={_labelClass}>Keywords — subject + body (comma-separated)</label>
              <input className={_inputClass} value={form.keywords} onChange={e => f('keywords', e.target.value)} placeholder="wire transfer, urgent payment, IBAN" />
            </div>
            <div className="col-span-2 flex flex-wrap gap-6 items-start">
              <div className="flex flex-col gap-2">
                <label className="flex items-center gap-2 text-[13px] text-[#a1a1aa] cursor-pointer">
                  <input type="checkbox" checked={form.has_attachment} onChange={e => f('has_attachment', e.target.checked)} className="accent-[#3b6ef6]" />
                  Has attachment
                </label>
                {form.has_attachment && (
                  <div className="ml-5 mt-1">
                    <p className="text-[11px] text-[#71717a] mb-1.5">Block specific types <span className="text-[#52525b]">(unchecked = any attachment)</span></p>
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 max-h-36 overflow-y-auto pr-1">
                      {ATTACHMENT_TYPE_OPTIONS.map(opt => (
                        <label key={opt.value} className="flex items-center gap-1.5 text-[12px] text-[#a1a1aa] cursor-pointer">
                          <input type="checkbox" checked={form.attachment_types.includes(opt.value)} onChange={() => toggleAttachmentType(opt.value)} className="accent-[#3b6ef6]" />
                          {opt.label}
                        </label>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              <label className="flex items-center gap-2 text-[13px] text-[#a1a1aa] cursor-pointer">
                <input type="checkbox" checked={form.has_link} onChange={e => f('has_link', e.target.checked)} className="accent-[#3b6ef6]" />
                Contains links
              </label>
              <label className="flex items-center gap-2 text-[13px] text-[#a1a1aa] cursor-pointer">
                <input type="checkbox" checked={form.notify_admin} onChange={e => f('notify_admin', e.target.checked)} className="accent-[#3b6ef6]" />
                Notify admin on match
              </label>
            </div>
          </div>
        </div>
      )}

      {error && <div className="px-3 py-2 rounded-lg bg-[#e03d4e]/10 border border-[#e03d4e]/20 text-[13px] text-[#fca5a5]">{error}</div>}

      <div className="flex gap-2 justify-end pt-1">
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button loading={saving} onClick={onSubmit}>{isEdit ? 'Save Changes' : 'Create Policy'}</Button>
      </div>
    </div>
  )
}

// ─── Action color helper (module-level) ───────────────────────────────────────
function actionBadgeClass(action: string): string {
  if (action === 'BLOCK' || action === 'BLOCK_DELETE') return 'bg-[#f87171]/10 text-[#f87171]'
  if (action === 'QUARANTINE') return 'bg-[#fb923c]/10 text-[#fb923c]'
  if (action === 'ALLOW') return 'bg-[#4ade80]/10 text-[#4ade80]'
  if (action === 'ALERT') return 'bg-[#facc15]/10 text-[#facc15]'
  return 'bg-white/[0.06] text-[#a1a1aa]'
}

// ─── TemplateCard (module-level) ─────────────────────────────────────────────
interface ExtendedTemplate extends ApiTemplate {
  live_feed?: boolean
  pack_id?: string
  _opendbl_meta?: { ip_count: number; last_refresh: number | null; label: string } | null
}

function TemplateCard({ tpl, onInstall }: { tpl: ExtendedTemplate; onInstall: (tpl: ApiTemplate) => void }) {
  const meta = tpl._opendbl_meta
  return (
    <div className={`flex items-start justify-between gap-4 p-3.5 rounded-xl border ${
      tpl.live_feed
        ? 'bg-amber-500/5 border-amber-500/20'
        : 'bg-[#1e1e24] border-white/[0.06]'
    }`}>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="text-[13px] font-medium text-[#d4d4d8]">{tpl.name}</div>
          {tpl.live_feed && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-amber-500/20 text-amber-400 font-semibold flex items-center gap-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse inline-block" />
              LIVE
            </span>
          )}
          {tpl.frameworks && tpl.frameworks.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              {tpl.frameworks.slice(0, 3).map(f => (
                <span key={f} className="text-[10px] px-1.5 py-0.5 rounded bg-[#3b6ef6]/10 text-[#93b4fd]">{f}</span>
              ))}
            </div>
          )}
        </div>
        <div className="text-[12px] text-[#71717a] mt-0.5 line-clamp-2">{tpl.description}</div>
        <div className="flex items-center gap-2 mt-1.5 flex-wrap">
          <span className={`text-[11px] font-medium inline-block px-1.5 py-0.5 rounded ${actionBadgeClass(tpl.action)}`}>
            {tpl.action}
          </span>
          {meta && meta.ip_count > 0 && (
            <span className="text-[10px] text-amber-400/70">
              {meta.ip_count.toLocaleString()} IPs cached
            </span>
          )}
          {meta && !meta.ip_count && (
            <span className="text-[10px] text-red-400/70">⚠ Not yet cached — will load at startup</span>
          )}
        </div>
      </div>
      <Button size="sm" variant="secondary" onClick={() => onInstall(tpl)}>
        Install
      </Button>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [loading, setLoading] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)
  const [templatesOpen, setTemplatesOpen] = useState(false)
  const [editPolicy, setEditPolicy] = useState<Policy | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [applying, setApplying] = useState(false)
  const [applyResult, setApplyResult] = useState<{ message: string } | null>(null)
  const [applyError, setApplyError] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)
  const [showApplyModal, setShowApplyModal] = useState(false)

  // Advanced Builder state
  const [builderTab, setBuilderTab] = useState<'visual' | 'advanced'>('visual')
  const [advancedText, setAdvancedText] = useState('')

  // Templates state
  const [templates, setTemplates] = useState<{ gulf: ApiTemplate[]; us: ApiTemplate[]; eu: ApiTemplate[]; threat_intel: ApiTemplate[] }>({
    gulf: [], us: [], eu: [], threat_intel: [],
  })
  const [templateTab, setTemplateTab] = useState<'gulf' | 'us' | 'eu' | 'threat_intel'>('gulf')
  const [opendblMeta, setOpendblMeta] = useState<Record<string, { ip_count: number; last_refresh: number | null; label: string }>>({})
  const [opendblRefreshing, setOpendblRefreshing] = useState(false)

  // CERT-CN feed state
  const [certCnMeta, setCertCnMeta] = useState<{ ips: number; urls: number; last_refresh?: number } | null>(null)
  const [certCnRefreshing, setCertCnRefreshing] = useState(false)

  // ANVA China block feed state
  const [anvaMeta, setAnvaMeta] = useState<Record<string, {
    label: string; description: string; ioc_type: string
    ioc_count: number; last_refresh: number | null; status: string; error?: string
  }>>({})
  const [anvaRefreshing, setAnvaRefreshing] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/policies')
      setPolicies(Array.isArray(r.data) ? r.data : (r.data?.items ?? []))
    } catch {}
    setLoading(false)
  }

  const loadTemplates = async () => {
    try {
      const r = await api.get('/api/policies/templates')
      setTemplates({
        gulf: r.data.gulf ?? [],
        us: r.data.us ?? [],
        eu: r.data.eu ?? [],
        threat_intel: r.data.threat_intel ?? [],
      })
    } catch {}
    // Load OpenDBL + ANVA status concurrently
    try {
      const [opendblRes, anvaRes, certCnRes] = await Promise.allSettled([
        api.get('/api/policies/opendbl/status'),
        api.get('/api/policies/anva/status'),
        api.get('/api/policies/cert-cn/status'),
      ])
      if (opendblRes.status === 'fulfilled') setOpendblMeta(opendblRes.value.data.packs ?? {})
      if (anvaRes.status === 'fulfilled') setAnvaMeta(anvaRes.value.data.packs ?? {})
      if (certCnRes.status === 'fulfilled') setCertCnMeta(certCnRes.value.data ?? null)
    } catch {}
  }

  useEffect(() => { load() }, [])
  useEffect(() => { if (templatesOpen) loadTemplates() }, [templatesOpen])

  const f = (k: keyof FormState, v: unknown) => setForm(prev => ({ ...prev, [k]: v }))

  const toggleAttachmentType = (type: string) => {
    setForm(prev => ({
      ...prev,
      attachment_types: prev.attachment_types.includes(type)
        ? prev.attachment_types.filter(t => t !== type)
        : [...prev.attachment_types, type],
    }))
  }

  const buildConditions = () => {
    const c: Record<string, unknown> = {}
    if (form.sender_email)    c.sender_email = form.sender_email
    if (form.sender_domain)   c.sender_domain = form.sender_domain
    if (form.recipient_email) c.recipient_email = form.recipient_email
    if (form.recipient_domain) c.recipient_domain = form.recipient_domain
    if (form.threat_type)     c.threat_type = form.threat_type
    if (form.risk_score_min)  c.risk_score_min = Number(form.risk_score_min)
    if (form.has_attachment) {
      c.has_attachment = true
      if (form.attachment_types.length > 0) {
        c.attachment_types = form.attachment_types
      }
    }
    if (form.has_link)        c.has_link = true
    if (form.keywords)        c.keywords = form.keywords.split(',').map((s: string) => s.trim()).filter(Boolean)
    if (form.subject_contains) c.subject_contains = form.subject_contains.split(',').map((s: string) => s.trim()).filter(Boolean)
    return Object.keys(c).length > 0 ? c : { match_all: true }
  }

  const formFromPolicy = (p: Policy): FormState => {
    const c = p.conditions || {}
    const att_types = Array.isArray(c.attachment_types) ? (c.attachment_types as string[]) : []
    return {
      name: p.name,
      description: p.description || '',
      priority: p.priority,
      action: p.action,
      sender_email: (c.sender_email as string) || '',
      sender_domain: (c.sender_domain as string) || '',
      recipient_email: (c.recipient_email as string) || '',
      recipient_domain: (c.recipient_domain as string) || '',
      threat_type: (c.threat_type as string) || '',
      risk_score_min: c.risk_score_min !== undefined ? String(c.risk_score_min) : '',
      has_attachment: !!(c.has_attachment),
      attachment_types: att_types,
      has_link: !!(c.has_link),
      keywords: Array.isArray(c.keywords) ? (c.keywords as string[]).join(', ') : (c.keywords as string || ''),
      subject_contains: Array.isArray(c.subject_contains) ? (c.subject_contains as string[]).join(', ') : (c.subject_contains as string || ''),
      notify_admin: (p.action_config as Record<string, unknown>)?.notify_admin !== false,
    }
  }

  const handleCreate = async () => {
    if (!form.name.trim()) { setError('Policy name is required'); return }

    let finalAction = form.action
    let finalConditions: Record<string, unknown>

    if (builderTab === 'advanced') {
      const parsed = parseAdvancedRule(advancedText || '')
      if (!parsed) { setError('Please enter a policy rule in the Advanced Builder'); return }
      if (parsed.error) { setError(parsed.error); return }
      if (!parsed.action) { setError('Could not determine action from rule text'); return }
      finalAction = parsed.action
      finalConditions = parsed.conditions
    } else {
      finalConditions = buildConditions()
    }

    setSaving(true); setError('')
    try {
      await api.post('/api/policies', {
        name: form.name,
        description: form.description || undefined,
        priority: Number(form.priority),
        action: finalAction,
        conditions: finalConditions,
        action_config: { notify_admin: form.notify_admin },
      })
      setCreateOpen(false)
      setForm(emptyForm)
      setAdvancedText('')
      setBuilderTab('visual')
      await load()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } } }
      setError(err?.response?.data?.detail ?? 'Failed to create policy')
    }
    setSaving(false)
  }

  const handleEdit = async () => {
    if (!editPolicy) return
    if (!form.name.trim()) { setError('Policy name is required'); return }
    setSaving(true); setError('')
    try {
      await api.put(`/api/policies/${editPolicy.id}`, {
        name: form.name,
        description: form.description || undefined,
        priority: Number(form.priority),
        action: form.action,
        conditions: buildConditions(),
        action_config: { notify_admin: form.notify_admin },
      })
      setEditPolicy(null)
      setForm(emptyForm)
      await load()
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } } }
      setError(err?.response?.data?.detail ?? 'Failed to update policy')
    }
    setSaving(false)
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this policy? This cannot be undone.')) return
    setDeleting(id)
    try {
      await api.delete(`/api/policies/${id}`)
      await load()
    } catch {}
    setDeleting(null)
  }

  const installTemplate = async (tpl: ApiTemplate) => {
    try {
      // Fetch next available priority to avoid collisions
      let priority = 50
      try {
        const pr = await api.get('/api/policies/next-priority')
        priority = pr.data.priority ?? 50
      } catch {}

      await api.post('/api/policies', {
        name: tpl.name,
        description: tpl.description,
        priority,
        action: tpl.action,
        conditions: tpl.conditions,
        action_config: tpl.action_config ?? { notify_admin: true },
      })
      await load()
      toast.success(`Template "${tpl.name}" installed as draft (priority ${priority}) — activate when ready.`)
    } catch {
      toast.error('Failed to install template')
    }
  }

  const activatePolicy = async (id: string) => {
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, status: 'active' } : p))
    try {
      await api.post(`/api/policies/${id}/activate`)
      toast.success('Policy activated — now enforcing on incoming email.')
      await load()
    } catch {
      toast.error('Failed to activate policy. Please try again.')
      await load()
    }
  }

  const pausePolicy = async (id: string) => {
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, status: 'paused' } : p))
    try {
      await api.post(`/api/policies/${id}/pause`)
      toast.success('Policy paused — no longer applying to new emails.')
      await load()
    } catch {
      toast.error('Failed to pause policy. Please try again.')
      await load()
    }
  }

  const applyRetroactive = async () => {
    setApplying(true)
    setApplyResult(null)
    setApplyError('')
    try {
      const r = await api.post('/api/policies/apply-retroactive')
      setApplyResult({ message: r.data?.message ?? 'Policies are being applied to all emails in the background.' })
      setTimeout(() => setApplyResult(null), 10000)
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } } }
      setApplyError(err?.response?.data?.detail ?? 'Failed to start policy application')
      setTimeout(() => setApplyError(''), 5000)
    }
    setApplying(false)
  }

  // Template groups — icons instead of emojis
  const templateGroups = [
    { key: 'gulf'        as const, label: 'Gulf / MENA',        icon: <Globe size={12} />,        items: templates.gulf },
    { key: 'us'          as const, label: 'US Standards',        icon: <Building2 size={12} />,    items: templates.us },
    { key: 'eu'          as const, label: 'EU / UK',             icon: <Scale size={12} />,        items: templates.eu },
    { key: 'threat_intel' as const, label: 'Threat Intel Packs', icon: <ShieldCheck size={12} />, items: templates.threat_intel },
  ]

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Policies</h1>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" onClick={() => setTemplatesOpen(true)}>
            <Layers size={13} /> Templates
          </Button>
          <Button size="sm" variant="secondary" loading={applying} onClick={() => setShowApplyModal(true)}
            title="Scan your inbox and apply all active policies to existing emails now">
            <Zap size={13} /> Apply Now
          </Button>
          <Button size="sm" onClick={() => {
            setCreateOpen(true)
            setError('')
            setForm(emptyForm)
            setBuilderTab('visual')
            setAdvancedText('')
          }}>
            <Plus size={13} /> New Policy
          </Button>
        </div>
      </div>

      {/* Retroactive apply results */}
      {applyResult && (
        <div className="flex items-start gap-3 px-4 py-3.5 bg-emerald-900/20 border border-emerald-700/30 rounded-xl text-[13px]">
          <CheckCircle2 size={15} className="text-emerald-400 mt-0.5 flex-shrink-0" />
          <div>
            <p className="text-emerald-300 font-semibold">Policies applied</p>
            <p className="text-emerald-400/80 text-[12px] mt-0.5">{applyResult.message}</p>
          </div>
        </div>
      )}
      {applyError && (
        <div className="flex items-center gap-2.5 px-4 py-3 bg-red-900/20 border border-red-700/30 rounded-xl text-[13px] text-red-300">
          <AlertTriangle size={14} className="flex-shrink-0" /> {applyError}
        </div>
      )}

      {/* Apply Now Confirmation Modal */}
      {showApplyModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-[#0d1b2a] border border-[#0f3460] rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h2 className="text-white font-semibold text-base mb-2">Apply Policies Retroactively?</h2>
            <p className="text-slate-400 text-sm leading-relaxed mb-6">
              This will re-analyse ALL emails in every connected inbox using your active policies. Depending on inbox size, this may generate a large number of threat alerts and quarantine notifications. Are you sure?
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowApplyModal(false)}
                className="px-4 py-2 text-sm font-medium rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => { setShowApplyModal(false); applyRetroactive() }}
                className="px-4 py-2 text-sm font-medium rounded-lg bg-amber-500 hover:bg-amber-600 text-black font-semibold transition-colors"
              >
                Apply Now
              </button>
            </div>
          </div>
        </div>
      )}

      {/* How policies work callout */}
      <div className="flex items-start gap-3 bg-[#3b6ef6]/[0.06] border border-[#3b6ef6]/20 rounded-xl px-5 py-3.5 text-[12px] text-[#93b4fd]">
        <Info size={13} className="mt-0.5 flex-shrink-0" />
        <div>
          <span className="font-semibold">Execution order:</span> Policies run <span className="font-medium">before</span> AI analysis.
          ALLOW policies bypass detection entirely. BLOCK moves email to trash, notifies admin, recipient, and sender.
          QUARANTINE moves to Himaya-Quarantine, notifies admin and recipient.
          ALERT/TAG still pass through AI for a full explanation.
          Lower priority number = runs first. <span className="font-medium">Click "Apply Now"</span> to retroactively apply active policies to emails already in your inbox.
        </div>
      </div>

      {/* Policy list */}
      <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
        {loading ? (
          <div className="p-6 space-y-3">
            {[...Array(3)].map((_, i) => <div key={i} className="h-12 animate-pulse bg-white/[0.04] rounded" />)}
          </div>
        ) : policies.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-[#52525b]">
            <ClipboardList size={32} className="mb-3" />
            <p className="text-[13px]">No policies yet. Install a template or create your own.</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/[0.06]">
                <th className="px-4 py-3 text-left text-[11px] font-medium text-[#52525b] uppercase tracking-wide w-8">#</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-[#52525b] uppercase tracking-wide w-[160px]">Policy</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-[#52525b] uppercase tracking-wide">Conditions</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-[#52525b] uppercase tracking-wide w-[90px]">Action</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-[#52525b] uppercase tracking-wide w-[80px]">Status</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-[#52525b] uppercase tracking-wide w-[60px]">Hits</th>
                <th className="px-4 py-3 w-[80px]"></th>
              </tr>
            </thead>
            <tbody>
              {policies.map(p => (
                <tr key={p.id} className="border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02]">
                  <td className="px-4 py-3 text-[12px] text-[#52525b] w-8">{p.priority}</td>
                  <td className="px-4 py-3 w-[160px]">
                    <div className="text-[13px] font-medium text-[#d4d4d8] break-words">{p.name}</div>
                    {p.description && <div className="text-[11px] text-[#52525b] mt-0.5 break-words">{p.description}</div>}
                  </td>
                  <td className="px-4 py-3 text-[11px] text-[#71717a]">
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(p.conditions || {}).map(([k, v]) => {
                        // Format condition value for display
                        let display = ''
                        if (Array.isArray(v)) {
                          display = (v as unknown[]).join(', ')
                        } else if (v !== null && typeof v === 'object') {
                          // e.g. threat_feed_match: { ip_match: ['cert_cn_ips'] }
                          const parts = Object.entries(v as Record<string, unknown>).map(([sk, sv]) =>
                            `${sk.replace('_match','')}: ${Array.isArray(sv) ? (sv as string[]).join(', ') : String(sv)}`
                          )
                          display = parts.join(' | ')
                        } else {
                          display = String(v)
                        }
                        return (
                          <span key={k} className="inline-block bg-white/[0.04] rounded px-1.5 py-0.5 whitespace-normal break-all">
                            {k.replace('_match','').replace(/_/g,' ')}: {display}
                          </span>
                        )
                      })}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-[11px] font-medium px-2 py-0.5 rounded ${actionBadgeClass(p.action)}`}>
                      {p.action}
                    </span>
                  </td>
                  <td className="px-4 py-3"><Badge variant={statusVariant(p.status)}>{p.status}</Badge></td>
                  <td className="px-4 py-3">
                    <span className={`text-[12px] font-semibold tabular-nums ${
                      (p.hit_count ?? 0) > 0 ? 'text-[#f97316]' : 'text-[#52525b]'
                    }`}>
                      {(p.hit_count ?? 0).toLocaleString()}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => { setEditPolicy(p); setForm(formFromPolicy(p)); setError('') }}
                        className="text-[#71717a] hover:text-[#3b6ef6] transition-colors p-1" title="Edit policy">
                        <Pencil size={13} />
                      </button>
                      {p.status !== 'active' ? (
                        <button onClick={() => activatePolicy(p.id)}
                          className="text-[#3b6ef6] hover:text-white transition-colors p-1" title="Activate">
                          <Play size={13} />
                        </button>
                      ) : (
                        <button onClick={() => pausePolicy(p.id)}
                          className="text-[#71717a] hover:text-white transition-colors p-1" title="Pause">
                          <Pause size={13} />
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(p.id)}
                        disabled={deleting === p.id}
                        className="text-[#71717a] hover:text-[#f87171] transition-colors p-1" title="Delete policy">
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Create Modal */}
      <Modal open={createOpen} onClose={() => { setCreateOpen(false); setError('') }} title="New Policy" size="lg">
        <PolicyFormContent
          form={form} f={f} error={error} saving={saving} isEdit={false}
          onCancel={() => { setCreateOpen(false); setError('') }}
          onSubmit={handleCreate}
          toggleAttachmentType={toggleAttachmentType}
          builderTab={builderTab}
          setBuilderTab={setBuilderTab}
          advancedText={advancedText}
          setAdvancedText={setAdvancedText}
        />
      </Modal>

      {/* Edit Modal */}
      <Modal open={!!editPolicy} onClose={() => { setEditPolicy(null); setError('') }} title={`Edit Policy: ${editPolicy?.name ?? ''}`} size="lg">
        <PolicyFormContent
          form={form} f={f} error={error} saving={saving} isEdit
          onCancel={() => { setEditPolicy(null); setError('') }}
          onSubmit={handleEdit}
          toggleAttachmentType={toggleAttachmentType}
        />
      </Modal>

      {/* Templates Modal */}
      <Modal open={templatesOpen} onClose={() => setTemplatesOpen(false)} title="Policy Templates" size="lg">
        <p className="text-[12px] text-[#71717a] mb-4">
          Pre-built policies for Gulf/MENA, US, EU compliance frameworks and live Threat Intelligence packs.
          Installed as drafts — activate when ready. Priorities are auto-assigned to avoid collisions.
        </p>

        {/* Template group tabs with count badges */}
        <div className="flex gap-1 bg-[#1a1a20] border border-white/[0.06] rounded-lg p-1 mb-4 flex-wrap">
          {templateGroups.map(group => (
            <button
              key={group.key}
              onClick={() => setTemplateTab(group.key)}
              className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-2 text-[12px] font-medium rounded-md transition-colors ${
                templateTab === group.key
                  ? 'bg-[#3b6ef6] text-white shadow'
                  : 'text-[#71717a] hover:text-[#a1a1aa]'
              }`}
            >
              {group.icon}
              {group.label}
              {group.items.length > 0 && (
                <span className={`text-[10px] px-1.5 py-0.5 rounded-full font-semibold ${
                  templateTab === group.key
                    ? 'bg-white/20 text-white'
                    : 'bg-white/[0.07] text-[#71717a]'
                }`}>
                  {group.items.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* OpenDBL info banner for threat_intel tab */}
        {templateTab === 'threat_intel' && (
          <div className="mb-3 space-y-3">
            {/* ── CERT-CN feed status ── */}
            <div className="p-3 rounded-xl bg-orange-500/10 border border-orange-500/20 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-orange-400 text-base">🔴</span>
                  <div>
                    <p className="text-[12px] font-semibold text-orange-300">CERT-CN Daily IOC Feed</p>
                    <p className="text-[11px] text-orange-400/70">
                      China National CERT threat reports — IPs &amp; URLs extracted every 6h. Install packs below to activate quarantine.
                    </p>
                  </div>
                </div>
                <button
                  onClick={async () => {
                    setCertCnRefreshing(true)
                    try {
                      await api.post('/api/policies/cert-cn/refresh')
                      toast.success('CERT-CN scrape triggered.')
                      setTimeout(async () => { const s = await api.get('/api/policies/cert-cn/status'); setCertCnMeta(s.data ?? null) }, 15000)
                    } catch { toast.error('CERT-CN refresh failed') }
                    setCertCnRefreshing(false)
                  }}
                  disabled={certCnRefreshing}
                  className="text-[11px] px-2.5 py-1 rounded-lg bg-orange-500/20 text-orange-300 hover:bg-orange-500/30 transition-colors disabled:opacity-50 shrink-0"
                >
                  {certCnRefreshing ? 'Scraping…' : '↻ Refresh Now'}
                </button>
              </div>
              {certCnMeta && (
                <div className="flex gap-2 flex-wrap">
                  <div className="flex items-center gap-1.5 bg-black/20 rounded-lg px-2 py-1">
                    <span className={`w-1.5 h-1.5 rounded-full ${(certCnMeta.ips ?? 0) > 0 ? 'bg-emerald-400' : 'bg-orange-400'}`} />
                    <span className="text-[10px] text-orange-300/80 font-medium">Malicious IPs</span>
                    <span className="text-[10px] text-orange-400/60">{(certCnMeta.ips ?? 0).toLocaleString()}</span>
                  </div>
                  <div className="flex items-center gap-1.5 bg-black/20 rounded-lg px-2 py-1">
                    <span className={`w-1.5 h-1.5 rounded-full ${(certCnMeta.urls ?? 0) > 0 ? 'bg-emerald-400' : 'bg-orange-400'}`} />
                    <span className="text-[10px] text-orange-300/80 font-medium">URLs/Domains</span>
                    <span className="text-[10px] text-orange-400/60">{(certCnMeta.urls ?? 0).toLocaleString()}</span>
                  </div>
                  {certCnMeta.last_refresh && (
                    <div className="flex items-center gap-1.5 bg-black/20 rounded-lg px-2 py-1">
                      <span className="text-[10px] text-orange-400/40">{Math.round((Date.now() / 1000 - certCnMeta.last_refresh) / 3600)}h ago</span>
                    </div>
                  )}
                </div>
              )}
            </div>
            {/* Status + refresh banner */}
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/20 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-amber-400 text-base">⚡</span>
                  <div>
                    <p className="text-[12px] font-semibold text-amber-300">Live Threat Intelligence — OpenDBL</p>
                    <p className="text-[11px] text-amber-400/70">
                      IP blocklists auto-refresh every 6 hours. Matching checks sender IP, originating headers, and link IPs in email body.
                    </p>
                  </div>
                </div>
                <button
                  onClick={async () => {
                    setOpendblRefreshing(true)
                    try {
                      await api.post('/api/policies/opendbl/refresh')
                      toast.success('OpenDBL refresh triggered — packs updating in background.')
                      setTimeout(async () => {
                        const s = await api.get('/api/policies/opendbl/status')
                        setOpendblMeta(s.data.packs ?? {})
                      }, 5000)
                    } catch { toast.error('Refresh failed') }
                    setOpendblRefreshing(false)
                  }}
                  disabled={opendblRefreshing}
                  className="text-[11px] px-2.5 py-1 rounded-lg bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 transition-colors disabled:opacity-50 shrink-0"
                >
                  {opendblRefreshing ? 'Refreshing…' : '↻ Refresh Now'}
                </button>
              </div>
              {/* Per-pack status pills */}
              {Object.keys(opendblMeta).length > 0 && (
                <div className="flex gap-2 flex-wrap">
                  {Object.entries(opendblMeta).map(([pid, m]) => (
                    <div key={pid} className="flex items-center gap-1.5 bg-black/20 rounded-lg px-2 py-1">
                      <span className={`w-1.5 h-1.5 rounded-full ${m.ip_count > 0 ? 'bg-emerald-400' : 'bg-red-400'}`} />
                      <span className="text-[10px] text-amber-300/80 font-medium">{m.label}</span>
                      {m.ip_count > 0 && (
                        <span className="text-[10px] text-amber-400/60">{m.ip_count.toLocaleString()} IPs</span>
                      )}
                      {m.last_refresh && (
                        <span className="text-[10px] text-amber-400/40">
                          · {Math.round((Date.now() / 1000 - m.last_refresh) / 60)}m ago
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>


          </div>
        )}

        {/* Template list for active tab */}
        <div className="space-y-2 max-h-[380px] overflow-y-auto pr-1">
          {templateGroups.find(g => g.key === templateTab)?.items.length === 0 ? (
            <div className="text-center py-8 text-[#52525b] text-[13px]">
              <div className="text-2xl mb-2">⏳</div>
              Loading templates…
            </div>
          ) : (
            templateGroups
              .find(g => g.key === templateTab)
              ?.items.map(tpl => {
                // For threat_intel packs, inject live OpenDBL metadata
                const enriched = templateTab === 'threat_intel'
                  ? {
                      ...tpl,
                      _opendbl_meta: opendblMeta[(tpl as ApiTemplate & { pack_id?: string }).pack_id ?? ''] ?? null,
                    }
                  : tpl
                return (
                  <TemplateCard
                    key={tpl.id}
                    tpl={enriched as ApiTemplate}
                    onInstall={tpl => { installTemplate(tpl); setTemplatesOpen(false) }}
                  />
                )
              })
          )}
        </div>
      </Modal>
    </div>
  )
}
