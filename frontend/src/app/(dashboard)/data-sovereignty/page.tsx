'use client'
import React, { useEffect, useState, useCallback } from 'react'
import {
  Globe2, ShieldAlert, ShieldCheck, RefreshCw, Scale,
  MapPin, Trash2, Plus, Layers, Server, FileWarning, CheckCircle2,
  Info, X, Lock, Zap, ClipboardCheck, AlertCircle,
  Database, UserSearch, Fingerprint,
} from 'lucide-react'
import Button from '@/components/ui/Button'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import api from '@/lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

interface JurisdictionPack {
  key: string
  name: string
  jurisdiction: string
  regulator: string
  legal_basis: string
  data_classes: string[]
  allowed_regions: string[]
  action: string
  transfer_rule: string
}

interface Policy {
  id: string
  name: string
  enabled: boolean
  jurisdiction: string
  pack_key: string | null
  data_classes: string[]
  allowed_regions: string[]
  action: string
  legal_basis: string | null
  created_at: string | null
}

interface Violation {
  id: string
  policy_name: string
  jurisdiction: string
  provider: string
  resource_ref: string
  resource_name: string | null
  data_class: string
  actual_region: string | null
  actual_country: string | null
  allowed_regions: string[]
  legal_basis: string | null
  verdict: string
  action: string
  confidence: string
  status: string
  detected_at: string | null
}

interface Overview {
  total_policies: number
  total_violations: number
  by_jurisdiction: Array<{ jurisdiction: string; policies: number; violations: number; critical: number; inferred: number }>
  by_provider: Array<{ provider: string; count: number }>
  by_data_class: Array<{ data_class: string; count: number }>
  packs_available: number
}

interface EnforcementAction {
  id: string
  violation_id: string | null
  action: string
  provider: string | null
  resource_ref: string | null
  executed: boolean
  manual_required: boolean
  result_message: string | null
  actor_email: string | null
  created_at: string | null
}

interface ColumnClassification {
  source: string
  lineage: { database: string; schema: string; table: string; column: string; path: string }
  data_class: string
  category: string
  detector: string
  confidence: number
  evidence: { samples?: string[]; sample_size?: number; match_count?: number; reason?: string; detector?: string }
  region: string | null
  country: string | null
  last_seen_at: string | null
}

interface ClassSummary {
  by_source: Array<{ source: string; columns: number; avg_confidence: number }>
  by_data_class: Array<{ data_class: string; columns: number }>
  total_columns: number
}

interface DSARMatch {
  source: string
  path: string
  data_class: string
  category: string
  region: string | null
  country: string | null
  confidence: number
  match_reason?: string
  remediation_sql?: string | null
}

interface DSARRequest {
  id: string
  subject_name: string | null
  subject_email: string | null
  request_type: string
  status: string
  legal_basis: string | null
  due_at: string | null
  summary: { total_matches?: number; systems?: string[]; by_source?: Record<string, number>; by_country?: Record<string, number> }
  created_by: string | null
  created_at: string | null
  completed_at: string | null
}

type Tab = 'overview' | 'violations' | 'policies' | 'actions' | 'classified' | 'dsar'

// ── Helpers ────────────────────────────────────────────────────────────────────

const actionColor = (a: string) => {
  switch (a) {
    case 'BLOCK': return 'bg-red-500/10 border-red-500/20 text-red-400'
    case 'QUARANTINE': return 'bg-orange-500/10 border-orange-500/20 text-orange-400'
    case 'WARN': return 'bg-amber-500/10 border-amber-500/20 text-amber-400'
    default: return 'bg-blue-500/10 border-blue-500/20 text-blue-400'
  }
}

const providerColor = (p: string) => {
  switch (p) {
    case 'aws': return 'text-[#FF9900]'
    case 'gcp': return 'text-[#4285F4]'
    case 'azure': return 'text-[#0089D6]'
    default: return 'text-[var(--muted)]'
  }
}

const fmtDate = (s: string | null) => {
  if (!s) return '—'
  return new Date(s).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// ── Page ────────────────────────────────────────────────────────────────────

export default function DataSovereigntyPage() {
  const [tab, setTab] = useState<Tab>('overview')
  const [enterprise, setEnterprise] = useState(true)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [seeding, setSeeding] = useState(false)

  const [overview, setOverview] = useState<Overview | null>(null)
  const [violations, setViolations] = useState<Violation[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [packs, setPacks] = useState<JurisdictionPack[]>([])
  const [actions, setActions] = useState<EnforcementAction[]>([])
  const [enforcingId, setEnforcingId] = useState<string | null>(null)
  const [showPackPicker, setShowPackPicker] = useState(false)

  const [classifications, setClassifications] = useState<ColumnClassification[]>([])
  const [classSummary, setClassSummary] = useState<ClassSummary | null>(null)
  const [dsars, setDsars] = useState<DSARRequest[]>([])
  const [showDsarModal, setShowDsarModal] = useState(false)
  const [dsarDetail, setDsarDetail] = useState<{ request: DSARRequest; matches: DSARMatch[] } | null>(null)
  const [creatingDsar, setCreatingDsar] = useState(false)
  const [dsarForm, setDsarForm] = useState({ subject_name: '', subject_email: '', national_id: '', phone: '', request_type: 'access' })

  const [showPolicyBuilder, setShowPolicyBuilder] = useState(false)
  const [savingPolicy, setSavingPolicy] = useState(false)
  const [dataClassOptions, setDataClassOptions] = useState<string[]>(['pii', 'phi', 'pci', 'financial', 'confidential', 'highly_confidential'])
  const [actionOptions, setActionOptions] = useState<string[]>(['WARN', 'BLOCK', 'QUARANTINE', 'NOTIFY'])
  const [regionInput, setRegionInput] = useState('')
  const [policyForm, setPolicyForm] = useState<{ name: string; jurisdiction: string; data_classes: string[]; allowed_regions: string[]; action: string; legal_basis: string }>({ name: '', jurisdiction: '', data_classes: [], allowed_regions: [], action: 'WARN', legal_basis: '' })

  const handle403 = (e: unknown) => {
    const err = e as { response?: { status?: number } }
    if (err.response?.status === 403) { setEnterprise(false); return true }
    return false
  }

  const loadAll = useCallback(async () => {
    setLoading(true)
    try {
      const [ov, vi, po, pk, ac] = await Promise.all([
        api.get('/api/sovereignty/overview'),
        api.get('/api/sovereignty/violations'),
        api.get('/api/sovereignty/policies'),
        api.get('/api/sovereignty/jurisdictions'),
        api.get('/api/sovereignty/actions'),
      ])
      setOverview(ov.data)
      setViolations(vi.data?.violations ?? [])
      setPolicies(po.data?.policies ?? [])
      setPacks(pk.data?.packs ?? [])
      if (Array.isArray(pk.data?.data_classes) && pk.data.data_classes.length) setDataClassOptions(pk.data.data_classes)
      if (Array.isArray(pk.data?.actions) && pk.data.actions.length) setActionOptions(pk.data.actions)
      setActions(ac.data?.actions ?? [])
      const [cs, cl, ds] = await Promise.all([
        api.get('/api/dsar/classifications/summary'),
        api.get('/api/dsar/classifications?limit=500'),
        api.get('/api/dsar/requests'),
      ])
      setClassSummary(cs.data)
      setClassifications(cl.data?.classifications ?? [])
      setDsars(ds.data?.requests ?? [])
    } catch (e) {
      if (!handle403(e)) console.error('sovereignty load failed', e)
    } finally {
      setLoading(false)
    }
  }, [])

  const createDsar = async () => {
    setCreatingDsar(true)
    try {
      const identifiers: Record<string, string> = {}
      if (dsarForm.national_id) identifiers.national_id = dsarForm.national_id
      if (dsarForm.phone) identifiers.phone = dsarForm.phone
      const { data } = await api.post('/api/dsar/requests', {
        subject_name: dsarForm.subject_name || null,
        subject_email: dsarForm.subject_email || null,
        subject_identifiers: identifiers,
        request_type: dsarForm.request_type,
      })
      setShowDsarModal(false)
      setDsarForm({ subject_name: '', subject_email: '', national_id: '', phone: '', request_type: 'access' })
      await loadAll()
      if (data.request_id) openDsar(data.request_id)
    } catch (e) { if (!handle403(e)) console.error(e) }
    finally { setCreatingDsar(false) }
  }

  const addRegion = (raw: string) => {
    const r = raw.trim()
    if (!r) return
    setPolicyForm(f => f.allowed_regions.includes(r) ? f : { ...f, allowed_regions: [...f.allowed_regions, r] })
    setRegionInput('')
  }

  const createPolicy = async () => {
    setSavingPolicy(true)
    try {
      await api.post('/api/sovereignty/policies', {
        name: policyForm.name.trim(),
        jurisdiction: (policyForm.jurisdiction.trim() || 'CUSTOM').toUpperCase(),
        data_classes: policyForm.data_classes,
        allowed_regions: policyForm.allowed_regions,
        action: policyForm.action,
        legal_basis: policyForm.legal_basis.trim() || null,
        enabled: true,
      })
      setShowPolicyBuilder(false)
      setPolicyForm({ name: '', jurisdiction: '', data_classes: [], allowed_regions: [], action: 'WARN', legal_basis: '' })
      setTab('policies')
      await loadAll()
    } catch (e) { if (!handle403(e)) console.error(e) }
    finally { setSavingPolicy(false) }
  }

  const openDsar = async (id: string) => {
    try {
      const { data } = await api.get(`/api/dsar/requests/${id}`)
      setDsarDetail({ request: data, matches: data.matches ?? [] })
    } catch (e) { if (!handle403(e)) console.error(e) }
  }

  const completeDsar = async (id: string) => {
    try {
      await api.post(`/api/dsar/requests/${id}/complete`)
      setDsarDetail(null)
      await loadAll()
    } catch (e) { if (!handle403(e)) console.error(e) }
  }

  useEffect(() => { loadAll() }, [loadAll])

  const runScan = async () => {
    setScanning(true)
    try {
      await api.post('/api/sovereignty/scan')
      await loadAll()
    } catch (e) { if (!handle403(e)) console.error(e) }
    finally { setScanning(false) }
  }

  const seedDefaults = async () => {
    setSeeding(true)
    try {
      await api.post('/api/sovereignty/policies/seed-defaults')
      await loadAll()
    } catch (e) { if (!handle403(e)) console.error(e) }
    finally { setSeeding(false) }
  }

  const addPolicyFromPack = async (pack: JurisdictionPack) => {
    try {
      await api.post('/api/sovereignty/policies', {
        name: pack.name,
        jurisdiction: pack.jurisdiction,
        pack_key: pack.key,
        data_classes: pack.data_classes,
        allowed_regions: pack.allowed_regions,
        action: pack.action,
        legal_basis: pack.legal_basis,
        enabled: true,
      })
      setShowPackPicker(false)
      await loadAll()
    } catch (e) { if (!handle403(e)) console.error(e) }
  }

  const togglePolicy = async (p: Policy) => {
    try {
      await api.patch(`/api/sovereignty/policies/${p.id}`, { enabled: !p.enabled })
      await loadAll()
    } catch (e) { if (!handle403(e)) console.error(e) }
  }

  const deletePolicy = async (id: string) => {
    try {
      await api.delete(`/api/sovereignty/policies/${id}`)
      await loadAll()
    } catch (e) { if (!handle403(e)) console.error(e) }
  }

  const enforceViolation = async (v: Violation) => {
    setEnforcingId(v.id)
    try {
      const { data } = await api.post(`/api/sovereignty/violations/${v.id}/enforce`)
      // Surface the outcome inline via the action log; reload to reflect status.
      window.alert(
        data.executed
          ? `Enforced: ${data.message}`
          : `Manual action required: ${data.message}`
      )
      await loadAll()
    } catch (e) { if (!handle403(e)) console.error(e) }
    finally { setEnforcingId(null) }
  }

  // ── Enterprise gate ──
  if (!enterprise) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <div className="w-14 h-14 rounded-2xl bg-[#24befa]/15 border border-[#24befa]/25 flex items-center justify-center mb-4">
          <Lock size={26} className="text-[#24befa]" />
        </div>
        <h1 className="text-[20px] font-semibold text-[var(--foreground)] mb-2">Data Sovereignty</h1>
        <p className="text-[13px] text-[var(--muted)] max-w-md">
          Data Sovereignty enforcement requires an Enterprise plan. Upgrade to define jurisdiction
          borders, detect cross-border residency violations, and generate auditor-grade evidence.
        </p>
      </div>
    )
  }

  const existingPackKeys = new Set(policies.map(p => p.pack_key).filter(Boolean))
  const regionSuggestions = Array.from(new Set(packs.flatMap(p => p.allowed_regions ?? []))).sort()

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#24befa]/25 to-[#24befa]/5 border border-[#24befa]/25 flex items-center justify-center shadow-lg shadow-[#24befa]/10">
            <Globe2 size={24} className="text-[#24befa]" />
          </div>
          <div>
            <h1 className="text-[20px] font-semibold text-[var(--foreground)]">Data Sovereignty</h1>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={seedDefaults} loading={seeding}>
            <Scale size={14} className="mr-1" /> Seed Jurisdiction Packs
          </Button>
          <Button size="sm" onClick={runScan} loading={scanning}>
            <RefreshCw size={14} className={`mr-1 ${scanning ? 'animate-spin' : ''}`} /> Run Sovereignty Scan
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-[var(--border)]">
        {([
          { id: 'overview' as const, label: 'Scorecard', icon: <ShieldCheck size={13} /> },
          { id: 'violations' as const, label: `Violations${overview ? ` (${overview.total_violations})` : ''}`, icon: <ShieldAlert size={13} /> },
          { id: 'policies' as const, label: `Policies${overview ? ` (${overview.total_policies})` : ''}`, icon: <Scale size={13} /> },
          { id: 'classified' as const, label: `Classified Data${classSummary ? ` (${classSummary.total_columns})` : ''}`, icon: <Database size={13} /> },
          { id: 'dsar' as const, label: `DSAR${dsars.length ? ` (${dsars.length})` : ''}`, icon: <UserSearch size={13} /> },
          { id: 'actions' as const, label: `Enforcement Log${actions.length ? ` (${actions.length})` : ''}`, icon: <ClipboardCheck size={13} /> },
        ]).map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
              tab === t.id ? 'border-[#24befa] text-[#24befa]' : 'border-transparent text-[var(--muted)] hover:text-[var(--foreground)]'
            }`}
          >
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-24 bg-white/[0.03] rounded-xl animate-pulse" />)}
          </div>
          <div className="h-64 bg-white/[0.03] rounded-xl animate-pulse" />
        </div>
      ) : (
        <>
          {/* ── Overview / Scorecard ── */}
          {tab === 'overview' && overview && (
            <div className="space-y-6">
              {/* Stat cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <StatCard icon={<Scale size={14} className="text-[#24befa]" />} label="Active Policies" value={overview.total_policies} />
                <StatCard icon={<ShieldAlert size={14} className="text-red-400" />} label="Open Violations" value={overview.total_violations} color={overview.total_violations > 0 ? 'text-red-400' : 'text-emerald-400'} />
                <StatCard icon={<Layers size={14} className="text-purple-400" />} label="Jurisdictions" value={overview.by_jurisdiction.length} />
                <StatCard icon={<Globe2 size={14} className="text-emerald-400" />} label="Packs Available" value={overview.packs_available} />
              </div>

              {overview.total_policies === 0 && (
                <div className="bg-[#24befa]/[0.06] border border-[#24befa]/20 rounded-xl p-5 flex items-start gap-3">
                  <Info size={18} className="text-[#24befa] flex-shrink-0 mt-0.5" />
                  <div className="text-[13px] text-[var(--foreground)]">
                    No sovereignty policies yet. Click <span className="font-semibold">Seed Jurisdiction Packs</span> to
                    load prebuilt borders for {overview.packs_available}+ regimes — KSA (PDPL/NCA), UAE, EU (GDPR), UK, US, Qatar, Bahrain, India (DPDP), China (PIPL), Brazil (LGPD) and more — or <span className="font-semibold">Build Policy</span> for a custom border, then <span className="font-semibold">Run Sovereignty Scan</span>.
                  </div>
                </div>
              )}

              {/* Per-jurisdiction posture */}
              {overview.by_jurisdiction.length > 0 && (
                <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
                  <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
                    <Scale size={14} className="text-[#24befa]" /> Posture by Jurisdiction
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {overview.by_jurisdiction.map(j => (
                      <div key={j.jurisdiction} className="flex items-center justify-between p-3 bg-white/[0.02] rounded-lg border border-white/[0.05]">
                        <div className="flex items-center gap-3">
                          <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${j.violations > 0 ? 'bg-red-500/15 text-red-400' : 'bg-emerald-500/15 text-emerald-400'}`}>
                            {j.violations > 0 ? <ShieldAlert size={16} /> : <ShieldCheck size={16} />}
                          </div>
                          <div>
                            <div className="text-[13px] font-semibold text-[var(--foreground)]">{j.jurisdiction}</div>
                            <div className="text-[10px] text-[var(--muted)]">{j.policies} polic{j.policies === 1 ? 'y' : 'ies'}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className={`text-[16px] font-bold ${j.violations > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{j.violations}</div>
                          <div className="text-[10px] text-[var(--muted)]">
                            {j.violations > 0 ? `${j.critical} critical` : 'compliant'}
                            {j.inferred > 0 ? ` · ${j.inferred} inferred` : ''}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Breakdown cards */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <BreakdownCard title="Violations by Provider" icon={<Server size={13} className="text-[#FF9900]" />}
                  rows={overview.by_provider.map(p => ({ label: p.provider.toUpperCase(), value: p.count, color: providerColor(p.provider) }))} />
                <BreakdownCard title="Violations by Data Class" icon={<FileWarning size={13} className="text-purple-400" />}
                  rows={overview.by_data_class.map(d => ({ label: d.data_class, value: d.count }))} />
              </div>
            </div>
          )}

          {/* ── Violations ── */}
          {tab === 'violations' && (
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl overflow-hidden">
              {violations.length === 0 ? (
                <div className="text-center py-16">
                  <ShieldCheck size={32} className="mx-auto text-emerald-400/50 mb-2" />
                  <div className="text-[13px] text-[var(--muted)]">No sovereignty violations detected. Run a scan after seeding policies.</div>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <Thead>
                      <Tr>
                        <Th>Resource</Th>
                        <Th>Provider</Th>
                        <Th>Data Class</Th>
                        <Th>Resides In</Th>
                        <Th>Jurisdiction</Th>
                        <Th>Legal Basis</Th>
                        <Th>Action</Th>
                        <Th>Status</Th>
                        <Th>Enforce</Th>
                        <Th>Detected</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {violations.map(v => (
                        <Tr key={v.id}>
                          <Td>
                            <div className="text-[12px] text-[var(--foreground)] font-medium max-w-[220px] truncate">{v.resource_name || v.resource_ref}</div>
                            {v.confidence === 'inferred' && (
                              <span className="text-[9px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">inferred region</span>
                            )}
                          </Td>
                          <Td><span className={`text-[11px] font-semibold ${providerColor(v.provider)}`}>{v.provider.toUpperCase()}</span></Td>
                          <Td><span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-300">{v.data_class}</span></Td>
                          <Td>
                            <div className="flex items-center gap-1 text-[12px] text-red-400">
                              <MapPin size={11} /> {v.actual_region || v.actual_country || 'unknown'}
                            </div>
                          </Td>
                          <Td><span className="text-[12px] text-[var(--foreground)]">{v.jurisdiction}</span></Td>
                          <Td><span className="text-[10px] text-[var(--muted)] max-w-[180px] block truncate" title={v.legal_basis || ''}>{v.legal_basis || '—'}</span></Td>
                          <Td><span className={`text-[10px] px-2 py-0.5 rounded-full border ${actionColor(v.action)}`}>{v.action}</span></Td>
                          <Td>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full ${
                              v.status === 'enforced' ? 'bg-emerald-500/10 text-emerald-400'
                              : v.status === 'manual_required' ? 'bg-amber-500/10 text-amber-400'
                              : 'bg-zinc-500/10 text-zinc-400'
                            }`}>{v.status === 'manual_required' ? 'manual' : v.status}</span>
                          </Td>
                          <Td>
                            {v.status === 'enforced' ? (
                              <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400"><CheckCircle2 size={12} /> done</span>
                            ) : (
                              <button
                                onClick={() => enforceViolation(v)}
                                disabled={enforcingId === v.id}
                                className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-lg border border-[#24befa]/30 text-[#24befa] hover:bg-[#24befa]/10 disabled:opacity-50"
                              >
                                {enforcingId === v.id ? <RefreshCw size={12} className="animate-spin" /> : <Zap size={12} />}
                                Enforce
                              </button>
                            )}
                          </Td>
                          <Td><span className="text-[11px] text-[var(--muted)]">{fmtDate(v.detected_at)}</span></Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </div>
              )}
            </div>
          )}

          {/* ── Policies ── */}
          {tab === 'policies' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <p className="text-[12px] text-[var(--muted)]">
                  Policies bind a data class + jurisdiction to allowed regions. Assets outside those borders are flagged.
                </p>
                <div className="flex items-center gap-2">
                  <Button size="sm" variant="secondary" onClick={() => setShowPackPicker(true)}>
                    <Layers size={14} className="mr-1" /> Add from Pack
                  </Button>
                  <Button size="sm" onClick={() => setShowPolicyBuilder(true)}>
                    <Plus size={14} className="mr-1" /> Build Policy
                  </Button>
                </div>
              </div>

              {policies.length === 0 ? (
                <div className="bg-[#13131a] border border-white/[0.06] rounded-xl text-center py-16">
                  <Scale size={32} className="mx-auto text-[#24befa]/40 mb-2" />
                  <div className="text-[13px] text-[var(--muted)]">No policies. Seed jurisdiction packs or add one from a pack.</div>
                </div>
              ) : (
                <div className="space-y-2">
                  {policies.map(p => (
                    <div key={p.id} className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-[13px] font-semibold text-[var(--foreground)]">{p.name}</span>
                            <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400">{p.jurisdiction}</span>
                            <span className={`text-[10px] px-2 py-0.5 rounded-full border ${actionColor(p.action)}`}>{p.action}</span>
                          </div>
                          <div className="text-[11px] text-[var(--muted)] mt-1.5">{p.legal_basis}</div>
                          <div className="flex flex-wrap gap-1 mt-2">
                            {p.data_classes.map(dc => (
                              <span key={dc} className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300">{dc}</span>
                            ))}
                          </div>
                          <div className="text-[10px] text-[var(--muted)] mt-2">
                            <span className="text-[var(--foreground)]">Allowed:</span> {p.allowed_regions.slice(0, 8).join(', ')}{p.allowed_regions.length > 8 ? ` +${p.allowed_regions.length - 8}` : ''}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0">
                          <button
                            onClick={() => togglePolicy(p)}
                            className={`text-[10px] px-2 py-1 rounded-lg border transition-colors ${
                              p.enabled ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
                            }`}
                          >
                            {p.enabled ? 'Enabled' : 'Disabled'}
                          </button>
                          <button onClick={() => deletePolicy(p.id)} className="text-[var(--muted)] hover:text-red-400 p-1.5 rounded-lg hover:bg-red-500/10">
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ── Classified Data (column-level, with evidence + lineage) ── */}
          {tab === 'classified' && (
            <div className="space-y-4">
              {classSummary && (
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <StatCard icon={<Database size={14} className="text-[#24befa]" />} label="Classified Columns" value={classSummary.total_columns} />
                  <StatCard icon={<Server size={14} className="text-purple-400" />} label="Sources" value={classSummary.by_source.length} />
                  <StatCard icon={<Fingerprint size={14} className="text-amber-400" />} label="PII Columns" value={classSummary.by_data_class.find(d => d.data_class === 'pii')?.columns ?? 0} />
                  <StatCard icon={<ShieldAlert size={14} className="text-red-400" />} label="Sensitive Classes" value={classSummary.by_data_class.length} />
                </div>
              )}
              <div className="bg-[#13131a] border border-white/[0.06] rounded-xl overflow-hidden">
                {classifications.length === 0 ? (
                  <div className="text-center py-16">
                    <Database size={32} className="mx-auto text-[#24befa]/40 mb-2" />
                    <div className="text-[13px] text-[var(--muted)]">No classified columns yet. Connect Snowflake/SAP and run a scan — column-level PII is classified automatically.</div>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <Table>
                      <Thead>
                        <Tr>
                          <Th>Source</Th>
                          <Th>Lineage (db.schema.table.column)</Th>
                          <Th>Class</Th>
                          <Th>Category</Th>
                          <Th>Confidence</Th>
                          <Th>Evidence</Th>
                          <Th>Region</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {classifications.map((c, i) => (
                          <Tr key={i}>
                            <Td><span className={`text-[11px] font-semibold ${providerColor(c.source)}`}>{c.source.toUpperCase()}</span></Td>
                            <Td><span className="text-[11px] font-mono text-[var(--foreground)] max-w-[300px] block truncate" title={c.lineage.path}>{c.lineage.database}.{c.lineage.schema}.{c.lineage.table}.<span className="text-[#24befa]">{c.lineage.column}</span></span></Td>
                            <Td><span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300">{c.data_class}</span></Td>
                            <Td><span className="text-[11px] text-[var(--muted)]">{c.category}</span></Td>
                            <Td><ConfidenceBar value={c.confidence} detector={c.detector} /></Td>
                            <Td>
                              <span className="text-[10px] text-[var(--muted)] max-w-[220px] block truncate" title={(c.evidence?.samples || []).join(' · ') + (c.evidence?.reason ? ` — ${c.evidence.reason}` : '')}>
                                {c.evidence?.reason || (c.evidence?.samples || []).join(' · ') || '—'}
                              </span>
                            </Td>
                            <Td><span className="text-[10px] text-[var(--muted)]">{c.region || '—'}{c.country ? ` (${c.country})` : ''}</span></Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── DSAR ── */}
          {tab === 'dsar' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-[12px] text-[var(--muted)] max-w-2xl">
                  Data Subject Access Requests. Creating a request builds a privacy-preserving cross-system <span className="text-[var(--foreground)]">data map</span> from the classified inventory — pointing to the exact columns/tables/systems holding the subject&apos;s PII, without reading raw values.
                </p>
                <Button size="sm" onClick={() => setShowDsarModal(true)}><Plus size={14} className="mr-1" /> New DSAR</Button>
              </div>
              <div className="bg-[#13131a] border border-white/[0.06] rounded-xl overflow-hidden">
                {dsars.length === 0 ? (
                  <div className="text-center py-16">
                    <UserSearch size={32} className="mx-auto text-[#24befa]/40 mb-2" />
                    <div className="text-[13px] text-[var(--muted)]">No DSARs yet. Create one to generate a subject data map.</div>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <Table>
                      <Thead>
                        <Tr><Th>Subject</Th><Th>Type</Th><Th>Status</Th><Th>Matches</Th><Th>Systems</Th><Th>Due</Th><Th></Th></Tr>
                      </Thead>
                      <Tbody>
                        {dsars.map(d => (
                          <Tr key={d.id}>
                            <Td><span className="text-[12px] text-[var(--foreground)]">{d.subject_name || d.subject_email || '—'}</span></Td>
                            <Td><span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 capitalize">{d.request_type}</span></Td>
                            <Td><span className={`text-[10px] px-2 py-0.5 rounded-full border ${d.status === 'completed' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-amber-500/10 border-amber-500/20 text-amber-400'}`}>{d.status}</span></Td>
                            <Td><span className="text-[12px] text-[var(--foreground)]">{d.summary?.total_matches ?? 0}</span></Td>
                            <Td><span className="text-[10px] text-[var(--muted)]">{(d.summary?.systems || []).join(', ') || '—'}</span></Td>
                            <Td><span className="text-[10px] text-[var(--muted)]">{fmtDate(d.due_at)}</span></Td>
                            <Td><button onClick={() => openDsar(d.id)} className="text-[11px] text-[#24befa] hover:underline">View map</button></Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ── Enforcement Log ── */}
          {tab === 'actions' && (
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl overflow-hidden">
              {actions.length === 0 ? (
                <div className="text-center py-16">
                  <ClipboardCheck size={32} className="mx-auto text-[#24befa]/40 mb-2" />
                  <div className="text-[13px] text-[var(--muted)]">No enforcement actions yet. Enforce a violation to build an auditable trail.</div>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <Thead>
                      <Tr>
                        <Th>Action</Th>
                        <Th>Provider</Th>
                        <Th>Resource</Th>
                        <Th>Outcome</Th>
                        <Th>Result</Th>
                        <Th>Actor</Th>
                        <Th>When</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {actions.map(a => (
                        <Tr key={a.id}>
                          <Td><span className={`text-[10px] px-2 py-0.5 rounded-full border ${actionColor(a.action)}`}>{a.action}</span></Td>
                          <Td><span className={`text-[11px] font-semibold ${providerColor(a.provider || '')}`}>{(a.provider || '—').toUpperCase()}</span></Td>
                          <Td><span className="text-[12px] text-[var(--foreground)] max-w-[220px] block truncate" title={a.resource_ref || ''}>{a.resource_ref || '—'}</span></Td>
                          <Td>
                            {a.executed ? (
                              <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400"><CheckCircle2 size={12} /> executed</span>
                            ) : a.manual_required ? (
                              <span className="inline-flex items-center gap-1 text-[11px] text-amber-400"><AlertCircle size={12} /> manual required</span>
                            ) : (
                              <span className="text-[11px] text-zinc-400">—</span>
                            )}
                          </Td>
                          <Td><span className="text-[11px] text-[var(--muted)] max-w-[280px] block truncate" title={a.result_message || ''}>{a.result_message || '—'}</span></Td>
                          <Td><span className="text-[11px] text-[var(--muted)]">{a.actor_email || 'system'}</span></Td>
                          <Td><span className="text-[11px] text-[var(--muted)]">{fmtDate(a.created_at)}</span></Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Policy Builder modal */}
      {showPolicyBuilder && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowPolicyBuilder(false)}>
          <div className="bg-[#13131a] border border-white/[0.1] rounded-2xl max-w-xl w-full max-h-[88vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5 border-b border-white/[0.06] sticky top-0 bg-[#13131a] z-10">
              <h3 className="text-[15px] font-semibold text-[var(--foreground)] flex items-center gap-2"><Scale size={16} className="text-[#24befa]" /> Build Custom Policy</h3>
              <button onClick={() => setShowPolicyBuilder(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]"><X size={18} /></button>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Policy name" value={policyForm.name} onChange={v => setPolicyForm(f => ({ ...f, name: v }))} placeholder="e.g. Customer PII must stay in KSA" />
                <Field label="Jurisdiction" value={policyForm.jurisdiction} onChange={v => setPolicyForm(f => ({ ...f, jurisdiction: v }))} placeholder="e.g. KSA, EU, CUSTOM" />
              </div>

              {/* Data classes */}
              <div>
                <label className="text-[11px] text-[var(--muted)] uppercase tracking-wide">Data classes</label>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {dataClassOptions.map(dc => {
                    const on = policyForm.data_classes.includes(dc)
                    return (
                      <button
                        key={dc}
                        onClick={() => setPolicyForm(f => ({ ...f, data_classes: on ? f.data_classes.filter(x => x !== dc) : [...f.data_classes, dc] }))}
                        className={`text-[10px] px-2 py-1 rounded-lg border transition-colors ${on ? 'bg-purple-500/15 border-purple-500/30 text-purple-300' : 'bg-white/[0.03] border-white/[0.08] text-[var(--muted)] hover:text-[var(--foreground)]'}`}
                      >{dc}</button>
                    )
                  })}
                </div>
              </div>

              {/* Action */}
              <div>
                <label className="text-[11px] text-[var(--muted)] uppercase tracking-wide">Enforcement action</label>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {actionOptions.map(a => (
                    <button
                      key={a}
                      onClick={() => setPolicyForm(f => ({ ...f, action: a }))}
                      className={`text-[10px] px-2.5 py-1 rounded-lg border transition-colors ${policyForm.action === a ? actionColor(a) : 'bg-white/[0.03] border-white/[0.08] text-[var(--muted)] hover:text-[var(--foreground)]'}`}
                    >{a}</button>
                  ))}
                </div>
              </div>

              {/* Allowed regions */}
              <div>
                <label className="text-[11px] text-[var(--muted)] uppercase tracking-wide">Allowed regions / countries</label>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {policyForm.allowed_regions.map(r => (
                    <span key={r} className="inline-flex items-center gap-1 text-[10px] px-2 py-1 rounded-lg bg-[#24befa]/10 border border-[#24befa]/25 text-[#24befa]">
                      {r}
                      <button onClick={() => setPolicyForm(f => ({ ...f, allowed_regions: f.allowed_regions.filter(x => x !== r) }))} className="hover:text-red-400"><X size={11} /></button>
                    </span>
                  ))}
                </div>
                <input
                  value={regionInput}
                  onChange={e => setRegionInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addRegion(regionInput) } }}
                  placeholder="Type a region/ISO code (e.g. SA, eu-west-1) and press Enter"
                  className="mt-2 w-full bg-white/[0.03] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] placeholder:text-[var(--muted)]/50"
                />
                {regionSuggestions.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {regionSuggestions.filter(r => !policyForm.allowed_regions.includes(r)).slice(0, 18).map(r => (
                      <button key={r} onClick={() => addRegion(r)} className="text-[9px] px-1.5 py-0.5 rounded bg-white/[0.03] border border-white/[0.06] text-[var(--muted)] hover:text-[var(--foreground)] hover:border-[#24befa]/30">+ {r}</button>
                    ))}
                  </div>
                )}
              </div>

              <Field label="Legal basis (optional)" value={policyForm.legal_basis} onChange={v => setPolicyForm(f => ({ ...f, legal_basis: v }))} placeholder="e.g. PDPL Art. 29" />

              <div className="flex justify-end gap-2 pt-1">
                <Button size="sm" variant="ghost" onClick={() => setShowPolicyBuilder(false)}>Cancel</Button>
                <Button
                  size="sm"
                  onClick={createPolicy}
                  loading={savingPolicy}
                  disabled={!policyForm.name.trim() || policyForm.data_classes.length === 0 || policyForm.allowed_regions.length === 0}
                >
                  Create Policy
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* DSAR create modal */}
      {showDsarModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowDsarModal(false)}>
          <div className="bg-[#13131a] border border-white/[0.1] rounded-2xl max-w-lg w-full" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5 border-b border-white/[0.06]">
              <h3 className="text-[15px] font-semibold text-[var(--foreground)] flex items-center gap-2"><UserSearch size={16} className="text-[#24befa]" /> New Data Subject Request</h3>
              <button onClick={() => setShowDsarModal(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]"><X size={18} /></button>
            </div>
            <div className="p-5 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <Field label="Subject name" value={dsarForm.subject_name} onChange={v => setDsarForm(f => ({ ...f, subject_name: v }))} placeholder="Jane Doe" />
                <Field label="Email" value={dsarForm.subject_email} onChange={v => setDsarForm(f => ({ ...f, subject_email: v }))} placeholder="jane@acme.com" />
                <Field label="National ID / EID" value={dsarForm.national_id} onChange={v => setDsarForm(f => ({ ...f, national_id: v }))} placeholder="optional" />
                <Field label="Phone" value={dsarForm.phone} onChange={v => setDsarForm(f => ({ ...f, phone: v }))} placeholder="optional" />
              </div>
              <div>
                <label className="text-[11px] text-[var(--muted)] uppercase tracking-wide">Request type</label>
                <select
                  value={dsarForm.request_type}
                  onChange={e => setDsarForm(f => ({ ...f, request_type: e.target.value }))}
                  className="mt-1 w-full bg-white/[0.03] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)]"
                >
                  <option value="access">Access (Right to Access)</option>
                  <option value="erasure">Erasure (Right to be Forgotten)</option>
                  <option value="rectification">Rectification</option>
                  <option value="portability">Portability</option>
                </select>
              </div>
              <p className="text-[10px] text-[var(--muted)]">A 30-day response clock (GDPR/PDPL) is set automatically. We locate columns by category — raw values are never read or stored.</p>
              <div className="flex justify-end gap-2 pt-2">
                <Button size="sm" variant="ghost" onClick={() => setShowDsarModal(false)}>Cancel</Button>
                <Button size="sm" onClick={createDsar} loading={creatingDsar}>Build Data Map</Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* DSAR detail (data map) modal */}
      {dsarDetail && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setDsarDetail(null)}>
          <div className="bg-[#13131a] border border-white/[0.1] rounded-2xl max-w-3xl w-full max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5 border-b border-white/[0.06] sticky top-0 bg-[#13131a]">
              <div>
                <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Subject Data Map — {dsarDetail.request.subject_name || dsarDetail.request.subject_email}</h3>
                <div className="text-[11px] text-[var(--muted)] mt-0.5 capitalize">{dsarDetail.request.request_type} · {dsarDetail.matches.length} matches · due {fmtDate(dsarDetail.request.due_at)}</div>
              </div>
              <button onClick={() => setDsarDetail(null)} className="text-[var(--muted)] hover:text-[var(--foreground)]"><X size={18} /></button>
            </div>
            <div className="p-5 space-y-2">
              {dsarDetail.matches.length === 0 ? (
                <div className="text-center py-10 text-[12px] text-[var(--muted)]">No classified PII columns matched this subject&apos;s identifier types. Classify more sources to widen coverage.</div>
              ) : dsarDetail.matches.map((m, i) => (
                <div key={i} className="bg-white/[0.02] border border-white/[0.05] rounded-xl p-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-[11px] font-semibold ${providerColor(m.source)}`}>{m.source.toUpperCase()}</span>
                    <span className="text-[11px] font-mono text-[var(--foreground)]">{m.path.split(':')[1]}</span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300">{m.category}</span>
                    <span className="text-[10px] text-[var(--muted)]">{m.region || '—'}{m.country ? ` (${m.country})` : ''}</span>
                    <span className="text-[10px] text-[var(--muted)] ml-auto">conf {(m.confidence * 100).toFixed(0)}%</span>
                  </div>
                  {m.remediation_sql && (
                    <pre className="mt-2 text-[10px] font-mono text-amber-300/90 bg-black/30 border border-amber-500/10 rounded-lg p-2 overflow-x-auto whitespace-pre-wrap">{m.remediation_sql}</pre>
                  )}
                </div>
              ))}
              <div className="flex justify-end gap-2 pt-3">
                {dsarDetail.request.status !== 'completed' && (
                  <Button size="sm" onClick={() => completeDsar(dsarDetail.request.id)}><CheckCircle2 size={14} className="mr-1" /> Mark Complete</Button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Pack picker modal */}
      {showPackPicker && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowPackPicker(false)}>
          <div className="bg-[#13131a] border border-white/[0.1] rounded-2xl max-w-2xl w-full max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5 border-b border-white/[0.06] sticky top-0 bg-[#13131a]">
              <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Jurisdiction Packs</h3>
              <button onClick={() => setShowPackPicker(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]"><X size={18} /></button>
            </div>
            <div className="p-5 space-y-3">
              {packs.map(pack => {
                const added = existingPackKeys.has(pack.key)
                return (
                  <div key={pack.key} className="bg-white/[0.02] border border-white/[0.05] rounded-xl p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="text-[13px] font-semibold text-[var(--foreground)]">{pack.name}</div>
                        <div className="text-[10px] text-[var(--muted)] mt-0.5">{pack.regulator} · {pack.legal_basis}</div>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {pack.data_classes.map(dc => (
                            <span key={dc} className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300">{dc}</span>
                          ))}
                        </div>
                      </div>
                      <Button size="sm" variant={added ? 'ghost' : 'secondary'} disabled={added} onClick={() => addPolicyFromPack(pack)}>
                        {added ? <CheckCircle2 size={14} /> : <Plus size={14} />}
                        <span className="ml-1">{added ? 'Added' : 'Add'}</span>
                      </Button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Sub-components ──────────────────────────────────────────────────────────

function StatCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number; color?: string }) {
  return (
    <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
      <div className="flex items-center gap-2 mb-2">{icon}<span className="text-[11px] text-[var(--muted)] uppercase tracking-wide">{label}</span></div>
      <div className={`text-2xl font-bold ${color || 'text-[var(--foreground)]'}`}>{value}</div>
    </div>
  )
}

function ConfidenceBar({ value, detector }: { value: number; detector: string }) {
  const pct = Math.round(value * 100)
  const color = value >= 0.85 ? 'bg-emerald-500' : value >= 0.65 ? 'bg-amber-500' : 'bg-zinc-500'
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="h-1.5 w-16 bg-white/[0.06] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-[var(--muted)]">{pct}%</span>
      <span className="text-[9px] px-1 py-0.5 rounded bg-white/[0.04] text-[var(--muted)]" title="detector">{detector}</span>
    </div>
  )
}

function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div>
      <label className="text-[11px] text-[var(--muted)] uppercase tracking-wide">{label}</label>
      <input
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="mt-1 w-full bg-white/[0.03] border border-white/[0.08] rounded-lg px-3 py-2 text-[13px] text-[var(--foreground)] placeholder:text-[var(--muted)]/50"
      />
    </div>
  )
}

function BreakdownCard({ title, icon, rows }: { title: string; icon: React.ReactNode; rows: Array<{ label: string; value: number; color?: string }> }) {
  const max = Math.max(1, ...rows.map(r => r.value))
  return (
    <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
      <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">{icon}{title}</h3>
      {rows.length === 0 ? (
        <div className="text-center py-4 text-[var(--muted)] text-[11px]">No violations</div>
      ) : (
        <div className="space-y-2.5">
          {rows.map((r, i) => (
            <div key={i}>
              <div className="flex justify-between text-[11px] mb-1">
                <span className={`capitalize ${r.color || 'text-[var(--foreground)]'}`}>{r.label}</span>
                <span className="text-[var(--muted)]">{r.value}</span>
              </div>
              <div className="h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
                <div className="h-full rounded-full bg-[#0ea5e9]" style={{ width: `${(r.value / max) * 100}%` }} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
