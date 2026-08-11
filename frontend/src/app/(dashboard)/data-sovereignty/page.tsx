'use client'
import React, { useEffect, useState, useCallback } from 'react'
import {
  Globe2, ShieldAlert, ShieldCheck, RefreshCw, Scale,
  MapPin, Trash2, Plus, Layers, Server, FileWarning, CheckCircle2,
  Info, X, Lock, Zap, ClipboardCheck, AlertCircle,
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

type Tab = 'overview' | 'violations' | 'policies' | 'actions'

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
      setActions(ac.data?.actions ?? [])
    } catch (e) {
      if (!handle403(e)) console.error('sovereignty load failed', e)
    } finally {
      setLoading(false)
    }
  }, [])

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
        <div className="w-14 h-14 rounded-2xl bg-[#3b6ef6]/15 border border-[#3b6ef6]/25 flex items-center justify-center mb-4">
          <Lock size={26} className="text-[#3b6ef6]" />
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-[#3b6ef6]/15 border border-[#3b6ef6]/25 flex items-center justify-center">
            <Globe2 size={24} className="text-[#3b6ef6]" />
          </div>
          <div>
            <h1 className="text-[20px] font-semibold text-[var(--foreground)]">Data Sovereignty</h1>
            <p className="text-[12px] text-[var(--muted)]">
              Enforce which nation&apos;s laws govern your data — detect cross-border residency violations across all connectors.
            </p>
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
          { id: 'actions' as const, label: `Enforcement Log${actions.length ? ` (${actions.length})` : ''}`, icon: <ClipboardCheck size={13} /> },
        ]).map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
              tab === t.id ? 'border-[#3b6ef6] text-[#3b6ef6]' : 'border-transparent text-[var(--muted)] hover:text-[var(--foreground)]'
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
                <StatCard icon={<Scale size={14} className="text-[#3b6ef6]" />} label="Active Policies" value={overview.total_policies} />
                <StatCard icon={<ShieldAlert size={14} className="text-red-400" />} label="Open Violations" value={overview.total_violations} color={overview.total_violations > 0 ? 'text-red-400' : 'text-emerald-400'} />
                <StatCard icon={<Layers size={14} className="text-purple-400" />} label="Jurisdictions" value={overview.by_jurisdiction.length} />
                <StatCard icon={<Globe2 size={14} className="text-emerald-400" />} label="Packs Available" value={overview.packs_available} />
              </div>

              {overview.total_policies === 0 && (
                <div className="bg-[#3b6ef6]/[0.06] border border-[#3b6ef6]/20 rounded-xl p-5 flex items-start gap-3">
                  <Info size={18} className="text-[#3b6ef6] flex-shrink-0 mt-0.5" />
                  <div className="text-[13px] text-[var(--foreground)]">
                    No sovereignty policies yet. Click <span className="font-semibold">Seed Jurisdiction Packs</span> to
                    load prebuilt borders for KSA (PDPL/NCA), UAE, EU (GDPR), UK and US — then <span className="font-semibold">Run Sovereignty Scan</span> to
                    evaluate your real connector data.
                  </div>
                </div>
              )}

              {/* Per-jurisdiction posture */}
              {overview.by_jurisdiction.length > 0 && (
                <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
                  <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
                    <Scale size={14} className="text-[#3b6ef6]" /> Posture by Jurisdiction
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
                                className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-lg border border-[#3b6ef6]/30 text-[#3b6ef6] hover:bg-[#3b6ef6]/10 disabled:opacity-50"
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
                <Button size="sm" variant="secondary" onClick={() => setShowPackPicker(true)}>
                  <Plus size={14} className="mr-1" /> Add from Pack
                </Button>
              </div>

              {policies.length === 0 ? (
                <div className="bg-[#13131a] border border-white/[0.06] rounded-xl text-center py-16">
                  <Scale size={32} className="mx-auto text-[#3b6ef6]/40 mb-2" />
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

          {/* ── Enforcement Log ── */}
          {tab === 'actions' && (
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl overflow-hidden">
              {actions.length === 0 ? (
                <div className="text-center py-16">
                  <ClipboardCheck size={32} className="mx-auto text-[#3b6ef6]/40 mb-2" />
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
                <div className="h-full rounded-full bg-[#3b6ef6]" style={{ width: `${(r.value / max) * 100}%` }} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
