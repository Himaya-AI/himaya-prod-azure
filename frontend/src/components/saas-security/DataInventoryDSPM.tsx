/**
 * DataInventoryDSPM
 *
 * Sensitive-data discovery panel for the Workspace Security → Data Inventory tab.
 * Backed by the /api/dspm/* endpoints. Shows overview tiles, findings table,
 * scan history, and the pattern catalogue. Triggers AWS scans against any
 * connected AWS account.
 *
 * Styling matches the existing saas-security page (dark slate cards, blue accent).
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react'
import api from '@/lib/api'

// ── Types matching backend/routers/dspm.py ───────────────────────────────────

type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

interface DSPMFinding {
  id: string
  cloud: string
  resource_type: string
  resource_id: string
  object_key: string
  category: string
  severity: Severity
  pattern_name: string
  match_count: number
  redacted_sample: string
  confidence: number
  region: string
  metadata: Record<string, unknown>
  first_seen_at: string | null
  last_seen_at: string | null
  resolved_at: string | null
}

interface DSPMOverview {
  by_cloud: Record<string, Record<string, number>>
  categories: Record<string, number>
  total_open: number
  total_resolved: number
  last_scan_by_cloud: Record<string, string | null>
}

interface DSPMScan {
  id: string
  cloud: string
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
  resources_scanned: number
  objects_sampled: number
  bytes_inspected: number
  findings_count: number
  severity_counts: Record<string, number> | null
  category_counts: Record<string, number> | null
  status: string
}

interface DSPMPattern {
  name: string
  description: string
  category: string
  confidence: number
  enabled: boolean
  has_validator: boolean
}

interface AwsConnection {
  id: string
  name?: string
  account_id?: string
  default_region?: string
}

interface AzureConnection {
  id: string
  name?: string
  tenant_id?: string
  subscription_id?: string
}

interface GcpConnection {
  id: string
  name?: string
  project_id?: string
}

interface SaasIntegrationLite {
  id: string
  provider: string
  tenant_id?: string
  status?: string
}

type SubTab = 'overview' | 'findings' | 'patterns' | 'scans'

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
  low: 'text-blue-400',
  info: 'text-zinc-400',
}

const SEVERITY_BG: Record<Severity, string> = {
  critical: 'bg-red-500/15 border-red-500/30 text-red-300',
  high: 'bg-orange-500/15 border-orange-500/30 text-orange-300',
  medium: 'bg-amber-500/15 border-amber-500/30 text-amber-300',
  low: 'bg-blue-500/15 border-blue-500/30 text-blue-300',
  info: 'bg-zinc-500/15 border-zinc-500/30 text-zinc-300',
}

function Tile({
  label,
  value,
  sub,
  color,
}: {
  label: string
  value: number | string
  sub?: string
  color?: string
}) {
  return (
    <div className="bg-[#0f0f12] border border-[#1e1e24] rounded-xl p-3">
      <div className="text-[11px] uppercase tracking-wide text-zinc-500">
        {label}
      </div>
      <div className={`text-2xl font-semibold mt-1 ${color ?? 'text-zinc-100'}`}>
        {value}
      </div>
      {sub && <div className="text-[11px] text-zinc-500 mt-0.5">{sub}</div>}
    </div>
  )
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block text-[10px] px-2 py-0.5 rounded-md border ${SEVERITY_BG[severity]}`}
    >
      {severity.toUpperCase()}
    </span>
  )
}

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function fmtTime(s: string | null): string {
  if (!s) return '—'
  try {
    return new Date(s).toLocaleString()
  } catch {
    return s
  }
}

// ── Component ────────────────────────────────────────────────────────────────

export default function DataInventoryDSPM() {
  const [subTab, setSubTab] = useState<SubTab>('overview')
  const [overview, setOverview] = useState<DSPMOverview | null>(null)
  const [findings, setFindings] = useState<DSPMFinding[]>([])
  const [scans, setScans] = useState<DSPMScan[]>([])
  const [patterns, setPatterns] = useState<DSPMPattern[]>([])
  const [awsConns, setAwsConns] = useState<AwsConnection[]>([])
  const [azureConns, setAzureConns] = useState<AzureConnection[]>([])
  const [gcpConns, setGcpConns] = useState<GcpConnection[]>([])
  const [m365Integs, setM365Integs] = useState<SaasIntegrationLite[]>([])
  const [loading, setLoading] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)

  // Findings filters
  const [filterCloud, setFilterCloud] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterCategory, setFilterCategory] = useState('')
  const [filterStatus, setFilterStatus] = useState('open')

  const loadOverview = useCallback(async () => {
    try {
      const { data } = await api.get<DSPMOverview>('/api/dspm/overview')
      setOverview(data)
    } catch (err) {
      console.error('DSPM overview failed:', err)
    }
  }, [])

  const loadFindings = useCallback(async () => {
    setLoading(true)
    try {
      const params = new URLSearchParams()
      if (filterCloud) params.set('cloud', filterCloud)
      if (filterSeverity) params.set('severity', filterSeverity)
      if (filterCategory) params.set('category', filterCategory)
      if (filterStatus) params.set('status', filterStatus)
      params.set('limit', '500')
      const { data } = await api.get<DSPMFinding[]>(
        `/api/dspm/findings?${params.toString()}`,
      )
      setFindings(data)
    } catch (err) {
      console.error('DSPM findings failed:', err)
    } finally {
      setLoading(false)
    }
  }, [filterCloud, filterSeverity, filterCategory, filterStatus])

  const loadScans = useCallback(async () => {
    try {
      const { data } = await api.get<DSPMScan[]>('/api/dspm/scans')
      setScans(data)
    } catch (err) {
      console.error('DSPM scans failed:', err)
    }
  }, [])

  const loadPatterns = useCallback(async () => {
    try {
      const { data } = await api.get<{ patterns: DSPMPattern[]; total: number }>(
        '/api/dspm/patterns',
      )
      setPatterns(data.patterns ?? [])
    } catch (err) {
      console.error('DSPM patterns failed:', err)
    }
  }, [])

  const loadAwsConnections = useCallback(async () => {
    try {
      const { data } = await api.get<{ connections?: AwsConnection[] } | AwsConnection[]>(
        '/api/aws/connections',
      )
      const list = Array.isArray(data) ? data : data.connections ?? []
      setAwsConns(list)
    } catch (err) {
      console.error('AWS connections list failed:', err)
    }
  }, [])

  const loadAzureConnections = useCallback(async () => {
    try {
      const { data } = await api.get<
        { connections?: AzureConnection[] } | AzureConnection[]
      >('/api/azure/connections')
      const list = Array.isArray(data) ? data : data.connections ?? []
      setAzureConns(list)
    } catch (err) {
      console.error('Azure connections list failed:', err)
    }
  }, [])

  const loadGcpConnections = useCallback(async () => {
    try {
      const { data } = await api.get<
        { connections?: GcpConnection[] } | GcpConnection[]
      >('/api/gcp/connections')
      const list = Array.isArray(data) ? data : data.connections ?? []
      setGcpConns(list)
    } catch (err) {
      console.error('GCP connections list failed:', err)
    }
  }, [])

  const loadM365Integrations = useCallback(async () => {
    try {
      const { data } = await api.get<
        { integrations?: SaasIntegrationLite[] } | SaasIntegrationLite[]
      >('/api/saas/integrations')
      const list = Array.isArray(data) ? data : data.integrations ?? []
      // Keep only one row per M365 tenant — a single Graph token serves
      // both teams + sharepoint sub-providers.
      const seen = new Set<string>()
      const deduped: SaasIntegrationLite[] = []
      for (const i of list) {
        if (!['m365', 'teams', 'sharepoint'].includes(i.provider)) continue
        const key = i.tenant_id || i.id
        if (seen.has(key)) continue
        seen.add(key)
        deduped.push(i)
      }
      setM365Integs(deduped)
    } catch (err) {
      console.error('SaaS integrations list failed:', err)
    }
  }, [])

  // Initial load
  useEffect(() => {
    loadOverview()
    loadAwsConnections()
    loadAzureConnections()
    loadGcpConnections()
    loadM365Integrations()
  }, [
    loadOverview,
    loadAwsConnections,
    loadAzureConnections,
    loadGcpConnections,
    loadM365Integrations,
  ])

  // Tab-driven loads
  useEffect(() => {
    if (subTab === 'findings') loadFindings()
    if (subTab === 'scans') loadScans()
    if (subTab === 'patterns' && patterns.length === 0) loadPatterns()
  }, [subTab, loadFindings, loadScans, loadPatterns, patterns.length])

  // Manual triggerAwsScan / triggerM365Scan removed — auto-scan every 5
  // min covers both. UI buttons removed in the render below as well.

  const triggerAzureScan = useCallback(
    async (connectionId: string) => {
      setScanning(connectionId)
      setMessage(null)
      try {
        await api.post(`/api/dspm/scan/azure/${connectionId}`)
        setMessage('DSPM Azure scan started in the background.')
        setTimeout(() => {
          loadOverview()
          loadScans()
        }, 5000)
      } catch (err: unknown) {
        const m = err instanceof Error ? err.message : 'Failed to start scan'
        setMessage(`Failed to start scan: ${m}`)
      } finally {
        setScanning(null)
      }
    },
    [loadOverview, loadScans],
  )

  const triggerGcpScan = useCallback(
    async (connectionId: string) => {
      setScanning(connectionId)
      setMessage(null)
      try {
        await api.post(`/api/dspm/scan/gcp/${connectionId}`)
        setMessage('DSPM GCP scan started in the background.')
        setTimeout(() => {
          loadOverview()
          loadScans()
        }, 5000)
      } catch (err: unknown) {
        const m = err instanceof Error ? err.message : 'Failed to start scan'
        setMessage(`Failed to start scan: ${m}`)
      } finally {
        setScanning(null)
      }
    },
    [loadOverview, loadScans],
  )

  const resolveOne = useCallback(
    async (id: string) => {
      try {
        await api.post(`/api/dspm/findings/${id}/resolve`)
        loadFindings()
        loadOverview()
      } catch (err) {
        console.error('resolve failed:', err)
      }
    },
    [loadFindings, loadOverview],
  )

  const reopenOne = useCallback(
    async (id: string) => {
      try {
        await api.post(`/api/dspm/findings/${id}/reopen`)
        loadFindings()
        loadOverview()
      } catch (err) {
        console.error('reopen failed:', err)
      }
    },
    [loadFindings, loadOverview],
  )

  const severityTotals: Record<Severity, number> = useMemo(() => {
    const acc: Record<Severity, number> = {
      info: 0, low: 0, medium: 0, high: 0, critical: 0,
    }
    if (!overview) return acc
    for (const cloud of Object.keys(overview.by_cloud)) {
      const row = overview.by_cloud[cloud]
      for (const sev of Object.keys(row) as Severity[]) {
        acc[sev] = (acc[sev] ?? 0) + (row[sev] ?? 0)
      }
    }
    return acc
  }, [overview])

  const topCategories = useMemo(() => {
    if (!overview) return []
    return Object.entries(overview.categories)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
  }, [overview])

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-4 mt-6">
      {/* Header + scan triggers */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-[15px] font-semibold text-zinc-100">
            Sensitive Data Discovery (DSPM)
          </h3>
          <p className="text-[12px] text-zinc-500 mt-0.5">
            Scans every connected source (AWS, Azure, GCP, Oracle, Microsoft 365, Databricks,
            GitHub, SAP, Snowflake, Salesforce) for PII, PCI, PHI, credentials, financial,
            and customer data. AWS · Azure · GCP · M365 run signature-based content scans;
            every other connector is classified by the heuristic DLP engine and mirrored
            into this view.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {awsConns.length === 0 &&
          azureConns.length === 0 &&
          gcpConns.length === 0 &&
          m365Integs.length === 0 ? (
            <div className="text-[12px] text-zinc-500 px-3 py-1.5 border border-[#1e1e24] rounded-lg">
              Connect any source — AWS, Azure, GCP, Oracle, Microsoft 365, Databricks, GitHub, SAP, Snowflake, or Salesforce — to enable DSPM scans.
            </div>
          ) : (
            <>
              {/* AWS and M365 manual scan buttons removed — auto-scan every 5 min
                  handles those. Azure and GCP retained for now since their
                  background loops are newer and users may want to force a run. */}
              {azureConns.map((c) => (
                <button
                  key={`azure-${c.id}`}
                  disabled={scanning === c.id}
                  onClick={() => triggerAzureScan(c.id)}
                  className="text-[12px] bg-[#0078d4] hover:bg-[#1a8cdb] disabled:opacity-50 text-white px-3 py-1.5 rounded-lg"
                >
                  {scanning === c.id
                    ? 'Scanning…'
                    : `Scan Azure · ${c.name || c.subscription_id?.slice(0, 8) || c.id.slice(0, 8)}`}
                </button>
              ))}
              {gcpConns.map((c) => (
                <button
                  key={`gcp-${c.id}`}
                  disabled={scanning === c.id}
                  onClick={() => triggerGcpScan(c.id)}
                  className="text-[12px] bg-[#4285F4] hover:bg-[#5b95f6] disabled:opacity-50 text-white px-3 py-1.5 rounded-lg"
                >
                  {scanning === c.id
                    ? 'Scanning…'
                    : `Scan GCP · ${c.project_id || c.name || c.id.slice(0, 8)}`}
                </button>
              ))}
            </>
          )}
          <div className="text-[11px] text-zinc-500 px-2 py-1.5 self-center">
            Auto-scans every 5 min
          </div>
        </div>
      </div>

      {message && (
        <div className="text-[12px] bg-[#0f0f12] border border-[#1e1e24] rounded-lg px-3 py-2 text-zinc-300">
          {message}
        </div>
      )}

      {/* Sub-tabs */}
      <div className="flex gap-1 border-b border-[#1e1e24]">
        {(['overview', 'findings', 'patterns', 'scans'] as SubTab[]).map((t) => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`text-[12px] px-3 py-1.5 -mb-px border-b-2 ${
              subTab === t
                ? 'border-[#3b6ef6] text-zinc-100'
                : 'border-transparent text-zinc-500 hover:text-zinc-300'
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* Overview sub-tab */}
      {subTab === 'overview' && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Tile label="Critical" value={severityTotals.critical} color={SEVERITY_COLOR.critical} />
            <Tile label="High" value={severityTotals.high} color={SEVERITY_COLOR.high} />
            <Tile label="Medium" value={severityTotals.medium} color={SEVERITY_COLOR.medium} />
            <Tile label="Low" value={severityTotals.low} color={SEVERITY_COLOR.low} />
            <Tile
              label="Resolved"
              value={overview?.total_resolved ?? 0}
              color="text-emerald-400"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="bg-[#0f0f12] border border-[#1e1e24] rounded-xl p-4">
              <div className="text-[12px] text-zinc-400 mb-2">Top categories</div>
              {topCategories.length === 0 ? (
                <div className="text-[12px] text-zinc-500">No findings yet.</div>
              ) : (
                <ul className="space-y-1">
                  {topCategories.map(([cat, n]) => (
                    <li
                      key={cat}
                      className="flex items-center justify-between text-[12px]"
                    >
                      <span className="text-zinc-300">{cat}</span>
                      <span className="text-zinc-500">{n}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div className="bg-[#0f0f12] border border-[#1e1e24] rounded-xl p-4">
              <div className="text-[12px] text-zinc-400 mb-2">Last scan</div>
              {overview && Object.keys(overview.last_scan_by_cloud).length > 0 ? (
                <ul className="space-y-1">
                  {Object.entries(overview.last_scan_by_cloud).map(([cloud, ts]) => (
                    <li
                      key={cloud}
                      className="flex items-center justify-between text-[12px]"
                    >
                      <span className="text-zinc-300">{cloud}</span>
                      <span className="text-zinc-500">{fmtTime(ts)}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-[12px] text-zinc-500">
                  No scans yet — trigger one above.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Findings sub-tab */}
      {subTab === 'findings' && (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <select
              value={filterCloud}
              onChange={(e) => setFilterCloud(e.target.value)}
              className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5"
            >
              <option value="">All Clouds</option>
              <option value="aws">AWS</option>
              <option value="m365">Microsoft 365</option>
              <option value="gcp">GCP</option>
              <option value="azure">Azure</option>
              <option value="salesforce">Salesforce</option>
              {/* Adnan 2026-06-23 (turn 3): all remaining connectors */}
              <option value="oracle">Oracle</option>
              <option value="databricks">Databricks</option>
              <option value="github">GitHub</option>
              <option value="sap">SAP</option>
              <option value="snowflake">Snowflake</option>
            </select>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5"
            >
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="">All</option>
            </select>
            <input
              placeholder="Category contains…"
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 w-48"
            />
          </div>

          <div className="bg-[#0f0f12] border border-[#1e1e24] rounded-xl overflow-hidden">
            <table className="w-full text-[12px]">
              <thead className="bg-[#111114] text-zinc-400">
                <tr>
                  <th className="text-left px-3 py-2">Severity</th>
                  <th className="text-left px-3 py-2">Category</th>
                  <th className="text-left px-3 py-2">Resource</th>
                  <th className="text-left px-3 py-2">Pattern</th>
                  <th className="text-right px-3 py-2">Matches</th>
                  <th className="text-left px-3 py-2">Last seen</th>
                  <th className="text-right px-3 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr>
                    <td colSpan={7} className="text-center py-6 text-zinc-500">
                      Loading…
                    </td>
                  </tr>
                )}
                {!loading && findings.length === 0 && (
                  <tr>
                    <td colSpan={7} className="text-center py-6 text-zinc-500">
                      No findings.
                    </td>
                  </tr>
                )}
                {!loading &&
                  findings.map((f) => (
                    <tr
                      key={f.id}
                      className="border-t border-[#1e1e24] hover:bg-[#111114]/60"
                    >
                      <td className="px-3 py-2">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-3 py-2 text-zinc-300">{f.category}</td>
                      <td className="px-3 py-2 text-zinc-300 max-w-[260px] truncate">
                        <span className="text-zinc-500">
                          {f.cloud}/{f.resource_type}/
                        </span>
                        {f.resource_id}/{f.object_key}
                      </td>
                      <td className="px-3 py-2 text-zinc-400">{f.pattern_name}</td>
                      <td className="px-3 py-2 text-right text-zinc-300">
                        {f.match_count}
                      </td>
                      <td className="px-3 py-2 text-zinc-500">
                        {fmtTime(f.last_seen_at)}
                      </td>
                      <td className="px-3 py-2 text-right">
                        {f.resolved_at ? (
                          <button
                            onClick={() => reopenOne(f.id)}
                            className="text-[11px] text-blue-300 hover:underline"
                          >
                            Reopen
                          </button>
                        ) : (
                          <button
                            onClick={() => resolveOne(f.id)}
                            className="text-[11px] text-emerald-300 hover:underline"
                          >
                            Resolve
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Patterns sub-tab */}
      {subTab === 'patterns' && (
        <div className="bg-[#0f0f12] border border-[#1e1e24] rounded-xl overflow-hidden">
          <table className="w-full text-[12px]">
            <thead className="bg-[#111114] text-zinc-400">
              <tr>
                <th className="text-left px-3 py-2">Pattern</th>
                <th className="text-left px-3 py-2">Description</th>
                <th className="text-left px-3 py-2">Category</th>
                <th className="text-right px-3 py-2">Confidence</th>
                <th className="text-left px-3 py-2">Validator</th>
              </tr>
            </thead>
            <tbody>
              {patterns.length === 0 && (
                <tr>
                  <td colSpan={5} className="text-center py-6 text-zinc-500">
                    Loading patterns…
                  </td>
                </tr>
              )}
              {patterns.map((p) => (
                <tr
                  key={p.name}
                  className="border-t border-[#1e1e24] hover:bg-[#111114]/60"
                >
                  <td className="px-3 py-2 text-zinc-200">{p.name}</td>
                  <td className="px-3 py-2 text-zinc-400">{p.description}</td>
                  <td className="px-3 py-2 text-zinc-400">{p.category}</td>
                  <td className="px-3 py-2 text-right text-zinc-400">
                    {(p.confidence * 100).toFixed(0)}%
                  </td>
                  <td className="px-3 py-2 text-zinc-500">
                    {p.has_validator ? 'yes' : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Scans sub-tab */}
      {subTab === 'scans' && (
        <div className="bg-[#0f0f12] border border-[#1e1e24] rounded-xl overflow-hidden">
          <table className="w-full text-[12px]">
            <thead className="bg-[#111114] text-zinc-400">
              <tr>
                <th className="text-left px-3 py-2">Cloud</th>
                <th className="text-left px-3 py-2">Started</th>
                <th className="text-right px-3 py-2">Duration</th>
                <th className="text-right px-3 py-2">Resources</th>
                <th className="text-right px-3 py-2">Objects</th>
                <th className="text-right px-3 py-2">Bytes</th>
                <th className="text-right px-3 py-2">Findings</th>
                <th className="text-left px-3 py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 && (
                <tr>
                  <td colSpan={8} className="text-center py-6 text-zinc-500">
                    No scans yet.
                  </td>
                </tr>
              )}
              {scans.map((s) => (
                <tr
                  key={s.id}
                  className="border-t border-[#1e1e24] hover:bg-[#111114]/60"
                >
                  <td className="px-3 py-2 text-zinc-300">{s.cloud}</td>
                  <td className="px-3 py-2 text-zinc-400">{fmtTime(s.started_at)}</td>
                  <td className="px-3 py-2 text-right text-zinc-400">
                    {s.duration_ms ? `${(s.duration_ms / 1000).toFixed(1)}s` : '—'}
                  </td>
                  <td className="px-3 py-2 text-right text-zinc-400">
                    {s.resources_scanned}
                  </td>
                  <td className="px-3 py-2 text-right text-zinc-400">
                    {s.objects_sampled}
                  </td>
                  <td className="px-3 py-2 text-right text-zinc-400">
                    {fmtBytes(s.bytes_inspected)}
                  </td>
                  <td className="px-3 py-2 text-right text-zinc-300">
                    {s.findings_count}
                  </td>
                  <td className="px-3 py-2 text-zinc-400">{s.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
