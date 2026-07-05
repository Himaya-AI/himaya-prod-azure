"use client"

/**
 * CSPM Connector Cards — Azure, Oracle Cloud Infrastructure, GitHub.
 *
 * Self-contained component used inside the Connectors tab of the
 * Workspace Security page. Talks to /api/azure, /api/oracle, /api/github,
 * and /api/cspm endpoints.
 */
import React, { useEffect, useState, useCallback } from 'react'
import Button from '@/components/ui/Button'
import api from '@/lib/api'
import {
  Github, Plug, Unplug, RefreshCw, X,
  CheckCircle2, AlertTriangle, Shield,
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────────

type CspmCloud = 'azure' | 'oracle' | 'github'

interface CspmConnection {
  id: string
  name: string
  status: string
  created_at: string
  last_scan_at: string | null
}

interface AzureConnection extends CspmConnection {
  tenant_id: string
  subscription_id: string
  scan_locations: string[]
}

interface OracleConnection extends CspmConnection {
  tenancy_id: string
  region: string
}

interface GitHubConnection extends CspmConnection {
  org: string
  max_repos: number
}

interface CspmStats {
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  last_scan_at: string | null
}

// ── Per-cloud config (icon, color, fields, endpoints) ───────────────────────

const CLOUD_CONFIG: Record<CspmCloud, {
  name: string
  desc: string
  bgClass: string
  Icon: React.FC<{ size?: number; className?: string }>
  endpoint: string
}> = {
  azure: {
    name: 'Microsoft Azure',
    desc: 'Storage, Key Vault, SQL, VM, NSG + Defender for Cloud',
    bgClass: 'bg-[#0078D4]/10',
    // Official Microsoft Azure logo from simple-icons (CC0). The previous path
    // was a malformed two-triangle composite that didn't render as the brand mark.
    Icon: ({ size = 22, className = '' }) => (
      <svg width={size} height={size} viewBox="0 0 24 24" className={className} fill="#0078D4">
        <path d="M5.483 21.3H24L14.025 4.05a1.05 1.05 0 0 0-1.83.001L10.34 7.22l5.04 8.652-9.897 5.428zM10.04 7.74L1.8 21.3h7.575L3.8 16.25l6.24-8.51z"/>
      </svg>
    ),
    endpoint: '/api/azure',
  },
  oracle: {
    name: 'Oracle Cloud Infrastructure',
    desc: 'IAM, VCN, Object Storage, KMS + Audit',
    bgClass: 'bg-[#C74634]/10',
    Icon: ({ size = 22, className = '' }) => (
      <svg width={size} height={size} viewBox="0 0 24 24" className={className} fill="#C74634">
        <path d="M16.412 4.412H7.588a7.588 7.588 0 1 0 0 15.176h8.824a7.588 7.588 0 1 0 0-15.176zm-.17 12.353H7.756a4.765 4.765 0 1 1 0-9.53h8.486a4.765 4.765 0 1 1 0 9.53z"/>
      </svg>
    ),
    endpoint: '/api/oracle',
  },
  github: {
    name: 'GitHub',
    desc: 'Repos, branch protection, secrets + Dependabot, code scanning',
    bgClass: 'bg-white/5',
    Icon: ({ size = 22, className = '' }) => <Github size={size} className={className} />,
    endpoint: '/api/github',
  },
}

// ── Single connector card ────────────────────────────────────────────────────

interface CardProps {
  cloud: CspmCloud
  connections: CspmConnection[]
  stats: CspmStats | null
  scanning: string | null
  onAdd: () => void
  onScan: (id: string) => void
  onDisconnect: (id: string) => void
}

function ConnectorCard({
  cloud, connections, stats, scanning, onAdd, onScan, onDisconnect,
}: CardProps) {
  const cfg = CLOUD_CONFIG[cloud]
  const Icon = cfg.Icon

  return (
    <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5 hover:border-white/[0.12] transition-colors">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${cfg.bgClass}`}>
            <Icon size={22} />
          </div>
          <div>
            <span className="font-semibold text-[var(--foreground)]">{cfg.name}</span>
            <p className="text-[11px] text-[var(--muted)] max-w-[280px]">{cfg.desc}</p>
          </div>
        </div>
        {connections.length === 0 ? (
          <Button size="sm" onClick={onAdd}>
            <Plug size={13} className="mr-1" /> Connect
          </Button>
        ) : (
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-emerald-500/10 border-emerald-500/20 text-emerald-400">
              {connections.length} connected
            </span>
            <Button size="sm" variant="ghost" onClick={onAdd}>
              <Plug size={11} />
            </Button>
          </div>
        )}
      </div>

      {/* Stats */}
      {stats && connections.length > 0 && (
        <div className="grid grid-cols-4 gap-2 mt-3 pt-3 border-t border-[var(--border)]">
          <Stat label="Findings" value={stats.total_findings} color="text-[var(--foreground)]" />
          <Stat label="Critical" value={stats.critical_findings} color="text-red-400" />
          <Stat label="High" value={stats.high_findings} color="text-orange-400" />
          <Stat label="Medium" value={stats.medium_findings} color="text-amber-400" />
        </div>
      )}

      {/* Connection rows */}
      {connections.length > 0 && (
        <div className="mt-3 space-y-2">
          {connections.map(conn => (
            <div key={conn.id} className="bg-[var(--background)]/50 rounded-lg p-2 flex items-center justify-between">
              <div className="min-w-0">
                <div className="text-[11px] font-medium text-[var(--foreground)] truncate">{conn.name}</div>
                <div className="text-[9px] text-[var(--muted)] truncate">
                  {(conn as AzureConnection).subscription_id
                    || (conn as OracleConnection).tenancy_id
                    || (conn as GitHubConnection).org
                    || conn.id.slice(0, 8)}
                  {conn.last_scan_at && (
                    <span className="ml-2 text-emerald-400">
                      <CheckCircle2 size={9} className="inline-block mr-0.5" />
                      Last scan: {new Date(conn.last_scan_at).toLocaleString()}
                    </span>
                  )}
                  {!conn.last_scan_at && (
                    <span className="ml-2 text-amber-400">
                      <AlertTriangle size={9} className="inline-block mr-0.5" />
                      Never scanned
                    </span>
                  )}
                </div>
              </div>
              <div className="flex gap-1 shrink-0">
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => onScan(conn.id)}
                  disabled={scanning === conn.id}
                  title="Run scan"
                >
                  <RefreshCw size={11} className={scanning === conn.id ? 'animate-spin' : ''} />
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => onDisconnect(conn.id)}
                  className="text-red-400"
                  title="Disconnect"
                >
                  <Unplug size={11} />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {connections.length === 0 && (
        <div className="text-center py-4 mt-3 border-t border-[var(--border)]">
          <span className="text-[11px] text-[var(--muted)]">No {cfg.name} connection yet</span>
        </div>
      )}
    </div>
  )
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="text-center">
      <div className={`text-[14px] font-bold ${color}`}>{value}</div>
      <div className="text-[9px] text-[var(--muted)]">{label}</div>
    </div>
  )
}

// ── Connect modals ───────────────────────────────────────────────────────────

interface ConnectModalProps {
  cloud: CspmCloud
  onClose: () => void
  onConnected: () => void
}

function ConnectModal({ cloud, onClose, onConnected }: ConnectModalProps) {
  const cfg = CLOUD_CONFIG[cloud]
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [form, setForm] = useState<Record<string, string>>({})

  const set = (k: string, v: string) => setForm(prev => ({ ...prev, [k]: v }))

  async function submit() {
    setSubmitting(true)
    setError(null)
    try {
      let body: Record<string, unknown> = { name: form.name || cfg.name }
      if (cloud === 'azure') {
        body = {
          ...body,
          tenant_id: form.tenant_id,
          client_id: form.client_id,
          client_secret: form.client_secret,
          subscription_id: form.subscription_id,
          scan_locations: form.scan_locations
            ? form.scan_locations.split(',').map(s => s.trim()).filter(Boolean)
            : ['eastus', 'westus', 'westus2', 'westeurope', 'northeurope'],
        }
      } else if (cloud === 'oracle') {
        body = {
          ...body,
          tenancy_id: form.tenancy_id,
          user_id: form.user_id,
          key_fingerprint: form.key_fingerprint,
          private_key_pem: form.private_key_pem,
          region: form.region || 'us-ashburn-1',
          compartment_id: form.compartment_id || undefined,
        }
      } else if (cloud === 'github') {
        body = {
          ...body,
          token: form.token,
          org: form.org,
          max_repos: form.max_repos ? parseInt(form.max_repos, 10) : 200,
        }
      }
      const res = await api.post(`${cfg.endpoint}/connect`, body)
      if (res.status >= 200 && res.status < 300) {
        onConnected()
        onClose()
      } else {
        setError((res.data?.detail as string) || 'Unknown error')
      }
    } catch (e: unknown) {
      const err = e as { response?: { data?: { detail?: string } } }
      setError(err.response?.data?.detail || 'Connection failed')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <div
        className="bg-[#13131a] border border-[var(--border)] rounded-xl p-6 w-full max-w-[520px] max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${cfg.bgClass}`}>
              <cfg.Icon size={22} />
            </div>
            <div>
              <h2 className="text-[15px] font-semibold text-[var(--foreground)]">
                Connect {cfg.name}
              </h2>
              <p className="text-[11px] text-[var(--muted)]">{cfg.desc}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-[var(--muted)] hover:text-[var(--foreground)]">
            <X size={18} />
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-[12px]">
            {error}
          </div>
        )}

        <div className="space-y-3">
          <Field label="Display name (optional)" value={form.name || ''} onChange={v => set('name', v)} placeholder={cfg.name} />

          {cloud === 'azure' && (
            <>
              <AzureSetupGuide />
              <Field
                label="Tenant ID"
                value={form.tenant_id || ''}
                onChange={v => set('tenant_id', v)}
                placeholder="00000000-0000-0000-0000-000000000000"
                hint="Microsoft Entra ID → Overview → Tenant ID. Same as Directory (tenant) ID on the app registration."
              />
              <Field
                label="Client ID (Application ID)"
                value={form.client_id || ''}
                onChange={v => set('client_id', v)}
                placeholder="00000000-0000-0000-0000-000000000000"
                hint="App registration → Overview → Application (client) ID."
              />
              <Field
                label="Client secret"
                value={form.client_secret || ''}
                onChange={v => set('client_secret', v)}
                placeholder="••••••••"
                type="password"
                hint='App registration → Certificates & secrets → New client secret. Copy the "Value" (not the Secret ID). Shown only once.'
              />
              <Field
                label="Subscription ID"
                value={form.subscription_id || ''}
                onChange={v => set('subscription_id', v)}
                placeholder="00000000-0000-0000-0000-000000000000"
                hint='Azure portal → Subscriptions → copy "Subscription ID" (a GUID). Or run `az account show --query id -o tsv`.'
              />
              <Field
                label="Scan locations (comma-separated, optional)"
                value={form.scan_locations || ''}
                onChange={v => set('scan_locations', v)}
                placeholder="eastus, westus, westeurope"
                hint="Leave blank to use defaults. Most ARM resources are returned globally regardless."
              />
            </>
          )}

          {cloud === 'oracle' && (
            <>
              <Field label="Tenancy OCID" value={form.tenancy_id || ''} onChange={v => set('tenancy_id', v)} placeholder="ocid1.tenancy.oc1..." />
              <Field label="User OCID" value={form.user_id || ''} onChange={v => set('user_id', v)} placeholder="ocid1.user.oc1..." />
              <Field label="Key fingerprint" value={form.key_fingerprint || ''} onChange={v => set('key_fingerprint', v)} placeholder="aa:bb:cc:dd:..." />
              <TextArea
                label="Private key (PEM, full -----BEGIN/END----- block)"
                value={form.private_key_pem || ''}
                onChange={v => set('private_key_pem', v)}
                placeholder="-----BEGIN PRIVATE KEY-----..."
                rows={6}
              />
              <Field label="Home region" value={form.region || ''} onChange={v => set('region', v)} placeholder="us-ashburn-1" />
              <Field label="Compartment OCID (optional, defaults to tenancy)" value={form.compartment_id || ''} onChange={v => set('compartment_id', v)} placeholder="ocid1.compartment.oc1..." />
              <Help>
                Generate an API signing key (<code>oci setup keys</code>), upload the public key to your
                user, and paste the private key + fingerprint here.
              </Help>
            </>
          )}

          {cloud === 'github' && (
            <>
              <Field label="Organization name" value={form.org || ''} onChange={v => set('org', v)} placeholder="my-org" />
              <Field label="Personal access token (fine-grained or classic)" value={form.token || ''} onChange={v => set('token', v)} placeholder="ghp_..." type="password" />
              <Field label="Max repos to scan (optional, default 200)" value={form.max_repos || ''} onChange={v => set('max_repos', v)} placeholder="200" />
              <Help>
                Token needs <code>read:org</code>, <code>repo</code>, and <code>admin:org</code> (read)
                scopes. Fine-grained PATs require: Administration (read), Code scanning alerts (read),
                Dependabot alerts (read), Metadata (read), Secret scanning alerts (read), Webhooks (read).
              </Help>
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 mt-5">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={submit} disabled={submitting}>
            {submitting && <RefreshCw size={12} className="mr-1 animate-spin" />}
            Connect &amp; scan
          </Button>
        </div>
      </div>
    </div>
  )
}

function Field({ label, value, onChange, placeholder, type = 'text', hint }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string; type?: string; hint?: string;
}) {
  return (
    <label className="block">
      <div className="text-[11px] text-[var(--muted)] mb-1">{label}</div>
      <input
        value={value}
        type={type}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-[var(--background)] border border-[var(--border)] rounded-lg px-3 py-2 text-[12px] text-[var(--foreground)] focus:border-white/20 focus:outline-none"
      />
      {hint && (
        <div className="text-[10px] text-[var(--muted)] mt-1 leading-snug">{hint}</div>
      )}
    </label>
  )
}

function TextArea({ label, value, onChange, placeholder, rows = 4 }: {
  label: string; value: string; onChange: (v: string) => void; placeholder?: string; rows?: number;
}) {
  return (
    <label className="block">
      <div className="text-[11px] text-[var(--muted)] mb-1">{label}</div>
      <textarea
        value={value}
        rows={rows}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-[var(--background)] border border-[var(--border)] rounded-lg px-3 py-2 text-[11px] font-mono text-[var(--foreground)] focus:border-white/20 focus:outline-none"
      />
    </label>
  )
}

function Help({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex gap-2 p-2 rounded-lg bg-blue-500/5 border border-blue-500/15 text-[10px] text-[var(--muted)]">
      <Shield size={11} className="shrink-0 mt-0.5 text-blue-400" />
      <span>{children}</span>
    </div>
  )
}

// ── Azure setup guide (collapsible) ─────────────────────────────────────────

function AzureSetupGuide() {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-lg border border-blue-500/20 bg-blue-500/5">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between gap-2 px-3 py-2 text-left"
      >
        <div className="flex items-center gap-2">
          <Shield size={12} className="text-blue-400" />
          <span className="text-[12px] font-medium text-[var(--foreground)]">
            How to set up Azure access (5 minutes)
          </span>
        </div>
        <span className="text-[11px] text-[var(--muted)]">{open ? 'Hide' : 'Show'}</span>
      </button>
      {open && (
        <div className="px-3 pb-3 text-[11px] text-[var(--muted)] leading-relaxed space-y-3">
          <p>
            We use Microsoft&apos;s standard service-principal flow (the same one Azure CLI uses).
            You create an app registration in Entra ID, grant it read-only RBAC on the subscription,
            and paste 4 IDs below. Everything is read-only — we never write to Azure.
          </p>

          <div>
            <div className="text-[var(--foreground)] font-medium mb-1">1 · Create an app registration</div>
            <ol className="list-decimal ml-4 space-y-0.5">
              <li>Go to <a className="text-blue-400 underline" href="https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade" target="_blank" rel="noreferrer">portal.azure.com → Microsoft Entra ID → App registrations</a></li>
              <li>Click <b>+ New registration</b>. Name it e.g. <code>helios-cspm</code>. Leave defaults (single tenant, no redirect URI). Click <b>Register</b>.</li>
              <li>On the Overview page copy <b>Application (client) ID</b> and <b>Directory (tenant) ID</b> — these are the Client ID and Tenant ID fields below.</li>
            </ol>
          </div>

          <div>
            <div className="text-[var(--foreground)] font-medium mb-1">2 · Create a client secret</div>
            <ol className="list-decimal ml-4 space-y-0.5">
              <li>Same app → <b>Certificates &amp; secrets</b> → <b>+ New client secret</b>.</li>
              <li>Set an expiry (Microsoft default: 180 days; max 24 months). Click <b>Add</b>.</li>
              <li>Copy the <b>Value</b> column immediately — it&apos;s only shown once. Paste it into <b>Client secret</b> below.</li>
            </ol>
          </div>

          <div>
            <div className="text-[var(--foreground)] font-medium mb-1">3 · Find your Subscription ID</div>
            <ol className="list-decimal ml-4 space-y-0.5">
              <li>Search the portal for <a className="text-blue-400 underline" href="https://portal.azure.com/#view/Microsoft_Azure_Billing/SubscriptionsBladeV2" target="_blank" rel="noreferrer">Subscriptions</a> (or run <code>az account show --query id -o tsv</code>).</li>
              <li>Copy the GUID in the <b>Subscription ID</b> column. If you don&apos;t see any subscription, you only have an Entra-only tenant — you need to create or be invited to an Azure subscription first.</li>
            </ol>
          </div>

          <div>
            <div className="text-[var(--foreground)] font-medium mb-1">4 · Grant read-only roles on the subscription</div>
            <p className="mb-1">Open <b>Subscriptions → [your sub] → Access control (IAM) → + Add → Add role assignment</b>. All three are real Azure built-in roles assigned at the <b>subscription</b> scope:</p>
            <ul className="list-disc ml-4 space-y-0.5">
              <li>
                <b>Reader</b> <span className="opacity-70">(required — this one resolves the connection)</span> — the built-in <code>Reader</code> role grants <code>*/read</code>, so it inventories Storage, Key Vault, SQL, NSGs, VMs, disks, App Services, public IPs <i>and</i> covers Defender for Cloud plans / auto-provisioning and role-assignment reads. This single role is enough for a full scan.
              </li>
              <li>
                <b>Key Vault Reader</b> <span className="opacity-70">(optional)</span> — only needed to enumerate Key Vault key/secret <i>metadata</i> (names/enabled state — never the values). <code>Reader</code> can&apos;t see Key Vault data-plane objects; without this role the Key Vault object checks are skipped silently.
              </li>
              <li>
                <b>Security Reader</b> <span className="opacity-70">(optional)</span> — not required for the current scan (<code>Reader</code> already covers the Defender plan/auto-provisioning checks). Add it only if you later enable ingestion of Defender for Cloud assessments and security alerts.
              </li>
            </ul>
            <p className="mt-1">
              For each role: pick the role → <b>Next</b> → <b>Assign access to: User, group, or service principal</b> → <b>+ Select members</b> → search for your app registration name → <b>Select</b> → <b>Review + assign</b>.
            </p>
          </div>

          <div>
            <div className="text-[var(--foreground)] font-medium mb-1">CLI shortcut</div>
            <pre className="bg-[var(--background)] border border-[var(--border)] rounded p-2 overflow-x-auto text-[10px] font-mono leading-relaxed">{`# Create app + service principal
az ad sp create-for-rbac --name helios-cspm --skip-assignment
# Returns: appId (= Client ID), password (= Client secret), tenant (= Tenant ID)

SUB=$(az account show --query id -o tsv)
SP_APP_ID=<appId from above>

# Required
az role assignment create --assignee "$SP_APP_ID" \
  --role "Reader" --scope "/subscriptions/$SUB"

# Recommended
az role assignment create --assignee "$SP_APP_ID" \
  --role "Security Reader" --scope "/subscriptions/$SUB"

# Optional (Key Vault metadata)
az role assignment create --assignee "$SP_APP_ID" \
  --role "Key Vault Reader" --scope "/subscriptions/$SUB"`}</pre>
          </div>

          <div className="pt-1 border-t border-[var(--border)]">
            <div className="text-[var(--foreground)] font-medium mb-1">Microsoft references</div>
            <ul className="list-disc ml-4 space-y-0.5">
              <li><a className="text-blue-400 underline" href="https://learn.microsoft.com/en-us/entra/identity-platform/howto-create-service-principal-portal" target="_blank" rel="noreferrer">Create an app + service principal (Microsoft Learn)</a></li>
              <li><a className="text-blue-400 underline" href="https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#reader" target="_blank" rel="noreferrer">Built-in role: Reader</a></li>
              <li><a className="text-blue-400 underline" href="https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#security-reader" target="_blank" rel="noreferrer">Built-in role: Security Reader</a></li>
              <li><a className="text-blue-400 underline" href="https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#key-vault-reader" target="_blank" rel="noreferrer">Built-in role: Key Vault Reader</a></li>
              <li><a className="text-blue-400 underline" href="https://learn.microsoft.com/en-us/azure/azure-portal/get-subscription-tenant-id" target="_blank" rel="noreferrer">Find your Azure subscription &amp; tenant ID</a></li>
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Top-level component ──────────────────────────────────────────────────────

export interface CSPMConnectorsProps {
  /**
   * Which clouds to render. Default ['azure', 'oracle', 'github'] preserves
   * the original behavior. Pass ['azure', 'oracle'] to embed inside a Cloud
   * Infrastructure section and ['github'] for a dedicated Code Security
   * section.
   */
  clouds?: CspmCloud[]
}

export default function CSPMConnectors({ clouds }: CSPMConnectorsProps = {}) {
  const visibleClouds: CspmCloud[] = clouds && clouds.length > 0
    ? clouds
    : ['azure', 'oracle', 'github']
  const [azureConns, setAzureConns] = useState<AzureConnection[]>([])
  const [oracleConns, setOracleConns] = useState<OracleConnection[]>([])
  const [githubConns, setGithubConns] = useState<GitHubConnection[]>([])
  const [stats, setStats] = useState<Record<CspmCloud, CspmStats | null>>({
    azure: null, oracle: null, github: null,
  })
  const [scanning, setScanning] = useState<string | null>(null)
  const [modal, setModal] = useState<CspmCloud | null>(null)

  const reload = useCallback(async () => {
    try {
      const [az, oc, gh, sAz, sOc, sGh] = await Promise.all([
        api.get('/api/azure/connections'),
        api.get('/api/oracle/connections'),
        api.get('/api/github/connections'),
        api.get('/api/azure/stats'),
        api.get('/api/oracle/stats'),
        api.get('/api/github/stats'),
      ])
      setAzureConns(Array.isArray(az.data) ? az.data : [])
      setOracleConns(Array.isArray(oc.data) ? oc.data : [])
      setGithubConns(Array.isArray(gh.data) ? gh.data : [])
      setStats({
        azure: sAz.data || null,
        oracle: sOc.data || null,
        github: sGh.data || null,
      })
    } catch {
      // tolerate transient errors silently; show empty cards
    }
  }, [])

  useEffect(() => { void reload() }, [reload])

  const handleScan = async (cloud: CspmCloud, id: string) => {
    setScanning(id)
    try {
      await api.post(`${CLOUD_CONFIG[cloud].endpoint}/connections/${id}/scan`)
      // Re-poll stats after a brief delay
      setTimeout(() => { void reload() }, 4000)
    } catch {
      // ignore
    } finally {
      setTimeout(() => setScanning(null), 4000)
    }
  }

  const handleDisconnect = async (cloud: CspmCloud, id: string) => {
    if (!confirm(`Disconnect this ${CLOUD_CONFIG[cloud].name} integration?`)) return
    try {
      await api.delete(`${CLOUD_CONFIG[cloud].endpoint}/connections/${id}`)
      void reload()
    } catch {
      // ignore
    }
  }

  const connsByCloud: Record<CspmCloud, CspmConnection[]> = {
    azure: azureConns,
    oracle: oracleConns,
    github: githubConns,
  }

  return (
    <>
      {visibleClouds.map(cloud => (
        <ConnectorCard
          key={cloud}
          cloud={cloud}
          connections={connsByCloud[cloud]}
          stats={stats[cloud]}
          scanning={scanning}
          onAdd={() => setModal(cloud)}
          onScan={id => void handleScan(cloud, id)}
          onDisconnect={id => void handleDisconnect(cloud, id)}
        />
      ))}
      {modal && (
        <ConnectModal
          cloud={modal}
          onClose={() => setModal(null)}
          onConnected={() => { void reload() }}
        />
      )}
    </>
  )
}
