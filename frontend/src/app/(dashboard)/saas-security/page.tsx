'use client'
import React, { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import {
  Cloud, CloudOff, AlertTriangle, CheckCircle2, XCircle,
  RefreshCw, ExternalLink, Info, ChevronDown, ChevronUp,
  ShieldCheck, ShieldAlert, Shield, Database, BarChart3, Plug, Unplug, X,
  Users, TrendingUp, FileWarning, Activity, Globe, Globe2, Eye, Clock, FileText,
  Link, UserX, Lock, Unlock, AlertOctagon, Building2, Trash2, Mail,
  Target, Zap, Network, GitBranch, Layers, Server, HardDrive, Key,
  Radio, Play, Pause, ChevronRight, ArrowRight, Code, Sparkles, Loader2,
  Search,
} from 'lucide-react'
import Button from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import api from '@/lib/api'
import CSPMConnectors from '@/components/saas-security/CSPMConnectors'
import DataInventoryDSPM from '@/components/saas-security/DataInventoryDSPM'
import MermaidDiagram from '@/components/MermaidDiagram'

// ── Microsoft Product Icons (Official) ─────────────────────────────────────────

// Microsoft Teams icon - official brand colors #5558AF/#7B83EB
function TeamsIcon({ size = 18, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 2381.4 2354.5" className={className}>
      <path fill="#5558AF" d="M2015.6 899.2c19.5 19.5 42.5 35 67.9 45.8 53 22.2 112.7 22.2 165.8 0 51.2-21.8 92-62.5 113.7-113.7 22.2-53 22.2-112.7 0-165.8-21.8-51.2-62.5-92-113.7-113.7-53-22.2-112.7-22.2-165.8 0-51.2 21.8-92 62.5-113.7 113.7-22.2 53-22.2 112.7 0 165.8 10.8 25.3 26.3 48.4 45.8 67.9zm-62.4 197.8v642.1h107c36.8-.2 73.4-3.6 109.5-10.4 36.3-6.4 71.3-18.6 103.7-36.2 30.6-16.6 57-40 77.3-68.2 21.3-31.3 32-68.6 30.5-106.5V1097h-428zm-346.8-269.2c28.4.2 56.6-5.5 82.8-16.7 51.2-21.8 91.9-62.5 113.6-113.7 22.2-53 22.2-112.7-.1-165.8-21.8-51.2-62.5-92-113.7-113.7-26.2-11.2-54.4-16.9-82.9-16.7-28.3-.2-56.3 5.5-82.3 16.7-19.4 8.3-25.5 19.1-52.2 32.1v329c26.8 13.1 32.8 23.8 52.2 32.1 26.1 11.3 54.1 17 82.6 16.7zm-134.8 1081.1c26.8 5.8 36.4 10.3 55.4 12.9 20.8 3 41.8 4.5 62.8 4.6 32.4-.2 64.8-3.6 96.5-10.4 32.3-6.5 63.3-18.6 91.5-35.7 27.7-17 51-40.2 68.2-67.7 19-32.1 28.3-69.1 26.9-106.4v-743h-401.3v945.7zM0 2113.7l1391.3 240.8V0L0 240.8v1872.9z"/>
      <path fill="#fff" d="M1016.7 722.4l-642.1 39.1v148.1l240.8-9.7v686.7l160.5 9.4V893.6l240.8-10.7z"/>
    </svg>
  )
}

// Microsoft SharePoint icon - official brand colors #038387/#1A9BA1/#37C6D0
function SharePointIcon({ size = 18, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={className}>
      <defs>
        <linearGradient id="sp-grad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#038387"/>
          <stop offset="100%" stopColor="#1A9BA1"/>
        </linearGradient>
      </defs>
      <circle cx="9" cy="9" r="8" fill="#038387"/>
      <circle cx="16" cy="12" r="6.5" fill="#1A9BA1"/>
      <circle cx="10" cy="17" r="5.5" fill="#37C6D0"/>
      <text x="5" y="13" fill="white" fontSize="10" fontFamily="Arial" fontWeight="bold">S</text>
    </svg>
  )
}

// ── Types ──────────────────────────────────────────────────────────────────────

interface SaasIntegration {
  id: string
  provider: 'teams' | 'sharepoint'
  status: 'active' | 'disconnected' | 'error'
  tenant_id?: string
  connected_at?: string
  last_synced_at?: string
  error_message?: string
}

interface SaasAlert {
  id: string
  provider: string
  alert_type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  title: string
  description: string
  resource_id?: string
  resource_name?: string
  resource_url?: string
  classification_result?: Record<string, unknown>
  posture_result?: Record<string, unknown>
  status: 'open' | 'acknowledged' | 'resolved' | 'suppressed'
  resolved_at?: string
  created_at?: string
  updated_at?: string
  source?: 'saas' | 'aws'
  remediation_steps?: string[]
}

interface DataItem {
  id: string
  provider: string
  item_type: string
  item_name: string
  item_url?: string
  parent_path?: string
  owner_email?: string
  size_bytes?: number
  classification_label?: string
  classification_score?: number
  classification_categories?: string[]
  classification_result?: Record<string, unknown>
  sharing_scope?: string
  last_modified_at?: string
  last_scanned_at?: string
  created_at?: string
  // AWS-specific fields
  region?: string
  resource_arn?: string
  encryption_enabled?: boolean
  public_access?: boolean
  source?: 'saas' | 'aws'
}

interface PostureCheck {
  id: string
  provider: string
  check_name: string
  check_category: string
  status: 'pass' | 'fail' | 'warning' | 'unknown'
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
  recommendation?: string
  evidence?: Record<string, unknown>
  remediation_steps: string[]
  last_checked_at?: string
}

interface AlertsResponse {
  total: number
  items: SaasAlert[]
}

interface DataResponse {
  total: number
  items: DataItem[]
}

interface PostureResponse {
  checks: Record<string, PostureCheck[]>
}

interface PostureSummary {
  by_status: Record<string, number>
  by_severity: Record<string, number>
}

interface DataSummary {
  total: number
  by_label: Record<string, number>
  by_scope: Record<string, number>
  by_provider: Record<string, number>
}

type Tab = 'overview' | 'connectors' | 'alerts' | 'data' | 'posture' | 'admin-actions' | 'attack-chain' | 'user-risk' | 'compliance' | 'governance'

// ── Data Residency Types ──────────────────────────────────────────────────────

interface DataResidencyInfo {
  tenant_region: string | null
  tenant_country: string | null
  primary_data_region?: string | null
  data_locations: Array<{ name: string; url: string; region: string; type: string }>
  user_activity_regions: Array<{
    country_code: string
    country: string
    region: string
    lat: number
    lng: number
    sign_in_count: number
  }>
  region_summary: Record<string, number>
  compliance_regions: Array<{
    regulation: string
    region: string
    status: string
    // Added by backend when live compliance posture is available
    score_pct?: number
    compliant?: number
    partial?: number
    total_controls?: number
  }>
  external_sharing_by_region: Array<{ region: string; count: number }>
  cloud_regions?: Array<{ provider: string; region: string; type: string; lat?: number; lng?: number; resource_count?: number }>
  aws_regions_enabled?: string[]
}

// ── Funnel Data for Security Exposure View ────────────────────────────────────

interface FunnelData {
  total_resources: number
  misconfigs: number
  exposures: number
  exploitable: number
  by_provider: Record<string, { resources: number; misconfigs: number; exposures: number; exploitable: number }>
}

// ── Worker Status ─────────────────────────────────────────────────────────────

interface WorkersStatus {
  classification_worker: boolean
  alert_scanner: boolean
  posture_checker: boolean
  sync_worker: boolean
  iam_scanner: boolean
}

// ── Theme constants ────────────────────────────────────────────────────────────

const SEV_BG: Record<string, string> = {
  low:      'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  medium:   'bg-amber-500/10 border-amber-500/20 text-amber-400',
  high:     'bg-red-500/10 border-red-500/20 text-red-400',
  critical: 'bg-red-900/30 border-red-500/40 text-red-300',
}

const LABEL_BG: Record<string, string> = {
  public:            'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  internal:          'bg-blue-500/10 border-blue-500/20 text-blue-400',
  confidential:      'bg-amber-500/10 border-amber-500/20 text-amber-400',
  highly_confidential: 'bg-red-500/10 border-red-500/20 text-red-400',
}

const STATUS_BG: Record<string, string> = {
  open:          'bg-red-500/10 border-red-500/20 text-red-400',
  acknowledged:  'bg-amber-500/10 border-amber-500/20 text-amber-400',
  resolved:      'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  suppressed:    'bg-zinc-500/10 border-zinc-500/20 text-zinc-400',
}

const ALERT_TYPE_BG: Record<string, string> = {
  sensitive_data:     'bg-orange-500/10 border-orange-500/20 text-orange-400',
  data_leak:          'bg-red-500/10 border-red-500/20 text-red-400',
  data_exposure:      'bg-red-500/10 border-red-500/20 text-red-400',
  pii:                'bg-purple-500/10 border-purple-500/20 text-purple-400',
  financial:          'bg-yellow-500/10 border-yellow-500/20 text-yellow-400',
  financial_invoice:  'bg-yellow-500/10 border-yellow-500/20 text-yellow-400',
  financial_tax:      'bg-yellow-500/10 border-yellow-500/20 text-yellow-400',
  credential:         'bg-pink-500/10 border-pink-500/20 text-pink-400',
  malware:            'bg-red-900/30 border-red-500/40 text-red-300',
  bulk_exfil:         'bg-red-900/30 border-red-500/40 text-red-300',
  hr_medical:         'bg-purple-500/10 border-purple-500/20 text-purple-400',
  // Behavioral threats
  impossible_travel:  'bg-red-500/10 border-red-500/20 text-red-400',
  mass_download:      'bg-orange-500/10 border-orange-500/20 text-orange-400',
  external_forwarding:'bg-amber-500/10 border-amber-500/20 text-amber-400',
  risky_oauth_app:    'bg-purple-500/10 border-purple-500/20 text-purple-400',
  suspicious_sharing: 'bg-pink-500/10 border-pink-500/20 text-pink-400',
  permission_escalation:'bg-red-500/10 border-red-500/20 text-red-400',
  // Entra ID / Admin
  entra_risky_user:   'bg-red-500/10 border-red-500/20 text-red-400',
  privileged_action:  'bg-amber-500/10 border-amber-500/20 text-amber-400',
  shadow_it_app:      'bg-purple-500/10 border-purple-500/20 text-purple-400',
  stale_external_share:'bg-orange-500/10 border-orange-500/20 text-orange-400',
  data_residency_violation:'bg-red-500/10 border-red-500/20 text-red-400',
  // Teams/SharePoint Security (new detections)
  phishing_url:       'bg-red-600/20 border-red-500/40 text-red-300',
  homograph_attack:   'bg-red-600/20 border-red-500/40 text-red-300',
  suspicious_signin:  'bg-amber-500/10 border-amber-500/20 text-amber-400',
  password_spray:     'bg-red-500/10 border-red-500/20 text-red-400',
  after_hours_activity:'bg-amber-500/10 border-amber-500/20 text-amber-400',
  ransomware_indicator:'bg-red-900/30 border-red-500/40 text-red-300',
  suspicious_extension:'bg-orange-500/10 border-orange-500/20 text-orange-400',
  macro_enabled:      'bg-orange-500/10 border-orange-500/20 text-orange-400',
  external_share_sensitive:'bg-pink-500/10 border-pink-500/20 text-pink-400',
  anonymous_link:     'bg-amber-500/10 border-amber-500/20 text-amber-400',
  // Databricks Security
  secret_in_notebook: 'bg-red-500/10 border-red-500/20 text-red-400',
  hardcoded_credential:'bg-red-500/10 border-red-500/20 text-red-400',
  insecure_cluster:   'bg-orange-500/10 border-orange-500/20 text-orange-400',
  overly_permissive_secret:'bg-amber-500/10 border-amber-500/20 text-amber-400',
  // AWS Security
  public_s3_bucket:   'bg-red-500/10 border-red-500/20 text-red-400',
  unencrypted_storage:'bg-orange-500/10 border-orange-500/20 text-orange-400',
  iam_overprivilege:  'bg-amber-500/10 border-amber-500/20 text-amber-400',
  root_account_usage: 'bg-red-500/10 border-red-500/20 text-red-400',
  mfa_disabled:       'bg-orange-500/10 border-orange-500/20 text-orange-400',
}

// Human-readable DLP category labels
const DLP_CATEGORY_LABELS: Record<string, { label: string; color: string }> = {
  // Finance
  financial_tax:      { label: 'Tax Data', color: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-300' },
  financial_invoice:  { label: 'Finance', color: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-300' },
  financial_account:  { label: 'Bank Account', color: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-300' },
  financial_salary:   { label: 'Payroll', color: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-300' },
  financial_budget:   { label: 'Budget', color: 'bg-yellow-500/15 border-yellow-500/30 text-yellow-300' },
  financial_wire:     { label: 'Wire Transfer', color: 'bg-red-500/15 border-red-500/30 text-red-300' },
  financial_iban:     { label: 'IBAN', color: 'bg-red-500/15 border-red-500/30 text-red-300' },
  // PII
  pii_ssn:            { label: 'SSN', color: 'bg-red-500/15 border-red-500/30 text-red-300' },
  pii_credit_card:    { label: 'Credit Card', color: 'bg-red-500/15 border-red-500/30 text-red-300' },
  pii_passport:       { label: 'Passport', color: 'bg-red-500/15 border-red-500/30 text-red-300' },
  pii_dob:            { label: 'Date of Birth', color: 'bg-orange-500/15 border-orange-500/30 text-orange-300' },
  pii_biometric:      { label: 'Biometric', color: 'bg-red-500/15 border-red-500/30 text-red-300' },
  pii_health_insurance: { label: 'Health Insurance', color: 'bg-purple-500/15 border-purple-500/30 text-purple-300' },
  // Health
  hr_medical:         { label: 'Medical / PHI', color: 'bg-purple-500/15 border-purple-500/30 text-purple-300' },
  // HR
  hr_performance:     { label: 'HR Data', color: 'bg-blue-500/15 border-blue-500/30 text-blue-300' },
  // Legal
  legal_nda:          { label: 'NDA', color: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-300' },
  legal_litigation:   { label: 'Legal / Litigation', color: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-300' },
  legal_ma:           { label: 'M&A', color: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-300' },
  legal_court_order:  { label: 'Court Order', color: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-300' },
  legal_ip_rights:    { label: 'IP Rights', color: 'bg-indigo-500/15 border-indigo-500/30 text-indigo-300' },
  // Credentials / Infra
  credential_privkey: { label: 'Private Key', color: 'bg-red-600/20 border-red-500/40 text-red-200' },
  credential_password:{ label: 'Password', color: 'bg-red-600/20 border-red-500/40 text-red-200' },
  credential_apikey:  { label: 'API Key', color: 'bg-red-600/20 border-red-500/40 text-red-200' },
  infra_ssh_key:      { label: 'SSH Key', color: 'bg-red-600/20 border-red-500/40 text-red-200' },
  infra_private_key:  { label: 'Private Key', color: 'bg-red-600/20 border-red-500/40 text-red-200' },
  db_sql_dump:        { label: 'DB Dump', color: 'bg-orange-600/20 border-orange-500/40 text-orange-200' },
  db_connection:      { label: 'DB Credentials', color: 'bg-orange-600/20 border-orange-500/40 text-orange-200' },
  // Source code  
  source_code:        { label: 'Source Code', color: 'bg-cyan-500/15 border-cyan-500/30 text-cyan-300' },
  // Compliance
  itar:               { label: 'ITAR', color: 'bg-red-700/20 border-red-600/40 text-red-200' },
  gdpr:               { label: 'GDPR', color: 'bg-blue-600/20 border-blue-500/40 text-blue-200' },
  bulk_exfil:         { label: 'Bulk Exfil', color: 'bg-red-700/20 border-red-600/40 text-red-200' },
  // Generic
  sensitive:          { label: 'Sensitive', color: 'bg-amber-500/15 border-amber-500/30 text-amber-300' },
}

function DlpCategoryPill({ category }: { category: string }) {
  const meta = DLP_CATEGORY_LABELS[category]
  const label = meta?.label ?? category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
  const color = meta?.color ?? 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold border ${color}`}>
      {label}
    </span>
  )
}

const POSTURE_ICON: Record<string, React.ReactNode> = {
  pass:    <CheckCircle2 size={14} className="text-emerald-400" />,
  fail:    <XCircle size={14} className="text-red-400" />,
  warning: <AlertTriangle size={14} className="text-amber-400" />,
  unknown: <Info size={14} className="text-zinc-400" />,
}

// ── Small utility components ───────────────────────────────────────────────────

function SevBadge({ level }: { level: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border ${SEV_BG[level] ?? SEV_BG.low}`}>
      {level === 'critical' || level === 'high'
        ? <AlertTriangle size={10} />
        : level === 'medium'
        ? <Info size={10} />
        : <CheckCircle2 size={10} />}
      {level}
    </span>
  )
}

function AlertTypeBadge({ type }: { type: string }) {
  const cls = ALERT_TYPE_BG[type] ?? 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${cls}`}>
      {type.replace(/_/g, ' ')}
    </span>
  )
}

function LabelBadge({ label }: { label?: string }) {
  const l = label ?? 'unknown'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${LABEL_BG[l] ?? 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'}`}>
      {l.replace('_', ' ')}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${STATUS_BG[status] ?? STATUS_BG.open}`}>
      {status}
    </span>
  )
}

function ProviderBadge({ provider }: { provider: string }) {
  const styles: Record<string, { bg: string; text: string }> = {
    teams: { bg: 'bg-purple-900/40', text: 'text-purple-300' },
    sharepoint: { bg: 'bg-blue-900/40', text: 'text-blue-300' },
    aws: { bg: 'bg-[#FF9900]/20', text: 'text-[#FF9900]' },
    gcp: { bg: 'bg-[#4285F4]/20', text: 'text-[#4285F4]' },
    databricks: { bg: 'bg-[#FF3621]/20', text: 'text-[#FF3621]' },
    sap: { bg: 'bg-[#0FAAFF]/20', text: 'text-[#0FAAFF]' },
    m365: { bg: 'bg-blue-900/40', text: 'text-blue-300' },
    google: { bg: 'bg-emerald-900/40', text: 'text-emerald-300' },
  }
  const s = styles[provider.toLowerCase()] || { bg: 'bg-zinc-800/40', text: 'text-zinc-400' }
  const labels: Record<string, string> = {
    teams: 'Teams',
    sharepoint: 'SharePoint',
    aws: 'AWS',
    gcp: 'GCP',
    databricks: 'Databricks',
    sap: 'SAP',
    m365: 'M365',
    google: 'Google',
  }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold ${s.bg} ${s.text}`}>
      {provider.toLowerCase() === 'aws' && <AWSLogo size={12} />}
      {labels[provider.toLowerCase()] || provider}
    </span>
  )
}

function StatCard({ label, value, sub, color }: { label: string; value: number | string; sub?: string; color?: string }) {
  return (
    <div className="bg-[#111114] border border-[#1e1e24] rounded-xl p-4 flex flex-col gap-1">
      <div className="text-[12px] text-[#71717a]">{label}</div>
      <div className={`text-2xl font-bold ${color ?? 'text-[#e4e4e7]'}`}>{value}</div>
      {sub && <div className="text-[11px] text-[#52525b]">{sub}</div>}
    </div>
  )
}

function ScoreBar({ score }: { score?: number }) {
  const pct = Math.round((score ?? 0) * 100)
  const color = pct >= 75 ? 'bg-red-500' : pct >= 50 ? 'bg-amber-500' : 'bg-emerald-500'
  return (
    <div className="flex items-center gap-1.5 min-w-[60px]">
      <div className="flex-1 h-1.5 bg-[#1e1e24] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-[#71717a] w-7 text-right">{pct}%</span>
    </div>
  )
}

function formatBytes(bytes?: number): string {
  if (!bytes) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function fmtDate(iso?: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

// ── ConnectorsTab ──────────────────────────────────────────────────────────────

function ConnectorsTab({
  integrations, loading, onConnect, onDisconnect, connecting, m365Connected, canAutoConnect, onAutoConnect,
}: {
  integrations: SaasIntegration[]
  loading: boolean
  onConnect: (provider: 'teams' | 'sharepoint') => void
  onDisconnect: (provider: string) => void
  connecting: string | null
  m365Connected?: boolean
  canAutoConnect?: boolean
  onAutoConnect: () => void
}) {
  const [autoConnecting, setAutoConnecting] = useState(false)
  const [consentGranted, setConsentGranted] = useState(false)
  const [consentLoading, setConsentLoading] = useState(false)
  const getInteg = (p: string) => integrations.find(i => i.provider === p)
  const allActive = integrations.filter(i => i.status === 'active').length === 2

  const providers: Array<{ id: 'teams' | 'sharepoint'; name: string; desc: string; color: string; Icon: React.FC<{ size?: number; className?: string }> }> = [
    {
      id: 'teams',
      name: 'Microsoft Teams',
      desc: 'Scan channel messages for sensitive content, data leakage, and policy violations.',
      color: 'from-[#5059C9]/20 to-[#7B83EB]/10 dark:from-[#5059C9]/30 dark:to-[#7B83EB]/10',
      Icon: TeamsIcon,
    },
    {
      id: 'sharepoint',
      name: 'SharePoint',
      desc: 'Monitor files and sites for sensitive data, external sharing, and classification gaps.',
      color: 'from-[#038387]/20 to-[#1A9BA1]/10 dark:from-[#038387]/30 dark:to-[#1A9BA1]/10',
      Icon: SharePointIcon,
    },
  ]

  const handleAutoConnect = async () => {
    setAutoConnecting(true)
    try {
      await onAutoConnect()
    } finally {
      setAutoConnecting(false)
    }
  }

  const handleGrantConsent = async () => {
    setConsentLoading(true)
    try {
      const r = await api.get('/api/saas/consent-url')
      const url = r.data?.url
      if (url) {
        window.open(url, '_blank')
        setConsentGranted(true)
      }
    } catch {
      // If no M365 integration found, show error via auto-connect flow
    } finally {
      setConsentLoading(false)
    }
  }

  return (
    <div className="space-y-5">

      {/* Step 1: Grant Admin Consent — always show unless all integrations are active */}
      {!allActive && (
        <div className={`border rounded-xl p-4 flex items-center justify-between gap-4 ${
          consentGranted
            ? 'bg-emerald-500/5 border-emerald-500/20'
            : 'bg-gradient-to-r from-amber-900/20 to-orange-900/10 border-amber-500/30'
        }`}>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              {consentGranted
                ? <CheckCircle2 size={16} className="text-emerald-500 flex-shrink-0" />
                : <ShieldCheck size={16} className="text-amber-500 flex-shrink-0" />}
              <span className="text-[13px] font-semibold text-[var(--foreground)]">
                {consentGranted ? 'Admin Consent Granted' : 'Step 1 — Grant Admin Consent'}
              </span>
            </div>
            <p className="text-[11px] text-[var(--muted)] mt-1">
              {consentGranted
                ? 'Permissions granted. Now click Auto-Connect below to enable Teams & SharePoint scanning.'
                : 'Required once so Helios can scan Teams messages and SharePoint files. Uses your existing M365 integration.'}
            </p>
          </div>
          <button
            onClick={handleGrantConsent}
            disabled={consentGranted || consentLoading || !m365Connected}
            className={`flex-shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold transition-colors ${
              consentGranted
                ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-600 dark:text-emerald-400 cursor-default'
                : 'bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-700 dark:text-amber-300'
            }`}
          >
            {consentLoading ? <RefreshCw size={12} className="animate-spin" /> : <ExternalLink size={12} />}
            {consentGranted ? 'Done ✓' : 'Grant Consent →'}
          </button>
        </div>
      )}

      {/* Step 2: Auto-connect */}
      {(canAutoConnect || consentGranted) && (
        <div className="bg-gradient-to-r from-blue-500/10 to-indigo-500/10 border border-blue-500/30 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <CheckCircle2 size={16} className="text-blue-500" />
              <span className="text-[13px] font-semibold text-[var(--foreground)]">
                {consentGranted ? 'Step 2 — Connect Teams & SharePoint' : 'M365 Already Connected'}
              </span>
            </div>
            <p className="text-[11px] text-[var(--muted)] mt-1">
              Enable Teams & SharePoint security scanning using your existing M365 integration.
            </p>
          </div>
          <Button
            onClick={handleAutoConnect}
            disabled={autoConnecting}
            className="ml-4 flex-shrink-0"
          >
            {autoConnecting ? (
              <RefreshCw size={13} className="mr-1 animate-spin" />
            ) : (
              <Plug size={13} className="mr-1" />
            )}
            Auto-Connect Both
          </Button>
        </div>
      )}

      {/* Microsoft 365 Section */}
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <svg viewBox="0 0 23 23" width="16" height="16" className="text-[#DC3E15]">
            <path fill="#f25022" d="M1 1h10v10H1z"/>
            <path fill="#00a4ef" d="M1 12h10v10H1z"/>
            <path fill="#7fba00" d="M12 1h10v10H12z"/>
            <path fill="#ffb900" d="M12 12h10v10H12z"/>
          </svg>
          <h3 className="text-[14px] font-semibold text-[var(--foreground)]">Microsoft 365</h3>
        </div>

        {loading ? (
          <div className="text-center py-8 text-[var(--muted)]">Loading integrations…</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {providers.map(p => {
              const integ = getInteg(p.id)
              const isActive = integ?.status === 'active'
              const isConnecting = connecting === p.id
              const IconComponent = p.Icon
              return (
                <div key={p.id} className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5 space-y-3 hover:border-white/[0.12] transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${isActive ? 'bg-white/10' : 'bg-[var(--muted)]/10'}`}>
                        <IconComponent size={22} className={isActive ? '' : 'opacity-50 grayscale'} />
                      </div>
                      <span className="font-semibold text-[var(--foreground)]">{p.name}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold border ${
                      isActive
                        ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                        : 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
                    }`}>
                      {integ?.status ?? 'disconnected'}
                    </span>
                  </div>
                  <p className="text-[12px] text-[var(--muted)] leading-relaxed">{p.desc}</p>
                  {isActive && integ?.last_synced_at && (
                    <div className="text-[11px] text-[var(--muted)]">Last synced: {fmtDate(integ.last_synced_at)}</div>
                  )}
                  {integ?.error_message && (
                    <div className="text-[11px] text-red-400 bg-red-500/10 border border-red-500/20 rounded px-2 py-1">
                      {integ.error_message}
                    </div>
                  )}
                  <div className="flex gap-2 pt-1">
                    {isActive ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onDisconnect(p.id)}
                        className="text-red-400 hover:text-red-300 border-red-500/20"
                      >
                        <Unplug size={13} className="mr-1" /> Disconnect
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        onClick={() => onConnect(p.id)}
                        disabled={isConnecting}
                      >
                        {isConnecting ? (
                          <RefreshCw size={13} className="mr-1 animate-spin" />
                        ) : (
                          <Plug size={13} className="mr-1" />
                        )}
                        Connect
                      </Button>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Cloud Infrastructure Section. alwaysShow=true on Connectors
          tab so the user can add the first AWS/GCP connection here. */}
      <CloudInfrastructureSection alwaysShow />

      {/* AI Infrastructure Section */}
      <AIInfrastructureSection alwaysShow />

      {/* Financial Platforms Section (includes Code Security / GitHub) */}
      <FinancialPlatformsSection alwaysShow />

      {/* Business Applications (SaaS SSPM) — Salesforce, etc. */}
      <BusinessAppsSection alwaysShow />

    </div>
  )
}

// ── Logo Components (Official Simple Icons) ────────────────────────────────────

// AWS Logo - Orange smile on dark, works on dark backgrounds
function AWSLogo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="#FF9900">
      <path d="M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.863.279a2.05 2.05 0 0 1-.248.104.472.472 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.416-.287-.807-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.175 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167zM21.698 16.207c-2.626 1.94-6.442 2.969-9.722 2.969-4.598 0-8.74-1.7-11.87-4.526-.247-.223-.024-.527.27-.351 3.384 1.963 7.559 3.153 11.877 3.153 2.914 0 6.114-.607 9.06-1.852.439-.2.814.287.385.607zM22.792 14.961c-.336-.43-2.22-.207-3.074-.103-.255.032-.295-.192-.063-.36 1.5-1.053 3.967-.75 4.254-.399.287.36-.08 2.826-1.485 4.007-.215.184-.423.088-.327-.151.32-.79 1.03-2.57.695-2.994z"/>
    </svg>
  )
}

// GCP Logo - Official Google Cloud (Simple Icons)
function GCPLogo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="#4285F4">
      <path d="M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-2.821-4.552l-.043.043.006-.05A9.344 9.344 0 0 0 12.19 2.38zm-.358 4.146c1.244-.04 2.518.368 3.486 1.15a5.186 5.186 0 0 1 1.862 4.078v.518c3.53-.07 3.53 5.262 0 5.193h-5.193l-.008.009v-.04H6.785a2.59 2.59 0 0 1-1.067-.23h.001a2.597 2.597 0 1 1 3.437-3.437l3.013-3.012A6.747 6.747 0 0 0 8.11 8.24c.018-.01.04-.026.054-.023a5.186 5.186 0 0 1 3.67-1.69z"/>
    </svg>
  )
}

// Databricks Logo - Official Simple Icons
function DatabricksLogo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="#FF3621">
      <path d="M.95 14.184L12 20.403l9.919-5.55v2.21L12 22.662l-10.484-5.96-.565.308v.77L12 24l11.05-6.218v-4.317l-.515-.309L12 19.118l-9.867-5.653v-2.21L12 16.805l11.05-6.218V6.32l-.515-.308L12 11.974 2.647 6.681 12 1.388l7.76 4.368.668-.411v-.566L12 0 .95 6.27v.72L12 13.207l9.919-5.55v2.26L12 15.52 1.516 9.56l-.565.308Z"/>
    </svg>
  )
}

// SAP Logo - Official Simple Icons
function SAPLogo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="#0FAAFF">
      <path d="M0 6.064v11.872h12.13L24 6.064zm3.264 2.208h.005c.863.001 1.915.245 2.676.633l-.82 1.43c-.835-.404-1.255-.442-1.73-.467-.708-.038-1.064.215-1.069.488-.007.332.669.633 1.305.838.964.306 2.19.715 2.377 1.9L7.77 8.437h2.046l2.064 5.576-.007-5.575h2.37c2.257 0 3.318.764 3.318 2.519 0 1.575-1.09 2.514-2.936 2.514h-.763l-.01 2.094-3.588-.003-.25-.908c-.37.122-.787.189-1.23.189-.456 0-.885-.071-1.263-.2l-.358.919-2 .006.09-.462c-.029.025-.057.05-.087.074-.535.43-1.208.629-2.037.644l-.213.002a5.075 5.075 0 0 1-2.581-.675l.73-1.448c.79.467 1.286.572 1.956.558.347-.007.598-.07.761-.239a.557.557 0 0 0 .156-.369c.007-.376-.53-.553-1.185-.756-.531-.164-1.135-.389-1.606-.735-.559-.41-.825-.924-.812-1.65a1.99 1.99 0 0 1 .566-1.377c.519-.537 1.357-.863 2.363-.863zm10.597 1.67v1.904h.521c.694 0 1.247-.23 1.248-.964 0-.709-.554-.94-1.248-.94zm-5.087.767l-.748 2.362c.223.085.481.133.757.133.268 0 .52-.047.742-.126l-.736-2.37z"/>
    </svg>
  )
}

// ── Purview Logo ──────────────────────────────────────────────────────────────
function PurviewLogo({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="#0078D4">
      <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm0 2.4c5.302 0 9.6 4.298 9.6 9.6s-4.298 9.6-9.6 9.6-9.6-4.298-9.6-9.6S6.698 2.4 12 2.4zm-1.2 3.6v4.8H6v2.4h4.8v4.8h2.4v-4.8H18v-2.4h-4.8V6h-2.4z"/>
    </svg>
  )
}

// ── Event Sources Section (shows what data flows into the system) ─────────────

function EventSourcesSection() {
  const [expanded, setExpanded] = useState(false)
  
  const eventSources = [
    {
      category: 'Microsoft 365 Security',
      icon: <svg viewBox="0 0 23 23" width="16" height="16"><path fill="#f25022" d="M1 1h10v10H1z"/><path fill="#00a4ef" d="M1 12h10v10H1z"/><path fill="#7fba00" d="M12 1h10v10H12z"/><path fill="#ffb900" d="M12 12h10v10H12z"/></svg>,
      sources: [
        { name: 'Sign-in Logs', endpoint: '/auditLogs/signIns', feeds: 'Alerts', desc: 'Risky sign-ins, brute force, impossible travel, legacy auth' },
        { name: 'Directory Audits', endpoint: '/auditLogs/directoryAudits', feeds: 'Alerts', desc: 'Permission changes, forwarding rules, DLP matches' },
        { name: 'Risk Detections', endpoint: '/identityProtection/riskDetections', feeds: 'Alerts', desc: 'Identity Protection risk events' },
        { name: 'Conditional Access', endpoint: '/identity/conditionalAccess/policies', feeds: 'Posture', desc: 'CA policy failures and blocks' },
      ]
    },
    {
      category: 'Microsoft Purview',
      icon: <PurviewLogo size={16} />,
      sources: [
        { name: 'eDiscovery Cases', endpoint: '/security/cases/ediscoveryCases', feeds: 'Alerts', desc: 'Active legal holds and data preservation' },
        { name: 'Label Policy Summary', endpoint: '/security/informationProtection/labelPolicySummary', feeds: 'Alerts', desc: 'Unlabeled content volume' },
        { name: 'Communication Compliance', endpoint: '/compliance/ediscovery/alerts', feeds: 'Alerts', desc: 'Policy violations in Teams/Exchange' },
        { name: 'Insider Risk', endpoint: '/security/alerts_v2 (InsiderRisk)', feeds: 'Alerts', desc: 'Data exfiltration and policy violations' },
        { name: 'DLP Policy Matches', endpoint: '/auditLogs/directoryAudits (DlpRuleMatch)', feeds: 'Alerts', desc: 'Sensitive data handling violations' },
      ]
    },
    {
      category: 'Teams & SharePoint',
      icon: <TeamsIcon size={16} />,
      sources: [
        { name: 'Team/Channel Events', endpoint: '/teams/*/channels', feeds: 'Data Inventory', desc: 'External users, guest owners, private channels' },
        { name: 'SharePoint Sites', endpoint: '/sites', feeds: 'Data Inventory', desc: 'Site permissions, external sharing, anonymous links' },
        { name: 'OneDrive Files', endpoint: '/users/*/drive', feeds: 'Data Inventory', desc: 'File classification, sync from unmanaged devices' },
        { name: 'App Permissions', endpoint: '/servicePrincipals', feeds: 'Posture', desc: 'Teams apps with excessive permissions' },
      ]
    },
    {
      category: 'AWS Security',
      icon: <AWSLogo size={16} />,
      sources: [
        { name: 'IAM Users/Roles', endpoint: 'iam:ListUsers/GetRole', feeds: 'Data Inventory', desc: 'MFA status, last activity, stale credentials' },
        { name: 'S3 Buckets', endpoint: 's3:ListBuckets/GetBucketAcl', feeds: 'Data Inventory + Alerts', desc: 'Public access, encryption, versioning' },
        { name: 'EC2 Instances', endpoint: 'ec2:DescribeInstances', feeds: 'Data Inventory', desc: 'IMDSv2, security groups, launched_by' },
        { name: 'CloudTrail', endpoint: 'cloudtrail:LookupEvents', feeds: 'Alerts', desc: 'Who launched instances, root activity' },
        { name: 'GuardDuty', endpoint: 'guardduty:ListFindings', feeds: 'Alerts', desc: 'Security findings (requires IAM perms)' },
        { name: 'Security Hub', endpoint: 'securityhub:GetFindings', feeds: 'Alerts', desc: 'Aggregated security findings' },
      ]
    },
    {
      category: 'Databricks',
      icon: <DatabricksLogo size={16} />,
      sources: [
        { name: 'Workspaces', endpoint: '/api/2.0/workspace/list', feeds: 'Data Inventory', desc: 'Notebooks, repos, folders' },
        { name: 'Clusters', endpoint: '/api/2.0/clusters/list', feeds: 'Data Inventory', desc: 'Running clusters, instance types' },
        { name: 'SQL Warehouses', endpoint: '/api/2.0/sql/warehouses', feeds: 'Data Inventory', desc: 'Data warehouse endpoints' },
        { name: 'Unity Catalog', endpoint: '/api/2.1/unity-catalog/tables', feeds: 'Data Inventory', desc: 'Tables, schemas, catalogs' },
        { name: 'Secrets', endpoint: '/api/2.0/secrets/scopes/list', feeds: 'Posture', desc: 'Secret scope permissions' },
      ]
    },
  ]

  return (
    <div className="mt-6">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-4 bg-[#13131a] border border-white/[0.06] rounded-xl hover:border-white/[0.12] transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-purple-500/20 to-blue-500/20 flex items-center justify-center">
            <Database size={16} className="text-purple-400" />
          </div>
          <div className="text-left">
            <h3 className="text-[14px] font-semibold text-[var(--foreground)]">Event Sources & Data Flow</h3>
            <p className="text-[11px] text-[var(--muted)]">
              {eventSources.reduce((acc, cat) => acc + cat.sources.length, 0)} API endpoints feeding into Alerts, Data Inventory, and Posture
            </p>
          </div>
        </div>
        <ChevronDown size={18} className={`text-[var(--muted)] transition-transform ${expanded ? 'rotate-180' : ''}`} />
      </button>

      {expanded && (
        <div className="mt-3 space-y-4">
          {eventSources.map((category) => (
            <div key={category.category} className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                {category.icon}
                <h4 className="text-[13px] font-semibold text-[var(--foreground)]">{category.category}</h4>
                <span className="ml-auto text-[10px] text-[var(--muted)] bg-white/[0.05] px-2 py-0.5 rounded-full">
                  {category.sources.length} sources
                </span>
              </div>
              <div className="space-y-2">
                {category.sources.map((source) => (
                  <div key={source.name} className="flex items-start gap-3 p-2 rounded-lg bg-white/[0.02] hover:bg-white/[0.04] transition-colors">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[12px] font-medium text-[var(--foreground)]">{source.name}</span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded font-medium ${
                          source.feeds.includes('Alerts') ? 'bg-red-500/10 text-red-400 border border-red-500/20' :
                          source.feeds.includes('Posture') ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' :
                          'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                        }`}>
                          → {source.feeds}
                        </span>
                      </div>
                      <div className="text-[10px] text-[var(--muted)] mt-0.5">{source.desc}</div>
                    </div>
                    <code className="text-[9px] text-purple-400/70 bg-purple-500/5 px-1.5 py-0.5 rounded font-mono flex-shrink-0 max-w-[180px] truncate" title={source.endpoint}>
                      {source.endpoint}
                    </code>
                  </div>
                ))}
              </div>
            </div>
          ))}
          
          {/* Legend */}
          <div className="flex items-center gap-4 text-[10px] text-[var(--muted)] px-1">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-500/60"></span> Feeds Alerts
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-blue-500/60"></span> Feeds Data Inventory
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-amber-500/60"></span> Feeds Posture
            </span>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Workspace Overview Tab ────────────────────────────────────────────────────

interface CloudStats {
  total_resources: number
  total_findings: number
  critical_findings: number
  high_findings: number
  by_provider: Record<string, { resources: number; findings: number }>
  data_regions: Array<{ provider: string; region: string }>
  connections: Record<string, number>
  recent_findings: Array<{
    finding_id: string
    severity: string
    title: string
    category: string
    detected_at: string
    provider: string
  }>
}

interface EmailStats {
  emails_scanned: number
  mailboxes: number
  m365_connected: boolean
  google_connected: boolean
  provider: string | null
}

interface WorkspaceStats {
  total_files: number
  classified_files: number
  sensitive_files: number
  external_shares: number
  alerts_today: number
  alerts_week: number
  posture_score: number
  connected_apps: number
  users_monitored: number
  high_risk_users: number
  data_by_classification: { label: string; count: number }[]
  alerts_by_type: { type: string; count: number }[]
  trend_7d: { date: string; alerts: number; files_scanned: number }[]
  cloud_stats?: CloudStats
  email_stats?: EmailStats
  funnel_data?: FunnelData
  workers_status?: WorkersStatus
  iam_risks?: Array<{
    id: string
    risk_type: string
    severity: string
    principal: string
    description: string
    provider: string
  }>
}

// ── Security Exposure Funnel (Wiz/Averlon Style) ───────────────────────────────────

function SecurityFunnelView({ data }: { data: FunnelData }) {
  const [activeStage, setActiveStage] = useState<string | null>(null)
  // Build the full stage list, then hide ones that are zero so we don't
  // render empty colored bands (which were appearing as "blank color blocks"
  // in the panel when most counts were 0). Keep at least the first stage
  // so the panel doesn't collapse entirely.
  const allStages = [
    { key: 'total_resources', label: 'Resources', shortLabel: 'Resources', value: data.total_resources, fill: '#3b6ef6', textColor: 'text-blue-400', icon: <Server size={14} />, description: 'All monitored resources across cloud and SaaS' },
    { key: 'misconfigs', label: 'Misconfigurations', shortLabel: 'Misconfigs', value: data.misconfigs, fill: '#f59e0b', textColor: 'text-amber-400', icon: <AlertTriangle size={14} />, description: 'Resources with security misconfigurations' },
    { key: 'exposures', label: 'Exposed Assets', shortLabel: 'Exposed', value: data.exposures, fill: '#f97316', textColor: 'text-orange-400', icon: <Globe size={14} />, description: 'Assets accessible from internet or externally' },
    { key: 'exploitable', label: 'Exploitable', shortLabel: 'Exploitable', value: data.exploitable, fill: '#ef4444', textColor: 'text-red-400', icon: <Target size={14} />, description: 'Critical findings attackers can actively exploit' },
  ]
  const stages = allStages.filter((s, i) => i === 0 || s.value > 0)

  const maxValue = Math.max(...stages.map(s => s.value), 1)

  return (
    <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
      <div className="flex items-center justify-between mb-5">
        <h3 className="text-[14px] font-semibold text-[var(--foreground)] flex items-center gap-2">
          <Layers size={16} className="text-[#3b6ef6]" />
          Security Exposure Funnel
        </h3>
        
      </div>
      
      {/* Funnel Visualization — SVG trapezoid funnel */}
      <div className="relative mb-4">
        <svg viewBox={`0 0 400 ${Math.max(stages.length * 52 + 12, 80)}`} className="w-full max-w-md mx-auto" style={{ height: `${Math.max(stages.length * 44 + 12, 70)}px` }}>
          {stages.map((stage, i) => {
            const allFunnelWidths = [380, 300, 220, 140]
            const funnelWidths = allFunnelWidths.slice(0, stages.length)
            const w = funnelWidths[i]
            const h = 44
            const y = i * 52
            const x = (400 - w) / 2
            const nextW = funnelWidths[i + 1] || Math.max(w - 60, 60)
            const nextX = (400 - nextW) / 2
            return (
              <g key={stage.key} onClick={() => setActiveStage(activeStage === stage.key ? null : stage.key)} className="cursor-pointer">
                <polygon
                  points={`${x},${y} ${x+w},${y} ${nextX+nextW},${y+h-2} ${nextX},${y+h-2}`}
                  fill={stage.fill}
                  opacity={activeStage === stage.key ? 0.85 : 0.55}
                  stroke={stage.fill}
                  strokeWidth="1"
                />
                <text x="200" y={y + h/2 + 5} textAnchor="middle" fontSize="11" fill="white" fontWeight="600" style={{ fontFamily: 'system-ui' }}>
                  {stage.shortLabel}: {stage.value.toLocaleString()}
                </text>
              </g>
            )
          })}
        </svg>
      </div>

      {/* Stage detail on click */}
      {activeStage && (() => {
        const s = stages.find(st => st.key === activeStage)!
        const idx = stages.indexOf(s)
        const prev = idx > 0 ? stages[idx - 1] : null
        const reduction = prev ? Math.round(((prev.value - s.value) / Math.max(prev.value, 1)) * 100) : 0
        return (
          <div className="mb-4 p-3 rounded-lg border text-[12px]" style={{ backgroundColor: s.fill + '15', borderColor: s.fill + '50' }}>
            <div className="flex items-center gap-2 mb-1">
              <span className={s.textColor}>{s.icon}</span>
              <span className="font-semibold" style={{ color: s.fill }}>{s.label}</span>
              <span className="text-[var(--foreground)] font-bold ml-1">{s.value.toLocaleString()}</span>
              {reduction > 0 && <span className="text-emerald-400 text-[10px]">({reduction}% filtered from previous)</span>}
            </div>
            <div className="text-[var(--muted)]">{s.description}</div>
          </div>
        )
      })()}

      {/* Stage breakdown bars */}
      <div className="space-y-2">
        {stages.map((stage) => {
          const pct = Math.round((stage.value / Math.max(maxValue, 1)) * 100)
          return (
            <div key={stage.key} className="flex items-center gap-3 cursor-pointer group" onClick={() => setActiveStage(activeStage === stage.key ? null : stage.key)}>
              <div className="flex items-center gap-1.5 w-32 sm:w-36 flex-shrink-0">
                <span className={stage.textColor}>{stage.icon}</span>
                <span className="text-[10px] sm:text-[11px] text-[var(--muted)] group-hover:text-[var(--foreground)] transition-colors truncate">{stage.label}</span>
              </div>
              <div className="flex-1 h-2 bg-white/[0.05] rounded-full overflow-hidden">
                <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: stage.fill }} />
              </div>
              <span className="text-[11px] font-semibold w-12 text-right" style={{ color: stage.fill }}>{stage.value.toLocaleString()}</span>
            </div>
          )
        })}
      </div>

      {/* By Provider Breakdown */}
      {Object.keys(data.by_provider).length > 0 && (
        <div className="mt-5 pt-5 border-t border-white/[0.06]">
          <div className="text-[11px] text-[var(--muted)] uppercase tracking-wide mb-3">By Provider</div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(data.by_provider).map(([provider, stats]) => (
              <div key={provider} className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
                <div className="flex items-center gap-2 mb-2">
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                    provider.toLowerCase() === 'aws' ? 'bg-[#FF9900]/20 text-[#FF9900]' :
                    provider.toLowerCase() === 'gcp' ? 'bg-[#4285F4]/20 text-[#4285F4]' :
                    provider.toLowerCase() === 'm365' ? 'bg-blue-500/20 text-blue-400' :
                    provider.toLowerCase() === 'sap' ? 'bg-[#0FAAFF]/20 text-[#0FAAFF]' :
                    provider.toLowerCase() === 'databricks' ? 'bg-[#FF3621]/20 text-[#FF3621]' :
                    'bg-white/10 text-white'
                  }`}>{provider.toUpperCase()}</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[10px]">
                  <div>
                    <div className="text-[var(--muted)]">Resources</div>
                    <div className="font-semibold text-[var(--foreground)]">{stats.resources}</div>
                  </div>
                  <div>
                    <div className="text-red-400">Exploitable</div>
                    <div className="font-semibold text-red-400">{stats.exploitable}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Live Alerts Panel ──────────────────────────────────────────────────────────

function LiveAlertsPanel({ alerts, isLive }: { alerts: Array<{ id: string; alert_type: string; severity: string; title: string; created_at: string; provider?: string }>; isLive: boolean }) {
  const timeAgo = (iso: string): string => {
    const now = new Date()
    const then = new Date(iso)
    const diffMs = now.getTime() - then.getTime()
    const diffSec = Math.floor(diffMs / 1000)
    const diffMin = Math.floor(diffSec / 60)
    const diffHr = Math.floor(diffMin / 60)
    const diffDay = Math.floor(diffHr / 24)
    if (diffSec < 60) return 'just now'
    if (diffMin < 60) return `${diffMin}m ago`
    if (diffHr < 24) return `${diffHr}h ago`
    if (diffDay < 7) return `${diffDay}d ago`
    return then.toLocaleDateString()
  }

  return (
    <div className="bg-[#13131a] border border-white/[0.06] rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-white/[0.06] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio size={14} className={isLive ? 'text-red-500 animate-pulse' : 'text-zinc-500'} />
          <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Live Alerts Feed</h3>
        </div>
        <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-[10px] font-medium ${
          isLive 
            ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400' 
            : 'bg-zinc-500/10 border border-zinc-500/20 text-zinc-400'
        }`}>
          {isLive ? (
            <>
              <div className="relative">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                <div className="absolute inset-0 w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
              </div>
              Live
            </>
          ) : (
            <>
              <div className="w-2 h-2 rounded-full bg-zinc-500" />
              Idle
            </>
          )}
        </div>
      </div>
      <div className="max-h-[280px] overflow-y-auto">
        {alerts.length === 0 ? (
          <div className="text-center py-8 text-[var(--muted)] text-[12px]">
            <ShieldCheck size={24} className="mx-auto mb-2 opacity-50" />
            No recent alerts — all clear!
          </div>
        ) : (
          <div className="divide-y divide-white/[0.04]">
            {alerts.map(alert => (
              <div key={alert.id} className="px-4 py-3 hover:bg-white/[0.02] transition-colors">
                <div className="flex items-start gap-3">
                  <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                    alert.severity === 'critical' ? 'bg-red-500 animate-pulse' :
                    alert.severity === 'high' ? 'bg-orange-500' :
                    alert.severity === 'medium' ? 'bg-amber-500' : 'bg-emerald-500'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[12px] font-medium text-[var(--foreground)] truncate">
                        {alert.title || alert.alert_type.replace(/_/g, ' ')}
                      </span>
                      {alert.provider && (
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                          alert.provider.toLowerCase() === 'aws' ? 'bg-[#FF9900]/20 text-[#FF9900]' :
                          alert.provider.toLowerCase() === 'teams' || alert.provider.toLowerCase() === 'sharepoint' ? 'bg-blue-500/20 text-blue-400' :
                          alert.provider.toLowerCase() === 'sap' ? 'bg-[#0FAAFF]/20 text-[#0FAAFF]' :
                          alert.provider.toLowerCase() === 'databricks' ? 'bg-[#FF3621]/20 text-[#FF3621]' :
                          'bg-white/10 text-white'
                        }`}>{alert.provider}</span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-[10px] text-[var(--muted)]">{timeAgo(alert.created_at)}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold border ${
                        alert.severity === 'critical' ? 'bg-red-500/10 border-red-500/20 text-red-400' :
                        alert.severity === 'high' ? 'bg-orange-500/10 border-orange-500/20 text-orange-400' :
                        alert.severity === 'medium' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
                        'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                      }`}>{alert.severity}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Workers Status Banner ─────────────────────────────────────────────────────

function WorkersStatusBanner({ status, isLive, onToggleLive }: { status?: WorkersStatus; isLive: boolean; onToggleLive: () => void }) {
  const workers = [
    { key: 'classification_worker', label: 'Classification', active: status?.classification_worker ?? true },
    { key: 'alert_scanner', label: 'Alert Scanner', active: status?.alert_scanner ?? true },
    { key: 'posture_checker', label: 'Posture', active: status?.posture_checker ?? true },
    { key: 'sync_worker', label: 'Sync', active: status?.sync_worker ?? true },
    { key: 'iam_scanner', label: 'IAM Scanner', active: status?.iam_scanner ?? true },
  ]

  return (
    <div className="flex items-center justify-between bg-gradient-to-r from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl px-5 py-3">
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Activity size={16} className="text-emerald-400" />
          <span className="text-[13px] font-medium text-[var(--foreground)]">Background Workers</span>
        </div>
        <div className="flex items-center gap-3">
          {workers.map(w => (
            <div key={w.key} className="flex items-center gap-1.5 text-[11px]">
              <div className={`w-2 h-2 rounded-full ${w.active ? 'bg-emerald-500 animate-pulse' : 'bg-zinc-500'}`} />
              <span className="text-[var(--muted)]">{w.label}</span>
            </div>
          ))}
        </div>
      </div>
      <button
        onClick={onToggleLive}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors ${
          isLive 
            ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400' 
            : 'bg-zinc-500/10 border border-zinc-500/20 text-zinc-400'
        }`}
      >
        {isLive ? <Play size={12} /> : <Pause size={12} />}
        {isLive ? 'Live Updates On' : 'Live Updates Off'}
      </button>
    </div>
  )
}

// ── Data Residency Section (always visible at top of Overview) ─────────────────

function DataResidencySummary() {
  const [data, setData] = useState<DataResidencyInfo | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    (async () => {
      try {
        const { data: res } = await api.get('/api/saas/data-residency')
        setData(res)
      } catch {
        // Endpoint may not exist
      }
      setLoading(false)
    })()
  }, [])

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-[280px] bg-white/[0.03] rounded-xl animate-pulse" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[1,2,3,4].map(i => <div key={i} className="h-20 bg-white/[0.03] rounded-xl animate-pulse" />)}
        </div>
      </div>
    )
  }

  if (!data) return null

  const regionColors: Record<string, string> = {
    'North America': '#3b6ef6',
    'Europe': '#10b981',
    'Asia Pacific': '#f59e0b',
    'Middle East': '#ef4444',
    'South America': '#8b5cf6',
    'Africa': '#ec4899',
  }

  const totalSignIns = data?.user_activity_regions?.reduce((sum, r) => sum + r.sign_in_count, 0) || 0

  const awsRegionToGeo: Record<string, string> = {
    'us-east-1': 'North America', 'us-east-2': 'North America', 'us-west-1': 'North America', 'us-west-2': 'North America',
    'eu-west-1': 'Europe', 'eu-west-2': 'Europe', 'eu-west-3': 'Europe', 'eu-central-1': 'Europe', 'eu-north-1': 'Europe',
    'ap-northeast-1': 'Asia Pacific', 'ap-northeast-2': 'Asia Pacific', 'ap-southeast-1': 'Asia Pacific', 'ap-southeast-2': 'Asia Pacific', 'ap-south-1': 'Asia Pacific',
    'sa-east-1': 'South America', 'me-south-1': 'Middle East', 'af-south-1': 'Africa', 'ca-central-1': 'North America',
  }

  const regionSummaryWithCloud: Record<string, number> = { ...(data?.region_summary || {}) }
  data?.cloud_regions?.forEach((cr) => {
    if (cr.resource_count && cr.resource_count > 0) {
      const geoRegion = awsRegionToGeo[cr.region]
      if (geoRegion) regionSummaryWithCloud[geoRegion] = (regionSummaryWithCloud[geoRegion] || 0) + cr.resource_count
    }
  })

  const connectedProviders = ['M365']
  if (data?.cloud_regions?.length) {
    const uniqueProviders = [...new Set(data.cloud_regions.filter(cr => (cr.resource_count || 0) > 0).map(cr => cr.provider))]
    connectedProviders.push(...uniqueProviders)
  }

  const msDatacenters: Record<string, { lat: number; lng: number }> = {
    'US': { lat: 37.0902, lng: -95.7129 }, 'CA': { lat: 45.4215, lng: -75.6972 },
    'GB': { lat: 51.5074, lng: -0.1278 }, 'UK': { lat: 51.5074, lng: -0.1278 },
    'DE': { lat: 50.1109, lng: 8.6821 }, 'FR': { lat: 48.8566, lng: 2.3522 },
    'NL': { lat: 52.3676, lng: 4.9041 }, 'IE': { lat: 53.3498, lng: -6.2603 },
    'AU': { lat: -33.8688, lng: 151.2093 }, 'JP': { lat: 35.6762, lng: 139.6503 },
    'SG': { lat: 1.3521, lng: 103.8198 }, 'IN': { lat: 19.0760, lng: 72.8777 },
    'BR': { lat: -23.5505, lng: -46.6333 }, 'ZA': { lat: -33.9249, lng: 18.4241 },
    'AE': { lat: 25.2048, lng: 55.2708 },
    'North America': { lat: 39.0438, lng: -77.4874 }, 'NAM': { lat: 39.0438, lng: -77.4874 },
    'EUR': { lat: 52.3676, lng: 4.9041 }, 'Europe': { lat: 52.3676, lng: 4.9041 },
    'APC': { lat: 1.3521, lng: 103.8198 }, 'Asia Pacific': { lat: 1.3521, lng: 103.8198 },
  }

  const dataLocations: Array<{ lat: number; lng: number; label: string; type: 'storage' | 'access' }> = []
  const tenantKey = data?.tenant_country || data?.tenant_region || ''
  if (tenantKey && msDatacenters[tenantKey]) {
    dataLocations.push({ ...msDatacenters[tenantKey], label: `M365 Tenant (${tenantKey})`, type: 'storage' })
  }

  return (
    <div className="space-y-4">
      {/* World Map - Always Visible */}
      <WorldMap 
        regions={data?.user_activity_regions || []} 
        dataLocations={dataLocations}
        cloudRegions={data?.cloud_regions?.filter(cr => cr.lat && cr.lng) || []}
      />

      {/* Primary Region Header + Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
        {/* Primary Region Card */}
        <div className="lg:col-span-1 bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Globe size={16} className="text-[#3b6ef6]" />
            <span className="text-[10px] text-[var(--muted)] uppercase">Primary Region</span>
          </div>
          <div className="text-[15px] font-semibold text-[var(--foreground)] mb-2">
            {data?.primary_data_region || data?.tenant_region || data?.tenant_country || 'Unknown'}
          </div>
          <div className="flex flex-wrap gap-1">
            {connectedProviders.map((p, i) => (
              <span key={i} className={`px-1.5 py-0.5 rounded text-[8px] font-semibold border ${
                p === 'AWS' ? 'bg-[#FF9900]/10 border-[#FF9900]/25 text-[#FF9900]' :
                p === 'GCP' ? 'bg-[#4285F4]/10 border-[#4285F4]/25 text-[#4285F4]' :
                'bg-blue-500/10 border-blue-500/25 text-blue-400'
              }`}>{p}</span>
            ))}
          </div>
        </div>

        {/* Sign-ins */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-1.5 mb-2">
            <Activity size={13} className="text-[#3b6ef6]" />
            <span className="text-[10px] text-[var(--muted)] uppercase">Sign-ins</span>
          </div>
          <div className="text-xl font-bold text-[var(--foreground)]">{totalSignIns.toLocaleString()}</div>
          <div className="text-[10px] text-[var(--muted)]">{data?.user_activity_regions?.length || 0} countries</div>
        </div>

        {/* Top Region */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-1.5 mb-2">
            <TrendingUp size={13} className="text-emerald-400" />
            <span className="text-[10px] text-[var(--muted)] uppercase">Top Region</span>
          </div>
          <div className="text-lg font-bold text-[var(--foreground)]">
            {Object.entries(regionSummaryWithCloud).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1])[0]?.[0] || 'N/A'}
          </div>
          <div className="text-[10px] text-[var(--muted)]">
            {Object.entries(regionSummaryWithCloud).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1])[0]?.[1]?.toLocaleString() || 0} events
          </div>
        </div>

        {/* Data Stores */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-1.5 mb-2">
            <Database size={13} className="text-amber-400" />
            <span className="text-[10px] text-[var(--muted)] uppercase">Data Stores</span>
          </div>
          <div className="text-xl font-bold text-[var(--foreground)]">{data?.data_locations?.length || 0}</div>
          <div className="text-[10px] text-[var(--muted)]">across regions</div>
        </div>

        {/* Compliance */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-1.5 mb-2">
            <CheckCircle2 size={13} className="text-purple-400" />
            <span className="text-[10px] text-[var(--muted)] uppercase">Compliance</span>
          </div>
          <div className="text-xl font-bold text-emerald-400">{data?.compliance_regions?.length || 0}</div>
          <div className="text-[10px] text-[var(--muted)]">frameworks</div>
        </div>
      </div>

      {/* Activity by Region + Compliance + Cloud Regions */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Region Distribution */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <h3 className="text-[12px] font-semibold text-[var(--foreground)] mb-3 flex items-center gap-2">
            <BarChart3 size={12} className="text-[#3b6ef6]" />
            Activity by Region
          </h3>
          {Object.entries(regionSummaryWithCloud).filter(([, v]) => v > 0).length === 0 ? (
            <div className="text-center py-4 text-[var(--muted)] text-[10px]">No regional data</div>
          ) : (
            <div className="space-y-2">
              {Object.entries(regionSummaryWithCloud).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([region, count]) => {
                const pct = totalSignIns > 0 ? (count / totalSignIns) * 100 : 0
                const color = regionColors[region] || '#6b7280'
                return (
                  <div key={region}>
                    <div className="flex items-center justify-between text-[10px] mb-1">
                      <div className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                        <span className="text-[var(--foreground)]">{region}</span>
                      </div>
                      <span className="text-[var(--muted)]">{count.toLocaleString()}</span>
                    </div>
                    <div className="h-1 bg-white/[0.05] rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Compliance Frameworks */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <h3 className="text-[12px] font-semibold text-[var(--foreground)] mb-3 flex items-center gap-2">
            <Shield size={12} className="text-emerald-400" />
            Compliance Frameworks
          </h3>
          {(data?.compliance_regions?.length || 0) === 0 ? (
            <div className="text-center py-4 text-[var(--muted)] text-[10px]">No frameworks identified</div>
          ) : (
            <div className="space-y-1.5">
              {data?.compliance_regions?.slice(0, 4).map((comp, i) => {
                // Score-driven colouring — reflects live posture from the
                // compliance worker assessments, not just country-mapping.
                const pct =
                  typeof comp.score_pct === 'number' ? comp.score_pct : null
                const tone =
                  pct == null     ? { bg: 'bg-slate-500/10',   tx: 'text-slate-400',   ic: 'text-slate-400'   }
                  : pct >= 80     ? { bg: 'bg-emerald-500/10', tx: 'text-emerald-400', ic: 'text-emerald-400' }
                  : pct >= 50     ? { bg: 'bg-amber-500/10',   tx: 'text-amber-400',   ic: 'text-amber-400'   }
                  :                 { bg: 'bg-red-500/10',     tx: 'text-red-400',     ic: 'text-red-400'     }
                const label =
                  pct == null     ? 'No data'
                  : pct >= 80     ? `${pct}% compliant`
                  : pct >= 50     ? `${pct}% partial`
                  :                 `${pct}% at risk`
                return (
                  <div key={i} className="flex items-center justify-between p-2 bg-white/[0.03] rounded-lg border border-white/[0.05]">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 size={12} className={tone.ic} />
                      <div>
                        <div className="text-[10px] font-medium text-[var(--foreground)]">{comp.regulation}</div>
                        <div className="text-[8px] text-[var(--muted)]">
                          {comp.region}
                          {typeof comp.total_controls === 'number' && comp.total_controls > 0 && (
                            <span className="ml-1 text-[var(--muted)]">
                              • {comp.compliant ?? 0}/{comp.total_controls} controls
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <span className={`text-[8px] px-1.5 py-0.5 rounded ${tone.bg} ${tone.tx}`}>
                      {label}
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Cloud Infrastructure by Region */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <h3 className="text-[12px] font-semibold text-[var(--foreground)] mb-3 flex items-center gap-2">
            <Server size={12} className="text-[#FF9900]" />
            Cloud Infrastructure
          </h3>
          {(!data?.cloud_regions || data.cloud_regions.filter(cr => (cr.resource_count || 0) > 0).length === 0) ? (
            <div className="text-center py-4 text-[var(--muted)] text-[10px]">No cloud resources</div>
          ) : (
            <div className="space-y-1.5">
              {data.cloud_regions.filter(cr => (cr.resource_count || 0) > 0).sort((a, b) => (b.resource_count || 0) - (a.resource_count || 0)).slice(0, 4).map((cr, i) => {
                const color = cr.provider === 'AWS' ? '#FF9900' : cr.provider === 'GCP' ? '#4285F4' : '#10b981'
                return (
                  <div key={i} className="flex items-center justify-between p-2 bg-white/[0.03] rounded-lg border border-white/[0.05]">
                    <div className="flex items-center gap-2">
                      <div className="w-5 h-5 rounded flex items-center justify-center" style={{ backgroundColor: color + '20' }}>
                        {cr.provider === 'AWS' ? <AWSLogo size={10} /> : <Cloud size={10} style={{ color }} />}
                      </div>
                      <div>
                        <div className="text-[10px] font-medium text-[var(--foreground)]">{cr.region}</div>
                        <div className="text-[8px] text-[var(--muted)]">{cr.provider}</div>
                      </div>
                    </div>
                    <div className="text-[11px] font-semibold" style={{ color }}>{cr.resource_count}</div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function WorkspaceOverviewTab() {
  const [stats, setStats] = useState<WorkspaceStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [recentAlerts, setRecentAlerts] = useState<Array<{
    id: string
    alert_type: string
    severity: string
    title: string
    created_at: string
    provider?: string
  }>>([]);
  const alertsRef = useRef<typeof recentAlerts>([])
  const [isLive, setIsLive] = useState(true)

  // Initial load
  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true)
        const [statsResp, alertsResp] = await Promise.all([
          api.get('/api/saas/stats').catch(() => ({ data: null })),
          api.get('/api/saas/alerts?page_size=10&status=open').catch(() => ({ data: { items: [] } })),
        ])
        setStats(statsResp.data)
        const alerts = alertsResp.data?.items ?? []
        setRecentAlerts(alerts)
        alertsRef.current = alerts
      } catch {
        // Stats endpoint may not exist yet
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  // Live polling for alerts (every 15 seconds)
  useEffect(() => {
    if (!isLive) return
    const interval = setInterval(async () => {
      try {
        const alertsResp = await api.get('/api/saas/alerts?page_size=10&status=open').catch(() => ({ data: { items: [] } }))
        const newAlerts = alertsResp.data?.items ?? []
        // Only update if there are new alerts
        if (JSON.stringify(newAlerts.map((a: { id: string }) => a.id)) !== JSON.stringify(alertsRef.current.map(a => a.id))) {
          setRecentAlerts(newAlerts)
          alertsRef.current = newAlerts
        }
      } catch {
        // Ignore polling errors
      }
    }, 15000)
    return () => clearInterval(interval)
  }, [isLive])

  // Mock/fallback stats while backend endpoint is built
  const displayStats = stats || {
    total_files: 0,
    classified_files: 0,
    sensitive_files: 0,
    external_shares: 0,
    alerts_today: 0,
    alerts_week: 0,
    posture_score: 0,
    connected_apps: 0,
    users_monitored: 0,
    high_risk_users: 0,
    data_by_classification: [],
    alerts_by_type: [],
    trend_7d: [],
    funnel_data: { total_resources: 0, misconfigs: 0, exposures: 0, exploitable: 0, by_provider: {} },
    workers_status: { classification_worker: true, alert_scanner: true, posture_checker: true, sync_worker: true, iam_scanner: true },
    iam_risks: [],
  }

  const classificationColors: Record<string, string> = {
    public: '#10b981',
    internal: '#3b82f6',
    confidential: '#f59e0b',
    highly_confidential: '#ef4444',
  }

  const alertTypeColors: Record<string, string> = {
    sensitive_data: '#f97316',
    data_exposure: '#ef4444',
    impossible_travel: '#ef4444',
    external_forwarding: '#f59e0b',
    risky_oauth_app: '#a855f7',
    mass_download: '#f97316',
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => (
            <div key={i} className="h-32 bg-white/[0.03] rounded-xl animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-64 bg-white/[0.03] rounded-xl animate-pulse" />
          <div className="h-64 bg-white/[0.03] rounded-xl animate-pulse" />
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Data Residency Map - Always at Top */}
      <DataResidencySummary />

      {/* Key Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {/* Cloud Resources */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-[#FF9900]/10 border border-[#FF9900]/20 flex items-center justify-center">
              <Cloud size={18} className="text-[#FF9900]" />
            </div>
            {(displayStats.cloud_stats?.total_resources ?? 0) > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-[#FF9900]/10 border border-[#FF9900]/20 text-[10px] font-semibold text-[#FF9900]">live</span>
            )}
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {(displayStats.cloud_stats?.total_resources ?? 0).toLocaleString()}
          </div>
          <div className="text-[12px] text-[#71717a]">Cloud Resources</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06] flex items-center gap-3 flex-wrap">
            {Object.entries(displayStats.cloud_stats?.by_provider || {}).slice(0, 3).map(([prov, st]) => (
              <span key={prov} className="text-[10px] text-[#71717a]">
                <span className="uppercase font-semibold mr-1" style={{ color: prov === 'aws' ? '#FF9900' : prov === 'gcp' ? '#4285F4' : '#a1a1aa' }}>{prov}</span>
                {st.resources}
              </span>
            ))}
            {(displayStats.cloud_stats?.total_resources ?? 0) === 0 && (
              <span className="text-[11px] text-[#71717a]">No cloud connector yet</span>
            )}
          </div>
        </div>

        {/* Connected Apps */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-[#3b6ef6]/10 border border-[#3b6ef6]/20 flex items-center justify-center">
              <Layers size={18} className="text-[#3b6ef6]" />
            </div>
            {displayStats.connected_apps > 0 && (
              <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[10px] font-semibold text-emerald-400">active</span>
            )}
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {displayStats.connected_apps}
          </div>
          <div className="text-[12px] text-[#71717a]">Connected Apps</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06] flex items-center gap-2 flex-wrap">
            {displayStats.email_stats?.m365_connected && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 font-semibold">M365</span>
            )}
            {displayStats.email_stats?.google_connected && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">Google</span>
            )}
            {(displayStats.cloud_stats?.connections?.aws ?? 0) > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#FF9900]/15 text-[#FF9900] font-semibold">AWS</span>
            )}
            {(displayStats.cloud_stats?.connections?.gcp ?? 0) > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#4285F4]/15 text-[#4285F4] font-semibold">GCP</span>
            )}
            {(displayStats.cloud_stats?.connections?.databricks ?? 0) > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#FF3621]/15 text-[#FF3621] font-semibold">Databricks</span>
            )}
            {displayStats.connected_apps === 0 && (
              <span className="text-[11px] text-[#71717a]">Connect a workspace to begin</span>
            )}
          </div>
        </div>

        {/* Sensitive Files */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center">
              <FileWarning size={18} className="text-red-400" />
            </div>
            {displayStats.sensitive_files > 0 && (
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500" />
              </span>
            )}
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {displayStats.sensitive_files.toLocaleString()}
          </div>
          <div className="text-[12px] text-[#71717a]">Sensitive Files</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06] flex items-center justify-between">
            <span className="text-[11px] text-[#71717a]">{displayStats.classified_files.toLocaleString()} classified</span>
          </div>
        </div>

        {/* Alerts Today */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
              <ShieldAlert size={18} className="text-amber-400" />
            </div>
            {displayStats.alerts_today > 0 && (
              <div className="px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/20">
                <span className="text-[11px] font-semibold text-amber-400">+{displayStats.alerts_today}</span>
              </div>
            )}
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {displayStats.alerts_week}
          </div>
          <div className="text-[12px] text-[#71717a]">Alerts This Week</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06] flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-[11px] text-[#71717a]">{displayStats.alerts_today} today</span>
            </div>
          </div>
        </div>

        {/* External Shares */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
              <Globe size={18} className="text-purple-400" />
            </div>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {displayStats.external_shares.toLocaleString()}
          </div>
          <div className="text-[12px] text-[#71717a]">External Shares</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06]">
            <span className="text-[11px] text-[#71717a]">Files shared outside org</span>
          </div>
        </div>

        {/* Posture Score */}
        <div className="bg-gradient-to-br from-[#13131a] to-[#1a1a24] border border-white/[0.06] rounded-xl p-5">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <ShieldCheck size={18} className="text-emerald-400" />
            </div>
            <div className={`px-2 py-0.5 rounded-full border ${
              displayStats.posture_score >= 80 ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
              displayStats.posture_score >= 60 ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
              'bg-red-500/10 border-red-500/20 text-red-400'
            }`}>
              <span className="text-[11px] font-semibold">
                {displayStats.posture_score >= 80 ? 'Good' : displayStats.posture_score >= 60 ? 'Fair' : 'Poor'}
              </span>
            </div>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)] mb-1">
            {displayStats.posture_score}%
          </div>
          <div className="text-[12px] text-[#71717a]">Security Posture</div>
          <div className="mt-3 pt-3 border-t border-white/[0.06]">
            <div className="w-full bg-white/[0.06] rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full ${
                  displayStats.posture_score >= 80 ? 'bg-emerald-500' :
                  displayStats.posture_score >= 60 ? 'bg-amber-500' : 'bg-red-500'
                }`}
                style={{ width: `${displayStats.posture_score}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Data Classification Distribution */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <Database size={15} className="text-[#3b6ef6]" />
            Data Classification
          </h3>
          {displayStats.data_by_classification.length > 0 ? (() => {
            const total = displayStats.data_by_classification.reduce((sum, d) => sum + d.count, 0)
            // Build SVG pie chart
            const cx = 60, cy = 60, r = 55
            let cumAngle = -Math.PI / 2
            const slices = displayStats.data_by_classification.map(item => {
              const pct = total > 0 ? item.count / total : 0
              const angle = pct * 2 * Math.PI
              const x1 = cx + r * Math.cos(cumAngle)
              const y1 = cy + r * Math.sin(cumAngle)
              cumAngle += angle
              const x2 = cx + r * Math.cos(cumAngle)
              const y2 = cy + r * Math.sin(cumAngle)
              const large = angle > Math.PI ? 1 : 0
              return { item, pct, x1, y1, x2, y2, large, color: classificationColors[item.label] || '#71717a' }
            })
            return (
              <div className="flex gap-4 items-start">
                {/* Pie chart */}
                <svg width="120" height="120" viewBox="0 0 120 120" className="flex-shrink-0">
                  {slices.map((s, i) => (
                    s.pct > 0.005 ? (
                      <path
                        key={i}
                        d={`M ${cx} ${cy} L ${s.x1.toFixed(2)} ${s.y1.toFixed(2)} A ${r} ${r} 0 ${s.large} 1 ${s.x2.toFixed(2)} ${s.y2.toFixed(2)} Z`}
                        fill={s.color}
                        stroke="#13131a"
                        strokeWidth="2"
                        opacity="0.9"
                      />
                    ) : null
                  ))}
                  <circle cx={cx} cy={cy} r="32" fill="#0a0a0f" />
                  <text x={cx} y={cy - 6} textAnchor="middle" className="fill-[#e4e4e7]" fontSize="14" fontWeight="bold">{total.toLocaleString()}</text>
                  <text x={cx} y={cy + 10} textAnchor="middle" className="fill-[#71717a]" fontSize="8">items</text>
                </svg>
                {/* Legend + bars */}
                <div className="flex-1 space-y-2.5">
                  {displayStats.data_by_classification.map((item, i) => {
                    const pct = total > 0 ? Math.round((item.count / total) * 100) : 0
                    const color = classificationColors[item.label] || '#71717a'
                    return (
                      <div key={i}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
                            <span className="text-[11px] text-[#a1a1aa] capitalize">{item.label.replace(/_/g, ' ')}</span>
                          </div>
                          <span className="text-[11px] font-semibold text-[var(--foreground)]">{pct}%</span>
                        </div>
                        <div className="w-full bg-white/[0.06] rounded-full h-1.5">
                          <div className="h-1.5 rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })() : (
            <div className="text-center py-8 text-[var(--muted)] text-[12px]">
              <Database size={24} className="mx-auto mb-2 opacity-50" />
              Connect a workspace to see data classification
            </div>
          )}
        </div>

        {/* Alert Types Distribution */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <ShieldAlert size={15} className="text-[#3b6ef6]" />
            Alerts by Type
          </h3>
          {displayStats.alerts_by_type.length > 0 ? (
            <div className="space-y-3">
              {displayStats.alerts_by_type.slice(0, 6).map((item, i) => {
                const total = displayStats.alerts_by_type.reduce((sum, d) => sum + d.count, 0)
                const pct = total > 0 ? Math.round((item.count / total) * 100) : 0
                const color = alertTypeColors[item.type] || '#71717a'
                return (
                  <div key={i}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                        <span className="text-[12px] text-[#a1a1aa] capitalize">{item.type.replace(/_/g, ' ')}</span>
                      </div>
                      <span className="text-[12px] font-semibold text-[var(--foreground)]">{item.count}</span>
                    </div>
                    <div className="w-full bg-white/[0.06] rounded-full h-2">
                      <div
                        className="h-2 rounded-full transition-all"
                        style={{ width: `${pct}%`, backgroundColor: color }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="text-center py-8 text-[var(--muted)] text-[12px]">
              <ShieldAlert size={24} className="mx-auto mb-2 opacity-50" />
              No alerts yet — great job!
            </div>
          )}
        </div>
      </div>

      {/* Security Funnel + Live Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Security Exposure Funnel (Wiz/Averlon style) */}
        <SecurityFunnelView data={displayStats.funnel_data || { total_resources: 0, misconfigs: 0, exposures: 0, exploitable: 0, by_provider: {} }} />

        {/* Live Alerts Panel */}
        <LiveAlertsPanel alerts={recentAlerts} isLive={isLive} />
      </div>

      {/* Cloud Infrastructure Findings */}
      {displayStats.cloud_stats && (displayStats.cloud_stats.total_findings > 0 || displayStats.cloud_stats.total_resources > 0) && (
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <Cloud size={15} className="text-orange-400" />
            Cloud Infrastructure
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
            <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
              <div className="text-[10px] text-[#71717a] mb-1">Resources</div>
              <div className="text-lg font-bold text-[var(--foreground)]">
                {displayStats.cloud_stats.total_resources.toLocaleString()}
              </div>
            </div>
            <div className="bg-white/[0.02] rounded-lg p-3 border border-white/[0.04]">
              <div className="text-[10px] text-[#71717a] mb-1">Findings</div>
              <div className="text-lg font-bold text-[var(--foreground)]">
                {displayStats.cloud_stats.total_findings}
              </div>
            </div>
            <div className="bg-red-500/10 rounded-lg p-3 border border-red-500/20">
              <div className="text-[10px] text-red-400 mb-1">Critical</div>
              <div className="text-lg font-bold text-red-400">
                {displayStats.cloud_stats.critical_findings}
              </div>
            </div>
            <div className="bg-orange-500/10 rounded-lg p-3 border border-orange-500/20">
              <div className="text-[10px] text-orange-400 mb-1">High</div>
              <div className="text-lg font-bold text-orange-400">
                {displayStats.cloud_stats.high_findings}
              </div>
            </div>
          </div>
          
          {/* By Provider */}
          {Object.keys(displayStats.cloud_stats.by_provider).length > 0 && (
            <div className="mb-4">
              <div className="text-[11px] text-[#71717a] mb-2">By Provider</div>
              <div className="flex flex-wrap gap-2">
                {Object.entries(displayStats.cloud_stats.by_provider).map(([provider, data]) => (
                  <div key={provider} className="bg-white/[0.02] rounded-lg px-3 py-2 border border-white/[0.04]">
                    <span className="text-[11px] font-semibold text-[var(--foreground)] uppercase">{provider}</span>
                    <span className="text-[10px] text-[#71717a] ml-2">
                      {data.resources} resources • {data.findings} findings
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Data Regions */}
          {displayStats.cloud_stats.data_regions.length > 0 && (
            <div className="mb-4">
              <div className="text-[11px] text-[#71717a] mb-2">Data Regions</div>
              <div className="flex flex-wrap gap-2">
                {displayStats.cloud_stats.data_regions.slice(0, 10).map((r, i) => (
                  <span key={i} className="px-2 py-1 rounded-full bg-[#3b6ef6]/10 border border-[#3b6ef6]/20 text-[10px] text-[#3b6ef6]">
                    {r.provider.toUpperCase()}: {r.region}
                  </span>
                ))}
              </div>
            </div>
          )}
          
          {/* Recent Cloud Findings */}
          {displayStats.cloud_stats.recent_findings.length > 0 && (
            <div>
              <div className="text-[11px] text-[#71717a] mb-2">Recent Findings</div>
              <div className="space-y-2">
                {displayStats.cloud_stats.recent_findings.slice(0, 5).map((finding, i) => (
                  <div key={i} className="flex items-center gap-3 p-2 bg-white/[0.02] rounded-lg border border-white/[0.04]">
                    <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      finding.severity === 'critical' ? 'bg-red-500' :
                      finding.severity === 'high' ? 'bg-orange-500' :
                      finding.severity === 'medium' ? 'bg-amber-500' : 'bg-emerald-500'
                    }`} />
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] font-medium text-[var(--foreground)] truncate">
                        {finding.title}
                      </div>
                      <div className="text-[9px] text-[#71717a]">
                        {finding.provider.toUpperCase()} • {finding.category}
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded-full text-[9px] font-semibold border ${
                      finding.severity === 'critical' ? 'bg-red-500/10 border-red-500/20 text-red-400' :
                      finding.severity === 'high' ? 'bg-orange-500/10 border-orange-500/20 text-orange-400' :
                      finding.severity === 'medium' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
                      'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                    }`}>
                      {finding.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Data Sovereignty Notice removed - data residency shown in dedicated tab */}
    </div>
  )
}

// ── Cloud Infrastructure Section ───────────────────────────────────────────────

function CloudInfrastructureSection({ alwaysShow = false }: { alwaysShow?: boolean }) {
  const [awsConnections, setAwsConnections] = useState<Array<{
    id: string
    name: string
    account_id: string | null
    arn: string | null
    status: string
    default_region: string
    scan_regions: string[]
    created_at: string | null
    last_scan_at: string | null
  }>>([]);
  const [gcpConnections, setGcpConnections] = useState<Array<{
    id: string
    name: string
    project_id: string | null
    status: string
    created_at: string | null
    last_scan_at: string | null
  }>>([]);
  const [loading, setLoading] = useState(true)
  const [showAWSModal, setShowAWSModal] = useState(false)
  const [showGCPModal, setShowGCPModal] = useState(false)
  const [showInfoModal, setShowInfoModal] = useState<'aws' | 'gcp' | null>(null)
  const [connecting, setConnecting] = useState<'aws' | 'gcp' | null>(null)
  const [scanning, setScanning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [awsStats, setAwsStats] = useState<{
    resources: { total: number; encrypted: number; public: number }
    findings: { total: number; critical: number; high: number }
  } | null>(null)
  const [gcpStats, setGcpStats] = useState<{
    resources: { total: number; encrypted: number; public: number }
    findings: { total: number; critical: number; high: number }
  } | null>(null)

  // AWS Form state
  const [awsFormData, setAwsFormData] = useState({
    name: 'AWS Account',
    access_key_id: '',
    secret_access_key: '',
    default_region: 'us-east-1',
    scan_regions: ['us-east-1', 'us-west-2', 'eu-west-1'],
  })

  // GCP Form state
  const [gcpFormData, setGcpFormData] = useState({
    name: 'GCP Project',
    project_id: '',
    service_account_json: '',
  })

  const loadConnections = useCallback(async () => {
    try {
      setLoading(true)
      const [awsResp, awsStatsResp, gcpResp, gcpStatsResp] = await Promise.all([
        api.get('/api/aws/connections').catch(() => ({ data: { connections: [] } })),
        api.get('/api/aws/stats').catch(() => ({ data: null })),
        api.get('/api/gcp/connections').catch(() => ({ data: { connections: [] } })),
        api.get('/api/gcp/stats').catch(() => ({ data: null })),
      ])
      setAwsConnections(awsResp.data?.connections ?? [])
      setAwsStats(awsStatsResp.data)
      setGcpConnections(gcpResp.data?.connections ?? [])
      setGcpStats(gcpStatsResp.data)
    } catch {
      // Cloud APIs not available yet
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadConnections() }, [loadConnections])

  const handleAWSConnect = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!awsFormData.access_key_id || !awsFormData.secret_access_key) {
      setError('Access Key ID and Secret Access Key are required')
      return
    }
    try {
      setConnecting('aws')
      setError(null)
      await api.post('/api/aws/connect', awsFormData)
      setShowAWSModal(false)
      setAwsFormData({ name: 'AWS Account', access_key_id: '', secret_access_key: '', default_region: 'us-east-1', scan_regions: ['us-east-1', 'us-west-2', 'eu-west-1'] })
      loadConnections()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to connect AWS account')
    } finally {
      setConnecting(null)
    }
  }

  const handleGCPConnect = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!gcpFormData.project_id || !gcpFormData.service_account_json) {
      setError('Project ID and Service Account JSON are required')
      return
    }
    try {
      setConnecting('gcp')
      setError(null)
      await api.post('/api/gcp/connect', gcpFormData)
      setShowGCPModal(false)
      setGcpFormData({ name: 'GCP Project', project_id: '', service_account_json: '' })
      loadConnections()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to connect GCP project')
    } finally {
      setConnecting(null)
    }
  }

  const handleDisconnect = async (provider: 'aws' | 'gcp', id: string) => {
    if (!confirm(`Disconnect this ${provider.toUpperCase()} account? All scan data will be deleted.`)) return
    try {
      await api.delete(`/api/${provider}/connections/${id}`)
      loadConnections()
    } catch {
      setError('Failed to disconnect')
    }
  }

  const handleScan = async (provider: 'aws' | 'gcp', id: string) => {
    try {
      setScanning(id)
      await api.post(`/api/${provider}/scan/${id}`)
      loadConnections()
    } catch {
      setError('Scan failed')
    } finally {
      setScanning(null)
    }
  }

  const awsRegions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-west-1', 'eu-west-2', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1', 'me-south-1', 'me-central-1']

  // Hide the entire panel on Overview if no AWS/GCP connection exists
  // yet (so the page declutters for orgs with no connections). The
  // Connectors tab passes alwaysShow=true so users still have a way to
  // add a brand-new connector from there.
  if (!alwaysShow && !loading && awsConnections.length === 0 && gcpConnections.length === 0) {
    return null
  }

  return (
    <div className="mt-8 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cloud size={16} className="text-[var(--muted)]" />
          <h3 className="text-[14px] font-semibold text-[var(--foreground)]">Cloud Infrastructure</h3>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* AWS Connector Card */}
        <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5 hover:border-white/[0.12] transition-colors">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[#FF9900]/10">
                <AWSLogo size={24} />
              </div>
              <div>
                <span className="font-semibold text-[var(--foreground)]">Amazon Web Services</span>
                <p className="text-[11px] text-[var(--muted)]">S3, EBS, EFS, RDS + CloudTrail</p>
              </div>
            </div>
            {awsConnections.length === 0 ? (
              <Button size="sm" onClick={() => setShowAWSModal(true)}>
                <Plug size={13} className="mr-1" /> Connect
              </Button>
            ) : (
              <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-emerald-500/10 border-emerald-500/20 text-emerald-400">
                {awsConnections.length} connected
              </span>
            )}
          </div>

          {/* AWS Stats */}
          {awsStats && awsStats.resources.total > 0 && (
            <div className="grid grid-cols-4 gap-2 mt-3 pt-3 border-t border-[var(--border)]">
              <div className="text-center">
                <div className="text-[14px] font-bold text-[var(--foreground)]">{awsStats.resources.total}</div>
                <div className="text-[9px] text-[var(--muted)]">Resources</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-emerald-400">{awsStats.resources.encrypted}</div>
                <div className="text-[9px] text-[var(--muted)]">Encrypted</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-amber-400">{awsStats.resources.public}</div>
                <div className="text-[9px] text-[var(--muted)]">Public</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-red-400">{awsStats.findings.critical + awsStats.findings.high}</div>
                <div className="text-[9px] text-[var(--muted)]">Findings</div>
              </div>
            </div>
          )}

          {/* AWS Connected accounts */}
          {awsConnections.length > 0 && (
            <div className="mt-3 space-y-2">
              {awsConnections.map(conn => (
                <div key={conn.id} className="bg-[var(--background)]/50 rounded-lg p-2 flex items-center justify-between">
                  <div>
                    <div className="text-[11px] font-medium text-[var(--foreground)]">{conn.name}</div>
                    <div className="text-[9px] text-[var(--muted)]">
                      {conn.account_id || 'N/A'} • {conn.default_region}
                    </div>
                  </div>
                  <div className="flex gap-1">
                    <Button size="sm" variant="ghost" onClick={() => handleScan('aws', conn.id)} disabled={scanning === conn.id}>
                      {scanning === conn.id ? <RefreshCw size={11} className="animate-spin" /> : <RefreshCw size={11} />}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => handleDisconnect('aws', conn.id)} className="text-red-400">
                      <Unplug size={11} />
                    </Button>
                  </div>
                </div>
              ))}
              <button onClick={() => setShowAWSModal(true)} className="w-full py-1.5 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] border border-dashed border-[var(--border)] rounded-lg">
                + Add AWS account
              </button>
            </div>
          )}

          <button onClick={() => setShowInfoModal('aws')} className="mt-3 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] flex items-center gap-1">
            <Info size={10} /> IAM setup guide
          </button>
        </div>

        {/* GCP Connector Card */}
        <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5 hover:border-white/[0.12] transition-colors">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[#4285F4]/10">
                <GCPLogo size={24} />
              </div>
              <div>
                <span className="font-semibold text-[var(--foreground)]">Google Cloud Platform</span>
                <p className="text-[11px] text-[var(--muted)]">GCS, BigQuery, Cloud SQL + Audit Logs</p>
              </div>
            </div>
            {gcpConnections.length === 0 ? (
              <Button size="sm" onClick={() => setShowGCPModal(true)}>
                <Plug size={13} className="mr-1" /> Connect
              </Button>
            ) : (
              <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-emerald-500/10 border-emerald-500/20 text-emerald-400">
                {gcpConnections.length} connected
              </span>
            )}
          </div>

          {/* GCP Stats */}
          {gcpStats && gcpStats.resources.total > 0 && (
            <div className="grid grid-cols-4 gap-2 mt-3 pt-3 border-t border-[var(--border)]">
              <div className="text-center">
                <div className="text-[14px] font-bold text-[var(--foreground)]">{gcpStats.resources.total}</div>
                <div className="text-[9px] text-[var(--muted)]">Resources</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-emerald-400">{gcpStats.resources.encrypted}</div>
                <div className="text-[9px] text-[var(--muted)]">Encrypted</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-amber-400">{gcpStats.resources.public}</div>
                <div className="text-[9px] text-[var(--muted)]">Public</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-red-400">{gcpStats.findings.critical + gcpStats.findings.high}</div>
                <div className="text-[9px] text-[var(--muted)]">Findings</div>
              </div>
            </div>
          )}

          {/* GCP Connected projects */}
          {gcpConnections.length > 0 && (
            <div className="mt-3 space-y-2">
              {gcpConnections.map(conn => (
                <div key={conn.id} className="bg-[var(--background)]/50 rounded-lg p-2 flex items-center justify-between">
                  <div>
                    <div className="text-[11px] font-medium text-[var(--foreground)]">{conn.name}</div>
                    <div className="text-[9px] text-[var(--muted)]">{conn.project_id || 'N/A'}</div>
                  </div>
                  <div className="flex gap-1">
                    <Button size="sm" variant="ghost" onClick={() => handleScan('gcp', conn.id)} disabled={scanning === conn.id}>
                      {scanning === conn.id ? <RefreshCw size={11} className="animate-spin" /> : <RefreshCw size={11} />}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => handleDisconnect('gcp', conn.id)} className="text-red-400">
                      <Unplug size={11} />
                    </Button>
                  </div>
                </div>
              ))}
              <button onClick={() => setShowGCPModal(true)} className="w-full py-1.5 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] border border-dashed border-[var(--border)] rounded-lg">
                + Add GCP project
              </button>
            </div>
          )}

          <button onClick={() => setShowInfoModal('gcp')} className="mt-3 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] flex items-center gap-1">
            <Info size={10} /> Service Account setup guide
          </button>
        </div>

        {/* Azure + Oracle Cloud cards (CSPM scan via /api/azure, /api/oracle) */}
        <CSPMConnectors clouds={['azure', 'oracle']} />
      </div>

      {/* AWS Connect Modal */}
      {showAWSModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 overflow-y-auto py-8" onClick={() => setShowAWSModal(false)}>
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl w-full max-w-lg p-6 my-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <AWSLogo size={20} />
                <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Connect AWS Account</h3>
              </div>
              <button onClick={() => setShowAWSModal(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]">
                <X size={18} />
              </button>
            </div>

            {/* IAM Setup Guide */}
            <details className="mb-4 bg-amber-500/5 border border-amber-500/20 rounded-lg">
              <summary className="px-3 py-2 text-[12px] font-semibold text-amber-400 cursor-pointer hover:bg-amber-500/10 rounded-lg">
                ⚙️ IAM Setup Guide (Required Permissions)
              </summary>
              <div className="px-3 pb-3 text-[11px] text-[#a1a1aa] space-y-2">
                <p className="pt-2">Create an IAM user with the following policy for Helios to scan your AWS resources:</p>
                <div className="bg-[var(--background)] rounded-lg p-3 font-mono text-[10px] overflow-x-auto">
                  <pre className="text-emerald-400">{`{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketEncryption",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "efs:DescribeFileSystems",
      "rds:DescribeDBInstances",
      "securityhub:GetFindings",
      "sts:GetCallerIdentity"
    ],
    "Resource": "*"
  }]
}`}</pre>
                </div>
                <p className="text-amber-400">
                  <strong>Steps:</strong> IAM → Users → Create User → Attach Policy (JSON above) → Create Access Key
                </p>
              </div>
            </details>

            {error && (
              <div className="mb-4 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-[12px] text-red-400">
                {error}
              </div>
            )}

            <form onSubmit={handleAWSConnect} className="space-y-4">
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Account Name</label>
                <input
                  type="text"
                  value={awsFormData.name}
                  onChange={e => setAwsFormData(d => ({ ...d, name: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="My AWS Account"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Access Key ID</label>
                <input
                  type="text"
                  value={awsFormData.access_key_id}
                  onChange={e => setAwsFormData(d => ({ ...d, access_key_id: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="AKIAIOSFODNN7EXAMPLE"
                  required
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Secret Access Key</label>
                <input
                  type="password"
                  value={awsFormData.secret_access_key}
                  onChange={e => setAwsFormData(d => ({ ...d, secret_access_key: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                  required
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Default Region</label>
                <select
                  value={awsFormData.default_region}
                  onChange={e => setAwsFormData(d => ({ ...d, default_region: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                >
                  {awsRegions.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Scan Regions</label>
                <div className="flex flex-wrap gap-1">
                  {awsRegions.map(r => (
                    <button
                      key={r}
                      type="button"
                      onClick={() => setAwsFormData(d => ({
                        ...d,
                        scan_regions: d.scan_regions.includes(r)
                          ? d.scan_regions.filter(x => x !== r)
                          : [...d.scan_regions, r]
                      }))}
                      className={`px-2 py-1 text-[10px] rounded border transition-colors ${
                        awsFormData.scan_regions.includes(r)
                          ? 'bg-[#3b6ef6]/20 border-[#3b6ef6]/40 text-[#3b6ef6]'
                          : 'border-[var(--border)] text-[var(--muted)] hover:border-[var(--foreground)]'
                      }`}
                    >
                      {r}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex justify-end pt-2">
                <Button type="submit" disabled={connecting === 'aws'}>
                  {connecting === 'aws' ? <RefreshCw size={13} className="mr-1 animate-spin" /> : <Plug size={13} className="mr-1" />}
                  Connect
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* GCP Connect Modal */}
      {showGCPModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowGCPModal(false)}>
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <GCPLogo size={20} />
                <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Connect GCP Project</h3>
              </div>
              <button onClick={() => setShowGCPModal(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]">
                <X size={18} />
              </button>
            </div>

            {error && (
              <div className="mb-4 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-[12px] text-red-400">
                {error}
              </div>
            )}

            <form onSubmit={handleGCPConnect} className="space-y-4">
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Project Name</label>
                <input
                  type="text"
                  value={gcpFormData.name}
                  onChange={e => setGcpFormData(d => ({ ...d, name: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="My GCP Project"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Project ID</label>
                <input
                  type="text"
                  value={gcpFormData.project_id}
                  onChange={e => setGcpFormData(d => ({ ...d, project_id: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="my-project-123456"
                  required
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Service Account JSON</label>
                <textarea
                  value={gcpFormData.service_account_json}
                  onChange={e => setGcpFormData(d => ({ ...d, service_account_json: e.target.value }))}
                  className="w-full px-3 py-2 text-[11px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6] h-32"
                  placeholder='{"type": "service_account", ...}'
                  required
                />
                <p className="text-[10px] text-[var(--muted)] mt-1">Paste the full service account key JSON file contents</p>
              </div>
              <div className="flex justify-end pt-2">
                <Button type="submit" disabled={connecting === 'gcp'}>
                  {connecting === 'gcp' ? <RefreshCw size={13} className="mr-1 animate-spin" /> : <Plug size={13} className="mr-1" />}
                  Connect
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Info Modals */}
      {showInfoModal === 'aws' && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowInfoModal(null)}>
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl w-full max-w-lg p-6 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Setting Up AWS IAM Credentials</h3>
              <button onClick={() => setShowInfoModal(null)} className="text-[var(--muted)] hover:text-[var(--foreground)]">
                <X size={18} />
              </button>
            </div>
            <div className="space-y-4 text-[12px] text-[var(--muted)]">
              <p className="text-[var(--foreground)]">Helios requires read-only access to scan your AWS resources.</p>
              <div className="space-y-3">
                <h4 className="font-semibold text-[var(--foreground)]">Required IAM Policies:</h4>
                <ul className="list-disc list-inside space-y-1 pl-2">
                  <li><code className="bg-[var(--background)] px-1 rounded">AmazonS3ReadOnlyAccess</code></li>
                  <li><code className="bg-[var(--background)] px-1 rounded">AmazonEC2ReadOnlyAccess</code></li>
                  <li><code className="bg-[var(--background)] px-1 rounded">AmazonRDSReadOnlyAccess</code></li>
                  <li><code className="bg-[var(--background)] px-1 rounded">CloudTrailReadOnlyAccess</code></li>
                </ul>
              </div>
              <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">
                <p className="text-amber-400 font-medium">Security Best Practices:</p>
                <ul className="list-disc list-inside mt-2 space-y-1">
                  <li>Use dedicated IAM user for Helios only</li>
                  <li>Never use root account credentials</li>
                  <li>Rotate access keys periodically</li>
                </ul>
              </div>
            </div>
            <div className="mt-6 flex justify-end">
              <Button onClick={() => setShowInfoModal(null)}>Got it</Button>
            </div>
          </div>
        </div>
      )}

      {showInfoModal === 'gcp' && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowInfoModal(null)}>
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl w-full max-w-lg p-6 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Setting Up GCP Service Account</h3>
              <button onClick={() => setShowInfoModal(null)} className="text-[var(--muted)] hover:text-[var(--foreground)]">
                <X size={18} />
              </button>
            </div>
            <div className="space-y-4 text-[12px] text-[var(--muted)]">
              <p className="text-[var(--foreground)]">Helios requires a service account with viewer access.</p>
              <div className="space-y-3">
                <h4 className="font-semibold text-[var(--foreground)]">Steps:</h4>
                <ol className="list-decimal list-inside space-y-2 pl-2">
                  <li>Go to <span className="text-[#3b6ef6]">IAM & Admin → Service Accounts</span></li>
                  <li>Create service account named <code className="bg-[var(--background)] px-1 rounded">helios-scanner</code></li>
                  <li>Grant these roles:
                    <ul className="list-disc list-inside ml-4 mt-1">
                      <li><code className="bg-[var(--background)] px-1 rounded">Storage Object Viewer</code></li>
                      <li><code className="bg-[var(--background)] px-1 rounded">BigQuery Data Viewer</code></li>
                      <li><code className="bg-[var(--background)] px-1 rounded">Cloud SQL Viewer</code></li>
                      <li><code className="bg-[var(--background)] px-1 rounded">Logs Viewer</code></li>
                    </ul>
                  </li>
                  <li>Create & download JSON key</li>
                </ol>
              </div>
            </div>
            <div className="mt-6 flex justify-end">
              <Button onClick={() => setShowInfoModal(null)}>Got it</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── AI Infrastructure Section ──────────────────────────────────────────────────

function AIInfrastructureSection({ alwaysShow = false }: { alwaysShow?: boolean }) {
  const [databricksConnections, setDatabricksConnections] = useState<Array<{
    id: string
    name: string
    workspace_url: string
    status: string
    created_at: string | null
    last_scan_at: string | null
  }>>([]);
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [stats, setStats] = useState<{
    notebooks: number
    clusters: number
    secrets: number
    findings: number
  } | null>(null)

  const [formData, setFormData] = useState({
    name: 'Databricks Workspace',
    workspace_url: '',
    access_token: '',
  })

  const loadConnections = useCallback(async () => {
    try {
      setLoading(true)
      const [connResp, statsResp] = await Promise.all([
        api.get('/api/databricks/connections').catch(() => ({ data: { connections: [] } })),
        api.get('/api/databricks/stats').catch(() => ({ data: null })),
      ])
      setDatabricksConnections(connResp.data?.connections ?? [])
      setStats(statsResp.data)
    } catch {
      // Not available yet
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadConnections() }, [loadConnections])

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.workspace_url || !formData.access_token) {
      setError('Workspace URL and Access Token are required')
      return
    }
    try {
      setConnecting(true)
      setError(null)
      await api.post('/api/databricks/connect', formData)
      setShowModal(false)
      setFormData({ name: 'Databricks Workspace', workspace_url: '', access_token: '' })
      loadConnections()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to connect Databricks workspace')
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async (id: string) => {
    if (!confirm('Disconnect this Databricks workspace?')) return
    try {
      await api.delete(`/api/databricks/connections/${id}`)
      loadConnections()
    } catch {
      setError('Failed to disconnect')
    }
  }

  const handleScan = async (id: string) => {
    try {
      setScanning(id)
      await api.post(`/api/databricks/scan/${id}`)
      loadConnections()
    } catch {
      setError('Scan failed')
    } finally {
      setScanning(null)
    }
  }

  // Hide panel on Overview until at least one AI/ML provider is connected.
  // Connectors tab passes alwaysShow=true so users can add the first one.
  if (!alwaysShow && !loading && databricksConnections.length === 0) {
    return null
  }

  return (
    <div className="mt-8 space-y-4">
      <div className="flex items-center gap-2">
        <Activity size={16} className="text-[var(--muted)]" />
        <h3 className="text-[14px] font-semibold text-[var(--foreground)]">AI Infrastructure</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Databricks Connector Card */}
        <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5 hover:border-white/[0.12] transition-colors">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[#FF3621]/10">
                <DatabricksLogo size={24} />
              </div>
              <div>
                <span className="font-semibold text-[var(--foreground)]">Databricks</span>
                <p className="text-[11px] text-[var(--muted)]">Notebooks, clusters, Unity Catalog + MLflow, secrets</p>
              </div>
            </div>
            {databricksConnections.length === 0 ? (
              <Button size="sm" onClick={() => setShowModal(true)}>
                <Plug size={13} className="mr-1" /> Connect
              </Button>
            ) : (
              <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-emerald-500/10 border-emerald-500/20 text-emerald-400">
                {databricksConnections.length} connected
              </span>
            )}
          </div>

          {/* Databricks Stats */}
          {stats && (
            <div className="grid grid-cols-4 gap-2 mt-3 pt-3 border-t border-[var(--border)]">
              <div className="text-center">
                <div className="text-[14px] font-bold text-[var(--foreground)]">{stats.notebooks}</div>
                <div className="text-[9px] text-[var(--muted)]">Notebooks</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-[var(--foreground)]">{stats.clusters}</div>
                <div className="text-[9px] text-[var(--muted)]">Clusters</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-amber-400">{stats.secrets}</div>
                <div className="text-[9px] text-[var(--muted)]">Secrets</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-red-400">{stats.findings}</div>
                <div className="text-[9px] text-[var(--muted)]">Findings</div>
              </div>
            </div>
          )}

          {/* Connected workspaces */}
          {databricksConnections.length > 0 && (
            <div className="mt-3 space-y-2">
              {databricksConnections.map(conn => (
                <div key={conn.id} className="bg-[var(--background)]/50 rounded-lg p-2 flex items-center justify-between">
                  <div>
                    <div className="text-[11px] font-medium text-[var(--foreground)]">{conn.name}</div>
                    <div className="text-[9px] text-[var(--muted)] truncate max-w-[180px]">{conn.workspace_url}</div>
                  </div>
                  <div className="flex gap-1">
                    <Button size="sm" variant="ghost" onClick={() => handleScan(conn.id)} disabled={scanning === conn.id}>
                      {scanning === conn.id ? <RefreshCw size={11} className="animate-spin" /> : <RefreshCw size={11} />}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => handleDisconnect(conn.id)} className="text-red-400">
                      <Unplug size={11} />
                    </Button>
                  </div>
                </div>
              ))}
              <button onClick={() => setShowModal(true)} className="w-full py-1.5 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] border border-dashed border-[var(--border)] rounded-lg">
                + Add workspace
              </button>
            </div>
          )}
        </div>

        {/* Snowflake SSPM connector */}
        <SnowflakeConnectorCard />
      </div>

      {/* Databricks Connect Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowModal(false)}>
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <DatabricksLogo size={20} />
                <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Connect Databricks</h3>
              </div>
              <button onClick={() => setShowModal(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]">
                <X size={18} />
              </button>
            </div>

            {error && (
              <div className="mb-4 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-[12px] text-red-400">
                {error}
              </div>
            )}

            <form onSubmit={handleConnect} className="space-y-4">
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Workspace Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={e => setFormData(d => ({ ...d, name: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="Production Workspace"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Workspace URL</label>
                <input
                  type="url"
                  value={formData.workspace_url}
                  onChange={e => setFormData(d => ({ ...d, workspace_url: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="https://adb-1234567890.12.azuredatabricks.net"
                  required
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Personal Access Token</label>
                <input
                  type="password"
                  value={formData.access_token}
                  onChange={e => setFormData(d => ({ ...d, access_token: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="dapi..."
                  required
                />
                <p className="text-[10px] text-[var(--muted)] mt-1">Generate in User Settings → Developer → Access Tokens</p>
              </div>
              <div className="flex justify-end pt-2">
                <Button type="submit" disabled={connecting}>
                  {connecting ? <RefreshCw size={13} className="mr-1 animate-spin" /> : <Plug size={13} className="mr-1" />}
                  Connect
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Snowflake SSPM Connector Card (AI Infrastructure) ──────────────────────

function SnowflakeLogo({ size = 22 }: { size?: number }) {
  // Official Snowflake mark (simple-icons, CC0)
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="#29B5E8">
      <path d="M23.7 16.5l-1.4-.8a1.4 1.4 0 0 0-1.4 0l-2.8 1.6V14a1.4 1.4 0 0 0-.7-1.2L14.6 11l2.8-1.6a1.4 1.4 0 0 0 .7-1.2V4.9l2.8 1.6a1.4 1.4 0 0 0 1.4 0l1.4-.8a.7.7 0 0 0 0-1.2l-1.4-.8a.7.7 0 0 0-.7 0L19.4 4.9V1.6a.7.7 0 0 0-.7-.7h-1.4a.7.7 0 0 0-.7.7v4.7l-2.8 1.6L12 6.5 10.2 7.9 7.4 6.3V1.6a.7.7 0 0 0-.7-.7H5.3a.7.7 0 0 0-.7.7v3.3L3 4a.7.7 0 0 0-.7 0L.9 4.5a.7.7 0 0 0 0 1.2l1.4.8a1.4 1.4 0 0 0 1.4 0l2.8-1.6v3.3a1.4 1.4 0 0 0 .7 1.2L10 11l-2.8 1.6a1.4 1.4 0 0 0-.7 1.2v3.3l-2.8-1.6a1.4 1.4 0 0 0-1.4 0L.9 16.3a.7.7 0 0 0 0 1.2l1.4.8a.7.7 0 0 0 .7 0l1.6-.9v3.3a.7.7 0 0 0 .7.7h1.4a.7.7 0 0 0 .7-.7v-4.7l2.8-1.6L12 16l1.8-1.4 2.8 1.6v4.7a.7.7 0 0 0 .7.7h1.4a.7.7 0 0 0 .7-.7v-3.3l1.6.9a.7.7 0 0 0 .7 0l1.4-.8a.7.7 0 0 0 0-1.2zM12 13.2l-2.5-1.4v-2.9L12 7.5l2.5 1.4v2.9z"/>
    </svg>
  )
}

interface SnowflakeConnection {
  id: string
  name: string
  account: string
  user: string
  role: string
  auth_method: string
  status: string
  created_at: string | null
  last_scan_at: string | null
  last_score: number | null
  last_grade: string | null
}

function SnowflakeConnectorCard() {
  const [connections, setConnections] = useState<SnowflakeConnection[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [showGuide, setShowGuide] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [stats, setStats] = useState<{
    total_findings: number
    critical_findings: number
    high_findings: number
    medium_findings: number
    low_findings: number
    average_score: number | null
    last_scan_at: string | null
  } | null>(null)

  const [authMode, setAuthMode] = useState<'password' | 'keypair'>('password')
  const [formData, setFormData] = useState({
    name: 'Snowflake Account',
    account: '',
    user: '',
    role: 'ACCOUNTADMIN',
    warehouse: '',
    password: '',
    private_key_pem: '',
    private_key_passphrase: '',
  })

  const loadConnections = useCallback(async () => {
    try {
      setLoading(true)
      const [connResp, statsResp] = await Promise.all([
        api.get('/api/snowflake/connections').catch(() => ({ data: { connections: [] } })),
        api.get('/api/snowflake/stats').catch(() => ({ data: null })),
      ])
      setConnections(connResp.data?.connections ?? [])
      setStats(statsResp.data)
    } catch {
      // Not available yet
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadConnections() }, [loadConnections])

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.account || !formData.user) {
      setError('Account identifier and user are required')
      return
    }
    if (authMode === 'password' && !formData.password) {
      setError('Password is required for password authentication')
      return
    }
    if (authMode === 'keypair' && !formData.private_key_pem) {
      setError('Private key PEM is required for key-pair authentication')
      return
    }
    try {
      setConnecting(true)
      setError(null)
      const body: Record<string, unknown> = {
        name: formData.name,
        account: formData.account.trim(),
        user: formData.user.trim(),
        role: formData.role || 'ACCOUNTADMIN',
        warehouse: formData.warehouse.trim() || undefined,
      }
      if (authMode === 'password') {
        body.password = formData.password
      } else {
        body.private_key_pem = formData.private_key_pem
        if (formData.private_key_passphrase) {
          body.private_key_passphrase = formData.private_key_passphrase
        }
      }
      await api.post('/api/snowflake/connect', body)
      setShowModal(false)
      setFormData({
        name: 'Snowflake Account', account: '', user: '',
        role: 'ACCOUNTADMIN', warehouse: '',
        password: '', private_key_pem: '', private_key_passphrase: '',
      })
      loadConnections()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to connect Snowflake account')
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async (id: string) => {
    if (!confirm('Disconnect this Snowflake account?')) return
    try {
      await api.delete(`/api/snowflake/connections/${id}`)
      loadConnections()
    } catch {
      setError('Failed to disconnect')
    }
  }

  const handleScan = async (id: string) => {
    try {
      setScanning(id)
      await api.post(`/api/snowflake/connections/${id}/scan`)
      setTimeout(() => loadConnections(), 2000)
    } catch {
      setError('Scan failed')
    } finally {
      setScanning(null)
    }
  }

  const gradeColor = (g: string | null | undefined) => {
    switch (g) {
      case 'A': return 'text-emerald-400'
      case 'B': return 'text-lime-400'
      case 'C': return 'text-amber-400'
      case 'D': return 'text-orange-400'
      case 'F': return 'text-red-400'
      default: return 'text-[var(--muted)]'
    }
  }

  return (
    <>
      <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5 hover:border-white/[0.12] transition-colors">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[#29B5E8]/10">
              <SnowflakeLogo size={24} />
            </div>
            <div>
              <span className="font-semibold text-[var(--foreground)]">Snowflake</span>
              <p className="text-[11px] text-[var(--muted)]">Users, roles, network policies + CIS Benchmark, DSPM</p>
            </div>
          </div>
          {connections.length === 0 ? (
            <Button size="sm" onClick={() => setShowModal(true)} disabled={loading}>
              <Plug size={13} className="mr-1" /> Connect
            </Button>
          ) : (
            <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-emerald-500/10 border-emerald-500/20 text-emerald-400">
              {connections.length} connected
            </span>
          )}
        </div>

        {stats && connections.length > 0 && (
          <div className="grid grid-cols-5 gap-2 mt-3 pt-3 border-t border-[var(--border)]">
            <div className="text-center">
              <div className={`text-[14px] font-bold ${stats.average_score === null ? 'text-[var(--muted)]' : 'text-[var(--foreground)]'}`}>
                {stats.average_score === null ? '—' : `${Math.round(stats.average_score)}`}
              </div>
              <div className="text-[9px] text-[var(--muted)]">Score</div>
            </div>
            <div className="text-center">
              <div className="text-[14px] font-bold text-red-400">{stats.critical_findings}</div>
              <div className="text-[9px] text-[var(--muted)]">Critical</div>
            </div>
            <div className="text-center">
              <div className="text-[14px] font-bold text-orange-400">{stats.high_findings}</div>
              <div className="text-[9px] text-[var(--muted)]">High</div>
            </div>
            <div className="text-center">
              <div className="text-[14px] font-bold text-amber-400">{stats.medium_findings}</div>
              <div className="text-[9px] text-[var(--muted)]">Medium</div>
            </div>
            <div className="text-center">
              <div className="text-[14px] font-bold text-[var(--foreground)]">{stats.total_findings}</div>
              <div className="text-[9px] text-[var(--muted)]">Total</div>
            </div>
          </div>
        )}

        {connections.length > 0 && (
          <div className="mt-3 space-y-2">
            {connections.map(conn => (
              <div key={conn.id} className="bg-[var(--background)]/50 rounded-lg p-2 flex items-center justify-between">
                <div className="min-w-0">
                  <div className="text-[11px] font-medium text-[var(--foreground)] truncate">
                    {conn.name}
                    {conn.last_grade && (
                      <span className={`ml-2 text-[10px] font-bold ${gradeColor(conn.last_grade)}`}>
                        {conn.last_grade}
                        {conn.last_score !== null ? ` · ${Math.round(conn.last_score)}` : ''}
                      </span>
                    )}
                  </div>
                  <div className="text-[9px] text-[var(--muted)] truncate max-w-[220px] font-mono">
                    {conn.account} · {conn.user} · {conn.auth_method}
                  </div>
                </div>
                <div className="flex gap-1">
                  <Button size="sm" variant="ghost" onClick={() => handleScan(conn.id)} disabled={scanning === conn.id} title="Re-scan">
                    <RefreshCw size={11} className={scanning === conn.id ? 'animate-spin' : ''} />
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => handleDisconnect(conn.id)} className="text-red-400" title="Disconnect">
                    <Unplug size={11} />
                  </Button>
                </div>
              </div>
            ))}
            <button onClick={() => setShowModal(true)} className="w-full py-1.5 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] border border-dashed border-[var(--border)] rounded-lg">
              + Add account
            </button>
          </div>
        )}
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowModal(false)}>
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl w-full max-w-[560px] max-h-[90vh] overflow-y-auto p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <SnowflakeLogo size={20} />
                <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Connect Snowflake</h3>
              </div>
              <button onClick={() => setShowModal(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]">
                <X size={18} />
              </button>
            </div>

            <div className="mb-4 rounded-lg border border-[#29B5E8]/20 bg-[#29B5E8]/5">
              <button
                type="button"
                onClick={() => setShowGuide(g => !g)}
                className="w-full flex items-center justify-between gap-2 px-3 py-2 text-left"
              >
                <span className="text-[12px] font-medium text-[var(--foreground)]">
                  How to set up Snowflake access (5 minutes)
                </span>
                <span className="text-[11px] text-[var(--muted)]">{showGuide ? 'Hide' : 'Show'}</span>
              </button>
              {showGuide && (
                <div className="px-3 pb-3 text-[11px] text-[var(--muted)] leading-relaxed space-y-3">
                  <p>
                    We run the <b>CIS Snowflake Foundations Benchmark v1.0.0</b> (39 checks across IAM,
                    Monitoring, Networking, Data Protection) read-only against your account. Nothing is
                    written to Snowflake.
                  </p>

                  <div>
                    <div className="text-[var(--foreground)] font-medium mb-1">1 · Find your account identifier</div>
                    <p>
                      Sign in to Snowsight → your username menu (bottom left) → hover an account to copy
                      the locator (e.g. <code>xy12345.us-east-1</code> or <code>org-account</code>).
                      Or run in any worksheet: <code>SELECT CURRENT_ACCOUNT(), CURRENT_REGION();</code>
                    </p>
                  </div>

                  <div>
                    <div className="text-[var(--foreground)] font-medium mb-1">2 · Pick a role with read access</div>
                    <p className="mb-1">
                      Easiest: use <b>ACCOUNTADMIN</b>. For least-privilege, create a dedicated role with:
                    </p>
                    <pre className="bg-[var(--background)] border border-[var(--border)] rounded p-2 overflow-x-auto text-[10px] font-mono leading-relaxed">{`USE ROLE ACCOUNTADMIN;
CREATE ROLE HELIOS_SSPM_READER;
-- ACCOUNT_USAGE / READER_ACCOUNT_USAGE schemas
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE HELIOS_SSPM_READER;
-- Recommended fine-grained database roles:
GRANT DATABASE ROLE SNOWFLAKE.SECURITY_VIEWER   TO ROLE HELIOS_SSPM_READER;
GRANT DATABASE ROLE SNOWFLAKE.GOVERNANCE_VIEWER TO ROLE HELIOS_SSPM_READER;
-- Attach to the user you'll authenticate as:
GRANT ROLE HELIOS_SSPM_READER TO USER <YOUR_USER>;`}</pre>
                  </div>

                  <div>
                    <div className="text-[var(--foreground)] font-medium mb-1">3 · Choose an authentication method</div>
                    <ul className="list-disc ml-4 space-y-1">
                      <li>
                        <b>Password</b> — quickest to try, but Snowflake increasingly blocks plain
                        password sign-ins for users with MFA. Best for short-lived testing only.
                      </li>
                      <li>
                        <b>Key pair (recommended for production)</b> — generate an RSA key pair and
                        attach the public key to the Snowflake user; paste the private PEM here.
                      </li>
                    </ul>
                  </div>

                  <div>
                    <div className="text-[var(--foreground)] font-medium mb-1">Key-pair quick recipe</div>
                    <pre className="bg-[var(--background)] border border-[var(--border)] rounded p-2 overflow-x-auto text-[10px] font-mono leading-relaxed">{`# Generate an unencrypted PKCS#8 RSA key (or add -aes256 for a passphrase)
openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -inform PEM -out rsa_key.p8
openssl rsa -in rsa_key.p8 -pubout -out rsa_key.pub

# In a Snowflake worksheet (public key body only, no BEGIN/END lines):
ALTER USER <YOUR_USER>
  SET RSA_PUBLIC_KEY='<contents of rsa_key.pub between the BEGIN/END lines>';`}</pre>
                    <p>Then paste the full <code>rsa_key.p8</code> (including BEGIN/END lines) into the Private Key PEM field below.</p>
                  </div>

                  <div className="pt-1 border-t border-[var(--border)]">
                    <div className="text-[var(--foreground)] font-medium mb-1">Official Snowflake references</div>
                    <ul className="list-disc ml-4 space-y-0.5">
                      <li><a className="text-[#29B5E8] underline" href="https://docs.snowflake.com/en/user-guide/admin-account-identifier" target="_blank" rel="noreferrer">Account identifiers</a></li>
                      <li><a className="text-[#29B5E8] underline" href="https://docs.snowflake.com/en/user-guide/key-pair-auth" target="_blank" rel="noreferrer">Key-pair authentication</a></li>
                      <li><a className="text-[#29B5E8] underline" href="https://docs.snowflake.com/en/sql-reference/snowflake-db-roles" target="_blank" rel="noreferrer">SECURITY_VIEWER / GOVERNANCE_VIEWER roles</a></li>
                      <li><a className="text-[#29B5E8] underline" href="https://www.cisecurity.org/benchmark/snowflake" target="_blank" rel="noreferrer">CIS Snowflake Foundations Benchmark v1.0.0</a></li>
                    </ul>
                  </div>
                </div>
              )}
            </div>

            {error && (
              <div className="mb-4 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-[12px] text-red-400">
                {error}
              </div>
            )}

            <form onSubmit={handleConnect} className="space-y-3">
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Display name (optional)</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={e => setFormData(d => ({ ...d, name: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#29B5E8]"
                  placeholder="Snowflake Production"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Account identifier</label>
                <input
                  type="text"
                  value={formData.account}
                  onChange={e => setFormData(d => ({ ...d, account: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#29B5E8]"
                  placeholder="xy12345.us-east-1"
                  required
                />
                <p className="text-[10px] text-[var(--muted)] mt-1">Account locator + region, or <code>org-account</code> form. Find via Snowsight → username menu, or <code>SELECT CURRENT_ACCOUNT()</code>.</p>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">User</label>
                  <input
                    type="text"
                    value={formData.user}
                    onChange={e => setFormData(d => ({ ...d, user: e.target.value }))}
                    className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#29B5E8]"
                    placeholder="HELIOS_SSPM_USER"
                    required
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Role</label>
                  <input
                    type="text"
                    value={formData.role}
                    onChange={e => setFormData(d => ({ ...d, role: e.target.value }))}
                    className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#29B5E8]"
                    placeholder="ACCOUNTADMIN"
                  />
                </div>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Warehouse (optional)</label>
                <input
                  type="text"
                  value={formData.warehouse}
                  onChange={e => setFormData(d => ({ ...d, warehouse: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#29B5E8]"
                  placeholder="COMPUTE_WH"
                />
                <p className="text-[10px] text-[var(--muted)] mt-1">Only needed if the role has no default warehouse.</p>
              </div>

              <div className="flex gap-2 border-b border-[var(--border)]">
                <button
                  type="button"
                  onClick={() => setAuthMode('password')}
                  className={`px-3 py-1.5 text-[12px] border-b-2 ${authMode === 'password' ? 'border-[#29B5E8] text-[var(--foreground)]' : 'border-transparent text-[var(--muted)]'}`}
                >
                  Password
                </button>
                <button
                  type="button"
                  onClick={() => setAuthMode('keypair')}
                  className={`px-3 py-1.5 text-[12px] border-b-2 ${authMode === 'keypair' ? 'border-[#29B5E8] text-[var(--foreground)]' : 'border-transparent text-[var(--muted)]'}`}
                >
                  Key pair (recommended)
                </button>
              </div>

              {authMode === 'password' ? (
                <div>
                  <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Password</label>
                  <input
                    type="password"
                    value={formData.password}
                    onChange={e => setFormData(d => ({ ...d, password: e.target.value }))}
                    className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#29B5E8]"
                    placeholder="••••••••"
                  />
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Private key (PEM, full -----BEGIN/END----- block)</label>
                    <textarea
                      value={formData.private_key_pem}
                      rows={6}
                      onChange={e => setFormData(d => ({ ...d, private_key_pem: e.target.value }))}
                      className="w-full px-3 py-2 text-[11px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#29B5E8]"
                      placeholder="-----BEGIN PRIVATE KEY-----..."
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Passphrase (optional)</label>
                    <input
                      type="password"
                      value={formData.private_key_passphrase}
                      onChange={e => setFormData(d => ({ ...d, private_key_passphrase: e.target.value }))}
                      className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#29B5E8]"
                      placeholder="Only if the key was generated with -aes256"
                    />
                  </div>
                </>
              )}

              <div className="flex justify-end pt-2">
                <Button type="submit" disabled={connecting}>
                  {connecting ? <RefreshCw size={13} className="mr-1 animate-spin" /> : <Plug size={13} className="mr-1" />}
                  Connect &amp; scan
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  )
}

// ── Financial Platforms Section ────────────────────────────────────────────────

function FinancialPlatformsSection({ alwaysShow = false }: { alwaysShow?: boolean }) {
  const [sapConnections, setSapConnections] = useState<Array<{
    id: string
    name: string
    system_id: string
    status: string
    created_at: string | null
    last_scan_at: string | null
  }>>([]);
  // Track GitHub separately so the Code Security sub-panel can be
  // independently shown/hidden based on whether GitHub is connected.
  const [githubConnections, setGithubConnections] = useState<Array<unknown>>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [stats, setStats] = useState<{
    users: number
    transactions: number
    sensitive_tables: number
    findings: number
  } | null>(null)

  const [formData, setFormData] = useState({
    name: 'SAP S/4HANA',
    system_id: '',
    host: '',
    client: '100',
    username: '',
    password: '',
  })

  const loadConnections = useCallback(async () => {
    try {
      setLoading(true)
      const [connResp, statsResp, ghResp] = await Promise.all([
        api.get('/api/sap/connections').catch(() => ({ data: { connections: [] } })),
        api.get('/api/sap/stats').catch(() => ({ data: null })),
        api.get('/api/github/connections').catch(() => ({ data: { connections: [] } })),
      ])
      setSapConnections(connResp.data?.connections ?? [])
      setStats(statsResp.data)
      setGithubConnections(ghResp.data?.connections ?? [])
    } catch {
      // Not available yet
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadConnections() }, [loadConnections])

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.host || !formData.username || !formData.password) {
      setError('Host, username, and password are required')
      return
    }
    try {
      setConnecting(true)
      setError(null)
      await api.post('/api/sap/connect', formData)
      setShowModal(false)
      setFormData({ name: 'SAP S/4HANA', system_id: '', host: '', client: '100', username: '', password: '' })
      loadConnections()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to connect SAP system')
    } finally {
      setConnecting(false)
    }
  }

  const handleDisconnect = async (id: string) => {
    if (!confirm('Disconnect this SAP system?')) return
    try {
      await api.delete(`/api/sap/connections/${id}`)
      loadConnections()
    } catch {
      setError('Failed to disconnect')
    }
  }

  const handleScan = async (id: string) => {
    try {
      setScanning(id)
      await api.post(`/api/sap/scan/${id}`)
      loadConnections()
    } catch {
      setError('Scan failed')
    } finally {
      setScanning(null)
    }
  }

  // On Overview these blocks hide when nothing's connected so the page
  // is clean. On Connectors (alwaysShow=true) we always render both so
  // users have a place to add SAP / GitHub from scratch.
  const showFinancial = alwaysShow || loading || sapConnections.length > 0
  const showCodeSecurity = alwaysShow || loading || githubConnections.length > 0

  if (!showFinancial && !showCodeSecurity) {
    return null
  }

  return (
    <>
    {showFinancial && (
    <div className="mt-8 space-y-4">
      <div className="flex items-center gap-2">
        <Building2 size={16} className="text-[var(--muted)]" />
        <h3 className="text-[14px] font-semibold text-[var(--foreground)]">Financial Platforms</h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* SAP S/4HANA Connector Card */}
        <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5 hover:border-white/[0.12] transition-colors">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[#0FAAFF]/10">
                <SAPLogo size={24} />
              </div>
              <div>
                <span className="font-semibold text-[var(--foreground)]">SAP S/4HANA</span>
                <p className="text-[11px] text-[var(--muted)]">Users, roles, transactions + audit logs</p>
              </div>
            </div>
            {sapConnections.length === 0 ? (
              <Button size="sm" onClick={() => setShowModal(true)}>
                <Plug size={13} className="mr-1" /> Connect
              </Button>
            ) : (
              <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold border bg-emerald-500/10 border-emerald-500/20 text-emerald-400">
                {sapConnections.length} connected
              </span>
            )}
          </div>

          {/* SAP Stats */}
          {stats && (
            <div className="grid grid-cols-4 gap-2 mt-3 pt-3 border-t border-[var(--border)]">
              <div className="text-center">
                <div className="text-[14px] font-bold text-[var(--foreground)]">{stats.users}</div>
                <div className="text-[9px] text-[var(--muted)]">Users</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-[var(--foreground)]">{stats.transactions}</div>
                <div className="text-[9px] text-[var(--muted)]">T-Codes</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-amber-400">{stats.sensitive_tables}</div>
                <div className="text-[9px] text-[var(--muted)]">Sensitive</div>
              </div>
              <div className="text-center">
                <div className="text-[14px] font-bold text-red-400">{stats.findings}</div>
                <div className="text-[9px] text-[var(--muted)]">Findings</div>
              </div>
            </div>
          )}

          {/* Connected systems */}
          {sapConnections.length > 0 && (
            <div className="mt-3 space-y-2">
              {sapConnections.map(conn => (
                <div key={conn.id} className="bg-[var(--background)]/50 rounded-lg p-2 flex items-center justify-between">
                  <div>
                    <div className="text-[11px] font-medium text-[var(--foreground)]">{conn.name}</div>
                    <div className="text-[9px] text-[var(--muted)]">{conn.system_id || 'N/A'}</div>
                  </div>
                  <div className="flex gap-1">
                    <Button size="sm" variant="ghost" onClick={() => handleScan(conn.id)} disabled={scanning === conn.id}>
                      {scanning === conn.id ? <RefreshCw size={11} className="animate-spin" /> : <RefreshCw size={11} />}
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => handleDisconnect(conn.id)} className="text-red-400">
                      <Unplug size={11} />
                    </Button>
                  </div>
                </div>
              ))}
              <button onClick={() => setShowModal(true)} className="w-full py-1.5 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] border border-dashed border-[var(--border)] rounded-lg">
                + Add SAP system
              </button>
            </div>
          )}
        </div>



        {/* Coming Soon: More Financial Platforms */}
        <div className="bg-[#13131a] border border-[var(--border)] border-dashed rounded-xl p-5 opacity-60">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[var(--muted)]/10">
              <Building2 size={20} className="text-[var(--muted)]" />
            </div>
            <div>
              <span className="font-semibold text-[var(--foreground)]">More ERP Systems</span>
              <p className="text-[11px] text-[var(--muted)]">Oracle ERP, NetSuite, Workday + access reviews</p>
            </div>
          </div>
          <div className="text-center py-4">
            <span className="px-3 py-1 rounded-full text-[10px] font-semibold border bg-[var(--muted)]/10 border-[var(--border)] text-[var(--muted)]">
              Coming Soon
            </span>
          </div>
        </div>
      </div>
    </div>
    )}

      {/* Code Security section — GitHub (separate from Cloud Infrastructure and
          Financial Platforms since it scans code repos, not cloud infra or
          ERPs). Detects 2FA enforcement, branch protection, secret scanning,
          Dependabot vulnerability alerts (CVEs in dependencies), code
          scanning open alerts (SAST), webhook HTTPS, outside collaborators,
          and admin sprawl. Only rendered when at least one GitHub org is
          connected. */}
      {showCodeSecurity && (
      <div className="mt-8 space-y-4">
        <div className="flex items-center gap-2">
          <Code size={16} className="text-[var(--muted)]" />
          <h3 className="text-[14px] font-semibold text-[var(--foreground)]">
            Code Security
          </h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <CSPMConnectors clouds={['github']} />
        </div>
      </div>
      )}

      {/* SAP Connect Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowModal(false)}>
          <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <SAPLogo size={20} />
                <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Connect SAP S/4HANA</h3>
              </div>
              <button onClick={() => setShowModal(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]">
                <X size={18} />
              </button>
            </div>

            {error && (
              <div className="mb-4 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 text-[12px] text-red-400">
                {error}
              </div>
            )}

            <form onSubmit={handleConnect} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">System Name</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={e => setFormData(d => ({ ...d, name: e.target.value }))}
                    className="w-full px-3 py-2 text-[13px] bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                    placeholder="Production"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">System ID (SID)</label>
                  <input
                    type="text"
                    value={formData.system_id}
                    onChange={e => setFormData(d => ({ ...d, system_id: e.target.value.toUpperCase() }))}
                    className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                    placeholder="PRD"
                    maxLength={3}
                  />
                </div>
              </div>
              <div>
                <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Application Server Host</label>
                <input
                  type="text"
                  value={formData.host}
                  onChange={e => setFormData(d => ({ ...d, host: e.target.value }))}
                  className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                  placeholder="sap-prd.company.com"
                  required
                />
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Client</label>
                  <input
                    type="text"
                    value={formData.client}
                    onChange={e => setFormData(d => ({ ...d, client: e.target.value }))}
                    className="w-full px-3 py-2 text-[13px] font-mono bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                    placeholder="100"
                    maxLength={3}
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Username</label>
                  <input
                    type="text"
                    value={formData.username}
                    onChange={e => setFormData(d => ({ ...d, username: e.target.value }))}
                    className="w-full px-3 py-2 text-[13px] bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                    placeholder="HELIOS_SVC"
                    required
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-[var(--muted)] mb-1">Password</label>
                  <input
                    type="password"
                    value={formData.password}
                    onChange={e => setFormData(d => ({ ...d, password: e.target.value }))}
                    className="w-full px-3 py-2 text-[13px] bg-[var(--background)] border border-[var(--border)] rounded-lg focus:outline-none focus:border-[#3b6ef6]"
                    placeholder="••••••••"
                    required
                  />
                </div>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3 text-[11px] text-blue-400">
                <strong>Required SAP Roles:</strong> SAP_BC_JSF_COMMUNICATION, SAP_NWBC_DISPLAY, or custom read-only role for security audit tables (USR*, AGR*, TOBJ*, PRGN*)
              </div>
              <div className="flex justify-end pt-2">
                <Button type="submit" disabled={connecting}>
                  {connecting ? <RefreshCw size={13} className="mr-1 animate-spin" /> : <Plug size={13} className="mr-1" />}
                  Connect
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  )
}



interface AIRemediation {
  summary: string
  impact: string
  steps: string[]
  generated_at: string
  ai_powered: boolean
}

// Render simple inline markdown for **bold** / `code` / URLs as rich text.
// Keeps it lightweight — no full markdown lib, just the patterns the
// remediation prompts actually return.
function RemediationProse({ text }: { text: string }) {
  // Split paragraphs on blank lines
  const paragraphs = text.split(/\n\n+/).filter(p => p.trim())
  return (
    <div className="space-y-2">
      {paragraphs.map((p, i) => (
        <p key={i} className="text-[12px] text-[#c4c4cc] leading-relaxed">
          {renderInline(p)}
        </p>
      ))}
    </div>
  )
}

function renderInline(text: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  // Split on URLs, **bold**, `code`
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`|https?:\/\/[^\s)]+)/g
  let lastIndex = 0
  let key = 0
  let m: RegExpExecArray | null
  while ((m = pattern.exec(text)) !== null) {
    if (m.index > lastIndex) out.push(text.slice(lastIndex, m.index))
    const tok = m[0]
    if (tok.startsWith('**')) {
      out.push(<strong key={key++} className="text-[var(--foreground)] font-semibold">{tok.slice(2, -2)}</strong>)
    } else if (tok.startsWith('`')) {
      out.push(<code key={key++} className="bg-[#1e1e24] px-1 py-0.5 rounded text-[11px] font-mono text-[#93b4fd]">{tok.slice(1, -1)}</code>)
    } else {
      out.push(
        <a key={key++} href={tok} target="_blank" rel="noreferrer" className="text-[#93b4fd] underline hover:text-[#b9cdff]">
          {tok}
        </a>,
      )
    }
    lastIndex = m.index + tok.length
  }
  if (lastIndex < text.length) out.push(text.slice(lastIndex))
  return out
}

function RemediationStepItem({ index, text }: { index: number; text: string }) {
  // Pull off a leading bold-like "Title:" prefix so we can render it as a
  // heading and the rest as body. Many Claude outputs look like:
  //   "Open the AWS S3 console: navigate to Buckets → …"
  const titleMatch = text.match(/^([A-Z][^:.]{3,80}):\s+([\s\S]+)$/)
  const title = titleMatch ? titleMatch[1].trim() : null
  const body = titleMatch ? titleMatch[2].trim() : text
  return (
    <li className="flex gap-3 bg-[#0e0e14] border border-[#1e1e24] rounded-lg p-3 hover:border-[#3b6ef6]/30 transition-colors">
      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-[11px] font-bold text-emerald-400">
        {index}
      </span>
      <div className="flex-1 min-w-0">
        {title && (
          <div className="text-[12px] font-semibold text-[var(--foreground)] mb-1">{title}</div>
        )}
        <div className="text-[12px] text-[#c4c4cc] leading-relaxed">
          {renderInline(body)}
        </div>
      </div>
    </li>
  )
}

function AIRemediationPanel({
  alertId,
  fallbackSteps,
}: {
  alertId: string
  fallbackSteps?: string[]
}) {
  const [data, setData] = useState<AIRemediation | null>(null)
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [open, setOpen] = useState(true)
  // Track the current alertId in a ref so an in-flight request from a
  // previously-selected alert doesn't overwrite state when the user
  // switches alerts mid-flight. Adnan 2026-06-17: this was causing
  // stale errors / a flash of the wrong alert's data when clicking
  // through alerts quickly.
  const currentAlertIdRef = useRef<string>(alertId)
  const abortRef = useRef<AbortController | null>(null)

  const fetchRemediation = useCallback(async (refresh: boolean = false) => {
    // Cancel any in-flight request from a previous alert.
    if (abortRef.current) {
      try { abortRef.current.abort() } catch { /* noop */ }
    }
    const controller = new AbortController()
    abortRef.current = controller
    const requestedFor = alertId
    currentAlertIdRef.current = alertId

    if (refresh) {
      setRefreshing(true)
    } else {
      setLoading(true)
    }
    setError(null)
    try {
      const url = `/api/saas/alerts/${alertId}/remediation${refresh ? '?refresh=true' : ''}`
      const r = await api.get(url, { signal: controller.signal, timeout: 45000 })
      // Guard: if alert has changed since we started, drop the result.
      if (currentAlertIdRef.current !== requestedFor) return
      setData(r.data as AIRemediation)
    } catch (e: unknown) {
      // Ignore aborts — user moved on.
      const err = e as { name?: string; code?: string; message?: string }
      if (err?.name === 'CanceledError' || err?.name === 'AbortError' || err?.code === 'ERR_CANCELED') return
      if (currentAlertIdRef.current !== requestedFor) return
      const msg = e instanceof Error ? e.message : 'Failed to load remediation'
      setError(msg)
    } finally {
      if (currentAlertIdRef.current === requestedFor) {
        setLoading(false)
        setRefreshing(false)
      }
    }
  }, [alertId])

  // When alertId changes (user clicked a different alert), reset state
  // immediately so we don't show stale data while the new request is
  // still in flight, then kick off a new fetch.
  useEffect(() => {
    setData(null)
    setError(null)
    fetchRemediation(false)
    return () => {
      // On unmount or when alertId changes, abort the in-flight call.
      if (abortRef.current) {
        try { abortRef.current.abort() } catch { /* noop */ }
      }
    }
  }, [fetchRemediation])

  const generatedAt = data?.generated_at ? new Date(data.generated_at) : null
  const ts = generatedAt ? generatedAt.toLocaleString() : ''

  return (
    <div className="bg-[#111114] border border-[#1e1e24] rounded-xl overflow-hidden">
      <div className="w-full flex items-center justify-between px-4 py-3">
        <button
          onClick={() => setOpen(!open)}
          className="flex items-center gap-2 hover:opacity-80 transition-opacity"
        >
          <ShieldCheck size={13} className="text-emerald-400" />
          <span className="text-[12px] font-semibold text-emerald-400">Remediation Actions</span>
          {data?.ai_powered && (
            <span className="text-[10px] bg-[#3b6ef6]/10 text-[#3b6ef6] border border-[#3b6ef6]/30 px-1.5 py-0.5 rounded inline-flex items-center gap-1">
              <Sparkles size={9} /> AI-generated
            </span>
          )}
          {data && !data.ai_powered && (
            <span className="text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20 px-1.5 py-0.5 rounded">
              Fallback
            </span>
          )}
          {data && data.steps.length > 0 && (
            <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-1.5 py-0.5 rounded">
              {data.steps.length} steps
            </span>
          )}
        </button>
        <div className="flex items-center gap-2">
          {ts && (
            <span className="text-[10px] text-[#52525b]" title={generatedAt?.toISOString()}>
              {ts}
            </span>
          )}
          <button
            onClick={() => fetchRemediation(true)}
            disabled={loading || refreshing}
            className="text-[#71717a] hover:text-[#e4e4e7] disabled:opacity-50"
            title="Re-run Himaya Data Posture agent"
          >
            <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} />
          </button>
          <button onClick={() => setOpen(!open)} className="text-[#71717a] hover:text-[#e4e4e7]">
            {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {open && (
        <div className="px-4 pb-4 space-y-3">
          {loading && !data && (
            <div className="space-y-2 animate-pulse">
              <div className="h-3 bg-[#1e1e24] rounded w-3/4" />
              <div className="h-3 bg-[#1e1e24] rounded w-full" />
              <div className="h-3 bg-[#1e1e24] rounded w-5/6" />
              <div className="h-3 bg-[#1e1e24] rounded w-2/3" />
              <div className="flex items-center gap-2 text-[11px] text-[#52525b] pt-2">
                <Loader2 size={11} className="animate-spin" />
                Generating context-specific remediation…
              </div>
            </div>
          )}

          {error && !loading && (
            <div className="text-[11px] text-amber-400">
              Could not load AI remediation: {error}.
              {fallbackSteps && fallbackSteps.length > 0 && (
                <span className="text-[#71717a]"> Showing heuristic steps below.</span>
              )}
            </div>
          )}

          {data && (
            <>
              {data.summary && (
                <div className="bg-[#0e0e14] border border-[#1e1e24] rounded-lg p-3">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-[#71717a] mb-1.5">
                    <AlertTriangle size={10} /> What’s wrong
                  </div>
                  <RemediationProse text={data.summary} />
                </div>
              )}
              {data.impact && (
                <div className="bg-[#0e0e14] border border-[#1e1e24] rounded-lg p-3">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-[#71717a] mb-1.5">
                    <Target size={10} /> Why it matters
                  </div>
                  <RemediationProse text={data.impact} />
                </div>
              )}
              {data.steps.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-[#71717a] mb-2">
                    <CheckCircle2 size={10} /> Recommended steps
                  </div>
                  <ol className="space-y-2">
                    {data.steps.map((step, i) => (
                      <RemediationStepItem key={i} index={i + 1} text={step} />
                    ))}
                  </ol>
                </div>
              )}
            </>
          )}

          {!data && !loading && error && fallbackSteps && fallbackSteps.length > 0 && (
            <ol className="space-y-2">
              {fallbackSteps.map((step, i) => (
                <RemediationStepItem key={i} index={i + 1} text={step} />
              ))}
            </ol>
          )}
        </div>
      )}
    </div>
  )
}

// ── AIResourceRiskPanel (Claude-generated per data item) ──────────────────

interface AIResourceRisk {
  assessment: string
  risks: string[]
  actions: string[]
  generated_at: string
  ai_powered: boolean
}

function AIResourceRiskPanel({ itemId }: { itemId: string }) {
  const [data, setData] = useState<AIResourceRisk | null>(null)
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Same race-condition guard as AIRemediationPanel — prevents a stale
  // in-flight request from a previously-clicked item overwriting state.
  const currentItemIdRef = useRef<string>(itemId)
  const abortRef = useRef<AbortController | null>(null)

  const fetchAnalysis = useCallback(async (refresh: boolean = false) => {
    if (abortRef.current) {
      try { abortRef.current.abort() } catch { /* noop */ }
    }
    const controller = new AbortController()
    abortRef.current = controller
    const requestedFor = itemId
    currentItemIdRef.current = itemId

    if (refresh) {
      setRefreshing(true)
    } else {
      setLoading(true)
    }
    setError(null)
    try {
      const url = `/api/saas/data/${itemId}/risk-analysis${refresh ? '?refresh=true' : ''}`
      const r = await api.get(url, { signal: controller.signal, timeout: 45000 })
      if (currentItemIdRef.current !== requestedFor) return
      setData(r.data as AIResourceRisk)
    } catch (e: unknown) {
      const err = e as { name?: string; code?: string }
      if (err?.name === 'CanceledError' || err?.name === 'AbortError' || err?.code === 'ERR_CANCELED') return
      if (currentItemIdRef.current !== requestedFor) return
      const msg = e instanceof Error ? e.message : 'Failed to load risk analysis'
      setError(msg)
    } finally {
      if (currentItemIdRef.current === requestedFor) {
        setLoading(false)
        setRefreshing(false)
      }
    }
  }, [itemId])

  useEffect(() => {
    setData(null)
    setError(null)
    fetchAnalysis(false)
    return () => {
      if (abortRef.current) {
        try { abortRef.current.abort() } catch { /* noop */ }
      }
    }
  }, [fetchAnalysis])

  const generatedAt = data?.generated_at ? new Date(data.generated_at) : null
  const ts = generatedAt ? generatedAt.toLocaleString() : ''

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="text-[11px] font-semibold text-[#3b6ef6] uppercase tracking-wide">Risk Analysis</div>
          {data?.ai_powered && (
            <span className="text-[9px] bg-[#3b6ef6]/10 text-[#3b6ef6] border border-[#3b6ef6]/30 px-1.5 py-0.5 rounded inline-flex items-center gap-1">
              <Sparkles size={8} /> AI-generated
            </span>
          )}
          {data && !data.ai_powered && (
            <span className="text-[9px] bg-amber-500/10 text-amber-400 border border-amber-500/20 px-1.5 py-0.5 rounded">
              Fallback
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {ts && (
            <span className="text-[10px] text-[#52525b]" title={generatedAt?.toISOString()}>
              {ts}
            </span>
          )}
          <button
            onClick={(e) => { e.stopPropagation(); fetchAnalysis(true) }}
            disabled={loading || refreshing}
            className="text-[#71717a] hover:text-[#e4e4e7] disabled:opacity-50"
            title="Re-run Himaya Data Posture agent"
          >
            <RefreshCw size={11} className={refreshing ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {loading && !data && (
        <div className="space-y-2 animate-pulse">
          <div className="h-3 bg-[#1e1e24] rounded w-full" />
          <div className="h-3 bg-[#1e1e24] rounded w-5/6" />
          <div className="h-3 bg-[#1e1e24] rounded w-4/5" />
          <div className="h-3 bg-[#1e1e24] rounded w-3/4" />
          <div className="flex items-center gap-2 text-[11px] text-[#52525b] pt-1">
            <Loader2 size={11} className="animate-spin" />
            Himaya Data Posture agent is analysing this resource…
          </div>
        </div>
      )}

      {error && !loading && (
        <p className="text-[11px] text-amber-400">Could not load AI risk analysis: {error}.</p>
      )}

      {data && (
        <div className="space-y-3">
          {data.assessment && (
            <p className="text-[12px] text-[#a1a1aa] leading-relaxed whitespace-pre-line">{data.assessment}</p>
          )}
          {data.risks.length > 0 && (
            <div>
              <div className="text-[10px] text-[#52525b] mb-1 uppercase tracking-wide">Specific risks</div>
              <ol className="space-y-1">
                {data.risks.map((risk, i) => (
                  <li key={i} className="flex gap-2 text-[12px]">
                    <span className="flex-shrink-0 w-4 h-4 rounded-full bg-amber-500/20 border border-amber-500/30 flex items-center justify-center text-[9px] font-bold text-amber-400">
                      {i + 1}
                    </span>
                    <span className="text-[#a1a1aa] leading-relaxed">{risk}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {data.actions.length > 0 && (
            <div>
              <div className="text-[10px] text-[#52525b] mb-1 uppercase tracking-wide">Recommended actions</div>
              <ol className="space-y-1">
                {data.actions.map((action, i) => (
                  <li key={i} className="flex gap-2 text-[12px]">
                    <span className="flex-shrink-0 w-4 h-4 rounded-full bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center text-[9px] font-bold text-emerald-400">
                      {i + 1}
                    </span>
                    <span className="text-[#a1a1aa] leading-relaxed">{action}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── AlertDetailPanel (slide-in) ────────────────────────────────────────────────

function AlertDetailPanel({
  alert, onClose, onUpdateStatus, updating,
}: {
  alert: SaasAlert | null
  onClose: () => void
  onUpdateStatus: (id: string, status: string) => void
  updating: boolean
}) {
  if (!alert) return null

  const cls = alert.classification_result as Record<string, unknown> | null | undefined
  type ClsRecord = { risk_level?: string; confidence?: number; categories?: string[]; explanation?: string; [key: string]: unknown }
  const clsT = cls as ClsRecord | null | undefined
  type PosRecord = { posture_risk?: string; findings?: string[]; remediation?: string; [key: string]: unknown }
  const pos = alert.posture_result as PosRecord | null | undefined

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 z-40"
        onClick={onClose}
      />
      {/* Panel */}
      <div className="fixed right-0 top-0 h-full w-full max-w-lg bg-[#0f0f12] border-l border-[#1e1e24] z-50 overflow-y-auto flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e1e24] flex-shrink-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SevBadge level={alert.severity} />
            <AlertTypeBadge type={alert.alert_type} />
            <StatusBadge status={alert.status} />
          </div>
          <button onClick={onClose} className="text-[#71717a] hover:text-[#e4e4e7]">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 space-y-4 p-5">
          <div>
            <h2 className="text-[15px] font-semibold text-[#e4e4e7]">{alert.title}</h2>
            <p className="text-[12px] text-[#71717a] mt-1">{alert.description}</p>
          </div>

          {/* Resource */}
          {alert.resource_name && (
            <div className="bg-[#111114] border border-[#1e1e24] rounded-xl p-4 space-y-1">
              <div className="text-[11px] text-[#52525b] uppercase tracking-wide">Resource</div>
              <div className="flex items-center gap-2">
                <span className="text-[13px] text-[#e4e4e7]">{alert.resource_name}</span>
                {alert.resource_url && (
                  <a href={alert.resource_url} target="_blank" rel="noreferrer" className="text-[#3b6ef6] hover:underline">
                    <ExternalLink size={12} />
                  </a>
                )}
              </div>
              <div className="text-[11px] text-[#52525b]">Provider: <ProviderBadge provider={alert.provider} /></div>
            </div>
          )}

          {/* Classification */}
          <div className="bg-[#111114] border border-[#1e1e24] rounded-xl p-4 space-y-2">
            <div className="text-[12px] font-semibold text-[#3b6ef6] flex items-center gap-1">
              <Database size={13} /> Data Classification
            </div>
            {clsT ? (
              <div className="space-y-1 text-[12px]">
                <div className="flex justify-between">
                  <span className="text-[#71717a]">Risk level</span>
                  <SevBadge level={clsT.risk_level ?? 'low'} />
                </div>
                <div className="flex justify-between">
                  <span className="text-[#71717a]">Confidence</span>
                  <span className="text-[#e4e4e7]">{clsT.confidence != null ? `${(Number(clsT.confidence) * 100).toFixed(0)}%` : '—'}</span>
                </div>
                {Array.isArray(clsT.categories) && clsT.categories.length > 0 && (
                  <div>
                    <div className="text-[#71717a] mb-1">Categories</div>
                    <div className="flex flex-wrap gap-1">
                      {clsT.categories.map((c: string) => (
                        <span key={c} className="bg-[#1e1e24] text-[#a1a1aa] px-2 py-0.5 rounded text-[10px]">{c}</span>
                      ))}
                    </div>
                  </div>
                )}
                {clsT.explanation && (
                  <p className="text-[11px] text-[#71717a] pt-1 border-t border-[#1e1e24] mt-2">{clsT.explanation}</p>
                )}
              </div>
            ) : (
              <div className="text-[12px] text-[#52525b]">No classification data available.</div>
            )}
          </div>

          {/* Posture */}
          {pos && (
            <div className="bg-[#111114] border border-[#1e1e24] rounded-xl p-4 space-y-2">
              <div className="text-[12px] font-semibold text-[#3b6ef6] flex items-center gap-1">
                <ShieldCheck size={13} /> Posture Analysis
              </div>
              <div className="space-y-1 text-[12px]">
                <div className="flex justify-between">
                  <span className="text-[#71717a]">Posture risk</span>
                  <SevBadge level={pos.posture_risk ?? 'low'} />
                </div>
                {Array.isArray(pos.findings) && pos.findings.length > 0 && (
                  <div>
                    <div className="text-[#71717a] mb-1">Findings</div>
                    <ul className="space-y-0.5">
                      {pos.findings.map((f: string, i: number) => (
                        <li key={i} className="text-[11px] text-[#a1a1aa] flex gap-1">
                          <span className="text-[#3b6ef6] mt-0.5">›</span> {f}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {pos.remediation && (
                  <p className="text-[11px] text-[#71717a] pt-1">{pos.remediation}</p>
                )}
              </div>
            </div>
          )}

          {/* Remediation Actions (Claude-generated) */}
          <AIRemediationPanel alertId={alert.id} fallbackSteps={alert.remediation_steps} />

          {/* Actions */}
          <div className="flex flex-wrap gap-2 pt-2 border-t border-[#1e1e24]">
            {alert.status === 'open' && (
              <Button size="sm" variant="ghost" onClick={() => onUpdateStatus(alert.id, 'acknowledged')} disabled={updating}>
                Acknowledge
              </Button>
            )}
            {alert.status !== 'resolved' && (
              <Button size="sm" onClick={() => onUpdateStatus(alert.id, 'resolved')} disabled={updating}>
                <CheckCircle2 size={13} className="mr-1" /> Resolve
              </Button>
            )}
            {alert.status !== 'suppressed' && (
              <Button size="sm" variant="ghost" onClick={() => onUpdateStatus(alert.id, 'suppressed')} disabled={updating}>
                Suppress
              </Button>
            )}
          </div>
        </div>
      </div>
    </>
  )
}

// ── AlertsTab ─────────────────────────────────────────────────────────────────

function AlertsTab({
  alerts, total, loading, onRunScan, scanning, onSelectAlert, selectedAlert,
  onCloseAlert, onUpdateAlertStatus, updatingAlert,
  filterSev, setFilterSev, filterStatus, setFilterStatus, filterProvider, setFilterProvider,
  page, setPage,
}: {
  alerts: SaasAlert[]
  total: number
  loading: boolean
  scanning: boolean
  onRunScan: () => void
  onSelectAlert: (a: SaasAlert) => void
  selectedAlert: SaasAlert | null
  onCloseAlert: () => void
  onUpdateAlertStatus: (id: string, status: string) => void
  updatingAlert: boolean
  filterSev: string
  setFilterSev: (v: string) => void
  filterStatus: string
  setFilterStatus: (v: string) => void
  filterProvider: string
  setFilterProvider: (v: string) => void
  page: number
  setPage: (n: number) => void
}) {
  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap gap-3 items-center">
        <select
          value={filterSev}
          onChange={e => { setFilterSev(e.target.value); setPage(1) }}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filterStatus}
          onChange={e => { setFilterStatus(e.target.value); setPage(1) }}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
        >
          <option value="">All Statuses</option>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="suppressed">Suppressed</option>
        </select>
        <select
          value={filterProvider}
          onChange={e => { setFilterProvider(e.target.value); setPage(1) }}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
        >
          <option value="">All Providers</option>
          <option value="teams">Teams</option>
          <option value="sharepoint">SharePoint</option>
          <option value="onedrive">OneDrive</option>
          <option value="aws">AWS</option>
          <option value="gcp">GCP</option>
          <option value="azure">Azure</option>
          <option value="oracle">Oracle Cloud</option>
          <option value="databricks">Databricks</option>
          <option value="github">GitHub</option>
          <option value="sap">SAP</option>
          <option value="salesforce">Salesforce</option>
          <option value="snowflake">Snowflake</option>
        </select>
        <div className="ml-auto">
          <Button size="sm" onClick={onRunScan} disabled={scanning}>
            {scanning ? <RefreshCw size={13} className="mr-1 animate-spin" /> : <ShieldAlert size={13} className="mr-1" />}
            Run Scan
          </Button>
        </div>
      </div>

      {/* Threat Intelligence Summary */}
      {!loading && alerts.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          {/* Phishing Detection */}
          <div className="bg-gradient-to-br from-red-950/40 to-red-900/20 border border-red-800/30 rounded-xl p-3">
            <div className="flex items-center gap-2 mb-1">
              <AlertOctagon size={14} className="text-red-400" />
              <span className="text-[11px] text-red-300 font-medium">Phishing URLs</span>
            </div>
            <div className="text-xl font-bold text-red-200">
              {alerts.filter(a => a.alert_type?.toLowerCase().includes('phishing')).length}
            </div>
          </div>
          {/* External Sharing */}
          <div className="bg-gradient-to-br from-orange-950/40 to-orange-900/20 border border-orange-800/30 rounded-xl p-3">
            <div className="flex items-center gap-2 mb-1">
              <Globe size={14} className="text-orange-400" />
              <span className="text-[11px] text-orange-300 font-medium">External Shares</span>
            </div>
            <div className="text-xl font-bold text-orange-200">
              {alerts.filter(a => a.alert_type?.toLowerCase().includes('external') || a.alert_type?.toLowerCase().includes('sharing')).length}
            </div>
          </div>
          {/* Sensitive Data */}
          <div className="bg-gradient-to-br from-purple-950/40 to-purple-900/20 border border-purple-800/30 rounded-xl p-3">
            <div className="flex items-center gap-2 mb-1">
              <FileWarning size={14} className="text-purple-400" />
              <span className="text-[11px] text-purple-300 font-medium">Sensitive Data</span>
            </div>
            <div className="text-xl font-bold text-purple-200">
              {alerts.filter(a => ['pii', 'pci', 'phi', 'sensitive', 'secret', 'credential'].some(t => a.alert_type?.toLowerCase().includes(t) || a.title?.toLowerCase().includes(t))).length}
            </div>
          </div>
          {/* Suspicious Activity */}
          <div className="bg-gradient-to-br from-amber-950/40 to-amber-900/20 border border-amber-800/30 rounded-xl p-3">
            <div className="flex items-center gap-2 mb-1">
              <Activity size={14} className="text-amber-400" />
              <span className="text-[11px] text-amber-300 font-medium">Suspicious Activity</span>
            </div>
            <div className="text-xl font-bold text-amber-200">
              {alerts.filter(a => ['suspicious', 'impossible_travel', 'after_hours', 'anomaly'].some(t => a.alert_type?.toLowerCase().includes(t))).length}
            </div>
          </div>
          {/* Malware/Ransomware */}
          <div className="bg-gradient-to-br from-rose-950/40 to-rose-900/20 border border-rose-800/30 rounded-xl p-3">
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert size={14} className="text-rose-400" />
              <span className="text-[11px] text-rose-300 font-medium">Malware Threats</span>
            </div>
            <div className="text-xl font-bold text-rose-200">
              {alerts.filter(a => ['malware', 'ransomware', 'executable', 'macro', 'virus'].some(t => a.alert_type?.toLowerCase().includes(t) || a.title?.toLowerCase().includes(t))).length}
            </div>
          </div>
          {/* IAM/Access Issues */}
          <div className="bg-gradient-to-br from-blue-950/40 to-blue-900/20 border border-blue-800/30 rounded-xl p-3">
            <div className="flex items-center gap-2 mb-1">
              <Key size={14} className="text-blue-400" />
              <span className="text-[11px] text-blue-300 font-medium">Access Issues</span>
            </div>
            <div className="text-xl font-bold text-blue-200">
              {alerts.filter(a => ['iam', 'access', 'permission', 'privilege', 'password'].some(t => a.alert_type?.toLowerCase().includes(t) || a.title?.toLowerCase().includes(t))).length}
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <div className="text-center py-16 text-[#52525b]">Loading alerts…</div>
      ) : alerts.length === 0 ? (
        <div className="text-center py-16 space-y-2">
          <Cloud size={32} className="mx-auto text-[#3b6ef6]/40" />
          <div className="text-[#52525b] text-sm">
            {filterSev || filterStatus || filterProvider
              ? 'No alerts match the current filters.'
              : 'No alerts yet. Alerts fire when sensitive files are shared externally or Teams messages contain high-risk content. Keep scanning — alerts appear automatically.'}
          </div>
        </div>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border border-[#1e1e24]">
            <Table>
              <Thead>
                <Tr>
                  <Th>Severity</Th>
                  <Th>Type</Th>
                  <Th>Title / Description</Th>
                  <Th>Provider</Th>
                  <Th>Resource</Th>
                  <Th>Date</Th>
                  <Th>Status</Th>
                </Tr>
              </Thead>
              <Tbody>
                {alerts.map(a => {
                  const cls = a.classification_result as Record<string, unknown> | null | undefined
                  const explanation = cls?.explanation as string | undefined
                  return (
                    <Tr
                      key={a.id}
                      className="cursor-pointer hover:bg-[#1a1a1f]"
                      onClick={() => onSelectAlert(a)}
                    >
                      <Td><SevBadge level={a.severity} /></Td>
                      <Td><AlertTypeBadge type={a.alert_type} /></Td>
                      <Td className="max-w-xs">
                        <div className="text-[13px] text-[#e4e4e7] truncate">{a.title}</div>
                        {explanation && (
                          <div className="text-[11px] text-[#71717a] truncate mt-0.5">{explanation}</div>
                        )}
                      </Td>
                      <Td><ProviderBadge provider={a.provider} /></Td>
                      <Td className="text-[12px] text-[#71717a] max-w-[120px] truncate">{a.resource_name ?? '—'}</Td>
                      <Td className="text-[12px] text-[#52525b]">{fmtDate(a.created_at)}</Td>
                      <Td><StatusBadge status={a.status} /></Td>
                    </Tr>
                  )
                })}
              </Tbody>
            </Table>
          </div>
          {/* Pagination */}
          <div className="flex items-center justify-between text-[12px] text-[#71717a]">
            <span>{total} total</span>
            <div className="flex gap-2">
              <Button size="sm" variant="ghost" onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1}>Prev</Button>
              <span className="px-2 py-1">Page {page}</span>
              <Button size="sm" variant="ghost" onClick={() => setPage(page + 1)} disabled={alerts.length < 20}>Next</Button>
            </div>
          </div>
        </>
      )}

      {/* Slide-in detail panel */}
      <AlertDetailPanel
        alert={selectedAlert}
        onClose={onCloseAlert}
        onUpdateStatus={onUpdateAlertStatus}
        updating={updatingAlert}
      />
    </div>
  )
}

// ── DataLifecycleTab ───────────────────────────────────────────────────────────

function DataTab({
  items, summary, total, loading,
  filterProvider, setFilterProvider,
  filterLabel, setFilterLabel,
  filterScope, setFilterScope,
  page, setPage,
}: {
  items: DataItem[]
  summary: DataSummary | null
  total: number
  loading: boolean
  filterProvider: string
  setFilterProvider: (v: string) => void
  filterLabel: string
  setFilterLabel: (v: string) => void
  filterScope: string
  setFilterScope: (v: string) => void
  page: number
  setPage: (n: number) => void
}) {
  const [expandedRow, setExpandedRow] = useState<string | null>(null)
  // DSPM sub-tab selector — Overview / Inventory / Discovery / Insights.
  const [dspmSubTab, setDspmSubTab] = useState<'overview' | 'inventory' | 'discovery' | 'insights'>('overview')
  // Local client-side type filter — Adnan asked for resource-type
  // filtering. Server returns mixed providers; we filter in-memory.
  const [filterItemType, setFilterItemType] = useState<string>('')

  // Adnan: IAM users belong in the User Risk section, not DSPM. Filter
  // them out of the table view here.
  const visibleItems = items.filter(it => {
    const t = (it.item_type || '').toLowerCase()
    if (t === 'iam_user' || t === 'iam_role' || t === 'user' || t === 'role') return false
    if (filterItemType && t !== filterItemType.toLowerCase()) return false
    return true
  })

  const uniqueItemTypes = Array.from(new Set(
    items
      .map(i => (i.item_type || '').toLowerCase())
      .filter(t => t && t !== 'iam_user' && t !== 'iam_role' && t !== 'user' && t !== 'role')
  )).sort()

  const confidentialCount = (summary?.by_label?.confidential ?? 0) + (summary?.by_label?.highly_confidential ?? 0)
  const externalCount = (summary?.by_scope?.external ?? 0) + (summary?.by_scope?.public ?? 0)
  const total2 = summary?.total ?? 0

  return (
    <div className="space-y-4">
      {/* DSPM Sub-tab switcher. Adnan asked the bottom-of-inventory DSPM
          discovery panel to live inside DSPM Overview; we also added a
          new "Insights" sub-tab for connector-driven DSPM capabilities
          (data flow map, access surface, cross-connector exposure). */}
      <div className="flex items-center gap-1 border-b border-[var(--border)] -mx-6 px-6 overflow-x-auto">
        {([
          { id: 'overview' as const, label: 'Overview', icon: <ShieldCheck size={13} /> },
          { id: 'inventory' as const, label: 'Data Inventory', icon: <Database size={13} /> },
          { id: 'discovery' as const, label: 'Sensitive Data Discovery', icon: <FileWarning size={13} /> },
          { id: 'insights' as const, label: 'DSPM Insights', icon: <Sparkles size={13} /> },
        ]).map(t => (
          <button
            key={t.id}
            onClick={() => setDspmSubTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-[12px] border-b-2 transition-colors ${
              dspmSubTab === t.id
                ? 'border-[#3b6ef6] text-[var(--foreground)]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--foreground)]'
            }`}
          >
            {t.icon}
            {t.label}
          </button>
        ))}
      </div>

      {dspmSubTab === 'overview' && (
        <DSPMOverview summary={summary} items={items} />
      )}

      {dspmSubTab === 'discovery' && (
        <DataInventoryDSPM />
      )}

      {dspmSubTab === 'insights' && (
        <DSPMInsights summary={summary} items={items} />
      )}

      {dspmSubTab === 'inventory' && (
      <>
      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Items" value={total2} />
        <StatCard
          label="Confidential"
          value={total2 > 0 ? `${Math.round((confidentialCount / total2) * 100)}%` : '0%'}
          sub={`${confidentialCount} files`}
          color="text-amber-400"
        />
        <StatCard
          label="Externally Shared"
          value={total2 > 0 ? `${Math.round((externalCount / total2) * 100)}%` : '0%'}
          sub={`${externalCount} files`}
          color="text-red-400"
        />
        <StatCard
          label="Public"
          value={summary?.by_scope?.public ?? 0}
          sub="files"
          color="text-red-400"
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={filterProvider}
          onChange={e => { setFilterProvider(e.target.value); setPage(1) }}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
        >
          <option value="">All Providers</option>
          <option value="teams">Teams</option>
          <option value="sharepoint">SharePoint</option>
          <option value="onedrive">OneDrive</option>
          <option value="aws">AWS (S3, RDS, EBS, EFS)</option>
          <option value="gcp">GCP (GCS, BQ)</option>
          <option value="azure">Azure (Blob, SQL)</option>
          <option value="databricks">Databricks (Notebooks)</option>
          <option value="github">GitHub (Repos)</option>
          <option value="sap">SAP (Tables)</option>
          {/* Adnan 2026-06-23 (turn 3): new connector branches */}
          <option value="snowflake">Snowflake (Tables)</option>
          <option value="oracle">Oracle (DB, OCI)</option>
          <option value="salesforce">Salesforce (Objects)</option>
        </select>
        <select
          value={filterItemType}
          onChange={e => { setFilterItemType(e.target.value); setPage(1) }}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
        >
          <option value="">All Resource Types</option>
          {uniqueItemTypes.map(t => (
            <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
          ))}
        </select>
        <select
          value={filterLabel}
          onChange={e => { setFilterLabel(e.target.value); setPage(1) }}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
        >
          <option value="">All Labels</option>
          <option value="public">Public</option>
          <option value="internal">Internal</option>
          <option value="confidential">Confidential</option>
          <option value="highly_confidential">Highly Confidential</option>
        </select>
        <select
          value={filterScope}
          onChange={e => { setFilterScope(e.target.value); setPage(1) }}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
        >
          <option value="">All Scopes</option>
          <option value="public">Public</option>
          <option value="external">External</option>
          <option value="org">Organization</option>
          <option value="private">Private</option>
        </select>
      </div>

      {loading ? (
        <div className="text-center py-16 text-[#52525b]">Loading data items…</div>
      ) : visibleItems.length === 0 ? (
        <div className="text-center py-16 space-y-2">
          <Database size={32} className="mx-auto text-[#3b6ef6]/40" />
          <div className="text-[#52525b] text-sm">No data items yet. Connect a provider and run a scan.</div>
        </div>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border border-[#1e1e24]">
            <Table>
              <Thead>
                <Tr>
                  <Th>Name / Location</Th>
                  <Th>Source</Th>
                  <Th>Label</Th>
                  <Th>DLP Categories</Th>
                  <Th>Risk Score</Th>
                  <Th>Sharing</Th>
                  <Th>Owner</Th>
                  <Th>Last Modified</Th>
                  <Th>Size</Th>
                </Tr>
              </Thead>
              <Tbody>
                {visibleItems.map(item => {
                  const cls = item.classification_result as Record<string, unknown> | null | undefined
                  const categories = item.classification_categories?.length
                    ? item.classification_categories
                    : Array.isArray(cls?.categories) ? cls.categories as string[] : []
                  const matchedPatterns = Array.isArray(cls?.matched_patterns) ? cls.matched_patterns as string[] : []
                  const isExpanded = expandedRow === item.id
                  const fmtSize = (b?: number) => !b ? '—' : b > 1048576 ? `${(b/1048576).toFixed(1)} MB` : `${Math.round(b/1024)} KB`
                  return (
                    <>
                      <Tr
                        key={item.id}
                        className="cursor-pointer hover:bg-[#1a1a1f]"
                        onClick={() => setExpandedRow(isExpanded ? null : item.id)}
                      >
                        <Td className="text-[13px] text-[#e4e4e7] max-w-xs">
                          <div className="flex items-center gap-1.5">
                            {item.provider === 'aws' && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#FF9900]/10 border border-[#FF9900]/20 text-[#FF9900] font-medium flex-shrink-0">
                                {item.item_type?.toUpperCase() || 'AWS'}
                              </span>
                            )}
                            <span className="truncate font-medium">{item.item_name}</span>
                            {item.item_url && (
                              <a href={item.item_url} target="_blank" rel="noreferrer"
                                className="text-[#3b6ef6] flex-shrink-0" onClick={e => e.stopPropagation()}>
                                <ExternalLink size={11} />
                              </a>
                            )}
                            {item.encryption_enabled && (
                              <span title="Encrypted"><Lock size={11} className="text-emerald-400 flex-shrink-0" /></span>
                            )}
                          </div>
                          <div className="text-[11px] text-[#52525b] truncate mt-0.5">
                            {item.provider === 'aws' && item.region ? (
                              <span className="inline-flex items-center gap-1">
                                <Globe size={10} className="text-[#FF9900]" />
                                {item.region}
                                {item.resource_arn && <span className="ml-1 opacity-60">• {item.resource_arn.split(':').slice(-1)[0]}</span>}
                              </span>
                            ) : (
                              item.parent_path
                            )}
                          </div>
                        </Td>
                        <Td><ProviderBadge provider={item.provider} /></Td>
                        <Td>
                          <LabelBadge label={item.classification_label} />
                        </Td>
                        <Td>
                          <div className="flex flex-wrap gap-1">
                            {categories.slice(0, 2).map((c, i) => (
                              <DlpCategoryPill key={i} category={c} />
                            ))}
                            {categories.length > 2 && <span className="text-[10px] text-[#52525b]">+{categories.length - 2}</span>}
                            {categories.length === 0 && <span className="text-[11px] text-[#52525b]">—</span>}
                          </div>
                        </Td>
                        <Td>
                          <ScoreBar score={item.classification_score} />
                        </Td>
                        <Td>
                          <span className={`text-[11px] px-2 py-0.5 rounded border ${
                            item.sharing_scope === 'public' || item.sharing_scope === 'external'
                              ? 'bg-red-500/10 border-red-500/20 text-red-400'
                              : item.sharing_scope === 'private'
                              ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                              : 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
                          }`}>{item.sharing_scope ?? '—'}</span>
                        </Td>
                        <Td className="text-[12px] text-[#71717a]">{item.owner_email?.split('@')[0] ?? '—'}</Td>
                        <Td className="text-[12px] text-[#52525b]">{fmtDate(item.last_modified_at) || fmtDate(item.last_scanned_at)}</Td>
                        <Td className="text-[12px] text-[#52525b]">{fmtSize(item.size_bytes)}</Td>
                      </Tr>
                      {isExpanded && (
                        <Tr key={`${item.id}-expanded`} className="bg-[#0a0a0f]">
                          <Td colSpan={9} className="px-5 py-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                              {/* Risk Analysis (Claude-generated) */}
                              <div className="space-y-3">
                                <AIResourceRiskPanel itemId={item.id} />
                                {matchedPatterns.length > 0 && (
                                  <div>
                                    <div className="text-[10px] text-[#52525b] mb-1 uppercase tracking-wide">Matched Patterns</div>
                                    <div className="flex flex-wrap gap-1">
                                      {matchedPatterns.map((p, i) => (
                                        <span key={i} className="bg-amber-500/10 border border-amber-500/20 text-amber-300 px-2 py-0.5 rounded text-[10px] font-mono">{p.replace(/_/g,' ')}</span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {categories.length > 0 && (
                                  <div>
                                    <div className="text-[10px] text-[#52525b] mb-1 uppercase tracking-wide">DLP Categories</div>
                                    <div className="flex flex-wrap gap-1">
                                      {categories.map((c, i) => (
                                        <DlpCategoryPill key={i} category={c} />
                                      ))}
                                      </div>
                                  </div>
                                )}
                              </div>
                              {/* File Inventory Timeline */}
                              <div className="space-y-3">
                                <div className="text-[11px] font-semibold text-[#3b6ef6] uppercase tracking-wide">File Inventory</div>

                                {/* Visual timeline */}
                                <div className="relative pl-5 border-l-2 border-[#1e1e24] space-y-3">
                                  {item.created_at && (
                                    <div className="relative flex items-start gap-2">
                                      <div className="absolute -left-[22px] w-3 h-3 rounded-full bg-[#3b6ef6] border-2 border-[#0a0a0f] mt-0.5" />
                                      <div>
                                        <div className="text-[10px] text-[#52525b] uppercase tracking-wide">Created / First seen</div>
                                        <div className="text-[12px] text-[#a1a1aa]">{fmtDate(item.created_at)}</div>
                                      </div>
                                    </div>
                                  )}
                                  {item.last_modified_at && (
                                    <div className="relative flex items-start gap-2">
                                      <div className="absolute -left-[22px] w-3 h-3 rounded-full bg-amber-400 border-2 border-[#0a0a0f] mt-0.5" />
                                      <div>
                                        <div className="text-[10px] text-[#52525b] uppercase tracking-wide">Last Modified</div>
                                        <div className="text-[12px] text-[#a1a1aa]">{fmtDate(item.last_modified_at)}</div>
                                      </div>
                                    </div>
                                  )}
                                  <div className="relative flex items-start gap-2">
                                    <div className="absolute -left-[22px] w-3 h-3 rounded-full bg-emerald-400 border-2 border-[#0a0a0f] mt-0.5" />
                                    <div>
                                      <div className="text-[10px] text-[#52525b] uppercase tracking-wide">Last Scanned by Helios</div>
                                      <div className="text-[12px] text-[#a1a1aa]">{fmtDate(item.last_scanned_at) || 'Unknown'}</div>
                                    </div>
                                  </div>
                                </div>

                                {/* Risk score bar */}
                                {item.classification_score !== undefined && (
                                  <div>
                                    <div className="flex justify-between text-[10px] mb-1">
                                      <span className="text-[#52525b] uppercase tracking-wide">Risk Score</span>
                                      <span className={(
                                        (item.classification_score ?? 0) > 0.7 ? 'text-red-400' :
                                        (item.classification_score ?? 0) > 0.4 ? 'text-amber-400' : 'text-emerald-400'
                                      )}>{Math.round((item.classification_score ?? 0) * 100)}%</span>
                                    </div>
                                    <div className="h-1.5 bg-[#1e1e24] rounded-full overflow-hidden">
                                      <div
                                        className={`h-full rounded-full transition-all ${
                                          (item.classification_score ?? 0) > 0.7 ? 'bg-red-500' :
                                          (item.classification_score ?? 0) > 0.4 ? 'bg-amber-500' : 'bg-emerald-500'
                                        }`}
                                        style={{ width: `${Math.round((item.classification_score ?? 0) * 100)}%` }}
                                      />
                                    </div>
                                  </div>
                                )}

                                {/* Metadata grid */}
                                <div className="grid grid-cols-2 gap-2">
                                  <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                    <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Owner</div>
                                    <div className="text-[#a1a1aa] font-mono text-[11px] truncate">{item.owner_email ?? '—'}</div>
                                  </div>
                                  <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                    <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Size</div>
                                    <div className="text-[#a1a1aa] text-[12px]">{fmtSize(item.size_bytes)}</div>
                                  </div>
                                  <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                    <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Sharing</div>
                                    <span className={`text-[11px] px-1.5 py-0.5 rounded border ${
                                      item.sharing_scope === 'external' || item.sharing_scope === 'public'
                                        ? 'bg-red-500/10 border-red-500/20 text-red-400'
                                        : item.sharing_scope === 'private'
                                        ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                                        : 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
                                    }`}>{item.sharing_scope ?? '—'}</span>
                                  </div>
                                  <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                    <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Source</div>
                                    <div className="text-[#a1a1aa] text-[11px] capitalize">{item.provider}</div>
                                  </div>
                                  <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24] col-span-2">
                                    <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Location</div>
                                    <div className="text-[#a1a1aa] text-[11px] truncate">{item.parent_path ?? '—'}</div>
                                  </div>
                                  {/* AWS-specific details */}
                                  {item.source === 'aws' && (
                                    <>
                                      <div className="bg-[#FF9900]/5 rounded-lg p-2 border border-[#FF9900]/20">
                                        <div className="text-[10px] text-[#FF9900]/70 uppercase tracking-wide mb-0.5">AWS Region</div>
                                        <div className="text-[#FF9900] text-[11px] font-mono">{item.region ?? '—'}</div>
                                      </div>
                                      <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                        <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Encryption</div>
                                        <span className={`text-[11px] px-1.5 py-0.5 rounded border ${
                                          item.encryption_enabled
                                            ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                                            : 'bg-red-500/10 border-red-500/20 text-red-400'
                                        }`}>{item.encryption_enabled ? 'Encrypted' : 'Not Encrypted'}</span>
                                      </div>
                                      {item.resource_arn && (
                                        <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24] col-span-2">
                                          <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Resource ARN</div>
                                          <div className="text-[#a1a1aa] text-[10px] font-mono truncate">{item.resource_arn}</div>
                                        </div>
                                      )}
                                      {/* IAM User/Role details */}
                                      {(item.item_type === 'iam_user' || item.item_type === 'iam_role') && (() => {
                                        const meta = (item as unknown as Record<string, unknown>).metadata as Record<string, unknown> | undefined
                                        const lastKeyUsed = meta?.last_key_used_at as string | undefined
                                        const roleLastUsed = meta?.role_last_used as string | undefined
                                        const passwordLastUsed = meta?.password_last_used as string | undefined
                                        const mfaEnabled = meta?.mfa_enabled as boolean | undefined
                                        const consoleAccess = meta?.console_access as boolean | undefined
                                        const attachedPolicies = meta?.attached_policies as Array<{PolicyName: string}> | undefined
                                        return (
                                          <>
                                            {(lastKeyUsed || roleLastUsed || passwordLastUsed) && (
                                              <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                                <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Last Activity</div>
                                                <div className="text-[#a1a1aa] text-[11px]">
                                                  {lastKeyUsed ? `Key: ${fmtDate(lastKeyUsed)}` : 
                                                   roleLastUsed ? `Role: ${fmtDate(roleLastUsed)}` :
                                                   passwordLastUsed ? `Console: ${fmtDate(passwordLastUsed)}` : 'Never'}
                                                </div>
                                              </div>
                                            )}
                                            {item.item_type === 'iam_user' && (
                                              <>
                                                <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                                  <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">MFA Status</div>
                                                  <span className={`text-[11px] px-1.5 py-0.5 rounded border ${
                                                    mfaEnabled
                                                      ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                                                      : 'bg-red-500/10 border-red-500/20 text-red-400'
                                                  }`}>{mfaEnabled ? 'MFA Enabled' : 'No MFA'}</span>
                                                </div>
                                                <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                                  <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Console Access</div>
                                                  <span className={`text-[11px] px-1.5 py-0.5 rounded border ${
                                                    consoleAccess
                                                      ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                                                      : 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
                                                  }`}>{consoleAccess ? 'Has Console' : 'No Console'}</span>
                                                </div>
                                              </>
                                            )}
                                            {attachedPolicies && attachedPolicies.length > 0 && (
                                              <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24] col-span-2">
                                                <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Attached Policies</div>
                                                <div className="flex flex-wrap gap-1 mt-1">
                                                  {attachedPolicies.slice(0, 4).map((p, i) => (
                                                    <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-[#3b6ef6]/10 border border-[#3b6ef6]/20 text-[#3b6ef6]">
                                                      {p.PolicyName}
                                                    </span>
                                                  ))}
                                                  {attachedPolicies.length > 4 && <span className="text-[10px] text-[#52525b]">+{attachedPolicies.length - 4}</span>}
                                                </div>
                                              </div>
                                            )}
                                          </>
                                        )
                                      })()}
                                      {/* EC2 Instance details */}
                                      {item.item_type === 'ec2_instance' && (() => {
                                        const meta = (item as unknown as Record<string, unknown>).metadata as Record<string, unknown> | undefined
                                        const launchedBy = meta?.launched_by as string | undefined
                                        const instanceType = meta?.instance_type as string | undefined
                                        const state = meta?.state as string | undefined
                                        const publicIp = meta?.public_ip as string | undefined
                                        const imdsv2Required = meta?.imdsv2_required as boolean | undefined
                                        return (
                                          <>
                                            {launchedBy && (
                                              <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                                <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Launched By</div>
                                                <div className="text-[#a1a1aa] text-[11px] font-mono">{launchedBy}</div>
                                              </div>
                                            )}
                                            {instanceType && (
                                              <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                                <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Instance Type</div>
                                                <div className="text-[#a1a1aa] text-[11px] font-mono">{instanceType}</div>
                                              </div>
                                            )}
                                            {state && (
                                              <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                                <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">State</div>
                                                <span className={`text-[11px] px-1.5 py-0.5 rounded border ${
                                                  state === 'running'
                                                    ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                                                    : state === 'stopped'
                                                    ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                                                    : 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
                                                }`}>{state}</span>
                                              </div>
                                            )}
                                            {publicIp && (
                                              <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                                <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">Public IP</div>
                                                <div className="text-red-400 text-[11px] font-mono">{publicIp}</div>
                                              </div>
                                            )}
                                            <div className="bg-[#111114] rounded-lg p-2 border border-[#1e1e24]">
                                              <div className="text-[10px] text-[#52525b] uppercase tracking-wide mb-0.5">IMDSv2</div>
                                              <span className={`text-[11px] px-1.5 py-0.5 rounded border ${
                                                imdsv2Required
                                                  ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                                                  : 'bg-red-500/10 border-red-500/20 text-red-400'
                                              }`}>{imdsv2Required ? 'Required' : 'Optional (Vulnerable)'}</span>
                                            </div>
                                          </>
                                        )
                                      })()}
                                    </>
                                  )}
                                </div>
                              </div>
                            </div>
                          </Td>
                        </Tr>
                      )}
                    </>
                  )
                })}
              </Tbody>
            </Table>
          </div>
          <div className="flex items-center justify-between text-[12px] text-[#71717a]">
            <span>{total} total</span>
            <div className="flex gap-2">
              <Button size="sm" variant="ghost" onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1}>Prev</Button>
              <span className="px-2 py-1">Page {page}</span>
              <Button size="sm" variant="ghost" onClick={() => setPage(page + 1)} disabled={items.length < 20}>Next</Button>
            </div>
          </div>
        </>
      )}

      </>
      )}
    </div>
  )
}

// ── DSPM Overview ─ controls + profile + summary  ─────────────────────────────────
// ── Data Posture world map (DSPM overview) ───────────────────────────
// Adnan 2026-06-23: similar to the main Overview map, but here every
// region we have a resource in is *coloured* by the dominant DLP
// label of the data sitting in that region. Legend shows the
// classification → colour mapping the rest of the product uses.
//
// We keep the colour set canonical here so it lines up with the DLP
// pipeline categories on the backend (cross_cloud_dlp.py). If you add
// or rename a category, mirror it in HEURISTIC_RULES there too.
const DSPM_REGION_DLP_COLORS: Record<string, string> = {
  // Sensitive content
  pii:            '#ef4444',  // red          — PII
  pci:            '#dc2626',  // dark red     — payment card
  phi:            '#ea580c',  // orange       — health
  credentials:    '#f59e0b',  // amber        — secrets / keys
  financial:      '#eab308',  // yellow       — financial records
  customer_data:  '#f43f5e',  // rose         — customer data
  source_code:    '#8b5cf6',  // violet       — source code / repos
  ml_data:        '#a855f7',  // purple       — ML datasets / models
  backup:         '#3b6ef6',  // blue         — backups / snapshots
  logs:           '#06b6d4',  // cyan         — logs / audit
  config:         '#0ea5e9',  // sky          — config / IaC
  network:        '#22c55e',  // green        — network
  identity:       '#84cc16',  // lime         — IAM / identity
  public_data:    '#9ca3af',  // gray         — public / marketing
  infrastructure: '#6b7280',  // dark gray    — misc infra
  storage:        '#475569',  // slate        — untagged storage
  // Fallback when category is unknown / missing
  unknown:        '#3f3f46',
}

const DSPM_REGION_DLP_LABELS: Record<string, string> = {
  pii: 'PII',
  pci: 'Payment card (PCI)',
  phi: 'Health (PHI)',
  credentials: 'Credentials / secrets',
  financial: 'Financial records',
  customer_data: 'Customer data',
  source_code: 'Source code',
  ml_data: 'ML datasets',
  backup: 'Backups / snapshots',
  logs: 'Logs / audit',
  config: 'Config / IaC',
  network: 'Network',
  identity: 'IAM / identity',
  public_data: 'Public / marketing',
  infrastructure: 'Infrastructure',
  storage: 'Storage (untagged)',
  unknown: 'Unclassified',
}

// Cloud region → ISO-2 country codes. Mirrors backend
// `cross_region_access.REGION_TO_COUNTRIES` so we can shade the right
// countries on the world map. Keep these two in sync. Adnan 2026-06-23
// (turn 4): adding regions requires updates in both places.
const EU_COUNTRIES = [
  'AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE',
  'IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE',
];
const REGION_TO_COUNTRIES: Record<string, string[]> = {
  // AWS
  'us-east-1': ['US'], 'us-east-2': ['US'], 'us-west-1': ['US'], 'us-west-2': ['US'],
  'ca-central-1': ['CA'], 'ca-west-1': ['CA'],
  'eu-west-1': EU_COUNTRIES, 'eu-west-2': ['GB'], 'eu-west-3': EU_COUNTRIES,
  'eu-central-1': EU_COUNTRIES, 'eu-central-2': [...EU_COUNTRIES, 'CH'],
  'eu-north-1': EU_COUNTRIES, 'eu-south-1': EU_COUNTRIES, 'eu-south-2': EU_COUNTRIES,
  'me-south-1': ['BH'], 'me-central-1': ['AE'],
  'ap-south-1': ['IN'], 'ap-south-2': ['IN'],
  'ap-northeast-1': ['JP'], 'ap-northeast-2': ['KR'], 'ap-northeast-3': ['JP'],
  'ap-southeast-1': ['SG'], 'ap-southeast-2': ['AU'], 'ap-southeast-3': ['ID'], 'ap-southeast-4': ['AU'],
  'ap-east-1': ['HK'], 'sa-east-1': ['BR'], 'af-south-1': ['ZA'], 'il-central-1': ['IL'],
  // GCP
  'us-central1': ['US'], 'us-east1': ['US'], 'us-east4': ['US'], 'us-east5': ['US'],
  'us-west1': ['US'], 'us-west2': ['US'], 'us-west3': ['US'], 'us-west4': ['US'],
  'northamerica-northeast1': ['CA'], 'northamerica-northeast2': ['CA'],
  'southamerica-east1': ['BR'], 'southamerica-west1': ['CL'],
  'europe-west1': EU_COUNTRIES, 'europe-west2': ['GB'], 'europe-west3': EU_COUNTRIES,
  'europe-west4': EU_COUNTRIES, 'europe-west6': [...EU_COUNTRIES, 'CH'],
  'europe-west8': EU_COUNTRIES, 'europe-west9': EU_COUNTRIES, 'europe-west10': EU_COUNTRIES,
  'europe-west12': EU_COUNTRIES, 'europe-central2': EU_COUNTRIES, 'europe-north1': EU_COUNTRIES,
  'europe-southwest1': EU_COUNTRIES,
  'asia-east1': ['TW'], 'asia-east2': ['HK'], 'asia-northeast1': ['JP'], 'asia-northeast2': ['JP'],
  'asia-northeast3': ['KR'], 'asia-south1': ['IN'], 'asia-south2': ['IN'],
  'asia-southeast1': ['SG'], 'asia-southeast2': ['ID'],
  'australia-southeast1': ['AU'], 'australia-southeast2': ['AU'],
  'me-central1': ['QA'], 'me-central2': ['SA'], 'me-west1': ['IL'],
  'africa-south1': ['ZA'],
  // Azure
  eastus: ['US'], eastus2: ['US'], centralus: ['US'], northcentralus: ['US'],
  southcentralus: ['US'], westus: ['US'], westus2: ['US'], westus3: ['US'],
  canadacentral: ['CA'], canadaeast: ['CA'],
  brazilsouth: ['BR'], brazilsoutheast: ['BR'],
  northeurope: EU_COUNTRIES, westeurope: EU_COUNTRIES,
  uksouth: ['GB'], ukwest: ['GB'],
  francecentral: EU_COUNTRIES, francesouth: EU_COUNTRIES,
  germanywestcentral: EU_COUNTRIES, germanynorth: EU_COUNTRIES,
  italynorth: EU_COUNTRIES, norwayeast: EU_COUNTRIES, norwaywest: EU_COUNTRIES,
  polandcentral: EU_COUNTRIES, spaincentral: EU_COUNTRIES,
  swedencentral: EU_COUNTRIES, swedensouth: EU_COUNTRIES,
  switzerlandnorth: [...EU_COUNTRIES, 'CH'], switzerlandwest: [...EU_COUNTRIES, 'CH'],
  uaenorth: ['AE'], uaecentral: ['AE'],
  qatarcentral: ['QA'], israelcentral: ['IL'],
  southafricanorth: ['ZA'], southafricawest: ['ZA'],
  australiaeast: ['AU'], australiasoutheast: ['AU'],
  australiacentral: ['AU'], australiacentral2: ['AU'],
  centralindia: ['IN'], southindia: ['IN'], westindia: ['IN'], jioindiawest: ['IN'],
  eastasia: ['HK'], southeastasia: ['SG'],
  japaneast: ['JP'], japanwest: ['JP'],
  koreacentral: ['KR'], koreasouth: ['KR'],
};

function _countriesForRegion(region: string | null | undefined): string[] {
  if (!region) return [];
  const key = region.trim().toLowerCase();
  if (REGION_TO_COUNTRIES[key]) return REGION_TO_COUNTRIES[key];
  // Loose match: "gcp:us-central1" → "us-central1"
  for (const cand of [key, key.split(':').pop() || '', key.replace(/_/g, '-')]) {
    if (REGION_TO_COUNTRIES[cand]) return REGION_TO_COUNTRIES[cand];
  }
  return [];
}

// Sensitivity tier ranking. Drives the country fill colour ("how hot
// is this country"). Adnan 2026-06-23 (turn 4): the request was to
// highlight countries by the SENSITIVITY of data sitting there, not
// just per-category. We bucket items by their classification_label and
// pick the highest tier present in that country.
const SENSITIVITY_TIER: Record<string, number> = {
  highly_confidential: 4,
  confidential:        3,
  internal:            2,
  public:              1,
  unknown:             0,
};

const SENSITIVITY_COLOR: Record<string, string> = {
  highly_confidential: '#ef4444', // red
  confidential:        '#f59e0b', // amber
  internal:            '#3b6ef6', // blue
  public:              '#10b981', // green (low-sensitivity, fine to share)
  unknown:             '#3f3f46', // slate
};

const SENSITIVITY_LABEL: Record<string, string> = {
  highly_confidential: 'Highly confidential',
  confidential:        'Confidential',
  internal:            'Internal',
  public:              'Public',
  unknown:             'Unclassified',
};

function DataPostureWorldMap({ items }: { items: DataItem[] }) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<unknown>(null);
  const [residency, setResidency] = useState<DataResidencyInfo | null>(null);
  const [loadingRes, setLoadingRes] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const { data: res } = await api.get('/api/saas/data-residency');
        setResidency(res);
      } catch (e) {
        console.error('Data Posture map: residency load failed:', e);
      }
      setLoadingRes(false);
    })();
  }, []);

  // Per-region rollup: category breakdown + sensitivity breakdown.
  // Adnan 2026-06-23 (turn 4): we now ALSO track the sensitivity
  // label so the country fill reflects the highest-tier data sitting
  // in that country.
  type RegionRollup = {
    cat: string;
    total: number;
    breakdown: Record<string, number>;
    sensitivity: Record<string, number>;
    topTier: string;
  };
  const regionDominantCat = useMemo<Record<string, RegionRollup>>(() => {
    const counts: Record<string, Record<string, number>> = {};
    const sens: Record<string, Record<string, number>> = {};
    items.forEach(it => {
      const reg = (it.region as string | undefined) || '';
      if (!reg) return;
      const cats = Array.isArray(it.classification_categories)
        ? (it.classification_categories as string[])
        : [];
      const cat = cats.length > 0 ? cats[0] : 'unknown';
      if (!counts[reg]) counts[reg] = {};
      counts[reg][cat] = (counts[reg][cat] || 0) + 1;
      const lbl = (it.classification_label as string) || 'unknown';
      if (!sens[reg]) sens[reg] = {};
      sens[reg][lbl] = (sens[reg][lbl] || 0) + 1;
    });
    const out: Record<string, RegionRollup> = {};
    Object.entries(counts).forEach(([reg, m]) => {
      let dom = 'unknown'; let max = -1; let tot = 0;
      Object.entries(m).forEach(([c, n]) => {
        tot += n;
        if (n > max) { dom = c; max = n; }
      });
      // Pick the highest sensitivity tier present (not the most-frequent).
      // A single highly_confidential file in a region of 1000 internal
      // files should still light up the country red.
      const sensMap = sens[reg] || {};
      let topTier = 'unknown'; let topRank = -1;
      Object.keys(sensMap).forEach(lbl => {
        const r = SENSITIVITY_TIER[lbl] ?? 0;
        if (r > topRank) { topRank = r; topTier = lbl; }
      });
      out[reg] = { cat: dom, total: tot, breakdown: m, sensitivity: sensMap, topTier };
    });
    return out;
  }, [items]);

  // Country-level rollup. For each ISO-2 we accumulate:
  //   - the highest sensitivity tier seen across all its regions
  //   - total item count
  //   - dominant DLP category (most-frequent across joined regions)
  //   - which providers/regions contributed (for the tooltip)
  type CountryRollup = {
    topTier: string;
    topRank: number;
    total: number;
    cat: string;
    breakdown: Record<string, number>;
    sensitivity: Record<string, number>;
    regions: Array<{ provider?: string; region: string; count: number }>;
  };
  const countryRollup = useMemo<Record<string, CountryRollup>>(() => {
    const out: Record<string, CountryRollup> = {};
    const upsert = (code: string, info: {
      cat: string;
      total: number;
      breakdown: Record<string, number>;
      sensitivity: Record<string, number>;
      topTier: string;
    }, regionLabel: string) => {
      if (!out[code]) {
        out[code] = {
          topTier: 'unknown', topRank: -1, total: 0,
          cat: 'unknown', breakdown: {}, sensitivity: {},
          regions: [],
        };
      }
      const cur = out[code];
      cur.total += info.total;
      Object.entries(info.breakdown).forEach(([k, v]) => {
        cur.breakdown[k] = (cur.breakdown[k] || 0) + v;
      });
      Object.entries(info.sensitivity).forEach(([k, v]) => {
        cur.sensitivity[k] = (cur.sensitivity[k] || 0) + v;
      });
      const r = SENSITIVITY_TIER[info.topTier] ?? 0;
      if (r > cur.topRank) { cur.topRank = r; cur.topTier = info.topTier; }
      cur.regions.push({ region: regionLabel, count: info.total });
      let dom = cur.cat; let max = -1;
      Object.entries(cur.breakdown).forEach(([k, v]) => {
        if (v > max) { max = v; dom = k; }
      });
      cur.cat = dom;
    };

    // Inventory-derived rollup (AWS / GCP / Azure / Oracle / Databricks).
    Object.entries(regionDominantCat).forEach(([region, info]) => {
      const codes = _countriesForRegion(region);
      if (codes.length === 0) return;
      codes.forEach(code => upsert(code, info, region));
    });

    // Adnan 2026-06-23 (turn 6): M365 / SharePoint / Teams items don't
    // carry a `region` column — their location is the tenant_country.
    // Roll those up against the residency response so the M365 tenant
    // country still shades on the map even when no cloud connector is
    // configured.
    const tc = (residency?.tenant_country || '').toUpperCase();
    if (tc && tc.length === 2) {
      const breakdown: Record<string, number> = {};
      const sens: Record<string, number> = {};
      let total = 0;
      let topTier = 'unknown';
      let topRank = -1;
      items.forEach(it => {
        const prov = (it.provider || '').toLowerCase();
        if (!['m365', 'teams', 'sharepoint', 'onedrive'].includes(prov)) return;
        const cats = Array.isArray(it.classification_categories)
          ? (it.classification_categories as string[]) : [];
        const cat = cats.length > 0 ? cats[0] : 'unknown';
        breakdown[cat] = (breakdown[cat] || 0) + 1;
        const lbl = (it.classification_label as string) || 'unknown';
        sens[lbl] = (sens[lbl] || 0) + 1;
        const r = SENSITIVITY_TIER[lbl] ?? 0;
        if (r > topRank) { topRank = r; topTier = lbl; }
        total += 1;
      });
      if (total > 0) {
        let dom = 'unknown'; let max = -1;
        Object.entries(breakdown).forEach(([k, v]) => {
          if (v > max) { max = v; dom = k; }
        });
        upsert(tc, {
          cat: dom, total, breakdown, sensitivity: sens, topTier,
        }, `M365 tenant (${tc})`);
      }
    }

    return out;
  }, [regionDominantCat, items, residency]);

  const cloudRegions = residency?.cloud_regions ?? [];
  const validCR = cloudRegions.filter(cr => cr.lat && cr.lng && (cr.lat !== 0 || cr.lng !== 0));

  // Sensitivity histogram (for the tier legend pills below the map).
  const sensHist = useMemo(() => {
    const h: Record<string, number> = {};
    Object.values(countryRollup).forEach(c => {
      h[c.topTier] = (h[c.topTier] || 0) + 1;
    });
    return h;
  }, [countryRollup]);

  useEffect(() => {
    let cancelled = false;
    let resizeObserver: ResizeObserver | null = null;

    const initMap = async () => {
      if (cancelled || !mapRef.current || typeof window === 'undefined') return;
      const rect = mapRef.current.getBoundingClientRect();
      if (rect.width < 50 || rect.height < 50) {
        requestAnimationFrame(initMap);
        return;
      }
      const jsVectorMap = (await import('jsvectormap')).default;
      await import('jsvectormap/dist/maps/world');
      await import('jsvectormap/dist/jsvectormap.css');
      if (cancelled || !mapRef.current) return;

      if (mapInstanceRef.current) {
        try { (mapInstanceRef.current as { destroy: () => void }).destroy(); } catch {}
        mapInstanceRef.current = null;
      }
      while (mapRef.current.firstChild) {
        mapRef.current.removeChild(mapRef.current.firstChild);
      }

      // Per-country tier assignments. We feed jsvectormap a STRING tier
      // per country (not a hex color) and let it look up the hex in the
      // `scale` map. This is the actual jsvectormap v1.7 API — the
      // previous turn passed hex colors directly which jsvectormap
      // silently dropped (its Series.setValues always calls
      // scale.getValue(value)).  Validated against jsvectormap@1.7.0
      // with jsdom — see /tmp/jvm_test/test.mjs.
      const tierByCode: Record<string, string> = {};
      Object.entries(countryRollup).forEach(([code, c]) => {
        tierByCode[code.toUpperCase()] = c.topTier || 'unknown';
      });

      // De-dupe markers by coords, keeping resource count + category.
      const seen = new Map<string, {
        provider: string; region: string;
        cat: string; count: number; total: number;
        breakdown: Record<string, number>;
        topTier: string;
      }>();
      validCR.forEach(cr => {
        const key = `${(cr.lat as number).toFixed(2)}_${(cr.lng as number).toFixed(2)}`;
        const dom = regionDominantCat[cr.region] ?? {
          cat: 'unknown', total: 0, breakdown: {}, sensitivity: {}, topTier: 'unknown',
        };
        const cur = seen.get(key);
        if (cur) {
          cur.count += (cr.resource_count || 0);
          cur.total += dom.total;
          Object.entries(dom.breakdown).forEach(([k, v]) => {
            cur.breakdown[k] = (cur.breakdown[k] || 0) + v;
          });
          let domCat = cur.cat; let domN = -1;
          Object.entries(cur.breakdown).forEach(([k, v]) => {
            if (v > domN) { domN = v; domCat = k; }
          });
          cur.cat = domCat;
          const a = SENSITIVITY_TIER[cur.topTier] ?? 0;
          const b = SENSITIVITY_TIER[dom.topTier] ?? 0;
          if (b > a) cur.topTier = dom.topTier;
        } else {
          seen.set(key, {
            provider: cr.provider, region: cr.region,
            cat: dom.cat, count: cr.resource_count || 0,
            total: dom.total, breakdown: { ...dom.breakdown },
            topTier: dom.topTier,
          });
        }
      });

      type MarkerInfo = {
        provider: string; region: string;
        cat: string; count: number; total: number;
        breakdown: Record<string, number>;
        topTier: string;
      };
      const markers: Array<{ name: string; coords: [number, number] }> = [];
      const markerStyles: Array<{ fill: string; stroke?: string; r?: number }> = [];
      const markerData: MarkerInfo[] = [];
      for (const [key, info] of seen.entries()) {
        const [latStr, lngStr] = key.split('_');
        // Bigger markers on the bigger map. Scale by total resources.
        const r = Math.min(Math.max(6 + Math.sqrt(Math.max(info.total, info.count)) * 1.1, 7), 18);
        // Marker fill = sensitivity tier (so the marker matches the
        // country fill it's sitting on), stroke = DLP category for a
        // second visual signal.
        const fill = SENSITIVITY_COLOR[info.topTier] ?? SENSITIVITY_COLOR.unknown;
        const stroke = DSPM_REGION_DLP_COLORS[info.cat] ?? '#fff';
        markers.push({
          name: `${info.provider} · ${info.region}`,
          coords: [parseFloat(latStr), parseFloat(lngStr)],
        });
        markerStyles.push({ fill, stroke, r });
        markerData.push(info);
      }

      // CRITICAL: jsvectormap@1.7 takes per-country overrides via
      // `series.regions[]`, NOT a top-level `regions:` key. The previous
      // revision used the wrong key and that's why no country shaded.
      // The TS types don't declare `series` either, so we cast.
      const mapOptions = {
        selector: mapRef.current,
        map: 'world',
        backgroundColor: '#080810',
        draggable: true,
        zoomButtons: true,
        zoomOnScroll: true,
        zoomMax: 8,
        zoomMin: 1,
        showTooltip: true,
        regionStyle: {
          initial: { fill: '#1a1a2e', fillOpacity: 1, stroke: '#2a2a3e', strokeWidth: 0.6 },
          hover:   { fillOpacity: 0.9, cursor: 'pointer' },
        },
        series: {
          regions: [{
            attribute: 'fill',
            // ISO-2 → tier name. jsvectormap will look the tier up in
            // `scale` and apply the resulting hex as the country's fill.
            values: tierByCode,
            scale: {
              highly_confidential: SENSITIVITY_COLOR.highly_confidential,
              confidential:        SENSITIVITY_COLOR.confidential,
              internal:            SENSITIVITY_COLOR.internal,
              public:              SENSITIVITY_COLOR.public,
              unknown:             SENSITIVITY_COLOR.unknown,
            },
          }],
        },
        markerStyle: {
          initial: { fill: '#3b6ef6', fillOpacity: 0.95, stroke: '#fff', strokeWidth: 2, r: 7 },
          hover:   { fillOpacity: 0.85, cursor: 'pointer' },
        },
        markers: markers.map((m, idx) => ({ ...m, style: markerStyles[idx] })),
        onRegionTooltipShow: (
          tooltip: { selector: { innerHTML: string } },
          _e: unknown,
          code: string,
        ) => {
          const c = countryRollup[code];
          if (!c) {
            // Country with no data — hide the tooltip body entirely.
            tooltip.selector.innerHTML = '';
            return;
          }
          const sensLines = Object.entries(c.sensitivity)
            .sort((a, b) => (SENSITIVITY_TIER[b[0]] || 0) - (SENSITIVITY_TIER[a[0]] || 0))
            .map(([k, v]) =>
              `<div>• <span style="color:${SENSITIVITY_COLOR[k] ?? '#aaa'}">${SENSITIVITY_LABEL[k] ?? k}</span>: ${v}</div>`)
            .join('');
          const catLines = Object.entries(c.breakdown)
            .sort((a, b) => b[1] - a[1]).slice(0, 4)
            .map(([k, v]) => `<div>• ${DSPM_REGION_DLP_LABELS[k] ?? k}: ${v}</div>`)
            .join('');
          const regionList = c.regions.map(r => r.region).slice(0, 5).join(', ');
          tooltip.selector.innerHTML = `
            <div class="text-[11px] font-semibold">${code} · ${c.total} resources</div>
            <div class="text-[10px] text-zinc-400 mt-0.5">Top tier: <span style="color:${SENSITIVITY_COLOR[c.topTier]}">${SENSITIVITY_LABEL[c.topTier] ?? c.topTier}</span></div>
            <div class="text-[10px] mt-1.5">${sensLines}</div>
            <div class="text-[10px] mt-1.5 text-zinc-400">DLP categories:</div>
            <div class="text-[10px]">${catLines || 'none classified'}</div>
            <div class="text-[10px] mt-1 text-zinc-500">Regions: ${regionList}</div>
          `;
        },
        onMarkerTooltipShow: (
          tooltip: { text: () => string; selector: { innerHTML: string } },
          index: number,
        ) => {
          const m = markers[index]; const d = markerData[index];
          if (!m || !d) return;
          const lines = Object.entries(d.breakdown)
            .sort((a, b) => b[1] - a[1]).slice(0, 4)
            .map(([k, v]) => `<div>• ${DSPM_REGION_DLP_LABELS[k] ?? k}: ${v}</div>`)
            .join('');
          tooltip.selector.innerHTML = `
            <div class="text-[11px] font-medium">${m.name}</div>
            <div class="text-[10px] text-zinc-400">${d.count} resources · ${d.total} classified</div>
            <div class="text-[10px] mt-0.5">Top tier: <span style="color:${SENSITIVITY_COLOR[d.topTier]}">${SENSITIVITY_LABEL[d.topTier] ?? d.topTier}</span></div>
            <div class="text-[10px] mt-1">${lines || 'No DLP classification yet'}</div>
          `;
        },
      } as unknown as ConstructorParameters<typeof jsVectorMap>[0];
      mapInstanceRef.current = new jsVectorMap(mapOptions);
      // Fail-loud diagnostic so we never again ship a 'no shading' bug
      // without noticing. Count how many countries actually received a
      // non-default fill.
      try {
        const root = (mapRef.current as HTMLElement);
        const all = root.querySelectorAll('path');
        let shaded = 0;
        const sensFills = new Set(Object.values(SENSITIVITY_COLOR).map(v => v.toLowerCase()));
        all.forEach(p => {
          const f = (p as SVGPathElement).style.fill
            || (p as SVGPathElement).getAttribute('fill') || '';
          if (sensFills.has(f.toLowerCase())) shaded += 1;
        });
        // eslint-disable-next-line no-console
        console.info(
          `[DataPostureWorldMap] countries shaded=${shaded} of ${all.length} paths; tiers=`,
          tierByCode,
        );
      } catch {}
    };

    initMap();

    if (mapRef.current && typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
          const { width, height } = entry.contentRect;
          if (width > 50 && height > 50 && !mapInstanceRef.current) initMap();
        }
      });
      resizeObserver.observe(mapRef.current);
    }

    return () => {
      cancelled = true;
      if (resizeObserver) { try { resizeObserver.disconnect(); } catch {} }
      if (mapInstanceRef.current) {
        try { (mapInstanceRef.current as { destroy: () => void }).destroy(); } catch {}
        mapInstanceRef.current = null;
      }
    };
  }, [validCR, regionDominantCat, countryRollup]);

  // Active DLP categories present in the data (for the small bottom-row legend).
  const activeCats = useMemo(() => {
    const s = new Set<string>();
    Object.values(regionDominantCat).forEach(d => s.add(d.cat));
    if (s.size === 0) s.add('unknown');
    return Array.from(s);
  }, [regionDominantCat]);

  const countriesShown = Object.keys(countryRollup).length;

  return (
    <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Globe size={14} className="text-[#3b6ef6]" />
        <h3 className="text-[13px] font-semibold text-[var(--foreground)]">
          Data Posture by Region
        </h3>
        <span className="text-[10px] text-[var(--muted)] ml-auto">
          {loadingRes
            ? 'loading…'
            : `${countriesShown} countries shaded · ${validCR.length} cloud regions · ${items.length} items`}
        </span>
      </div>
      <p className="text-[11px] text-[var(--muted)] mb-3">
        Countries are shaded by the highest data-sensitivity tier sitting there.
        Markers show the specific cloud region holding the data; marker fill = sensitivity tier,
        marker outline = dominant DLP category. Hover any country or marker for the breakdown.
      </p>

      {/* Sensitivity tier legend (this is the primary legend now — it
          matches the country fill). */}
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <span className="text-[10px] uppercase tracking-wide text-[var(--muted)]">Sensitivity:</span>
        {(['highly_confidential', 'confidential', 'internal', 'public', 'unknown'] as const).map(tier => {
          const n = sensHist[tier] || 0;
          return (
            <span
              key={tier}
              className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md border border-[var(--border)] text-[10px] ${
                n > 0 ? 'bg-[#0e0e14] text-[var(--foreground)]/85' : 'bg-transparent text-[var(--muted)] opacity-60'
              }`}
            >
              <span
                className="inline-block w-3 h-3 rounded-sm"
                style={{ background: SENSITIVITY_COLOR[tier] }}
              />
              {SENSITIVITY_LABEL[tier]}
              <span className="text-[var(--muted)]">({n})</span>
            </span>
          );
        })}
      </div>

      {/* Adnan 2026-06-23 (turn 5): h-[640px] was still too small on
          1440p+ displays. Make the map fill 80% of viewport height with
          a 640px floor and a 1100px ceiling so the legend below stays
          on-screen on smaller monitors. */}
      <div
        ref={mapRef}
        className="w-full min-h-[640px] h-[80vh] max-h-[1100px] rounded-lg overflow-hidden bg-[#080810] mb-3"
      />

      {/* DLP category legend (smaller — secondary, matches marker outline). */}
      <div className="flex flex-wrap gap-1.5">
        <span className="text-[10px] uppercase tracking-wide text-[var(--muted)] self-center mr-1">Marker outline:</span>
        {activeCats.map(cat => (
          <span
            key={cat}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-md border border-[var(--border)] bg-[#0e0e14] text-[9px] text-[var(--foreground)]/80"
          >
            <span
              className="inline-block w-2 h-2 rounded-full"
              style={{ background: DSPM_REGION_DLP_COLORS[cat] ?? DSPM_REGION_DLP_COLORS.unknown }}
            />
            {DSPM_REGION_DLP_LABELS[cat] ?? cat}
          </span>
        ))}
      </div>
    </div>
  );
}

function DSPMOverview({
  summary,
  items,
}: {
  summary: DataSummary | null
  items: DataItem[]
}) {
  const total = summary?.total ?? 0
  const confidential = (summary?.by_label?.confidential ?? 0) + (summary?.by_label?.highly_confidential ?? 0)
  const publicCount = summary?.by_scope?.public ?? 0
  const externalCount = summary?.by_scope?.external ?? 0
  const orgCount = summary?.by_scope?.org ?? 0
  const privateCount = summary?.by_scope?.private ?? 0
  const byProvider = summary?.by_provider || {}
  const visibleForRiskCalc = items.filter(it => {
    const t = (it.item_type || '').toLowerCase()
    return t !== 'iam_user' && t !== 'iam_role' && t !== 'user' && t !== 'role'
  })
  const unclassifiedCount = visibleForRiskCalc.filter(
    it => !it.classification_label || it.classification_label === 'unknown'
  ).length
  const classificationCoverage = visibleForRiskCalc.length > 0
    ? Math.round((1 - unclassifiedCount / visibleForRiskCalc.length) * 100)
    : 0

  // Surfaces controls. Each control is a binary "is this DSPM
  // capability operating against your data" check, evaluated from the
  // discovered inventory + provider coverage. Adnan asked for more
  // DSPM features here — these are the standard DSPM control families.
  const controls = [
    {
      name: 'Continuous data discovery',
      desc: 'Identify SaaS, cloud, and code repos containing data',
      ok: Object.keys(byProvider).length > 0,
      value: `${Object.keys(byProvider).length} providers actively scanning`,
    },
    {
      name: 'Sensitive-data classification',
      desc: 'Himaya Data Posture agent labels every discovered resource by content',
      ok: classificationCoverage >= 50,
      value: `${classificationCoverage}% of resources classified`,
    },
    {
      name: 'Exposure detection',
      desc: 'Surface public + externally-shared resources',
      ok: publicCount + externalCount > 0 || total > 0,
      value: `${publicCount} public · ${externalCount} external-shared`,
    },
    {
      name: 'Access governance',
      desc: 'Visibility into who can read each data resource',
      ok: total > 0,
      value: `${orgCount + privateCount} org-scoped · ${privateCount} private`,
    },
    {
      name: 'Confidential data protection',
      desc: 'Flag highly-confidential resources for review',
      ok: confidential > 0 || total === 0,
      value: `${confidential} confidential / ${total} total`,
    },
  ]

  return (
    <div className="space-y-6">
      {/* Profile / posture summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Resources" value={total} />
        <StatCard
          label="Classification Coverage"
          value={`${classificationCoverage}%`}
          sub={`${unclassifiedCount} unclassified`}
          color={classificationCoverage >= 75 ? 'text-emerald-400' : classificationCoverage >= 50 ? 'text-amber-400' : 'text-red-400'}
        />
        <StatCard
          label="Confidential"
          value={confidential}
          sub={`${total > 0 ? Math.round((confidential / total) * 100) : 0}% of inventory`}
          color="text-amber-400"
        />
        <StatCard
          label="Externally Exposed"
          value={publicCount + externalCount}
          sub={`${publicCount} public + ${externalCount} shared`}
          color={publicCount + externalCount > 0 ? 'text-red-400' : 'text-emerald-400'}
        />
      </div>

      {/* Data Posture world map — added 2026-06-23 (Adnan).
          Every region a resource lives in coloured by its dominant DLP
          category. The colour key is canonical — see
          DLP_CATEGORY_COLORS just above DataPostureWorldMap. */}
      <DataPostureWorldMap items={items} />

      {/* DSPM control matrix */}
      <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <ShieldCheck size={14} className="text-[#3b6ef6]" />
          <h3 className="text-[13px] font-semibold text-[var(--foreground)]">DSPM Controls</h3>
        </div>
        <div className="space-y-2">
          {controls.map(c => (
            <div
              key={c.name}
              className="flex items-start gap-3 py-2.5 border-b border-[var(--border)] last:border-b-0"
            >
              <div className="mt-0.5">
                {c.ok ? (
                  <CheckCircle2 size={14} className="text-emerald-400" />
                ) : (
                  <AlertTriangle size={14} className="text-amber-400" />
                )}
              </div>
              <div className="flex-1">
                <div className="text-[12px] font-medium text-[var(--foreground)]">{c.name}</div>
                <div className="text-[11px] text-[var(--muted)]">{c.desc}</div>
              </div>
              <div className="text-[11px] text-[var(--foreground)]/80 text-right">{c.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Data profile by provider */}
      {Object.keys(byProvider).length > 0 && (
        <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Database size={14} className="text-[#3b6ef6]" />
            <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Resources by Provider</h3>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(byProvider)
              .sort((a, b) => (b[1] as number) - (a[1] as number))
              .map(([prov, count]) => (
                <div key={prov} className="bg-[#0e0e14] border border-[var(--border)] rounded-lg p-3">
                  <div className="text-[11px] uppercase tracking-wide text-[var(--muted)]">{prov}</div>
                  <div className="text-xl font-semibold text-[var(--foreground)] mt-1">{count as number}</div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── DSPM Insights ─────────────────────────────────────────────────────────────
// New DSPM sub-tab Adnan asked for: high-value DSPM features computed
// from the live inventory across all connected paid connectors.
// Toxic Combinations panel (backend-driven, Concentric/Varonis style)
interface ToxicCombination {
  id: string
  rule_id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  title: string
  description: string
  resources: Array<Record<string, unknown>>
  factors: string[]
  status: string
  first_seen_at: string | null
  last_seen_at: string | null
}

function ToxicCombinationsPanel({ fallbackItems }: { fallbackItems: DataItem[] }) {
  const [items, setItems] = useState<ToxicCombination[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [running, setRunning] = useState(false)

  const load = useCallback(async () => {
    try {
      const r = await api.get<{ items: ToxicCombination[] }>(
        '/api/dspm/toxic-combinations?status=open&limit=100',
      )
      setItems(r.data.items || [])
      setError(null)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setError(msg)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const runNow = async () => {
    setRunning(true)
    try {
      await api.post('/api/dspm/toxic-combinations/run', {})
      await load()
    } catch {} finally { setRunning(false) }
  }

  const resolve = async (id: string) => {
    try {
      await api.post(`/api/dspm/toxic-combinations/${id}/resolve`, {})
      setItems(prev => prev.filter(x => x.id !== id))
    } catch {}
  }

  const sevPill = (s: string) => {
    if (s === 'critical') return 'bg-red-500/10 border-red-500/30 text-red-400'
    if (s === 'high')     return 'bg-orange-500/10 border-orange-500/30 text-orange-400'
    if (s === 'medium')   return 'bg-amber-500/10 border-amber-500/30 text-amber-400'
    return 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400'
  }

  const showFallback = !loading && items.length === 0 && fallbackItems.length > 0

  return (
    <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <AlertOctagon size={14} className="text-red-400" />
        <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Toxic Combinations</h3>
        <span className="text-[10px] text-[var(--muted)] ml-auto">
          {loading ? 'loading…' : `${items.length} open`}
        </span>
        <button
          onClick={runNow}
          disabled={running}
          className="text-[10px] px-2 py-1 rounded border border-[var(--border)] text-[var(--muted)] hover:bg-[#1a1a22] disabled:opacity-50"
          title="Force a synchronous run of the toxic engine for your org"
        >
          {running ? 'Running…' : 'Run now'}
        </button>
      </div>
      <p className="text-[11px] text-[var(--muted)] mb-3">
        Compound risk findings: pairs / sets of facts that are individually tolerable but
        critical together. Triage these first — they are where breaches actually start.
      </p>

      {error && (
        <div className="text-[11px] text-amber-400 mb-3">
          API: {error}. Falling back to heuristic view below.
        </div>
      )}

      {loading ? (
        <div className="text-[12px] text-[var(--muted)]">Loading toxic combinations…</div>
      ) : items.length > 0 ? (
        <div className="divide-y divide-[var(--border)]">
          {items.slice(0, 12).map(tc => (
            <div key={tc.id} className="py-3 flex items-start gap-3">
              <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold border ${sevPill(tc.severity)} flex-shrink-0`}>
                {tc.severity.toUpperCase()}
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-[12px] text-[var(--foreground)] font-medium">{tc.title}</div>
                <div className="text-[11px] text-[var(--muted)] mt-0.5">{tc.description}</div>
                {tc.factors.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {tc.factors.map((f, i) => (
                      <span key={i} className="text-[9px] px-1.5 py-0.5 rounded bg-[#1a1a22] border border-[var(--border)] text-[var(--muted)]">
                        {f}
                      </span>
                    ))}
                  </div>
                )}
                <div className="text-[9px] text-[#52525b] mt-1">rule: {tc.rule_id}</div>
              </div>
              <button
                onClick={() => resolve(tc.id)}
                className="text-[10px] px-2 py-0.5 rounded border border-[var(--border)] text-[var(--muted)] hover:bg-[#1a1a22] flex-shrink-0"
              >
                Resolve
              </button>
            </div>
          ))}
          {items.length > 12 && (
            <div className="py-2 text-[11px] text-[var(--muted)]">+ {items.length - 12} more</div>
          )}
        </div>
      ) : showFallback ? (
        <div>
          <div className="text-[11px] text-[var(--muted)] mb-2">
            Backend engine has no findings yet — showing heuristic results:
          </div>
          <div className="divide-y divide-[var(--border)]">
            {fallbackItems.slice(0, 8).map(it => (
              <div key={it.id} className="py-2.5 flex items-start gap-3">
                <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-red-500/10 border border-red-500/20 text-red-400">
                  {(it.classification_label || '').toUpperCase().replace('_', ' ')}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-[12px] text-[var(--foreground)] truncate">{it.item_name || it.item_type}</div>
                  <div className="text-[10px] text-[var(--muted)]">
                    {it.provider} · {it.sharing_scope} · {it.owner_email || 'no owner'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="text-[12px] text-emerald-400/80 flex items-center gap-1.5">
          <CheckCircle2 size={12} /> No toxic combinations detected.
        </div>
      )}
    </div>
  )
}

// Data Correlation Graph (Mermaid)
function DataCorrelationGraph({ items }: { items: DataItem[] }) {
  const conf = items.filter(
    it => it.classification_label === 'confidential' || it.classification_label === 'highly_confidential'
  )
  if (conf.length === 0) return null

  const providerNodes = new Map<string, number>()
  const ownerNodes = new Map<string, { provider: string; count: number; external: number }>()
  conf.forEach(it => {
    const p = it.provider || 'unknown'
    providerNodes.set(p, (providerNodes.get(p) || 0) + 1)
    const owner = (it.owner_email || 'unowned').toLowerCase()
    const key = `${p}::${owner}`
    const cur = ownerNodes.get(key) || { provider: p, count: 0, external: 0 }
    cur.count += 1
    if (it.sharing_scope === 'external' || it.sharing_scope === 'public') cur.external += 1
    ownerNodes.set(key, cur)
  })

  const sortedOwners = Array.from(ownerNodes.entries())
    .sort((a, b) => (b[1].external - a[1].external) || (b[1].count - a[1].count))
    .slice(0, 18)

  const sanitize = (s: string) =>
    s.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 32) || 'x'

  const lines: string[] = []
  lines.push('flowchart LR')
  lines.push('  classDef provider fill:#1a1a22,stroke:#3a3a48,color:#e4e4e7;')
  lines.push('  classDef owner fill:#1a1f2a,stroke:#3b6ef6,color:#cdd6e8;')
  lines.push('  classDef external fill:#2a0f12,stroke:#f87171,color:#fecaca;')

  Array.from(providerNodes.entries()).forEach(([p, n]) => {
    const id = `P_${sanitize(p)}`
    lines.push(`  ${id}(["${p} (${n})"]):::provider`)
  })

  sortedOwners.forEach(([key, info]) => {
    const ownerEmail = key.split('::')[1] || 'unowned'
    const safeOwner = sanitize(ownerEmail)
    const oid = `O_${sanitize(info.provider)}_${safeOwner}`
    const label = ownerEmail.length > 24 ? ownerEmail.slice(0, 22) + '…' : ownerEmail
    lines.push(`  ${oid}["${label}<br/>${info.count} files"]:::owner`)
    lines.push(`  P_${sanitize(info.provider)} --> ${oid}`)
    if (info.external > 0) {
      const eid = `E_${sanitize(info.provider)}_${safeOwner}`
      lines.push(`  ${eid}(("↗ ${info.external} external")):::external`)
      lines.push(`  ${oid} -.->|shared| ${eid}`)
    }
  })

  const chart = lines.join('\n')

  return (
    <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Network size={14} className="text-[#3b6ef6]" />
        <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Data Correlation Map</h3>
        <span className="text-[10px] text-[var(--muted)] ml-auto">Top {sortedOwners.length} owners by exposure</span>
      </div>
      <p className="text-[11px] text-[var(--muted)] mb-4">
        How confidential data flows from each connector through its top owners to external
        endpoints. Red “external” nodes are where data leaves your tenant.
      </p>
      <div className="min-h-[200px]">
        <MermaidDiagram chart={chart} />
      </div>
    </div>
  )
}

// Access Intelligence — per-owner blast radius across providers
interface OwnerRow {
  owner: string
  total: number
  sensitive: number
  external: number
  providers: Record<string, number>
  provider_count: number
  last_seen: string | null
  exposure_score: number
}

function AccessIntelligencePanel() {
  const [owners, setOwners] = useState<OwnerRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const r = await api.get<{ items: OwnerRow[] }>('/api/dspm/access/owners?limit=30')
        if (!cancelled) setOwners(r.data.items || [])
      } catch (e: unknown) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  return (
    <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Users size={14} className="text-[#3b6ef6]" />
        <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Access Intelligence</h3>
        <span className="text-[10px] text-[var(--muted)] ml-auto">
          {loading ? 'loading…' : `${owners.length} identities ranked`}
        </span>
      </div>
      <p className="text-[11px] text-[var(--muted)] mb-3">
        Per-owner exposure across every connected provider. Sorted by exposure score
        (sensitive assets + 3× external shares). This is the list to use when scoping
        an offboarding, access review, or credential rotation.
      </p>
      {error && <div className="text-[11px] text-amber-400 mb-2">{error}</div>}
      {loading ? (
        <div className="text-[12px] text-[var(--muted)]">Aggregating identities…</div>
      ) : owners.length === 0 ? (
        <div className="text-[12px] text-[var(--muted)]">No identities to rank yet — scan inventory first.</div>
      ) : (
        <div className="divide-y divide-[var(--border)]">
          {owners.slice(0, 15).map(o => (
            <div key={o.owner} className="py-2.5">
              <button
                onClick={() => setExpanded(expanded === o.owner ? null : o.owner)}
                className="w-full flex items-center gap-3 text-left hover:bg-[#0e0e14] -mx-2 px-2 py-1 rounded"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-[12px] text-[var(--foreground)] truncate font-medium">{o.owner}</div>
                  <div className="text-[10px] text-[var(--muted)] mt-0.5">
                    {o.total} total · {o.sensitive} sensitive · {o.external} external
                    {o.provider_count > 1 && (
                      <span className="ml-2 text-orange-400">cross-cloud ({o.provider_count})</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  {Object.entries(o.providers).slice(0, 4).map(([prov, n]) => (
                    <span key={prov} className="text-[9px] px-1.5 py-0.5 rounded bg-[#1a1a22] border border-[var(--border)] text-[var(--muted)]">
                      {prov}: {n}
                    </span>
                  ))}
                  <span className={`text-[11px] font-semibold px-2 py-0.5 rounded ${
                    o.exposure_score > 20 ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                      : o.exposure_score > 5 ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  }`}>
                    {o.exposure_score}
                  </span>
                </div>
              </button>
              {expanded === o.owner && (
                <OwnerBlastRadius owner={o.owner} />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function OwnerBlastRadius({ owner }: { owner: string }) {
  const [items, setItems] = useState<Array<Record<string, unknown>>>([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const r = await api.get<{ items: Array<Record<string, unknown>> }>(
          `/api/dspm/access/blast-radius/${encodeURIComponent(owner)}`,
        )
        if (!cancelled) setItems(r.data.items || [])
      } catch {} finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [owner])
  if (loading) return <div className="text-[11px] text-[var(--muted)] mt-2 ml-2">Loading blast radius…</div>
  if (items.length === 0) return <div className="text-[11px] text-[var(--muted)] mt-2 ml-2">No assets resolved.</div>
  return (
    <div className="mt-2 ml-2 pl-3 border-l border-[var(--border)] space-y-1 max-h-[260px] overflow-auto">
      {items.slice(0, 40).map((it, i) => (
        <div key={i} className="flex items-center gap-2 text-[11px]">
          <span className="text-[9px] px-1 py-0.5 rounded bg-[#1a1a22] border border-[var(--border)] text-[var(--muted)] flex-shrink-0">
            {String(it.provider || '?')}
          </span>
          <span className="text-[var(--foreground)] truncate flex-1">{String(it.name || it.type || 'item')}</span>
          {String(it.sharing || '') === 'external' || String(it.sharing || '') === 'public' ? (
            <span className="text-[9px] text-red-400 flex-shrink-0">{String(it.sharing)}</span>
          ) : null}
          {it.label ? (
            <span className="text-[9px] text-amber-400 flex-shrink-0">{String(it.label)}</span>
          ) : null}
        </div>
      ))}
      {items.length > 40 && (
        <div className="text-[10px] text-[var(--muted)]">+ {items.length - 40} more</div>
      )}
    </div>
  )
}

function DSPMInsights({
  summary,
  items,
}: {
  summary: DataSummary | null
  items: DataItem[]
}) {
  const visible = items.filter(it => {
    const t = (it.item_type || '').toLowerCase()
    return t !== 'iam_user' && t !== 'iam_role' && t !== 'user' && t !== 'role'
  })

  const isExt = (s?: string) => s === 'external' || s === 'public'
  const isConfidential = (l?: string) => l === 'confidential' || l === 'highly_confidential'

  const toxic = visible.filter(it =>
    isConfidential(it.classification_label) && isExt(it.sharing_scope)
  )

  const ownerMap = new Map<string, Map<string, DataItem[]>>()
  visible.forEach(it => {
    if (!isConfidential(it.classification_label)) return
    const owner = (it.owner_email || '').toLowerCase()
    if (!owner) return
    if (!ownerMap.has(owner)) ownerMap.set(owner, new Map())
    const provMap = ownerMap.get(owner)!
    const p = (it.provider || 'unknown')
    if (!provMap.has(p)) provMap.set(p, [])
    provMap.get(p)!.push(it)
  })
  const crossConnector = Array.from(ownerMap.entries())
    .filter(([, provMap]) => provMap.size >= 2)
    .map(([owner, provMap]) => {
      const allItems = Array.from(provMap.values()).flat()
      const externallyExposed = allItems.filter(it => isExt(it.sharing_scope))
      return {
        owner,
        providers: Array.from(provMap.keys()),
        total: allItems.length,
        external: externallyExposed.length,
      }
    })
    .sort((a, b) => b.external - a.external || b.total - a.total)
    .slice(0, 8)

  const shadow = visible.filter(it =>
    !it.classification_label || it.classification_label === 'unknown'
  )
  const shadowRatio = visible.length > 0 ? Math.round((shadow.length / visible.length) * 100) : 0

  const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000
  const forgotten = visible.filter(it => {
    if (!isConfidential(it.classification_label)) return false
    if (!isExt(it.sharing_scope)) return false
    const lm = it.last_modified_at ? new Date(it.last_modified_at).getTime() : 0
    return lm > 0 && lm < ninetyDaysAgo
  }).sort((a, b) => {
    const at = a.last_modified_at ? new Date(a.last_modified_at).getTime() : 0
    const bt = b.last_modified_at ? new Date(b.last_modified_at).getTime() : 0
    return at - bt
  }).slice(0, 8)

  const stewardCount = new Map<string, { total: number; confidential: number; external: number }>()
  visible.forEach(it => {
    const owner = (it.owner_email || '').toLowerCase()
    if (!owner) return
    const e = stewardCount.get(owner) || { total: 0, confidential: 0, external: 0 }
    e.total += 1
    if (isConfidential(it.classification_label)) e.confidential += 1
    if (isExt(it.sharing_scope)) e.external += 1
    stewardCount.set(owner, e)
  })
  const stewards = Array.from(stewardCount.entries())
    .map(([owner, c]) => ({ owner, ...c, risk: c.confidential * 2 + c.external * 3 }))
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 6)

  const byProviderLabel = new Map<string, Record<string, number>>()
  visible.forEach(it => {
    const p = it.provider || 'unknown'
    const l = it.classification_label || 'unknown'
    if (!byProviderLabel.has(p)) byProviderLabel.set(p, {})
    const rec = byProviderLabel.get(p)!
    rec[l] = (rec[l] || 0) + 1
  })
  const labelColor: Record<string, string> = {
    public: 'bg-zinc-400/60',
    internal: 'bg-blue-400/60',
    confidential: 'bg-amber-400/70',
    highly_confidential: 'bg-red-400/75',
    pii: 'bg-purple-400/70',
    phi: 'bg-pink-400/70',
    unknown: 'bg-zinc-700/40',
  }

  const surfaceScore = (() => {
    const total = visible.length || 1
    const toxicWeight = toxic.length * 4
    const shadowWeight = shadow.length * 1
    const forgottenWeight = forgotten.length * 3
    const ratio = (toxicWeight + shadowWeight + forgottenWeight) / total
    return Math.max(0, Math.min(100, Math.round(100 - ratio * 100)))
  })()
  const surfaceColor = surfaceScore >= 80 ? 'text-emerald-400'
    : surfaceScore >= 60 ? 'text-amber-400' : 'text-red-400'

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-4 flex flex-col items-center justify-center">
          <div className={`text-3xl font-bold ${surfaceColor}`}>{surfaceScore}</div>
          <div className="text-[11px] text-[var(--muted)] mt-1 text-center">Data Surface Score</div>
          <div className="text-[10px] text-[var(--muted)]/70 mt-0.5 text-center">100 = no exposure</div>
        </div>
        <StatCard
          label="Toxic Combinations"
          value={toxic.length}
          sub="Confidential + externally exposed"
          color={toxic.length > 0 ? 'text-red-400' : 'text-emerald-400'}
        />
        <StatCard
          label="Shadow Data"
          value={shadow.length}
          sub={`${shadowRatio}% of inventory unclassified`}
          color={shadowRatio > 25 ? 'text-amber-400' : 'text-emerald-400'}
        />
        <StatCard
          label="Forgotten Exposed"
          value={forgotten.length}
          sub="Confidential + external + stale 90d+"
          color={forgotten.length > 0 ? 'text-amber-400' : 'text-emerald-400'}
        />
      </div>

      {/* Real, backend-driven Toxic Combinations engine (multi-rule). Falls
          back to the heuristic toxic[] list above if the API hasn't run yet. */}
      <ToxicCombinationsPanel fallbackItems={toxic} />

      {/* Access Intelligence — per-owner exposure score, click for blast radius */}
      <AccessIntelligencePanel />

      <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Network size={14} className="text-[#3b6ef6]" />
          <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Cross-Connector Exposure</h3>
          <span className="text-[10px] text-[var(--muted)] ml-auto">{crossConnector.length} owners</span>
        </div>
        <p className="text-[11px] text-[var(--muted)] mb-3">
          Owners with confidential data spread across multiple connected providers. These are the
          accounts where a single credential compromise has the widest blast radius.
        </p>
        {crossConnector.length === 0 ? (
          <div className="text-[12px] text-[var(--muted)]">No cross-connector exposure detected yet.</div>
        ) : (
          <Table>
            <Thead>
              <Tr>
                <Th>Owner</Th>
                <Th>Providers</Th>
                <Th>Confidential items</Th>
                <Th>Externally exposed</Th>
              </Tr>
            </Thead>
            <Tbody>
              {crossConnector.map(c => (
                <Tr key={c.owner}>
                  <Td className="text-[12px] text-[var(--foreground)]">{c.owner}</Td>
                  <Td>
                    <div className="flex gap-1">
                      {c.providers.map(p => (
                        <span key={p} className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-[#3b6ef6]/10 border border-[#3b6ef6]/20 text-[#93b4fd]">{p}</span>
                      ))}
                    </div>
                  </Td>
                  <Td className="text-[12px] text-amber-400">{c.total}</Td>
                  <Td className={`text-[12px] ${c.external > 0 ? 'text-red-400' : 'text-emerald-400'}`}>{c.external}</Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </div>

      <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Clock size={14} className="text-amber-400" />
          <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Forgotten Exposed Data</h3>
          <span className="text-[10px] text-[var(--muted)] ml-auto">{forgotten.length} stale resources</span>
        </div>
        <p className="text-[11px] text-[var(--muted)] mb-3">
          Confidential data that has been externally shared and not touched in 90+ days. These are
          often forgotten regulatory time-bombs left behind by departed projects or employees.
        </p>
        {forgotten.length === 0 ? (
          <div className="text-[12px] text-emerald-400/80 flex items-center gap-1.5">
            <CheckCircle2 size={12} /> No forgotten exposed data found.
          </div>
        ) : (
          <div className="divide-y divide-[var(--border)]">
            {forgotten.map(it => (
              <div key={it.id} className="py-2.5 flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="text-[12px] text-[var(--foreground)] truncate">{it.item_name || it.item_type}</div>
                  <div className="text-[10px] text-[var(--muted)]">
                    {it.provider} · last modified {it.last_modified_at ? new Date(it.last_modified_at).toLocaleDateString() : 'unknown'}
                  </div>
                </div>
                <span className="text-[10px] text-amber-400">{it.sharing_scope}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Users size={14} className="text-[#3b6ef6]" />
          <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Top Data Stewards</h3>
          <span className="text-[10px] text-[var(--muted)] ml-auto">By risk score</span>
        </div>
        <p className="text-[11px] text-[var(--muted)] mb-3">
          Owners ranked by how much high-risk data they hold. Use this to assign accountability
          for data minimisation and access reviews.
        </p>
        {stewards.length === 0 ? (
          <div className="text-[12px] text-[var(--muted)]">No owners assigned to discovered data yet.</div>
        ) : (
          <div className="space-y-2">
            {stewards.map(s => {
              const maxRisk = stewards[0].risk || 1
              const widthPct = Math.max(8, Math.round((s.risk / maxRisk) * 100))
              return (
                <div key={s.owner} className="flex items-center gap-3">
                  <div className="text-[12px] text-[var(--foreground)] truncate w-56 flex-shrink-0">{s.owner}</div>
                  <div className="flex-1 h-3 bg-[#0e0e14] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-[#3b6ef6] to-red-400"
                      style={{ width: `${widthPct}%` }}
                    />
                  </div>
                  <div className="text-[10px] text-[var(--muted)] w-44 flex-shrink-0 text-right">
                    {s.total} items · <span className="text-amber-400">{s.confidential}</span> conf · <span className="text-red-400">{s.external}</span> ext
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Layers size={14} className="text-[#3b6ef6]" />
          <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Data Classification Flow</h3>
          <span className="text-[10px] text-[var(--muted)] ml-auto">Across all connected providers</span>
        </div>
        <p className="text-[11px] text-[var(--muted)] mb-4">
          How each connector contributes to your overall data classification mix. Heavy red / amber
          on any one connector tells you where your DLP investments should focus.
        </p>
        {byProviderLabel.size === 0 ? (
          <div className="text-[12px] text-[var(--muted)]">No classified data yet.</div>
        ) : (
          <div className="space-y-3">
            {Array.from(byProviderLabel.entries()).map(([prov, labels]) => {
              const total = Object.values(labels).reduce((s, n) => s + n, 0)
              return (
                <div key={prov}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[12px] font-medium text-[var(--foreground)]">{prov}</span>
                    <span className="text-[10px] text-[var(--muted)]">{total} items</span>
                  </div>
                  <div className="flex h-3 rounded overflow-hidden bg-[#0e0e14]">
                    {Object.entries(labels).sort((a, b) => b[1] - a[1]).map(([label, n]) => (
                      <div
                        key={label}
                        className={`${labelColor[label] || 'bg-zinc-500/40'}`}
                        style={{ width: `${(n / total) * 100}%` }}
                        title={`${label}: ${n}`}
                      />
                    ))}
                  </div>
                </div>
              )
            })}
            <div className="flex flex-wrap gap-3 pt-2 mt-2 border-t border-[var(--border)] text-[10px] text-[var(--muted)]">
              {Object.entries(labelColor).map(([label, color]) => (
                <div key={label} className="flex items-center gap-1">
                  <div className={`w-2.5 h-2.5 rounded ${color}`} />
                  <span>{label.replace('_', ' ')}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Data correlation graph — mermaid diagram showing how sensitive data
          moves between providers, owners, and external endpoints. */}
      <DataCorrelationGraph items={visible} />

      {visible.length === 0 && (
        <div className="bg-[#0e0e14] border border-dashed border-[var(--border)] rounded-xl p-8 text-center text-[12px] text-[var(--muted)]">
          DSPM Insights derive from your live inventory. Connect more providers (SharePoint,
          OneDrive, Databricks, AWS, GCP) and run a scan to populate this view.
        </div>
      )}
      {summary && summary.total > 0 && summary.total < 25 && (
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 text-[12px] text-blue-300 flex items-start gap-2">
          <Info size={13} className="mt-0.5 flex-shrink-0" />
          <span>Sample size is small ({summary.total} items). Insights will get more useful as more providers are connected and scans complete.</span>
        </div>
      )}

      {/* Adnan 2026-06-23 (turn 2): three new DSPM panels powered by
          backend services added the same day — stale data lifecycle,
          permission/ACL diffs, and GenAI shadow-IT discovery. Each is
          a self-contained tile so individual panels can fail without
          taking down the others. */}
      <StaleDataPanel />
      <PermissionDiffsPanel />
      <GenAIShadowITPanel />
    </div>
  )
}

// ── StaleDataPanel ──────────────────────────────────────────────────
function StaleDataPanel() {
  type Item = {
    id: string; table: string; supports_delete: boolean; name?: string;
    label: string; last_modified?: string; days_stale: number;
    url?: string; owner?: string; provider: string;
  }
  const [items, setItems] = useState<Item[]>([])
  const [summary, setSummary] = useState<{ total: number; by_provider: Record<string, number> } | null>(null)
  const [loading, setLoading] = useState(true)
  const [running, setRunning] = useState(false)
  const [resultMsg, setResultMsg] = useState<string | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [s, l] = await Promise.all([
        api.get('/api/data-lifecycle/summary'),
        api.get('/api/data-lifecycle/stale?limit=50'),
      ])
      setSummary(s.data)
      setItems(l.data.items || [])
    } catch (e) {
      console.warn('stale data load failed', e)
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => { load() }, [load])

  const toggle = (id: string) => {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id); else next.add(id)
    setSelected(next)
  }

  const bulkAction = async (action: string, dryRun: boolean) => {
    if (selected.size === 0) return
    setRunning(true); setResultMsg(null)
    try {
      const r = await api.post('/api/data-lifecycle/stale/bulk-action', {
        resource_ids: Array.from(selected),
        action, dry_run: dryRun,
        reason: 'stale_confidential_cleanup',
      })
      const { ok, tagged_for_review, error } = r.data.summary || {}
      setResultMsg(
        `${dryRun ? 'Dry run: ' : ''}${ok || 0} actioned · ${tagged_for_review || 0} tagged for owner review · ${error || 0} errors`,
      )
      if (!dryRun) { setSelected(new Set()); await load() }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setResultMsg(`Failed: ${msg}`)
    } finally {
      setRunning(false)
    }
  }

  return (
    <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Clock size={14} className="text-amber-400" />
        <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Stale Sensitive Data (data minimisation)</h3>
        <span className="text-[10px] text-[var(--muted)] ml-auto">
          {loading ? 'loading…' : `${summary?.total ?? 0} candidates across ${Object.keys(summary?.by_provider || {}).length} connectors`}
        </span>
      </div>
      <p className="text-[11px] text-[var(--muted)] mb-3">
        Confidential resources untouched for 365+ days across every connected source. GDPR / PDPL / HIPAA all
        require justification for retaining sensitive data past business need — archive, delete, or tag for owner review.
      </p>
      {loading ? (
        <div className="text-[11px] text-[var(--muted)]">Loading…</div>
      ) : items.length === 0 ? (
        <div className="text-[11px] text-emerald-400/80">No stale confidential data — your retention hygiene is clean.</div>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-[var(--border)] mb-3">
            <table className="w-full text-[11px]">
              <thead className="bg-[#0e0e14] text-[var(--muted)]">
                <tr>
                  <th className="text-left px-3 py-2 w-8">
                    <input
                      type="checkbox"
                      checked={selected.size === items.length}
                      onChange={() => setSelected(selected.size === items.length ? new Set() : new Set(items.map(i => i.id)))}
                    />
                  </th>
                  <th className="text-left px-3 py-2">Name</th>
                  <th className="text-left px-3 py-2">Provider</th>
                  <th className="text-left px-3 py-2">Label</th>
                  <th className="text-right px-3 py-2">Days stale</th>
                </tr>
              </thead>
              <tbody>
                {items.slice(0, 12).map(it => (
                  <tr key={it.id} className="border-t border-[var(--border)]">
                    <td className="px-3 py-1.5">
                      <input type="checkbox" checked={selected.has(it.id)} onChange={() => toggle(it.id)} />
                    </td>
                    <td className="px-3 py-1.5 text-[var(--foreground)]">{it.name || it.id.slice(0, 12)}</td>
                    <td className="px-3 py-1.5 text-[var(--muted)]">{it.provider}</td>
                    <td className="px-3 py-1.5 text-amber-400">{it.label.replace('_', ' ')}</td>
                    <td className="px-3 py-1.5 text-right text-red-400">{it.days_stale}d</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="ghost" disabled={running || selected.size === 0} onClick={() => bulkAction('tag_for_review', true)}>
              Dry run — tag {selected.size || ''} for owner review
            </Button>
            <Button size="sm" disabled={running || selected.size === 0} onClick={() => bulkAction('tag_for_review', false)}>
              {running ? 'Running…' : 'Apply — tag for owner review'}
            </Button>
            {resultMsg && <span className="text-[10px] text-[var(--muted)] ml-2">{resultMsg}</span>}
          </div>
        </>
      )}
    </div>
  )
}

// ── PermissionDiffsPanel ─────────────────────────────────────────────
function PermissionDiffsPanel() {
  type Diff = {
    resource_id: string; table: string; name?: string; field: string;
    before: unknown; after: unknown; severity: string;
    rollback_hint: string; snapshot_at?: string;
  }
  const [diffs, setDiffs] = useState<Diff[]>([])
  const [bySev, setBySev] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)
  const [snapshotting, setSnapshotting] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await api.get('/api/permission-diff?since_hours=24')
      setDiffs(r.data.items || [])
      setBySev(r.data.by_severity || {})
    } catch (e) {
      console.warn('permission diff load failed', e)
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => { load() }, [load])

  const sevColor = (s: string) => s === 'critical' ? 'text-red-400'
    : s === 'high' ? 'text-orange-400'
    : s === 'medium' ? 'text-amber-400' : 'text-emerald-400'

  const recompute = async () => {
    setSnapshotting(true)
    try { await api.post('/api/permission-diff/snapshot'); await load() }
    catch (e) { console.warn(e) }
    finally { setSnapshotting(false) }
  }

  return (
    <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Activity size={14} className="text-[#3b6ef6]" />
        <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Permission Changes (last 24h)</h3>
        <span className="text-[10px] text-[var(--muted)] ml-auto">
          {loading ? 'loading…' : `${bySev.critical || 0} critical · ${bySev.high || 0} high · ${bySev.medium || 0} medium`}
        </span>
        <button onClick={recompute} disabled={snapshotting} className="text-[10px] px-2 py-1 rounded border border-[var(--border)] text-[var(--muted)] hover:bg-[#1a1a22] disabled:opacity-50">
          {snapshotting ? 'Snapshotting…' : 'Take baseline snapshot'}
        </button>
      </div>
      <p className="text-[11px] text-[var(--muted)] mb-3">
        Daily snapshot diff of ACL / encryption / sharing-scope fields across every connector. A bucket flipping public,
        encryption being disabled, or a SharePoint file moving from private to public will show up here.
      </p>
      {loading ? (
        <div className="text-[11px] text-[var(--muted)]">Loading…</div>
      ) : diffs.length === 0 ? (
        <div className="text-[11px] text-emerald-400/80">No permission changes detected in the last 24h.</div>
      ) : (
        <div className="divide-y divide-[var(--border)]">
          {diffs.slice(0, 10).map(d => (
            <div key={`${d.resource_id}-${d.field}`} className="py-2 flex items-start gap-3">
              <span className={`text-[9px] uppercase tracking-wide font-semibold ${sevColor(d.severity)} min-w-[60px]`}>
                {d.severity}
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-[11px] text-[var(--foreground)] font-medium truncate">
                  {d.name || d.resource_id.slice(0, 12)}
                </div>
                <div className="text-[10px] text-[var(--muted)]">
                  {d.table} · <span className="text-amber-300">{d.field}</span> changed{' '}
                  <code className="bg-[#0e0e14] px-1 rounded text-[var(--muted)]">{String(d.before)}</code>{' '}→{' '}
                  <code className="bg-[#0e0e14] px-1 rounded text-red-300">{String(d.after)}</code>
                </div>
                <div className="text-[10px] text-[var(--muted)] mt-1">
                  <span className="text-emerald-300">Rollback:</span> <code className="break-all">{d.rollback_hint}</code>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── GenAIShadowITPanel ──────────────────────────────────────────────
function GenAIShadowITPanel() {
  type Finding = {
    vendor_id: string; vendor: string; category: string;
    risk: string; sources: string[]; evidence_count: number;
    unique_users: number;
  }
  const [items, setItems] = useState<Finding[]>([])
  const [byRisk, setByRisk] = useState<Record<string, number>>({})
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    (async () => {
      try {
        const r = await api.get('/api/genai-shadow-it')
        setItems(r.data.items || [])
        setByRisk(r.data.by_risk || {})
      } catch (e) {
        console.warn('genai shadow IT load failed', e)
      } finally {
        setLoading(false)
      }
    })()
  }, [])

  const riskColor = (r: string) => r === 'high' ? 'text-red-400'
    : r === 'medium' ? 'text-amber-400' : 'text-emerald-400'

  return (
    <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Sparkles size={14} className="text-violet-400" />
        <h3 className="text-[13px] font-semibold text-[var(--foreground)]">GenAI Shadow IT</h3>
        <span className="text-[10px] text-[var(--muted)] ml-auto">
          {loading ? 'loading…' : `${items.length} vendors · ${byRisk.high || 0} high risk`}
        </span>
      </div>
      <p className="text-[11px] text-[var(--muted)] mb-3">
        Where your organisation's data may be flowing to ChatGPT, Gemini, Copilot, Cursor, Codeium, Perplexity
        and 20+ other GenAI vendors. Discovered passively from M365 OAuth grants, Teams apps, SaaS item URLs,
        GitHub findings, and audit-log egress.
      </p>
      {loading ? (
        <div className="text-[11px] text-[var(--muted)]">Loading…</div>
      ) : items.length === 0 ? (
        <div className="text-[11px] text-emerald-400/80">No GenAI usage detected from the signals we can see today.</div>
      ) : (
        <div className="divide-y divide-[var(--border)]">
          {items.slice(0, 12).map(it => (
            <div key={it.vendor_id} className="py-2 flex items-start gap-3">
              <span className={`text-[9px] uppercase tracking-wide font-semibold ${riskColor(it.risk)} min-w-[60px]`}>
                {it.risk}
              </span>
              <div className="flex-1 min-w-0">
                <div className="text-[11px] text-[var(--foreground)] font-medium">{it.vendor}</div>
                <div className="text-[10px] text-[var(--muted)]">
                  {it.category} · {it.evidence_count} signals · {it.unique_users} unique users · sources: {it.sources.join(', ')}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── PostureTab ─────────────────────────────────────────────────────────────────

function PostureTab({
  checks, summary, loading, onRunCheck, running,
}: {
  checks: Record<string, PostureCheck[]>
  summary: PostureSummary | null
  loading: boolean
  onRunCheck: () => void
  running: boolean
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  // Adnan: posture should be searchable + filtered to AI-driven static
  // posture checks (NIST / CIS / vendor baselines), not admin actions.
  const [search, setSearch] = useState<string>('')
  const [providerFilter, setProviderFilter] = useState<string>('')

  // Exclude any checks that are really admin-action audit entries
  // (different table, different intent). Posture = "is this configured
  // correctly" not "did someone do something".
  const isAdminActionCheck = (c: PostureCheck) => {
    const id = (c.id || '').toLowerCase()
    const cat = (c.check_category || '').toLowerCase()
    const name = (c.check_name || '').toLowerCase()
    return (
      cat.includes('admin action') || cat.includes('admin-action') ||
      id.startsWith('admin_action') || id.startsWith('audit_event') ||
      name.startsWith('admin action:') || name.startsWith('action:')
    )
  }

  const matchesSearch = (c: PostureCheck) => {
    if (!search.trim()) return true
    const q = search.trim().toLowerCase()
    return (
      (c.check_name || '').toLowerCase().includes(q) ||
      (c.id || '').toLowerCase().includes(q) ||
      (c.description || '').toLowerCase().includes(q) ||
      (c.check_category || '').toLowerCase().includes(q) ||
      (c.provider || '').toLowerCase().includes(q)
    )
  }
  const matchesProvider = (c: PostureCheck) => {
    if (!providerFilter) return true
    return (c.provider || '').toLowerCase() === providerFilter.toLowerCase()
  }

  // Apply filters to the grouped checks map.
  const filteredChecks: Record<string, PostureCheck[]> = {}
  for (const [cat, items] of Object.entries(checks)) {
    const kept = items.filter(c => !isAdminActionCheck(c) && matchesSearch(c) && matchesProvider(c))
    if (kept.length > 0) filteredChecks[cat] = kept
  }

  // Discover available providers from the data so the dropdown only
  // shows what is actually connected.
  const availableProviders = Array.from(new Set(
    Object.values(checks).flat().map(c => (c.provider || '').toLowerCase()).filter(Boolean)
  )).sort()

  const toggleExpand = (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const passCount = summary?.by_status?.pass ?? 0
  const failCount = summary?.by_status?.fail ?? 0
  const warnCount = summary?.by_status?.warning ?? 0
  const totalChecks = passCount + failCount + warnCount
  const postureScore = totalChecks > 0
    ? Math.round(((passCount * 1.0 + warnCount * 0.5) / totalChecks) * 100)
    : null
  const postureColor = postureScore == null ? 'text-slate-400'
    : postureScore >= 80 ? 'text-emerald-400'
    : postureScore >= 50 ? 'text-amber-400'
    : 'text-red-400'
  const postureLabel = postureScore == null ? 'N/A'
    : postureScore >= 80 ? 'Good'
    : postureScore >= 50 ? 'Fair'
    : 'At Risk'

  const highFails = summary?.by_severity?.high ?? 0
  const critFails = summary?.by_severity?.critical ?? 0

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-3">
        <div className="bg-[#111114] border border-[#1e1e24] rounded-xl p-4 flex flex-col items-center justify-center">
          <div className={`text-3xl font-bold ${postureColor}`}>{postureScore ?? '—'}</div>
          <div className="text-[11px] text-[#71717a] mt-1">Posture Score</div>
          {postureLabel !== 'N/A' && (
            <div className={`text-[10px] font-semibold mt-1 px-2 py-0.5 rounded-full border ${
              postureScore! >= 80 ? 'bg-emerald-900/30 text-emerald-300 border-emerald-700/40'
              : postureScore! >= 50 ? 'bg-amber-900/30 text-amber-300 border-amber-700/40'
              : 'bg-red-900/30 text-red-300 border-red-700/40'
            }`}>{postureLabel}</div>
          )}
        </div>
        <StatCard label="Pass" value={passCount} color="text-emerald-400" />
        <StatCard label="Fail" value={failCount} color="text-red-400"
          sub={highFails + critFails > 0 ? `${highFails + critFails} high/critical` : undefined} />
        <StatCard label="Warning" value={warnCount} color="text-amber-400" />
      </div>

      <div className="flex justify-end">
        <Button size="sm" onClick={onRunCheck} disabled={running}>
          {running ? <RefreshCw size={13} className="mr-1 animate-spin" /> : <ShieldCheck size={13} className="mr-1" />}
          Run Posture Check
        </Button>
      </div>

      {/* Source/Provider Summary Banner */}
      {!loading && Object.keys(checks).length > 0 && (() => {
        // Aggregate by provider from all checks
        const allChecks = Object.values(checks).flat();
        const providerGroups: Record<string, { pass: number; fail: number; warn: number }> = {};
        allChecks.forEach(c => {
          const p = c.provider || 'unknown';
          if (!providerGroups[p]) providerGroups[p] = { pass: 0, fail: 0, warn: 0 };
          if (c.status === 'pass') providerGroups[p].pass++;
          else if (c.status === 'fail') providerGroups[p].fail++;
          else providerGroups[p].warn++;
        });
        const providerMeta: Record<string, { label: string; color: string }> = {
          aws: { label: 'AWS', color: '#FF9900' },
          m365: { label: 'M365', color: '#0078d4' },
          teams: { label: 'Teams', color: '#5558AF' },
          sharepoint: { label: 'SharePoint', color: '#038387' },
          sap: { label: 'SAP', color: '#0FAAFF' },
          databricks: { label: 'Databricks', color: '#FF3621' },
          google: { label: 'Google', color: '#4285F4' },
        };
        return (
          <div className="bg-[#0f0f12] border border-[#1e1e24] rounded-xl p-4">
            <div className="text-[11px] text-[#71717a] uppercase tracking-wide mb-3">Checks by Source</div>
            <div className="flex flex-wrap gap-3">
              {Object.entries(providerGroups).map(([provider, stats]) => {
                const meta = providerMeta[provider] || { label: provider.toUpperCase(), color: '#71717a' };
                const total = stats.pass + stats.fail + stats.warn;
                const score = total > 0 ? Math.round(((stats.pass + stats.warn * 0.5) / total) * 100) : 0;
                return (
                  <div key={provider} className="flex items-center gap-3 bg-white/[0.02] rounded-lg px-3 py-2.5 border border-white/[0.04]">
                    <div className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: meta.color }} />
                      <span className="text-[12px] font-semibold text-[var(--foreground)]">{meta.label}</span>
                    </div>
                    <div className="h-4 w-px bg-white/10" />
                    <div className="text-[11px] text-[var(--muted)]"><span className="text-emerald-400 font-semibold">{stats.pass}</span> pass</div>
                    <div className="text-[11px] text-[var(--muted)]"><span className="text-red-400 font-semibold">{stats.fail}</span> fail</div>
                    {stats.warn > 0 && <div className="text-[11px] text-[var(--muted)]"><span className="text-amber-400 font-semibold">{stats.warn}</span> warn</div>}
                    <div className="h-1.5 w-16 bg-white/[0.06] rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${score}%`, backgroundColor: meta.color }} />
                    </div>
                    <span className="text-[10px] font-semibold" style={{ color: meta.color }}>{score}%</span>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {/* Search + provider filter */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search posture checks (name, ID, category, provider)…"
            className="w-full pl-8 pr-3 py-1.5 bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg outline-none focus:border-[#3b6ef6]"
          />
        </div>
        <select
          value={providerFilter}
          onChange={e => setProviderFilter(e.target.value)}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
        >
          <option value="">All Providers</option>
          {availableProviders.map(p => (
            <option key={p} value={p}>{p}</option>
          ))}
        </select>
      </div>

      {loading ? (
        <div className="text-center py-16 text-[#52525b]">Loading posture checks…</div>
      ) : Object.keys(filteredChecks).length === 0 ? (
        <div className="text-center py-16 space-y-2">
          <ShieldCheck size={32} className="mx-auto text-[#3b6ef6]/40" />
          <div className="text-[#52525b] text-sm">
            {Object.keys(checks).length === 0
              ? 'No posture checks yet. Connect a provider and run a check.'
              : 'No posture checks match your filters.'}
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {Object.entries(filteredChecks).map(([category, categoryChecks]) => (
            <div key={category} className="bg-[#111114] border border-[#1e1e24] rounded-xl overflow-hidden">
              <div className="px-4 py-2.5 bg-[#0f0f12] border-b border-[#1e1e24] text-[12px] font-semibold text-[#a1a1aa] uppercase tracking-wide">
                {category}
              </div>
              <div className="divide-y divide-[#1e1e24]">
                {categoryChecks.filter(c => c.status !== 'unknown').concat(categoryChecks.filter(c => c.status === 'unknown')).map(check => {
                  const isUnknown = check.status === 'unknown'
                  const ev = check.evidence ?? {}
                  // Build evidence display lines
                  const evLines = Object.entries(ev)
                    .filter(([k]) => !k.includes('_count') || true)
                    .slice(0, 6)
                    .map(([k, v]) => `${k.replace(/_/g,' ')}: ${JSON.stringify(v)}`)
                  return (
                  <div key={check.id} className={`px-4 py-3 space-y-1.5 ${isUnknown ? 'opacity-50' : ''}`}>
                    <div className="flex items-center gap-3">
                      {POSTURE_ICON[check.status]}
                      <div className="flex-1 min-w-0">
                        <span className="text-[13px] text-[#e4e4e7] font-medium">{check.check_name}</span>
                        {isUnknown && <span className="ml-2 text-[10px] text-[#52525b] bg-[#1e1e24] px-1.5 py-0.5 rounded">requires premium license</span>}
                      </div>
                      <SevBadge level={check.severity} />
                      <ProviderBadge provider={check.provider} />
                      {!isUnknown && (
                        <button onClick={() => toggleExpand(check.id)} className="text-[#52525b] hover:text-[#a1a1aa]">
                          {expanded.has(check.id) ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                        </button>
                      )}
                    </div>
                    <p className={`text-[12px] ${isUnknown ? 'text-[#52525b]' : 'text-[#71717a]'}`}>{check.description}</p>
                    {/* Evidence from tenant — actual control state */}
                    {!isUnknown && evLines.length > 0 && (
                      <div className="flex flex-wrap gap-x-4 gap-y-0.5">
                        {evLines.map((line, i) => (
                          <span key={i} className="text-[11px] font-mono text-[#52525b]">{line}</span>
                        ))}
                      </div>
                    )}
                    {expanded.has(check.id) && !isUnknown && (
                      <div className="mt-2 space-y-2 pl-4 border-l-2 border-[#1e1e24]">
                        {check.recommendation && (
                          <div className="text-[12px] text-[#a1a1aa]">
                            <span className="font-semibold text-[#3b6ef6]">Recommendation: </span>
                            {check.recommendation}
                          </div>
                        )}
                        {check.remediation_steps.length > 0 && (
                          <div>
                            <div className="text-[11px] text-[#52525b] mb-1 font-semibold uppercase tracking-wide">How to fix</div>
                            <ol className="space-y-0.5">
                              {check.remediation_steps.map((step, i) => (
                                <li key={i} className="text-[11px] text-[#71717a] flex gap-2">
                                  <span className="text-[#3b6ef6] font-semibold">{i + 1}.</span> {step}
                                </li>
                              ))}
                            </ol>
                          </div>
                        )}
                        {check.last_checked_at && (
                          <div className="text-[11px] text-[#52525b]">Verified: {fmtDate(check.last_checked_at)}</div>
                        )}
                      </div>
                    )}
                  </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function SaasSecurityPage() {
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  // Connectors
  const [integrations, setIntegrations] = useState<SaasIntegration[]>([])
  const [integrationsLoading, setIntegrationsLoading] = useState(true)
  const [connecting, setConnecting] = useState<string | null>(null)
  const [m365Connected, setM365Connected] = useState(false)
  const [canAutoConnect, setCanAutoConnect] = useState(false)

  // Alerts
  const [alerts, setAlerts] = useState<SaasAlert[]>([])
  const [alertsTotal, setAlertsTotal] = useState(0)
  const [alertsLoading, setAlertsLoading] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [selectedAlert, setSelectedAlert] = useState<SaasAlert | null>(null)
  const [filterSev, setFilterSev] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterProvider, setFilterProvider] = useState('')
  const [alertPage, setAlertPage] = useState(1)
  const [updatingAlert, setUpdatingAlert] = useState(false)

  // Data
  const [dataItems, setDataItems] = useState<DataItem[]>([])
  const [dataTotal, setDataTotal] = useState(0)
  const [dataLoading, setDataLoading] = useState(false)
  const [dataSummary, setDataSummary] = useState<DataSummary | null>(null)
  const [dataFilterProvider, setDataFilterProvider] = useState('')
  const [dataFilterLabel, setDataFilterLabel] = useState('')
  const [dataFilterScope, setDataFilterScope] = useState('')
  const [dataPage, setDataPage] = useState(1)

  // Posture
  const [postureChecks, setPostureChecks] = useState<Record<string, PostureCheck[]>>({})
  const [postureSummary, setPostureSummary] = useState<PostureSummary | null>(null)
  const [postureLoading, setPostureLoading] = useState(false)
  const [runningPosture, setRunningPosture] = useState(false)

  const [error, setError] = useState<string | null>(null)

  // ── Loaders ────────────────────────────────────────────────────────────────

  const loadIntegrations = useCallback(async () => {
    try {
      setIntegrationsLoading(true)
      const r = await api.get('/api/saas/integrations')
      // New API shape: { integrations, m365_connected, can_auto_connect }
      const data = r.data
      if (Array.isArray(data)) {
        // Legacy shape
        setIntegrations(data)
      } else {
        setIntegrations(data?.integrations ?? [])
        setM365Connected(data?.m365_connected ?? false)
        setCanAutoConnect(data?.can_auto_connect ?? false)
      }
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      if (msg?.includes('Enterprise')) {
        setError('SaaS Security requires an Enterprise plan.')
      }
    } finally {
      setIntegrationsLoading(false)
    }
  }, [])

  const loadAlerts = useCallback(async () => {
    try {
      setAlertsLoading(true)
      const params = new URLSearchParams({ page: String(alertPage), page_size: '20' })
      if (filterSev) params.set('severity', filterSev)
      if (filterStatus) params.set('status', filterStatus)
      if (filterProvider) params.set('provider', filterProvider)
      const r = await api.get(`/api/saas/alerts?${params}`)
      setAlerts(r.data?.items ?? [])
      setAlertsTotal(r.data?.total ?? 0)
    } catch { /* ignore */ }
    finally { setAlertsLoading(false) }
  }, [alertPage, filterSev, filterStatus, filterProvider])

  const loadData = useCallback(async () => {
    try {
      setDataLoading(true)
      const params = new URLSearchParams({ page: String(dataPage), page_size: '20' })
      if (dataFilterProvider) params.set('provider', dataFilterProvider)
      if (dataFilterLabel) params.set('classification_label', dataFilterLabel)
      if (dataFilterScope) params.set('sharing_scope', dataFilterScope)
      const [r, s] = await Promise.all([
        api.get(`/api/saas/data?${params}`),
        api.get('/api/saas/data/summary'),
      ])
      setDataItems(r.data?.items ?? [])
      setDataTotal(r.data?.total ?? 0)
      setDataSummary(s.data)
    } catch { /* ignore */ }
    finally { setDataLoading(false) }
  }, [dataPage, dataFilterProvider, dataFilterLabel, dataFilterScope])

  const loadPosture = useCallback(async () => {
    try {
      setPostureLoading(true)
      const [r, s] = await Promise.all([
        api.get('/api/saas/posture'),
        api.get('/api/saas/posture/summary'),
      ])
      setPostureChecks(r.data?.checks ?? {})
      setPostureSummary(s.data)
    } catch { /* ignore */ }
    finally { setPostureLoading(false) }
  }, [])

  // Initial load
  useEffect(() => { loadIntegrations() }, [loadIntegrations])

  // Tab-aware load
  useEffect(() => {
    if (activeTab === 'alerts') loadAlerts()
  }, [activeTab, loadAlerts])
  useEffect(() => { if (activeTab === 'data') loadData() }, [activeTab, loadData])
  useEffect(() => { if (activeTab === 'posture') loadPosture() }, [activeTab, loadPosture])

  // Handle redirect back after OAuth
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const connected = params.get('connected')
    const consentGranted = params.get('consent_granted')
    const err = params.get('error')
    if (connected) {
      loadIntegrations()
      window.history.replaceState({}, '', window.location.pathname)
    }
    if (consentGranted) {
      // Admin consent was just granted — switch to connectors tab and show success
      setActiveTab('connectors')
      window.history.replaceState({}, '', window.location.pathname)
    }
    if (err) {
      if (err === 'consent_denied') {
        setError('Admin consent was not granted. Please click "Grant Admin Consent" and approve the permissions.')
      } else {
        setError(`Connection error: ${err}`)
      }
      window.history.replaceState({}, '', window.location.pathname)
    }
  }, [loadIntegrations])

  // ── Handlers ───────────────────────────────────────────────────────────────

  const handleConnect = async (provider: 'teams' | 'sharepoint') => {
    try {
      setConnecting(provider)
      // tenant_id resolved server-side from the org's existing M365 integration
      await api.post('/api/saas/connect-from-m365', { provider })
      loadIntegrations()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to connect. Grant admin consent first then try again.')
    } finally {
      setConnecting(null)
    }
  }

  const handleDisconnect = async (provider: string) => {
    try {
      await api.delete(`/api/saas/integrations/${provider}`)
      loadIntegrations()
    } catch {
      setError('Failed to disconnect.')
    }
  }

  const handleRunScan = async () => {
    try {
      setScanning(true)
      await api.post('/api/saas/alerts/scan')
      setTimeout(() => {
        loadAlerts()
        setScanning(false)
      }, 3000)
    } catch {
      setScanning(false)
    }
  }

  const handleSelectAlert = (a: SaasAlert) => {
    setSelectedAlert(a)
  }

  const handleCloseAlert = () => {
    setSelectedAlert(null)
  }

  const handleUpdateAlertStatus = async (id: string, status: string) => {
    try {
      setUpdatingAlert(true)
      const r = await api.patch(`/api/saas/alerts/${id}`, { status })
      setSelectedAlert(r.data)
      loadAlerts()
    } catch {
      setError('Failed to update alert status.')
    } finally {
      setUpdatingAlert(false)
    }
  }

  const handleRunPosture = async () => {
    try {
      setRunningPosture(true)
      await api.post('/api/saas/posture/run')
      setTimeout(() => {
        loadPosture()
        setRunningPosture(false)
      }, 4000)
    } catch {
      setRunningPosture(false)
    }
  }

  const handleAutoConnect = async () => {
    try {
      await api.post('/api/saas/auto-connect')
      loadIntegrations()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setError(msg || 'Failed to auto-connect. Ensure admin consent has been granted for Helios SaaS Security.')
    }
  }

  // ── Tab config ─────────────────────────────────────────────────────────────

  const tabs: Array<{ id: Tab; label: string; icon: React.ReactNode }> = [
    { id: 'overview', label: 'Overview', icon: <BarChart3 size={13} /> },
    { id: 'alerts', label: 'Alerts', icon: <ShieldAlert size={13} /> },
    { id: 'data', label: 'Data Security Posture', icon: <Database size={13} /> },
    { id: 'governance', label: 'Governance', icon: <Building2 size={13} /> },
    { id: 'attack-chain', label: 'Attack Chain', icon: <Network size={13} /> },
    { id: 'user-risk', label: 'User Risk', icon: <Users size={13} /> },
    { id: 'compliance', label: 'Compliance', icon: <CheckCircle2 size={13} /> },
    { id: 'posture', label: 'Posture', icon: <ShieldCheck size={13} /> },
    { id: 'admin-actions', label: 'Admin Actions', icon: <Shield size={13} /> },
    { id: 'connectors', label: 'Connectors', icon: <Plug size={13} /> },
  ]

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-[var(--background)]">
      {/* Page header */}
      <div className="flex-shrink-0 px-6 pt-6 pb-4 border-b border-[var(--border)]">
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Workspace Security</h1>
      </div>

      {/* Error banner */}
      {error && (
        <div className="mx-6 mt-4 bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3 text-[12px] text-red-400 flex items-center justify-between">
          {error}
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">✕</button>
        </div>
      )}

      {/* Tabs */}
      <div className="flex-shrink-0 px-6 pt-4">
        <div className="flex gap-1 border-b border-[var(--border)]">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-[#3b6ef6] text-[#3b6ef6]'
                  : 'border-transparent text-[var(--muted)] hover:text-[var(--foreground)]'
              }`}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {activeTab === 'overview' && (
          <WorkspaceOverviewTab />
        )}
        {activeTab === 'connectors' && (
          <ConnectorsTab
            integrations={integrations}
            loading={integrationsLoading}
            onConnect={handleConnect}
            onDisconnect={handleDisconnect}
            connecting={connecting}
            m365Connected={m365Connected}
            canAutoConnect={canAutoConnect}
            onAutoConnect={handleAutoConnect}
          />
        )}
        {activeTab === 'alerts' && (
          <AlertsTab
            alerts={alerts}
            total={alertsTotal}
            loading={alertsLoading}
            scanning={scanning}
            onRunScan={handleRunScan}
            onSelectAlert={handleSelectAlert}
            selectedAlert={selectedAlert}
            onCloseAlert={handleCloseAlert}
            onUpdateAlertStatus={handleUpdateAlertStatus}
            updatingAlert={updatingAlert}
            filterSev={filterSev}
            setFilterSev={setFilterSev}
            filterStatus={filterStatus}
            setFilterStatus={setFilterStatus}
            filterProvider={filterProvider}
            setFilterProvider={setFilterProvider}
            page={alertPage}
            setPage={setAlertPage}
          />
        )}
        {activeTab === 'data' && (
          <DataTab
            items={dataItems}
            summary={dataSummary}
            total={dataTotal}
            loading={dataLoading}
            filterProvider={dataFilterProvider}
            setFilterProvider={setDataFilterProvider}
            filterLabel={dataFilterLabel}
            setFilterLabel={setDataFilterLabel}
            filterScope={dataFilterScope}
            setFilterScope={setDataFilterScope}
            page={dataPage}
            setPage={setDataPage}
          />
        )}
        {activeTab === 'posture' && (
          <PostureTab
            checks={postureChecks}
            summary={postureSummary}
            loading={postureLoading}
            onRunCheck={handleRunPosture}
            running={runningPosture}
          />
        )}
        {activeTab === 'admin-actions' && <AdminActionsTab />}
        {activeTab === 'attack-chain' && <AttackChainTab />}
        {activeTab === 'user-risk' && <UserRiskScoresTab />}
        {activeTab === 'compliance' && <ComplianceTab />}
        {activeTab === 'governance' && <GovernanceTab />}

      </div>
    </div>
  )
}

// ── Admin Actions Tab ─────────────────────────────────────────────────────────

function AdminActionsTab() {
  const [actions, setActions] = useState<Array<{
    id: string; admin_email: string; action_type: string; target_type?: string;
    target_id?: string; target_name?: string; details?: Record<string, unknown>;
    provider: string; created_at?: string;
  }>>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>('');
  const [permissionError, setPermissionError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionDetail, setActionDetail] = useState<{
    id: string; ip_address?: string; geo_info?: {
      city?: string; region?: string; country?: string; country_name?: string;
      lat?: number; lng?: number; org?: string; timezone?: string;
    }; details?: Record<string, unknown>;
  } | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const params = filter ? `?action_type=${filter}` : '';
        const { data } = await api.get(`/api/saas/admin-actions${params}`);
        setActions(data.actions || []);
        if (data.permission_error) {
          setPermissionError(data.permission_error);
        } else {
          setPermissionError(null);
        }
      } catch (err: unknown) {
        const anyErr = err as { response?: { status?: number } };
        if (anyErr?.response?.status === 403) {
          setPermissionError('Admin audit logs require AuditLog.Read.All permission. Please re-authorize with additional permissions.');
        }
      }
      setLoading(false);
    })();
  }, [filter]);

  const actionColors: Record<string, string> = {
    user_deleted: 'bg-red-500/10 border-red-500/20 text-red-400',
    role_assigned: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
    permission_changed: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
    policy_modified: 'bg-purple-500/10 border-purple-500/20 text-purple-400',
    app_consent_granted: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
    default: 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400',
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-[14px] font-semibold text-[var(--foreground)]">Admin Actions</h2>
        <select
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="text-[11px] bg-[var(--input)] border border-[var(--border)] rounded px-2 py-1 text-[var(--foreground)]"
        >
          <option value="">All actions</option>
          <option value="user_deleted">User Deleted</option>
          <option value="role_assigned">Role Assigned</option>
          <option value="permission_changed">Permission Changed</option>
          <option value="policy_modified">Policy Modified</option>
          <option value="app_consent_granted">App Consent Granted</option>
        </select>
      </div>
      {permissionError && (
        <div className="flex items-start gap-3 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30">
          <AlertTriangle size={16} className="text-amber-400 mt-0.5 flex-shrink-0" />
          <div>
            <div className="text-[12px] font-semibold text-amber-400 mb-1">Permission Required</div>
            <div className="text-[11px] text-amber-300/80">{permissionError}</div>
          </div>
        </div>
      )}
      {loading ? (
        <div className="text-center py-8 text-[var(--muted)] text-[12px]">Loading admin actions...</div>
      ) : actions.length === 0 ? (
        <div className="text-center py-12 text-[var(--muted)] text-[12px]">
          <Shield size={32} className="mx-auto mb-2 text-[var(--muted)]" />
          No admin actions recorded yet. Actions will appear here as admins perform privileged operations.
          {!permissionError && (
            <div className="mt-3 text-[10px] text-[var(--muted)]/60">
              Note: Requires <code className="bg-white/5 px-1 rounded">AuditLog.Read.All</code> permission in your Microsoft 365 app registration.
            </div>
          )}
        </div>
      ) : (
        <div className="overflow-auto rounded-xl border border-[var(--border)]">
          <Table>
            <Thead>
              <Tr>
                <Th>Admin</Th>
                <Th>Action</Th>
                <Th>Target</Th>
                <Th>Provider</Th>
                <Th>Details</Th>
                <Th>Time</Th>
              </Tr>
            </Thead>
            <Tbody>
              {actions.map(action => (
                <React.Fragment key={action.id}>
                  <Tr 
                    className="cursor-pointer hover:bg-white/5 transition-colors"
                    onClick={async () => {
                      if (expandedId === action.id) {
                        setExpandedId(null);
                        setActionDetail(null);
                      } else {
                        setExpandedId(action.id);
                        setDetailLoading(true);
                        try {
                          const { data } = await api.get(`/api/saas/admin-actions/${action.id}`);
                          setActionDetail(data);
                        } catch { setActionDetail(null); }
                        setDetailLoading(false);
                      }
                    }}
                  >
                    <Td>
                      <div className="flex items-center gap-2">
                        <Shield size={14} className="text-amber-400" />
                        <span className="font-medium text-[12px]">{action.admin_email}</span>
                      </div>
                    </Td>
                    <Td>
                      <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-semibold border ${actionColors[action.action_type] || actionColors.default}`}>
                        {action.action_type.replace(/_/g, ' ')}
                      </span>
                    </Td>
                    <Td>
                      <div className="text-[12px]">
                        {action.target_name || action.target_id || '—'}
                        {action.target_type && (
                          <span className="text-[10px] text-[var(--muted)] ml-1">({action.target_type})</span>
                        )}
                      </div>
                    </Td>
                    <Td>
                      <span className="inline-flex px-2 py-0.5 rounded text-[10px] font-semibold bg-purple-900/40 text-purple-300">
                        {action.provider === 'm365' ? 'M365' : action.provider}
                      </span>
                    </Td>
                    <Td>
                      <div className="text-[10px] text-[var(--muted)] max-w-[200px] truncate">
                        {action.details ? JSON.stringify(action.details).slice(0, 50) : '—'}
                      </div>
                    </Td>
                    <Td className="text-[var(--muted)] text-[11px]">
                      {action.created_at ? new Date(action.created_at).toLocaleString() : '—'}
                    </Td>
                  </Tr>
                  {expandedId === action.id && (
                    <tr>
                      <td colSpan={6} className="bg-[#0a0a12] p-4 border-t border-white/5">
                        {detailLoading ? (
                          <div className="text-center py-4 text-[var(--muted)] text-[11px]">Loading details...</div>
                        ) : actionDetail ? (
                          <div className="grid grid-cols-2 gap-6">
                            {/* IP & Geolocation */}
                            <div className="space-y-3">
                              <h4 className="text-[11px] font-semibold text-[var(--foreground)] uppercase tracking-wide">Source IP & Location</h4>
                              {actionDetail.ip_address ? (
                                <div className="space-y-2">
                                  <div className="flex items-center gap-2">
                                    <Globe size={14} className="text-cyan-400" />
                                    <span className="text-[12px] font-mono text-[var(--foreground)]">{actionDetail.ip_address}</span>
                                  </div>
                                  {actionDetail.geo_info && (
                                    <div className="pl-6 space-y-1 text-[11px] text-[var(--muted)]">
                                      {actionDetail.geo_info.city && <div>City: <span className="text-[var(--foreground)]">{actionDetail.geo_info.city}</span></div>}
                                      {actionDetail.geo_info.region && <div>Region: <span className="text-[var(--foreground)]">{actionDetail.geo_info.region}</span></div>}
                                      {actionDetail.geo_info.country_name && <div>Country: <span className="text-[var(--foreground)]">{actionDetail.geo_info.country_name}</span></div>}
                                      {actionDetail.geo_info.org && <div>ISP/Org: <span className="text-[var(--foreground)]">{actionDetail.geo_info.org}</span></div>}
                                      {actionDetail.geo_info.timezone && <div>Timezone: <span className="text-[var(--foreground)]">{actionDetail.geo_info.timezone}</span></div>}
                                      {actionDetail.geo_info.lat && actionDetail.geo_info.lng && (
                                        <div>Coords: <span className="text-[var(--foreground)]">{actionDetail.geo_info.lat.toFixed(4)}, {actionDetail.geo_info.lng.toFixed(4)}</span></div>
                                      )}
                                    </div>
                                  )}
                                </div>
                              ) : (
                                <div className="text-[11px] text-[var(--muted)]">No IP address recorded</div>
                              )}
                            </div>
                            {/* Full Details */}
                            <div className="space-y-3">
                              <h4 className="text-[11px] font-semibold text-[var(--foreground)] uppercase tracking-wide">Full Details</h4>
                              <pre className="text-[10px] text-[var(--muted)] bg-black/30 p-3 rounded-lg overflow-auto max-h-[200px] whitespace-pre-wrap">
                                {JSON.stringify(actionDetail.details || action.details, null, 2)}
                              </pre>
                            </div>
                          </div>
                        ) : (
                          <div className="text-center py-4 text-[var(--muted)] text-[11px]">Could not load details</div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </Tbody>
          </Table>
        </div>
      )}
    </div>
  );
}

// ── Data Flows Tab ─────────────────────────────────────────────────────────────

function DataFlowsTab() {
  const [flows, setFlows] = useState<{
    flows: Array<{ source: string; target: string; value: number }>;
    raw: Array<{ source: string; target: string; value: number; owner: string }>;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const { data } = await api.get('/api/saas/data-flows');
        setFlows(data);
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, []);

  const maxValue = flows?.flows?.length ? Math.max(...flows.flows.map(f => f.value)) : 1;

  return (
    <div className="space-y-6">
      <h2 className="text-[14px] font-semibold text-[var(--foreground)]">Data Flows</h2>
      {loading ? (
        <div className="text-center py-8 text-[var(--muted)] text-[12px]">Loading data flows...</div>
      ) : !flows || flows.flows.length === 0 ? (
        <div className="text-center py-12 text-[var(--muted)] text-[12px]">
          <Database size={32} className="mx-auto mb-2 text-[var(--muted)]" />
          No external data sharing detected. Files shared externally will appear here.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Flow Summary */}
          <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
            <h3 className="text-[12px] font-semibold text-[var(--foreground)] mb-4">External Sharing by Domain</h3>
            <div className="space-y-3">
              {flows.flows.slice(0, 10).map((flow, i) => (
                <div key={i} className="flex items-center gap-3">
                  <div className="w-24 text-[11px] text-[var(--foreground)] truncate font-medium">
                    {flow.source}
                  </div>
                  <div className="flex-1">
                    <div className="h-4 bg-[var(--border)] rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          flow.target === 'Public (Anyone)' ? 'bg-red-500' : 'bg-amber-500'
                        }`}
                        style={{ width: `${Math.max(5, (flow.value / maxValue) * 100)}%` }}
                      />
                    </div>
                  </div>
                  <div className="w-20 text-right">
                    <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-semibold ${
                      flow.target === 'Public (Anyone)'
                        ? 'bg-red-500/10 border border-red-500/20 text-red-400'
                        : 'bg-amber-500/10 border border-amber-500/20 text-amber-400'
                    }`}>
                      {flow.value} files
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Detailed Flows */}
          <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
            <h3 className="text-[12px] font-semibold text-[var(--foreground)] mb-4">Top External Sharers</h3>
            <div className="space-y-2">
              {flows.raw.slice(0, 10).map((flow, i) => (
                <div key={i} className="flex items-center justify-between py-2 border-b border-[var(--border)] last:border-0">
                  <div className="flex items-center gap-2">
                    <ExternalLink size={12} className={flow.target === 'Public (Anyone)' ? 'text-red-400' : 'text-amber-400'} />
                    <span className="text-[11px] text-[var(--foreground)]">{flow.owner}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-[var(--muted)]">{flow.target}</span>
                    <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                      flow.target === 'Public (Anyone)'
                        ? 'bg-red-500/10 text-red-400'
                        : 'bg-amber-500/10 text-amber-400'
                    }`}>
                      {flow.value}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Summary Stats */}
          <div className="lg:col-span-2 grid grid-cols-3 gap-4">
            <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4 text-center">
              <div className="text-2xl font-bold text-[var(--foreground)]">
                {flows.flows.reduce((sum, f) => sum + f.value, 0)}
              </div>
              <div className="text-[11px] text-[var(--muted)]">Total External Shares</div>
            </div>
            <div className="bg-[var(--card)] rounded-xl border border-amber-500/20 p-4 text-center">
              <div className="text-2xl font-bold text-amber-400">
                {flows.flows.filter(f => f.target === 'External Users').reduce((sum, f) => sum + f.value, 0)}
              </div>
              <div className="text-[11px] text-[var(--muted)]">External User Shares</div>
            </div>
            <div className="bg-[var(--card)] rounded-xl border border-red-500/20 p-4 text-center">
              <div className="text-2xl font-bold text-red-400">
                {flows.flows.filter(f => f.target === 'Public (Anyone)').reduce((sum, f) => sum + f.value, 0)}
              </div>
              <div className="text-[11px] text-[var(--muted)]">Public (Anyone) Shares</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Risky Users Tab ───────────────────────────────────────────────────────────

function RiskyUsersTab() {
  const [users, setUsers] = useState<Array<{
    id: string; user_email: string; risk_level: string; risk_state?: string;
    risk_detail?: string; created_at?: string;
  }>>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const { data } = await api.get('/api/saas/risky-users');
        setUsers(data.users || []);
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, []);

  const riskColors: Record<string, string> = {
    high: 'bg-red-500/10 border-red-500/20 text-red-600 dark:text-red-400',
    medium: 'bg-amber-500/10 border-amber-500/20 text-amber-600 dark:text-amber-400',
    low: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-600 dark:text-emerald-400',
  };

  return (
    <div className="space-y-4">
      <h2 className="text-[14px] font-semibold text-[var(--foreground)]">Risky Users</h2>
      {loading ? (
        <div className="text-center py-8 text-[var(--muted)] text-[12px]">Loading risky users...</div>
      ) : users.length === 0 ? (
        <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-8">
          <div className="flex flex-col items-center justify-center text-center max-w-md mx-auto">
            <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center mb-4">
              <ShieldCheck size={32} className="text-emerald-500" />
            </div>
            <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-2">No Risky Users Detected</h3>
            <p className="text-[12px] text-[var(--muted)]">
              Entra ID Identity Protection hasn't flagged any users as risky. This data is pulled from Microsoft's risk detection engine which monitors sign-in anomalies, leaked credentials, and suspicious activity.
            </p>
          </div>
        </div>
      ) : (
        <div className="overflow-auto rounded-xl border border-[var(--border)]">
          <Table>
            <Thead>
              <Tr>
                <Th>User</Th>
                <Th>Risk Level</Th>
                <Th>State</Th>
                <Th>Detail</Th>
                <Th>Detected</Th>
              </Tr>
            </Thead>
            <Tbody>
              {users.map(u => (
                <Tr key={u.id}>
                  <Td>
                    <div className="flex items-center gap-2">
                      <AlertTriangle size={14} className={u.risk_level === 'high' ? 'text-red-500' : 'text-amber-500'} />
                      <span className="font-medium">{u.user_email}</span>
                    </div>
                  </Td>
                  <Td>
                    <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-semibold border ${riskColors[u.risk_level] || riskColors.low}`}>
                      {u.risk_level}
                    </span>
                  </Td>
                  <Td className="text-[var(--muted)] text-[11px]">{u.risk_state || '—'}</Td>
                  <Td className="text-[var(--muted)] text-[11px] max-w-[200px] truncate">{u.risk_detail || '—'}</Td>
                  <Td className="text-[var(--muted)] text-[11px]">
                    {u.created_at ? new Date(u.created_at).toLocaleDateString() : '—'}
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </div>
      )}
    </div>
  );
}

// ── Risk Heatmap Tab ─────────────────────────────────────────────────────────

function RiskHeatmapTab() {
  const [data, setData] = useState<{
    user_risk: Array<{ user: string; alert_count: number; risk_score: number }>;
    file_sensitivity: Array<{ label: string; count: number }>;
    severity_distribution: Array<{ severity: string; count: number }>;
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const { data: d } = await api.get('/api/saas/risk-heatmap');
        setData(d);
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, []);

  // Compute totals for summary cards
  const totalAlerts = data?.severity_distribution?.reduce((sum, s) => sum + s.count, 0) || 0;
  const criticalHigh = data?.severity_distribution?.filter(s => s.severity === 'critical' || s.severity === 'high').reduce((sum, s) => sum + s.count, 0) || 0;
  const totalFiles = data?.file_sensitivity?.reduce((sum, f) => sum + f.count, 0) || 0;
  const sensitiveFiles = data?.file_sensitivity?.filter(f => f.label === 'confidential' || f.label === 'highly_confidential').reduce((sum, f) => sum + f.count, 0) || 0;
  const maxSevCount = Math.max(...(data?.severity_distribution?.map(s => s.count) || [1]), 1);
  const maxFileCount = Math.max(...(data?.file_sensitivity?.map(f => f.count) || [1]), 1);

  const sevColors: Record<string, { bg: string; bar: string }> = {
    critical: { bg: 'bg-red-500/10 border-red-500/30', bar: 'bg-red-500' },
    high: { bg: 'bg-orange-500/10 border-orange-500/30', bar: 'bg-orange-500' },
    medium: { bg: 'bg-amber-500/10 border-amber-500/30', bar: 'bg-amber-500' },
    low: { bg: 'bg-emerald-500/10 border-emerald-500/30', bar: 'bg-emerald-500' },
  };
  const labelColors: Record<string, { bg: string; bar: string; text: string }> = {
    highly_confidential: { bg: 'bg-red-500/10', bar: 'bg-red-500', text: 'Highly Confidential' },
    confidential: { bg: 'bg-orange-500/10', bar: 'bg-orange-500', text: 'Confidential' },
    internal: { bg: 'bg-amber-500/10', bar: 'bg-amber-500', text: 'Internal' },
    public: { bg: 'bg-emerald-500/10', bar: 'bg-emerald-500', text: 'Public' },
    unknown: { bg: 'bg-zinc-500/10', bar: 'bg-zinc-500', text: 'Unknown' },
  };

  return (
    <div className="space-y-6">
      <h2 className="text-[14px] font-semibold text-[var(--foreground)]">Risk Overview</h2>
      {loading ? (
        <div className="text-center py-8 text-[var(--muted)] text-[12px]">Loading risk data...</div>
      ) : !data ? (
        <div className="text-center py-8 text-[var(--muted)] text-[12px]">No risk data available.</div>
      ) : (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Activity size={16} className="text-[var(--muted)]" />
                <span className="text-[11px] text-[var(--muted)] font-medium">Total Alerts</span>
              </div>
              <div className="text-2xl font-bold text-[var(--foreground)]">{totalAlerts}</div>
            </div>
            <div className="bg-[var(--card)] border border-red-500/20 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle size={16} className="text-red-500" />
                <span className="text-[11px] text-[var(--muted)] font-medium">Critical/High</span>
              </div>
              <div className="text-2xl font-bold text-red-500">{criticalHigh}</div>
            </div>
            <div className="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <Database size={16} className="text-[var(--muted)]" />
                <span className="text-[11px] text-[var(--muted)] font-medium">Files Scanned</span>
              </div>
              <div className="text-2xl font-bold text-[var(--foreground)]">{totalFiles}</div>
            </div>
            <div className="bg-[var(--card)] border border-amber-500/20 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <FileWarning size={16} className="text-amber-500" />
                <span className="text-[11px] text-[var(--muted)] font-medium">Sensitive Files</span>
              </div>
              <div className="text-2xl font-bold text-amber-500">{sensitiveFiles}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Severity Distribution */}
            <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Alert Severity</h3>
                <span className="text-[10px] text-[var(--muted)] bg-[var(--muted)]/10 px-2 py-0.5 rounded">Last 30 days</span>
              </div>
              <div className="space-y-3">
                {['critical', 'high', 'medium', 'low'].map(sev => {
                  const item = data.severity_distribution.find(s => s.severity === sev);
                  const count = item?.count || 0;
                  const colors = sevColors[sev] || sevColors.low;
                  return (
                    <div key={sev} className="group">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <div className={`w-2.5 h-2.5 rounded-full ${colors.bar}`} />
                          <span className="text-[12px] text-[var(--foreground)] capitalize font-medium">{sev}</span>
                        </div>
                        <span className="text-[12px] text-[var(--foreground)] font-semibold">{count}</span>
                      </div>
                      <div className="h-2 bg-[var(--muted)]/10 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${colors.bar}`}
                          style={{ width: `${Math.max(2, (count / maxSevCount) * 100)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Data Classification */}
            <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Data Classification</h3>
                <span className="text-[10px] text-[var(--muted)] bg-[var(--muted)]/10 px-2 py-0.5 rounded">SharePoint files</span>
              </div>
              <div className="space-y-3">
                {['highly_confidential', 'confidential', 'internal', 'public'].map(label => {
                  const item = data.file_sensitivity.find(f => f.label === label);
                  const count = item?.count || 0;
                  const colors = labelColors[label] || labelColors.unknown;
                  return (
                    <div key={label}>
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <div className={`w-2.5 h-2.5 rounded-full ${colors.bar}`} />
                          <span className="text-[12px] text-[var(--foreground)] font-medium">{colors.text}</span>
                        </div>
                        <span className="text-[12px] text-[var(--foreground)] font-semibold">{count}</span>
                      </div>
                      <div className="h-2 bg-[var(--muted)]/10 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${colors.bar}`}
                          style={{ width: `${Math.max(2, (count / maxFileCount) * 100)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Behavioral Risks - Users */}
          <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Users size={16} className="text-[var(--muted)]" />
                <h3 className="text-[13px] font-semibold text-[var(--foreground)]">User Risk Distribution</h3>
              </div>
              <span className="text-[10px] text-[var(--muted)] bg-[var(--muted)]/10 px-2 py-0.5 rounded">Based on behavioral alerts</span>
            </div>
            {data.user_risk.length === 0 ? (
              <div className="text-center py-8 text-[var(--muted)] text-[12px]">
                <ShieldCheck size={24} className="mx-auto mb-2 text-emerald-500" />
                No user-based behavioral alerts detected
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
                {data.user_risk.slice(0, 10).map((u, i) => {
                  const riskLevel = u.risk_score > 10 ? 'high' : u.risk_score > 5 ? 'medium' : 'low';
                  const borderColor = riskLevel === 'high' ? 'border-red-500/30' : riskLevel === 'medium' ? 'border-amber-500/30' : 'border-[var(--border)]';
                  const bgColor = riskLevel === 'high' ? 'bg-red-500/5' : riskLevel === 'medium' ? 'bg-amber-500/5' : 'bg-[var(--card)]';
                  return (
                    <div key={u.user} className={`${bgColor} border ${borderColor} rounded-xl p-3 transition-all hover:scale-[1.02]`}>
                      <div className="flex items-center gap-1 mb-1">
                        <span className="text-[9px] font-semibold text-[var(--muted)] uppercase">#{i + 1}</span>
                      </div>
                      <div className="text-[11px] text-[var(--foreground)] font-medium truncate" title={u.user}>
                        {u.user.split('@')[0]}
                      </div>
                      <div className="flex items-baseline gap-1 mt-1">
                        <span className="text-lg font-bold text-[var(--foreground)]">{u.alert_count}</span>
                        <span className="text-[10px] text-[var(--muted)]">alerts</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ── External Collaboration Tab ───────────────────────────────────────────────

// ── Attack Chain Tab ────────────────────────────────────────────────────────────

interface AttackPathNode {
  type: string
  name: string
  detail: string
  icon: string
}

interface AttackPath {
  id: string
  // Verbose fields
  title?: string
  severity?: string
  type?: string
  description?: string
  entry_point?: AttackPathNode
  pivot_points?: AttackPathNode[]
  impact?: AttackPathNode
  affected_resources?: string[]
  remediation?: string[]
  detected_at?: string
  // Legacy fields
  resource_name: string
  resource_type: string
  provider: string
  exposure_type: 'public_internet' | 'anonymous_link' | 'external_share' | 'public_bucket' | 'open_port' | 'privilege_escalation' | 'risky_signin'
  risk_level: 'critical' | 'high' | 'medium' | 'low'
  path_steps: Array<{ step: number; description: string; icon: string }>
  classification?: string
  region?: string
  url?: string
}

function AttackChainTab() {
  const [data, setData] = useState<{
    attack_paths: AttackPath[]
    summary: {
      total_paths: number
      critical_paths: number
      high_paths: number
      by_provider: Record<string, number>
      by_exposure: Record<string, number>
    }
  } | null>(null)
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  useEffect(() => {
    (async () => {
      try {
        const { data: result } = await api.get('/api/saas/attack-chains').catch(() => ({ data: null }))
        if (result) {
          setData(result)
        } else {
          // Fallback: construct from external-collaboration + posture data
          const [extResp, postureResp] = await Promise.all([
            api.get('/api/saas/external-collaboration').catch(() => ({ data: null })),
            api.get('/api/saas/posture').catch(() => ({ data: null })),
          ])

          const paths: AttackPath[] = []

          if (extResp.data?.anonymous_links) {
            extResp.data.anonymous_links.forEach((link: { id: string; file_name: string; provider: string }) => {
              paths.push({
                id: `anon-${link.id}`,
                title: `Anonymous Link Exposes '${link.file_name}' to Internet`,
                severity: 'high',
                type: 'data_leak',
                description: `File '${link.file_name}' is shared via an anonymous link in ${link.provider}, meaning anyone with the URL can access it without authentication. This creates a data leak risk.`,
                entry_point: { type: 'internet', name: 'Public Internet', detail: 'No authentication required.', icon: 'GLOBE' },
                pivot_points: [{ type: 'anonymous_link', name: 'Anonymous Share Link', detail: 'File accessible to anyone with the URL.', icon: 'LINK' }],
                impact: { type: 'data_leak', name: 'Unauthorized Data Access', detail: `Contents of '${link.file_name}' exposed to any internet user.`, icon: 'SHIELD_ALERT' },
                affected_resources: [link.file_name],
                remediation: ['1. Remove the anonymous link from sharing settings.', '2. Enable DLP policies to prevent anonymous sharing of sensitive files.'],
                detected_at: new Date().toISOString(),
                resource_name: link.file_name,
                resource_type: 'file',
                provider: link.provider,
                exposure_type: 'anonymous_link',
                risk_level: 'high',
                path_steps: [
                  { step: 1, description: 'Public Internet', icon: 'GLOBE' },
                  { step: 2, description: 'Anonymous Link', icon: 'LINK' },
                  { step: 3, description: link.file_name.slice(0, 20), icon: 'FILE_TEXT' },
                  { step: 4, description: 'Data Leak', icon: 'SHIELD_ALERT' },
                ],
              })
            })
          }

          if (extResp.data?.external_shares) {
            extResp.data.external_shares
              .filter((s: { is_sensitive: boolean }) => s.is_sensitive)
              .slice(0, 10)
              .forEach((share: { id: string; file_name: string; provider: string; classification?: string }) => {
                paths.push({
                  id: `ext-${share.id}`,
                  title: `Sensitive File '${share.file_name}' Shared with External Users`,
                  severity: 'high',
                  type: 'data_leak',
                  description: `The file '${share.file_name}' classified as ${share.classification || 'sensitive'} has been shared with external parties outside your organization via ${share.provider}.`,
                  entry_point: { type: 'external_actor', name: 'External User', detail: 'User outside the organization with share access.', icon: 'USER_X' },
                  pivot_points: [{ type: 'external_share', name: 'External Share Link', detail: 'File shared with external email domain.', icon: 'LINK' }],
                  impact: { type: 'data_leak', name: 'Sensitive Data Leak', detail: `${share.classification || 'Sensitive'} file '${share.file_name}' accessible to external parties.`, icon: 'SHIELD_ALERT' },
                  affected_resources: [share.file_name],
                  remediation: ['1. Review and remove the external share.', '2. Apply DLP policy to block external sharing of classified content.', '3. Verify intent with file owner.'],
                  detected_at: new Date().toISOString(),
                  resource_name: share.file_name,
                  resource_type: 'file',
                  provider: share.provider,
                  exposure_type: 'external_share',
                  risk_level: 'high',
                  classification: share.classification,
                  path_steps: [
                    { step: 1, description: 'External User', icon: 'USER_X' },
                    { step: 2, description: 'Shared Link', icon: 'LINK' },
                    { step: 3, description: share.file_name.slice(0, 20), icon: 'FILE_TEXT' },
                    { step: 4, description: 'Data Leak', icon: 'SHIELD_ALERT' },
                  ],
                })
              })
          }

          if (postureResp.data?.checks?.aws) {
            postureResp.data.checks.aws
              .filter((c: { status: string; check_name: string }) => c.status === 'fail' && c.check_name.toLowerCase().includes('public'))
              .forEach((check: { id: string; check_name: string; evidence?: { bucket?: string; resource?: string } }, i: number) => {
                const bucketName = check.evidence?.bucket || check.evidence?.resource || 'Unknown Bucket'
                paths.push({
                  id: `aws-${check.id || i}`,
                  title: `Public S3 Bucket '${bucketName}' Exposes Data to Internet`,
                  severity: 'critical',
                  type: 'data_exfil',
                  description: `S3 bucket '${bucketName}' has public access enabled. Any internet user can list and download its contents without authentication, creating a critical data exfiltration risk.`,
                  entry_point: { type: 'internet', name: 'Public Internet', detail: 'No authentication required.', icon: 'GLOBE' },
                  pivot_points: [{ type: 'public_access', name: 'Block Public Access Disabled', detail: `Bucket '${bucketName}' allows public access via policy or ACL.`, icon: 'UNLOCK' }],
                  impact: { type: 'data_exposure', name: 'Unrestricted Data Exfiltration', detail: `All objects in '${bucketName}' are downloadable by any internet actor.`, icon: 'ALERT_OCTAGON' },
                  affected_resources: [`arn:aws:s3:::${bucketName}`, `s3://${bucketName}/*`],
                  remediation: ['1. Enable S3 Block Public Access on the bucket.', '2. Remove bucket policies with Principal: *.', '3. Audit objects for sensitive data with Amazon Macie.'],
                  detected_at: new Date().toISOString(),
                  resource_name: bucketName,
                  resource_type: 's3_bucket',
                  provider: 'aws',
                  exposure_type: 'public_bucket',
                  risk_level: 'critical',
                  path_steps: [
                    { step: 1, description: 'Public Internet', icon: 'GLOBE' },
                    { step: 2, description: 'No Auth Required', icon: 'UNLOCK' },
                    { step: 3, description: bucketName.slice(0, 18), icon: 'DATABASE' },
                    { step: 4, description: 'Data Exfiltration', icon: 'ALERT_OCTAGON' },
                  ],
                })
              })
          }

          const summary = {
            total_paths: paths.length,
            critical_paths: paths.filter(p => p.risk_level === 'critical').length,
            high_paths: paths.filter(p => p.risk_level === 'high').length,
            by_provider: paths.reduce((acc, p) => ({ ...acc, [p.provider]: (acc[p.provider] || 0) + 1 }), {} as Record<string, number>),
            by_exposure: paths.reduce((acc, p) => ({ ...acc, [p.exposure_type]: (acc[p.exposure_type] || 0) + 1 }), {} as Record<string, number>),
          }

          setData({ attack_paths: paths, summary })
        }
      } catch {
        setData({ attack_paths: [], summary: { total_paths: 0, critical_paths: 0, high_paths: 0, by_provider: {}, by_exposure: {} } })
      }
      setLoading(false)
    })()
  }, [])

  if (loading) {
    return <div className="text-center py-12 text-[var(--muted)]"><RefreshCw className="animate-spin mx-auto" size={24} /></div>
  }

  const isEmpty = !data || data.attack_paths.length === 0

  if (isEmpty) {
    return (
      <div className="text-center py-16">
        <ShieldCheck size={48} className="mx-auto mb-4 text-emerald-500" />
        <h3 className="text-[16px] font-semibold text-[var(--foreground)] mb-2">No Attack Paths Detected</h3>
        <p className="text-[13px] text-[var(--muted)] max-w-md mx-auto">
          No publicly reachable resources found. Attack chains will appear here when resources are exposed to the internet.
        </p>
      </div>
    )
  }

  // Map icon code strings to Lucide components
  function StepIcon({ code, size = 14, className = '' }: { code: string; size?: number; className?: string }) {
    const props = { size, className }
    switch (code) {
      case 'GLOBE': return <Globe {...props} />
      case 'UNLOCK': return <Unlock {...props} />
      case 'LOCK': return <Lock {...props} />
      case 'DATABASE': return <Database {...props} />
      case 'ALERT_OCTAGON': return <AlertOctagon {...props} />
      case 'SHIELD_ALERT': return <ShieldAlert {...props} />
      case 'USER': return <Users {...props} />
      case 'USER_X': return <UserX {...props} />
      case 'KEY': return <Key {...props} />
      case 'SERVER': return <Server {...props} />
      case 'LINK': return <Link {...props} />
      case 'FILE_TEXT': return <FileText {...props} />
      case 'NETWORK': return <Network {...props} />
      default: return <AlertTriangle {...props} />
    }
  }

  function stepIconColor(code: string, position: 'entry' | 'pivot' | 'impact'): string {
    if (position === 'entry') return 'text-red-400'
    if (position === 'impact') return 'text-amber-400'
    return 'text-blue-400'
  }

  const exposureLabels: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    public_internet: { label: 'Public Internet', color: 'text-red-400 bg-red-500/10 border-red-500/20', icon: <Globe size={12} /> },
    anonymous_link: { label: 'Anonymous Link', color: 'text-orange-400 bg-orange-500/10 border-orange-500/20', icon: <Link size={12} /> },
    external_share: { label: 'External Share', color: 'text-amber-400 bg-amber-500/10 border-amber-500/20', icon: <Users size={12} /> },
    public_bucket: { label: 'Public Bucket', color: 'text-red-400 bg-red-500/10 border-red-500/20', icon: <HardDrive size={12} /> },
    open_port: { label: 'Open Port', color: 'text-red-400 bg-red-500/10 border-red-500/20', icon: <Server size={12} /> },
    privilege_escalation: { label: 'Privilege Escalation', color: 'text-purple-400 bg-purple-500/10 border-purple-500/20', icon: <Key size={12} /> },
    risky_signin: { label: 'Risky Sign-In', color: 'text-rose-400 bg-rose-500/10 border-rose-500/20', icon: <UserX size={12} /> },
  }

  const severityConfig: Record<string, { label: string; dot: string; badge: string }> = {
    critical: { label: 'Critical', dot: 'bg-red-500 animate-pulse', badge: 'text-red-400 bg-red-500/10 border-red-500/30' },
    high: { label: 'High', dot: 'bg-orange-500', badge: 'text-orange-400 bg-orange-500/10 border-orange-500/30' },
    medium: { label: 'Medium', dot: 'bg-amber-500', badge: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
    low: { label: 'Low', dot: 'bg-emerald-500', badge: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' },
  }

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 text-[var(--muted)] mb-1">
            <Network size={14} />
            <span className="text-[11px]">Attack Paths</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">{data.summary.total_paths}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-red-500/30 p-4">
          <div className="flex items-center gap-2 text-red-500 mb-1">
            <Target size={14} />
            <span className="text-[11px]">Critical Paths</span>
          </div>
          <div className="text-2xl font-bold text-red-500">{data.summary.critical_paths}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-orange-500/30 p-4">
          <div className="flex items-center gap-2 text-orange-500 mb-1">
            <AlertTriangle size={14} />
            <span className="text-[11px]">High Risk</span>
          </div>
          <div className="text-2xl font-bold text-orange-500">{data.summary.high_paths}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 text-[var(--muted)] mb-1">
            <Layers size={14} />
            <span className="text-[11px]">Providers</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">{Object.keys(data.summary.by_provider).length}</div>
        </div>
      </div>

      {/* Exposure Types Distribution */}
      <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
        <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-3">Exposure Types</h3>
        <div className="flex flex-wrap gap-2">
          {Object.entries(data.summary.by_exposure).map(([type, count]) => {
            const meta = exposureLabels[type] || { label: type, color: 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20', icon: <Globe size={12} /> }
            return (
              <span key={type} className={`px-3 py-1.5 rounded-lg text-[12px] border flex items-center gap-2 ${meta.color}`}>
                {meta.icon}
                {meta.label} <span className="font-bold">({count})</span>
              </span>
            )
          })}
        </div>
      </div>

      {/* Attack Paths */}
      <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] overflow-hidden">
        <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="text-[13px] font-semibold text-[var(--foreground)] flex items-center gap-2">
            <GitBranch size={14} className="text-red-400" />
            Internet-Reachable Attack Chains
          </h3>
          <span className="text-[10px] text-[var(--muted)] bg-white/[0.05] px-2 py-1 rounded">Click to expand</span>
        </div>
        <div className="divide-y divide-[var(--border)]">
          {data.attack_paths.slice(0, 20).map((path) => {
            const isExpanded = expandedId === path.id
            const sev = path.severity || path.risk_level
            const sevCfg = severityConfig[sev] || severityConfig.high
            const meta = exposureLabels[path.exposure_type] || { label: path.exposure_type, color: 'text-zinc-400 bg-zinc-500/10 border-zinc-500/20', icon: <Globe size={12} /> }
            const title = path.title || path.resource_name

            return (
              <div key={path.id}>
                {/* Row Header */}
                <div
                  className="px-4 py-3 hover:bg-white/[0.02] cursor-pointer transition-colors"
                  onClick={() => setExpandedId(isExpanded ? null : path.id)}
                >
                  <div className="flex items-start gap-3">
                    {/* Severity dot */}
                    <div className={`w-2 h-2 rounded-full flex-shrink-0 mt-1.5 ${sevCfg.dot}`} />

                    {/* Main Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[12px] font-semibold text-[var(--foreground)] leading-snug">{title}</span>
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${sevCfg.badge}`}>{sevCfg.label}</span>
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                          path.provider.toLowerCase() === 'aws' ? 'bg-[#FF9900]/20 text-[#FF9900]' :
                          ['teams', 'sharepoint', 'm365'].includes(path.provider.toLowerCase()) ? 'bg-blue-500/20 text-blue-400' :
                          'bg-white/10 text-white'
                        }`}>{path.provider.toUpperCase()}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                        <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] border ${meta.color}`}>
                          {meta.icon}{meta.label}
                        </span>
                        {path.classification && (
                          <span className="text-[9px] text-purple-400 bg-purple-500/10 px-1.5 py-0.5 rounded border border-purple-500/20">
                            {path.classification.replace('_', ' ')}
                          </span>
                        )}
                        {/* Attack path mini-preview */}
                        <div className="hidden md:flex items-center gap-1 text-[10px] text-[var(--muted)]">
                          {path.path_steps.map((step, i) => (
                            <span key={step.step} className="flex items-center gap-1">
                              <StepIcon
                                code={step.icon}
                                size={10}
                                className={i === 0 ? 'text-red-400' : i === path.path_steps.length - 1 ? 'text-amber-400' : 'text-blue-400'}
                              />
                              <span className="text-[9px]">{step.description}</span>
                              {i < path.path_steps.length - 1 && <ArrowRight size={8} className="text-[var(--muted)]" />}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    <ChevronDown size={14} className={`text-[var(--muted)] flex-shrink-0 mt-1 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                  </div>
                </div>

                {/* Expanded Detail Panel */}
                {isExpanded && (
                  <div className="bg-white/[0.015] border-t border-[var(--border)] px-4 py-4 space-y-5">
                    {/* Description */}
                    {path.description && (
                      <div>
                        <div className="text-[10px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Info size={11} /> Analysis
                        </div>
                        <p className="text-[12px] text-[var(--foreground)] leading-relaxed opacity-90">{path.description}</p>
                      </div>
                    )}

                    {/* Attack Chain Visualization */}
                    <div>
                      <div className="text-[10px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-3 flex items-center gap-1.5">
                        <GitBranch size={11} /> Attack Chain
                      </div>
                      <div className="flex items-stretch gap-0">
                        {/* Entry Point */}
                        {path.entry_point && (
                          <div className="flex-1 bg-red-500/10 border border-red-500/30 rounded-l-lg p-3">
                            <div className="flex items-center gap-1.5 mb-1">
                              <AlertOctagon size={13} className="text-red-400" />
                              <span className="text-[10px] font-bold text-red-400 uppercase">Entry Point</span>
                            </div>
                            <div className="text-[11px] font-semibold text-[var(--foreground)]">{path.entry_point.name}</div>
                            <div className="text-[10px] text-[var(--muted)] mt-1 leading-relaxed">{path.entry_point.detail}</div>
                          </div>
                        )}

                        {/* Arrow */}
                        {path.pivot_points && path.pivot_points.length > 0 && (
                          <div className="flex items-center px-1 flex-shrink-0">
                            <ArrowRight size={16} className="text-[var(--muted)]" />
                          </div>
                        )}

                        {/* Pivot Points */}
                        {path.pivot_points && path.pivot_points.map((pivot, idx) => (
                          <div key={idx} className="flex items-stretch gap-0">
                            <div className="flex-1 bg-blue-500/10 border border-blue-500/30 p-3 min-w-[140px]">
                              <div className="flex items-center gap-1.5 mb-1">
                                <Network size={13} className="text-blue-400" />
                                <span className="text-[10px] font-bold text-blue-400 uppercase">Pivot</span>
                              </div>
                              <div className="text-[11px] font-semibold text-[var(--foreground)]">{pivot.name}</div>
                              <div className="text-[10px] text-[var(--muted)] mt-1 leading-relaxed">{pivot.detail}</div>
                            </div>
                            {idx < (path.pivot_points?.length ?? 0) - 1 && (
                              <div className="flex items-center px-1 flex-shrink-0">
                                <ArrowRight size={16} className="text-[var(--muted)]" />
                              </div>
                            )}
                          </div>
                        ))}

                        {/* Arrow to Impact */}
                        {path.impact && (
                          <div className="flex items-center px-1 flex-shrink-0">
                            <ArrowRight size={16} className="text-[var(--muted)]" />
                          </div>
                        )}

                        {/* Impact */}
                        {path.impact && (
                          <div className="flex-1 bg-amber-500/10 border border-amber-500/30 rounded-r-lg p-3">
                            <div className="flex items-center gap-1.5 mb-1">
                              <Target size={13} className="text-amber-400" />
                              <span className="text-[10px] font-bold text-amber-400 uppercase">Impact</span>
                            </div>
                            <div className="text-[11px] font-semibold text-[var(--foreground)]">{path.impact.name}</div>
                            <div className="text-[10px] text-[var(--muted)] mt-1 leading-relaxed">{path.impact.detail}</div>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Affected Resources */}
                    {path.affected_resources && path.affected_resources.length > 0 && (
                      <div>
                        <div className="text-[10px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <Database size={11} /> Affected Resources
                        </div>
                        <div className="flex flex-col gap-1">
                          {path.affected_resources.map((res, i) => (
                            <div key={i} className="flex items-center gap-2 text-[11px] font-mono text-[var(--foreground)] bg-white/[0.04] px-2.5 py-1.5 rounded border border-[var(--border)]">
                              <HardDrive size={10} className="text-[var(--muted)] flex-shrink-0" />
                              <span className="truncate opacity-80">{res}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Remediation Steps */}
                    {path.remediation && path.remediation.length > 0 && (
                      <div>
                        <div className="text-[10px] font-semibold text-[var(--muted)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                          <ShieldCheck size={11} className="text-emerald-400" />
                          <span className="text-emerald-400">Remediation Steps</span>
                        </div>
                        <div className="flex flex-col gap-1.5">
                          {path.remediation.map((step, i) => (
                            <div key={i} className="flex items-start gap-2 text-[11px] text-[var(--foreground)] opacity-85">
                              <CheckCircle2 size={12} className="text-emerald-400 flex-shrink-0 mt-0.5" />
                              <span className="leading-relaxed">{step}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Detected At */}
                    {path.detected_at && (
                      <div className="text-[10px] text-[var(--muted)] flex items-center gap-1.5 pt-1 border-t border-[var(--border)]">
                        <Clock size={10} />
                        Detected: {new Date(path.detected_at).toLocaleString()}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ── Sensitive Exposure Tab ────────────────────────────────────────────────────

function SensitiveExposureTab() {
  const [data, setData] = useState<{
    exposed_files: Array<{
      id: string; file_name: string; owner: string; sharing_scope: string;
      shared_with_count: number; sensitivity?: string; classification: string;
      provider: string; last_modified?: string; file_path?: string; risk_level: string;
    }>;
    by_classification: Record<string, number>;
    by_owner: Record<string, number>;
    summary: { total_sensitive_files: number; externally_shared: number; publicly_accessible: number; high_risk_count: number };
  } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const { data: result } = await api.get('/api/saas/sensitive-exposure');
        setData(result);
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, []);

  if (loading) return <div className="text-center py-12 text-[var(--muted)]"><RefreshCw className="animate-spin mx-auto" size={24} /></div>;

  if (!data || data.summary.total_sensitive_files === 0) {
    return (
      <div className="text-center py-16">
        <Lock size={48} className="mx-auto mb-4 text-emerald-500" />
        <h3 className="text-[16px] font-semibold text-[var(--foreground)] mb-2">No Sensitive Data Exposure</h3>
        <p className="text-[13px] text-[var(--muted)] max-w-md mx-auto">
          No sensitive files (PII, Financial, Health) are externally shared or over-permissioned.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 text-[var(--muted)] mb-1">
            <FileWarning size={14} />
            <span className="text-[11px]">Sensitive Files</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">{data.summary.total_sensitive_files}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-red-500/30 p-4">
          <div className="flex items-center gap-2 text-red-500 mb-1">
            <AlertOctagon size={14} />
            <span className="text-[11px]">Publicly Accessible</span>
          </div>
          <div className="text-2xl font-bold text-red-500">{data.summary.publicly_accessible}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-amber-500/30 p-4">
          <div className="flex items-center gap-2 text-amber-500 mb-1">
            <Globe size={14} />
            <span className="text-[11px]">Externally Shared</span>
          </div>
          <div className="text-2xl font-bold text-amber-500">{data.summary.externally_shared}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-red-500/30 p-4">
          <div className="flex items-center gap-2 text-red-500 mb-1">
            <TrendingUp size={14} />
            <span className="text-[11px]">High Risk</span>
          </div>
          <div className="text-2xl font-bold text-red-500">{data.summary.high_risk_count}</div>
        </div>
      </div>

      {/* By Classification */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
          <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-3">By Classification</h3>
          <div className="space-y-2">
            {Object.entries(data.by_classification).sort((a, b) => b[1] - a[1]).map(([cls, count]) => (
              <div key={cls} className="flex items-center justify-between">
                <span className="text-[12px] text-[var(--foreground)] capitalize">{cls}</span>
                <span className="text-[12px] font-semibold text-[var(--foreground)]">{count}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
          <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-3">Top Owners</h3>
          <div className="space-y-2">
            {Object.entries(data.by_owner).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([owner, count]) => (
              <div key={owner} className="flex items-center justify-between">
                <span className="text-[12px] text-[var(--foreground)] truncate max-w-[150px]" title={owner}>{owner.split('@')[0]}</span>
                <span className="text-[12px] font-semibold text-[var(--foreground)]">{count} files</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Files Table */}
      <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] overflow-hidden">
        <div className="px-4 py-3 border-b border-[var(--border)]">
          <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Exposed Sensitive Files</h3>
        </div>
        <Table>
          <Thead>
            <Tr>
              <Th>Risk</Th>
              <Th>File</Th>
              <Th>Classification</Th>
              <Th>Scope</Th>
              <Th>Owner</Th>
            </Tr>
          </Thead>
          <Tbody>
            {data.exposed_files.slice(0, 25).map(file => (
              <Tr key={file.id}>
                <Td>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                    file.risk_level === 'critical' ? 'bg-red-500/20 text-red-400' :
                    file.risk_level === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    file.risk_level === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                    'bg-emerald-500/20 text-emerald-400'
                  }`}>
                    {file.risk_level}
                  </span>
                </Td>
                <Td><span className="truncate max-w-[200px] block" title={file.file_name}>{file.file_name}</span></Td>
                <Td><span className="capitalize">{file.classification}</span></Td>
                <Td><span className="capitalize">{file.sharing_scope}</span></Td>
                <Td>{file.owner?.split('@')[0]}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </div>
    </div>
  );
}

// ── Stale Permissions Tab ─────────────────────────────────────────────────────

function StalePermissionsTab() {
  const [data, setData] = useState<{
    stale_shares: Array<{
      id: string; file_name: string; owner: string; sharing_scope: string;
      shared_with_count: number; provider: string; created_at?: string;
      last_modified?: string; days_stale: number;
    }>;
    summary: { total_stale: number; external_stale: number; internal_stale: number; potential_savings: number };
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [days, setDays] = useState(90);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const { data: result } = await api.get(`/api/saas/stale-permissions?days=${days}`);
        setData(result);
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, [days]);

  if (loading) return <div className="text-center py-12 text-[var(--muted)]"><RefreshCw className="animate-spin mx-auto" size={24} /></div>;

  if (!data || data.summary.total_stale === 0) {
    return (
      <div className="text-center py-16">
        <CheckCircle2 size={48} className="mx-auto mb-4 text-emerald-500" />
        <h3 className="text-[16px] font-semibold text-[var(--foreground)] mb-2">No Stale Permissions</h3>
        <p className="text-[13px] text-[var(--muted)] max-w-md mx-auto">
          All shared files have been accessed or modified within the last {days} days.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Filter */}
      <div className="flex items-center gap-4">
        <span className="text-[12px] text-[var(--muted)]">Inactive for:</span>
        {[30, 60, 90, 180, 365].map(d => (
          <button
            key={d}
            onClick={() => setDays(d)}
            className={`px-3 py-1 rounded-lg text-[11px] font-medium transition-colors ${
              days === d ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' : 'bg-[var(--card)] text-[var(--muted)] border border-[var(--border)]'
            }`}
          >
            {d} days
          </button>
        ))}
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 text-[var(--muted)] mb-1">
            <Clock size={14} />
            <span className="text-[11px]">Total Stale</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">{data.summary.total_stale}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-amber-500/30 p-4">
          <div className="flex items-center gap-2 text-amber-500 mb-1">
            <Globe size={14} />
            <span className="text-[11px]">External Stale</span>
          </div>
          <div className="text-2xl font-bold text-amber-500">{data.summary.external_stale}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 text-[var(--muted)] mb-1">
            <Building2 size={14} />
            <span className="text-[11px]">Internal Stale</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">{data.summary.internal_stale}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-emerald-500/30 p-4">
          <div className="flex items-center gap-2 text-emerald-500 mb-1">
            <Trash2 size={14} />
            <span className="text-[11px]">Revocable Permissions</span>
          </div>
          <div className="text-2xl font-bold text-emerald-500">{data.summary.potential_savings}</div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th>Days Stale</Th>
              <Th>File</Th>
              <Th>Scope</Th>
              <Th>Shared With</Th>
              <Th>Owner</Th>
            </Tr>
          </Thead>
          <Tbody>
            {data.stale_shares.slice(0, 30).map(share => (
              <Tr key={share.id}>
                <Td>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                    share.days_stale > 180 ? 'bg-red-500/20 text-red-400' :
                    share.days_stale > 90 ? 'bg-amber-500/20 text-amber-400' :
                    'bg-[var(--muted)]/20 text-[var(--muted)]'
                  }`}>
                    {share.days_stale}d
                  </span>
                </Td>
                <Td><span className="truncate max-w-[200px] block" title={share.file_name}>{share.file_name}</span></Td>
                <Td><span className="capitalize">{share.sharing_scope}</span></Td>
                <Td>{share.shared_with_count} users</Td>
                <Td>{share.owner?.split('@')[0]}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </div>
    </div>
  );
}

// ── User Risk Scores Tab ──────────────────────────────────────────────────────

function UserRiskScoresTab() {
  const [data, setData] = useState<{
    users: Array<{
      email: string; risk_score: number; risk_level: string;
      display_name?: string; job_title?: string; department?: string;
      signals: Array<{ type: string; severity?: string; detail?: string; count?: number; high_count?: number; sensitive?: number }>;
    }>;
    summary: { total_users: number; high_risk: number; medium_risk: number; low_risk: number };
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedUser, setExpandedUser] = useState<string | null>(null);
  const [userDetail, setUserDetail] = useState<{
    email: string;
    lifecycle: {
      created_at?: string;
      last_used?: string;
      mfa_enabled?: boolean;
      console_access?: boolean;
      access_key_count?: number;
      access_keys?: Array<{ AccessKeyId?: string; Status?: string; CreateDate?: string }>;
      risk_state?: string;
      last_scanned?: string;
    };
    permissions: Array<string | { PolicyName?: string; name?: string }>;
    recent_activity: Array<{ action: string; target?: string; time?: string; source_ip?: string; region?: string }>;
    sign_in_locations: Array<{ ip: string; city?: string; region?: string; country?: string; time?: string }>;
    risk_factors: Array<{ type: string; severity: string; title: string; description?: string; detected_at?: string }>;
    owned_items?: Array<{ name: string; classification?: string; sharing?: string; last_modified?: string }>;
    resource_arn?: string;
    ai_assessment?: {
      risk_score?: number;
      risk_band?: string;
      headline?: string;
      key_concerns?: string[];
      recommended_actions?: string[];
      trust_signals?: string[];
    };
  } | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const { data: result } = await api.get('/api/saas/user-risk-scores');
        setData(result);
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, []);

  if (loading) return <div className="text-center py-12 text-[var(--muted)]"><RefreshCw className="animate-spin mx-auto" size={24} /></div>;

  if (!data || data.summary.total_users === 0) {
    return (
      <div className="text-center py-16">
        <Users size={48} className="mx-auto mb-4 text-emerald-500" />
        <h3 className="text-[16px] font-semibold text-[var(--foreground)] mb-2">No User Risk Data</h3>
        <p className="text-[13px] text-[var(--muted)] max-w-md mx-auto">
          User risk scores are calculated from behavioral signals, alerts, and external sharing patterns.
          Run a scan to populate this data.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-4">
          <div className="flex items-center gap-2 text-[var(--muted)] mb-1">
            <Users size={14} />
            <span className="text-[11px]">Total Users</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">{data.summary.total_users}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-red-500/30 p-4">
          <div className="flex items-center gap-2 text-red-500 mb-1">
            <AlertTriangle size={14} />
            <span className="text-[11px]">High Risk</span>
          </div>
          <div className="text-2xl font-bold text-red-500">{data.summary.high_risk}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-amber-500/30 p-4">
          <div className="flex items-center gap-2 text-amber-500 mb-1">
            <AlertTriangle size={14} />
            <span className="text-[11px]">Medium Risk</span>
          </div>
          <div className="text-2xl font-bold text-amber-500">{data.summary.medium_risk}</div>
        </div>
        <div className="bg-[var(--card)] rounded-xl border border-emerald-500/30 p-4">
          <div className="flex items-center gap-2 text-emerald-500 mb-1">
            <CheckCircle2 size={14} />
            <span className="text-[11px]">Low Risk</span>
          </div>
          <div className="text-2xl font-bold text-emerald-500">{data.summary.low_risk}</div>
        </div>
      </div>

      {/* Source Breakdown Legend */}
      <div className="flex flex-wrap gap-3 text-[11px]">
        {[
          { source: 'entra_risky', label: 'Entra ID / M365', color: '#3b6ef6' },
          { source: 'alerts', label: 'Security Alerts', color: '#f97316' },
          { source: 'external_share', label: 'External Sharing', color: '#ef4444' },
          { source: 'admin_actions', label: 'Admin Actions', color: '#8b5cf6' },
          { source: 'aws_iam', label: 'AWS IAM', color: '#FF9900' },
          { source: 'databricks', label: 'Databricks', color: '#FF3621' },
        ].map(item => (
          <div key={item.source} className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: item.color }} />
            <span className="text-[var(--muted)]">{item.label}</span>
          </div>
        ))}
      </div>

      {/* Users List */}
      <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] overflow-hidden">
        <Table>
          <Thead>
            <Tr>
              <Th></Th>
              <Th>User</Th>
              <Th>Risk Score</Th>
              <Th>Level</Th>
              <Th>Source Breakdown</Th>
            </Tr>
          </Thead>
          <Tbody>
            {data.users.slice(0, 30).map(user => {
              // Aggregate signal contributions by source type
              const sourceColors: Record<string, string> = {
                entra_risky: '#3b6ef6', alerts: '#f97316', external_share: '#ef4444', external_shares: '#ef4444',
                admin_actions: '#8b5cf6', aws_iam: '#FF9900', aws_no_mfa: '#FF9900', aws_multiple_keys: '#FF9900',
                aws_console_no_mfa: '#FF9900', databricks: '#FF3621',
              };
              const sourceLabels: Record<string, string> = {
                entra_risky: 'Entra', alerts: 'Alerts', external_share: 'Shares', external_shares: 'Shares',
                admin_actions: 'Admin', aws_iam: 'IAM', aws_no_mfa: 'No MFA', aws_multiple_keys: 'Multi-Key',
                aws_console_no_mfa: 'Console/No MFA', databricks: 'DB',
              };
              const isExpanded = expandedUser === user.email;
              return (
                <React.Fragment key={user.email}>
                  <Tr 
                    className="cursor-pointer hover:bg-white/5 transition-colors"
                    onClick={async () => {
                      if (isExpanded) {
                        setExpandedUser(null);
                        setUserDetail(null);
                      } else {
                        setExpandedUser(user.email);
                        setDetailLoading(true);
                        try {
                          const { data: detail } = await api.get(`/api/saas/user-risk-details/${encodeURIComponent(user.email)}`);
                          setUserDetail(detail);
                        } catch { setUserDetail(null); }
                        setDetailLoading(false);
                      }
                    }}
                  >
                    <Td className="w-8">
                      <ChevronRight size={14} className={`text-[var(--muted)] transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                    </Td>
                    <Td>
                      <div>
                        <div className="text-[12px] font-medium text-[var(--foreground)]">{user.display_name || user.email}</div>
                        {user.display_name && <div className="text-[10px] text-[var(--muted)]">{user.email}</div>}
                        {user.job_title && <div className="text-[10px] text-[var(--muted)]">{user.job_title}{user.department ? ` • ${user.department}` : ''}</div>}
                      </div>
                    </Td>
                    <Td>
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-2.5 bg-[var(--muted)]/20 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              user.risk_score >= 60 ? 'bg-red-500' :
                              user.risk_score >= 30 ? 'bg-amber-500' :
                              'bg-emerald-500'
                            }`}
                            style={{ width: `${user.risk_score}%` }}
                          />
                        </div>
                        <span className={`text-[12px] font-bold ${
                          user.risk_score >= 60 ? 'text-red-400' :
                          user.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'
                        }`}>{user.risk_score}</span>
                      </div>
                    </Td>
                    <Td>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-medium ${
                        user.risk_level === 'high' ? 'bg-red-500/20 text-red-400' :
                        user.risk_level === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-emerald-500/20 text-emerald-400'
                      }`}>
                        {user.risk_level}
                      </span>
                    </Td>
                    <Td>
                      <div className="flex flex-wrap gap-1">
                        {user.signals.map((s, i) => {
                          const color = sourceColors[s.type] || '#71717a';
                          const label = sourceLabels[s.type] || s.type;
                          return (
                            <span key={i} className="px-1.5 py-0.5 rounded text-[9px] font-medium border"
                              style={{ backgroundColor: color + '20', color, borderColor: color + '40' }}>
                              {label}{s.count ? ` ×${s.count}` : s.severity ? ` (${s.severity})` : ''}
                            </span>
                          );
                        })}
                      </div>
                    </Td>
                  </Tr>
                  {/* Expanded Detail Row */}
                  {isExpanded && (
                    <tr>
                      <td colSpan={5} className="bg-[#0a0a12] p-4 border-t border-white/5">
                        {detailLoading ? (
                          <div className="text-center py-4 text-[var(--muted)] text-[11px]">Loading details...</div>
                        ) : userDetail ? (
                          <>
                          {/* AI Risk Assessment (Claude-generated) */}
                          {userDetail.ai_assessment && (
                            <div className="mb-5 bg-gradient-to-br from-[#3b6ef6]/10 to-[#3b6ef6]/5 border border-[#3b6ef6]/25 rounded-xl p-4">
                              <div className="flex items-start justify-between mb-3">
                                <div className="flex items-center gap-2">
                                  <ShieldCheck size={14} className="text-[#3b6ef6]" />
                                  <span className="text-[12px] font-semibold text-[#3b6ef6] uppercase tracking-wide">AI Risk Assessment</span>
                                </div>
                                {userDetail.ai_assessment.risk_band && (
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                    userDetail.ai_assessment.risk_band === 'critical' ? 'bg-red-500/20 text-red-400' :
                                    userDetail.ai_assessment.risk_band === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                    userDetail.ai_assessment.risk_band === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                                    'bg-emerald-500/20 text-emerald-400'
                                  }`}>{userDetail.ai_assessment.risk_band}{userDetail.ai_assessment.risk_score !== undefined ? ` · ${userDetail.ai_assessment.risk_score}` : ''}</span>
                                )}
                              </div>
                              {userDetail.ai_assessment.headline && (
                                <div className="text-[13px] text-[var(--foreground)] font-medium mb-3">{userDetail.ai_assessment.headline}</div>
                              )}
                              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px]">
                                {userDetail.ai_assessment.key_concerns && userDetail.ai_assessment.key_concerns.length > 0 && (
                                  <div>
                                    <div className="text-[10px] uppercase text-red-400 font-semibold mb-1.5">Key Concerns</div>
                                    <ul className="space-y-1">
                                      {userDetail.ai_assessment.key_concerns.slice(0, 5).map((c, i) => (
                                        <li key={i} className="flex items-start gap-1.5 text-[var(--foreground)]">
                                          <span className="text-red-400 mt-0.5 flex-shrink-0">•</span><span>{c}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                {userDetail.ai_assessment.recommended_actions && userDetail.ai_assessment.recommended_actions.length > 0 && (
                                  <div>
                                    <div className="text-[10px] uppercase text-[#3b6ef6] font-semibold mb-1.5">Recommended Actions</div>
                                    <ul className="space-y-1">
                                      {userDetail.ai_assessment.recommended_actions.slice(0, 5).map((a, i) => (
                                        <li key={i} className="flex items-start gap-1.5 text-[var(--foreground)]">
                                          <span className="text-[#3b6ef6] mt-0.5 flex-shrink-0">{i + 1}.</span><span>{a}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                                {userDetail.ai_assessment.trust_signals && userDetail.ai_assessment.trust_signals.length > 0 && (
                                  <div>
                                    <div className="text-[10px] uppercase text-emerald-400 font-semibold mb-1.5">Trust Signals</div>
                                    <ul className="space-y-1">
                                      {userDetail.ai_assessment.trust_signals.slice(0, 5).map((t, i) => (
                                        <li key={i} className="flex items-start gap-1.5 text-[var(--foreground)]">
                                          <span className="text-emerald-400 mt-0.5 flex-shrink-0">✓</span><span>{t}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                          <div className="grid grid-cols-3 gap-6">
                            {/* Lifecycle & Status */}
                            <div className="space-y-3">
                              <h4 className="text-[11px] font-semibold text-[var(--foreground)] uppercase tracking-wide flex items-center gap-2">
                                <Clock size={12} className="text-cyan-400" /> Lifecycle
                              </h4>
                              <div className="space-y-2 text-[11px]">
                                {userDetail.lifecycle.created_at ? (
                                  <div className="flex justify-between">
                                    <span className="text-[var(--muted)]">Created:</span>
                                    <span className="text-[var(--foreground)]">{new Date(userDetail.lifecycle.created_at).toLocaleDateString()}</span>
                                  </div>
                                ) : null}
                                {userDetail.lifecycle.last_used ? (
                                  <div className="flex justify-between">
                                    <span className="text-[var(--muted)]">Last Used:</span>
                                    <span className="text-[var(--foreground)]">{new Date(userDetail.lifecycle.last_used).toLocaleString()}</span>
                                  </div>
                                ) : null}
                                {userDetail.lifecycle.mfa_enabled !== undefined ? (
                                  <div className="flex justify-between">
                                    <span className="text-[var(--muted)]">MFA:</span>
                                    <span className={userDetail.lifecycle.mfa_enabled ? 'text-emerald-400' : 'text-red-400'}>
                                      {userDetail.lifecycle.mfa_enabled ? '✓ Enabled' : '✗ Disabled'}
                                    </span>
                                  </div>
                                ) : null}
                                {userDetail.lifecycle.console_access !== undefined ? (
                                  <div className="flex justify-between">
                                    <span className="text-[var(--muted)]">Console Access:</span>
                                    <span className="text-[var(--foreground)]">{userDetail.lifecycle.console_access ? 'Yes' : 'No'}</span>
                                  </div>
                                ) : null}
                                {userDetail.lifecycle.access_key_count !== undefined ? (
                                  <div className="flex justify-between">
                                    <span className="text-[var(--muted)]">Access Keys:</span>
                                    <span className="text-[var(--foreground)]">{userDetail.lifecycle.access_key_count}</span>
                                  </div>
                                ) : null}
                                {userDetail.lifecycle.risk_state ? (
                                  <div className="flex justify-between">
                                    <span className="text-[var(--muted)]">Risk State:</span>
                                    <span className="text-amber-400">{userDetail.lifecycle.risk_state}</span>
                                  </div>
                                ) : null}
                              </div>
                              {/* Permissions */}
                              {userDetail.permissions.length > 0 && (
                                <>
                                  <h4 className="text-[11px] font-semibold text-[var(--foreground)] uppercase tracking-wide flex items-center gap-2 mt-4">
                                    <Key size={12} className="text-purple-400" /> Permissions
                                  </h4>
                                  <div className="flex flex-wrap gap-1">
                                    {userDetail.permissions.slice(0, 8).map((p, i) => (
                                      <span key={i} className="px-1.5 py-0.5 rounded text-[9px] bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                        {typeof p === 'string' ? p : (p as Record<string, string>).PolicyName || (p as Record<string, string>).name || 'policy'}
                                      </span>
                                    ))}
                                    {userDetail.permissions.length > 8 && (
                                      <span className="text-[9px] text-[var(--muted)]">+{userDetail.permissions.length - 8} more</span>
                                    )}
                                  </div>
                                </>
                              )}
                            </div>
                            
                            {/* Recent Activity */}
                            <div className="space-y-3">
                              <h4 className="text-[11px] font-semibold text-[var(--foreground)] uppercase tracking-wide flex items-center gap-2">
                                <Activity size={12} className="text-blue-400" /> Recent Activity
                              </h4>
                              {userDetail.recent_activity.length > 0 ? (
                                <div className="space-y-2 max-h-[200px] overflow-auto">
                                  {userDetail.recent_activity.slice(0, 5).map((a, i) => (
                                    <div key={i} className="text-[10px] p-2 bg-black/30 rounded">
                                      <div className="text-[var(--foreground)] font-medium">{a.action}</div>
                                      {a.target && <div className="text-[var(--muted)]">Target: {a.target}</div>}
                                      {a.source_ip && <div className="text-[var(--muted)]">IP: {a.source_ip}</div>}
                                      {a.time && <div className="text-[var(--muted)]">{new Date(a.time).toLocaleString()}</div>}
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <div className="text-[11px] text-[var(--muted)]">No recent activity recorded</div>
                              )}
                            </div>
                            
                            {/* Sign-in Locations & Risk Factors */}
                            <div className="space-y-3">
                              {userDetail.sign_in_locations.length > 0 && (
                                <>
                                  <h4 className="text-[11px] font-semibold text-[var(--foreground)] uppercase tracking-wide flex items-center gap-2">
                                    <Globe size={12} className="text-cyan-400" /> Sign-in Locations
                                  </h4>
                                  <div className="space-y-1">
                                    {userDetail.sign_in_locations.slice(0, 4).map((loc, i) => (
                                      <div key={i} className="text-[10px] flex items-center gap-2">
                                        <span className="font-mono text-cyan-400">{loc.ip}</span>
                                        <span className="text-[var(--muted)]">
                                          {[loc.city, loc.region, loc.country].filter(Boolean).join(', ')}
                                        </span>
                                      </div>
                                    ))}
                                  </div>
                                </>
                              )}
                              {userDetail.risk_factors.length > 0 && (
                                <>
                                  <h4 className="text-[11px] font-semibold text-[var(--foreground)] uppercase tracking-wide flex items-center gap-2 mt-4">
                                    <AlertTriangle size={12} className="text-red-400" /> Risk Factors
                                  </h4>
                                  <div className="space-y-2 max-h-[150px] overflow-auto">
                                    {userDetail.risk_factors.slice(0, 5).map((rf, i) => (
                                      <div key={i} className={`text-[10px] p-2 rounded border ${
                                        rf.severity === 'critical' || rf.severity === 'high' ? 'bg-red-500/10 border-red-500/30' :
                                        rf.severity === 'medium' ? 'bg-amber-500/10 border-amber-500/30' :
                                        'bg-zinc-500/10 border-zinc-500/30'
                                      }`}>
                                        <div className="font-medium text-[var(--foreground)]">{rf.title}</div>
                                        {rf.description && <div className="text-[var(--muted)] truncate">{rf.description}</div>}
                                      </div>
                                    ))}
                                  </div>
                                </>
                              )}
                            </div>
                          </div>
                          </>
                        ) : (
                          <div className="text-center py-4 text-[var(--muted)] text-[11px]">Could not load details</div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </Tbody>
        </Table>
      </div>
    </div>
  );
}

// ── Compliance Tab ───────────────────────────────────────────────────────────

function ComplianceTab() {
  type FrameworkCheck = {
    name: string;
    passed: boolean;
    control_id?: string;
    family?: string;
    resource_count?: number;
    severity_breakdown?: Record<string, number>;
  };
  type AIRemediationControl = {
    control_id?: string;
    citation?: string;
    priority?: string;
    steps?: string[];
  };
  type Framework = {
    name?: string;
    status: string;
    score: number;
    issues: string[];
    checks: FrameworkCheck[];
    discovered_resources?: Record<string, number>;
    failed_controls?: Array<{ control_id?: string; family?: string; finding_count?: number }>;
    ai_remediation?: { controls?: AIRemediationControl[] };
  };
  const [data, setData] = useState<{
    frameworks: Record<string, Framework>;
    overall_score: number;
    critical_issues: Array<{ framework: string; issue: string; severity: string }>;
    resource_inventory?: Record<string, Record<string, number>>;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const { data: result } = await api.get('/api/saas/compliance-status');
        setData(result);
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, []);

  if (loading) return <div className="text-center py-12 text-[var(--muted)]"><RefreshCw className="animate-spin mx-auto" size={24} /></div>;

  if (!data) {
    return (
      <div className="text-center py-16">
        <Shield size={48} className="mx-auto mb-4 text-[var(--muted)]" />
        <h3 className="text-[16px] font-semibold text-[var(--foreground)] mb-2">Compliance Data Unavailable</h3>
        <p className="text-[13px] text-[var(--muted)] max-w-md mx-auto">
          Run a SaaS scan to populate compliance status.
        </p>
      </div>
    );
  }

  const statusColors: Record<string, string> = {
    compliant: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    at_risk: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    non_compliant: 'bg-red-500/20 text-red-400 border-red-500/30',
  };

  const frameworkMeta: Record<string, { icon: string; region: string; color: string }> = {
    'SAMA':     { icon: 'SA',  region: 'Saudi Arabia',  color: '#10b981' },
    'NCA':      { icon: 'NC',  region: 'Saudi Arabia',  color: '#3b6ef6' },
    'ISO27001': { icon: 'IS',  region: 'Global',        color: '#8b5cf6' },
    'SOC2':     { icon: 'S2',  region: 'North America', color: '#f59e0b' },
    'GDPR':     { icon: 'EU',  region: 'Europe',        color: '#06b6d4' },
    'HIPAA':    { icon: 'HC',  region: 'Healthcare',    color: '#ef4444' },
    'PCI-DSS':  { icon: 'PC',  region: 'Global',        color: '#f97316' },
    'PDPL':     { icon: 'PD',  region: 'Saudi Arabia',  color: '#a855f7' },
    'NIST-CSF': { icon: 'NI',  region: 'Global',        color: '#22d3ee' },
  };

  return (
    <div className="space-y-6">
      {/* Overall Score + Radial Chart */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-6 flex flex-col items-center justify-center">
          <svg width="100" height="100" viewBox="0 0 100 100">
            <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
            <circle
              cx="50" cy="50" r="42" fill="none"
              stroke={data.overall_score >= 90 ? '#10b981' : data.overall_score >= 70 ? '#f59e0b' : '#ef4444'}
              strokeWidth="10"
              strokeDasharray={`${(data.overall_score / 100) * 263.9} 263.9`}
              strokeLinecap="round"
              transform="rotate(-90 50 50)"
            />
            <text x="50" y="46" textAnchor="middle" fontSize="18" fontWeight="bold" fill="currentColor" className="fill-[var(--foreground)]">{data.overall_score}%</text>
            <text x="50" y="60" textAnchor="middle" fontSize="8" fill="#71717a">overall</text>
          </svg>
          <h3 className="text-[13px] font-semibold text-[var(--foreground)] mt-2">Compliance Score</h3>
          <p className="text-[11px] text-[var(--muted)] mt-1">Across {Object.keys(data.frameworks).length} frameworks</p>
        </div>
        <div className="col-span-2 grid grid-cols-2 md:grid-cols-3 gap-3">
          {Object.entries(data.frameworks).map(([name, fw]) => {
            const meta = frameworkMeta[name] || { icon: 'FW', region: 'Global', color: '#71717a' };
            const passCount = fw.checks.filter(c => c.passed).length;
            const totalChecks = fw.checks.length;
            return (
              <div key={name} className={`bg-[var(--card)] rounded-xl border p-4 cursor-pointer hover:brightness-110 transition-all ${
                fw.status === 'compliant' ? 'border-emerald-500/30' :
                fw.status === 'at_risk' ? 'border-amber-500/30' : 'border-red-500/30'
              }`} onClick={() => setExpandedFramework(expandedFramework === name ? null : name)}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{meta.icon}</span>
                    <h4 className="text-[13px] font-semibold text-[var(--foreground)]">{name}</h4>
                  </div>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-medium border ${statusColors[fw.status] || statusColors.at_risk}`}>
                    {fw.status.replace('_', ' ')}
                  </span>
                </div>
                <div className="text-[11px] text-[var(--muted)] mb-2">{meta.region}</div>
                {/* Control coverage progress bar */}
                <div className="mb-2">
                  <div className="flex justify-between text-[10px] mb-1">
                    <span className="text-[var(--muted)]">Control Coverage</span>
                    <span style={{ color: meta.color }} className="font-semibold">{fw.score}%</span>
                  </div>
                  <div className="h-2 bg-white/[0.06] rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{ width: `${fw.score}%`, backgroundColor: meta.color }} />
                  </div>
                </div>
                {totalChecks > 0 && (
                  <div className="text-[10px] text-[var(--muted)]">{passCount}/{totalChecks} controls passing</div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Expanded Framework Detail */}
      {expandedFramework && data.frameworks[expandedFramework] && (() => {
        const fw = data.frameworks[expandedFramework];
        const meta = frameworkMeta[expandedFramework] || { icon: '📋', region: 'Global', color: '#71717a' };
        return (
          <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-5">
            <div className="flex items-center gap-3 mb-4">
              <span className="text-2xl">{meta.icon}</span>
              <div>
                <h3 className="text-[15px] font-semibold text-[var(--foreground)]">{expandedFramework} — Control Coverage</h3>
                <p className="text-[11px] text-[var(--muted)]">{meta.region} • {fw.checks.filter(c => c.passed).length}/{fw.checks.length} controls passing</p>
              </div>
              <button className="ml-auto text-[var(--muted)] hover:text-[var(--foreground)]" onClick={() => setExpandedFramework(null)}>
                <X size={16} />
              </button>
            </div>
            {/* Visual control grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-4">
              {fw.checks.map((check, i) => (
                <div key={i} className={`flex items-center gap-2 p-2.5 rounded-lg border ${
                  check.passed ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-red-500/5 border-red-500/20'
                }`}>
                  {check.passed
                    ? <CheckCircle2 size={14} className="text-emerald-500 flex-shrink-0" />
                    : <XCircle size={14} className="text-red-500 flex-shrink-0" />
                  }
                  <span className="text-[12px] text-[var(--foreground)]">{check.name}</span>
                </div>
              ))}
            </div>
            {/* Discovered resources */}
            {fw.discovered_resources && Object.keys(fw.discovered_resources).length > 0 && (
              <div className="mt-3 pt-3 border-t border-[var(--border)]">
                <h4 className="text-[12px] font-semibold text-[var(--muted)] mb-2 uppercase tracking-wide">Discovered Resources</h4>
                <div className="grid grid-cols-3 gap-2 text-[11px]">
                  {Object.entries(fw.discovered_resources).map(([k, v]) => (
                    <div key={k} className="bg-white/[0.03] rounded p-2 border border-white/[0.04]">
                      <div className="text-[9px] uppercase text-[var(--muted)]">{k.replace(/_/g, ' ')}</div>
                      <div className="text-[14px] font-bold text-[var(--foreground)]">{v}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Issues */}
            {fw.issues.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[var(--border)]">
                <h4 className="text-[12px] font-semibold text-amber-400 mb-2">Issues to Address</h4>
                <div className="space-y-1">
                  {fw.issues.map((issue, i) => (
                    <div key={i} className="flex items-start gap-2 text-[11px] text-[var(--muted)]">
                      <span className="text-amber-400 mt-0.5">•</span> {issue}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* AI Remediation */}
            {fw.ai_remediation && fw.ai_remediation.controls && fw.ai_remediation.controls.length > 0 && (
              <div className="mt-3 pt-3 border-t border-[var(--border)]">
                <h4 className="text-[12px] font-semibold text-[#3b6ef6] mb-2 uppercase tracking-wide flex items-center gap-2">
                  <ShieldCheck size={12} /> AI Remediation Plan
                </h4>
                <div className="space-y-3">
                  {fw.ai_remediation.controls.map((ctrl, i) => (
                    <div key={i} className="bg-[#3b6ef6]/5 rounded-lg p-3 border border-[#3b6ef6]/15">
                      <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                        <span className="text-[11px] font-bold text-[#3b6ef6]">{ctrl.control_id || 'Control'}</span>
                        {ctrl.priority && (
                          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                            ctrl.priority === 'P0' ? 'bg-red-500/20 text-red-400' :
                            ctrl.priority === 'P1' ? 'bg-amber-500/20 text-amber-400' :
                            'bg-emerald-500/20 text-emerald-400'
                          }`}>{ctrl.priority}</span>
                        )}
                        {ctrl.citation && (
                          <span className="text-[10px] text-[var(--muted)]">{ctrl.citation}</span>
                        )}
                      </div>
                      {ctrl.steps && ctrl.steps.length > 0 && (
                        <ul className="space-y-1 text-[11px] text-[var(--foreground)]">
                          {ctrl.steps.map((step, j) => (
                            <li key={j} className="flex items-start gap-2">
                              <span className="text-[#3b6ef6] flex-shrink-0">{j + 1}.</span>
                              <span>{step}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })()}

      {/* All Framework Progress Bars */}
      <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] p-5">
        <h3 className="text-[13px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
          <BarChart3 size={14} className="text-[#3b6ef6]" />
          Framework Coverage Overview
        </h3>
        <div className="space-y-4">
          {Object.entries(data.frameworks).map(([name, fw]) => {
            const meta = frameworkMeta[name] || { icon: '📋', region: 'Global', color: '#71717a' };
            const passCount = fw.checks.filter(c => c.passed).length;
            const totalChecks = fw.checks.length;
            return (
              <div key={name}>
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-sm">{meta.icon}</span>
                    <span className="text-[13px] font-medium text-[var(--foreground)]">{name}</span>
                    <span className="text-[10px] text-[var(--muted)]">{meta.region}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-[var(--muted)]">{passCount}/{totalChecks} controls</span>
                    <span className="text-[12px] font-bold" style={{ color: meta.color }}>{fw.score}%</span>
                  </div>
                </div>
                <div className="h-3 bg-white/[0.06] rounded-full overflow-hidden relative">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${fw.score}%`, backgroundColor: meta.color }}
                  />
                  {/* Tick marks every 25% */}
                  {[25, 50, 75].map(tick => (
                    <div key={tick} className="absolute top-0 h-full w-px bg-black/20" style={{ left: `${tick}%` }} />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Critical Issues */}
      {data.critical_issues.length > 0 && (
        <div className="bg-red-500/10 rounded-xl border border-red-500/30 p-4">
          <h3 className="text-[13px] font-semibold text-red-400 mb-3 flex items-center gap-2">
            <AlertTriangle size={14} />
            Critical Compliance Issues
          </h3>
          <div className="space-y-2">
            {data.critical_issues.map((issue, i) => (
              <div key={i} className="flex items-center gap-3 text-[12px]">
                <span className="px-2 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px]">{issue.framework}</span>
                <span className="text-[var(--foreground)]">{issue.issue}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── File Activity Tab ────────────────────────────────────────────────────────

function FileActivityTab() {
  const [activities, setActivities] = useState<Array<{
    id: string; activity_type: string; title: string; description?: string;
    resource_id?: string; resource_name?: string; severity: string;
    provider: string; timestamp?: string;
  }>>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const params = filter ? `?user_email=${filter}` : '';
        const { data } = await api.get(`/api/saas/file-activity${params}`);
        setActivities(data.activities || []);
      } catch { /* ignore */ }
      setLoading(false);
    })();
  }, [filter]);

  if (loading) return <div className="text-center py-12 text-[var(--muted)]"><RefreshCw className="animate-spin mx-auto" size={24} /></div>;

  return (
    <div className="space-y-4">
      {/* Filter */}
      <div className="flex items-center gap-2">
        <input
          type="text"
          placeholder="Filter by user email..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-3 py-2 bg-[var(--card)] border border-[var(--border)] rounded-lg text-[12px] text-[var(--foreground)] w-64"
        />
      </div>

      {activities.length === 0 ? (
        <div className="text-center py-16">
          <FileText size={48} className="mx-auto mb-4 text-[var(--muted)]" />
          <h3 className="text-[16px] font-semibold text-[var(--foreground)] mb-2">No File Activity</h3>
          <p className="text-[13px] text-[var(--muted)] max-w-md mx-auto">
            File activity events will appear here when alerts are generated.
          </p>
        </div>
      ) : (
        <div className="bg-[var(--card)] rounded-xl border border-[var(--border)] overflow-hidden">
          <Table>
            <Thead>
              <Tr>
                <Th>Time</Th>
                <Th>Activity</Th>
                <Th>Resource</Th>
                <Th>Severity</Th>
                <Th>Provider</Th>
              </Tr>
            </Thead>
            <Tbody>
              {activities.slice(0, 50).map(act => (
                <Tr key={act.id}>
                  <Td>
                    <span className="text-[11px] text-[var(--muted)]">
                      {act.timestamp ? new Date(act.timestamp).toLocaleString() : '-'}
                    </span>
                  </Td>
                  <Td>
                    <div>
                      <span className="text-[12px] font-medium text-[var(--foreground)]">{act.title}</span>
                      {act.description && (
                        <p className="text-[10px] text-[var(--muted)] truncate max-w-[300px]">{act.description}</p>
                      )}
                    </div>
                  </Td>
                  <Td>
                    <span className="text-[11px] text-[var(--foreground)] truncate max-w-[150px] block">
                      {act.resource_name || act.resource_id || '-'}
                    </span>
                  </Td>
                  <Td>
                    <span className={`px-2 py-0.5 rounded text-[10px] ${
                      act.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      act.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      act.severity === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                      'bg-[var(--muted)]/20 text-[var(--muted)]'
                    }`}>
                      {act.severity}
                    </span>
                  </Td>
                  <Td><span className="capitalize">{act.provider}</span></Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        </div>
      )}
    </div>
  );
}

// ── Data Residency Tab (World Map + Where Data Lives) ──────────────────────

// World Map component using real map image with data overlays
// Shows: 1) Data storage locations (blue squares), 2) User access locations (colored dots)
// Static world map with marker overlays - no scrolling/interaction
function WorldMap({ 
  regions, 
  dataLocations,
  cloudRegions,
}: { 
  regions: Array<{ lat: number; lng: number; country: string; sign_in_count: number; region: string }>;
  dataLocations?: Array<{ lat: number; lng: number; label: string; type: 'storage' | 'access' }>;
  cloudRegions?: Array<{ provider: string; region: string; lat?: number; lng?: number; resource_count?: number }>;
}) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<unknown>(null);

  // Filter out invalid coordinates (lat=0, lng=0 means unknown/ocean)
  const validRegions = regions.filter(r => r.lat !== 0 || r.lng !== 0);
  const validDataLocations = dataLocations?.filter(d => d.lat !== 0 || d.lng !== 0) || [];
  const validCloudRegions = cloudRegions?.filter(cr => cr.lat && cr.lng && (cr.lat !== 0 || cr.lng !== 0) && (cr.resource_count || 0) > 0) || [];

  // Region colors
  const regionColors: Record<string, string> = {
    'North America': '#3b6ef6',
    'Europe': '#10b981',
    'Asia Pacific': '#f59e0b',
    'Middle East': '#ef4444',
    'South America': '#8b5cf6',
    'Africa': '#ec4899',
    'Unknown': '#6b7280',
  };

  useEffect(() => {
    let cancelled = false;
    let resizeObserver: ResizeObserver | null = null;

    // jsvectormap needs a non-zero container before it draws. If the
    // panel is mounted while a parent is still laying out (e.g. tab
    // swap, initial paint with skeletons), the SVG is created with
    // width=0 and never recovers. Wait until the container actually
    // has size, then re-init on every resize.
    const initMap = async () => {
      if (cancelled || !mapRef.current || typeof window === 'undefined') return;
      const rect = mapRef.current.getBoundingClientRect();
      if (rect.width < 50 || rect.height < 50) {
        // Try again on the next frame — a parent is still sizing us.
        requestAnimationFrame(initMap);
        return;
      }

      // Import jsvectormap and the world map (client-side only)
      const jsVectorMap = (await import('jsvectormap')).default;
      await import('jsvectormap/dist/maps/world');
      await import('jsvectormap/dist/jsvectormap.css');
      if (cancelled || !mapRef.current) return;

      // Destroy existing map if any
      if (mapInstanceRef.current) {
        try {
          (mapInstanceRef.current as { destroy: () => void }).destroy();
        } catch {
          /* already destroyed */
        }
        mapInstanceRef.current = null;
      }
      // Clear any leftover SVG nodes that jsvectormap left behind
      while (mapRef.current.firstChild) {
        mapRef.current.removeChild(mapRef.current.firstChild);
      }

      // Build markers array with marker type for styling.
      //
      // 2026-06-17: Adnan asked for the map to be simplified — use ONE
      // blue marker for any resource (M365 / AWS / GCP / Databricks /
      // GitHub / SAP / Oracle / Azure) and a different colour only for
      // user activity (humans signing in). Helps focus on "where is my
      // data" without per-provider colour soup.
      const markers: Array<{ name: string; coords: [number, number] }> = [];
      const markerStyles: Array<{ fill: string; stroke?: string; r?: number }> = [];

      const RESOURCE_FILL = '#3b6ef6';   // single blue for all resources
      const RESOURCE_STROKE = '#60a5fa';
      const ACTIVITY_FILL = '#10b981';   // green for human sign-in locations

      // De-dupe by coordinate so two providers in the same datacenter
      // don't render as two stacked dots.
      const seen = new Map<string, { count: number; labels: string[] }>();
      const addResource = (lat: number, lng: number, label: string, count: number) => {
        const key = `${lat.toFixed(2)}_${lng.toFixed(2)}`;
        const cur = seen.get(key);
        if (cur) {
          cur.count += count;
          cur.labels.push(label);
        } else {
          seen.set(key, { count, labels: [label] });
        }
      };

      // 1. M365 storage locations
      validDataLocations.filter(d => d.type === 'storage').forEach(loc => {
        addResource(loc.lat, loc.lng, loc.label, 1);
      });

      // 2. All cloud / connector regions (AWS, GCP, Databricks, GitHub,
      //    SAP, Oracle, Azure — backend returns them all in cloud_regions).
      validCloudRegions.forEach(cr => {
        addResource(
          cr.lat!,
          cr.lng!,
          `${cr.provider} · ${cr.region} · ${cr.resource_count} resources`,
          cr.resource_count || 1,
        );
      });

      // Flush de-duped resource markers to the map.
      for (const [key, info] of seen.entries()) {
        const [latStr, lngStr] = key.split('_');
        const r = Math.min(Math.max(4 + Math.sqrt(info.count) * 0.6, 5), 11);
        markers.push({
          name: info.labels.join('\n'),
          coords: [parseFloat(latStr), parseFloat(lngStr)],
        });
        markerStyles.push({ fill: RESOURCE_FILL, stroke: RESOURCE_STROKE, r });
      }

      // 3. User activity regions — separate colour so people can still
      //    distinguish "where my users log in from" vs "where my data lives".
      validRegions.forEach(region => {
        const size = Math.min(Math.max(Math.sqrt(region.sign_in_count) * 0.8, 4), 10);
        markers.push({
          name: `${region.country} · ${region.sign_in_count} sign-ins`,
          coords: [region.lat, region.lng],
        });
        markerStyles.push({ fill: ACTIVITY_FILL, r: size });
      });

      // Create the map
      mapInstanceRef.current = new jsVectorMap({
        selector: mapRef.current,
        map: 'world',
        backgroundColor: '#080810',
        draggable: false,
        zoomButtons: false,
        zoomOnScroll: false,
        zoomOnScrollSpeed: 1,
        zoomMax: 1,
        zoomMin: 1,
        showTooltip: true,
        regionStyle: {
          initial: {
            fill: '#1a1a2e',
            fillOpacity: 1,
            stroke: '#2a2a3e',
            strokeWidth: 0.5,
            strokeOpacity: 1,
          },
          hover: {
            fillOpacity: 0.8,
            cursor: 'default',
          },
        },
        markerStyle: {
          initial: {
            fill: '#3b6ef6',
            fillOpacity: 1,
            stroke: '#fff',
            strokeWidth: 2,
            strokeOpacity: 0.8,
            r: 6,
          },
          hover: {
            fillOpacity: 0.8,
            cursor: 'pointer',
          },
        },
        markers: markers.map((m, idx) => ({
          ...m,
          style: markerStyles[idx],
        })),
        onMarkerTooltipShow: (tooltip: { text: () => string; selector: { innerHTML: string } }, index: number) => {
          const marker = markers[index];
          if (marker) {
            tooltip.selector.innerHTML = `<div class="text-xs font-medium">${marker.name}</div>`;
          }
        },
      });
    };

    initMap();

    // Re-init if the container is resized later (parent finally lays
    // us out, sidebar collapses, etc.). This is what fixes the
    // "have to reload to see the map" bug.
    if (mapRef.current && typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
          const { width, height } = entry.contentRect;
          if (width > 50 && height > 50 && !mapInstanceRef.current) {
            // Container became visible after the first init no-op; draw now.
            initMap();
          }
        }
      });
      resizeObserver.observe(mapRef.current);
    }

    return () => {
      cancelled = true;
      if (resizeObserver) {
        try { resizeObserver.disconnect(); } catch { /* noop */ }
      }
      if (mapInstanceRef.current) {
        try {
          (mapInstanceRef.current as { destroy: () => void }).destroy();
        } catch { /* noop */ }
        mapInstanceRef.current = null;
      }
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [validRegions.length, validDataLocations.length, validCloudRegions.length]);

  return (
    <div className="relative w-full rounded-xl border border-white/[0.08] overflow-hidden bg-[#080810]">
      {/* JSVectorMap container */}
      <div 
        ref={mapRef} 
        className="w-full" 
        style={{ height: '320px' }}
      />

      {/* Legend — unified: one entry for Resources (any connector), one
          for User Activity (humans signing in). Adnan asked for this
          simplification so the legend doesn't carry per-provider colour
          soup that confuses people. */}
      <div className="absolute bottom-3 left-3 flex items-center gap-4 bg-black/80 backdrop-blur-sm px-3 py-2 rounded-lg border border-white/10 z-10">
        {(validDataLocations.filter(d => d.type === 'storage').length > 0 || validCloudRegions.length > 0) && (
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 bg-[#3b6ef6] rounded-full border border-[#60a5fa]/60" />
            <span className="text-[10px] text-white/80">Resources</span>
          </div>
        )}
        {validRegions.length > 0 && (
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 bg-[#10b981] rounded-full" />
            <span className="text-[10px] text-white/80">User Activity</span>
          </div>
        )}
      </div>
      
      {/* Title */}
      <div className="absolute top-3 left-3 bg-black/70 backdrop-blur-sm px-3 py-1.5 rounded-lg border border-white/10">
        <div className="text-[12px] font-semibold text-white">Data Residency Map</div>
        <div className="text-[9px] text-white/50">Storage locations & access patterns</div>
      </div>

      {/* Stats */}
      <div className="absolute top-3 right-3 bg-black/70 backdrop-blur-sm px-3 py-2 rounded-lg border border-white/10 text-right">
        {validRegions.length > 0 && (
          <div className="text-[12px] text-white">
            <span className="font-bold">{validRegions.reduce((sum, r) => sum + r.sign_in_count, 0).toLocaleString()}</span>
            <span className="text-white/60 ml-1">sign-ins</span>
          </div>
        )}
        {validCloudRegions.length > 0 && (
          <div className="text-[12px] text-[#FF9900]">
            <span className="font-bold">{validCloudRegions.reduce((sum, cr) => sum + (cr.resource_count || 0), 0).toLocaleString()}</span>
            <span className="text-[#FF9900]/60 ml-1">cloud resources</span>
          </div>
        )}
        {validDataLocations.length > 0 && (
          <div className="text-[12px] text-cyan-400">
            <span className="font-bold">{validDataLocations.filter(d => d.type === 'storage').length}</span>
            <span className="text-cyan-400/60 ml-1">data stores</span>
          </div>
        )}
      </div>
    </div>
  );
}

// Expandable Data Storage Locations Panel
function DataStorageLocationsPanel({ locations }: { locations: Array<{ name: string; type: string; region: string; url?: string }> }) {
  const [expanded, setExpanded] = useState(false);
  const displayCount = expanded ? locations.length : 8;
  const hasMore = locations.length > 8;

  return (
    <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
      <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
        <Database size={14} className="text-cyan-400" />
        Data Storage Locations
        <span className="text-[11px] font-normal text-[var(--muted)] ml-auto">{locations.length} total</span>
      </h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {locations.slice(0, displayCount).map((loc, i) => (
          <div key={i} className="flex items-center gap-3 p-2.5 bg-white/[0.02] rounded-lg border border-white/[0.04] hover:border-white/[0.08] transition-colors">
            <div className={`w-7 h-7 rounded flex items-center justify-center flex-shrink-0 ${
              loc.type === 'AWS' ? 'bg-[#FF9900]/20' : 
              loc.type === 'SharePoint' ? 'bg-blue-500/20' : 
              'bg-cyan-500/20'
            }`}>
              {loc.type === 'AWS' ? <AWSLogo size={14} /> : 
               loc.type === 'SharePoint' ? <SharePointIcon size={14} /> : 
               <Database size={12} className="text-cyan-400" />}
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[11px] font-medium text-[var(--foreground)] truncate">{loc.name}</div>
              <div className="text-[9px] text-[var(--muted)]">{loc.type} • {loc.region}</div>
            </div>
          </div>
        ))}
      </div>
      {hasMore && (
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full mt-3 py-2 px-3 bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.06] rounded-lg text-[11px] text-[var(--muted)] hover:text-[var(--foreground)] transition-colors flex items-center justify-center gap-1.5"
        >
          {expanded ? (
            <>
              <ChevronUp size={14} />
              Show less
            </>
          ) : (
            <>
              <ChevronDown size={14} />
              Show {locations.length - 8} more locations
            </>
          )}
        </button>
      )}
    </div>
  );
}

function DataResidencyTab() {
  const [data, setData] = useState<DataResidencyInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const { data: res } = await api.get('/api/saas/data-residency');
        setData(res);
      } catch (e) {
        console.error('Failed to load data residency:', e);
      }
      setLoading(false);
    })();
  }, []);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-[300px] bg-white/[0.03] rounded-xl animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map(i => <div key={i} className="h-32 bg-white/[0.03] rounded-xl animate-pulse" />)}
        </div>
      </div>
    );
  }

  const regionColors: Record<string, string> = {
    'North America': '#3b6ef6',
    'Europe': '#10b981',
    'Asia Pacific': '#f59e0b',
    'Middle East': '#ef4444',
    'South America': '#8b5cf6',
    'Africa': '#ec4899',
  };

  const totalSignIns = data?.user_activity_regions?.reduce((sum, r) => sum + r.sign_in_count, 0) || 0;

  // Build data storage locations from tenant info
  // Comprehensive M365/Azure datacenter locations with country codes AND region names
  const msDatacenters: Record<string, { lat: number; lng: number }> = {
    // Country codes (2-letter ISO)
    'US': { lat: 37.0902, lng: -95.7129 },
    'CA': { lat: 45.4215, lng: -75.6972 },
    'MX': { lat: 23.6345, lng: -102.5528 },
    'GB': { lat: 51.5074, lng: -0.1278 },
    'UK': { lat: 51.5074, lng: -0.1278 },
    'DE': { lat: 50.1109, lng: 8.6821 },
    'FR': { lat: 48.8566, lng: 2.3522 },
    'NL': { lat: 52.3676, lng: 4.9041 },
    'IE': { lat: 53.3498, lng: -6.2603 },
    'SE': { lat: 59.3293, lng: 18.0686 },
    'NO': { lat: 59.9139, lng: 10.7522 },
    'DK': { lat: 55.6761, lng: 12.5683 },
    'FI': { lat: 60.1699, lng: 24.9384 },
    'CH': { lat: 47.3769, lng: 8.5417 },
    'AT': { lat: 48.2082, lng: 16.3738 },
    'BE': { lat: 50.8503, lng: 4.3517 },
    'IT': { lat: 41.9028, lng: 12.4964 },
    'ES': { lat: 40.4168, lng: -3.7038 },
    'PT': { lat: 38.7223, lng: -9.1393 },
    'PL': { lat: 52.2297, lng: 21.0122 },
    'AE': { lat: 25.2048, lng: 55.2708 },
    'SA': { lat: 24.7136, lng: 46.6753 },
    'QA': { lat: 25.2854, lng: 51.5310 },
    'KW': { lat: 29.3759, lng: 47.9774 },
    'BH': { lat: 26.0667, lng: 50.5577 },
    'AU': { lat: -33.8688, lng: 151.2093 },
    'JP': { lat: 35.6762, lng: 139.6503 },
    'SG': { lat: 1.3521, lng: 103.8198 },
    'IN': { lat: 19.0760, lng: 72.8777 },
    'KR': { lat: 37.5665, lng: 126.9780 },
    'HK': { lat: 22.3193, lng: 114.1694 },
    'NZ': { lat: -41.2866, lng: 174.7756 },
    'BR': { lat: -23.5505, lng: -46.6333 },
    'AR': { lat: -34.6037, lng: -58.3816 },
    'ZA': { lat: -33.9249, lng: 18.4241 },
    // Region name aliases
    'United States': { lat: 37.0902, lng: -95.7129 },
    'North America': { lat: 39.0438, lng: -77.4874 },
    'NAM': { lat: 39.0438, lng: -77.4874 },
    'EUR': { lat: 52.3676, lng: 4.9041 },
    'Europe': { lat: 52.3676, lng: 4.9041 },
    'GBR': { lat: 51.5074, lng: -0.1278 },
    'DEU': { lat: 50.1109, lng: 8.6821 },
    'APC': { lat: 1.3521, lng: 103.8198 },
    'Asia Pacific': { lat: 1.3521, lng: 103.8198 },
    'JPN': { lat: 35.6762, lng: 139.6503 },
    'AUS': { lat: -33.8688, lng: 151.2093 },
    'IND': { lat: 19.0760, lng: 72.8777 },
    'BRA': { lat: -23.5505, lng: -46.6333 },
    'South America': { lat: -23.5505, lng: -46.6333 },
    'Middle East': { lat: 25.2048, lng: 55.2708 },
    'CAN': { lat: 45.4215, lng: -75.6972 },
    'FRA': { lat: 48.8566, lng: 2.3522 },
    'CHE': { lat: 47.3769, lng: 8.5417 },
    'KOR': { lat: 37.5665, lng: 126.9780 },
    'ZAF': { lat: -33.9249, lng: 18.4241 },
    'ARE': { lat: 25.2048, lng: 55.2708 },
    'Africa': { lat: -26.2041, lng: 28.0473 },
  };

  const dataLocations: Array<{ lat: number; lng: number; label: string; type: 'storage' | 'access' }> = [];
  
  // Try multiple fields for tenant location
  const tenantRegion = data?.tenant_region || '';
  const tenantCountry = data?.tenant_country || '';
  const primaryRegion = data?.primary_data_region || '';
  
  // Add M365 tenant storage location
  const tenantKey = tenantCountry || tenantRegion;
  if (tenantKey && msDatacenters[tenantKey]) {
    dataLocations.push({ 
      ...msDatacenters[tenantKey], 
      label: `M365 Tenant (${tenantKey})`, 
      type: 'storage' 
    });
  } else if (tenantKey) {
    // Try to find a matching datacenter by partial match
    const match = Object.entries(msDatacenters).find(([k]) => 
      tenantKey.toLowerCase().includes(k.toLowerCase()) || k.toLowerCase().includes(tenantKey.toLowerCase())
    );
    if (match && (match[1].lat !== 0 || match[1].lng !== 0)) {
      dataLocations.push({ ...match[1], label: `M365 Tenant (${tenantKey})`, type: 'storage' });
    }
  }
  
  // Add SharePoint sites as data locations if available (deduplicated)
  const addedRegions = new Set<string>();
  if (data?.data_locations) {
    data.data_locations.forEach((loc: { region?: string; url?: string; name?: string; type?: string }) => {
      const region = loc.region || '';
      // Skip if we already added this region or if it's AWS (handled separately)
      if (addedRegions.has(region) || loc.type === 'AWS') return;
      if (region && msDatacenters[region] && (msDatacenters[region].lat !== 0 || msDatacenters[region].lng !== 0)) {
        dataLocations.push({ ...msDatacenters[region], label: `SharePoint (${region})`, type: 'storage' });
        addedRegions.add(region);
      }
    });
  }

  // Compute connected providers for summary
  const connectedProviders = ['M365'];
  if (data?.cloud_regions && data.cloud_regions.length > 0) {
    const uniqueProviders = [...new Set(data.cloud_regions.filter(cr => (cr.resource_count || 0) > 0).map(cr => cr.provider))];
    connectedProviders.push(...uniqueProviders);
  }
  
  // Count resources by region for the "Activity by Region" section
  // Include both user sign-ins AND cloud resources
  const regionSummaryWithCloud: Record<string, number> = { ...(data?.region_summary || {}) };
  
  // Map AWS/GCP region codes to geographic regions
  const awsRegionToGeo: Record<string, string> = {
    'us-east-1': 'North America', 'us-east-2': 'North America', 'us-west-1': 'North America', 'us-west-2': 'North America',
    'eu-west-1': 'Europe', 'eu-west-2': 'Europe', 'eu-west-3': 'Europe', 'eu-central-1': 'Europe', 'eu-north-1': 'Europe', 'eu-south-1': 'Europe',
    'ap-northeast-1': 'Asia Pacific', 'ap-northeast-2': 'Asia Pacific', 'ap-northeast-3': 'Asia Pacific',
    'ap-southeast-1': 'Asia Pacific', 'ap-southeast-2': 'Asia Pacific', 'ap-southeast-3': 'Asia Pacific',
    'ap-south-1': 'Asia Pacific', 'ap-east-1': 'Asia Pacific',
    'sa-east-1': 'South America',
    'me-south-1': 'Middle East', 'me-central-1': 'Middle East',
    'af-south-1': 'Africa',
    'ca-central-1': 'North America',
  };
  
  if (data?.cloud_regions) {
    data.cloud_regions.forEach((cr: { provider: string; region: string; resource_count?: number }) => {
      if (cr.resource_count && cr.resource_count > 0) {
        const geoRegion = awsRegionToGeo[cr.region];
        if (geoRegion && geoRegion !== 'Unknown') {
          // Add resource count to the geographic region
          regionSummaryWithCloud[geoRegion] = (regionSummaryWithCloud[geoRegion] || 0) + cr.resource_count;
        }
      }
    });
  }

  return (
    <div className="space-y-6">
      {/* Hero Section - Primary Data Region */}
      <div className="bg-[#13131a] border border-white/[0.08] rounded-xl p-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-[#3b6ef6]/15 border border-[#3b6ef6]/25 flex items-center justify-center">
              <Globe size={22} className="text-[#3b6ef6]" />
            </div>
            <div>
              <div className="text-[11px] text-[var(--muted)] uppercase tracking-wide mb-0.5">Primary Data Region</div>
              <h2 className="text-[18px] font-semibold text-[var(--foreground)]">
                {data?.primary_data_region || data?.tenant_region || data?.tenant_country || 'Unknown'}
              </h2>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {connectedProviders.map((p, i) => (
              <span 
                key={i}
                className={`px-2.5 py-1 rounded-lg text-[10px] font-semibold border ${
                  p === 'AWS' ? 'bg-[#FF9900]/10 border-[#FF9900]/25 text-[#FF9900]' :
                  p === 'GCP' ? 'bg-[#4285F4]/10 border-[#4285F4]/25 text-[#4285F4]' :
                  'bg-blue-500/10 border-blue-500/25 text-blue-400'
                }`}
              >
                {p}
              </span>
            ))}
          </div>
        </div>
        {data?.tenant_country && data.tenant_country !== data?.primary_data_region && (
          <div className="mt-3 pt-3 border-t border-white/[0.06] text-[11px] text-[var(--muted)]">
            M365 tenant country: <span className="text-[var(--foreground)]">{data.tenant_country}</span>
          </div>
        )}
      </div>

      {/* World Map */}
      <WorldMap 
        regions={data?.user_activity_regions || []} 
        dataLocations={dataLocations}
        cloudRegions={data?.cloud_regions?.filter(cr => cr.lat && cr.lng) || []}
      />

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Sign-ins */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Activity size={14} className="text-[#3b6ef6]" />
            <span className="text-[11px] text-[var(--muted)] uppercase tracking-wide">Total Sign-ins</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">
            {totalSignIns.toLocaleString()}
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-1">
            Across {data?.user_activity_regions?.length || 0} countries
          </div>
        </div>

        {/* Top Region */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp size={14} className="text-emerald-400" />
            <span className="text-[11px] text-[var(--muted)] uppercase tracking-wide">Top Region</span>
          </div>
          <div className="text-xl font-bold text-[var(--foreground)]">
            {Object.entries(regionSummaryWithCloud).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1])[0]?.[0] || 'N/A'}
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-1">
            {Object.entries(regionSummaryWithCloud).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1])[0]?.[1]?.toLocaleString() || 0} sign-ins
          </div>
        </div>

        {/* Data Locations */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Database size={14} className="text-amber-400" />
            <span className="text-[11px] text-[var(--muted)] uppercase tracking-wide">Data Locations</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">
            {data?.data_locations?.length || 0}
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-1">
            SharePoint sites & data stores
          </div>
        </div>

        {/* Compliance */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle2 size={14} className="text-purple-400" />
            <span className="text-[11px] text-[var(--muted)] uppercase tracking-wide">Regulations</span>
          </div>
          <div className="text-2xl font-bold text-[var(--foreground)]">
            {data?.compliance_regions?.length || 0}
          </div>
          <div className="text-[10px] text-[var(--muted)] mt-1">
            Applicable frameworks
          </div>
        </div>
      </div>

      {/* Regional Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Region Distribution */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <BarChart3 size={14} className="text-[#3b6ef6]" />
            Activity by Region
          </h3>
          {Object.entries(regionSummaryWithCloud).filter(([, v]) => v > 0).length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-[var(--muted)]">
              <Globe size={24} className="mb-2 opacity-50" />
              <p className="text-[12px]">No regional activity data available yet.</p>
              <p className="text-[10px] mt-1">Connect workspaces to see geographic distribution.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {Object.entries(regionSummaryWithCloud).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).map(([region, count]) => {
                const pct = totalSignIns > 0 ? (count / totalSignIns) * 100 : 0;
                const color = regionColors[region] || '#6b7280';
                return (
                  <div key={region}>
                    <div className="flex items-center justify-between text-[12px] mb-1">
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                        <span className="text-[var(--foreground)]">{region}</span>
                      </div>
                      <span className="text-[var(--muted)]">{count.toLocaleString()} ({pct.toFixed(1)}%)</span>
                    </div>
                    <div className="h-2 bg-white/[0.05] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-500"
                        style={{ width: `${pct}%`, backgroundColor: color }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Compliance Frameworks */}
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <Shield size={14} className="text-emerald-400" />
            Applicable Compliance Frameworks
          </h3>
          {(data?.compliance_regions?.length || 0) === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-[var(--muted)]">
              <Info size={24} className="mb-2 opacity-50" />
              <p className="text-[12px]">No compliance frameworks identified for this region.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {data?.compliance_regions?.map((comp, i) => (
                <div key={i} className="flex items-center justify-between p-3 bg-white/[0.03] rounded-lg border border-white/[0.05]">
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                      comp.status === 'applicable' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                    }`}>
                      {comp.status === 'applicable' ? <CheckCircle2 size={16} /> : <AlertTriangle size={16} />}
                    </div>
                    <div>
                      <div className="text-[12px] font-medium text-[var(--foreground)]">{comp.regulation}</div>
                      <div className="text-[10px] text-[var(--muted)]">{comp.region}</div>
                    </div>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded ${
                    comp.status === 'applicable' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'
                  }`}>
                    {comp.status === 'applicable' ? 'Applicable' : 'Review Required'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Cloud Infrastructure Resources by Region */}
      {data?.cloud_regions && data.cloud_regions.filter(cr => (cr.resource_count || 0) > 0).length > 0 && (
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <Server size={14} className="text-[#FF9900]" />
            Cloud Infrastructure by Region
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {data.cloud_regions.filter(cr => (cr.resource_count || 0) > 0).sort((a, b) => (b.resource_count || 0) - (a.resource_count || 0)).slice(0, 6).map((cr, i) => {
              const color = cr.provider === 'AWS' ? '#FF9900' : cr.provider === 'GCP' ? '#4285F4' : '#10b981';
              return (
                <div key={i} className="flex items-center justify-between p-3 bg-white/[0.03] rounded-lg border border-white/[0.05]">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: color + '20' }}>
                      {cr.provider === 'AWS' ? <AWSLogo size={16} /> : <Cloud size={16} style={{ color }} />}
                    </div>
                    <div>
                      <div className="text-[12px] font-medium text-[var(--foreground)]">{cr.region}</div>
                      <div className="text-[10px] text-[var(--muted)]">{cr.provider}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-[14px] font-semibold" style={{ color }}>{cr.resource_count?.toLocaleString()}</div>
                    <div className="text-[9px] text-[var(--muted)]">resources</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Data Storage Locations */}
      {data?.data_locations && data.data_locations.length > 0 && (
        <DataStorageLocationsPanel locations={data.data_locations} />
      )}

      {/* External Sharing Summary */}
      {data?.external_sharing_by_region && data.external_sharing_by_region.length > 0 && (
        <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
            <Users size={14} className="text-purple-400" />
            External Sharing
          </h3>
          <div className="space-y-2">
            {data.external_sharing_by_region.map((share: { region: string; count: number }, i) => (
              <div key={i} className="flex items-center justify-between p-2 bg-white/[0.02] rounded-lg">
                <span className="text-[12px] text-[var(--foreground)]">{share.region}</span>
                <span className="text-[12px] font-medium text-purple-400">{share.count} share{share.count !== 1 ? 's' : ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Countries Table */}
      <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-5">
        <h3 className="text-[14px] font-semibold text-[var(--foreground)] mb-4 flex items-center gap-2">
          <Globe size={14} className="text-[#3b6ef6]" />
          User Activity by Country
        </h3>
        {(data?.user_activity_regions?.length || 0) === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-[var(--muted)]">
            <Globe size={24} className="mb-2 opacity-50" />
            <p className="text-[12px]">No user activity data available.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <Thead>
                <Tr>
                  <Th>Country</Th>
                  <Th>Region</Th>
                  <Th>Sign-ins</Th>
                  <Th>Share</Th>
                </Tr>
              </Thead>
              <Tbody>
                {data?.user_activity_regions?.slice(0, 10).map((r, i) => {
                  const pct = totalSignIns > 0 ? (r.sign_in_count / totalSignIns) * 100 : 0;
                  const color = regionColors[r.region] || '#6b7280';
                  return (
                    <Tr key={i}>
                      <Td>
                        <div className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                          <span className="text-[12px] font-medium text-[var(--foreground)]">{r.country}</span>
                          <span className="text-[10px] text-[var(--muted)]">({r.country_code})</span>
                        </div>
                      </Td>
                      <Td><span className="text-[12px] text-[var(--muted)]">{r.region}</span></Td>
                      <Td><span className="text-[12px] text-[var(--foreground)] font-medium">{r.sign_in_count.toLocaleString()}</span></Td>
                      <Td>
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
                            <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
                          </div>
                          <span className="text-[10px] text-[var(--muted)]">{pct.toFixed(1)}%</span>
                        </div>
                      </Td>
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Governance Tab ─────────────────────────────────────────────────────────────

type GovernanceSubTab = 'external-users' | 'conditional-access' | 'teams-apps' | 'meeting-security' | 'dlp';

interface ExternalUser {
  id: string;
  // Backend uses snake_case keys; we mirror them here so the panel works
  // off the real /api/saas/external-users response. Old camelCase keys
  // (displayName, lastSignIn, daysSinceActivity, riskLevel, riskReasons)
  // are kept as optional aliases to ease the migration.
  display_name?: string;
  email: string;
  external_state?: string;
  created_at?: string;
  last_sign_in?: string | null;
  days_inactive?: number | null;
  is_stale?: boolean;
  risk_indicators?: string[];
  teams_access?: string[];
  sharepoint_access?: string[];
  // Legacy camelCase aliases (some callers still set them)
  displayName?: string;
  createdDateTime?: string;
  lastSignIn?: string;
  daysSinceActivity?: number;
  teamsAccess?: string[];
  sharepointAccess?: string[];
  riskLevel?: 'low' | 'medium' | 'high';
  riskReasons?: string[];
}

interface ExternalInteraction {
  id: string;
  email: string;
  display_name: string;
  interaction_type: 'meeting_attendee' | 'file_share' | 'chat_member' | 'audit_event';
  organizer: string;
  event_time?: string | null;
  risk: string;
  detail: string;
}

interface CAPolicy {
  id: string;
  displayName: string;
  state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced';
  conditions: {
    users?: { includeUsers?: string[]; excludeUsers?: string[] };
    applications?: { includeApplications?: string[] };
    locations?: { includeLocations?: string[] };
    signInRiskLevels?: string[];
    userRiskLevels?: string[];
  };
  grantControls?: {
    builtInControls?: string[];
  };
  createdDateTime?: string;
  modifiedDateTime?: string;
}

interface BlockedSignIn {
  id: string;
  userPrincipalName: string;
  ipAddress: string;
  location?: { city?: string; countryOrRegion?: string };
  clientAppUsed: string;
  conditionalAccessStatus: string;
  appliedPolicies: string[];
  createdDateTime: string;
}

interface TeamsApp {
  id: string;
  display_name: string;
  short_description?: string;
  publisher?: string;
  version?: string;
  distribution_method: string;
  external_id?: string;
  install_count: number;
  install_scopes?: string[];   // ['team'] / ['user'] / both
  permissions: Array<string | { id?: string }>;
  permission_count?: number;
  risk_level: 'low' | 'medium' | 'high';
  risk_factors?: string[];
  certification?: string;
  isBlocked?: boolean;
}

function GovernanceTab() {
  const [subTab, setSubTab] = useState<GovernanceSubTab>('external-users');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // External Users state
  const [externalUsers, setExternalUsers] = useState<ExternalUser[]>([]);
  const [externalUsersTotal, setExternalUsersTotal] = useState(0);
  const [externalUsersFilter, setExternalUsersFilter] = useState<'all' | 'stale' | 'high-risk'>('all');
  const [externalInteractions, setExternalInteractions] = useState<ExternalInteraction[]>([]);
  
  // CA Policies state
  const [caPolicies, setCaPolicies] = useState<CAPolicy[]>([]);
  const [blockedSignIns, setBlockedSignIns] = useState<BlockedSignIn[]>([]);
  const [caGaps, setCaGaps] = useState<string[]>([]);
  const [multiCloudControls, setMultiCloudControls] = useState<Array<{
    cloud: string;
    cloud_label: string;
    control_name: string;
    status: 'healthy' | 'partial' | 'missing';
    summary: string;
  }>>([]);
  
  // Teams Apps state
  const [teamsApps, setTeamsApps] = useState<TeamsApp[]>([]);
  const [teamsAppsFilter, setTeamsAppsFilter] = useState<'all' | 'risky' | 'blocked'>('all');
  
  // Load data based on subtab
  const loadExternalUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (externalUsersFilter !== 'all') params.append('filter', externalUsersFilter);
      const res = await api.get(`/api/saas/external-users?${params}`);
      // Backend returns `items` (guest users) AND `external_interactions`
      // (ad-hoc meeting attendees / file recipients / chat members).
      setExternalUsers(res.data?.items ?? res.data?.users ?? []);
      setExternalUsersTotal(res.data?.total ?? 0);
      setExternalInteractions(res.data?.external_interactions ?? []);
    } catch (e: unknown) {
      const err = e as { response?: { status?: number } };
      if (err.response?.status === 403) {
        setError('Requires User.Read.All permission in Microsoft Graph');
      } else {
        setError('Failed to load external users');
      }
    } finally {
      setLoading(false);
    }
  }, [externalUsersFilter]);
  
  const loadCAPolicies = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [policiesRes, signInsRes, gapsRes, mcRes] = await Promise.all([
        api.get('/api/saas/conditional-access/policies'),
        api.get('/api/saas/conditional-access/blocked-signins?limit=50'),
        api.get('/api/saas/conditional-access/gaps'),
        api.get('/api/saas/conditional-access/multi-cloud').catch(() => ({ data: { controls: [] } })),
      ]);
      setCaPolicies(policiesRes.data?.policies ?? []);
      setBlockedSignIns(signInsRes.data?.blocked_signins ?? []);
      setCaGaps(gapsRes.data?.gaps ?? []);
      setMultiCloudControls(mcRes.data?.controls ?? []);
    } catch (e: unknown) {
      const err = e as { response?: { status?: number } };
      if (err.response?.status === 403) {
        setError('Requires Policy.Read.All permission in Microsoft Graph');
      } else {
        setError('Failed to load Conditional Access data');
      }
    } finally {
      setLoading(false);
    }
  }, []);
  
  const loadTeamsApps = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Adnan 2026-06-18: include builtin so user-added Microsoft
      // apps + sideloaded apps also surface. Filtering happens
      // client-side via teamsAppsFilter.
      const params = new URLSearchParams({ include_builtin: 'true' });
      const res = await api.get(`/api/saas/teams-apps?${params}`);
      setTeamsApps(res.data?.items ?? []);
    } catch (e: unknown) {
      const err = e as { response?: { status?: number } };
      if (err.response?.status === 403) {
        setError('Requires TeamsAppInstallation.Read permission in Microsoft Graph');
      } else if (err.response?.status === 504) {
        setError('Teams app catalog is slow to enumerate. Retry in a moment — the result will be cached for 5 min.');
      } else {
        setError('Failed to load Teams apps');
      }
    } finally {
      setLoading(false);
    }
  }, []);
  
  useEffect(() => {
    if (subTab === 'external-users') loadExternalUsers();
    else if (subTab === 'conditional-access') loadCAPolicies();
    else if (subTab === 'teams-apps') loadTeamsApps();
  }, [subTab, loadExternalUsers, loadCAPolicies, loadTeamsApps]);
  
  const subTabs: Array<{ id: GovernanceSubTab; label: string; icon: React.ReactNode }> = [
    { id: 'external-users', label: 'External Users', icon: <UserX size={12} /> },
    { id: 'conditional-access', label: 'Conditional Access', icon: <Lock size={12} /> },
    { id: 'teams-apps', label: 'Teams Apps', icon: <Layers size={12} /> },
    { id: 'meeting-security', label: 'Meeting Security', icon: <Radio size={12} /> },
    // Adnan asked to drop the Data Protection tab here — DLP lives in
    // its own top-level section.
  ];
  
  const getRiskBadge = (level: 'low' | 'medium' | 'high') => {
    const colors = {
      low: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
      medium: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
      high: 'bg-red-500/10 border-red-500/20 text-red-400',
    };
    return <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${colors[level]}`}>{level}</span>;
  };
  
  const formatDate = (dateStr?: string) => {
    if (!dateStr) return '—';
    const d = new Date(dateStr);
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };
  
  return (
    <div className="space-y-4">
      {/* Sub-tabs */}
      <div className="flex gap-1 border-b border-[var(--border)]">
        {subTabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setSubTab(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-[11px] font-medium border-b-2 transition-colors ${
              subTab === tab.id
                ? 'border-[#3b6ef6] text-[#3b6ef6]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--foreground)]'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>
      
      {/* Error banner */}
      {error && (
        <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl px-4 py-3 text-[12px] text-amber-400 flex items-center gap-2">
          <AlertTriangle size={14} />
          {error}
        </div>
      )}
      
      {/* Loading */}
      {loading && (
        <div className="text-center py-16 text-[var(--muted)]">
          <RefreshCw size={20} className="mx-auto animate-spin mb-2" />
          Loading...
        </div>
      )}
      
      {/* External Users Tab */}
      {!loading && subTab === 'external-users' && (
        <div className="space-y-4">
          {/* Header & Filters */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-[14px] font-semibold text-[var(--foreground)]">External Users</h3>
              <p className="text-[11px] text-[var(--muted)]">{externalUsersTotal} guest user{externalUsersTotal !== 1 ? 's' : ''} in your tenant</p>
            </div>
            <select
              value={externalUsersFilter}
              onChange={e => setExternalUsersFilter(e.target.value as typeof externalUsersFilter)}
              className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[11px] rounded-lg px-3 py-1.5 outline-none"
            >
              <option value="all">All Users</option>
              <option value="stale">Stale (90+ days)</option>
              <option value="high-risk">High Risk</option>
            </select>
          </div>
          
          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="text-[11px] text-[var(--muted)] mb-1">Total Guests</div>
              <div className="text-[20px] font-bold text-[var(--foreground)]">{externalUsersTotal}</div>
            </div>
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="text-[11px] text-[var(--muted)] mb-1">Stale (&gt;90 days)</div>
              <div className="text-[20px] font-bold text-amber-400">{externalUsers.filter(u => ((u.days_inactive ?? u.daysSinceActivity) ?? 999) > 90).length}</div>
            </div>
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="text-[11px] text-[var(--muted)] mb-1">With Teams Access</div>
              <div className="text-[20px] font-bold text-purple-400">{externalUsers.filter(u => (u.teams_access?.length ?? u.teamsAccess?.length ?? 0) > 0).length}</div>
            </div>
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="text-[11px] text-[var(--muted)] mb-1">Meeting Attendees</div>
              <div className="text-[20px] font-bold text-blue-400">{externalInteractions.filter(i => i.interaction_type === 'meeting_attendee').length}</div>
            </div>
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="text-[11px] text-[var(--muted)] mb-1">File Shares</div>
              <div className="text-[20px] font-bold text-red-400">{externalInteractions.filter(i => i.interaction_type === 'file_share' || i.interaction_type === 'chat_member').length}</div>
            </div>
          </div>
          
          {/* Users Table */}
          {externalUsers.length === 0 ? (
            <div className="text-center py-12 text-[var(--muted)]">
              <UserX size={32} className="mx-auto mb-2 opacity-40" />
              <div className="text-[13px]">No external users found</div>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-xl border border-[#1e1e24]">
              <Table>
                <Thead>
                  <Tr>
                    <Th>User</Th>
                    <Th>Last Activity</Th>
                    <Th>Teams Access</Th>
                    <Th>SharePoint Access</Th>
                    <Th>Risk</Th>
                    <Th>Actions</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {externalUsers.map(user => {
                    const displayName = user.display_name ?? user.displayName ?? user.email.split('@')[0];
                    const lastSignIn = user.last_sign_in ?? user.lastSignIn ?? null;
                    const daysInactive = user.days_inactive ?? user.daysSinceActivity ?? null;
                    const teams = user.teams_access ?? user.teamsAccess ?? [];
                    const sharepoint = user.sharepoint_access ?? user.sharepointAccess ?? [];
                    const riskLevel: 'low' | 'medium' | 'high' = user.riskLevel ?? (
                      (user.risk_indicators ?? []).includes('dormant') ? 'high' :
                      (user.risk_indicators ?? []).includes('stale') ? 'medium' : 'low'
                    );
                    return (
                    <Tr key={user.id}>
                      <Td>
                        <div>
                          <div className="text-[12px] text-[var(--foreground)] font-medium">{displayName}</div>
                          <div className="text-[10px] text-[var(--muted)]">{user.email}</div>
                        </div>
                      </Td>
                      <Td>
                        <div className="text-[12px]">
                          {lastSignIn ? (
                            <>
                              <span className={daysInactive && daysInactive > 90 ? 'text-amber-400' : 'text-[var(--foreground)]'}>
                                {formatDate(lastSignIn)}
                              </span>
                              {daysInactive ? (
                                <span className="text-[10px] text-[var(--muted)] ml-1">({daysInactive}d ago)</span>
                              ) : null}
                            </>
                          ) : (
                            <span className="text-red-400">Never</span>
                          )}
                        </div>
                      </Td>
                      <Td>
                        {teams.length > 0 ? (
                          <span className="text-[11px] text-purple-400">{teams.length} team{teams.length !== 1 ? 's' : ''}</span>
                        ) : (
                          <span className="text-[11px] text-[var(--muted)]">None</span>
                        )}
                      </Td>
                      <Td>
                        {sharepoint.length > 0 ? (
                          <span className="text-[11px] text-blue-400">{sharepoint.length} site{sharepoint.length !== 1 ? 's' : ''}</span>
                        ) : (
                          <span className="text-[11px] text-[var(--muted)]">None</span>
                        )}
                      </Td>
                      <Td>{getRiskBadge(riskLevel)}</Td>
                      <Td>
                        <button className="text-[10px] text-red-400 hover:text-red-300 px-2 py-1 rounded border border-red-500/20 hover:bg-red-500/10">
                          Revoke
                        </button>
                      </Td>
                    </Tr>
                    );
                  })}
                </Tbody>
              </Table>
            </div>
          )}

          {/* External Interactions (ad-hoc meeting attendees + file shares + chat invites) */}
          {externalInteractions.length > 0 && (
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-[13px] font-semibold text-[var(--foreground)] flex items-center gap-2">
                  <Users size={14} />
                  External Interactions (recent)
                </h4>
                <span className="text-[10px] text-[var(--muted)]">
                  {externalInteractions.length} event{externalInteractions.length !== 1 ? 's' : ''} · meeting attendees, file shares, chat invites
                </span>
              </div>
              <div className="overflow-x-auto">
                <Table>
                  <Thead>
                    <Tr>
                      <Th>External Party</Th>
                      <Th>Type</Th>
                      <Th>Initiated by</Th>
                      <Th>When</Th>
                      <Th>Detail</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {externalInteractions.slice(0, 50).map(it => {
                      const typeBadge: Record<ExternalInteraction['interaction_type'], { label: string; cls: string }> = {
                        meeting_attendee: { label: 'Meeting', cls: 'bg-blue-500/10 border-blue-500/20 text-blue-400' },
                        file_share: { label: 'File share', cls: 'bg-red-500/10 border-red-500/20 text-red-400' },
                        chat_member: { label: 'Chat invite', cls: 'bg-purple-500/10 border-purple-500/20 text-purple-400' },
                        audit_event: { label: 'Audit', cls: 'bg-zinc-500/10 border-zinc-500/20 text-zinc-300' },
                      };
                      const tb = typeBadge[it.interaction_type];
                      return (
                      <Tr key={it.id}>
                        <Td>
                          <div className="text-[12px] font-medium text-[var(--foreground)]">{it.display_name}</div>
                          <div className="text-[10px] text-[var(--muted)]">{it.email}</div>
                        </Td>
                        <Td><span className={`text-[10px] px-2 py-0.5 rounded-full border ${tb.cls}`}>{tb.label}</span></Td>
                        <Td><span className="text-[11px]">{it.organizer}</span></Td>
                        <Td><span className="text-[11px] text-[var(--muted)]">{it.event_time ? formatDate(it.event_time) : '—'}</span></Td>
                        <Td><span className="text-[11px] text-[var(--muted)]">{it.detail}</span></Td>
                      </Tr>
                      );
                    })}
                  </Tbody>
                </Table>
              </div>
              {externalInteractions.length > 50 && (
                <div className="text-[10px] text-[var(--muted)] mt-2 text-center">
                  Showing 50 of {externalInteractions.length} events.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Conditional Access Tab */}
      {!loading && subTab === 'conditional-access' && (
        <div className="space-y-4">
          {/* Multi-cloud identity posture banner */}
          <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-[13px] font-semibold text-[var(--foreground)] flex items-center gap-2">
                <Globe2 size={14} />
                Multi-Cloud Identity Posture
              </h4>
              <span className="text-[10px] text-[var(--muted)]">
                {multiCloudControls.length} cloud{multiCloudControls.length !== 1 ? 's' : ''} covered · reads from connected CSPM scanners
              </span>
            </div>
            {multiCloudControls.length === 0 ? (
              <div className="text-[11px] text-[var(--muted)] py-2">
                Only Microsoft 365 is currently feeding identity posture. Connect AWS / GCP / Salesforce / GitHub / Snowflake under Connectors to roll their IAM / session / 2FA findings up into this view.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {multiCloudControls.map(c => (
                  <div key={`${c.cloud}-${c.control_name}`} className="flex items-center justify-between p-2.5 bg-white/[0.02] rounded-lg border border-white/[0.05]">
                    <div className="min-w-0">
                      <div className="text-[12px] font-medium text-[var(--foreground)]">{c.cloud_label}</div>
                      <div className="text-[10px] text-[var(--muted)]">{c.control_name} · {c.summary}</div>
                    </div>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                      c.status === 'healthy' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                      c.status === 'partial' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
                      'bg-red-500/10 border-red-500/20 text-red-400'
                    }`}>
                      {c.status}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Policy Gaps Warning */}
          {caGaps.length > 0 && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4">
              <h4 className="text-[13px] font-semibold text-red-400 mb-2 flex items-center gap-2">
                <AlertOctagon size={14} />
                Policy Gaps Detected
              </h4>
              <ul className="space-y-1">
                {caGaps.map((gap, i) => (
                  <li key={i} className="text-[11px] text-red-300 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 bg-red-400 rounded-full" />
                    {gap}
                  </li>
                ))}
              </ul>
            </div>
          )}
          
          {/* Summary */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="text-[11px] text-[var(--muted)] mb-1">CA Policies</div>
              <div className="text-[20px] font-bold text-[var(--foreground)]">{caPolicies.length}</div>
              <div className="text-[10px] text-emerald-400">{caPolicies.filter(p => p.state === 'enabled').length} enabled</div>
            </div>
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="text-[11px] text-[var(--muted)] mb-1">Blocked Sign-ins (24h)</div>
              <div className="text-[20px] font-bold text-red-400">{blockedSignIns.length}</div>
            </div>
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <div className="text-[11px] text-[var(--muted)] mb-1">Policy Gaps</div>
              <div className="text-[20px] font-bold text-amber-400">{caGaps.length}</div>
            </div>
          </div>
          
          {/* Policies List */}
          <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
            <h4 className="text-[13px] font-semibold text-[var(--foreground)] mb-3">Conditional Access Policies</h4>
            <div className="space-y-2">
              {caPolicies.map(policy => (
                <div key={policy.id} className="flex items-center justify-between p-3 bg-white/[0.02] rounded-lg border border-white/[0.05]">
                  <div>
                    <div className="text-[12px] font-medium text-[var(--foreground)]">{policy.displayName}</div>
                    <div className="text-[10px] text-[var(--muted)]">
                      {policy.grantControls?.builtInControls?.join(', ') || 'No grant controls'}
                    </div>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                    policy.state === 'enabled' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                    policy.state === 'enabledForReportingButNotEnforced' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
                    'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
                  }`}>
                    {policy.state === 'enabledForReportingButNotEnforced' ? 'Report Only' : policy.state}
                  </span>
                </div>
              ))}
              {caPolicies.length === 0 && (
                <div className="text-center py-8 text-[var(--muted)] text-[12px]">No policies found</div>
              )}
            </div>
          </div>
          
          {/* Blocked Sign-ins */}
          {blockedSignIns.length > 0 && (
            <div className="bg-[#13131a] border border-white/[0.06] rounded-xl p-4">
              <h4 className="text-[13px] font-semibold text-[var(--foreground)] mb-3">Recent Blocked Sign-ins</h4>
              <div className="overflow-x-auto">
                <Table>
                  <Thead>
                    <Tr>
                      <Th>User</Th>
                      <Th>IP / Location</Th>
                      <Th>Client App</Th>
                      <Th>Blocked By</Th>
                      <Th>Time</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {blockedSignIns.slice(0, 10).map(si => (
                      <Tr key={si.id}>
                        <Td><span className="text-[12px]">{si.userPrincipalName?.split('@')[0]}</span></Td>
                        <Td>
                          <div className="text-[11px]">
                            <div>{si.ipAddress}</div>
                            {si.location && <div className="text-[var(--muted)]">{si.location.city}, {si.location.countryOrRegion}</div>}
                          </div>
                        </Td>
                        <Td><span className="text-[11px]">{si.clientAppUsed}</span></Td>
                        <Td><span className="text-[11px] text-amber-400">{si.appliedPolicies?.join(', ') || '—'}</span></Td>
                        <Td><span className="text-[11px] text-[var(--muted)]">{formatDate(si.createdDateTime)}</span></Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              </div>
            </div>
          )}
        </div>
      )}
      
      {/* Teams Apps Tab */}
      {!loading && subTab === 'teams-apps' && (
        <TeamsAppsPanel
          apps={teamsApps}
          filter={teamsAppsFilter}
          setFilter={setTeamsAppsFilter}
        />
      )}
      {/* Meeting Security Tab — implemented 2026-06-17.
          Replaces the old "Coming Soon" stub. */}
      {!loading && subTab === 'meeting-security' && (
        <MeetingSecurityPanel />
      )}

      {/* DLP tab removed — DLP lives in its own top-level page. */}
    </div>
  );
}

// ── Teams Apps Panel ──────────────────────────────────────────────────────────
// Adnan 2026-06-18: rewrite to match new backend payload (snake_case
// items[] with install_scopes, risk_factors, etc) and add a per-app
// AI risk analysis drawer.
function TeamsAppsPanel({
  apps,
  filter,
  setFilter,
}: {
  apps: TeamsApp[]
  filter: 'all' | 'risky' | 'blocked'
  setFilter: (v: 'all' | 'risky' | 'blocked') => void
}) {
  const [openApp, setOpenApp] = useState<TeamsApp | null>(null)

  const filtered = apps.filter(a => {
    if (filter === 'risky') return a.risk_level === 'high' || a.risk_level === 'medium'
    if (filter === 'blocked') return !!a.isBlocked
    return true
  })

  const riskBadge = (level: 'low' | 'medium' | 'high') => {
    const map = {
      low: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
      medium: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
      high: 'bg-red-500/10 border-red-500/20 text-red-400',
    }
    return (
      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${map[level]}`}>
        {level}
      </span>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-[14px] font-semibold text-[var(--foreground)]">Teams Apps (Installed)</h3>
          <p className="text-[11px] text-[var(--muted)]">
            {apps.length} installed app{apps.length !== 1 ? 's' : ''} · permission + scope risk analysis. Catalog-only apps are hidden by default.
          </p>
        </div>
        <select
          value={filter}
          onChange={e => setFilter(e.target.value as typeof filter)}
          className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[11px] rounded-lg px-3 py-1.5 outline-none"
        >
          <option value="all">All Installed</option>
          <option value="risky">Risky</option>
          <option value="blocked">Blocked</option>
        </select>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filtered.map(app => {
          const isUserScope = (app.install_scopes || []).includes('user')
          const isTeamScope = (app.install_scopes || []).includes('team')
          const isSideloaded = app.distribution_method === 'organization'
          return (
            <button
              key={app.id}
              onClick={() => setOpenApp(app)}
              className={`text-left bg-[#13131a] border rounded-xl p-4 hover:border-[#3b6ef6]/30 transition-colors ${
                app.isBlocked ? 'border-red-500/30 opacity-60' : 'border-white/[0.06]'
              }`}
            >
              <div className="flex items-start justify-between mb-2">
                <div className="min-w-0">
                  <div className="text-[13px] font-medium text-[var(--foreground)] truncate">{app.display_name}</div>
                  <div className="text-[10px] text-[var(--muted)]">{app.publisher || 'Unknown publisher'}</div>
                </div>
                {riskBadge(app.risk_level)}
              </div>

              <div className="flex flex-wrap items-center gap-2 text-[10px] text-[var(--muted)] mb-2">
                <span className="flex items-center gap-1">
                  <Users size={10} />
                  {app.install_count} install{app.install_count !== 1 ? 's' : ''}
                </span>
                {isTeamScope && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] bg-[#3b6ef6]/10 border border-[#3b6ef6]/20 text-[#93b4fd]">team</span>
                )}
                {isUserScope && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] bg-purple-500/10 border border-purple-500/20 text-purple-300">user</span>
                )}
                {isSideloaded && (
                  <span className="px-1.5 py-0.5 rounded text-[9px] bg-amber-500/10 border border-amber-500/20 text-amber-300">sideloaded</span>
                )}
              </div>

              {app.permission_count != null && app.permission_count > 0 && (
                <div className="text-[10px] text-amber-400 mb-2">
                  {app.permission_count} permission{app.permission_count !== 1 ? 's' : ''}
                </div>
              )}

              {(app.risk_factors || []).length > 0 && (
                <div className="text-[10px] text-[var(--muted)] line-clamp-2">
                  {(app.risk_factors || []).slice(0, 2).join(' · ')}
                </div>
              )}

              <div className="text-[10px] text-[var(--muted)]/70 mt-3 flex items-center gap-1">
                <Sparkles size={10} className="text-[#3b6ef6]" /> Click for AI risk analysis
              </div>
            </button>
          )
        })}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-[var(--muted)]">
          <Layers size={32} className="mx-auto mb-2 opacity-40" />
          <div className="text-[13px]">
            {apps.length === 0 ? 'No Teams apps found' : 'No apps match this filter'}
          </div>
        </div>
      )}

      {openApp && (
        <TeamsAppRiskDrawer app={openApp} onClose={() => setOpenApp(null)} />
      )}
    </div>
  )
}

interface TeamsAppRiskAnalysis {
  assessment: string
  risks: string[]
  actions: string[]
  generated_at: string
  ai_powered: boolean
}

function TeamsAppRiskDrawer({ app, onClose }: { app: TeamsApp; onClose: () => void }) {
  const [data, setData] = useState<TeamsAppRiskAnalysis | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const currentAppIdRef = useRef<string>(app.id)
  const abortRef = useRef<AbortController | null>(null)

  const fetchAnalysis = useCallback(async (refresh = false) => {
    if (abortRef.current) {
      try { abortRef.current.abort() } catch { /* noop */ }
    }
    const controller = new AbortController()
    abortRef.current = controller
    const requestedFor = app.id
    currentAppIdRef.current = app.id
    if (refresh) setRefreshing(true)
    else setLoading(true)
    setErr(null)
    try {
      const r = await api.get(
        `/api/saas/teams-apps/${encodeURIComponent(app.id)}/risk-analysis${refresh ? '?refresh=true' : ''}`,
        { signal: controller.signal, timeout: 45000 },
      )
      if (currentAppIdRef.current !== requestedFor) return
      setData(r.data as TeamsAppRiskAnalysis)
    } catch (e: unknown) {
      const ex = e as { name?: string; code?: string; response?: { data?: { detail?: string } } }
      if (ex?.name === 'CanceledError' || ex?.name === 'AbortError' || ex?.code === 'ERR_CANCELED') return
      if (currentAppIdRef.current !== requestedFor) return
      setErr(ex?.response?.data?.detail || 'Failed to load AI risk analysis.')
    } finally {
      if (currentAppIdRef.current === requestedFor) {
        setLoading(false)
        setRefreshing(false)
      }
    }
  }, [app.id])

  useEffect(() => {
    setData(null)
    setErr(null)
    fetchAnalysis(false)
    return () => {
      if (abortRef.current) {
        try { abortRef.current.abort() } catch { /* noop */ }
      }
    }
  }, [fetchAnalysis])

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end" onClick={onClose}>
      <div
        className="w-full max-w-2xl bg-[var(--background)] border-l border-[var(--border)] h-full overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-[var(--background)] border-b border-[var(--border)] px-6 py-4 z-10">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold border bg-zinc-500/10 border-zinc-500/20 text-zinc-300">
                  {app.distribution_method}
                </span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
                  app.risk_level === 'high' ? 'bg-red-500/10 border-red-500/20 text-red-400'
                  : app.risk_level === 'medium' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                  : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                }`}>
                  {app.risk_level}
                </span>
              </div>
              <h3 className="text-[15px] font-semibold text-[var(--foreground)]">{app.display_name}</h3>
              <p className="text-[12px] text-[var(--muted)] mt-1">
                {app.publisher || 'Unknown publisher'} · {app.permission_count || 0} permission{(app.permission_count || 0) === 1 ? '' : 's'} · {app.install_count} install{app.install_count === 1 ? '' : 's'}
              </p>
            </div>
            <button onClick={onClose} className="text-[var(--muted)] hover:text-[var(--foreground)]">
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="px-6 py-5 space-y-5">
          {app.short_description && (
            <div className="bg-[#0e0e14] border border-[var(--border)] rounded-xl p-4 text-[12px] text-[var(--foreground)] leading-relaxed">
              {app.short_description}
            </div>
          )}

          {(app.risk_factors || []).length > 0 && (
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--muted)] mb-2">Heuristic risk factors</div>
              <div className="space-y-1.5">
                {(app.risk_factors || []).map((rf, i) => (
                  <div key={i} className="flex items-start gap-2 text-[12px] text-[var(--foreground)]/85">
                    <AlertTriangle size={12} className="text-amber-400 mt-0.5 flex-shrink-0" />
                    <span>{rf}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {app.permissions && app.permissions.length > 0 && (
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--muted)] mb-2">Permissions ({app.permission_count})</div>
              <div className="flex flex-wrap gap-1.5">
                {app.permissions.slice(0, 20).map((p, i) => {
                  const name = typeof p === 'string' ? p : (p.id || JSON.stringify(p))
                  return (
                    <span key={i} className="px-2 py-1 rounded-md text-[11px] bg-[#1e1e24] border border-[#1e1e24] text-[#c4c4cc] font-mono">
                      {name}
                    </span>
                  )
                })}
              </div>
            </div>
          )}

          {/* AI Risk Analysis */}
          <div className="bg-gradient-to-br from-[#3b6ef6]/[0.06] to-transparent border border-[#3b6ef6]/20 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles size={14} className="text-[#3b6ef6]" />
              <span className="text-[12px] font-semibold text-[var(--foreground)]">AI Risk Analysis</span>
              {data && (
                <span className={`text-[10px] px-2 py-0.5 rounded-full border ${data.ai_powered
                  ? 'bg-[#3b6ef6]/10 border-[#3b6ef6]/30 text-[#93b4fd]'
                  : 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400'}`}>
                  {data.ai_powered ? 'AI-generated' : 'Heuristic'}
                </span>
              )}
              <button
                onClick={() => fetchAnalysis(true)}
                disabled={refreshing || loading}
                className="ml-auto text-[11px] text-[var(--muted)] hover:text-[var(--foreground)] flex items-center gap-1"
              >
                <RefreshCw size={11} className={refreshing ? 'animate-spin' : ''} />
                Regenerate
              </button>
            </div>

            {loading ? (
              <div className="space-y-2">
                <div className="h-3 bg-white/[0.05] rounded animate-pulse w-3/4" />
                <div className="h-3 bg-white/[0.05] rounded animate-pulse w-full" />
                <div className="h-3 bg-white/[0.05] rounded animate-pulse w-5/6" />
              </div>
            ) : err ? (
              <div className="text-[12px] text-red-300">{err}</div>
            ) : data ? (
              <div className="space-y-4">
                <div className="text-[12px] text-[var(--foreground)]/90 leading-relaxed">{data.assessment}</div>
                {data.risks.length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-[var(--muted)] mb-1.5">Specific risks</div>
                    <ol className="list-decimal pl-4 space-y-1.5 text-[12px] text-[var(--foreground)]/85">
                      {data.risks.map((x, i) => <li key={i}>{x}</li>)}
                    </ol>
                  </div>
                )}
                {data.actions.length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-[var(--muted)] mb-1.5">Recommended actions</div>
                    <ol className="list-decimal pl-4 space-y-1.5 text-[12px] text-[var(--foreground)]/85">
                      {data.actions.map((x, i) => <li key={i}>{x}</li>)}
                    </ol>
                  </div>
                )}
                <div className="text-[10px] text-[var(--muted)] pt-2 border-t border-[var(--border)]">
                  Generated {fmtDate(data.generated_at)}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Meeting Security Panel  ────────────────────────────────────────
// Reads /api/saas/meeting-security/risks and renders:
//  - Policy posture summary (anonymous join / lobby bypass / auto record
//    / external attendee / file shares) based on the recent meeting sample.
//  - Per-risk feed with severity, type, organiser, attendees, and an
//    "AI risk analysis" drawer (Claude-driven via
//    /api/saas/meeting-security/risks/{id}/analysis).
//  - Filters: severity, risk type, search.

interface MeetingRisk {
  id: string
  meeting_id?: string
  subject?: string
  organizer?: string
  risk_type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  description: string
  external_attendees?: string[]
  event_time?: string
  initiated_by?: string
  remediation_url?: string
  classification?: unknown
}

interface MeetingRisksResponse {
  total: number
  high_severity_count: number
  by_type: Record<string, number>
  by_severity: Record<string, number>
  policy_findings: {
    meetings_sampled?: number
    meetings_with_external?: number
    meetings_with_lobby_bypass_everyone?: number
    meetings_with_anonymous_join?: number
    meetings_with_auto_recording?: number
    meetings_allowing_external_presenters?: number
    meetings_chat_unrestricted?: number
    app_pinning_allowed?: boolean
  }
  items: MeetingRisk[]
}

function MeetingSecurityPanel() {
  const [data, setData] = useState<MeetingRisksResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState<string | null>(null)
  const [filterSev, setFilterSev] = useState<string>('')
  const [filterType, setFilterType] = useState<string>('')
  const [search, setSearch] = useState<string>('')
  const [openRisk, setOpenRisk] = useState<MeetingRisk | null>(null)

  const load = useCallback(async () => {
    try {
      setLoading(true)
      setErr(null)
      const r = await api.get<MeetingRisksResponse>('/api/saas/meeting-security/risks')
      setData(r.data)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setErr(msg || 'Failed to load Meeting Security data. Ensure M365 is connected.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const sevColor = (s: string) => {
    if (s === 'critical') return 'bg-red-500/15 border-red-500/30 text-red-300'
    if (s === 'high') return 'bg-red-500/10 border-red-500/20 text-red-400'
    if (s === 'medium') return 'bg-amber-500/10 border-amber-500/20 text-amber-400'
    if (s === 'low') return 'bg-blue-500/10 border-blue-500/20 text-blue-400'
    return 'bg-zinc-500/10 border-zinc-500/20 text-zinc-400'
  }
  const typeLabel = (t: string) => {
    const map: Record<string, string> = {
      external_attendee: 'External attendee',
      lobby_bypass: 'Lobby bypass',
      auto_recording: 'Auto recording',
      no_entry_announcement: 'No entry announcement',
      meeting_file_share: 'File shared in meeting',
      meeting_file_share_external: 'File shared with external',
      meeting_external_attendee: 'External attendee detected',
      policy_change: 'Policy change',
      policy_posture: 'Tenant policy posture',
      recommendation: 'Recommendation',
      other: 'Other',
    }
    return map[t] || t.replace(/_/g, ' ')
  }

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-[120px] bg-white/[0.03] rounded-xl animate-pulse" />
        {[1, 2, 3].map(i => <div key={i} className="h-16 bg-white/[0.03] rounded-xl animate-pulse" />)}
      </div>
    )
  }
  if (err) {
    return (
      <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-5 text-[13px] text-red-300 flex items-start gap-3">
        <AlertTriangle size={16} className="mt-0.5 flex-shrink-0" />
        <div>
          <div className="font-semibold text-red-200 mb-1">Meeting Security unavailable</div>
          <div className="text-red-300/80">{err}</div>
          <Button size="sm" variant="ghost" className="mt-3" onClick={load}>
            <RefreshCw size={12} className="mr-1" /> Retry
          </Button>
        </div>
      </div>
    )
  }
  if (!data) return null

  const pf = data.policy_findings || {}
  const sampled = pf.meetings_sampled || 0
  const pct = (n?: number) => sampled > 0 ? Math.round(((n || 0) / sampled) * 100) : 0

  // Apply filters
  const visible = data.items.filter(r => {
    if (filterSev && r.severity !== filterSev) return false
    if (filterType && r.risk_type !== filterType) return false
    if (search.trim()) {
      const q = search.trim().toLowerCase()
      if (
        !(r.title || '').toLowerCase().includes(q) &&
        !(r.subject || '').toLowerCase().includes(q) &&
        !(r.organizer || '').toLowerCase().includes(q) &&
        !(r.description || '').toLowerCase().includes(q)
      ) return false
    }
    return true
  })

  return (
    <div className="space-y-5">
      {/* Header strip + refresh */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-[14px] font-semibold text-[var(--foreground)] flex items-center gap-2">
            <Radio size={14} className="text-[#3b6ef6]" />
            Meeting Security
          </h3>
          <p className="text-[11px] text-[var(--muted)] mt-0.5">
            Live posture for Teams meetings: lobby bypass, anonymous join, recording,
            external attendees, and meeting-chat file shares.
          </p>
        </div>
        <Button size="sm" variant="ghost" onClick={load}>
          <RefreshCw size={12} className="mr-1" /> Refresh
        </Button>
      </div>

      {/* Top stat row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total risks" value={data.total} />
        <StatCard
          label="High / Critical"
          value={data.high_severity_count}
          color={data.high_severity_count > 0 ? 'text-red-400' : 'text-emerald-400'}
        />
        <StatCard
          label="Meetings sampled"
          value={sampled}
          sub={sampled === 0 ? 'No recent meetings' : 'Last 50'}
        />
        <StatCard
          label="Meetings with external"
          value={pf.meetings_with_external || 0}
          sub={sampled ? `${pct(pf.meetings_with_external)}% of sample` : ''}
          color={(pf.meetings_with_external || 0) > 0 ? 'text-amber-400' : 'text-emerald-400'}
        />
      </div>

      {/* Tenant policy posture card */}
      {sampled > 0 && (
        <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <ShieldCheck size={14} className="text-[#3b6ef6]" />
            <h3 className="text-[13px] font-semibold text-[var(--foreground)]">Tenant Meeting Posture</h3>
            <span className="text-[10px] text-[var(--muted)] ml-auto">Sample of {sampled} recent meetings</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {[
              { label: 'Lobby bypass for everyone', val: pf.meetings_with_lobby_bypass_everyone, danger: 0.3 },
              { label: 'Anonymous join allowed', val: pf.meetings_with_anonymous_join, danger: 0.2 },
              { label: 'Automatic recording on', val: pf.meetings_with_auto_recording, danger: 0.5 },
              { label: 'External presenter allowed', val: pf.meetings_allowing_external_presenters, danger: 0.3 },
              { label: 'Meeting chat unrestricted', val: pf.meetings_chat_unrestricted, danger: 0.6 },
              { label: 'Meetings with external attendee', val: pf.meetings_with_external, danger: 0.4 },
            ].map(row => {
              const ratio = sampled ? (row.val || 0) / sampled : 0
              const danger = ratio >= row.danger
              return (
                <div
                  key={row.label}
                  className={`bg-[#0e0e14] border rounded-lg p-3 ${danger ? 'border-amber-500/30' : 'border-[var(--border)]'}`}
                >
                  <div className="text-[10px] uppercase tracking-wide text-[var(--muted)]">{row.label}</div>
                  <div className={`text-lg font-semibold mt-1 ${danger ? 'text-amber-300' : 'text-[var(--foreground)]'}`}>
                    {row.val || 0}
                    <span className="text-[10px] text-[var(--muted)] font-normal ml-1">/{sampled}</span>
                  </div>
                  <div className="text-[10px] text-[var(--muted)] mt-1">{Math.round(ratio * 100)}% of sample</div>
                </div>
              )
            })}
          </div>
          {pf.app_pinning_allowed && (
            <div className="mt-3 text-[11px] text-[var(--muted)] flex items-center gap-1.5">
              <Info size={11} /> User app pinning is allowed at the tenant level.
            </div>
          )}
        </div>
      )}

      {/* Filters */}
      {data.items.length > 0 && (
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search meetings (subject, organiser, description)…"
              className="w-full pl-8 pr-3 py-1.5 bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg outline-none focus:border-[#3b6ef6]"
            />
          </div>
          <select
            value={filterSev}
            onChange={e => setFilterSev(e.target.value)}
            className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <select
            value={filterType}
            onChange={e => setFilterType(e.target.value)}
            className="bg-[#111114] border border-[#1e1e24] text-[#e4e4e7] text-[12px] rounded-lg px-3 py-1.5 outline-none focus:border-[#3b6ef6]"
          >
            <option value="">All risk types</option>
            {Object.keys(data.by_type).sort().map(t => (
              <option key={t} value={t}>{typeLabel(t)} ({data.by_type[t]})</option>
            ))}
          </select>
        </div>
      )}

      {/* Risk feed */}
      {visible.length === 0 ? (
        <div className="text-center py-16 space-y-2">
          <ShieldCheck size={28} className="mx-auto text-emerald-400/60" />
          <div className="text-[#a1a1aa] text-sm">
            {data.items.length === 0
              ? 'No meeting risks detected in the current sample.'
              : 'No risks match your filters.'}
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          {visible.map(r => {
            const ext = r.external_attendees || []
            return (
              <button
                key={r.id}
                onClick={() => setOpenRisk(r)}
                className="w-full bg-[#13131a] border border-[var(--border)] rounded-xl p-4 text-left hover:border-white/[0.12] transition-colors"
              >
                <div className="flex items-start gap-3">
                  <div className="mt-0.5">
                    {r.severity === 'critical' || r.severity === 'high'
                      ? <AlertOctagon size={14} className="text-red-400" />
                      : r.severity === 'medium'
                        ? <AlertTriangle size={14} className="text-amber-400" />
                        : r.severity === 'info'
                          ? <Info size={14} className="text-blue-400" />
                          : <ShieldAlert size={14} className="text-blue-400" />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-1.5 py-0.5 rounded-full text-[9px] font-semibold border ${sevColor(r.severity)}`}>{r.severity}</span>
                      <span className="px-1.5 py-0.5 rounded-full text-[9px] font-semibold border bg-zinc-500/10 border-zinc-500/20 text-zinc-300">
                        {typeLabel(r.risk_type)}
                      </span>
                      <span className="text-[13px] font-medium text-[var(--foreground)] truncate">{r.title}</span>
                    </div>
                    <div className="text-[12px] text-[var(--muted)] mt-1 line-clamp-2">
                      {r.description}
                    </div>
                    <div className="flex items-center gap-3 mt-2 text-[10px] text-[var(--muted)] flex-wrap">
                      {r.subject && (
                        <span className="flex items-center gap-1"><Radio size={10} /> {r.subject}</span>
                      )}
                      {r.organizer && (
                        <span className="flex items-center gap-1"><Users size={10} /> {r.organizer}</span>
                      )}
                      {ext.length > 0 && (
                        <span className="flex items-center gap-1 text-amber-400">
                          <UserX size={10} /> {ext.length} external
                        </span>
                      )}
                      {r.event_time && (
                        <span className="flex items-center gap-1"><Clock size={10} /> {fmtDate(r.event_time)}</span>
                      )}
                    </div>
                  </div>
                  <ChevronRight size={14} className="text-[var(--muted)] mt-1" />
                </div>
              </button>
            )
          })}
        </div>
      )}

      {openRisk && (
        <MeetingRiskDrawer
          risk={openRisk}
          onClose={() => setOpenRisk(null)}
        />
      )}
    </div>
  )
}

function MeetingRiskDrawer({
  risk, onClose,
}: {
  risk: MeetingRisk
  onClose: () => void
}) {
  const [analysis, setAnalysis] = useState<{
    assessment: string
    risks: string[]
    actions: string[]
    generated_at: string
    ai_powered: boolean
  } | null>(null)
  const [loadingA, setLoadingA] = useState(true)
  const [errA, setErrA] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const currentRiskIdRef = useRef<string>(risk.id)
  const abortRef = useRef<AbortController | null>(null)

  const fetchAnalysis = useCallback(async (refresh = false) => {
    if (abortRef.current) {
      try { abortRef.current.abort() } catch { /* noop */ }
    }
    const controller = new AbortController()
    abortRef.current = controller
    const requestedFor = risk.id
    currentRiskIdRef.current = risk.id
    try {
      if (refresh) setRefreshing(true)
      else setLoadingA(true)
      setErrA(null)
      const r = await api.get(
        `/api/saas/meeting-security/risks/${encodeURIComponent(risk.id)}/analysis${refresh ? '?refresh=true' : ''}`,
        { signal: controller.signal, timeout: 45000 },
      )
      if (currentRiskIdRef.current !== requestedFor) return
      setAnalysis(r.data)
    } catch (e: unknown) {
      const err = e as { name?: string; code?: string; response?: { data?: { detail?: string } } }
      if (err?.name === 'CanceledError' || err?.name === 'AbortError' || err?.code === 'ERR_CANCELED') return
      if (currentRiskIdRef.current !== requestedFor) return
      const msg = err?.response?.data?.detail
      setErrA(msg || 'Failed to load AI analysis.')
    } finally {
      if (currentRiskIdRef.current === requestedFor) {
        setLoadingA(false)
        setRefreshing(false)
      }
    }
  }, [risk.id])

  useEffect(() => { fetchAnalysis(false) }, [fetchAnalysis])

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end" onClick={onClose}>
      <div
        className="w-full max-w-2xl bg-[var(--background)] border-l border-[var(--border)] h-full overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-[var(--background)] border-b border-[var(--border)] px-6 py-4 z-10">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold border bg-zinc-500/10 border-zinc-500/20 text-zinc-300">
                  {risk.risk_type.replace(/_/g, ' ')}
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold border bg-amber-500/10 border-amber-500/20 text-amber-400">
                  {risk.severity}
                </span>
              </div>
              <h3 className="text-[15px] font-semibold text-[var(--foreground)]">{risk.title}</h3>
              {risk.subject && (
                <p className="text-[12px] text-[var(--muted)] mt-1">
                  Meeting: {risk.subject}
                  {risk.organizer ? ` — organised by ${risk.organizer}` : ''}
                </p>
              )}
            </div>
            <button onClick={onClose} className="text-[var(--muted)] hover:text-[var(--foreground)]">
              <X size={18} />
            </button>
          </div>
        </div>

        <div className="px-6 py-5 space-y-5">
          <div className="bg-[#0e0e14] border border-[var(--border)] rounded-xl p-4 text-[12px] text-[var(--foreground)] leading-relaxed">
            {risk.description}
          </div>

          {risk.external_attendees && risk.external_attendees.length > 0 && (
            <div>
              <div className="text-[11px] uppercase tracking-wide text-[var(--muted)] mb-2">External attendees</div>
              <div className="flex flex-wrap gap-1.5">
                {risk.external_attendees.map((e, i) => (
                  <span key={i} className="px-2 py-1 rounded-md text-[11px] bg-amber-500/10 border border-amber-500/20 text-amber-300">
                    {e}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* AI Risk Analysis */}
          <div className="bg-gradient-to-br from-[#3b6ef6]/[0.06] to-transparent border border-[#3b6ef6]/20 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <Sparkles size={14} className="text-[#3b6ef6]" />
              <span className="text-[12px] font-semibold text-[var(--foreground)]">AI Risk Analysis</span>
              {analysis && (
                <span className={`text-[10px] px-2 py-0.5 rounded-full border ${analysis.ai_powered
                  ? 'bg-[#3b6ef6]/10 border-[#3b6ef6]/30 text-[#93b4fd]'
                  : 'bg-zinc-500/10 border-zinc-500/30 text-zinc-400'}`}>
                  {analysis.ai_powered ? 'AI-generated' : 'Heuristic'}
                </span>
              )}
              <button
                onClick={() => fetchAnalysis(true)}
                disabled={refreshing || loadingA}
                className="ml-auto text-[11px] text-[var(--muted)] hover:text-[var(--foreground)] flex items-center gap-1"
              >
                <RefreshCw size={11} className={refreshing ? 'animate-spin' : ''} />
                Regenerate
              </button>
            </div>

            {loadingA ? (
              <div className="space-y-2">
                <div className="h-3 bg-white/[0.05] rounded animate-pulse w-3/4" />
                <div className="h-3 bg-white/[0.05] rounded animate-pulse w-full" />
                <div className="h-3 bg-white/[0.05] rounded animate-pulse w-5/6" />
              </div>
            ) : errA ? (
              <div className="text-[12px] text-red-300">{errA}</div>
            ) : analysis ? (
              <div className="space-y-4">
                <div className="text-[12px] text-[var(--foreground)]/90 leading-relaxed">
                  {analysis.assessment}
                </div>
                {analysis.risks.length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-[var(--muted)] mb-1.5">Specific risks</div>
                    <ol className="list-decimal pl-4 space-y-1.5 text-[12px] text-[var(--foreground)]/85">
                      {analysis.risks.map((x, i) => <li key={i}>{x}</li>)}
                    </ol>
                  </div>
                )}
                {analysis.actions.length > 0 && (
                  <div>
                    <div className="text-[10px] uppercase tracking-wide text-[var(--muted)] mb-1.5">Recommended actions</div>
                    <ol className="list-decimal pl-4 space-y-1.5 text-[12px] text-[var(--foreground)]/85">
                      {analysis.actions.map((x, i) => <li key={i}>{x}</li>)}
                    </ol>
                  </div>
                )}
                <div className="text-[10px] text-[var(--muted)] pt-2 border-t border-[var(--border)]">
                  Generated {fmtDate(analysis.generated_at)}
                </div>
              </div>
            ) : null}
          </div>

          {risk.remediation_url && (
            <a
              href={risk.remediation_url}
              target="_blank"
              rel="noreferrer"
              className="flex items-center justify-center gap-2 w-full px-4 py-2.5 bg-[#3b6ef6]/15 hover:bg-[#3b6ef6]/25 border border-[#3b6ef6]/30 text-[#93b4fd] text-[12px] font-medium rounded-lg transition-colors"
            >
              Open in Teams Admin Center <ExternalLink size={12} />
            </a>
          )}
        </div>
      </div>
    </div>
  )
}


// ── Business Applications Section (Salesforce SSPM, SALSA-inspired) ─────────

interface SalesforceConn {
  id: string
  name: string
  instance_url: string
  auth_method: string
  include_custom_only: boolean
  allow_bruteforce_probe: boolean
  last_scanned_at: string | null
  created_at: string | null
}

function SalesforceLogo({ size = 22 }: { size?: number }) {
  // Salesforce cloud mark (simplified, CC0)
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="#00A1E0">
      <path d="M9.998 5.482c.81-.846 1.94-1.37 3.19-1.37 1.66 0 3.11.927 3.88 2.302a4.74 4.74 0 0 1 1.94-.413c2.65 0 4.8 2.175 4.8 4.857 0 2.683-2.15 4.857-4.8 4.857a4.7 4.7 0 0 1-.95-.097c-.49 1.86-2.18 3.23-4.19 3.23-.84 0-1.64-.23-2.32-.64-.7 1.65-2.34 2.81-4.25 2.81-1.99 0-3.69-1.25-4.36-3.01a3.6 3.6 0 0 1-.74.08c-1.99 0-3.6-1.62-3.6-3.62 0-1.34.73-2.51 1.81-3.13a4.13 4.13 0 0 1-.34-1.66c0-2.29 1.86-4.15 4.15-4.15a4.1 4.1 0 0 1 3.2 1.53l.58.43z"/>
    </svg>
  )
}

function BusinessAppsSection({ alwaysShow = false }: { alwaysShow?: boolean }) {
  const [connections, setConnections] = useState<SalesforceConn[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [findingsCount, setFindingsCount] = useState<number>(0)
  const [guestObjects, setGuestObjects] = useState<number>(0)

  const [form, setForm] = useState({
    name: 'Salesforce Org',
    instance_url: '',
    auth_method: 'unauthenticated' as 'unauthenticated' | 'session' | 'aura_token',
    session_id: '',
    aura_token: '',
    include_custom_only: false,
    allow_bruteforce_probe: false,
  })

  const load = useCallback(async () => {
    try {
      setLoading(true)
      const [c, f, o] = await Promise.all([
        api.get('/api/salesforce/connections').catch(() => ({ data: [] })),
        api.get('/api/salesforce/findings?status=open').catch(() => ({ data: [] })),
        api.get('/api/salesforce/objects').catch(() => ({ data: [] })),
      ])
      setConnections(c.data || [])
      setFindingsCount((f.data || []).length)
      const objs = o.data || []
      setGuestObjects(objs.filter((x: { guest_accessible: boolean }) => x.guest_accessible).length)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const handleConnect = async () => {
    if (!form.instance_url.trim()) {
      setError('Instance URL is required (e.g. https://acme.lightning.force.com)')
      return
    }
    setConnecting(true)
    setError(null)
    try {
      await api.post('/api/salesforce/connect', {
        name: form.name,
        instance_url: form.instance_url.trim(),
        auth_method: form.auth_method,
        session_id: form.auth_method === 'session' ? form.session_id : undefined,
        aura_token: form.auth_method === 'aura_token' ? form.aura_token : undefined,
        include_custom_only: form.include_custom_only,
        allow_bruteforce_probe: form.allow_bruteforce_probe,
      })
      setShowModal(false)
      setForm({
        name: 'Salesforce Org', instance_url: '',
        auth_method: 'unauthenticated', session_id: '', aura_token: '',
        include_custom_only: false, allow_bruteforce_probe: false,
      })
      load()
    } catch (e) {
      const ex = e as { response?: { data?: { detail?: string } } }
      setError(ex?.response?.data?.detail || 'Failed to connect')
    } finally {
      setConnecting(false)
    }
  }

  const handleScan = async (id: string) => {
    setScanning(id)
    try {
      await api.post(`/api/salesforce/scan/${id}`)
      setTimeout(load, 5000)
    } catch (e) {
      console.error(e)
    } finally {
      setScanning(null)
    }
  }

  const handleDisconnect = async (id: string) => {
    if (!confirm('Disconnect this Salesforce org?')) return
    try {
      await api.delete(`/api/salesforce/connections/${id}`)
      load()
    } catch (e) {
      console.error(e)
    }
  }

  if (!alwaysShow && !loading && connections.length === 0) return null

  return (
    <div className="mt-8 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cloud size={16} className="text-[var(--muted)]" />
          <h3 className="text-[14px] font-semibold text-[var(--foreground)]">Business Applications</h3>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-[#13131a] border border-[var(--border)] rounded-xl p-5 hover:border-white/[0.12] transition-colors">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-[#00A1E0]/10">
                <SalesforceLogo size={24} />
              </div>
              <div>
                <span className="font-semibold text-[var(--foreground)]">Salesforce</span>
                <div className="text-[10px] text-[var(--muted)]">
                  SSPM · SALSA-inspired guest-data exposure probe
                </div>
              </div>
            </div>
            {connections.length === 0 ? (
              <Button size="sm" onClick={() => setShowModal(true)} disabled={connecting}>
                Connect
              </Button>
            ) : (
              <div className="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded">
                {connections.length} connected
              </div>
            )}
          </div>

          <p className="text-[11px] text-[var(--muted)] mb-3 leading-relaxed">
            Probes your Salesforce instance for guest-accessible sObjects,
            anonymous REST/SOAP API exposure, and predictable record IDs.
            Read-only — never writes or creates records.
          </p>

          {connections.length > 0 && (
            <>
              <div className="grid grid-cols-2 gap-2 mb-3">
                <div className="bg-[var(--background)]/50 rounded-lg p-2">
                  <div className="text-[9px] text-[var(--muted)] uppercase tracking-wide">Open findings</div>
                  <div className="text-[16px] font-semibold text-[var(--foreground)]">{findingsCount}</div>
                </div>
                <div className="bg-[var(--background)]/50 rounded-lg p-2">
                  <div className="text-[9px] text-[var(--muted)] uppercase tracking-wide">Guest sObjects</div>
                  <div className="text-[16px] font-semibold text-amber-300">{guestObjects}</div>
                </div>
              </div>

              <div className="space-y-2">
                {connections.map(conn => (
                  <div key={conn.id} className="bg-[var(--background)]/50 rounded-lg p-2 flex items-center justify-between">
                    <div>
                      <div className="text-[11px] font-medium text-[var(--foreground)]">{conn.name}</div>
                      <div className="text-[9px] text-[var(--muted)]">
                        {conn.instance_url.replace(/^https?:\/\//, '')} · {conn.auth_method}
                      </div>
                    </div>
                    <div className="flex gap-1">
                      <Button size="sm" variant="ghost" onClick={() => handleScan(conn.id)} disabled={scanning === conn.id}>
                        {scanning === conn.id ? <RefreshCw size={11} className="animate-spin" /> : <RefreshCw size={11} />}
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => handleDisconnect(conn.id)} className="text-red-400">
                        <Unplug size={11} />
                      </Button>
                    </div>
                  </div>
                ))}
                <button onClick={() => setShowModal(true)} className="w-full py-1.5 text-[10px] text-[var(--muted)] hover:text-[var(--foreground)] border border-dashed border-[var(--border)] rounded-lg">
                  + Add Salesforce org
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-[#0f0f12] border border-[var(--border)] rounded-xl p-6 max-w-lg w-full max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-[15px] font-semibold text-[var(--foreground)]">Connect Salesforce</h3>
              <button onClick={() => setShowModal(false)} className="text-[var(--muted)] hover:text-[var(--foreground)]">
                <X size={16} />
              </button>
            </div>
            {error && (
              <div className="mb-3 text-[12px] text-red-300 bg-red-900/20 border border-red-800/40 rounded-lg p-2">
                {error}
              </div>
            )}
            <div className="space-y-3">
              <div>
                <label className="text-[11px] text-[var(--muted)]">Name</label>
                <input
                  value={form.name}
                  onChange={e => setForm({ ...form, name: e.target.value })}
                  className="w-full bg-[#111114] border border-[var(--border)] rounded-lg px-3 py-2 text-[12px] text-[var(--foreground)]"
                />
              </div>
              <div>
                <label className="text-[11px] text-[var(--muted)]">Instance URL *</label>
                <input
                  value={form.instance_url}
                  onChange={e => setForm({ ...form, instance_url: e.target.value })}
                  placeholder="https://acme.lightning.force.com"
                  className="w-full bg-[#111114] border border-[var(--border)] rounded-lg px-3 py-2 text-[12px] text-[var(--foreground)]"
                />
              </div>
              <div>
                <label className="text-[11px] text-[var(--muted)]">Auth method</label>
                <select
                  value={form.auth_method}
                  onChange={e => setForm({ ...form, auth_method: e.target.value as 'unauthenticated' | 'session' | 'aura_token' })}
                  className="w-full bg-[#111114] border border-[var(--border)] rounded-lg px-3 py-2 text-[12px] text-[var(--foreground)]"
                >
                  <option value="unauthenticated">Unauthenticated (guest user probe)</option>
                  <option value="session">Session ID cookie</option>
                  <option value="aura_token">Aura token</option>
                </select>
              </div>
              {form.auth_method === 'session' && (
                <div>
                  <label className="text-[11px] text-[var(--muted)]">Session ID</label>
                  <input
                    type="password"
                    value={form.session_id}
                    onChange={e => setForm({ ...form, session_id: e.target.value })}
                    className="w-full bg-[#111114] border border-[var(--border)] rounded-lg px-3 py-2 text-[12px] text-[var(--foreground)] font-mono"
                  />
                </div>
              )}
              {form.auth_method === 'aura_token' && (
                <div>
                  <label className="text-[11px] text-[var(--muted)]">Aura Token</label>
                  <input
                    type="password"
                    value={form.aura_token}
                    onChange={e => setForm({ ...form, aura_token: e.target.value })}
                    className="w-full bg-[#111114] border border-[var(--border)] rounded-lg px-3 py-2 text-[12px] text-[var(--foreground)] font-mono"
                  />
                </div>
              )}
              <label className="flex items-center gap-2 text-[12px] text-[var(--foreground)]">
                <input
                  type="checkbox"
                  checked={form.include_custom_only}
                  onChange={e => setForm({ ...form, include_custom_only: e.target.checked })}
                />
                Probe only custom objects (*__c)
              </label>
              <label className="flex items-center gap-2 text-[12px] text-[var(--foreground)]">
                <input
                  type="checkbox"
                  checked={form.allow_bruteforce_probe}
                  onChange={e => setForm({ ...form, allow_bruteforce_probe: e.target.checked })}
                />
                Allow record-ID bruteforce probe (politer to leave off)
              </label>
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
                <div className="text-[11px] text-amber-200">
                  This connector implements a defensive read-only version of the
                  <a href="https://github.com/cosad3s/salsa" target="_blank" rel="noreferrer" className="underline mx-1">SALSA</a>
                  pentest tool. It never creates or modifies records. Use it on
                  Salesforce orgs you own/operate.
                </div>
              </div>
              <div className="flex gap-2 pt-2">
                <Button size="sm" onClick={handleConnect} disabled={connecting || !form.instance_url}>
                  {connecting ? 'Connecting…' : 'Connect & scan'}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setShowModal(false)}>Cancel</Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
