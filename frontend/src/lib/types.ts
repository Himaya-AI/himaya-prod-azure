export interface User {
  id: string
  email: string
  name?: string
  full_name?: string
  role: 'admin' | 'analyst' | 'viewer'
  is_active: boolean
  is_vip?: boolean
  risk_score?: number
  department?: string | null
  job_title?: string | null
  org_id?: string
  organization_id?: string
  last_login?: string
  created_at: string
  tier?: string
  plan?: string
}

export interface Organization {
  id: string
  name: string
  domain: string
  country: string
  language: 'en' | 'ar'
  mfa_enforced: boolean
  created_at: string
}

export interface Threat {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'new' | 'quarantined' | 'released' | 'false_positive' | 'investigating'
  subject: string
  sender: string
  sender_domain: string
  recipient: string
  received_at: string
  graph_score: number
  content_score: number
  reputation_score: number
  overall_score: number
  ai_explanation_en: string
  ai_explanation_ar: string
  sama_controls: string[]
  nca_controls: string[]
  timeline: ThreatEvent[]
  organization_id: string
}

export interface ThreatEvent {
  timestamp: string
  action: string
  actor: string
  details: string
}

export interface ThreatFeedEvent {
  id: string
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  sender_domain: string
  recipient: string
  received_at: string
}

export interface Employee {
  id: string
  name: string
  email: string
  department?: string | null
  job_title?: string | null
  role?: string
  risk_score: number
  threats_30d: number
  is_vip?: boolean
  last_threat_at?: string | null
  organization_id?: string
}

export interface Policy {
  id: string
  name: string
  priority: number
  status: 'active' | 'shadow' | 'paused' | 'draft'
  action: 'quarantine' | 'alert' | 'block' | 'allow' | 'tag'
  conditions: PolicyCondition[]
  created_at: string
  updated_at: string
}

export interface PolicyCondition {
  field: string
  operator: string
  value: string
}

export interface ComplianceControl {
  id: string
  control_id: string
  framework: 'SAMA_CSF' | 'NCA_ECC' | 'UAE_NESA' | 'CBUAE'
  name_en: string
  name_ar: string
  control_name_en?: string  // alias from backend
  control_name_ar?: string  // alias from backend
  status: 'compliant' | 'partial' | 'non_compliant' | 'not_applicable' | 'not_started'
  evidence_count: number
  description?: string
}

export interface DashboardSummary {
  status: 'healthy' | 'warning' | 'critical'
  threats_this_week: number
  total_threats_week?: number
  quarantined_today: number
  risk_score: number
  compliance_score: number
  active_threats: number
  total_employees: number
  total_threats_today?: number
  total_threats_month?: number
  top_threat_type?: string | null
  threat_type_breakdown?: Record<string, number>
}

export interface TrendDataPoint {
  date: string
  threats_detected: number
  quarantined: number
}

export interface AtRiskEmployee {
  id: string
  name: string
  email: string
  department: string
  risk_score: number
  threats_30d: number
}

export interface AuthResponse {
  access_token: string
  token_type: string
  user: User
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  size: number
  pages: number
}
