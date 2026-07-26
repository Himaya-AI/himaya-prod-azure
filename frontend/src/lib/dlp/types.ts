export type DlpMode = 'monitor' | 'enforce'
export type PolicyAction = 'allow' | 'hold' | 'stop'
export type PolicyStatus = 'builtin' | 'draft' | 'published' | 'archived'

export interface DlpStatus {
  status: 'disabled' | 'ready'
  pipeline_enabled: boolean
  mode: DlpMode
  classifier_url_configured: boolean
  legacy_independent: boolean
  message_counts: Record<string, number>
  failed_outbox_commands: number
}

export interface DlpTenantSettings {
  enabled: boolean
  mode: DlpMode
  domains: string[]
  lexicon_version: string
  active_policy_version: number | null
}

export interface DlpTenantSettingsUpdate {
  enabled: boolean
  mode: DlpMode
  domains: string[]
  lexicon_version: string
}

export interface RuleConditions {
  entity_types: string[]
  detectors: string[]
  min_confidence: number
  min_match_count: number
  llm_classifications: string[]
  llm_categories: string[]
  external_recipients_only: boolean
  recipient_domains: string[]
}

export interface PolicyRule {
  rule_id: string
  name: string
  action: PolicyAction
  conditions: RuleConditions
  priority: number
  enabled: boolean
}

export interface PolicyDocument {
  default_action: PolicyAction
  rules: PolicyRule[]
}

export interface PolicyVersion {
  id: string | null
  version: number
  status: PolicyStatus
  document: PolicyDocument
  created_at: string | null
  published_at: string | null
}

export interface DlpMessageSummary {
  message_id: string
  envelope_from: string
  envelope_to: string[]
  state: string
  received_at: string
  intended_action: string | null
  effective_action: string | null
  explanation: string | null
}

export interface DlpMessageList {
  items: DlpMessageSummary[]
  next_cursor: string | null
}

export interface DlpMessageListParams {
  state?: string
  before?: string
  limit?: number
}

export interface DlpReviewActionRequest {
  reason: string
  idempotency_key: string
}

export interface DlpReviewActionResponse {
  message_id: string
  action: 'release' | 'stop'
  command_id: string
  status: 'queued' | 'already_queued'
}

export type DlpReviewAction = 'release' | 'stop'
