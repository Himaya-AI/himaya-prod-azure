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
  reviewable_count?: number
  oldest_reviewable_at?: string | null
  oldest_reviewable_from?: string | null
  failed_outbox_commands: number
  failed_outbox_items?: DlpFailedOutboxCommand[]
}

export interface DlpFailedOutboxCommand {
  command_id: string
  message_id: string
  command_type: string
  last_error: string | null
  attempts: number
  updated_at: string
  envelope_from: string | null
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
  reviewable: boolean
}

export interface DlpMessageList {
  items: DlpMessageSummary[]
  next_cursor: string | null
  next_id?: string | null
}

export interface DlpMessageListParams {
  state?: string
  reviewable?: boolean
  before?: string
  before_id?: string
  limit?: number
}

export interface DlpFindingSummary {
  detector: string
  entity_type: string
  confidence: number
}

export interface DlpPartSummary {
  part_index: number
  content_type: string
  filename: string | null
  extraction_status: string
  limitation_code: string | null
  limitation_detail: string | null
}

export interface DlpExtractionLimitation {
  code: string
  detail: string
}

export interface DlpReviewHistoryItem {
  action: 'release' | 'stop'
  reason: string
  actor_user_id: string
  created_at: string
}

export interface DlpDeliveryAttempt {
  outcome: string
  resulting_state: string
  attempt_number: number
  smtp_stage: string | null
  smtp_code: number | null
  smtp_message: string | null
  detail: string | null
  remote_host: string | null
  accepted_recipients: string[]
  refused_recipients: string[]
  attempt_started_at: string | null
  attempt_finished_at: string | null
  occurred_at: string
}

export interface DlpCommandStatus {
  command_id: string
  command_type: string
  status: 'queued' | 'sent' | 'failed' | string
  attempts: number
  last_error: string | null
  created_at: string
  published_at: string | null
  gateway_status: string | null
}

export interface DlpMessageDetail extends DlpMessageSummary {
  policy_version: string | null
  matched_rule_ids: string[]
  findings: DlpFindingSummary[]
  extraction_limitations: DlpExtractionLimitation[]
  parts: DlpPartSummary[]
  subject: string | null
  sanitized_preview: string | null
  preview_available: boolean
  review_history: DlpReviewHistoryItem[]
  deliveries: DlpDeliveryAttempt[]
  commands: DlpCommandStatus[]
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

export type DlpNavigateTarget =
  | { tab: 'queue' }
  | { tab: 'policy' }
  | { tab: 'messages'; filter?: string }
