import type { PolicyRule, RuleConditions } from './types'

export interface PolicyRuleTemplate {
  id: string
  label: string
  description: string
  rule_id_prefix: string
  name: string
  action: PolicyRule['action']
  priority: number
  conditions: Partial<RuleConditions>
}

const IDENTITY_ENTITY_TYPES = [
  'CREDIT_CARD',
  'IBAN_CODE',
  'US_BANK_NUMBER',
  'US_SSN',
  'US_PASSPORT',
  'US_DRIVER_LICENSE',
  'UK_NHS',
  'UK_NINO',
  'IN_AADHAAR',
  'IN_PAN',
] as const

function baseConditions(overrides: Partial<RuleConditions> = {}): RuleConditions {
  return {
    entity_types: [],
    detectors: [],
    min_confidence: 0.8,
    min_match_count: 1,
    min_llm_confidence: 0,
    llm_classifications: [],
    llm_categories: [],
    external_recipients_only: true,
    recipient_domains: [],
    match_all: false,
    ...overrides,
  }
}

export const POLICY_RULE_TEMPLATES: readonly PolicyRuleTemplate[] = [
  {
    id: 'hold-pii-external',
    label: 'Hold PII to external',
    description: 'Hold mail with financial or identity entities sent outside the tenant.',
    rule_id_prefix: 'template.pii.external',
    name: 'Hold PII sent externally',
    action: 'hold',
    priority: 20,
    conditions: {
      entity_types: [...IDENTITY_ENTITY_TYPES],
      min_confidence: 0.8,
      external_recipients_only: true,
    },
  },
  {
    id: 'stop-credentials',
    label: 'Stop credentials',
    description: 'Stop outbound mail when the credential detector matches.',
    rule_id_prefix: 'template.credentials.external',
    name: 'Stop credentials sent externally',
    action: 'stop',
    priority: 10,
    conditions: {
      detectors: ['credential'],
      min_confidence: 0.8,
      external_recipients_only: true,
    },
  },
  {
    id: 'hold-lexicon',
    label: 'Hold lexicon',
    description: 'Hold mail that matches tenant confidential terms.',
    rule_id_prefix: 'template.lexicon.external',
    name: 'Hold confidential terms sent externally',
    action: 'hold',
    priority: 30,
    conditions: {
      detectors: ['lexicon'],
      min_confidence: 0.75,
      external_recipients_only: true,
    },
  },
]

export function uniqueSuffix() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID().slice(0, 8)
  }
  return Date.now().toString(36)
}

export function ruleFromTemplate(template: PolicyRuleTemplate): PolicyRule {
  return {
    rule_id: `${template.rule_id_prefix}.${uniqueSuffix()}`.slice(0, 128),
    name: template.name,
    action: template.action,
    priority: template.priority,
    enabled: true,
    conditions: baseConditions(template.conditions),
  }
}

export function createBlankRule(): PolicyRule {
  return {
    rule_id: `custom.rule.${uniqueSuffix()}`.slice(0, 128),
    name: 'New DLP rule',
    action: 'hold',
    priority: 100,
    enabled: false,
    conditions: baseConditions(),
  }
}
