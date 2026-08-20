import type { PolicyAction, PolicyDocument, PolicyRule, RuleConditions } from './types'

export interface PolicyFieldChange {
  label: string
  from: string
  to: string
}

export type PolicyChange =
  | { kind: 'default_action'; from: PolicyAction; to: PolicyAction }
  | { kind: 'added'; rule: PolicyRule }
  | { kind: 'removed'; rule: PolicyRule }
  | {
    kind: 'changed'
    ruleId: string
    name: string
    fields: PolicyFieldChange[]
  }

function formatList(values: string[]) {
  const next = [...values].map((item) => item.trim()).filter(Boolean).sort()
  return next.length ? next.join(', ') : '—'
}

function formatBool(value: boolean) {
  return value ? 'yes' : 'no'
}

function formatEnabled(value: boolean) {
  return value ? 'On' : 'Off'
}

function conditionFields(conditions: RuleConditions): Array<[string, string]> {
  return [
    ['Detectors', formatList(conditions.detectors)],
    ['Entity types', formatList(conditions.entity_types)],
    ['Min confidence', String(conditions.min_confidence)],
    ['Min LLM confidence', String(conditions.min_llm_confidence ?? 0)],
    ['Min matches', String(conditions.min_match_count)],
    ['LLM classifications', formatList(conditions.llm_classifications)],
    ['LLM categories', formatList(conditions.llm_categories)],
    ['Recipient domains', formatList(conditions.recipient_domains)],
    ['External recipients only', formatBool(conditions.external_recipients_only)],
    ['Match all', formatBool(Boolean(conditions.match_all))],
  ]
}

function ruleFields(rule: PolicyRule): Array<[string, string]> {
  return [
    ['Name', rule.name],
    ['Action', rule.action],
    ['Enabled', formatEnabled(rule.enabled)],
    ['Priority', String(rule.priority)],
    ...conditionFields(rule.conditions),
  ]
}

function diffRule(before: PolicyRule, after: PolicyRule): PolicyFieldChange[] {
  const previous = new Map(ruleFields(before))
  const fields: PolicyFieldChange[] = []
  for (const [label, to] of ruleFields(after)) {
    const from = previous.get(label) ?? '—'
    if (from !== to) fields.push({ label, from, to })
  }
  return fields
}

export function diffPolicies(
  published: PolicyDocument,
  draft: PolicyDocument,
): PolicyChange[] {
  const changes: PolicyChange[] = []
  if (published.default_action !== draft.default_action) {
    changes.push({
      kind: 'default_action',
      from: published.default_action,
      to: draft.default_action,
    })
  }

  const publishedById = new Map(published.rules.map((rule) => [rule.rule_id, rule]))
  const draftById = new Map(draft.rules.map((rule) => [rule.rule_id, rule]))

  for (const rule of draft.rules) {
    const previous = publishedById.get(rule.rule_id)
    if (!previous) {
      changes.push({ kind: 'added', rule })
      continue
    }
    const fields = diffRule(previous, rule)
    if (fields.length > 0) {
      changes.push({
        kind: 'changed',
        ruleId: rule.rule_id,
        name: rule.name,
        fields,
      })
    }
  }

  for (const rule of published.rules) {
    if (!draftById.has(rule.rule_id)) {
      changes.push({ kind: 'removed', rule })
    }
  }

  return changes
}

export function summarizePolicyDiff(changes: PolicyChange[]) {
  const added = changes.filter((change) => change.kind === 'added').length
  const removed = changes.filter((change) => change.kind === 'removed').length
  const changed = changes.filter((change) => change.kind === 'changed').length
  const defaultAction = changes.find((change) => change.kind === 'default_action')
  const parts = [
    added ? `${added} added` : null,
    changed ? `${changed} changed` : null,
    removed ? `${removed} removed` : null,
    defaultAction && defaultAction.kind === 'default_action'
      ? `default action ${defaultAction.from} → ${defaultAction.to}`
      : null,
  ].filter((item): item is string => Boolean(item))
  return parts.length ? parts.join(', ') : 'no rule changes'
}
