import type { PolicyRule } from './types'

function joinList(values: string[], empty = '') {
  if (values.length === 0) return empty
  if (values.length === 1) return values[0]
  return `${values.slice(0, -1).join(', ')} and ${values[values.length - 1]}`
}

export function describeRule(rule: PolicyRule): string {
  const conditions = rule.conditions
  const action = rule.action.toUpperCase()
  const scope = [
    conditions.external_recipients_only ? 'external recipients' : null,
    conditions.recipient_domains.length
      ? `domains ${joinList(conditions.recipient_domains)}`
      : null,
  ].filter((item): item is string => Boolean(item))
  const scopeText = scope.length ? ` to ${scope.join(', ')}` : ''

  if (conditions.match_all) {
    return `Match every message${scopeText} → ${action}`
  }

  const findingParts: string[] = []
  if (conditions.detectors.length && conditions.entity_types.length) {
    findingParts.push(
      `${joinList(conditions.detectors)} AND ${joinList(conditions.entity_types)}`,
    )
  } else if (conditions.detectors.length) {
    findingParts.push(joinList(conditions.detectors))
  } else if (conditions.entity_types.length) {
    findingParts.push(joinList(conditions.entity_types))
  }

  const llmParts: string[] = []
  if (conditions.llm_classifications.length) {
    llmParts.push(`LLM ${joinList(conditions.llm_classifications)}`)
  }
  if (conditions.llm_categories.length) {
    llmParts.push(`categories ${joinList(conditions.llm_categories)}`)
  }

  const content = [...findingParts, ...llmParts]
  if (content.length === 0) {
    return `No content filter${scopeText} → ${action}`
  }
  return `If ${content.join('; ')}${scopeText} → ${action}`
}

export function hasContentFilters(rule: PolicyRule): boolean {
  const conditions = rule.conditions
  return (
    conditions.entity_types.length > 0
    || conditions.detectors.length > 0
    || conditions.llm_classifications.length > 0
    || conditions.llm_categories.length > 0
  )
}
