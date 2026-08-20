'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Copy,
  Info,
  Lock,
  Plus,
  Save,
  Send,
  Trash2,
} from 'lucide-react'

import Button from '@/components/ui/Button'
import { toast } from '@/components/ui/Toast'
import { ActionChip } from './DlpChrome'
import DlpPolicyDiff from './DlpPolicyDiff'
import {
  getDlpErrorMessage,
  getDlpPolicyDraft,
  publishDlpPolicy,
  saveDlpPolicyDraft,
} from '@/lib/dlp/api'
import { diffPolicies, summarizePolicyDiff } from '@/lib/dlp/policy-diff'
import {
  POLICY_RULE_TEMPLATES,
  createBlankRule,
  ruleFromTemplate,
  uniqueSuffix,
  type PolicyRuleTemplate,
} from '@/lib/dlp/policy-templates'
import {
  DLP_DETECTORS,
  DLP_ENTITY_TYPES,
  DLP_LLM_CLASSIFICATIONS,
} from '@/lib/dlp/policy-options'
import type {
  PolicyAction,
  PolicyDocument,
  PolicyRule,
  PolicyVersion,
  RuleConditions,
} from '@/lib/dlp/types'

interface Props {
  activePolicy: PolicyVersion
  draftPolicy: PolicyVersion | null
  canManage: boolean
  onChanged: () => Promise<void>
}

function cloneDocument(document: PolicyDocument): PolicyDocument {
  return JSON.parse(JSON.stringify(document)) as PolicyDocument
}

function splitValues(value: string): string[] {
  return [...new Set(
    value
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean),
  )]
}

function PolicyField({
  label,
  value,
  onChange,
  placeholder,
  disabled,
}: {
  label: string
  value: string[]
  onChange: (value: string[]) => void
  placeholder: string
  disabled: boolean
}) {
  const [draft, setDraft] = useState<string | null>(null)

  return (
    <label className="block">
      <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">
        {label}
      </span>
      <input
        value={draft ?? value.join(', ')}
        onFocus={() => setDraft((current) => current ?? value.join(', '))}
        onChange={(event) => setDraft(event.target.value)}
        onBlur={() => {
          onChange(splitValues(draft ?? value.join(', ')))
          setDraft(null)
        }}
        placeholder={placeholder}
        disabled={disabled}
        className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-xs text-white outline-none focus:border-[#3b6ef6]/60 disabled:opacity-60"
      />
    </label>
  )
}

interface ChipOption {
  value: string
  label: string
}

function PolicyChipSelect({
  label,
  options,
  value,
  onChange,
  disabled,
}: {
  label: string
  options: readonly ChipOption[]
  value: string[]
  onChange: (value: string[]) => void
  disabled: boolean
}) {
  const known = new Set(options.map((option) => option.value))
  const chips: ChipOption[] = [
    ...options,
    ...value
      .filter((item) => !known.has(item))
      .map((item) => ({ value: item, label: item })),
  ]

  function toggle(option: string) {
    onChange(
      value.includes(option)
        ? value.filter((item) => item !== option)
        : [...value, option],
    )
  }

  return (
    <div>
      <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">
        {label}
      </span>
      <div role="group" aria-label={label} className="flex flex-wrap gap-1.5">
        {chips.map((option) => {
          const selected = value.includes(option.value)
          return (
            <button
              key={option.value}
              type="button"
              aria-pressed={selected}
              disabled={disabled}
              onClick={() => toggle(option.value)}
              className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                selected
                  ? 'border-[#3b6ef6]/50 bg-[#3b6ef6]/15 text-[#93b4fd]'
                  : 'border-white/[0.08] bg-white/[0.02] text-[#71717a] hover:border-white/[0.16] hover:text-[#a1a1aa]'
              }`}
            >
              {option.label}
            </button>
          )
        })}
      </div>
    </div>
  )
}

function ruleHasNoContentConditions(rule: PolicyRule): boolean {
  const conditions = rule.conditions
  return (
    conditions.entity_types.length === 0 &&
    conditions.detectors.length === 0 &&
    conditions.llm_classifications.length === 0 &&
    conditions.llm_categories.length === 0 &&
    conditions.recipient_domains.length === 0
  )
}

function RuleEditor({
  rule,
  disabled,
  expanded,
  onToggleExpanded,
  onChange,
  onDuplicate,
  onDelete,
  duplicateDisabled = false,
}: {
  rule: PolicyRule
  disabled: boolean
  expanded: boolean
  onToggleExpanded: () => void
  onChange: (rule: PolicyRule) => void
  onDuplicate: () => void
  onDelete: () => void
  duplicateDisabled?: boolean
}) {
  function patch(values: Partial<PolicyRule>) {
    onChange({ ...rule, ...values })
  }

  function patchConditions(values: Partial<RuleConditions>) {
    patch({ conditions: { ...rule.conditions, ...values } })
  }

  const detectChips = [
    ...rule.conditions.detectors,
    ...rule.conditions.entity_types.slice(0, 3),
  ]
  const hasFindingConditions = (
    rule.conditions.detectors.length > 0
    || rule.conditions.entity_types.length > 0
  )

  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.07] bg-[#13131a]">
      <div className="flex items-center gap-3 px-4 py-3">
        <button
          type="button"
          role="switch"
          aria-checked={rule.enabled}
          disabled={disabled}
          title="On/Off is not live until you save this draft and publish."
          onClick={() => patch({ enabled: !rule.enabled })}
          className={`w-14 shrink-0 rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wide transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
            rule.enabled
              ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
              : 'border-white/[0.08] bg-white/[0.03] text-[#71717a]'
          }`}
        >
          {rule.enabled ? 'On' : 'Off'}
        </button>
        <button
          type="button"
          onClick={onToggleExpanded}
          className="min-w-0 flex-1 text-left"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-medium text-white">{rule.name}</span>
            <ActionChip action={rule.action} />
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            <span className="text-[11px] text-[#71717a]">
              Priority {rule.priority}
            </span>
            {detectChips.length > 0 ? detectChips.map((chip, chipIndex) => (
              <span
                key={`${chip}-${chipIndex}`}
                className="rounded border border-white/[0.07] bg-[#1e1e2c] px-1.5 py-0.5 text-[10px] text-[#a1a1aa]"
              >
                {chip.replaceAll('_', ' ')}
              </span>
            )) : (
              <span className="text-[11px] text-[#52525b]">No detectors set</span>
            )}
          </div>
        </button>
        <button
          type="button"
          onClick={onToggleExpanded}
          aria-label={expanded ? 'Collapse rule' : 'Expand rule'}
          className="p-1 text-[#71717a] hover:text-white"
        >
          {expanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
        </button>
      </div>

      {expanded && (
        <div className="space-y-4 border-t border-white/[0.06] p-4">
          <div className="grid gap-3 md:grid-cols-2">
            <label>
              <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">Name</span>
              <input
                value={rule.name}
                maxLength={255}
                disabled={disabled}
                onChange={(event) => patch({ name: event.target.value })}
                className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-xs text-white outline-none focus:border-[#3b6ef6]/60 disabled:opacity-60"
              />
            </label>
            <label>
              <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">Rule ID</span>
              <input
                value={rule.rule_id}
                maxLength={128}
                disabled={disabled}
                onChange={(event) => patch({ rule_id: event.target.value })}
                className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 font-mono text-xs text-white outline-none focus:border-[#3b6ef6]/60 disabled:opacity-60"
              />
            </label>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <label>
              <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">Action</span>
              <select
                value={rule.action}
                disabled={disabled}
                onChange={(event) => patch({ action: event.target.value as PolicyAction })}
                className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-xs text-white outline-none disabled:opacity-60"
              >
                <option value="allow">Allow</option>
                <option value="hold">Hold</option>
                <option value="stop">Stop</option>
              </select>
            </label>
            <label>
              <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">Priority</span>
              <input
                type="number"
                min={0}
                max={10000}
                value={rule.priority}
                disabled={disabled}
                onChange={(event) => patch({ priority: Number(event.target.value) })}
                className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-xs text-white outline-none disabled:opacity-60"
              />
            </label>
            <label>
              <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">Min confidence</span>
              <input
                type="number"
                min={0}
                max={1}
                step={0.05}
                value={rule.conditions.min_confidence}
                disabled={disabled || !hasFindingConditions}
                onChange={(event) => patchConditions({ min_confidence: Number(event.target.value) })}
                className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-xs text-white outline-none disabled:opacity-60"
              />
            </label>
            <label>
              <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">Min matches</span>
              <input
                type="number"
                min={1}
                value={rule.conditions.min_match_count}
                disabled={disabled || !hasFindingConditions}
                onChange={(event) => patchConditions({ min_match_count: Number(event.target.value) })}
                className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-xs text-white outline-none disabled:opacity-60"
              />
            </label>
          </div>

          {ruleHasNoContentConditions(rule) && (
            <div className="flex gap-2 rounded-lg border border-amber-500/20 bg-amber-500/[0.06] px-3 py-2">
              <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-400" />
              <p className="text-xs text-amber-200/80">
                {rule.conditions.external_recipients_only
                  ? 'This rule has no content conditions and will match every external message if enabled.'
                  : 'This rule has no content conditions and will match every message if enabled.'}
              </p>
            </div>
          )}
          {!hasFindingConditions && (
            <p className="text-[11px] text-[#52525b]">
              Min confidence and min matches apply only when detectors or entity types are set.
            </p>
          )}

          <div className="grid gap-3 md:grid-cols-2">
            <PolicyChipSelect
              label="Detectors"
              options={DLP_DETECTORS}
              value={rule.conditions.detectors}
              onChange={(detectors) => patchConditions({ detectors })}
              disabled={disabled}
            />
            <PolicyChipSelect
              label="Entity types"
              options={DLP_ENTITY_TYPES.map((entityType) => ({
                value: entityType,
                label: entityType.replaceAll('_', ' '),
              }))}
              value={rule.conditions.entity_types}
              onChange={(entity_types) => patchConditions({ entity_types })}
              disabled={disabled}
            />
            <PolicyChipSelect
              label="LLM classifications"
              options={DLP_LLM_CLASSIFICATIONS.map((classification) => ({
                value: classification,
                label: classification,
              }))}
              value={rule.conditions.llm_classifications}
              onChange={(llm_classifications) => patchConditions({ llm_classifications })}
              disabled={disabled}
            />
            <PolicyField
              label="LLM categories"
              value={rule.conditions.llm_categories}
              onChange={(llm_categories) => patchConditions({ llm_categories })}
              placeholder="financial, legal"
              disabled={disabled}
            />
            <PolicyField
              label="Recipient domains"
              value={rule.conditions.recipient_domains}
              onChange={(recipient_domains) => patchConditions({ recipient_domains })}
              placeholder="partner.example"
              disabled={disabled}
            />
            <label className="flex items-center gap-2 self-end rounded-lg border border-white/[0.07] px-3 py-2">
              <input
                type="checkbox"
                checked={rule.conditions.external_recipients_only}
                disabled={disabled}
                onChange={(event) => patchConditions({ external_recipients_only: event.target.checked })}
                className="accent-[#3b6ef6]"
              />
              <span className="text-xs text-[#a1a1aa]">External recipients only</span>
            </label>
          </div>

          <div className="flex justify-end gap-2 border-t border-white/[0.06] pt-3">
            <Button
              variant="ghost"
              size="sm"
              disabled={disabled || duplicateDisabled}
              onClick={onDuplicate}
            >
              <Copy size={13} /> Duplicate
            </Button>
            <Button variant="ghost" size="sm" disabled={disabled} onClick={onDelete} className="text-red-400">
              <Trash2 size={13} /> Delete
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}

function policyIdentity(activePolicy: PolicyVersion, draftPolicy: PolicyVersion | null) {
  const source = draftPolicy ?? activePolicy
  return [
    activePolicy.id ?? 'active',
    activePolicy.version,
    activePolicy.status,
    activePolicy.published_at ?? '',
    draftPolicy?.id ?? 'no-draft',
    draftPolicy?.version ?? '',
    draftPolicy?.status ?? '',
    JSON.stringify(source.document),
  ].join(':')
}

function isWholeNumber(value: number) {
  return Number.isInteger(value) && Number.isFinite(value)
}

export default function DlpPolicyTab({
  activePolicy,
  draftPolicy,
  canManage,
  onChanged,
}: Props) {
  const source = draftPolicy?.document ?? activePolicy.document
  const [document, setDocument] = useState<PolicyDocument>(() => cloneDocument(source))
  const [savedSnapshot, setSavedSnapshot] = useState(() => JSON.stringify(source))
  const [expandedRule, setExpandedRule] = useState<string | null>(source.rules[0]?.rule_id ?? null)
  const [saving, setSaving] = useState(false)
  const [publishing, setPublishing] = useState(false)
  const [syncedIdentity, setSyncedIdentity] = useState(
    () => policyIdentity(activePolicy, draftPolicy),
  )

  const dirty = JSON.stringify(document) !== savedSnapshot
  const publishedDiff = useMemo(
    () => diffPolicies(activePolicy.document, document),
    [activePolicy.document, document],
  )

  useEffect(() => {
    const nextIdentity = policyIdentity(activePolicy, draftPolicy)
    if (dirty && nextIdentity === syncedIdentity) return
    if (dirty && nextIdentity !== syncedIdentity) {
      toast.error('The saved draft changed on the server. Your unsaved edits were kept.')
      setSyncedIdentity(nextIdentity)
      return
    }

    const next = draftPolicy?.document ?? activePolicy.document
    setDocument(cloneDocument(next))
    setSavedSnapshot(JSON.stringify(next))
    setSyncedIdentity(nextIdentity)
    setExpandedRule((current) => {
      if (current && next.rules.some((rule) => rule.rule_id === current)) {
        return current
      }
      return next.rules[0]?.rule_id ?? null
    })
  }, [activePolicy, draftPolicy, dirty, syncedIdentity])
  const duplicateIds = useMemo(() => {
    const seen = new Set<string>()
    return document.rules
      .map((rule) => rule.rule_id)
      .filter((id) => {
        if (seen.has(id)) return true
        seen.add(id)
        return false
      })
  }, [document.rules])
  const valid =
    duplicateIds.length === 0 &&
    document.rules.length <= 500 &&
    document.rules.every((rule) =>
      Boolean(rule.rule_id.trim()) &&
      Boolean(rule.name.trim()) &&
      isWholeNumber(rule.priority) &&
      rule.priority >= 0 &&
      rule.priority <= 10000 &&
      Number.isFinite(rule.conditions.min_confidence) &&
      rule.conditions.min_confidence >= 0 &&
      rule.conditions.min_confidence <= 1 &&
      isWholeNumber(rule.conditions.min_match_count) &&
      rule.conditions.min_match_count >= 1,
    )
  const editingLocked = !canManage || saving || publishing

  function replaceRule(index: number, rule: PolicyRule) {
    setDocument((current) => ({
      ...current,
      rules: current.rules.map((item, itemIndex) => itemIndex === index ? rule : item),
    }))
  }

  function addRule(rule: PolicyRule = createBlankRule()) {
    setDocument((current) => ({ ...current, rules: [...current.rules, rule] }))
    setExpandedRule(rule.rule_id)
  }

  function addTemplate(template: PolicyRuleTemplate) {
    addRule(ruleFromTemplate(template))
  }

  function duplicateRule(index: number) {
    if (document.rules.length >= 500) return
    const rule = cloneDocument({
      default_action: document.default_action,
      rules: [document.rules[index]],
    }).rules[0]
    const suffix = uniqueSuffix()
    const marker = `.copy.${suffix}`
    const base = rule.rule_id.slice(0, Math.max(1, 128 - marker.length))
    rule.rule_id = `${base}${marker}`.slice(0, 128)
    rule.name = `${rule.name} (copy)`.slice(0, 255)
    setDocument((current) => ({ ...current, rules: [...current.rules, rule] }))
    setExpandedRule(rule.rule_id)
  }

  async function saveDraft() {
    if (!canManage || !valid || saving || publishing) return
    const submitted = JSON.stringify(document)
    setSaving(true)
    try {
      const saved = await saveDlpPolicyDraft(
        document,
        draftPolicy
          ? { id: draftPolicy.id, version: draftPolicy.version }
          : null,
      )
      setDocument((current) => (
        JSON.stringify(current) === submitted
          ? cloneDocument(saved.document)
          : current
      ))
      setSavedSnapshot(JSON.stringify(saved.document))
      setSyncedIdentity(policyIdentity(activePolicy, saved))
      toast.success(`Policy draft v${saved.version} saved.`)
      await onChanged()
    } catch (error) {
      toast.error(getDlpErrorMessage(error, 'Could not save policy draft.'))
    } finally {
      setSaving(false)
    }
  }

  async function publish() {
    if (!canManage || !draftPolicy || dirty || saving || publishing) return
    let latest = draftPolicy
    try {
      const remote = await getDlpPolicyDraft()
      if (
        !remote
        || remote.id !== draftPolicy.id
        || remote.version !== draftPolicy.version
        || JSON.stringify(remote.document) !== savedSnapshot
      ) {
        toast.error('The draft changed on the server. Reloading.')
        await onChanged()
        return
      }
      latest = remote
    } catch (error) {
      toast.error(getDlpErrorMessage(error, 'Could not verify the policy draft.'))
      return
    }
    if (!latest.id) {
      toast.error('The draft is missing an id. Reload and save again.')
      return
    }
    if (!window.confirm(
      `Publish policy draft v${latest.version} with ${latest.document.rules.length} rules?\n\n`
      + `Vs active v${activePolicy.version}: ${summarizePolicyDiff(diffPolicies(activePolicy.document, latest.document))}.\n`
      + 'Published versions are immutable.',
    )) return
    setPublishing(true)
    try {
      const published = await publishDlpPolicy({
        draft_id: latest.id as string,
        expected_version: latest.version,
        document: latest.document,
      })
      setDocument(cloneDocument(published.document))
      setSavedSnapshot(JSON.stringify(published.document))
      setSyncedIdentity(policyIdentity(published, null))
      toast.success(`Policy v${published.version} published.`)
      await onChanged()
    } catch (error) {
      toast.error(getDlpErrorMessage(error, 'Could not publish policy.'))
    } finally {
      setPublishing(false)
    }
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-gradient-to-br from-[#13131a] to-[#1a1a24] p-5">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-[14px] font-semibold text-white">Policy rules</h2>
            <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
              draftPolicy
                ? 'border-amber-500/20 bg-amber-500/10 text-amber-400'
                : 'border-[#3b6ef6]/20 bg-[#3b6ef6]/10 text-[#93b4fd]'
            }`}>
              {draftPolicy ? `DRAFT v${draftPolicy.version}` : `${activePolicy.status.toUpperCase()} v${activePolicy.version}`}
            </span>
            {dirty && (
              <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2 py-0.5 text-[11px] font-semibold text-[#a1a1aa]">
                UNSAVED
              </span>
            )}
          </div>
          <p className="mt-1 text-[12px] text-[#71717a]">
            Active version {activePolicy.version}. Stop outranks Hold, then Allow; lower priority numbers win remaining ties.
            {' '}On/Off and other edits stay in this browser until you Save draft. Switching tabs keeps unsaved work; a full page reload discards it.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="secondary"
            onClick={saveDraft}
            loading={saving}
            disabled={!canManage || !dirty || !valid}
          >
            <Save size={14} /> Save draft
          </Button>
          <Button
            onClick={publish}
            loading={publishing}
            disabled={!canManage || !draftPolicy || dirty}
          >
            <Send size={14} /> Publish
          </Button>
        </div>
      </div>

      {canManage && (
        <div className="flex items-start gap-2 rounded-xl border border-[#3b6ef6]/20 bg-[#3b6ef6]/[0.06] px-4 py-3 text-[12px] text-[#93b4fd]">
          <Info size={13} className="mt-0.5 shrink-0" />
          <span>
            On/Off and every other edit are draft-only until you Save. A full page reload discards unsaved changes; switching DLP tabs does not.
            The gateway enforces the active version, not this editor.
          </span>
        </div>
      )}

      {!canManage && (
        <div className="flex gap-2 rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
          <Lock size={14} className="mt-0.5 text-[#71717a]" />
          <p className="text-xs text-[#71717a]">
            Administrator permission is required to edit or publish policy.
          </p>
        </div>
      )}

      {duplicateIds.length > 0 && (
        <p className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3 py-2 text-xs text-red-300">
          Rule IDs must be unique: {duplicateIds.join(', ')}
        </p>
      )}

      <DlpPolicyDiff
        publishedVersion={activePolicy.version}
        changes={publishedDiff}
        hasDraft={Boolean(draftPolicy)}
        includesUnsaved={dirty}
      />

      <section className="rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <label>
            <span className="mb-1.5 block text-xs font-medium text-[#a1a1aa]">Default action</span>
            <select
              value={document.default_action}
              disabled={editingLocked}
              onChange={(event) => setDocument((current) => ({
                ...current,
                default_action: event.target.value as PolicyAction,
              }))}
              className="min-w-40 rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-sm text-white outline-none disabled:opacity-60"
            >
              <option value="allow">Allow</option>
              <option value="hold">Hold</option>
              <option value="stop">Stop</option>
            </select>
          </label>
          <Button
            variant="outline"
            size="sm"
            disabled={editingLocked || document.rules.length >= 500}
            onClick={() => addRule()}
          >
            <Plus size={13} /> Blank rule
          </Button>
        </div>
        <div className="mt-4">
          <p className="mb-2 text-[11px] font-medium text-[#71717a]">Add from template</p>
          <div className="grid gap-2 md:grid-cols-3">
            {POLICY_RULE_TEMPLATES.map((template) => (
              <button
                key={template.id}
                type="button"
                disabled={editingLocked || document.rules.length >= 500}
                onClick={() => addTemplate(template)}
                className="rounded-lg border border-white/[0.08] bg-white/[0.02] p-3 text-left transition-colors hover:border-white/[0.14] hover:bg-white/[0.04] disabled:cursor-not-allowed disabled:opacity-50"
              >
                <p className="text-[12px] font-medium text-white">{template.label}</p>
                <p className="mt-1 text-[11px] leading-relaxed text-[#71717a]">
                  {template.description}
                </p>
              </button>
            ))}
          </div>
        </div>
      </section>

      <div className="space-y-3">
        {document.rules.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/[0.1] px-4 py-14 text-center">
            <p className="text-[13px] text-[#71717a]">This policy has no rules yet.</p>
            <p className="mt-1 text-[11px] text-[#52525b]">
              Start from a template or add a blank rule. Templates insert into this document; they do not create a second policy.
            </p>
            {canManage && (
              <Button
                variant="ghost"
                size="sm"
                className="mt-3"
                disabled={editingLocked}
                onClick={() => addRule()}
              >
                <Plus size={13} /> Add a blank rule
              </Button>
            )}
          </div>
        ) : document.rules.map((rule, index) => (
          <RuleEditor
            key={`${index}-${rule.rule_id}`}
            rule={rule}
            disabled={editingLocked}
            expanded={expandedRule === rule.rule_id}
            onToggleExpanded={() => setExpandedRule(
              expandedRule === rule.rule_id ? null : rule.rule_id,
            )}
            onChange={(updated) => replaceRule(index, updated)}
            onDuplicate={() => duplicateRule(index)}
            duplicateDisabled={document.rules.length >= 500}
            onDelete={() => {
              if (!window.confirm(`Delete rule "${rule.name}" from this draft?`)) return
              setDocument((current) => ({
                ...current,
                rules: current.rules.filter((_, itemIndex) => itemIndex !== index),
              }))
            }}
          />
        ))}
      </div>
    </div>
  )
}
