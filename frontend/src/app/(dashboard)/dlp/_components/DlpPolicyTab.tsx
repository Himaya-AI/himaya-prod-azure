'use client'

import { useEffect, useMemo, useState } from 'react'
import {
  ChevronDown,
  ChevronUp,
  Copy,
  Lock,
  Plus,
  Save,
  Send,
  Trash2,
} from 'lucide-react'

import { Badge } from '@/components/ui/Badge'
import Button from '@/components/ui/Button'
import { toast } from '@/components/ui/Toast'
import {
  getDlpErrorMessage,
  publishDlpPolicy,
  saveDlpPolicyDraft,
} from '@/lib/dlp/api'
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

function createRule(): PolicyRule {
  const suffix =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID().slice(0, 8)
      : Date.now().toString(36)
  return {
    rule_id: `custom.rule.${suffix}`,
    name: 'New DLP rule',
    action: 'hold',
    priority: 100,
    enabled: true,
    conditions: {
      entity_types: [],
      detectors: [],
      min_confidence: 0.8,
      min_match_count: 1,
      llm_classifications: [],
      llm_categories: [],
      external_recipients_only: true,
      recipient_domains: [],
    },
  }
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
  return (
    <label className="block">
      <span className="mb-1.5 block text-[11px] font-medium text-[#71717a]">
        {label}
      </span>
      <input
        value={value.join(', ')}
        onChange={(event) => onChange(splitValues(event.target.value))}
        placeholder={placeholder}
        disabled={disabled}
        className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-xs text-white outline-none focus:border-[#3b6ef6]/60 disabled:opacity-60"
      />
    </label>
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
}: {
  rule: PolicyRule
  disabled: boolean
  expanded: boolean
  onToggleExpanded: () => void
  onChange: (rule: PolicyRule) => void
  onDuplicate: () => void
  onDelete: () => void
}) {
  function patch(values: Partial<PolicyRule>) {
    onChange({ ...rule, ...values })
  }

  function patchConditions(values: Partial<RuleConditions>) {
    patch({ conditions: { ...rule.conditions, ...values } })
  }

  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.07] bg-white/[0.02]">
      <div className="flex items-center gap-3 px-4 py-3">
        <button
          type="button"
          role="switch"
          aria-checked={rule.enabled}
          disabled={disabled}
          onClick={() => patch({ enabled: !rule.enabled })}
          className={`relative h-5 w-9 shrink-0 rounded-full transition-colors disabled:opacity-50 ${
            rule.enabled ? 'bg-[#3b6ef6]' : 'bg-white/10'
          }`}
        >
          <span
            className={`absolute top-1 h-3 w-3 rounded-full bg-white transition-transform ${
              rule.enabled ? 'translate-x-5' : 'translate-x-1'
            }`}
          />
        </button>
        <button
          type="button"
          onClick={onToggleExpanded}
          className="min-w-0 flex-1 text-left"
        >
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium text-white">{rule.name}</span>
            <Badge variant={rule.action === 'stop' ? 'danger' : rule.action === 'hold' ? 'warning' : 'success'}>
              {rule.action.toUpperCase()}
            </Badge>
          </div>
          <p className="mt-0.5 text-[11px] text-[#71717a]">
            Priority {rule.priority} · {rule.rule_id}
          </p>
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
                disabled={disabled}
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
                disabled={disabled}
                onChange={(event) => patchConditions({ min_match_count: Number(event.target.value) })}
                className="w-full rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-xs text-white outline-none disabled:opacity-60"
              />
            </label>
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <PolicyField
              label="Detectors (comma separated)"
              value={rule.conditions.detectors}
              onChange={(detectors) => patchConditions({ detectors })}
              placeholder="credential, pii, lexicon"
              disabled={disabled}
            />
            <PolicyField
              label="Entity types"
              value={rule.conditions.entity_types}
              onChange={(entity_types) => patchConditions({ entity_types })}
              placeholder="CREDIT_CARD, US_SSN"
              disabled={disabled}
            />
            <PolicyField
              label="LLM classifications"
              value={rule.conditions.llm_classifications}
              onChange={(llm_classifications) => patchConditions({ llm_classifications })}
              placeholder="SENSITIVE, UNCERTAIN"
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
            <Button variant="ghost" size="sm" disabled={disabled} onClick={onDuplicate}>
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
  return [
    activePolicy.id ?? 'active',
    activePolicy.version,
    activePolicy.status,
    activePolicy.published_at ?? '',
    draftPolicy?.id ?? 'no-draft',
    draftPolicy?.version ?? '',
    draftPolicy?.status ?? '',
  ].join(':')
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

  useEffect(() => {
    const nextIdentity = policyIdentity(activePolicy, draftPolicy)
    // Keep local edits when the parent refreshes the same draft/active policy.
    if (dirty && nextIdentity === syncedIdentity) return

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
      rule.priority >= 0 &&
      rule.priority <= 10000 &&
      rule.conditions.min_confidence >= 0 &&
      rule.conditions.min_confidence <= 1 &&
      rule.conditions.min_match_count >= 1,
    )

  function replaceRule(index: number, rule: PolicyRule) {
    setDocument((current) => ({
      ...current,
      rules: current.rules.map((item, itemIndex) => itemIndex === index ? rule : item),
    }))
  }

  function addRule() {
    const rule = createRule()
    setDocument((current) => ({ ...current, rules: [...current.rules, rule] }))
    setExpandedRule(rule.rule_id)
  }

  function duplicateRule(index: number) {
    const rule = cloneDocument({
      default_action: document.default_action,
      rules: [document.rules[index]],
    }).rules[0]
    const suffix = Date.now().toString(36)
    rule.rule_id = `${rule.rule_id}.copy.${suffix}`.slice(0, 128)
    rule.name = `${rule.name} (copy)`.slice(0, 255)
    setDocument((current) => ({ ...current, rules: [...current.rules, rule] }))
    setExpandedRule(rule.rule_id)
  }

  async function saveDraft() {
    if (!canManage || !valid) return
    setSaving(true)
    try {
      const saved = await saveDlpPolicyDraft(document)
      setDocument(cloneDocument(saved.document))
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
    if (!canManage || !draftPolicy || dirty) return
    if (!window.confirm(
      `Publish policy draft v${draftPolicy.version} with ${document.rules.length} rules? Published versions are immutable.`,
    )) return
    setPublishing(true)
    try {
      const published = await publishDlpPolicy()
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
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-medium text-white">Policy document</h2>
            <Badge variant={draftPolicy ? 'warning' : 'info'}>
              {draftPolicy ? `DRAFT v${draftPolicy.version}` : `${activePolicy.status.toUpperCase()} v${activePolicy.version}`}
            </Badge>
            {dirty && <Badge variant="neutral">UNSAVED</Badge>}
          </div>
          <p className="mt-1 text-xs text-[#71717a]">
            Active version {activePolicy.version}. Lower priority numbers win ties.
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

      <section className="rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <label>
            <span className="mb-1.5 block text-xs font-medium text-[#a1a1aa]">Default action</span>
            <select
              value={document.default_action}
              disabled={!canManage}
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
          <Button variant="outline" size="sm" disabled={!canManage || document.rules.length >= 500} onClick={addRule}>
            <Plus size={13} /> Add rule
          </Button>
        </div>
      </section>

      <div className="space-y-3">
        {document.rules.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/[0.1] py-12 text-center">
            <p className="text-sm text-[#71717a]">This policy has no rules.</p>
            {canManage && (
              <Button variant="ghost" size="sm" className="mt-3" onClick={addRule}>
                <Plus size={13} /> Add the first rule
              </Button>
            )}
          </div>
        ) : document.rules.map((rule, index) => (
          <RuleEditor
            key={`${index}-${rule.rule_id}`}
            rule={rule}
            disabled={!canManage}
            expanded={expandedRule === rule.rule_id}
            onToggleExpanded={() => setExpandedRule(
              expandedRule === rule.rule_id ? null : rule.rule_id,
            )}
            onChange={(updated) => replaceRule(index, updated)}
            onDuplicate={() => duplicateRule(index)}
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
