'use client'

import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import { AxiosError } from 'axios'
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Inbox,
  Info,
  Lock,
  Mail,
  RefreshCw,
  ShieldX,
  Undo2,
  X,
} from 'lucide-react'

import Button from '@/components/ui/Button'
import { Table, Tbody, Td, Th, Thead, Tr } from '@/components/ui/Table'
import { toast } from '@/components/ui/Toast'
import { ActionChip, OutcomeChip, StateChip, formatRecipientList, snippetText } from './DlpChrome'
import {
  getDlpErrorMessage,
  getDlpMessage,
  listDlpMessages,
  releaseDlpMessage,
  stopDlpMessage,
} from '@/lib/dlp/api'
import type {
  DlpMessageDetail,
  DlpMessageSummary,
  DlpReviewAction,
} from '@/lib/dlp/types'

interface Props {
  canManage: boolean
  defaultFilter?: string
  variant?: 'queue' | 'messages'
  refreshEpoch?: number
  onReviewed?: () => void
}

interface PendingReview {
  message: DlpMessageSummary
  action: DlpReviewAction
  idempotencyKey: string
}

const MESSAGE_FILTER_GROUPS: Array<{
  label: string
  options: Array<{ value: string; label: string }>
}> = [
  {
    label: 'All',
    options: [{ value: '', label: 'All traffic' }],
  },
  {
    label: 'Review',
    options: [
      { value: 'reviewable', label: 'Held / reviewable' },
      { value: 'release_requested', label: 'Release requested' },
      { value: 'stop_requested', label: 'Stop requested' },
      { value: 'stopped', label: 'Stopped' },
      { value: 'decided', label: 'Decided (pipeline; held review is Queue)' },
    ],
  },
  {
    label: 'Delivered',
    options: [
      { value: 'provider_accepted', label: 'Provider accepted' },
    ],
  },
  {
    label: 'In flight',
    options: [
      { value: 'retry_scheduled', label: 'Retry scheduled' },
      { value: 'allow_pending', label: 'Allow pending' },
      { value: 'submitting', label: 'Submitting' },
    ],
  },
  {
    label: 'Needs attention',
    options: [
      { value: 'failed', label: 'Failed' },
      { value: 'delivery_retry_exhausted', label: 'Retry exhausted' },
      { value: 'outcome_uncertain', label: 'Outcome uncertain' },
      { value: 'partially_accepted', label: 'Partially accepted' },
    ],
  },
  {
    label: 'Pipeline (usually empty)',
    options: [
      { value: 'received', label: 'Received' },
      { value: 'classified', label: 'Classified' },
    ],
  },
]

const POLL_SETTLED_STATES = new Set([
  'provider_accepted',
  'failed',
  'delivery_retry_exhausted',
  'outcome_uncertain',
  'partially_accepted',
  'stopped',
])

function emptyCopy(isQueue: boolean, filter: string) {
  if (isQueue) {
    return {
      title: 'No held messages are waiting for review.',
      detail: 'Queue is held mail only. Policy-stopped mail is under Messages as Stop requested, then Stopped after the gateway ack. Decided is a pipeline state, not this list.',
    }
  }
  if (filter === 'received' || filter === 'classified') {
    return {
      title: 'No messages at this pipeline step.',
      detail: 'Received and Classified are usually empty unless a message is stuck before a decision.',
    }
  }
  if (filter === 'stopped') {
    return {
      title: 'No stopped messages.',
      detail: 'Stopped is the terminal result after the gateway applies a stop command. In-flight stops stay in Stop requested until that ack arrives.',
    }
  }
  if (filter === 'stop_requested') {
    return {
      title: 'No stop commands are in flight.',
      detail: 'Stop requested means the control plane queued a stop and is waiting for the gateway ack. Completed stops are under Stopped.',
    }
  }
  if (filter === 'decided') {
    return {
      title: 'No messages in Decided.',
      detail: 'Decided includes allow, hold, and stop decisions that have not moved on yet. Held mail awaiting review is in Queue.',
    }
  }
  if (filter === 'reviewable') {
    return {
      title: 'No held messages match this filter.',
      detail: 'Held review also lives in the Queue tab.',
    }
  }
  if (filter === 'release_requested') {
    return {
      title: 'No release commands are in flight.',
      detail: 'Release requested means the control plane queued a release and is waiting for the gateway to apply it. Failed releases that are still held return to Queue.',
    }
  }
  return {
    title: 'No messages match this filter.',
    detail: 'Traffic appears here after the gateway captures a message.',
  }
}

function toSummary(detail: DlpMessageDetail): DlpMessageSummary {
  return {
    message_id: detail.message_id,
    envelope_from: detail.envelope_from,
    envelope_to: detail.envelope_to,
    state: detail.state,
    received_at: detail.received_at,
    intended_action: detail.intended_action,
    effective_action: detail.effective_action,
    explanation: detail.explanation,
    reviewable: detail.reviewable,
  }
}

function matchesListQuery(
  message: Pick<DlpMessageSummary, 'state' | 'reviewable'>,
  variant: 'queue' | 'messages',
  filter: string,
) {
  if (variant === 'queue' || filter === 'reviewable') return message.reviewable
  if (filter) return message.state === filter
  return true
}

function applyPolledMessage(
  current: DlpMessageSummary[],
  detail: DlpMessageDetail,
  variant: 'queue' | 'messages',
  filter: string,
) {
  if (!matchesListQuery(detail, variant, filter)) {
    return current.filter((item) => item.message_id !== detail.message_id)
  }
  const summary = toSummary(detail)
  return current.map((item) => (
    item.message_id === detail.message_id ? summary : item
  ))
}

function uniqueMessages(items: DlpMessageSummary[]) {
  return [...new Map(items.map((item) => [item.message_id, item])).values()]
}

function MessagePreviewCell({
  message,
  subject,
}: {
  message: DlpMessageSummary
  subject: string | null
}) {
  const snippet = snippetText(message.explanation)
  const recipients = formatRecipientList(message.envelope_to)
  return (
    <Td className="max-w-[360px] align-top">
      <p className="truncate text-xs text-white">
        {subject || message.envelope_from}
      </p>
      <p className="mt-0.5 truncate text-[11px] text-[#a1a1aa]">
        {subject
          ? `${message.envelope_from} → ${recipients}`
          : `To: ${recipients}`}
      </p>
      {snippet && (
        <p className="mt-1 line-clamp-2 text-[11px] text-[#71717a]">
          {snippet}
        </p>
      )}
    </Td>
  )
}

function makeIdempotencyKey() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return `dlp-review-${Date.now()}-${Math.random().toString(36).slice(2)}`
}

function ReviewDialog({
  review,
  isQueue,
  onClose,
  onComplete,
}: {
  review: PendingReview
  isQueue: boolean
  onClose: () => void
  onComplete: () => Promise<void>
}) {
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit() {
    if (submitting) return
    const trimmed = reason.trim()
    if (trimmed.length < 3) return
    setSubmitting(true)
    try {
      const payload = {
        reason: trimmed,
        idempotency_key: review.idempotencyKey,
      }
      const response = review.action === 'release'
        ? await releaseDlpMessage(review.message.message_id, payload)
        : await stopDlpMessage(review.message.message_id, payload)
      toast.success(
        response.status === 'already_queued'
          ? `${review.action === 'release' ? 'Release' : 'Stop'} was already queued.`
          : `${review.action === 'release' ? 'Release' : 'Stop'} command queued.`,
      )
      await onComplete()
      onClose()
    } catch (error) {
      const status = error instanceof AxiosError ? error.response?.status : undefined
      toast.error(getDlpErrorMessage(error, 'Could not queue the review action.'))
      if (status === 409) {
        await onComplete()
        onClose()
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="review-dialog-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget && !submitting) onClose()
      }}
    >
      <div className="w-full max-w-lg rounded-xl border border-white/[0.1] bg-[#15151d] shadow-2xl">
        <div className="flex items-center justify-between border-b border-white/[0.07] px-5 py-4">
          <div>
            <h2 id="review-dialog-title" className="text-sm font-semibold text-white">
              {review.action === 'release' ? 'Release held message' : 'Stop held message'}
            </h2>
            <p className="mt-1 max-w-sm truncate text-xs text-[#71717a]">
              {review.message.envelope_from}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            aria-label="Close"
            className="p-1.5 text-[#71717a] hover:text-white disabled:opacity-50"
          >
            <X size={16} />
          </button>
        </div>
        <div className="space-y-4 p-5">
          <div className={`rounded-lg border p-3 ${
            review.action === 'stop'
              ? 'border-red-500/20 bg-red-500/[0.06]'
              : 'border-[#3b6ef6]/20 bg-[#3b6ef6]/[0.06]'
          }`}>
            <div className="flex gap-2">
              {review.action === 'stop'
                ? <AlertTriangle size={15} className="mt-0.5 text-red-400" />
                : <Undo2 size={15} className="mt-0.5 text-[#93b4fd]" />}
              <p className="text-xs leading-relaxed text-[#a1a1aa]">
                {review.action === 'stop'
                  ? (isQueue
                    ? 'This queues a gateway command to permanently stop delivery. The message leaves Queue immediately and appears in Messages as Stop requested until the gateway ack moves it to Stopped.'
                    : 'This queues a gateway command to permanently stop delivery. The row stays Stop requested until the gateway ack moves it to Stopped.')
                  : 'This queues a gateway command to release the held message.'}
                {' '}Queued does not mean gateway processing has completed.
              </p>
            </div>
          </div>
          <label className="block">
            <span className="mb-1.5 block text-xs font-medium text-[#a1a1aa]">
              Review reason
            </span>
            <textarea
              autoFocus
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              minLength={3}
              maxLength={2000}
              rows={4}
              placeholder="Explain why this message should be released or stopped."
              className="w-full resize-y rounded-lg border border-white/[0.08] bg-[#0d0d12] px-3 py-2 text-sm text-white outline-none focus:border-[#3b6ef6]/60"
            />
            <span className="mt-1 block text-right text-[10px] text-[#52525b]">
              {reason.length}/2000
            </span>
          </label>
        </div>
        <div className="flex justify-end gap-2 border-t border-white/[0.07] px-5 py-4">
          <Button variant="ghost" onClick={onClose} disabled={submitting}>Cancel</Button>
          <Button
            variant={review.action === 'stop' ? 'danger' : 'primary'}
            onClick={submit}
            loading={submitting}
            disabled={reason.trim().length < 3}
          >
            {review.action === 'release' ? <Undo2 size={14} /> : <ShieldX size={14} />}
            Queue {review.action}
          </Button>
        </div>
      </div>
    </div>
  )
}

function MessageDetailPanel({ detail }: { detail: DlpMessageDetail }) {
  return (
    <div className="space-y-4 py-1">
      <div className="grid gap-3 md:grid-cols-3">
        <div>
          <p className="text-[10px] uppercase tracking-wide text-[#52525b]">Subject</p>
          <p className="mt-1 text-xs text-[#a1a1aa]">
            {detail.subject || (detail.preview_available ? '—' : 'Unavailable')}
          </p>
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-wide text-[#52525b]">Policy version</p>
          <p className="mt-1 text-xs text-[#a1a1aa]">{detail.policy_version ?? '—'}</p>
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-wide text-[#52525b]">Intended action</p>
          <p className="mt-1 text-xs text-[#a1a1aa]">{detail.intended_action ?? 'Pending'}</p>
        </div>
      </div>

      <div>
        <p className="text-[10px] uppercase tracking-wide text-[#52525b]">Explanation</p>
        <p className="mt-1 text-xs leading-relaxed text-[#a1a1aa]">
          {detail.explanation ?? 'No decision explanation is available.'}
        </p>
      </div>

      {(detail.matched_rule_ids ?? []).length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">Matched rules</p>
          <div className="flex flex-wrap gap-1.5">
            {(detail.matched_rule_ids ?? []).map((ruleId) => (
              <span
                key={ruleId}
                className="rounded border border-white/[0.07] bg-[#1e1e2c] px-2 py-0.5 text-[11px] text-[#a1a1aa]"
              >
                {ruleId}
              </span>
            ))}
          </div>
        </div>
      )}

      {(detail.findings ?? []).length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">Findings</p>
          <div className="space-y-1.5">
            {(detail.findings ?? []).map((finding, index) => (
              <div
                key={`${finding.detector}-${finding.entity_type}-${index}`}
                className="flex flex-wrap items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2"
              >
                <span className="rounded-full border border-[#3b6ef6]/20 bg-[#3b6ef6]/10 px-2 py-0.5 text-[11px] font-semibold text-[#93b4fd]">
                  {finding.detector}
                </span>
                <span className="text-xs text-[#a1a1aa]">{finding.entity_type}</span>
                <span className="text-[11px] text-[#71717a]">
                  {(finding.confidence * 100).toFixed(0)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {detail.sanitized_preview && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">
            Sanitized preview
          </p>
          <p className="whitespace-pre-wrap rounded-lg border border-white/[0.06] bg-[#0d0d12] px-3 py-2 text-xs leading-relaxed text-[#a1a1aa]">
            {detail.sanitized_preview}
          </p>
        </div>
      )}

      {!detail.preview_available && (
        <p className="text-[11px] text-[#52525b]">
          Content preview is unavailable for this message.
        </p>
      )}

      {(detail.extraction_limitations ?? []).length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">Limitations</p>
          <ul className="space-y-1 text-xs text-amber-200/80">
            {(detail.extraction_limitations ?? []).map((item, index) => (
              <li key={`${item.code}-${index}`}>
                <span className="font-medium">{item.code}</span>
                {item.detail ? `: ${item.detail}` : ''}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">
          Gateway commands
        </p>
        {(detail.commands ?? []).length === 0 ? (
          <p className="text-[11px] text-[#52525b]">
            No gateway commands have been queued for this message.
          </p>
        ) : (
          <div className="space-y-2">
            {(detail.commands ?? []).map((command) => (
              <div
                key={command.command_id}
                className="rounded-lg border border-white/[0.06] px-3 py-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    title={
                      command.status === 'sent'
                        ? 'Published to the gateway command queue. This is not confirmation that the gateway applied it.'
                        : command.status === 'queued'
                          ? 'Waiting to be published to the gateway command queue.'
                          : command.status === 'failed'
                            ? 'Publishing this command failed. If the message is still held, retry from Queue.'
                            : undefined
                    }
                    className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                    command.status === 'failed'
                      ? 'border-red-500/20 bg-red-500/10 text-red-400'
                      : command.status === 'sent'
                        ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                        : 'border-amber-500/20 bg-amber-500/10 text-amber-400'
                  }`}>
                    {command.status.toUpperCase()}
                  </span>
                  <span className="text-xs capitalize text-[#a1a1aa]">
                    {command.command_type.replaceAll('_', ' ')}
                  </span>
                  {command.gateway_status && (
                    <span className="text-[11px] text-[#71717a]">
                      gateway: {command.gateway_status.replaceAll('_', ' ')}
                    </span>
                  )}
                  <span className="ml-auto text-[11px] text-[#71717a]">
                    {new Date(command.created_at).toLocaleString()}
                  </span>
                </div>
                {command.last_error && (
                  <p className="mt-1 text-[11px] leading-relaxed text-red-300/80">
                    {command.last_error}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">
          Delivery attempts
        </p>
        {(detail.deliveries ?? []).length === 0 ? (
          <p className="text-[11px] text-[#52525b]">
            No delivery attempts recorded yet.
          </p>
        ) : (
          <div className="space-y-2">
            {(detail.deliveries ?? []).map((attempt, index) => (
              <div
                key={`${attempt.attempt_number}-${attempt.occurred_at}-${index}`}
                className="rounded-lg border border-white/[0.06] px-3 py-2"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <OutcomeChip outcome={attempt.outcome} />
                  <span className="text-xs text-[#a1a1aa]">
                    Attempt {attempt.attempt_number}
                  </span>
                  {attempt.smtp_stage && (
                    <span className="text-[11px] text-[#71717a]">
                      stage: {attempt.smtp_stage.replaceAll('_', ' ')}
                    </span>
                  )}
                  {attempt.smtp_code != null && (
                    <span className="text-[11px] text-[#71717a]">
                      SMTP {attempt.smtp_code}
                    </span>
                  )}
                  <span className="ml-auto text-[11px] text-[#71717a]">
                    {new Date(attempt.occurred_at).toLocaleString()}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-[#71717a]">
                  <span>
                    Resulting state: {attempt.resulting_state.replaceAll('_', ' ')}
                  </span>
                  {attempt.remote_host && <span>via {attempt.remote_host}</span>}
                  <span>
                    {attempt.accepted_recipients.length} accepted ·{' '}
                    {attempt.refused_recipients.length} refused
                  </span>
                </div>
                {attempt.refused_recipients.length > 0 && (
                  <p className="mt-1 break-all text-[11px] text-red-300/80">
                    Refused: {attempt.refused_recipients.join(', ')}
                  </p>
                )}
                {attempt.accepted_recipients.length > 0 && (
                  <p className="mt-1 break-all text-[11px] text-[#71717a]">
                    Accepted: {attempt.accepted_recipients.join(', ')}
                  </p>
                )}
                {(attempt.detail || attempt.smtp_message) && (
                  <p className="mt-1 text-[11px] leading-relaxed text-amber-200/70">
                    {attempt.detail ?? attempt.smtp_message}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {(detail.review_history ?? []).length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">Review history</p>
          <div className="space-y-2">
            {(detail.review_history ?? []).map((item, index) => (
              <div
                key={`${item.action}-${item.created_at}-${index}`}
                className="rounded-lg border border-white/[0.06] px-3 py-2"
              >
                <div className="flex items-center gap-2">
                  <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                    item.action === 'stop'
                      ? 'border-red-500/20 bg-red-500/10 text-red-400'
                      : 'border-[#3b6ef6]/20 bg-[#3b6ef6]/10 text-[#93b4fd]'
                  }`}>
                    {item.action.toUpperCase()}
                  </span>
                  <span className="text-[11px] text-[#71717a]">
                    {new Date(item.created_at).toLocaleString()}
                  </span>
                </div>
                <p className="mt-1 text-xs text-[#a1a1aa]">{item.reason}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function DlpMessagesTab({
  canManage,
  defaultFilter = '',
  variant = 'messages',
  refreshEpoch = 0,
  onReviewed,
}: Props) {
  const [messages, setMessages] = useState<DlpMessageSummary[]>([])
  const [filter, setFilter] = useState(defaultFilter)
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [nextId, setNextId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [details, setDetails] = useState<Record<string, DlpMessageDetail>>({})
  const [detailLoading, setDetailLoading] = useState<string | null>(null)
  const [review, setReview] = useState<PendingReview | null>(null)
  const pollTimers = useRef(new Map<string, Array<ReturnType<typeof setTimeout>>>())
  const expandedRef = useRef<string | null>(null)
  const listGeneration = useRef(0)
  const detailRequest = useRef(0)
  const previousRefreshEpoch = useRef(refreshEpoch)

  function clearPolls(messageId?: string) {
    const timers = pollTimers.current
    if (messageId) {
      timers.get(messageId)?.forEach(clearTimeout)
      timers.delete(messageId)
      return
    }
    for (const list of timers.values()) {
      list.forEach(clearTimeout)
    }
    timers.clear()
  }

  useEffect(() => {
    expandedRef.current = expanded
  }, [expanded])

  useEffect(() => {
    setFilter(defaultFilter)
  }, [defaultFilter])

  const load = useCallback(async ({
    append = false,
    cursor = null,
    cursorId = null,
    background = false,
    quiet = false,
  }: {
    append?: boolean
    cursor?: string | null
    cursorId?: string | null
    background?: boolean
    quiet?: boolean
  } = {}) => {
    const generation = listGeneration.current
    if (append) setLoadingMore(true)
    else if (!background && !quiet) setLoading(true)
    if (!background && !quiet) setError(null)
    const queryFilter = variant === 'queue' ? 'reviewable' : filter
    try {
      const response = await listDlpMessages({
        reviewable: queryFilter === 'reviewable' ? true : undefined,
        state: queryFilter && queryFilter !== 'reviewable' ? queryFilter : undefined,
        before: append ? cursor ?? undefined : undefined,
        before_id: append ? cursorId ?? undefined : undefined,
        limit: 50,
      })
      if (generation !== listGeneration.current) {
        return { ok: false as const, items: [] as DlpMessageSummary[] }
      }
      setMessages((current) => {
        if (append) return uniqueMessages([...current, ...response.items])
        if (background) {
          const incoming = new Map(response.items.map((item) => [item.message_id, item]))
          return current.map((item) => incoming.get(item.message_id) ?? item)
        }
        return uniqueMessages(response.items)
      })
      if (!background) {
        setNextCursor(response.next_cursor)
        setNextId(response.next_id ?? null)
      }
      return { ok: true as const, items: response.items }
    } catch (requestError) {
      if (generation !== listGeneration.current) {
        return { ok: false as const, items: [] as DlpMessageSummary[] }
      }
      const message = getDlpErrorMessage(requestError, 'Could not load DLP messages.')
      if (background) return { ok: false as const, items: [] as DlpMessageSummary[] }
      if (append) {
        toast.error(message)
        return { ok: false as const, items: [] as DlpMessageSummary[] }
      }
      if (quiet) {
        toast.error(message)
        return { ok: false as const, items: [] as DlpMessageSummary[] }
      }
      setError(message)
      return { ok: false as const, items: [] as DlpMessageSummary[] }
    } finally {
      if (generation !== listGeneration.current) return
      if (append) setLoadingMore(false)
      else if (!background && !quiet) setLoading(false)
    }
  }, [filter, variant])

  useEffect(() => {
    listGeneration.current += 1
    clearPolls()
    setMessages([])
    setNextCursor(null)
    setNextId(null)
    setExpanded(null)
    setDetails({})
    void load()
  }, [filter, load])

  useEffect(() => {
    if (previousRefreshEpoch.current === refreshEpoch) return
    previousRefreshEpoch.current = refreshEpoch
    listGeneration.current += 1
    setNextCursor(null)
    setNextId(null)
    void load({ quiet: true })
  }, [load, refreshEpoch])

  useEffect(() => () => {
    listGeneration.current += 1
    clearPolls()
  }, [])

  const refreshDetail = useCallback(async (messageId: string) => {
    try {
      const detail = await getDlpMessage(messageId)
      setDetails((current) => ({ ...current, [messageId]: detail }))
    } catch {
      // Keep the last known detail on transient refresh failures.
    }
  }, [])

  const scheduleFollowUpRefresh = useCallback((messageId: string) => {
    clearPolls(messageId)
    let settled = false
    const timers: Array<ReturnType<typeof setTimeout>> = []
    pollTimers.current.set(messageId, timers)

    const tick = async () => {
      if (settled || pollTimers.current.get(messageId) !== timers) return
      try {
        const detail = await getDlpMessage(messageId)
        if (settled || pollTimers.current.get(messageId) !== timers) return
        setMessages((current) => applyPolledMessage(current, detail, variant, filter))
        setDetails((current) => (
          current[messageId] || expandedRef.current === messageId
            ? { ...current, [messageId]: detail }
            : current
        ))
        if (
          !matchesListQuery(detail, variant, filter)
          || POLL_SETTLED_STATES.has(detail.state)
        ) {
          settled = true
          clearPolls(messageId)
        }
      } catch {
        if (expandedRef.current === messageId) {
          void refreshDetail(messageId)
        }
      }
    }

    for (const delay of [3000, 8000, 15000, 30000, 45000]) {
      timers.push(setTimeout(() => { void tick() }, delay))
    }
  }, [filter, refreshDetail, variant])

  async function toggleDetail(messageId: string) {
    if (expanded === messageId) {
      setExpanded(null)
      return
    }
    const requestId = ++detailRequest.current
    setExpanded(messageId)
    if (details[messageId]) return
    setDetailLoading(messageId)
    try {
      const detail = await getDlpMessage(messageId)
      if (requestId !== detailRequest.current) return
      setDetails((current) => ({ ...current, [messageId]: detail }))
    } catch (requestError) {
      if (requestId !== detailRequest.current) return
      toast.error(getDlpErrorMessage(requestError, 'Could not load message detail.'))
      setExpanded((current) => (current === messageId ? null : current))
    } finally {
      if (requestId === detailRequest.current) setDetailLoading(null)
    }
  }

  const isQueue = variant === 'queue'
  const knownFilters = new Set(
    MESSAGE_FILTER_GROUPS.flatMap((group) => group.options.map((option) => option.value)),
  )
  const empty = emptyCopy(isQueue, isQueue ? 'reviewable' : filter)

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-xl border border-[#3b6ef6]/20 bg-[#3b6ef6]/[0.06] px-4 py-3 text-[12px] text-[#93b4fd]">
        <Info size={13} className="mt-0.5 shrink-0" />
        <span>
          {isQueue
            ? 'Queue is held mail only — effective action hold, still awaiting review. Policy-stopped mail moves to Messages as Stop requested, then Stopped after the gateway ack. Decided is a pipeline state, not this queue.'
            : 'Messages is all captured mail. Use Queue for held review. Stop requested is in flight; Stopped is the gateway ack. Decided is not the held queue.'}
        </span>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-[14px] font-semibold text-white">
            {isQueue ? 'Review queue' : 'Message traffic'}
          </h2>
          <p className="mt-1 text-[12px] text-[#71717a]">
            {isQueue
              ? 'Release or stop queues a gateway command. Queued does not mean delivery has completed.'
              : 'Filter by delivery and review states. Pipeline filters are usually empty unless mail is stuck.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!isQueue && (
            <select
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              className="max-w-[260px] rounded-lg border border-white/[0.08] bg-[#13131a] px-3 py-2 text-xs text-white outline-none"
            >
              {MESSAGE_FILTER_GROUPS.map((group) => (
                <optgroup key={group.label} label={group.label}>
                  {group.options.map((item) => (
                    <option key={item.value || 'all'} value={item.value}>{item.label}</option>
                  ))}
                </optgroup>
              ))}
              {filter && !knownFilters.has(filter) && (
                <optgroup label="Current">
                  <option value={filter}>{filter.replaceAll('_', ' ')}</option>
                </optgroup>
              )}
            </select>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              listGeneration.current += 1
              setNextCursor(null)
              setNextId(null)
              void load()
            }}
            loading={loading}
          >
            <RefreshCw size={13} /> Refresh
          </Button>
        </div>
      </div>

      {!canManage && (
        <div className="flex gap-2 rounded-xl border border-white/[0.07] bg-[#13131a] p-3">
          <Lock size={14} className="mt-0.5 text-[#71717a]" />
          <p className="text-xs text-[#71717a]">
            Administrator permission is required to release or stop held messages.
          </p>
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-white/[0.07] bg-[#13131a]">
        {error ? (
          <div className="flex flex-col items-center gap-3 px-4 py-12 text-center">
            <AlertTriangle size={20} className="text-red-400" />
            <p className="text-sm text-red-300">{error}</p>
            <Button variant="outline" size="sm" onClick={() => void load()}>
              Retry
            </Button>
          </div>
        ) : loading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, index) => (
              <div key={index} className="h-12 animate-pulse rounded-lg bg-white/[0.03]" />
            ))}
          </div>
        ) : messages.length === 0 ? (
          <div className="flex flex-col items-center px-4 py-14 text-center">
            {isQueue
              ? <Inbox size={23} className="text-[#52525b]" />
              : <Mail size={23} className="text-[#52525b]" />}
            <p className="mt-3 text-[13px] text-[#71717a]">{empty.title}</p>
            <p className="mt-1 max-w-md text-[11px] text-[#52525b]">{empty.detail}</p>
          </div>
        ) : (
          <Table>
            <Thead>
              <Tr>
                <Th>Received</Th>
                <Th>Message</Th>
                <Th>State</Th>
                <Th>Decision</Th>
                <Th className="text-right">Review</Th>
              </Tr>
            </Thead>
            <Tbody>
              {messages.map((message) => (
                <Fragment key={message.message_id}>
                  <Tr>
                    <Td className="whitespace-nowrap align-top text-xs">
                      {new Date(message.received_at).toLocaleString()}
                    </Td>
                    <MessagePreviewCell
                      message={message}
                      subject={details[message.message_id]?.subject?.trim() || null}
                    />
                    <Td className="align-top">
                      <StateChip state={message.state} />
                    </Td>
                    <Td className="align-top">
                      <div className="flex items-center gap-2">
                        <ActionChip action={message.effective_action} />
                        <button
                          type="button"
                          aria-label="Toggle message detail"
                          onClick={() => void toggleDetail(message.message_id)}
                          className="p-1 text-[#71717a] hover:text-white"
                        >
                          {expanded === message.message_id
                            ? <ChevronUp size={13} />
                            : <ChevronDown size={13} />}
                        </button>
                      </div>
                    </Td>
                    <Td className="align-top">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={!canManage || !message.reviewable}
                          className="border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/10"
                          onClick={() => setReview({
                            message,
                            action: 'release',
                            idempotencyKey: makeIdempotencyKey(),
                          })}
                        >
                          <Undo2 size={12} /> Release
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={!canManage || !message.reviewable}
                          className="border-red-500/20 text-red-400 hover:bg-red-500/10"
                          onClick={() => setReview({
                            message,
                            action: 'stop',
                            idempotencyKey: makeIdempotencyKey(),
                          })}
                        >
                          <ShieldX size={12} /> Stop
                        </Button>
                      </div>
                    </Td>
                  </Tr>
                  {expanded === message.message_id && (
                    <Tr className="hover:bg-transparent">
                      <Td colSpan={5} className="bg-white/[0.015]">
                        {detailLoading === message.message_id ? (
                          <div className="space-y-2 py-2">
                            <div className="h-4 w-1/3 animate-pulse rounded bg-white/[0.04]" />
                            <div className="h-16 animate-pulse rounded bg-white/[0.04]" />
                          </div>
                        ) : details[message.message_id] ? (
                          <MessageDetailPanel detail={details[message.message_id]} />
                        ) : (
                          <p className="py-2 text-xs text-[#71717a]">
                            Detail is unavailable.
                          </p>
                        )}
                      </Td>
                    </Tr>
                  )}
                </Fragment>
              ))}
            </Tbody>
          </Table>
        )}
      </div>

      {!loading && !error && nextCursor && (
        <div className="flex justify-center">
          <Button
            variant="outline"
            onClick={() => void load({
              append: true,
              cursor: nextCursor,
              cursorId: nextId,
            })}
            loading={loadingMore}
          >
            Load more
          </Button>
        </div>
      )}

      {review && (
        <ReviewDialog
          review={review}
          isQueue={isQueue}
          onClose={() => setReview(null)}
          onComplete={async () => {
            const messageId = review.message.message_id
            try {
              const detail = await getDlpMessage(messageId)
              setMessages((current) => applyPolledMessage(current, detail, variant, filter))
              setDetails((current) => ({ ...current, [messageId]: detail }))
            } catch {
              if (isQueue) {
                setMessages((current) => current.filter((item) => item.message_id !== messageId))
              }
            }
            onReviewed?.()
            scheduleFollowUpRefresh(messageId)
          }}
        />
      )}
    </div>
  )
}
