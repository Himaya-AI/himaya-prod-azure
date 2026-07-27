'use client'

import { Fragment, useCallback, useEffect, useState } from 'react'
import { AxiosError } from 'axios'
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Lock,
  Mail,
  RefreshCw,
  ShieldX,
  Undo2,
  X,
} from 'lucide-react'

import { Badge } from '@/components/ui/Badge'
import Button from '@/components/ui/Button'
import { Table, Tbody, Td, Th, Thead, Tr } from '@/components/ui/Table'
import { toast } from '@/components/ui/Toast'
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
}

interface PendingReview {
  message: DlpMessageSummary
  action: DlpReviewAction
  idempotencyKey: string
}

const FILTERS = [
  { value: '', label: 'All messages' },
  { value: 'reviewable', label: 'Held / reviewable' },
  { value: 'received', label: 'Received' },
  { value: 'decided', label: 'Decided' },
  { value: 'held', label: 'Held' },
  { value: 'release_requested', label: 'Release requested' },
  { value: 'stop_requested', label: 'Stop requested' },
]

function actionVariant(action: string | null) {
  if (action === 'stop') return 'danger' as const
  if (action === 'hold') return 'warning' as const
  if (action === 'allow') return 'success' as const
  return 'neutral' as const
}

function makeIdempotencyKey() {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID()
  }
  return `dlp-review-${Date.now()}-${Math.random().toString(36).slice(2)}`
}

function ReviewDialog({
  review,
  onClose,
  onComplete,
}: {
  review: PendingReview
  onClose: () => void
  onComplete: () => Promise<void>
}) {
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(false)

  async function submit() {
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
                  ? 'This queues a gateway command to permanently stop delivery.'
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

      {detail.matched_rule_ids.length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">Matched rules</p>
          <div className="flex flex-wrap gap-1.5">
            {detail.matched_rule_ids.map((ruleId) => (
              <Badge key={ruleId} variant="neutral">{ruleId}</Badge>
            ))}
          </div>
        </div>
      )}

      {detail.findings.length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">Findings</p>
          <div className="space-y-1.5">
            {detail.findings.map((finding, index) => (
              <div
                key={`${finding.detector}-${finding.entity_type}-${index}`}
                className="flex flex-wrap items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2"
              >
                <Badge variant="info">{finding.detector}</Badge>
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

      {detail.extraction_limitations.length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">Limitations</p>
          <ul className="space-y-1 text-xs text-amber-200/80">
            {detail.extraction_limitations.map((item, index) => (
              <li key={`${item.code}-${index}`}>
                <span className="font-medium">{item.code}</span>
                {item.detail ? `: ${item.detail}` : ''}
              </li>
            ))}
          </ul>
        </div>
      )}

      {detail.review_history.length > 0 && (
        <div>
          <p className="mb-2 text-[10px] uppercase tracking-wide text-[#52525b]">Review history</p>
          <div className="space-y-2">
            {detail.review_history.map((item, index) => (
              <div
                key={`${item.action}-${item.created_at}-${index}`}
                className="rounded-lg border border-white/[0.06] px-3 py-2"
              >
                <div className="flex items-center gap-2">
                  <Badge variant={item.action === 'stop' ? 'danger' : 'info'}>
                    {item.action.toUpperCase()}
                  </Badge>
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

export default function DlpMessagesTab({ canManage }: Props) {
  const [messages, setMessages] = useState<DlpMessageSummary[]>([])
  const [filter, setFilter] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [details, setDetails] = useState<Record<string, DlpMessageDetail>>({})
  const [detailLoading, setDetailLoading] = useState<string | null>(null)
  const [review, setReview] = useState<PendingReview | null>(null)

  const load = useCallback(async (append = false, cursor: string | null = null) => {
    if (append) setLoadingMore(true)
    else setLoading(true)
    setError(null)
    try {
      const response = await listDlpMessages({
        reviewable: filter === 'reviewable' ? true : undefined,
        state: filter && filter !== 'reviewable' ? filter : undefined,
        before: append ? cursor ?? undefined : undefined,
        limit: 50,
      })
      setMessages((current) => {
        const combined = append ? [...current, ...response.items] : response.items
        return [...new Map(combined.map((item) => [item.message_id, item])).values()]
      })
      setNextCursor(response.next_cursor)
    } catch (requestError) {
      setError(getDlpErrorMessage(requestError, 'Could not load DLP messages.'))
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [filter])

  useEffect(() => {
    setMessages([])
    setNextCursor(null)
    setExpanded(null)
    setDetails({})
    void load(false, null)
  }, [filter, load])

  async function toggleDetail(messageId: string) {
    if (expanded === messageId) {
      setExpanded(null)
      return
    }
    setExpanded(messageId)
    if (details[messageId]) return
    setDetailLoading(messageId)
    try {
      const detail = await getDlpMessage(messageId)
      setDetails((current) => ({ ...current, [messageId]: detail }))
    } catch (requestError) {
      toast.error(getDlpErrorMessage(requestError, 'Could not load message detail.'))
      setExpanded(null)
    } finally {
      setDetailLoading(null)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium text-white">DLP messages</h2>
          <p className="mt-1 text-xs text-[#71717a]">
            Review held decisions with findings and a bounded sanitized preview.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            className="rounded-lg border border-white/[0.08] bg-[#13131a] px-3 py-2 text-xs text-white outline-none"
          >
            {FILTERS.map((item) => (
              <option key={item.value} value={item.value}>{item.label}</option>
            ))}
          </select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setNextCursor(null)
              void load(false, null)
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
            <Button variant="outline" size="sm" onClick={() => void load(false, null)}>
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
            <Mail size={23} className="text-[#52525b]" />
            <p className="mt-3 text-sm text-[#71717a]">No messages match this filter.</p>
          </div>
        ) : (
          <Table>
            <Thead>
              <Tr>
                <Th>Received</Th>
                <Th>Sender / recipients</Th>
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
                    <Td className="max-w-[320px] align-top">
                      <p className="truncate text-xs text-white">{message.envelope_from}</p>
                      <p className="mt-1 truncate text-[11px] text-[#71717a]">
                        To: {message.envelope_to.join(', ')}
                      </p>
                    </Td>
                    <Td className="align-top">
                      <Badge variant="neutral">{message.state.replaceAll('_', ' ')}</Badge>
                    </Td>
                    <Td className="align-top">
                      <div className="flex items-center gap-2">
                        <Badge variant={actionVariant(message.effective_action)}>
                          {(message.effective_action ?? 'pending').toUpperCase()}
                        </Badge>
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
                          variant="ghost"
                          size="sm"
                          disabled={!canManage || !message.reviewable}
                          onClick={() => setReview({
                            message,
                            action: 'release',
                            idempotencyKey: makeIdempotencyKey(),
                          })}
                        >
                          <Undo2 size={12} /> Release
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          disabled={!canManage || !message.reviewable}
                          className="text-red-400"
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
            onClick={() => void load(true, nextCursor)}
            loading={loadingMore}
          >
            Load more
          </Button>
        </div>
      )}

      {review && (
        <ReviewDialog
          review={review}
          onClose={() => setReview(null)}
          onComplete={async () => {
            setDetails({})
            await load(false, null)
          }}
        />
      )}
    </div>
  )
}
