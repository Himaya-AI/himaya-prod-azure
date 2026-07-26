'use client'

import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
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
  listDlpMessages,
  releaseDlpMessage,
  stopDlpMessage,
} from '@/lib/dlp/api'
import type {
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
  { value: 'release_requested', label: 'Release requested' },
  { value: 'stop_requested', label: 'Stop requested' },
]

function actionVariant(action: string | null) {
  if (action === 'stop') return 'danger' as const
  if (action === 'hold') return 'warning' as const
  if (action === 'allow') return 'success' as const
  return 'neutral' as const
}

function isReviewable(message: DlpMessageSummary) {
  return (
    message.effective_action === 'hold' &&
    ['decided', 'held'].includes(message.state)
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
      toast.error(getDlpErrorMessage(error, 'Could not queue the review action.'))
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

export default function DlpMessagesTab({ canManage }: Props) {
  const [messages, setMessages] = useState<DlpMessageSummary[]>([])
  const [filter, setFilter] = useState('')
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [review, setReview] = useState<PendingReview | null>(null)

  const load = useCallback(async (append = false) => {
    if (append) setLoadingMore(true)
    else setLoading(true)
    setError(null)
    try {
      const response = await listDlpMessages({
        state: filter && filter !== 'reviewable' ? filter : undefined,
        before: append ? nextCursor ?? undefined : undefined,
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
  }, [filter, nextCursor])

  useEffect(() => {
    setMessages([])
    setNextCursor(null)
    void load(false)
    // nextCursor is intentionally excluded: a cursor update must not reload page one.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter])

  const visibleMessages = useMemo(
    () => filter === 'reviewable' ? messages.filter(isReviewable) : messages,
    [filter, messages],
  )

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium text-white">DLP messages</h2>
          <p className="mt-1 text-xs text-[#71717a]">
            Envelope and decision data. Content preview is not yet available in v2.
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
          <Button variant="outline" size="sm" onClick={() => void load(false)} loading={loading}>
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
            <Button variant="outline" size="sm" onClick={() => void load(false)}>Retry</Button>
          </div>
        ) : loading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, index) => (
              <div key={index} className="h-12 animate-pulse rounded-lg bg-white/[0.03]" />
            ))}
          </div>
        ) : visibleMessages.length === 0 ? (
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
              {visibleMessages.map((message) => (
                <Fragment key={message.message_id}>
                  <Tr key={message.message_id}>
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
                          aria-label="Toggle decision explanation"
                          onClick={() => setExpanded(
                            expanded === message.message_id ? null : message.message_id,
                          )}
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
                          disabled={!canManage || !isReviewable(message)}
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
                          disabled={!canManage || !isReviewable(message)}
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
                    <Tr key={`${message.message_id}-detail`} className="hover:bg-transparent">
                      <Td colSpan={5} className="bg-white/[0.015]">
                        <div className="grid gap-3 py-1 md:grid-cols-3">
                          <div>
                            <p className="text-[10px] uppercase tracking-wide text-[#52525b]">Intended action</p>
                            <p className="mt-1 text-xs text-[#a1a1aa]">{message.intended_action ?? 'Pending'}</p>
                          </div>
                          <div className="md:col-span-2">
                            <p className="text-[10px] uppercase tracking-wide text-[#52525b]">Explanation</p>
                            <p className="mt-1 text-xs leading-relaxed text-[#a1a1aa]">
                              {message.explanation ?? 'No decision explanation is available.'}
                            </p>
                          </div>
                        </div>
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
          <Button variant="outline" onClick={() => void load(true)} loading={loadingMore}>
            Load more
          </Button>
        </div>
      )}

      {review && (
        <ReviewDialog
          review={review}
          onClose={() => setReview(null)}
          onComplete={async () => { await load(false) }}
        />
      )}
    </div>
  )
}
