import {
  Activity,
  AlertTriangle,
  Ban,
  Clock,
  Eye,
  FileWarning,
  Inbox,
  PieChart,
  ShieldCheck,
} from 'lucide-react'

import {
  ActionChip,
  MetricCard,
  RingChart,
  STATE_GROUP_COLORS,
  StateChip,
  countStates,
  formatAge,
  formatRecipientList,
  formatState,
  snippetText,
} from './DlpChrome'
import type {
  DlpMessageSummary,
  DlpNavigateTarget,
  DlpStatus,
  DlpTenantSettings,
  PolicyVersion,
} from '@/lib/dlp/types'

interface Props {
  status: DlpStatus
  settings: DlpTenantSettings
  activePolicy: PolicyVersion
  recentMessages: DlpMessageSummary[]
  onNavigate: (target: DlpNavigateTarget) => void
}

function JumpLink({
  children,
  onClick,
}: {
  children: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={(event) => {
        event.stopPropagation()
        onClick()
      }}
      className="text-[11px] font-medium text-[#93b4fd] hover:text-white"
    >
      {children}
    </button>
  )
}

function JumpHint({ children }: { children: string }) {
  return (
    <span className="text-[11px] font-medium text-[#93b4fd]">{children}</span>
  )
}

export default function DlpOverviewTab({
  status,
  settings,
  activePolicy,
  recentMessages,
  onNavigate,
}: Props) {
  const counts = status.message_counts
  const totalMessages = Object.values(counts).reduce((sum, count) => sum + count, 0)
  const reviewable = status.reviewable_count ?? 0
  const stopRequested = counts.stop_requested ?? 0
  const stopped = counts.stopped ?? 0
  const heldAndStopped = reviewable + stopRequested + stopped
  const interventionRate = totalMessages > 0
    ? Math.round((heldAndStopped / totalMessages) * 100)
    : 0
  const activeRules = activePolicy.document.rules.filter((rule) => rule.enabled).length

  const issueStates = [
    'failed',
    'delivery_retry_exhausted',
    'outcome_uncertain',
    'partially_accepted',
  ]
  const delivered = countStates(counts, ['provider_accepted'])
  const retry = countStates(counts, ['retry_scheduled'])
  const issues = countStates(counts, issueStates)
  const inflightRaw = countStates(counts, [
    'received',
    'classified',
    'decided',
    'held',
    'release_requested',
    'allow_pending',
    'submitting',
  ])
  const inflight = Math.max(inflightRaw - reviewable, 0)
  const oldestHeldAge = status.oldest_reviewable_at
    ? formatAge(status.oldest_reviewable_at)
    : null
  const oldestHeldFrom = snippetText(status.oldest_reviewable_from, 40)

  const pipelineGroups: Array<{
    label: string
    value: number
    color: string
    href?: DlpNavigateTarget
  }> = [
    {
      label: 'Held',
      value: reviewable,
      color: '#f97316',
      href: { tab: 'queue' },
    },
    {
      label: 'Stop requested',
      value: stopRequested,
      color: '#f59e0b',
      href: { tab: 'messages', filter: 'stop_requested' },
    },
    {
      label: 'Stopped',
      value: stopped,
      color: '#e11d48',
      href: { tab: 'messages', filter: 'stopped' },
    },
    {
      label: 'In flight',
      value: inflight,
      color: STATE_GROUP_COLORS.processing,
    },
    {
      label: 'Delivered',
      value: delivered,
      color: STATE_GROUP_COLORS.delivered,
      href: { tab: 'messages', filter: 'provider_accepted' },
    },
    {
      label: 'Retry',
      value: retry,
      color: STATE_GROUP_COLORS.retry,
      href: { tab: 'messages', filter: 'retry_scheduled' },
    },
    {
      label: 'Needs attention',
      value: issues,
      color: STATE_GROUP_COLORS.issues,
    },
  ]
  const groupedTotal = pipelineGroups.reduce((sum, group) => sum + group.value, 0)
  const ungrouped = Math.max(totalMessages - groupedTotal, 0)
  const ringData: typeof pipelineGroups = [
    ...pipelineGroups.filter((group) => group.value > 0),
    ...(ungrouped > 0
      ? [{ label: 'Other', value: ungrouped, color: '#71717a' }]
      : []),
  ]

  const waitingItems = [
    reviewable > 0 && {
      key: 'held',
      title: 'Held for review',
      count: reviewable,
      detail: oldestHeldAge
        ? `Oldest capture ${oldestHeldAge}${oldestHeldFrom ? ` · ${oldestHeldFrom}` : ''}`
        : 'Held mail is waiting in Queue.',
      tone: 'amber' as const,
      onClick: () => onNavigate({ tab: 'queue' }),
    },
    stopRequested > 0 && {
      key: 'stop_requested',
      title: 'Stop requested',
      count: stopRequested,
      detail: 'Waiting for the gateway to acknowledge stop.',
      tone: 'amber' as const,
      onClick: () => onNavigate({ tab: 'messages', filter: 'stop_requested' }),
    },
    status.failed_outbox_commands > 0 && {
      key: 'outbox',
      title: 'Failed gateway commands',
      count: status.failed_outbox_commands,
      detail: 'These commands were not applied by the gateway.',
      tone: 'red' as const,
      onClick: () => onNavigate({ tab: 'messages' }),
    },
  ].filter((item): item is Exclude<typeof item, false> => Boolean(item))

  const warnings = [
    !status.pipeline_enabled && 'The DLP runtime pipeline is disabled.',
    !settings.enabled && 'DLP is disabled for this tenant.',
    !status.classifier_url_configured && 'The classifier service is not configured.',
    status.failed_outbox_commands > 0 &&
      `${status.failed_outbox_commands} gateway command(s) failed.`,
  ].filter((item): item is string => Boolean(item))

  const failedCommands = status.failed_outbox_items ?? []

  const deliveryAlerts = [
    {
      state: 'delivery_retry_exhausted',
      label: 'Delivery retries exhausted',
      detail: 'These messages will not be retried automatically and need a manual decision.',
      tone: 'red' as const,
    },
    {
      state: 'failed',
      label: 'Delivery failed',
      detail: 'The gateway reported a permanent delivery failure.',
      tone: 'red' as const,
    },
    {
      state: 'outcome_uncertain',
      label: 'Uncertain delivery outcomes',
      detail: 'The final provider response was not captured; verify delivery out of band.',
      tone: 'amber' as const,
    },
    {
      state: 'partially_accepted',
      label: 'Partially accepted deliveries',
      detail: 'Some recipients refused the message while others accepted it.',
      tone: 'amber' as const,
    },
  ]
    .map((alert) => ({
      ...alert,
      count: counts[alert.state] ?? 0,
    }))
    .filter((alert) => alert.count > 0)

  return (
    <div className="space-y-6">
      {warnings.length > 0 && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.06] p-4">
          <div className="flex gap-3">
            <AlertTriangle size={17} className="mt-0.5 shrink-0 text-amber-400" />
            <div>
              <p className="text-sm font-medium text-amber-300">Attention required</p>
              <ul className="mt-1 space-y-1 text-xs text-amber-200/70">
                {warnings.map((warning) => <li key={warning}>{warning}</li>)}
              </ul>
            </div>
          </div>
        </div>
      )}

      {failedCommands.length > 0 && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/[0.06] p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <p className="text-sm font-medium text-red-300">Failed gateway commands</p>
            <JumpLink onClick={() => onNavigate({ tab: 'messages' })}>
              Open Messages
            </JumpLink>
          </div>
          <div className="space-y-2">
            {failedCommands.map((item) => (
              <div
                key={item.command_id}
                className="rounded-lg border border-red-500/10 bg-black/20 px-3 py-2"
              >
                <div className="flex flex-wrap items-center gap-2 text-[12px]">
                  <span className="capitalize text-red-200">
                    {item.command_type.replaceAll('_', ' ')}
                  </span>
                  <span className="text-[#a1a1aa]">
                    {item.envelope_from || item.message_id}
                  </span>
                  <span className="ml-auto text-[11px] text-[#71717a]">
                    {item.attempts} attempt{item.attempts === 1 ? '' : 's'}
                  </span>
                </div>
                {item.last_error && (
                  <p className="mt-1 text-[11px] leading-relaxed text-red-200/70">
                    {item.last_error}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {deliveryAlerts.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2">
          {deliveryAlerts.map((alert) => (
            <button
              key={alert.state}
              type="button"
              onClick={() => onNavigate({ tab: 'messages', filter: alert.state })}
              className={`rounded-xl border p-4 text-left transition-colors hover:bg-white/[0.03] ${
                alert.tone === 'red'
                  ? 'border-red-500/20 bg-red-500/[0.06]'
                  : 'border-amber-500/20 bg-amber-500/[0.06]'
              }`}
            >
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <AlertTriangle
                    size={14}
                    className={alert.tone === 'red' ? 'text-red-400' : 'text-amber-400'}
                  />
                  <p className={`text-sm font-medium ${
                    alert.tone === 'red' ? 'text-red-300' : 'text-amber-300'
                  }`}>
                    {alert.label}
                  </p>
                </div>
                <span className={`text-lg font-semibold ${
                  alert.tone === 'red' ? 'text-red-300' : 'text-amber-300'
                }`}>
                  {alert.count}
                </span>
              </div>
              <p className={`mt-1 text-xs ${
                alert.tone === 'red' ? 'text-red-200/70' : 'text-amber-200/70'
              }`}>
                {alert.detail}
              </p>
              <p className="mt-2 text-[11px] font-medium text-[#93b4fd]">
                Open in Messages →
              </p>
            </button>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Messages observed"
          value={totalMessages}
          icon={Activity}
          onClick={() => onNavigate({ tab: 'messages' })}
          footer={
            <div className="flex items-center justify-between">
              <div className="text-[11px] text-[#71717a]">
                <span>All-time snapshot</span>
                {' · '}
                <span>{settings.enabled ? 'Tenant enabled' : 'Tenant disabled'}</span>
                {' · '}
                <span className="capitalize">{settings.mode}</span>
              </div>
              <JumpHint>Open Messages</JumpHint>
            </div>
          }
        />
        <MetricCard
          label="Held + stopped"
          value={heldAndStopped}
          icon={Ban}
          iconClass="bg-red-500/10 border-red-500/20 text-red-400"
          badge={
            <div
              title="Share of all observed messages — not a time window"
              className="rounded-full border border-red-500/20 bg-red-500/10 px-2 py-0.5"
            >
              <span className="text-[11px] font-semibold text-red-400">{interventionRate}%</span>
            </div>
          }
          footer={
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-1.5">
                  <div className="h-2 w-2 rounded-full bg-orange-500" />
                  <span className="text-[11px] text-[#71717a]">{reviewable} held</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="h-2 w-2 rounded-full bg-amber-500" />
                  <span className="text-[11px] text-[#71717a]">{stopRequested} stop requested</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="h-2 w-2 rounded-full bg-red-500" />
                  <span className="text-[11px] text-[#71717a]">{stopped} stopped</span>
                </div>
              </div>
              <div className="flex flex-wrap gap-3">
                <JumpLink onClick={() => onNavigate({ tab: 'queue' })}>
                  Open Queue
                </JumpLink>
                {stopRequested > 0 && (
                  <JumpLink onClick={() => onNavigate({ tab: 'messages', filter: 'stop_requested' })}>
                    Stop requested
                  </JumpLink>
                )}
                {stopped > 0 && (
                  <JumpLink onClick={() => onNavigate({ tab: 'messages', filter: 'stopped' })}>
                    Stopped
                  </JumpLink>
                )}
              </div>
              <p className="text-[11px] text-[#52525b]">
                Share of all observed messages — not a 24h or 7d window.
              </p>
            </div>
          }
        />
        <MetricCard
          label="Active rules"
          value={activeRules}
          icon={ShieldCheck}
          iconClass="bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
          onClick={() => onNavigate({ tab: 'policy' })}
          footer={
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-[#71717a]">
                Policy v{activePolicy.version} · {activePolicy.status}
              </span>
              <JumpHint>Open Policy</JumpHint>
            </div>
          }
        />
        <MetricCard
          label="Pending review"
          value={reviewable}
          icon={Clock}
          iconClass="bg-amber-500/10 border-amber-500/20 text-amber-400"
          onClick={() => onNavigate({ tab: 'queue' })}
          badge={reviewable > 0 ? (
            <span className="relative flex h-3 w-3">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-75" />
              <span className="relative inline-flex h-3 w-3 rounded-full bg-amber-500" />
            </span>
          ) : undefined}
          footer={
            <div className="flex items-center justify-between gap-3">
              <span className="min-w-0 truncate text-[11px] text-[#71717a]">
                {reviewable === 0
                  ? 'No held mail'
                  : oldestHeldAge
                    ? `Oldest capture ${oldestHeldAge}${oldestHeldFrom ? ` · ${oldestHeldFrom}` : ''}`
                    : 'Held mail only — not the same as Decided'}
              </span>
              <JumpHint>Open Queue</JumpHint>
            </div>
          }
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
          <h3 className="mb-1 flex items-center gap-2 text-[14px] font-semibold text-[var(--foreground)]">
            <PieChart size={15} className="text-[#3b6ef6]" />
            Pipeline status
          </h3>
          <p className="mb-4 text-[11px] text-[#71717a]">
            All observed messages. This is not a 24-hour or 7-day window.
          </p>
          {totalMessages === 0 ? (
            <div className="py-10 text-center text-[13px] text-[#71717a]">
              No messages have been observed yet.
            </div>
          ) : (
            <div className="flex items-center justify-between">
              <RingChart
                data={ringData}
                centerValue={totalMessages}
                centerLabel="Total"
              />
              <div className="ml-6 flex-1 space-y-1">
                {ringData.map((item) => {
                  const target = item.href
                  const content = (
                    <>
                      <div className="flex min-w-0 items-center gap-2">
                        <div className="h-3 w-3 shrink-0 rounded-full" style={{ backgroundColor: item.color }} />
                        <span className="truncate text-[12px] text-[#a1a1aa]">{item.label}</span>
                      </div>
                      <span className="text-[12px] font-semibold text-[var(--foreground)]">{item.value}</span>
                    </>
                  )
                  if (target && item.value > 0) {
                    return (
                      <button
                        key={item.label}
                        type="button"
                        onClick={() => onNavigate(target)}
                        className="flex w-full items-center justify-between rounded-md px-1 py-1 text-left hover:bg-white/[0.04]"
                      >
                        {content}
                      </button>
                    )
                  }
                  return (
                    <div key={item.label} className="flex items-center justify-between px-1 py-1">
                      {content}
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
          <h3 className="mb-1 flex items-center gap-2 text-[14px] font-semibold text-[var(--foreground)]">
            <Inbox size={15} className="text-[#3b6ef6]" />
            Waiting on an operator
          </h3>
          <p className="mb-4 text-[11px] text-[#71717a]">
            Held review and failed commands. Stop requested waits on the gateway, not an operator. Delivery issues are listed above when present.
          </p>
          {waitingItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-2 py-10">
              <p className="text-[13px] text-[#71717a]">Nothing is waiting on an operator.</p>
              <p className="text-[11px] text-[#52525b]">
                Held mail and failed gateway commands appear here. Delivery failures are listed above.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {waitingItems.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  onClick={item.onClick}
                  className={`flex w-full items-start justify-between gap-3 rounded-lg border p-3 text-left transition-colors hover:bg-white/[0.03] ${
                    item.tone === 'red'
                      ? 'border-red-500/15 bg-red-500/[0.05]'
                      : 'border-amber-500/15 bg-amber-500/[0.05]'
                  }`}
                >
                  <div className="min-w-0">
                    <p className={`text-[13px] font-medium ${
                      item.tone === 'red' ? 'text-red-300' : 'text-amber-300'
                    }`}>
                      {item.title}
                    </p>
                    <p className="mt-0.5 truncate text-[11px] text-[#a1a1aa]">
                      {item.detail}
                    </p>
                  </div>
                  <span className={`text-lg font-semibold ${
                    item.tone === 'red' ? 'text-red-300' : 'text-amber-300'
                  }`}>
                    {item.count}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
        <h3 className="mb-1 flex items-center gap-2 text-[14px] font-semibold text-[var(--foreground)]">
          <FileWarning size={15} className="text-[#3b6ef6]" />
          Message states
        </h3>
          <p className="mb-4 text-[11px] text-[#71717a]">
            All-time counts by persisted control-plane state. Click a state to open it in Messages. Held mail awaiting review is the Queue tab. Operator holds persist as decided with action hold, not a separate held state.
          </p>
        {Object.keys(counts).length === 0 ? (
          <div className="py-8 text-center text-[13px] text-[#71717a]">
            No messages have been processed yet.
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
            {Object.entries(counts)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([state, count]) => (
                <button
                  key={state}
                  type="button"
                  onClick={() => onNavigate({ tab: 'messages', filter: state })}
                  className="flex items-center justify-between rounded-lg border border-white/[0.05] bg-white/[0.03] p-3 text-left transition-colors hover:border-white/[0.12] hover:bg-white/[0.05]"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <div className="h-2 w-2 shrink-0 rounded-full bg-[#3b6ef6]" />
                    <span className="truncate text-[12px] capitalize text-[#a1a1aa]" title={formatState(state)}>
                      {formatState(state)}
                    </span>
                  </div>
                  <span className="text-[12px] font-semibold text-[var(--foreground)]">{count}</span>
                </button>
              ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <h3 className="flex items-center gap-2 text-[14px] font-semibold text-[var(--foreground)]">
              <Eye size={15} className="text-[#3b6ef6]" />
              Latest observed messages
            </h3>
            <p className="mt-1 text-[11px] text-[#71717a]">
              The most recent 10 messages. This is a recency list, not a trend or health score.
            </p>
          </div>
          {recentMessages.length > 0 && (
            <JumpLink onClick={() => onNavigate({ tab: 'messages' })}>
              Open Messages
            </JumpLink>
          )}
        </div>
        {recentMessages.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 py-12">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-white/[0.03]">
              <Activity size={20} className="text-[#71717a]" />
            </div>
            <div className="text-center">
              <p className="mb-1 text-[13px] text-[#71717a]">No DLP messages yet</p>
              <p className="text-[11px] text-[#52525b]">
                Activity appears here when outbound mail is captured and classified.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            {recentMessages.map((message) => {
              const explanation = snippetText(message.explanation, 120)
              return (
              <button
                key={message.message_id}
                type="button"
                onClick={() => {
                  if (message.reviewable) {
                    onNavigate({ tab: 'queue' })
                    return
                  }
                  onNavigate({ tab: 'messages', filter: message.state })
                }}
                className="flex w-full items-center gap-3 rounded-lg border border-white/[0.04] bg-white/[0.02] p-3 text-left transition-colors hover:bg-white/[0.04]"
              >
                <div className={`h-2 w-2 shrink-0 rounded-full ${
                  message.effective_action === 'stop' ? 'bg-red-500'
                    : message.effective_action === 'hold' ? 'bg-orange-500'
                      : message.effective_action === 'allow' ? 'bg-emerald-500'
                        : 'bg-[#3b6ef6]'
                }`} />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-[12px] font-medium text-[var(--foreground)]">
                      {message.envelope_from}
                    </span>
                    <StateChip state={message.state} />
                    <ActionChip action={message.effective_action} />
                  </div>
                  <div className="truncate text-[11px] text-[#71717a]">
                    To: {formatRecipientList(message.envelope_to)}
                    {explanation ? ` · ${explanation}` : ''}
                  </div>
                </div>
                <span className="whitespace-nowrap text-[10px] text-[#52525b]">
                  {new Date(message.received_at).toLocaleString()}
                </span>
              </button>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
