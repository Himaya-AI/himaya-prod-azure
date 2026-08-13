import {
  Activity,
  AlertTriangle,
  Ban,
  BarChart3,
  Clock,
  Eye,
  FileWarning,
  PieChart,
  ShieldCheck,
} from 'lucide-react'

import {
  ACTION_COLORS,
  ActionChip,
  BarChart,
  MetricCard,
  RingChart,
  STATE_GROUP_COLORS,
  StateChip,
  countStates,
  formatState,
} from './DlpChrome'
import type {
  DlpMessageSummary,
  DlpStatus,
  DlpTenantSettings,
  PolicyVersion,
} from '@/lib/dlp/types'

interface Props {
  status: DlpStatus
  settings: DlpTenantSettings
  activePolicy: PolicyVersion
  recentMessages: DlpMessageSummary[]
}

export default function DlpOverviewTab({
  status,
  settings,
  activePolicy,
  recentMessages,
}: Props) {
  const counts = status.message_counts
  const totalMessages = Object.values(counts).reduce((sum, count) => sum + count, 0)
  const reviewable = status.reviewable_count ?? 0
  const stopped = counts.stop_requested ?? 0
  const heldAndStopped = reviewable + stopped
  const interventionRate = totalMessages > 0
    ? Math.round((heldAndStopped / totalMessages) * 100)
    : 0
  const activeRules = activePolicy.document.rules.filter((rule) => rule.enabled).length

  const pipelineGroups = [
    {
      label: 'Delivered',
      value: countStates(counts, ['provider_accepted']),
      color: STATE_GROUP_COLORS.delivered,
    },
    {
      label: 'Processing',
      value: countStates(counts, [
        'received',
        'classified',
        'decided',
        'release_requested',
        'allow_pending',
        'submitting',
      ]),
      color: STATE_GROUP_COLORS.processing,
    },
    {
      label: 'Retry',
      value: countStates(counts, ['retry_scheduled']),
      color: STATE_GROUP_COLORS.retry,
    },
    {
      label: 'Needs attention',
      value: countStates(counts, [
        'failed',
        'delivery_retry_exhausted',
        'outcome_uncertain',
        'partially_accepted',
        'stop_requested',
      ]),
      color: STATE_GROUP_COLORS.issues,
    },
  ]
  const groupedTotal = pipelineGroups.reduce((sum, group) => sum + group.value, 0)
  const ungrouped = Math.max(totalMessages - groupedTotal, 0)
  const ringData = ungrouped > 0
    ? [...pipelineGroups, { label: 'Other', value: ungrouped, color: '#71717a' }]
    : pipelineGroups

  const recentActions = recentMessages.reduce(
    (acc, message) => {
      if (message.effective_action === 'allow') acc.allow += 1
      else if (message.effective_action === 'hold') acc.hold += 1
      else if (message.effective_action === 'stop') acc.stop += 1
      return acc
    },
    { allow: 0, hold: 0, stop: 0 },
  )

  const warnings = [
    !status.pipeline_enabled && 'The DLP runtime pipeline is disabled.',
    !settings.enabled && 'DLP is disabled for this tenant.',
    !status.classifier_url_configured && 'The classifier service is not configured.',
    status.failed_outbox_commands > 0 &&
      `${status.failed_outbox_commands} gateway command(s) failed.`,
  ].filter((item): item is string => Boolean(item))

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

      {deliveryAlerts.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2">
          {deliveryAlerts.map((alert) => (
            <div
              key={alert.state}
              className={`rounded-xl border p-4 ${
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
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          label="Messages observed"
          value={totalMessages}
          icon={Activity}
          footer={
            <div className="flex items-center justify-between text-[11px] text-[#71717a]">
              <span>{settings.enabled ? 'Tenant enabled' : 'Tenant disabled'}</span>
              <span className="capitalize">{settings.mode}</span>
            </div>
          }
        />
        <MetricCard
          label="Held + stopped"
          value={heldAndStopped}
          icon={Ban}
          iconClass="bg-red-500/10 border-red-500/20 text-red-400"
          badge={
            <div className="rounded-full border border-red-500/20 bg-red-500/10 px-2 py-0.5">
              <span className="text-[11px] font-semibold text-red-400">{interventionRate}%</span>
            </div>
          }
          footer={
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full bg-orange-500" />
                <span className="text-[11px] text-[#71717a]">{reviewable} held</span>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="h-2 w-2 rounded-full bg-red-500" />
                <span className="text-[11px] text-[#71717a]">{stopped} stop requested</span>
              </div>
            </div>
          }
        />
        <MetricCard
          label="Active rules"
          value={activeRules}
          icon={ShieldCheck}
          iconClass="bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
          footer={
            <span className="text-[11px] text-[#71717a]">
              Policy v{activePolicy.version} · {activePolicy.status}
            </span>
          }
        />
        <MetricCard
          label="Pending review"
          value={reviewable}
          icon={Clock}
          iconClass="bg-amber-500/10 border-amber-500/20 text-amber-400"
          badge={reviewable > 0 ? (
            <span className="relative flex h-3 w-3">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-75" />
              <span className="relative inline-flex h-3 w-3 rounded-full bg-amber-500" />
            </span>
          ) : undefined}
          footer={
            <span className="text-[11px] text-[#71717a]">
              Held messages awaiting approval
            </span>
          }
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
          <h3 className="mb-4 flex items-center gap-2 text-[14px] font-semibold text-[var(--foreground)]">
            <PieChart size={15} className="text-[#3b6ef6]" />
            Pipeline status
          </h3>
          <div className="flex items-center justify-between">
            <RingChart
              data={ringData}
              centerValue={totalMessages}
              centerLabel="Total"
            />
            <div className="ml-6 flex-1 space-y-2">
              {ringData.map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-3 w-3 rounded-full" style={{ backgroundColor: item.color }} />
                    <span className="text-[12px] text-[#a1a1aa]">{item.label}</span>
                  </div>
                  <span className="text-[12px] font-semibold text-[var(--foreground)]">{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
          <h3 className="mb-4 flex items-center gap-2 text-[14px] font-semibold text-[var(--foreground)]">
            <BarChart3 size={15} className="text-[#3b6ef6]" />
            Recent decisions
          </h3>
          <BarChart
            data={[
              { label: 'Allow', value: recentActions.allow, color: ACTION_COLORS.allow },
              { label: 'Hold', value: recentActions.hold, color: ACTION_COLORS.hold },
              { label: 'Stop', value: recentActions.stop, color: ACTION_COLORS.stop },
            ]}
          />
          <p className="mt-3 text-[11px] text-[#52525b]">
            From the latest {recentMessages.length} observed messages.
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
        <h3 className="mb-4 flex items-center gap-2 text-[14px] font-semibold text-[var(--foreground)]">
          <FileWarning size={15} className="text-[#3b6ef6]" />
          Message states
        </h3>
        {Object.keys(counts).length === 0 ? (
          <div className="py-8 text-center text-[13px] text-[#71717a]">
            No messages have been processed yet.
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
            {Object.entries(counts)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([state, count]) => (
                <div
                  key={state}
                  className="flex items-center justify-between rounded-lg border border-white/[0.05] bg-white/[0.03] p-3"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <div className="h-2 w-2 shrink-0 rounded-full bg-[#3b6ef6]" />
                    <span className="truncate text-[12px] capitalize text-[#a1a1aa]" title={formatState(state)}>
                      {formatState(state)}
                    </span>
                  </div>
                  <span className="text-[12px] font-semibold text-[var(--foreground)]">{count}</span>
                </div>
              ))}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-white/[0.06] bg-[#13131a] p-5">
        <h3 className="mb-4 flex items-center gap-2 text-[14px] font-semibold text-[var(--foreground)]">
          <Eye size={15} className="text-[#3b6ef6]" />
          Recent activity
        </h3>
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
            {recentMessages.slice(0, 8).map((message) => (
              <div
                key={message.message_id}
                className="flex items-center gap-3 rounded-lg border border-white/[0.04] bg-white/[0.02] p-3 transition-colors hover:bg-white/[0.04]"
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
                    To: {message.envelope_to.join(', ') || '—'}
                  </div>
                </div>
                <span className="whitespace-nowrap text-[10px] text-[#52525b]">
                  {new Date(message.received_at).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
