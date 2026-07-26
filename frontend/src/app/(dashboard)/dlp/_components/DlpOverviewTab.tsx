import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  ScanSearch,
  ShieldCheck,
} from 'lucide-react'
import type { ElementType } from 'react'

import { Badge } from '@/components/ui/Badge'
import { Table, Tbody, Td, Th, Thead, Tr } from '@/components/ui/Table'
import type {
  DlpMessageSummary,
  DlpStatus,
  DlpTenantSettings,
} from '@/lib/dlp/types'

interface Props {
  status: DlpStatus
  settings: DlpTenantSettings
  recentMessages: DlpMessageSummary[]
}

function Metric({
  label,
  value,
  detail,
  icon: Icon,
  warning = false,
}: {
  label: string
  value: string | number
  detail: string
  icon: ElementType
  warning?: boolean
}) {
  return (
    <div className="rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-xs text-[#71717a]">{label}</span>
        <Icon size={15} className={warning ? 'text-amber-400' : 'text-[#3b6ef6]'} />
      </div>
      <div className="text-xl font-semibold text-[var(--foreground)]">{value}</div>
      <p className="mt-1 text-xs text-[#71717a]">{detail}</p>
    </div>
  )
}

function ActionBadge({ action }: { action: string | null }) {
  if (!action) return <span className="text-[#52525b]">—</span>
  const variant =
    action === 'stop' ? 'danger' : action === 'hold' ? 'warning' : 'success'
  return <Badge variant={variant}>{action.toUpperCase()}</Badge>
}

export default function DlpOverviewTab({
  status,
  settings,
  recentMessages,
}: Props) {
  const totalMessages = Object.values(status.message_counts).reduce(
    (sum, count) => sum + count,
    0,
  )
  const warnings = [
    !status.pipeline_enabled && 'The DLP runtime pipeline is disabled.',
    !settings.enabled && 'DLP is disabled for this tenant.',
    !status.classifier_url_configured && 'The classifier service is not configured.',
    status.failed_outbox_commands > 0 &&
      `${status.failed_outbox_commands} gateway command(s) failed.`,
  ].filter((item): item is string => Boolean(item))

  return (
    <div className="space-y-5">
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

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric
          label="Runtime pipeline"
          value={status.pipeline_enabled ? 'Ready' : 'Disabled'}
          detail="Gateway and worker environment"
          icon={Activity}
          warning={!status.pipeline_enabled}
        />
        <Metric
          label="Tenant protection"
          value={settings.enabled ? 'Enabled' : 'Disabled'}
          detail={`${settings.mode === 'monitor' ? 'Monitoring only' : 'Enforcing policy'}`}
          icon={ShieldCheck}
          warning={!settings.enabled}
        />
        <Metric
          label="Messages observed"
          value={totalMessages}
          detail={`${Object.keys(status.message_counts).length} message state(s)`}
          icon={Database}
        />
        <Metric
          label="Classifier"
          value={status.classifier_url_configured ? 'Configured' : 'Missing'}
          detail={`Policy v${settings.active_policy_version ?? 0}`}
          icon={ScanSearch}
          warning={!status.classifier_url_configured}
        />
      </div>

      {Object.keys(status.message_counts).length > 0 && (
        <div className="rounded-xl border border-white/[0.07] bg-[#13131a] p-4">
          <h2 className="mb-3 text-sm font-medium text-[var(--foreground)]">
            Message states
          </h2>
          <div className="flex flex-wrap gap-2">
            {Object.entries(status.message_counts)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([state, count]) => (
                <div
                  key={state}
                  className="flex items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.025] px-3 py-2"
                >
                  <CheckCircle2 size={12} className="text-[#3b6ef6]" />
                  <span className="text-xs capitalize text-[#a1a1aa]">
                    {state.replaceAll('_', ' ')}
                  </span>
                  <span className="text-xs font-semibold text-white">{count}</span>
                </div>
              ))}
          </div>
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-white/[0.07] bg-[#13131a]">
        <div className="border-b border-white/[0.06] px-4 py-3">
          <h2 className="text-sm font-medium text-[var(--foreground)]">
            Recent messages
          </h2>
          <p className="mt-0.5 text-xs text-[#71717a]">
            Latest messages observed by DLP v2
          </p>
        </div>
        {recentMessages.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-[#71717a]">
            No DLP messages have been processed yet.
          </div>
        ) : (
          <Table>
            <Thead>
              <Tr>
                <Th>Received</Th>
                <Th>Sender</Th>
                <Th>State</Th>
                <Th>Decision</Th>
              </Tr>
            </Thead>
            <Tbody>
              {recentMessages.map((message) => (
                <Tr key={message.message_id}>
                  <Td className="whitespace-nowrap text-xs">
                    {new Date(message.received_at).toLocaleString()}
                  </Td>
                  <Td className="max-w-[260px] truncate text-xs">
                    {message.envelope_from}
                  </Td>
                  <Td>
                    <Badge variant="neutral">
                      {message.state.replaceAll('_', ' ')}
                    </Badge>
                  </Td>
                  <Td><ActionBadge action={message.effective_action} /></Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </div>
    </div>
  )
}
