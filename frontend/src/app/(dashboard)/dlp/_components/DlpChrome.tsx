import type { ElementType, ReactNode } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Lock,
  ShieldAlert,
} from 'lucide-react'

export const ACTION_COLORS = {
  allow: '#10b981',
  hold: '#f97316',
  stop: '#ef4444',
} as const

export const STATE_GROUP_COLORS = {
  delivered: '#10b981',
  processing: '#3b6ef6',
  retry: '#f59e0b',
  issues: '#ef4444',
} as const

const ACTION_PILL: Record<string, string> = {
  allow: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  hold: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
  stop: 'bg-red-500/10 border-red-500/20 text-red-400',
}

const STATE_PILL: Record<string, string> = {
  provider_accepted: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
  retry_scheduled: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
  partially_accepted: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
  outcome_uncertain: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
  held: 'bg-orange-500/10 border-orange-500/20 text-orange-400',
  decided: 'bg-[#3b6ef6]/10 border-[#3b6ef6]/20 text-[#93b4fd]',
  classified: 'bg-[#3b6ef6]/10 border-[#3b6ef6]/20 text-[#93b4fd]',
  failed: 'bg-red-500/10 border-red-500/20 text-red-400',
  delivery_retry_exhausted: 'bg-red-500/10 border-red-500/20 text-red-400',
  stop_requested: 'bg-red-500/10 border-red-500/20 text-red-400',
}

export function formatState(value: string) {
  return value.replaceAll('_', ' ')
}

export function ActionChip({ action }: { action: string | null }) {
  if (!action) {
    return <span className="text-[11px] text-[#52525b]">Pending</span>
  }
  const key = action.toLowerCase()
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${ACTION_PILL[key] ?? 'bg-white/[0.04] border-white/[0.08] text-[#a1a1aa]'}`}>
      {key === 'stop' ? <ShieldAlert size={10} /> : key === 'hold' ? <Lock size={10} /> : <CheckCircle2 size={10} />}
      {action.toUpperCase()}
    </span>
  )
}

export function StateChip({ state }: { state: string }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold capitalize ${STATE_PILL[state] ?? 'bg-white/[0.04] border-white/[0.08] text-[#a1a1aa]'}`}>
      {(state === 'failed' || state === 'delivery_retry_exhausted' || state === 'stop_requested') && (
        <AlertTriangle size={10} />
      )}
      {formatState(state)}
    </span>
  )
}

export function OutcomeChip({ outcome }: { outcome: string }) {
  const key = outcome.toLowerCase()
  const tone =
    key === 'accepted' ? ACTION_PILL.allow
      : key === 'failed' ? ACTION_PILL.stop
        : key === 'deferred' || key === 'partial' || key === 'uncertain'
          ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
          : 'bg-white/[0.04] border-white/[0.08] text-[#a1a1aa]'
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${tone}`}>
      {outcome.toUpperCase()}
    </span>
  )
}

export function MetricCard({
  label,
  value,
  icon: Icon,
  iconClass = 'bg-[#3b6ef6]/10 border-[#3b6ef6]/20 text-[#3b6ef6]',
  badge,
  footer,
}: {
  label: string
  value: string | number
  icon: ElementType
  iconClass?: string
  badge?: ReactNode
  footer?: ReactNode
}) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-gradient-to-br from-[#13131a] to-[#1a1a24] p-5">
      <div className="mb-3 flex items-start justify-between">
        <div className={`flex h-10 w-10 items-center justify-center rounded-xl border ${iconClass}`}>
          <Icon size={18} />
        </div>
        {badge}
      </div>
      <div className="mb-1 text-2xl font-bold text-[var(--foreground)]">{value}</div>
      <div className="text-[12px] text-[#71717a]">{label}</div>
      {footer && (
        <div className="mt-3 border-t border-white/[0.06] pt-3">{footer}</div>
      )}
    </div>
  )
}

export function RingChart({
  data,
  size = 140,
  strokeWidth = 16,
  centerLabel,
  centerValue,
}: {
  data: { label: string; value: number; color: string }[]
  size?: number
  strokeWidth?: number
  centerLabel?: string
  centerValue?: string | number
}) {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const segments = data.map((segment, index) => {
    const percentage = total > 0 ? segment.value / total : 0
    const offset = data
      .slice(0, index)
      .reduce((sum, item) => sum + (total > 0 ? item.value / total : 0), 0)
    return {
      ...segment,
      strokeDasharray: `${circumference * percentage} ${circumference}`,
      strokeDashoffset: -circumference * offset,
    }
  })

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90 transform">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth={strokeWidth}
        />
        {segments.map((segment) => (
          <circle
            key={segment.label}
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={segment.color}
            strokeWidth={strokeWidth}
            strokeDasharray={segment.strokeDasharray}
            strokeDashoffset={segment.strokeDashoffset}
            strokeLinecap="round"
            className="transition-all duration-500"
          />
        ))}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        {centerValue !== undefined && (
          <span className="text-2xl font-bold text-[var(--foreground)]">{centerValue}</span>
        )}
        {centerLabel && (
          <span className="text-[11px] text-[#71717a]">{centerLabel}</span>
        )}
      </div>
    </div>
  )
}

export function BarChart({
  data,
  height = 140,
  barWidth = 40,
}: {
  data: { label: string; value: number; color?: string }[]
  height?: number
  barWidth?: number
}) {
  const maxValue = Math.max(...data.map((item) => item.value), 1)

  return (
    <div className="flex items-end justify-between gap-2" style={{ height }}>
      {data.map((item) => (
        <div key={item.label} className="flex flex-col items-center gap-1">
          <span className="text-[10px] font-medium text-[#71717a]">{item.value}</span>
          <div
            className="rounded-t transition-all duration-500"
            style={{
              width: barWidth,
              height: `${Math.max((item.value / maxValue) * (height - 40), 4)}px`,
              backgroundColor: item.color || '#3b6ef6',
            }}
          />
          <span className="max-w-[48px] truncate text-[10px] text-[#71717a]">{item.label}</span>
        </div>
      ))}
    </div>
  )
}

export function countStates(
  counts: Record<string, number>,
  keys: string[],
) {
  return keys.reduce((sum, key) => sum + (counts[key] ?? 0), 0)
}
