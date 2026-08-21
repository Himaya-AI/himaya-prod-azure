import { ReactNode } from 'react'

interface MetricCardProps {
  label: string
  value: string | number
  sublabel?: string
  icon?: ReactNode
  accent?: 'red' | 'amber' | 'green' | 'blue'
  loading?: boolean
}

const dotColors = {
  red: 'bg-rose-500',
  amber: 'bg-amber-400',
  green: 'bg-emerald-400',
  blue: 'bg-blue-400',
}

/**
 * Flat KPI cell (Strata Cloud Manager-style): muted inline icon + uppercase
 * label, large neutral value with a small severity dot. Designed to sit inside
 * a shared bordered strip (gap-px grid) rather than as a standalone card.
 */
export default function MetricCard({ label, value, sublabel, icon, accent = 'blue', loading }: MetricCardProps) {
  if (loading) {
    return (
      <div className="bg-[#101014] p-4 h-full">
        <div className="animate-pulse space-y-3">
          <div className="h-3 bg-white/[0.05] rounded w-2/3" />
          <div className="h-7 bg-white/[0.05] rounded w-1/2" />
        </div>
      </div>
    )
  }
  return (
    <div className="bg-[#101014] p-4 h-full hover:bg-white/[0.02] transition-colors">
      <div className="flex items-center gap-1.5 text-slate-500">
        {icon && <span className="shrink-0 [&>svg]:w-[13px] [&>svg]:h-[13px]">{icon}</span>}
        <span className="text-[10.5px] font-medium uppercase tracking-wider leading-tight truncate">{label}</span>
      </div>
      <div className="mt-2 flex items-baseline gap-2 min-w-0">
        <span className={`font-semibold text-white truncate ${typeof value === 'string' && value.length > 10 ? 'text-lg' : 'text-[26px] leading-8'} tabular-nums`}>{value}</span>
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotColors[accent]}`} />
      </div>
      {sublabel && <div className="text-[11px] text-slate-500 mt-1 truncate">{sublabel}</div>}
    </div>
  )
}
