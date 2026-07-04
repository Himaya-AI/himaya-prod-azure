import { ReactNode } from 'react'
import { Card } from '@/components/ui/Card'

interface MetricCardProps {
  label: string
  value: string | number
  sublabel?: string
  icon?: ReactNode
  accent?: 'red' | 'amber' | 'green' | 'blue'
  loading?: boolean
}

const accents = {
  red: 'text-[#e94560]',
  amber: 'text-amber-400',
  green: 'text-emerald-400',
  blue: 'text-blue-400',
}

export default function MetricCard({ label, value, sublabel, icon, accent = 'blue', loading }: MetricCardProps) {
  if (loading) {
    return (
      <Card>
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-[#0f3460]/40 rounded w-2/3" />
          <div className="h-8 bg-[#0f3460]/40 rounded w-1/2" />
        </div>
      </Card>
    )
  }
  return (
    <Card className="flex items-start justify-between gap-2">
      <div className="min-w-0 flex-1">
        <div className="text-xs text-slate-400 mb-1 font-medium uppercase tracking-wide leading-tight">{label}</div>
        <div className={`font-bold truncate ${typeof value === 'string' && value.length > 10 ? 'text-lg sm:text-xl' : 'text-2xl sm:text-3xl'} ${accents[accent]}`}>{value}</div>
        {sublabel && <div className="text-xs text-slate-500 mt-1 truncate">{sublabel}</div>}
      </div>
      {icon && (
        <div className={`p-2 sm:p-2.5 rounded-lg shrink-0 ${accents[accent]}`}
          style={{ background: 'color-mix(in srgb, currentColor 12%, transparent)' }}>
          {icon}
        </div>
      )}
    </Card>
  )
}
