'use client'
import React from 'react'
import { CheckCircle, AlertTriangle, XCircle } from 'lucide-react'
import type { DashboardSummary } from '@/lib/types'

interface Props {
  summary: DashboardSummary | null
  loading?: boolean
}

export default function StatusBanner({ summary, loading }: Props) {
  if (loading) {
    return <div className="h-14 rounded-xl bg-white/[0.03] animate-pulse border border-white/[0.06]" />
  }
  if (!summary) return null

  const configMap: Record<string, { bg: string; border: string; text: string; sub: string; icon: React.ElementType; label: string; desc: string }> = {
    healthy: {
      bg: 'bg-white/[0.02]',
      border: 'border-white/[0.07]',
      text: 'text-[#d4d4d8]',
      sub: 'text-[#71717a]',
      icon: CheckCircle,
      label: 'All systems healthy',
      desc: 'No active threats requiring immediate attention',
    },
    warning: {
      bg: 'bg-[#f59e0b]/[0.05]',
      border: 'border-[#f59e0b]/20',
      text: 'text-[#fcd34d]',
      sub: 'text-[#92400e]/80',
      icon: AlertTriangle,
      label: 'Active threats detected',
      desc: `${summary.active_threats ?? 0} threat(s) require review`,
    },
    critical: {
      bg: 'bg-[#e03d4e]/[0.06]',
      border: 'border-[#e03d4e]/20',
      text: 'text-[#fca5a5]',
      sub: 'text-[#fca5a5]/70',
      icon: XCircle,
      label: 'Critical — immediate action required',
      desc: `${summary.active_threats ?? 0} critical threat(s) detected`,
    },
  }
  const config = configMap[summary.status] ?? configMap.healthy
  const Icon = config.icon

  return (
    <div className={`flex items-center gap-4 px-5 py-3.5 rounded-xl border ${config.bg} ${config.border}`}>
      <Icon size={18} className={config.text} strokeWidth={1.5} />
      <div>
        <div className={`text-[13px] font-medium ${config.text}`}>{config.label}</div>
        <div className={`text-[12px] mt-0.5 ${config.sub}`}>{config.desc}</div>
      </div>
    </div>
  )
}
