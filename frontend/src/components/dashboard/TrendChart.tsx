'use client'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { TrendingUp } from 'lucide-react'
import type { TrendDataPoint } from '@/lib/types'

interface Props {
  data: TrendDataPoint[]
  loading?: boolean
}

export default function TrendChart({ data, loading }: Props) {
  const hasData = data && data.length > 0

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>30-Day Potential Threat Trend</CardTitle>
          {hasData && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 border border-red-500/20 text-red-400">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              Live
            </span>
          )}
        </div>
      </CardHeader>
      {loading ? (
        <div className="h-48 animate-pulse bg-[#0f3460]/20 rounded" />
      ) : !hasData ? (
        <div className="h-[220px] flex flex-col items-center justify-center gap-3 text-center">
          <div className="w-12 h-12 rounded-full bg-[#3b6ef6]/10 flex items-center justify-center">
            <TrendingUp size={22} className="text-[#3b6ef6]/40" />
          </div>
          <div>
            <p className="text-[13px] font-medium text-slate-400">No trend data yet</p>
            <p className="text-[12px] text-slate-600 mt-1">Data will appear once emails are analysed</p>
          </div>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#0f3460" />
            <XAxis
              dataKey="date"
              tick={{ fill: '#64748b', fontSize: 11 }}
              tickLine={false}
              tickFormatter={(v: string) => {
                try { return new Date(v).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) } catch { return v }
              }}
            />
            <YAxis tick={{ fill: '#64748b', fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: '#16213e', border: '1px solid #0f3460', borderRadius: 8, fontSize: 12 }}
              labelStyle={{ color: '#94a3b8' }}
              labelFormatter={(v) => {
                try { return new Date(String(v)).toLocaleDateString('en-GB', { weekday: 'short', day: '2-digit', month: 'short' }) } catch { return String(v) }
              }}
            />
            <Legend wrapperStyle={{ fontSize: 12, color: '#94a3b8' }} />
            <Line
              type="monotone"
              dataKey="threats_detected"
              name="Potential Threats"
              stroke="#e94560"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
            />
            <Line
              type="monotone"
              dataKey="quarantined"
              name="Quarantined"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </Card>
  )
}
