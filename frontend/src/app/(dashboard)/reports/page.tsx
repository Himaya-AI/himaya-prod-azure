'use client'
import { useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import Button from '@/components/ui/Button'
import api from '@/lib/api'
import { Download, BarChart2, Shield, FileText } from 'lucide-react'

interface Report {
  id: string
  name: string
  type: string
  framework?: string
  generated_at: string
  status: 'ready' | 'generating' | 'failed'
}

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/api/reports')
      .then(r => setReports(Array.isArray(r.data) ? r.data : (r.data?.items ?? [])))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[18px] font-semibold text-[var(--foreground)]">Reports</h1>
        <p className="text-sm text-slate-400 mt-0.5">Security reports and exports</p>
      </div>

      {/* Quick generate cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {[
          { icon: Shield, label: 'Threat Summary', desc: 'Weekly threat activity report', type: 'threat_summary' },
          { icon: BarChart2, label: 'Risk Report', desc: 'Organization risk posture analysis', type: 'risk_report' },
          { icon: FileText, label: 'Compliance Report', desc: 'SAMA/NCA compliance status', type: 'compliance' },
        ].map(({ icon: Icon, label, desc, type }) => (
          <Card key={type} className="flex items-start gap-4">
            <div className="p-2.5 rounded-lg bg-[#0f3460]/40">
              <Icon size={18} className="text-[#e94560]" />
            </div>
            <div className="flex-1">
              <div className="text-sm font-semibold text-slate-200">{label}</div>
              <div className="text-xs text-slate-500 mt-0.5 mb-3">{desc}</div>
              <Button size="sm" variant="secondary" onClick={() => api.post('/api/reports/generate', { type })}>
                Generate
              </Button>
            </div>
          </Card>
        ))}
      </div>

      {/* Report history */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Recent Reports</h2>
        <div className="bg-[#16213e] border border-[#0f3460]/50 rounded-xl overflow-hidden">
          {loading ? (
            <div className="p-6 space-y-3">
              {[...Array(3)].map((_, i) => <div key={i} className="h-12 animate-pulse bg-[#0f3460]/20 rounded" />)}
            </div>
          ) : reports.length === 0 ? (
            <div className="text-center text-slate-500 py-16 text-sm">No reports generated yet</div>
          ) : (
            <div className="divide-y divide-[#0f3460]/30">
              {reports.map(r => (
                <div key={r.id} className="flex items-center gap-4 px-4 py-3">
                  <FileText size={16} className="text-slate-500" />
                  <div className="flex-1">
                    <div className="text-sm font-medium text-slate-200">{r.name}</div>
                    <div className="text-xs text-slate-500">{new Date(r.generated_at).toLocaleString()}</div>
                  </div>
                  <Badge variant={r.status === 'ready' ? 'success' : r.status === 'generating' ? 'info' : 'danger'}>
                    {r.status}
                  </Badge>
                  {r.status === 'ready' && (
                    <Button size="sm" variant="ghost" onClick={() => window.open(`${(process.env.NEXT_PUBLIC_API_URL || 'https://app.himaya.ai')}/api/reports/${r.id}/download`, '_blank')}>
                      <Download size={13} />
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
