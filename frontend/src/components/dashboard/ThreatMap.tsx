'use client'
import { useEffect, useState } from 'react'
import { Globe, Zap } from 'lucide-react'
import api from '@/lib/api'

interface CountryThreat {
  country: string
  country_code: string
  threat_count: number
}

const REFRESH_MS = 4 * 60 * 60 * 1000 // 4 hours

export default function ThreatMap() {
  const [data, setData] = useState<CountryThreat[]>([])
  const [loading, setLoading] = useState(true)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const fetchData = async (silent = false) => {
    if (!silent) setLoading(true)
    try {
      const res = await api.get('/api/dashboard/threat-map')
      setData(res.data ?? [])
      setLastUpdated(new Date())
    } catch {
      // silent fail
    }
    if (!silent) setLoading(false)
  }

  useEffect(() => {
    fetchData(false)
    const id = setInterval(() => fetchData(true), REFRESH_MS)
    return () => clearInterval(id)
  }, [])

  const maxCount = data.length > 0 ? Math.max(...data.map(d => d.threat_count)) : 1
  const displayed = data.slice(0, 9)

  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl p-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div className="flex items-center gap-2 flex-wrap">
          <Globe size={15} className="text-[#3b6ef6]" />
          <h3 className="text-[13px] font-semibold text-white">
            Potential Threat Ingress Locations
          </h3>
          <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 text-red-400 border border-red-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
            Live
          </span>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-[10px] text-slate-500">
              Updated {lastUpdated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
          )}
          <span className="text-[10px] text-slate-600">Refreshes every 4h</span>
        </div>
      </div>

      {loading ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-10 animate-pulse bg-white/[0.04] rounded" />
          ))}
        </div>
      ) : displayed.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 gap-2 text-center">
          <Globe size={28} className="text-slate-600" />
          <p className="text-[12px] text-slate-500 italic max-w-xs">
            No data yet — ingress locations populate as emails are scanned and geo-tagged.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-3">
          {displayed.map((row, i) => {
            const pct = Math.round((row.threat_count / maxCount) * 100)
            const code = row.country_code.toLowerCase()
            // Intensity colour: fades from deep red (top) to amber (bottom)
            const hue = Math.round(10 - (i / Math.max(displayed.length - 1, 1)) * 10) // 10→0 (red-ish)
            const intensity = Math.max(40, 85 - i * 4)
            return (
              <div key={row.country_code || row.country} className="flex flex-col gap-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-bold text-slate-500 w-5 shrink-0 tabular-nums">
                    #{i + 1}
                  </span>
                  {code ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      src={`https://flagcdn.com/24x18/${code}.png`}
                      alt={row.country}
                      width={24}
                      height={18}
                      className="rounded-sm shrink-0 shadow-sm"
                      onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
                    />
                  ) : (
                    <div className="w-6 h-4 rounded-sm bg-white/[0.06] shrink-0" />
                  )}
                  <span className="text-[12px] text-slate-300 font-medium truncate flex-1">
                    {row.country}
                  </span>
                  <span className="text-[11px] font-bold px-2 py-0.5 rounded-full shrink-0"
                    style={{ background: 'rgba(239,68,68,0.12)', color: '#f87171' }}>
                    {row.threat_count.toLocaleString()}
                  </span>
                </div>
                <div className="ml-7 h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${pct}%`,
                      background: `hsl(${hue}, 85%, ${intensity}%)`,
                    }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
