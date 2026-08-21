'use client'
import { useEffect, useRef, useState } from 'react'
import { Globe } from 'lucide-react'
import api from '@/lib/api'

interface CountryThreat {
  country: string
  country_code: string
  threat_count: number
}

const REFRESH_MS = 4 * 60 * 60 * 1000 // 4 hours

// Choropleth world map — same jsvectormap engine as the Data Residency map.
function ThreatWorldMap({ data }: { data: CountryThreat[] }) {
  const mapRef = useRef<HTMLDivElement>(null)
  const mapInstanceRef = useRef<unknown>(null)

  useEffect(() => {
    let cancelled = false

    const initMap = async () => {
      if (cancelled || !mapRef.current || typeof window === 'undefined') return
      const rect = mapRef.current.getBoundingClientRect()
      if (rect.width < 50 || rect.height < 50) {
        requestAnimationFrame(initMap)
        return
      }

      const jsVectorMap = (await import('jsvectormap')).default
      await import('jsvectormap/dist/maps/world')
      await import('jsvectormap/dist/jsvectormap.css')
      if (cancelled || !mapRef.current) return

      if (mapInstanceRef.current) {
        try { (mapInstanceRef.current as { destroy: () => void }).destroy() } catch { /* already destroyed */ }
        mapInstanceRef.current = null
      }
      while (mapRef.current.firstChild) mapRef.current.removeChild(mapRef.current.firstChild)

      const values: Record<string, number> = {}
      const counts: Record<string, { country: string; count: number }> = {}
      data.forEach(d => {
        if (d.country_code) {
          values[d.country_code] = d.threat_count
          counts[d.country_code] = { country: d.country, count: d.threat_count }
        }
      })

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      mapInstanceRef.current = new (jsVectorMap as any)({
        selector: mapRef.current,
        map: 'world',
        backgroundColor: 'transparent',
        zoomButtons: false,
        zoomOnScroll: false,
        regionStyle: {
          initial: { fill: '#1e1e26', stroke: '#0b0b0e', strokeWidth: 0.4 },
          hover: { fill: '#2c2c36' },
        },
        visualizeData: {
          scale: ['#3d1d20', '#ef4444'],
          values,
        },
        onRegionTooltipShow: (_e: unknown, tooltip: { text: (t: string) => void; _tooltip?: unknown }, code: string) => {
          const hit = counts[code]
          const name = (tooltip as unknown as { text: () => string }).text()
          tooltip.text(hit ? `${hit.country} — ${hit.count.toLocaleString()} potential threats` : String(name))
        },
      })
    }

    initMap()
    return () => {
      cancelled = true
      if (mapInstanceRef.current) {
        try { (mapInstanceRef.current as { destroy: () => void }).destroy() } catch { /* noop */ }
        mapInstanceRef.current = null
      }
    }
  }, [data])

  return <div ref={mapRef} className="w-full h-[320px] lg:h-[420px]" />
}

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
          <Globe size={15} className="text-[#24befa]" />
          <h3 className="text-[13px] font-semibold text-white">
            Potential Threat Ingress Locations
          </h3>
          <span className="flex items-center gap-1.5 text-[10px] font-medium text-slate-500">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400/80 animate-pulse" />
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
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 h-[260px] animate-pulse bg-white/[0.04] rounded-lg" />
          <div className="space-y-2">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-8 animate-pulse bg-white/[0.04] rounded" />
            ))}
          </div>
        </div>
      ) : displayed.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 gap-2 text-center">
          <Globe size={28} className="text-slate-600" />
          <p className="text-[12px] text-slate-500 italic max-w-xs">
            No data yet — ingress locations populate as emails are scanned and geo-tagged.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
          {/* Choropleth map */}
          <div className="lg:col-span-2 min-w-0">
            <ThreatWorldMap data={displayed} />
          </div>

          {/* Ranked list */}
          <div className="space-y-2.5">
            {displayed.map((row, i) => {
              const pct = Math.round((row.threat_count / maxCount) * 100)
              const code = row.country_code.toLowerCase()
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
                        width={20}
                        height={15}
                        className="rounded-sm shrink-0 shadow-sm"
                        onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
                      />
                    ) : (
                      <div className="w-5 h-3.5 rounded-sm bg-white/[0.06] shrink-0" />
                    )}
                    <span className="text-[12px] text-slate-300 font-medium truncate flex-1">
                      {row.country}
                    </span>
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full shrink-0"
                      style={{ background: 'rgba(239,68,68,0.12)', color: '#f87171' }}>
                      {row.threat_count.toLocaleString()}
                    </span>
                  </div>
                  <div className="ml-7 h-1 bg-white/[0.05] rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700 bg-[#ef4444]/70"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
