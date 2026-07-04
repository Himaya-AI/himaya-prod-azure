'use client'
import { useEffect, useState, useRef } from 'react'
import type { ThreatFeedEvent } from '@/lib/types'
import api from '@/lib/api'
import { t } from '@/lib/i18n'
import { useLang } from '@/lib/LangContext'
import { useRouter } from 'next/navigation'
import { ArrowRight } from 'lucide-react'

function fmtTimestamp(iso: string | null | undefined): string {
  if (!iso) return ''
  try {
    const d = new Date(iso)
    const now = new Date()
    const diffMs = now.getTime() - d.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    if (diffMins < 1) return 'just now'
    if (diffMins < 60) return `${diffMins}m ago`
    // Same day: show time
    if (d.toDateString() === now.toDateString()) {
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
    // Different day: show date + time
    return d.toLocaleDateString([], { day: '2-digit', month: 'short' }) + ' ' +
      d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  } catch { return '' }
}

const riskDot: Record<string, string> = {
  critical: 'bg-[#f87171]',
  high:     'bg-[#fb923c]',
  medium:   'bg-[#a1a1aa]',
  low:      'bg-[#52525b]',
}
const riskLabel: Record<string, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low',
}

export default function ThreatFeed() {
  const { lang } = useLang()
  const router = useRouter()
  const [events, setEvents] = useState<ThreatFeedEvent[]>([])
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const fetchRecent = async () => {
    try {
      const res = await api.get('/api/dashboard/threats/recent')
      if (Array.isArray(res.data)) {
        setEvents(res.data.slice(0, 10))
        setLastUpdated(new Date())
      }
    } catch {}
  }

  useEffect(() => {
    fetchRecent()
    pollRef.current = setInterval(fetchRecent, 30000)
    return () => { if (pollRef.current) clearInterval(pollRef.current) }
  }, [])

  return (
    <div className="bg-[#141417] border border-white/[0.07] rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/[0.06]">
        <div className="flex items-center gap-2">
          <span className="text-[13px] font-semibold text-[#e4e4e7]">{t(lang, 'liveThreats')}</span>
          {lastUpdated && (
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold bg-red-500/10 border border-red-500/20 text-red-400">
              <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
              Live
            </span>
          )}
        </div>
        <button
          onClick={() => router.push('/threats')}
          className="flex items-center gap-1 text-[10px] text-[#3b6ef6] hover:text-blue-300 transition-colors"
        >
          View All <ArrowRight size={10} />
        </button>
      </div>
      <div>
        {events.length === 0 ? (
          <div className="text-[13px] text-[#52525b] text-center py-10">
            {t(lang, 'noThreats')}
          </div>
        ) : events.map((ev, i) => (
          <div key={ev.id ?? i} className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02] transition-colors">
            <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${riskDot[ev.severity] ?? 'bg-[#52525b]'}`} />
            <div className="min-w-0 flex-1">
              <div className="text-[12px] font-medium text-[#d4d4d8] truncate">{ev.type ?? 'Unknown'}</div>
              <div className="text-[11px] text-[#52525b] truncate mt-0.5">{ev.sender_domain} → {ev.recipient}</div>
            </div>
            <div className="flex-shrink-0 text-right ml-1">
              <div className="text-[11px] text-[#71717a]">{riskLabel[ev.severity] ?? ev.severity}</div>
              <div className="text-[10px] text-[#3f3f46]">
                {fmtTimestamp(ev.received_at)}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
