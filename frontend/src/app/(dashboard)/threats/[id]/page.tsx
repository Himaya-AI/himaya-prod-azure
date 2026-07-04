'use client'
import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import ThreatDetail from '@/components/threats/ThreatDetail'
import Button from '@/components/ui/Button'
import { ChevronLeft } from 'lucide-react'
import api from '@/lib/api'
import type { Threat } from '@/lib/types'

export default function ThreatDetailPage() {
  const { id } = useParams<{ id: string }>()
  const router = useRouter()
  const [threat, setThreat] = useState<Threat | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get<Threat>(`/api/threats/${id}`)
      .then(r => setThreat(r.data))
      .catch(() => setError('Threat not found'))
      .finally(() => setLoading(false))
  }, [id])

  return (
    <div className="space-y-5">
      <Button variant="ghost" size="sm" onClick={() => router.back()}>
        <ChevronLeft size={15} /> Back to Threats
      </Button>

      {loading && (
        <div className="space-y-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 animate-pulse bg-[#16213e] rounded-xl border border-[#0f3460]/30" />
          ))}
        </div>
      )}
      {error && <div className="text-center text-red-400 py-20 text-sm">{error}</div>}
      {threat && <ThreatDetail threat={threat} />}
    </div>
  )
}
