'use client'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { Table, Thead, Tbody, Tr, Th, Td } from '@/components/ui/Table'
import { SeverityBadge, StatusBadge, TypeBadge } from './ThreatBadge'
import Button from '@/components/ui/Button'
import type { Threat } from '@/lib/types'
import { format } from 'date-fns'
import { Eye } from 'lucide-react'
import api from '@/lib/api'

interface Props {
  threats: Threat[]
  selected: string[]
  onSelect: (id: string) => void
  onSelectAll: () => void
  loading?: boolean
}

export default function ThreatTable({ threats, selected, onSelect, onSelectAll, loading, onStatusChange }: Props & { onStatusChange?: (id: string, status: string) => void }) {
  const router = useRouter()
  const [updatingStatus, setUpdatingStatus] = useState<string | null>(null)

  const changeStatus = async (id: string, status: string, e: React.MouseEvent) => {
    e.stopPropagation()
    setUpdatingStatus(id)
    try {
      await api.patch(`/api/threats/${id}/status`, { status })
      onStatusChange?.(id, status)
    } catch {}
    setUpdatingStatus(null)
  }

  if (loading) {
    return (
      <div className="space-y-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-12 animate-pulse bg-[#0f3460]/20 rounded" />
        ))}
      </div>
    )
  }

  return (
    <Table>
      <Thead>
        <Tr>
          <Th className="w-10">
            <input
              type="checkbox"
              className="rounded border-[#0f3460] bg-transparent"
              checked={selected.length === threats.length && threats.length > 0}
              onChange={onSelectAll}
            />
          </Th>
          <Th>Severity</Th>
          <Th>Type</Th>
          <Th>Recipient</Th>
          <Th>Sender Domain</Th>
          <Th>Time</Th>
          <Th>Status</Th>
          <Th>Actions</Th>
        </Tr>
      </Thead>
      <Tbody>
        {threats.map(t => (
          <Tr key={t.id} className="cursor-pointer" onClick={() => router.push(`/threats/${t.id}`)}>
            <Td onClick={e => e.stopPropagation()}>
              <input
                type="checkbox"
                className="rounded border-[#0f3460] bg-transparent"
                checked={selected.includes(t.id)}
                onChange={() => onSelect(t.id)}
              />
            </Td>
            <Td><SeverityBadge severity={t.severity} /></Td>
            <Td><TypeBadge type={t.type} /></Td>
            <Td className="max-w-[160px] truncate text-xs">{t.recipient}</Td>
            <Td className="text-xs">{t.sender_domain}</Td>
            <Td className="text-xs text-slate-500 whitespace-nowrap">
              {t.received_at ? (
                <span className="flex flex-col gap-0.5">
                  <span className="text-slate-300">{format(new Date(t.received_at), 'MMM d, yyyy')}</span>
                  <span className="text-slate-500">{format(new Date(t.received_at), 'HH:mm')}</span>
                </span>
              ) : '-'}
            </Td>
            <Td onClick={e => e.stopPropagation()}>
              <select
                value={t.status || 'new'}
                onChange={e => changeStatus(t.id, e.target.value, e as any)}
                disabled={updatingStatus === t.id}
                className="bg-[#0f1923] text-[11px] border border-[#0f3460] rounded px-1.5 py-0.5 text-slate-300 cursor-pointer focus:outline-none hover:border-[#3b6ef6]/50"
                title="Change investigation status"
              >
                <option value="new">New</option>
                <option value="investigating">Investigating</option>
                <option value="resolved">Resolved</option>
                <option value="closed">Closed</option>
              </select>
            </Td>
            <Td onClick={e => e.stopPropagation()}>
              <Button size="sm" variant="ghost" onClick={() => router.push(`/threats/${t.id}`)}>
                <Eye size={13} />
              </Button>
            </Td>
          </Tr>
        ))}
        {threats.length === 0 && (
          <Tr>
            <Td colSpan={8} className="text-center text-slate-500 py-10">No threats found</Td>
          </Tr>
        )}
      </Tbody>
    </Table>
  )
}
