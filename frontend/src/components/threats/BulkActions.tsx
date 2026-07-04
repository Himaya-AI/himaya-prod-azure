'use client'
import Button from '@/components/ui/Button'
import { Shield, CheckCircle, XCircle, X } from 'lucide-react'

interface Props {
  count: number
  onQuarantine: () => void
  onRelease: () => void
  onFalsePositive: () => void
  onClear: () => void
}

export default function BulkActions({ count, onQuarantine, onRelease, onFalsePositive, onClear }: Props) {
  if (count === 0) return null
  return (
    <div className="flex items-center gap-3 px-4 py-3 bg-[#0f3460]/40 border border-[#0f3460]/50 rounded-lg">
      <span className="text-sm text-slate-300 font-medium">{count} selected</span>
      <div className="h-4 w-px bg-[#0f3460]" />
      <Button size="sm" variant="secondary" onClick={onQuarantine}>
        <Shield size={13} /> Quarantine
      </Button>
      <Button size="sm" variant="ghost" onClick={onRelease}>
        <CheckCircle size={13} /> Release
      </Button>
      <Button size="sm" variant="ghost" onClick={onFalsePositive}>
        <XCircle size={13} /> False Positive
      </Button>
      <button onClick={onClear} className="ml-auto text-slate-500 hover:text-white transition-colors">
        <X size={16} />
      </button>
    </div>
  )
}
