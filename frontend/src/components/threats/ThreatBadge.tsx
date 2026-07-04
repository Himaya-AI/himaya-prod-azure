import { Badge } from '@/components/ui/Badge'

type Severity = 'critical' | 'high' | 'medium' | 'low'
type Status = 'new' | 'quarantined' | 'released' | 'false_positive' | 'investigating'

export function SeverityBadge({ severity }: { severity: Severity }) {
  const map: Record<Severity, 'danger' | 'warning' | 'info' | 'neutral'> = {
    critical: 'danger',
    high: 'warning',
    medium: 'info',
    low: 'neutral',
  }
  return <Badge variant={map[severity]}>{severity.toUpperCase()}</Badge>
}

export function StatusBadge({ status }: { status: Status }) {
  const map: Record<Status, 'danger' | 'warning' | 'success' | 'neutral' | 'info'> = {
    new: 'danger',
    quarantined: 'warning',
    released: 'success',
    false_positive: 'neutral',
    investigating: 'info',
  }
  const label: Record<Status, string> = {
    new: 'New',
    quarantined: 'Quarantined',
    released: 'Released',
    false_positive: 'False Positive',
    investigating: 'Investigating',
  }
  return <Badge variant={map[status]}>{label[status]}</Badge>
}

export function TypeBadge({ type }: { type: string }) {
  return (
    <Badge variant="info" className="font-mono text-xs">
      {type.replace(/_/g, ' ')}
    </Badge>
  )
}
