import { severityColor, verdictBadge } from '../api/client'

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${severityColor(severity)}`}>
      {severity}
    </span>
  )
}

export function VerdictBadge({ verdict }: { verdict: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${verdictBadge(verdict)}`}>
      {verdict}
    </span>
  )
}

export function ConfidenceMeter({ confidence }: { confidence: number }) {
  const pct = Math.round(confidence * 100)
  const color = confidence >= 0.8 ? 'text-[var(--danger)]' : confidence >= 0.5 ? 'text-[var(--warning)]' : 'text-[var(--success)]'
  return <span className={color}>{pct}%</span>
}
