import { type Finding } from '../api/client'
import { SeverityBadge } from './Badges'

export function EvidenceTree({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return <p className="text-sm text-[var(--text-secondary)]">No evidence recorded</p>
  }

  return (
    <div className="space-y-2">
      {findings.map((finding, i) => (
        <div key={i} className="bg-[var(--bg-primary)] rounded p-3">
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs font-mono text-[var(--accent)]">
              {finding.detector_id}
            </span>
          </div>
          <p className="text-sm">{finding.description}</p>
          {finding.matched_value && (
            <pre className="mt-2 text-xs font-mono bg-[var(--bg-tertiary)] p-2 rounded overflow-x-auto max-h-20">
              {finding.matched_value.slice(0, 500)}
            </pre>
          )}
          {finding.class_name && (
            <div className="mt-1 text-xs text-[var(--text-secondary)]">
              {finding.class_name}.{finding.method_name}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
