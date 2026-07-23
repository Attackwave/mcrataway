import { useState } from 'react'
import { type Verdict } from '../api/client'
import { VerdictBadge, ConfidenceMeter } from './Badges'
import { EvidenceTree } from './EvidenceTree'

interface FindingTableProps {
  findings: Verdict[]
}

export function FindingTable({ findings }: FindingTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null)

  if (findings.length === 0) {
    return <p className="text-sm text-[var(--text-secondary)]">No findings to display</p>
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[var(--border-color)]">
            <th className="text-left py-2 px-3 text-[var(--text-secondary)] font-medium">File</th>
            <th className="text-left py-2 px-3 text-[var(--text-secondary)] font-medium">Verdict</th>
            <th className="text-left py-2 px-3 text-[var(--text-secondary)] font-medium">Confidence</th>
            <th className="text-left py-2 px-3 text-[var(--text-secondary)] font-medium">Indicators</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => {
            const id = `${f.file_path}-${i}`
            const isExpanded = expandedId === id
            return (
              <tr key={id} className="border-b border-[var(--border-color)]">
                <td colSpan={4} className="p-0">
                  <button
                    onClick={() => setExpandedId(isExpanded ? null : id)}
                    className="w-full flex items-center justify-between p-3 hover:bg-[var(--bg-tertiary)] transition-colors"
                  >
                    <div className="flex items-center gap-3 text-left">
                      <VerdictBadge verdict={f.verdict} />
                      <span className="font-mono text-sm">
                        {f.file_path.split(/[/\\]/).pop()}
                      </span>
                      <ConfidenceMeter confidence={f.confidence} />
                    </div>
                    <span className="text-[var(--text-secondary)] text-sm">
                      {f.findings.length} {isExpanded ? '▲' : '▼'}
                    </span>
                  </button>
                  {isExpanded && (
                    <div className="border-t border-[var(--border-color)] p-4 bg-[var(--bg-secondary)]">
                      <div className="text-xs text-[var(--text-secondary)] mb-2">
                        SHA-256: {f.sha256}
                      </div>
                      <EvidenceTree findings={f.findings} />
                    </div>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
