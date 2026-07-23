import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getFindings } from '../api/client'
import { FindingTable } from '../components/FindingTable'

export default function FindingsPage() {
  const [filterSeverity, setFilterSeverity] = useState<string>('')
  const [searchTerm, setSearchTerm] = useState('')

  const { data: findings, isLoading } = useQuery({
    queryKey: ['findings', filterSeverity],
    queryFn: () => getFindings(filterSeverity || undefined),
  })

  const filtered = findings?.filter((f) => {
    if (!searchTerm) return true
    const term = searchTerm.toLowerCase()
    return (
      f.file_path.toLowerCase().includes(term) ||
      f.findings.some(
        (finding) =>
          finding.description.toLowerCase().includes(term) ||
          finding.detector_id.toLowerCase().includes(term),
      )
    )
  })

  if (isLoading) {
    return <div className="text-[var(--text-secondary)]">Loading findings...</div>
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-3">
        <select
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
          className="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded px-3 py-2 text-sm"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <input
          type="text"
          placeholder="Search files, detectors, descriptions..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="flex-1 bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded px-3 py-2 text-sm placeholder:text-[var(--text-secondary)]"
        />
      </div>

      <div className="text-sm text-[var(--text-secondary)]">
        {filtered?.length ?? 0} finding(s)
      </div>

      {filtered && filtered.length > 0 ? (
        <FindingTable findings={filtered} />
      ) : (
        <div className="text-center py-12 text-[var(--text-secondary)]">
          No findings match your criteria
        </div>
      )}
    </div>
  )
}
