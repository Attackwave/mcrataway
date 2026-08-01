import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { deleteHistoryEntry, getHistory, getHistoryReport } from '../api/client'
import { FindingTable } from '../components/FindingTable'

export default function HistoryPage() {
  const queryClient = useQueryClient()
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null)

  const { data: entries, isLoading } = useQuery({
    queryKey: ['history'],
    queryFn: getHistory,
  })

  const { data: report, isLoading: isReportLoading } = useQuery({
    queryKey: ['history', selectedScanId],
    queryFn: () => getHistoryReport(selectedScanId!),
    enabled: selectedScanId !== null,
  })

  const deleteMutation = useMutation({
    mutationFn: (scanId: string) => deleteHistoryEntry(scanId),
    onSuccess: (_data, scanId) => {
      queryClient.invalidateQueries({ queryKey: ['history'] })
      if (selectedScanId === scanId) {
        setSelectedScanId(null)
      }
    },
  })

  if (isLoading) {
    return <div className="text-[var(--text-secondary)]">Loading history...</div>
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">History</h2>

      <div className="text-sm text-[var(--text-secondary)]">
        {entries?.length ?? 0} past scan(s) — the most recent {' '}
        {entries?.length ?? 0} are kept, older scans are dropped automatically.
      </div>

      <div className="space-y-2">
        {entries?.map((entry) => {
          const isSelected = selectedScanId === entry.scan_id
          return (
            <div
              key={entry.scan_id}
              className="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-lg p-4"
            >
              <div className="flex items-center justify-between">
                <button
                  onClick={() => setSelectedScanId(isSelected ? null : entry.scan_id)}
                  className="flex-1 min-w-0 text-left"
                >
                  <p className="text-sm">
                    {new Date(entry.timestamp).toLocaleString()}
                  </p>
                  <p className="font-mono text-xs text-[var(--text-secondary)] truncate mt-1">
                    {entry.roots.join(', ') || 'No roots'}
                  </p>
                  <p className="text-xs mt-1">
                    <span className="text-[var(--danger)]">{entry.summary.malicious} malicious</span>
                    {' · '}
                    <span className="text-[var(--warning)]">{entry.summary.suspicious} suspicious</span>
                    {' · '}
                    <span className="text-[var(--success)]">{entry.summary.clean} clean</span>
                    {' · '}
                    {entry.summary.total_files} total
                  </p>
                </button>

                <button
                  onClick={() => deleteMutation.mutate(entry.scan_id)}
                  disabled={deleteMutation.isPending}
                  className="ml-4 px-3 py-1.5 bg-[var(--bg-tertiary)] hover:bg-[var(--border-color)] rounded text-sm transition-colors disabled:opacity-50"
                >
                  Delete
                </button>
              </div>

              {isSelected && (
                <div className="border-t border-[var(--border-color)] mt-4 pt-4">
                  {isReportLoading && (
                    <p className="text-sm text-[var(--text-secondary)]">Loading report...</p>
                  )}
                  {report && 'error' in report && (
                    <p className="text-sm text-[var(--text-secondary)]">{report.error}</p>
                  )}
                  {report && !('error' in report) && (
                    <FindingTable findings={report.files} />
                  )}
                </div>
              )}
            </div>
          )
        })}

        {entries?.length === 0 && (
          <div className="text-center py-12 text-[var(--text-secondary)]">
            No past scans yet — results appear here automatically after a scan completes.
          </div>
        )}
      </div>
    </div>
  )
}
