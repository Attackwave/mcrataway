import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getQuarantined, restoreQuarantined } from '../api/client'

export default function QuarantinePage() {
  const queryClient = useQueryClient()

  const { data: items, isLoading } = useQuery({
    queryKey: ['quarantine'],
    queryFn: getQuarantined,
  })

  const restoreMutation = useMutation({
    mutationFn: (sha256: string) => restoreQuarantined(sha256),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['quarantine'] })
    },
  })

  if (isLoading) {
    return <div className="text-[var(--text-secondary)]">Loading quarantine...</div>
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Quarantine</h2>

      <div className="text-sm text-[var(--text-secondary)]">
        {items?.length ?? 0} quarantined item(s)
      </div>

      <div className="space-y-2">
        {items?.map((item) => (
          <div
            key={item.sha256}
            className="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-lg p-4"
          >
            <div className="flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <p className="font-mono text-sm truncate">{item.original_path}</p>
                <p className="text-xs text-[var(--text-secondary)] mt-1">
                  SHA-256: {item.sha256}
                </p>
                <p className="text-xs text-[var(--text-secondary)]">
                  Verdict: {item.verdict} | {new Date(item.timestamp).toLocaleString()}
                </p>
                {item.restored && (
                  <span className="text-xs text-[var(--success)] mt-1 inline-block">
                    Restored
                  </span>
                )}
              </div>

              {!item.restored && (
                <button
                  onClick={() => restoreMutation.mutate(item.sha256)}
                  disabled={restoreMutation.isPending}
                  className="ml-4 px-3 py-1.5 bg-[var(--bg-tertiary)] hover:bg-[var(--border-color)] rounded text-sm transition-colors disabled:opacity-50"
                >
                  Restore
                </button>
              )}
            </div>
          </div>
        ))}

        {items?.length === 0 && (
          <div className="text-center py-12 text-[var(--text-secondary)]">
            No quarantined items
          </div>
        )}
      </div>
    </div>
  )
}
