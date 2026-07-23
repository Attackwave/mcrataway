import { useState, useCallback, useRef, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getRoots, startScan, getJob, connectJobStream, type ScanJob, type Verdict, verdictBadge, severityColor } from '../api/client'

export default function ScanPage() {
  const { data: roots, isLoading: loadingRoots } = useQuery({
    queryKey: ['roots'],
    queryFn: getRoots,
  })

  const [job, setJob] = useState<ScanJob | null>(null)
  const [findings, setFindings] = useState<Verdict[]>([])
  const wsRef = useRef<WebSocket | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Cleanup WebSocket and poll on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
      if (wsRef.current) {
        wsRef.current.onmessage = null
        wsRef.current.onerror = null
        wsRef.current.onclose = null
        if (wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.close()
        }
        wsRef.current = null
      }
    }
  }, [])

  const handleStartScan = useCallback(async () => {
    const result = await startScan()
    const newJob: ScanJob = {
      job_id: result.job_id,
      status: 'PENDING',
      progress: 0,
      total_files: 0,
      scanned_files: 0,
      error: null,
    }
    setJob(newJob)
    setFindings([])

    const ws = connectJobStream(result.job_id)
    wsRef.current = ws

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === 'progress') {
        setJob((prev) =>
          prev
            ? {
                ...prev,
                status: 'RUNNING',
                progress: data.progress ?? 0,
                scanned_files: data.scanned ?? 0,
                total_files: data.total ?? 0,
              }
            : null,
        )
      } else if (data.type === 'finding') {
        // 'finding' events carry every scanned file (CLEAN included).
        // Avoid double-counting if already added via a 'verdict' event.
        setFindings((prev) => {
          const exists = prev.some(
            (f) => f.file_path === data.finding.file_path,
          )
          return exists ? prev : [...prev, data.finding]
        })
      } else if (data.type === 'verdict') {
        // 'verdict' events are a subset (MALICIOUS/SUSPICIOUS only).
        setFindings((prev) => {
          const exists = prev.some(
            (f) => f.file_path === data.verdict.file_path,
          )
          return exists ? prev : [...prev, data.verdict]
        })
      } else if (data.type === 'status') {
        setJob((prev) =>
          prev ? { ...prev, status: data.status, error: data.error ?? null } : null,
        )
        if (data.status === 'COMPLETED' || data.status === 'FAILED') {
          ws.close()
        }
      }
    }

    ws.onerror = () => {
      setJob((prev) =>
        prev ? { ...prev, status: 'FAILED', error: 'WebSocket connection lost' } : null,
      )
    }

    // Fallback polling
    const poll = setInterval(async () => {
      try {
        const status = await getJob(result.job_id)
        setJob(status)
        if (status.status === 'COMPLETED' || status.status === 'FAILED') {
          clearInterval(poll)
          pollRef.current = null
          ws.close()
        }
      } catch {
        // ignore
      }
    }, 2000)
    pollRef.current = poll

    ws.onclose = () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }
  }, [])

  const isRunning = job?.status === 'PENDING' || job?.status === 'RUNNING'
  const progress = job?.progress ?? 0
  const totalCount = findings.length
  const maliciousCount = findings.filter((f) => f.verdict === 'MALICIOUS').length
  const suspiciousCount = findings.filter((f) => f.verdict === 'SUSPICIOUS').length

  return (
    <div className="space-y-6">
      <section className="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Scan</h2>

        <div className="mb-4">
          <h3 className="text-sm text-[var(--text-secondary)] mb-1">Discovered roots</h3>
          {loadingRoots ? (
            <p className="text-sm text-[var(--text-secondary)]">Loading...</p>
          ) : roots && roots.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {roots.map((root) => (
                <span
                  key={root}
                  className="px-2 py-1 bg-[var(--bg-tertiary)] rounded text-xs font-mono"
                >
                  {root}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-sm text-[var(--text-secondary)]">No Minecraft roots found</p>
          )}
        </div>

        <button
          onClick={handleStartScan}
          disabled={isRunning}
          className={`px-4 py-2 rounded-md font-medium transition-colors ${
            isRunning
              ? 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)] cursor-not-allowed'
              : 'bg-[var(--success)] text-white hover:bg-green-600'
          }`}
        >
          {isRunning ? 'Scanning...' : 'Start Scan'}
        </button>

        {job && (
          <div className="mt-4">
            <div className="flex items-center justify-between text-sm mb-1">
              <span className="text-[var(--text-secondary)]">
                Status: <span className="text-[var(--text-primary)]">{job.status}</span>
              </span>
              <span className="text-[var(--text-secondary)]">
                {job.scanned_files} / {job.total_files} files
              </span>
            </div>
            <div className="h-1.5 bg-[var(--bg-tertiary)] rounded-full overflow-hidden">
              <div
                className="h-full bg-[var(--accent)] rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            {job.error && (
              <p className="text-sm text-[var(--danger)] mt-2">{job.error}</p>
            )}
          </div>
        )}
      </section>

      {totalCount > 0 && (
        <section className="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Live Results</h2>

          <div className="grid grid-cols-4 gap-4 mb-6">
            <div className="bg-[var(--bg-primary)] rounded-lg p-4 text-center">
              <div className="text-2xl font-bold">{totalCount}</div>
              <div className="text-sm text-[var(--text-secondary)]">Total</div>
            </div>
            <div className="bg-[var(--bg-primary)] rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-[var(--danger)]">{maliciousCount}</div>
              <div className="text-sm text-[var(--text-secondary)]">Malicious</div>
            </div>
            <div className="bg-[var(--bg-primary)] rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-[var(--warning)]">{suspiciousCount}</div>
              <div className="text-sm text-[var(--text-secondary)]">Suspicious</div>
            </div>
            <div className="bg-[var(--bg-primary)] rounded-lg p-4 text-center">
              <div className="text-2xl font-bold text-[var(--success)]">
                {totalCount - maliciousCount - suspiciousCount}
              </div>
              <div className="text-sm text-[var(--text-secondary)]">Clean</div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border-color)]">
                  <th className="text-left py-2 px-3 text-[var(--text-secondary)] font-medium">File</th>
                  <th className="text-left py-2 px-3 text-[var(--text-secondary)] font-medium">Verdict</th>
                  <th className="text-left py-2 px-3 text-[var(--text-secondary)] font-medium">Confidence</th>
                  <th className="text-left py-2 px-3 text-[var(--text-secondary)] font-medium">Findings</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => (
                  <tr
                    key={i}
                    className="border-b border-[var(--border-color)] hover:bg-[var(--bg-tertiary)]"
                  >
                    <td className="py-2 px-3 font-mono text-xs">
                      {f.file_path.split(/[/\\]/).pop()}
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${verdictBadge(f.verdict)}`}>
                        {f.verdict}
                      </span>
                    </td>
                    <td className="py-2 px-3">{(f.confidence * 100).toFixed(0)}%</td>
                    <td className="py-2 px-3">
                      <div className="flex flex-wrap gap-1">
                        {f.findings.slice(0, 3).map((finding, j) => (
                          <span key={j} className={`text-xs px-1.5 py-0.5 rounded ${severityColor(finding.severity)}`}>
                            {finding.detector_id}
                          </span>
                        ))}
                        {f.findings.length > 3 && (
                          <span className="text-xs text-[var(--text-secondary)]">
                            +{f.findings.length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
