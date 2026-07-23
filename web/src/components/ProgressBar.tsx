export function ProgressBar({ progress, scanned, total }: { progress: number; scanned: number; total: number }) {
  return (
    <div className="mt-4">
      <div className="flex items-center justify-between text-sm mb-1">
        <span className="text-[var(--text-secondary)]">
          Progress: <span className="text-[var(--text-primary)]">{Math.round(progress)}%</span>
        </span>
        <span className="text-[var(--text-secondary)]">
          {scanned} / {total} files
        </span>
      </div>
      <div className="h-1.5 bg-[var(--bg-tertiary)] rounded-full overflow-hidden">
        <div
          className="h-full bg-[var(--accent)] rounded-full transition-all duration-300"
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        />
      </div>
    </div>
  )
}
