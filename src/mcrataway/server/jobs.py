"""Job registry — tracks scan jobs and manages WebSocket subscribers."""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from mcrataway.constants import JobStatus

# Maximum number of completed/failed jobs to retain
_MAX_COMPLETED_JOBS = 50

# Maximum number of events to buffer per job for late-subscriber replay.
# Without a cap, a 100k-file scan would buffer 100k+ events in memory
# alongside the job's findings list. The tail is kept so recent
# subscribers still get a meaningful replay of the final state.
_MAX_EVENT_LOG_PER_JOB = 500


@dataclass
class ScanJob:
    """A single scan job."""

    job_id: str
    status: JobStatus = JobStatus.PENDING
    progress: float = 0.0
    total_files: int = 0
    scanned_files: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    verdicts: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    roots: list[str] = field(default_factory=list)
    event_log: list[dict[str, Any]] = field(default_factory=list)


class JobRegistry:
    """Manages scan jobs and WebSocket subscribers."""

    def __init__(self) -> None:
        self.jobs: dict[str, ScanJob] = {}
        self.subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def create_job(self, roots: list[str]) -> str:
        """Create a new scan job and return its ID."""
        job_id = str(uuid.uuid4())
        self.jobs[job_id] = ScanJob(
            job_id=job_id,
            status=JobStatus.PENDING,
            roots=roots,
            started_at=datetime.now(UTC).isoformat(),
        )
        self.subscribers[job_id] = []
        return job_id

    def track_task(self, job_id: str, task: asyncio.Task[None]) -> None:
        """Track a background scan task to prevent garbage collection."""
        self._tasks[job_id] = task

        def _cleanup(_t: asyncio.Task[None], jid: str = job_id) -> None:
            self._tasks.pop(jid, None)

        task.add_done_callback(_cleanup)

    def get_job(self, job_id: str) -> ScanJob | None:
        return self.jobs.get(job_id)

    def list_jobs(self) -> list[ScanJob]:
        return list(self.jobs.values())

    def update_status(self, job_id: str, status: JobStatus, error: str | None = None) -> None:
        job = self.jobs.get(job_id)
        if job:
            job.status = status
            if error:
                job.error = error
            if status in (JobStatus.COMPLETED, JobStatus.FAILED):
                # Record completion time for both terminal states so
                # _cleanup_old_jobs sorts them correctly instead of
                # dropping FAILED jobs first (their completed_at was
                # previously None, which sorted before any timestamp).
                job.completed_at = datetime.now(UTC).isoformat()
            self._emit(job_id, {"type": "status", "status": status.value, "error": error})
            # Clean up old completed/failed jobs to bound memory
            if status in (JobStatus.COMPLETED, JobStatus.FAILED):
                self._cleanup_old_jobs()

    def update_progress(self, job_id: str, progress: float, scanned: int, total: int) -> None:
        job = self.jobs.get(job_id)
        if job:
            job.progress = progress
            job.scanned_files = scanned
            job.total_files = total
            self._emit(job_id, {
                "type": "progress",
                "progress": progress,
                "scanned": scanned,
                "total": total,
            })

    def add_finding(self, job_id: str, finding: dict[str, Any]) -> None:
        job = self.jobs.get(job_id)
        if job:
            job.findings.append(finding)
            self._emit(job_id, {"type": "finding", "finding": finding})

    def add_verdict(self, job_id: str, verdict: dict[str, Any]) -> None:
        job = self.jobs.get(job_id)
        if job:
            job.verdicts.append(verdict)
            self._emit(job_id, {"type": "verdict", "verdict": verdict})

    def emit_done(self, job_id: str) -> None:
        """Signal subscribers that the job is finished."""
        self._emit(job_id, {"type": "done"})

    async def subscribe(self, job_id: str) -> asyncio.Queue[dict[str, Any]]:
        """Subscribe to job events. Returns a queue.

        Late subscribers receive a replay of all buffered events before
        live events continue. Non-existent jobs receive a terminal
        ``done`` event so the WebSocket does not hang.
        """
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        if job_id in self.subscribers:
            # Replay buffered events FIRST, using put_nowait so no event
            # loop yield allows a concurrent _emit to interleave live
            # events ahead of the historical ones. The queue is still
            # empty and not yet registered as a subscriber, so no live
            # event can reach it during the replay.
            job = self.jobs.get(job_id)
            if job:
                for event in job.event_log:
                    queue.put_nowait(event)
            # Only now register for live events — they will be appended
            # strictly after the replayed history.
            self.subscribers[job_id].append(queue)
        else:
            # Non-existent job — send a terminal event immediately
            await queue.put({"type": "done", "error": "Job not found"})
        return queue

    def unsubscribe(self, job_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        """Remove a subscriber queue when its WebSocket disconnects."""
        subs = self.subscribers.get(job_id)
        if subs and queue in subs:
            subs.remove(queue)

    def _emit(self, job_id: str, event: dict[str, Any]) -> None:
        """Emit an event to all subscribers and buffer it for late joiners.

        The per-job event log is capped at :data:`_MAX_EVENT_LOG_PER_JOB`
        entries (keeping the most recent) so a large scan cannot grow
        the buffer unbounded alongside the job's findings list.
        """
        if job_id in self.subscribers:
            for queue in self.subscribers[job_id]:
                queue.put_nowait(event)
        job = self.jobs.get(job_id)
        if job:
            job.event_log.append(event)
            if len(job.event_log) > _MAX_EVENT_LOG_PER_JOB:
                # Drop the oldest events to bound memory.
                del job.event_log[: len(job.event_log) - _MAX_EVENT_LOG_PER_JOB]

    async def shutdown(self) -> None:
        """Close all subscriber queues."""
        for queues in self.subscribers.values():
            for queue in queues:
                await queue.put({"type": "done"})

    def _cleanup_old_jobs(self) -> None:
        """Remove old completed/failed jobs to bound memory usage."""
        finished = [
            (jid, job)
            for jid, job in self.jobs.items()
            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED)
        ]
        if len(finished) <= _MAX_COMPLETED_JOBS:
            return
        # Sort by completion time (oldest first), keep the most recent.
        # Fall back to started_at for jobs that never set completed_at.
        finished.sort(key=lambda item: item[1].completed_at or item[1].started_at or "")
        to_remove = finished[: len(finished) - _MAX_COMPLETED_JOBS]
        for jid, _ in to_remove:
            self.jobs.pop(jid, None)
            self.subscribers.pop(jid, None)
            self._tasks.pop(jid, None)
