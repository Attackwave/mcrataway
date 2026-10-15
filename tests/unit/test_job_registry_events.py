"""Tests for the job registry's event delivery and history persistence.

Two ways a scan's event handling could hurt the server it runs in:

- a subscriber queue per WebSocket had no bound, so a tab that stopped
  draining accumulated the rest of the scan's stream in memory;
- completing a job wrote its (potentially multi-megabyte) report to disk
  inline on the event loop, freezing every other request and the whole
  WebSocket feed for the duration of the write.
"""

import threading
from typing import Any

from mcrataway.constants import JobStatus
from mcrataway.server.jobs import _MAX_SUBSCRIBER_BACKLOG, JobRegistry


class _RecordingHistory:
    """Stands in for HistoryStore, recording which thread the write ran on."""

    def __init__(self) -> None:
        self.jobs: list[Any] = []
        self.threads: list[int] = []

    def record(self, job: Any) -> None:
        self.jobs.append(job)
        self.threads.append(threading.get_ident())


async def test_a_slow_subscriber_cannot_grow_its_queue_without_bound() -> None:
    registry = JobRegistry()
    job_id = registry.create_job(roots=["/tmp"])
    assert job_id is not None
    queue = await registry.subscribe(job_id)

    overflow = _MAX_SUBSCRIBER_BACKLOG * 3
    for n in range(overflow):
        registry.add_finding(job_id, {"n": n})

    assert queue.qsize() <= _MAX_SUBSCRIBER_BACKLOG
    drained = []
    while not queue.empty():
        drained.append(queue.get_nowait())
    # The newest event is the one a catching-up subscriber needs; the
    # oldest are what gets dropped.
    assert drained[-1]["finding"] == {"n": overflow - 1}


async def test_terminal_event_reaches_a_subscriber_that_fell_behind() -> None:
    """Whatever is dropped, the ``done`` event must not be: a subscriber
    that misses it would keep a dead WebSocket open forever."""
    registry = JobRegistry()
    job_id = registry.create_job(roots=["/tmp"])
    assert job_id is not None
    queue = await registry.subscribe(job_id)
    for n in range(_MAX_SUBSCRIBER_BACKLOG * 2):
        registry.add_finding(job_id, {"n": n})

    registry.emit_done(job_id)

    drained = []
    while not queue.empty():
        drained.append(queue.get_nowait())
    assert drained[-1] == {"type": "done"}


async def test_completing_a_job_records_history_off_the_event_loop() -> None:
    """The report write must not run on the loop thread, and must have
    finished by the time the job reads as COMPLETED — otherwise History
    can serve a scan that just finished as missing."""
    history = _RecordingHistory()
    registry = JobRegistry(history=history)  # type: ignore[arg-type]
    job_id = registry.create_job(roots=["/tmp"])
    assert job_id is not None
    loop_thread = threading.get_ident()

    await registry.update_status(job_id, JobStatus.COMPLETED)

    assert [job.job_id for job in history.jobs] == [job_id]
    assert history.threads[0] != loop_thread
