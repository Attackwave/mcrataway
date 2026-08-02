"""Tests for the concurrent scan-job cap (server/jobs.py _MAX_RUNNING_JOBS).

Each running scan job spawns up to ``config.max_workers`` threads and
holds in-memory archive state. Without a cap, an authenticated caller
(or a stuck UI that re-POSTs, or a misconfigured automation) can
exhaust the host by starting unbounded concurrent scans. The cap
rejects new jobs while running jobs are at the limit; the scan route
translates that into HTTP 429.
"""

from mcrataway.constants import JobStatus
from mcrataway.server.jobs import _MAX_RUNNING_JOBS, JobRegistry


def test_create_job_rejected_when_running_cap_hit():
    """Starting more than _MAX_RUNNING_JOBS concurrent jobs must return
    None (which the scan route translates to 429), not create unbounded
    jobs."""
    registry = JobRegistry()
    created = []
    for _ in range(_MAX_RUNNING_JOBS):
        jid = registry.create_job(roots=["/tmp"])
        assert jid is not None
        created.append(jid)

    # One over the cap — must be rejected.
    overflow = registry.create_job(roots=["/tmp"])
    assert overflow is None


def test_job_accepted_after_running_one_completes():
    """A completed job frees its slot — a new job must then be accepted."""
    registry = JobRegistry()
    jid = registry.create_job(roots=["/tmp"])
    assert jid is not None
    registry.update_status(jid, JobStatus.COMPLETED)

    # Slot is freed now.
    jid2 = registry.create_job(roots=["/tmp"])
    assert jid2 is not None


def test_job_accepted_after_running_one_fails():
    """A failed job also frees its slot."""
    registry = JobRegistry()
    jid = registry.create_job(roots=["/tmp"])
    assert jid is not None
    registry.update_status(jid, JobStatus.FAILED, error="boom")

    jid2 = registry.create_job(roots=["/tmp"])
    assert jid2 is not None
