"""Unit tests for the scan history store (server/history.py)."""

from pathlib import Path

from mcrataway.constants import JobStatus
from mcrataway.server.history import HistoryStore, build_scan_report_from_job
from mcrataway.server.jobs import ScanJob


def _make_job(
    job_id: str,
    started_at: str,
    findings: list[dict] | None = None,
) -> ScanJob:
    return ScanJob(
        job_id=job_id,
        status=JobStatus.COMPLETED,
        started_at=started_at,
        completed_at=started_at,
        roots=["/mods"],
        findings=findings or [],
    )


def _finding(sha256: str, verdict: str, detector_severity: str = "HIGH") -> dict:
    return {
        "file_path": f"{sha256}.jar",
        "sha256": sha256,
        "verdict": verdict,
        "confidence": 0.9,
        "findings": [
            {
                "detector_id": "d01",
                "severity": detector_severity,
                "description": "test finding",
                "file_path": f"{sha256}.jar",
            }
        ]
        if verdict != "CLEAN"
        else [],
    }


def test_build_scan_report_from_job_counts_all_verdicts():
    job = _make_job(
        "job1",
        "2026-01-01T00:00:00",
        findings=[
            _finding("aaa", "MALICIOUS"),
            _finding("bbb", "CLEAN"),
            _finding("ccc", "SUSPICIOUS"),
        ],
    )
    report = build_scan_report_from_job(job)
    assert report.total_files == 3
    assert report.malicious_count == 1
    assert report.suspicious_count == 1
    assert report.clean_count == 1


def test_record_creates_index_and_report_file(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history")
    job = _make_job("job1", "2026-01-01T00:00:00", findings=[_finding("aaa", "MALICIOUS")])
    store.record(job)

    assert (tmp_path / "history" / "index.json").exists()
    assert (tmp_path / "history" / "reports" / "job1.json").exists()


def test_list_entries_newest_first(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history")
    store.record(_make_job("job1", "2026-01-01T00:00:00"))
    store.record(_make_job("job2", "2026-01-03T00:00:00"))
    store.record(_make_job("job3", "2026-01-02T00:00:00"))

    entries = store.list_entries()
    assert [e.scan_id for e in entries] == ["job2", "job3", "job1"]


def test_get_report_roundtrip(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history")
    job = _make_job("job1", "2026-01-01T00:00:00", findings=[_finding("aaa", "MALICIOUS")])
    store.record(job)

    report = store.get_report("job1")
    assert report is not None
    assert report["scan_id"] == "job1"
    assert report["summary"]["malicious"] == 1
    assert report["files"][0]["sha256"] == "aaa"


def test_get_report_nonexistent_returns_none(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history")
    assert store.get_report("does-not-exist") is None


def test_delete_removes_entry_and_file(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history")
    store.record(_make_job("job1", "2026-01-01T00:00:00"))

    assert store.delete("job1") is True
    assert store.list_entries() == []
    assert store.get_report("job1") is None
    assert not (tmp_path / "history" / "reports" / "job1.json").exists()


def test_delete_nonexistent_returns_false(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history")
    assert store.delete("does-not-exist") is False


def test_enforce_limit_evicts_oldest(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history", max_entries=2)
    store.record(_make_job("job1", "2026-01-01T00:00:00"))
    store.record(_make_job("job2", "2026-01-02T00:00:00"))
    store.record(_make_job("job3", "2026-01-03T00:00:00"))

    entries = store.list_entries()
    assert len(entries) == 2
    assert {e.scan_id for e in entries} == {"job2", "job3"}
    assert store.get_report("job1") is None
    assert not (tmp_path / "history" / "reports" / "job1.json").exists()


def test_record_same_scan_id_twice_does_not_duplicate_index_entry(tmp_path: Path):
    """A job re-recorded under the same scan_id (should not normally
    happen, but defends against a duplicate index entry if it does)
    must not leave two entries for the same scan_id in the index."""
    store = HistoryStore(history_dir=tmp_path / "history")
    store.record(_make_job("job1", "2026-01-01T00:00:00"))
    store.record(_make_job("job1", "2026-01-01T00:00:00"))

    entries = store.list_entries()
    assert len(entries) == 1


def test_purge_removes_all_entries_and_reports(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history")
    store.record(_make_job("job1", "2026-01-01T00:00:00"))
    store.record(_make_job("job2", "2026-01-02T00:00:00"))
    store.record(_make_job("job3", "2026-01-03T00:00:00"))

    count = store.purge()

    assert count == 3
    assert store.list_entries() == []
    assert store.get_report("job1") is None
    assert store.get_report("job2") is None
    assert store.get_report("job3") is None
    assert not (tmp_path / "history" / "reports" / "job1.json").exists()
    assert not (tmp_path / "history" / "reports" / "job2.json").exists()
    assert not (tmp_path / "history" / "reports" / "job3.json").exists()


def test_purge_empty_store_returns_zero(tmp_path: Path):
    store = HistoryStore(history_dir=tmp_path / "history")
    assert store.purge() == 0
