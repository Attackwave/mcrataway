"""Tests for the audit log (reporting/audit_log.py).

The audit log is an append-only JSONL trail of every scan verdict and
quarantine action, written to ~/.mcrataway/audit.log with 0o600 perms.
For incident response ("did we catch the fractureiser drop last
week?"), this is the definitive record — quarantine manifests and
scan history don't cover the full timeline the way a chronological
event log does.
"""

import json
from pathlib import Path

import mcrataway.constants as constants
from mcrataway.reporting.audit_log import (
    log_event,
    log_quarantine,
    log_scan_verdict,
    read_audit_log,
)

_ORIGINAL_CONFIG_DIR = constants.CONFIG_DIR


def _redirect_log(tmp_path: Path) -> Path:
    """Point the audit log at tmp_path/audit.log for the duration of
    the test, and clean up the file so each test starts fresh.

    Restores the original CONFIG_DIR on teardown — mutating a global
    constant without restoring it leaks into other tests (the CLI exit-
    code tests, for example, then find CONFIG_DIR pointing at a deleted
    tmp_path and the scan engine's audit-log writes fail).
    """
    log_path = tmp_path / "audit.log"
    constants.CONFIG_DIR = tmp_path
    if log_path.exists():
        log_path.unlink()
    return log_path


def pytest_runtest_teardown():  # noqa: D401
    """Restore CONFIG_DIR after every test in this module."""
    constants.CONFIG_DIR = _ORIGINAL_CONFIG_DIR


def test_log_event_appends_jsonl(tmp_path: Path) -> None:
    log_path = _redirect_log(tmp_path)
    log_event("test_event", field1="a", field2=42)

    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["event_type"] == "test_event"
    assert entry["field1"] == "a"
    assert entry["field2"] == 42
    assert "timestamp" in entry
    assert "scanner_version" in entry


def test_multiple_events_are_appended_chronologically(tmp_path: Path) -> None:
    _redirect_log(tmp_path)
    log_event("first", n=1)
    log_event("second", n=2)
    log_event("third", n=3)

    events = read_audit_log(limit=100)
    assert len(events) == 3
    assert [e["n"] for e in events] == [1, 2, 3]


def test_log_scan_verdict_fields(tmp_path: Path) -> None:
    _redirect_log(tmp_path)
    log_scan_verdict(
        file_path="/mods/evil.jar",
        file_hash="abc123",
        verdict="MALICIOUS",
        confidence=0.95,
        finding_count=5,
    )
    events = read_audit_log()
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "scan_verdict"
    assert ev["file_path"] == "/mods/evil.jar"
    assert ev["verdict"] == "MALICIOUS"
    assert ev["finding_count"] == 5


def test_log_quarantine_fields(tmp_path: Path) -> None:
    _redirect_log(tmp_path)
    log_quarantine(
        file_path="/mods/evil.jar",
        file_hash="abc123",
        outcome="success",
        quarantine_id="evil_abc123",
    )
    events = read_audit_log()
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "quarantine"
    assert ev["outcome"] == "success"
    assert ev["quarantine_id"] == "evil_abc123"


def test_corrupted_last_line_does_not_invalidate_rest(tmp_path: Path) -> None:
    """A crash mid-write may leave a truncated last line; reading must
    skip it and return the valid entries before it."""
    log_path = _redirect_log(tmp_path)
    log_event("good", n=1)
    log_event("good", n=2)
    # Append a corrupted line manually.
    with open(log_path, "a") as f:
        f.write('{"event_type": "truncated", "n":')

    events = read_audit_log()
    assert len(events) == 2
    assert all(e["event_type"] == "good" for e in events)


def test_audit_log_file_has_restrictive_permissions(tmp_path: Path) -> None:
    """The audit log contains scan paths and quarantine locations — on
    a multi-user system it must not be world/group readable, matching
    TOKEN_FILE and config.yaml's treatment."""
    import sys

    log_path = _redirect_log(tmp_path)
    log_event("test")
    if sys.platform != "win32":
        mode = log_path.stat().st_mode & 0o777
        assert mode == 0o600, f"audit.log is {oct(mode)}, expected 0o600"


def test_read_audit_log_empty_when_no_file(tmp_path: Path) -> None:
    _redirect_log(tmp_path)
    events = read_audit_log()
    assert events == []
