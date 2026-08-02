"""Audit log — append-only JSON Lines record of what the scanner did.

For incident response ("did we catch the fractureiser drop last
week?"), quarantine manifests and scan history are not enough: the
user needs a single, chronological, tamper-evident trail of every
verdict, quarantine action, and skipped-entry batch. This module
writes one JSON object per line to ``~/.mcrataway/audit.log`` (0o600
perms, like the token file — scan paths and quarantine locations are
sensitive on a multi-user system).

The log is line-delimited JSON (JSONL), not a JSON array, so it is
safe to append to without reading/parsing the whole file, and a
corrupted last line does not invalidate the rest. Rotate externally
(logrotate) if it grows large; the scanner does not self-rotate to
keep the hot path simple.
"""

import contextlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import mcrataway.constants as constants

_write_lock = threading.Lock()


def _audit_log_file() -> Path:
    """Resolve the audit log path at call time (not import time) so
    that tests redirecting MCRATAWAY_HOME / constants.CONFIG_DIR take
    effect without needing to re-import this module."""
    return constants.CONFIG_DIR / "audit.log"


def _ensure_log_file() -> Path:
    """Ensure the audit log file exists with restrictive permissions."""
    path = _audit_log_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()
        with contextlib.suppress(OSError):
            path.chmod(0o600)
    return path


def log_event(event_type: str, **fields: Any) -> None:
    """Append one audit event to the log.

    *event_type* is a short string identifying the kind of event
    (``scan_verdict``, ``quarantine``, ``skipped_entries``). Additional
    keyword arguments become fields in the JSON object. Every event
    gets an automatic ``timestamp`` (UTC ISO-8601) and ``scanner_version``.

    Failures to write (disk full, permission denied) are swallowed —
    the audit log is a best-effort forensic aid, not a critical-path
    component; a scan must not fail because the audit log could not be
    written.
    """
    from mcrataway.constants import SCANNER_VERSION

    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "scanner_version": SCANNER_VERSION,
        "event_type": event_type,
        **fields,
    }
    line = json.dumps(entry, default=str) + "\n"
    try:
        path = _ensure_log_file()
        with _write_lock, open(path, "a") as f:
            f.write(line)
    except OSError:
        pass


def log_scan_verdict(
    file_path: str,
    file_hash: str,
    verdict: str,
    confidence: float,
    finding_count: int,
    skipped: list[dict[str, str]] | None = None,
) -> None:
    """Log a per-file scan verdict."""
    log_event(
        "scan_verdict",
        file_path=file_path,
        sha256=file_hash,
        verdict=verdict,
        confidence=confidence,
        finding_count=finding_count,
        skipped_entries=skipped or [],
    )


def log_quarantine(
    file_path: str,
    file_hash: str,
    outcome: str,
    quarantine_id: str | None = None,
    error: str | None = None,
) -> None:
    """Log a quarantine action (success, failure, or no-op)."""
    log_event(
        "quarantine",
        file_path=file_path,
        sha256=file_hash,
        outcome=outcome,
        quarantine_id=quarantine_id,
        error=error,
    )


def read_audit_log(limit: int = 100) -> list[dict[str, Any]]:
    """Read the last *limit* events from the audit log (newest last).

    Returns a list of parsed JSON objects. Corrupted lines are skipped
    (not fatal) — a truncated last line from a crash does not prevent
    reading the valid entries before it.
    """
    path = _audit_log_file()
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return events[-limit:]


# Test helpers — not part of the public API, but used by tests to
# redirect the audit log to a temp path without monkeypatching the
# constants module.
def _set_log_path_for_testing(path: Path) -> None:
    """Redirect audit log writes to *path* (test-only).

    Sets constants.CONFIG_DIR so that ``_audit_log_file()`` resolves
    to ``path`` (which must be ``<dir>/audit.log``).
    """
    constants.CONFIG_DIR = path.parent
