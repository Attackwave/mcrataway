"""Scan history store — persists completed scan reports to disk so
results survive a server restart.

Independent of JobRegistry's in-memory _MAX_COMPLETED_JOBS eviction
(src/mcrataway/server/jobs.py) — that bounds RAM; this bounds disk
under ~/.mcrataway/history. The two mechanisms deliberately share no
code: one protects the running process's memory, the other protects
the user's disk across restarts.

Two-tier storage avoids reading every full report (which can be
several MB for a scan with thousands of findings) just to list past
scans:

    <history_dir>/index.json              - small array of HistoryEntry
    <history_dir>/reports/<scan_id>.json  - one full ScanReport per scan
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcrataway.constants import HISTORY_DIR, Severity, Verdict
from mcrataway.reporting.model import FileReport, Finding, ScanReport

if TYPE_CHECKING:
    from mcrataway.server.jobs import ScanJob

_DEFAULT_MAX_ENTRIES = 50


@dataclass
class HistoryEntry:
    """Lightweight index entry — the summary shown in the history list
    without reading the full report."""

    scan_id: str
    timestamp: str
    roots: list[str] = field(default_factory=list)
    total_files: int = 0
    malicious: int = 0
    suspicious: int = 0
    clean: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "roots": self.roots,
            "summary": {
                "total_files": self.total_files,
                "malicious": self.malicious,
                "suspicious": self.suspicious,
                "clean": self.clean,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HistoryEntry":
        summary = data.get("summary", {})
        return cls(
            scan_id=data.get("scan_id", ""),
            timestamp=data.get("timestamp", ""),
            roots=list(data.get("roots", [])),
            total_files=summary.get("total_files", 0),
            malicious=summary.get("malicious", 0),
            suspicious=summary.get("suspicious", 0),
            clean=summary.get("clean", 0),
        )

    @classmethod
    def from_report(cls, report: ScanReport) -> "HistoryEntry":
        return cls(
            scan_id=report.scan_id,
            timestamp=report.timestamp,
            roots=list(report.scanned_roots),
            total_files=report.total_files,
            malicious=report.malicious_count,
            suspicious=report.suspicious_count,
            clean=report.clean_count,
        )


def build_scan_report_from_job(job: "ScanJob") -> ScanReport:
    """Reconstruct a ScanReport from a ScanJob's accumulated findings.

    This is the same job.findings-dict -> Finding/FileReport/ScanReport
    reconstruction previously inlined in server/routes/reports.py —
    extracted here so HistoryStore.record() and the /reports/{job_id}
    route share one implementation instead of two copies of the same
    lenient verdict/severity parsing.
    """
    file_reports: list[FileReport] = []
    # Iterate job.findings (all scanned files, including CLEAN) rather
    # than job.verdicts (only MALICIOUS/SUSPICIOUS) — using verdicts
    # would silently drop every clean file, making clean_count always
    # 0 and total_files wrong.
    for v in job.findings:
        try:
            verdict_val = Verdict(str(v.get("verdict", "CLEAN")).upper())
        except ValueError:
            verdict_val = Verdict.CLEAN
        findings = []
        for f in v.get("findings", []):
            # Lenient with severity casing/values — a corrupted job
            # store or hand-edited JSON should not crash report
            # building with a KeyError from Severity[...].
            sev_name = f.get("severity", "INFO")
            try:
                severity = Severity[str(sev_name).upper()]
            except (KeyError, AttributeError):
                severity = Severity.INFO
            findings.append(
                Finding(
                    detector_id=f.get("detector_id", ""),
                    severity=severity,
                    description=f.get("description", ""),
                    file_path=f.get("file_path", ""),
                    class_name=f.get("class_name", ""),
                    method_name=f.get("method_name", ""),
                    matched_value=f.get("matched_value", ""),
                )
            )
        file_reports.append(
            FileReport(
                file_path=v.get("file_path", ""),
                sha256=v.get("sha256", ""),
                verdict=verdict_val,
                confidence=v.get("confidence", 0.0),
                findings=findings,
                metadata=v.get("metadata", {}),
            )
        )

    return ScanReport(
        scan_id=job.job_id,
        timestamp=job.started_at or "",
        hostname="mcrataway-server",
        os_name="Python",
        scanned_roots=job.roots,
        files=file_reports,
    )


class HistoryStore:
    """Persists completed ScanJobs as ScanReports under
    <history_dir>/reports/<scan_id>.json, with a lightweight
    <history_dir>/index.json for listing without reading full reports.
    """

    def __init__(
        self,
        history_dir: Path | str | None = None,
        max_entries: int = _DEFAULT_MAX_ENTRIES,
    ) -> None:
        self.history_dir = Path(history_dir) if history_dir else HISTORY_DIR
        self.reports_dir = self.history_dir / "reports"
        self.index_path = self.history_dir / "index.json"
        self.max_entries = max_entries

    def record(self, job: "ScanJob") -> None:
        """Build a ScanReport from job, persist it, and enforce the
        retention limit."""
        report = build_scan_report_from_job(job)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = self.reports_dir / f"{report.scan_id}.json"
        report_path.write_text(json.dumps(report.to_dict(), indent=2))

        entries = self._read_index()
        entries = [e for e in entries if e.scan_id != report.scan_id]
        entries.append(HistoryEntry.from_report(report))
        self._write_index(entries)
        self._enforce_limit()

    def list_entries(self) -> list[HistoryEntry]:
        """Return history entries, newest first."""
        entries = self._read_index()
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)

    def get_report(self, scan_id: str) -> dict[str, Any] | None:
        """Return the full report dict for scan_id, or None if absent."""
        report_path = self.reports_dir / f"{scan_id}.json"
        if not report_path.exists():
            return None
        try:
            data: dict[str, Any] = json.loads(report_path.read_text())
            return data
        except (json.JSONDecodeError, OSError):
            return None

    def delete(self, scan_id: str) -> bool:
        """Remove one entry from the index and its report file.
        Returns False if scan_id was not found in the index."""
        entries = self._read_index()
        remaining = [e for e in entries if e.scan_id != scan_id]
        if len(remaining) == len(entries):
            return False
        self._write_index(remaining)
        (self.reports_dir / f"{scan_id}.json").unlink(missing_ok=True)
        return True

    def _enforce_limit(self) -> None:
        """Drop oldest entries beyond max_entries, deleting their
        report files — analogous to JobRegistry._cleanup_old_jobs()."""
        entries = self._read_index()
        if len(entries) <= self.max_entries:
            return
        entries.sort(key=lambda e: e.timestamp)
        to_remove = entries[: len(entries) - self.max_entries]
        keep = entries[len(entries) - self.max_entries :]
        for entry in to_remove:
            (self.reports_dir / f"{entry.scan_id}.json").unlink(missing_ok=True)
        self._write_index(keep)

    def _read_index(self) -> list[HistoryEntry]:
        if not self.index_path.exists():
            return []
        try:
            data = json.loads(self.index_path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
        if not isinstance(data, list):
            return []
        return [HistoryEntry.from_dict(d) for d in data if isinstance(d, dict)]

    def _write_index(self, entries: list[HistoryEntry]) -> None:
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.index_path.write_text(
            json.dumps([e.to_dict() for e in entries], indent=2)
        )
