"""Scan report data models."""

from dataclasses import dataclass, field
from typing import Any

from mcrataway.constants import Severity, Verdict


@dataclass
class Finding:
    """A single finding from a detector or rule match."""

    detector_id: str
    severity: Severity
    description: str
    file_path: str
    class_name: str = ""
    method_name: str = ""
    matched_value: str = ""
    context: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "severity": self.severity.name,
            "description": self.description,
            "file_path": self.file_path,
            "class_name": self.class_name,
            "method_name": self.method_name,
            "matched_value": self.matched_value,
            "context": self.context,
        }


@dataclass
class FileReport:
    """Scan result for a single file."""

    file_path: str
    sha256: str
    verdict: Verdict
    confidence: float
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "sha256": self.sha256,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }


@dataclass
class ScanReport:
    """Full scan report."""

    scan_id: str
    timestamp: str
    hostname: str
    os_name: str
    scanned_roots: list[str] = field(default_factory=list)
    files: list[FileReport] = field(default_factory=list)

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def malicious_count(self) -> int:
        return sum(1 for f in self.files if f.verdict == Verdict.MALICIOUS)

    @property
    def suspicious_count(self) -> int:
        return sum(1 for f in self.files if f.verdict == Verdict.SUSPICIOUS)

    @property
    def clean_count(self) -> int:
        return sum(1 for f in self.files if f.verdict == Verdict.CLEAN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "scanned_roots": self.scanned_roots,
            "summary": {
                "total_files": self.total_files,
                "malicious": self.malicious_count,
                "suspicious": self.suspicious_count,
                "clean": self.clean_count,
            },
            "files": [f.to_dict() for f in self.files],
        }
