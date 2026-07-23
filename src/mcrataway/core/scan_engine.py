"""Core scan engine — orchestrates the full pipeline per artifact."""

import fnmatch
import hashlib
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcrataway.constants import Severity, Verdict
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.verdict import VerdictAggregator
from mcrataway.detectors.base import Detector
from mcrataway.parsers.archive import ArchiveReader, find_class_entries
from mcrataway.parsers.classfile import parse_class
from mcrataway.parsers.manifest import parse_archive_manifest
from mcrataway.parsers.string_reconstructor import reconstruct_strings
from mcrataway.reporting.model import FileReport, Finding, ScanReport
from mcrataway.rules.loader import RulePack


@dataclass
class ArtifactResult:
    """Result of scanning a single artifact."""

    file_path: str
    file_hash: str
    verdict: Verdict
    confidence: float
    findings: list[Finding]
    metadata: dict[str, Any] = field(default_factory=dict)


class ScanEngine:
    """Orchestrates bytecode analysis, detection, and verdict for artifacts."""

    def __init__(
        self,
        rules: list[RulePack] | None = None,
        quarantine: QuarantineManager | None = None,
        max_workers: int = 4,
        detectors: list[Detector] | None = None,
        whitelisted_hashes: set[str] | list[str] | None = None,
        excluded_paths: list[str] | None = None,
    ) -> None:
        self.rules = rules or []
        self.quarantine = quarantine or QuarantineManager()
        self.max_workers = max_workers
        self.detectors = detectors or self._default_detectors()
        self.verdict_agg = VerdictAggregator()
        self.whitelisted_hashes = set(whitelisted_hashes or [])
        self.excluded_paths = excluded_paths or []

    @staticmethod
    def _default_detectors() -> list[Detector]:
        """Instantiate all built-in detectors."""
        from mcrataway.detectors.d01_process_exec import D01ProcessExec
        from mcrataway.detectors.d02_network_io import D02NetworkIO
        from mcrataway.detectors.d03_dynamic_loading import D03DynamicLoading
        from mcrataway.detectors.d04_filesystem_jar_mod import D04FilesystemJarMod
        from mcrataway.detectors.d05_persistence import D05Persistence
        from mcrataway.detectors.d06_deserialization import D06Deserialization
        from mcrataway.detectors.d07_native_jni import D07NativeJni
        from mcrataway.detectors.d08_credential_theft import D08CredentialTheft
        from mcrataway.detectors.d09_obfuscation import D09Obfuscation
        from mcrataway.detectors.d10_reflection_indirect import D10ReflectionIndirect
        from mcrataway.detectors.d11_onchain_c2 import D11OnchainC2
        from mcrataway.detectors.d12_resourcepack_exploit import D12ResourcepackExploit

        return [
            D01ProcessExec(),
            D02NetworkIO(),
            D03DynamicLoading(),
            D04FilesystemJarMod(),
            D05Persistence(),
            D06Deserialization(),
            D07NativeJni(),
            D08CredentialTheft(),
            D09Obfuscation(),
            D10ReflectionIndirect(),
            D11OnchainC2(),
            D12ResourcepackExploit(),
        ]

    def scan_files(
        self,
        files: list[Path],
        root: str = "",
        on_progress: Callable[[Path], None] | None = None
    ) -> list[ArtifactResult]:
        """Scan a list of files concurrently using ``max_workers`` threads.
        
        If *on_progress* is provided, it is called with each file path
        immediately before it is scanned.
        """
        if not files:
            return []

        lock = threading.Lock()

        def _process_file(f: Path) -> ArtifactResult:
            if on_progress:
                with lock:
                    on_progress(f)
            try:
                result = self._scan_single(f, root)
                self.maybe_quarantine(f, result)
                return result
            except Exception as exc:
                return ArtifactResult(
                    file_path=str(f),
                    file_hash="",
                    verdict=Verdict.SUSPICIOUS,
                    confidence=0.3,
                    findings=[
                        Finding(
                            detector_id="scan_engine",
                            severity=Severity.MEDIUM,
                            description=f"Scan failed: {type(exc).__name__}: {exc}",
                            file_path=str(f),
                        )
                    ],
                )

        if self.max_workers > 1 and len(files) > 1:
            results: list[ArtifactResult] = []
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_file = {executor.submit(_process_file, f): f for f in files}
                for future in as_completed(future_to_file):
                    results.append(future.result())
            return results
        else:
            return [_process_file(f) for f in files]

    def maybe_quarantine(self, path: Path, result: ArtifactResult) -> None:
        """Quarantine the file if its verdict and the config warrant it."""
        is_mal = result.verdict == Verdict.MALICIOUS
        is_susp = result.verdict == Verdict.SUSPICIOUS
        do_mal = self.quarantine.do_quarantine_malicious
        do_susp = self.quarantine.do_quarantine_suspicious
        if (is_mal and do_mal) or (is_susp and do_susp):
            self.quarantine.quarantine(path, result)

    def _scan_single(self, path: Path, root: str) -> ArtifactResult:
        """Scan a single file."""
        str_path = str(path)
        for pattern in self.excluded_paths:
            if fnmatch.fnmatch(str_path, pattern) or fnmatch.fnmatch(path.name, pattern):
                return ArtifactResult(
                    file_path=str_path,
                    file_hash="",
                    verdict=Verdict.CLEAN,
                    confidence=1.0,
                    findings=[],
                    metadata={"excluded": True},
                )

        file_hash = self._hash_file(path)
        if file_hash and file_hash in self.whitelisted_hashes:
            return ArtifactResult(
                file_path=str_path,
                file_hash=file_hash,
                verdict=Verdict.CLEAN,
                confidence=1.0,
                findings=[],
                metadata={"whitelisted": True},
            )
        suffix = path.suffix.lower()

        if suffix in (".jar", ".zip"):
            return self._scan_archive(path, file_hash, root)
        elif suffix in (".js", ".ts", ".mcfunction", ".lua"):
            return self._scan_script(path, file_hash, root)
        elif suffix in (".json", ".toml", ".yml", ".yaml", ".mcmeta", ".txt"):
            return self._scan_config(path, file_hash, root)
        else:
            return ArtifactResult(
                file_path=str(path),
                file_hash=file_hash,
                verdict=Verdict.CLEAN,
                confidence=1.0,
                findings=[],
            )

    def _scan_archive(self, path: Path, file_hash: str, root: str) -> ArtifactResult:
        """Scan a JAR/ZIP archive."""
        findings: list[Finding] = []
        index = EvidenceIndex()
        metadata: dict[str, Any] = {}

        try:
            reader = ArchiveReader(path)
            entries = reader.entries()
        except Exception:
            return ArtifactResult(
                file_path=str(path),
                file_hash=file_hash,
                verdict=Verdict.SUSPICIOUS,
                confidence=0.5,
                findings=[
                    Finding(
                        detector_id="archive",
                        severity=Severity.MEDIUM,
                        description="Archive cannot be read",
                        file_path=str(path),
                    )
                ],
                metadata=metadata,
            )

        # Parse manifest
        manifest_entries: dict[str, bytes] = {}
        manifest_names = {
            "fabric.mod.json", "mcmod.info", "META-INF/MANIFEST.MF",
        }
        for entry in entries:
            if entry.name in manifest_names or entry.name.endswith("mods.toml"):
                manifest_entries[entry.name] = entry.data
        if manifest_entries:
            manifest = parse_archive_manifest(manifest_entries)
            metadata["mod_id"] = manifest.mod_id
            metadata["loader"] = manifest.loader
            metadata["name"] = manifest.name
            metadata["version"] = manifest.version

        # Scan class files
        class_entries = find_class_entries(entries)
        class_entry_names = {e.name for e in class_entries}
        for entry in class_entries:
            parsed = parse_class(entry.data)
            if parsed:
                for detector in self.detectors:
                    evs = detector.analyze_class(parsed)
                    index.add_many(evs)

                # Reconstruct hidden strings
                reconstructed = reconstruct_strings(parsed)
                for rs in reconstructed:
                    index.add(
                        Evidence(
                            detector_id="string_reconstruction",
                            severity=Severity.INFO,
                            class_name=rs.class_name,
                            method_name=rs.method_name,
                            offset=rs.offset,
                            description=f"Reconstructed string: {rs.value[:80]}...",
                            matched_value=rs.value[:200],
                            context={"technique": rs.technique},
                        )
                    )

        # Scan non-class archive entries with archive-aware detectors (e.g. D12)
        for entry in entries:
            if entry.name in class_entry_names:
                continue
            for detector in self.detectors:
                archive_method = getattr(detector, "analyze_archive_entry", None)
                if archive_method is None:
                    continue
                evs = archive_method(entry.name, entry.data)
                index.add_many(evs)

        # Apply signature rules to archive entries
        for rule in self.rules:
            matches = rule.matches_archive(entries, class_entries)
            for match in matches:
                index.add(
                    Evidence(
                        detector_id=f"rule:{rule.pack_id}:{match.rule_id}",
                        severity=match.severity,
                        class_name=match.class_name or "",
                        method_name="",
                        offset=0,
                        description=match.description,
                        matched_value=match.matched_value,
                        context={"rule_pack": rule.pack_id, "rule_id": match.rule_id},
                    )
                )

        verdict, confidence = self.verdict_agg.compute(index)

        for ev in index.evidence:
            findings.append(
                Finding(
                    detector_id=ev.detector_id,
                    severity=ev.severity,
                    description=ev.description,
                    file_path=str(path),
                    class_name=ev.class_name,
                    method_name=ev.method_name,
                    matched_value=ev.matched_value,
                    context=ev.context,
                )
            )

        return ArtifactResult(
            file_path=str(path),
            file_hash=file_hash,
            verdict=verdict,
            confidence=confidence,
            findings=findings,
            metadata=metadata,
        )

    def _scan_script(self, path: Path, file_hash: str, root: str) -> ArtifactResult:
        """Scan a script file."""
        from mcrataway.parsers.scripts import analyze_script

        try:
            data = path.read_bytes()
        except Exception:
            return ArtifactResult(
                file_path=str(path),
                file_hash=file_hash,
                verdict=Verdict.CLEAN,
                confidence=1.0,
                findings=[],
            )

        analysis = analyze_script(data, str(path))
        findings: list[Finding] = []
        for pattern in analysis.suspicious_patterns:
            findings.append(
                Finding(
                    detector_id=f"script:{pattern['type']}",
                    severity=Severity.MEDIUM,
                    description=pattern["description"],
                    file_path=str(path),
                )
            )

        verdict = Verdict.SUSPICIOUS if findings else Verdict.CLEAN
        confidence = 0.7 if findings else 1.0

        return ArtifactResult(
            file_path=str(path),
            file_hash=file_hash,
            verdict=verdict,
            confidence=confidence,
            findings=findings,
        )

    def _scan_config(self, path: Path, file_hash: str, root: str) -> ArtifactResult:
        """Scan a config file for embedded scripts or malicious payloads."""
        try:
            data = path.read_text(errors="replace")
        except Exception:
            return ArtifactResult(
                file_path=str(path),
                file_hash=file_hash,
                verdict=Verdict.CLEAN,
                confidence=1.0,
                findings=[],
            )

        findings: list[Finding] = []
        # Check for embedded JS in JSON config
        if "javascript:" in data or "eval(" in data:
            findings.append(
                Finding(
                    detector_id="config:embedded_script",
                    severity=Severity.MEDIUM,
                    description="Config contains embedded JavaScript",
                    file_path=str(path),
                )
            )

        verdict = Verdict.SUSPICIOUS if findings else Verdict.CLEAN
        return ArtifactResult(
            file_path=str(path),
            file_hash=file_hash,
            verdict=verdict,
            confidence=0.7 if findings else 1.0,
            findings=findings,
        )

    @staticmethod
    def _hash_file(path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except Exception:
            return ""
        return h.hexdigest()

    def build_report(
        self,
        roots: list[Path],
        results: list[ArtifactResult],
    ) -> ScanReport:
        """Build a full ScanReport from scan results."""
        import datetime
        import platform
        import uuid

        report = ScanReport(
            scan_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.UTC).isoformat(),
            hostname=platform.node(),
            os_name=platform.system(),
            scanned_roots=[str(r) for r in roots],
        )

        for result in results:
            file_report = FileReport(
                file_path=result.file_path,
                sha256=result.file_hash,
                verdict=result.verdict,
                confidence=result.confidence,
                findings=result.findings,
                metadata=result.metadata,
            )
            report.files.append(file_report)

        return report
