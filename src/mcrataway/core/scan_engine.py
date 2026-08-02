"""Core scan engine — orchestrates the full pipeline per artifact."""

import contextlib
import fnmatch
import hashlib
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcrataway.constants import Severity, Verdict
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.verdict import VerdictAggregator
from mcrataway.detectors.base import Detector
from mcrataway.parsers.archive import (
    DEFAULT_MAX_NESTING_DEPTH,
    ArchiveEntry,
    ArchiveReader,
    SizeBudget,
    is_java_class,
    is_nested_archive,
)
from mcrataway.parsers.classfile import parse_class
from mcrataway.parsers.manifest import parse_archive_manifest
from mcrataway.parsers.string_reconstructor import ReconstructedString, reconstruct_strings
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
    evidence_index: EvidenceIndex | None = None
    reconstructed_strings: list[ReconstructedString] | None = None


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
        max_nesting_depth: int = DEFAULT_MAX_NESTING_DEPTH,
    ) -> None:
        self.rules = rules or []
        self.quarantine = quarantine or QuarantineManager()
        self.max_workers = max_workers
        self.detectors = detectors or self._default_detectors()
        self.verdict_agg = VerdictAggregator()
        self.whitelisted_hashes = set(whitelisted_hashes or [])
        self.excluded_paths = excluded_paths or []
        self.max_nesting_depth = max_nesting_depth

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
        from mcrataway.detectors.d13_mixin_coremod import D13MixinCoremod

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
            D13MixinCoremod(),
            D12ResourcepackExploit(),
        ]

    def scan_files(
        self,
        files: list[Path],
        on_progress: Callable[[Path], None] | None = None,
        keep_evidence_index: bool = False,
    ) -> list[ArtifactResult]:
        """Scan a list of files concurrently using ``max_workers`` threads.

        If *on_progress* is provided, it is called with each file path
        immediately before it is scanned.

        If *keep_evidence_index* is True, the per-archive EvidenceIndex
        built during the scan is retained on ArtifactResult.evidence_index
        instead of being discarded — used by the rulegen pipeline, which
        needs the full correlated evidence, not just the flattened
        Finding list. Default False preserves existing behavior for the
        CLI, server, and all other callers.
        """
        if not files:
            return []

        def _process_file(f: Path) -> ArtifactResult:
            if on_progress:
                # No lock here: synchronizing an arbitrary caller-supplied
                # callback is the caller's responsibility, not this
                # method's. The server's on_progress (server/routes/scan.py)
                # is already thread-safe via loop.call_soon_threadsafe; the
                # CLI's on_progress (cli.py) drives a rich.progress.Progress
                # instance, which is NOT safe to update concurrently from
                # multiple threads, so the CLI wraps its own callback in a
                # lock. Locking unconditionally here previously serialized
                # every worker thread around this call regardless of
                # whether the callback needed it, eliminating most of the
                # benefit of max_workers > 1 for the (already thread-safe)
                # server path.
                on_progress(f)
            try:
                result = self._scan_single(f, keep_evidence_index=keep_evidence_index)
                self.maybe_quarantine(f, result)
                self._audit_verdict(f, result)
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

        try:
            if self.max_workers > 1 and len(files) > 1:
                results: list[ArtifactResult] = []
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_file = {executor.submit(_process_file, f): f for f in files}
                    for future in as_completed(future_to_file):
                        results.append(future.result())
                return results
            else:
                return [_process_file(f) for f in files]
        finally:
            # Clear the bytecode decode cache after every scan job. A
            # long-running `mcrataway serve` process performs many
            # scan jobs over its lifetime; without this the cache
            # would accumulate one entry per distinct method body ever
            # seen across every job, unboundedly.
            from mcrataway.parsers.instructions import clear_cache
            clear_cache()

    def maybe_quarantine(self, path: Path, result: ArtifactResult) -> None:
        """Quarantine the file if its verdict and the config warrant it.

        A failed quarantine attempt (disk full, permission denied, a
        crash between copying and removing the original — see
        QuarantineManager.quarantine's rollback handling) previously
        returned ``None`` with nothing checking it: the caller would
        see a MALICIOUS verdict with no indication that the file was
        actually *not* isolated, which is more dangerous than a loud
        failure — the user could believe the threat was contained when
        it was not. The outcome is now recorded on
        ``result.metadata`` so callers (CLI, server report) can surface
        it instead of it disappearing silently.

        Every quarantine attempt (success, failure, or no-op) is also
        written to the audit log (``~/.mcrataway/audit.log``) for
        incident-response traceability — "was this file isolated, and
        when?" must be answerable after the fact.
        """
        from mcrataway.core.quarantine import QuarantineOutcome
        from mcrataway.reporting.audit_log import log_quarantine

        is_mal = result.verdict == Verdict.MALICIOUS
        is_susp = result.verdict == Verdict.SUSPICIOUS
        do_mal = self.quarantine.do_quarantine_malicious
        do_susp = self.quarantine.do_quarantine_suspicious
        if (is_mal and do_mal) or (is_susp and do_susp):
            qresult = self.quarantine.quarantine(path, result)
            if qresult.outcome is QuarantineOutcome.FAILED:
                result.metadata["quarantine_failed"] = True
            elif qresult.outcome is QuarantineOutcome.SUCCESS:
                result.metadata["quarantined"] = True
            log_quarantine(
                file_path=str(path),
                file_hash=result.file_hash,
                outcome=qresult.outcome.value,
                quarantine_id=qresult.manifest.sha256 if qresult.manifest else None,
            )
            # ALREADY_QUARANTINED / SOURCE_MISSING are not failures —
            # nothing to surface for either.

    @staticmethod
    def _audit_verdict(path: Path, result: ArtifactResult) -> None:
        """Write a per-file verdict event to the audit log.

        Non-MALICIOUS/SUSPICIOUS verdicts are logged too — the audit
        trail's value is answering "was this file ever scanned, and
        what did the scanner conclude?", which requires recording
        CLEAN verdicts as well as threats.
        """
        from mcrataway.reporting.audit_log import log_scan_verdict

        skipped = result.metadata.get("skipped_entries")
        log_scan_verdict(
            file_path=str(path),
            file_hash=result.file_hash,
            verdict=result.verdict.value,
            confidence=result.confidence,
            finding_count=len(result.findings),
            skipped=skipped,
        )

    def _scan_single(self, path: Path, *, keep_evidence_index: bool = False) -> ArtifactResult:
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
            return self._scan_archive(path, file_hash, keep_evidence_index=keep_evidence_index)
        elif suffix in (".js", ".ts", ".mcfunction", ".lua"):
            return self._scan_script(path, file_hash)
        elif suffix in (".json", ".toml", ".yml", ".yaml", ".mcmeta", ".txt"):
            return self._scan_config(path, file_hash)
        else:
            return ArtifactResult(
                file_path=str(path),
                file_hash=file_hash,
                verdict=Verdict.CLEAN,
                confidence=1.0,
                findings=[],
            )

    def _scan_archive(
        self, path: Path, file_hash: str, *, keep_evidence_index: bool = False
    ) -> ArtifactResult:
        """Scan a JAR/ZIP archive, recursing into nested archives.

        Nested archives (a JAR packed inside another JAR, e.g. Forge
        JarJar / Fabric "nested jars", or a payload staged for later
        loading) are opened and analyzed too — this is how real
        Minecraft mod malware (fractureiser Stage-0) hides its payload.
        Detection of the inner archive is by content (ZIP magic bytes),
        not by file extension, so renaming the inner archive does not
        help an attacker evade it.
        """
        findings: list[Finding] = []
        index = EvidenceIndex()
        metadata: dict[str, Any] = {}
        size_budget = SizeBudget()

        try:
            reader = ArchiveReader(path, size_budget=size_budget)
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

        reconstructed_out: list[ReconstructedString] | None = (
            [] if keep_evidence_index else None
        )
        display_name = path.name
        try:
            manifest_metadata = self._analyze_archive_entries(
                reader.entries(),
                display_name,
                index,
                size_budget,
                depth=0,
                reconstructed_out=reconstructed_out,
            )
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
        metadata.update(manifest_metadata)

        from mcrataway.core.behavior_chains import evaluate_chains
        from mcrataway.detectors.d05_persistence import D05Persistence
        from mcrataway.detectors.d11_onchain_c2 import D11OnchainC2
        D05Persistence.escalate_weak_indicators(index)
        D11OnchainC2.escalate_crypto_with_onchain_indicators(index)
        # Runs last: needs the final, fully-escalated evidence picture
        # per class to distinguish a complete multi-step behavior from
        # a single capability finding — see behavior_chains.py.
        evaluate_chains(index)

        if size_budget.skipped:
            for name, reason in size_budget.skipped:
                index.add(
                    Evidence(
                        detector_id="archive",
                        severity=Severity.MEDIUM,
                        class_name="",
                        method_name="",
                        offset=0,
                        description=(
                            f"Entry not scanned ({reason}): {name} — "
                            f"result below does not cover this entry"
                        ),
                        matched_value=name,
                        context={"skip_reason": reason},
                    )
                )
            metadata["skipped_entries"] = [
                {"name": n, "reason": r} for n, r in size_budget.skipped
            ]

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
            evidence_index=index if keep_evidence_index else None,
            reconstructed_strings=reconstructed_out,
        )

    def _analyze_archive_entries(
        self,
        entries: Iterator[ArchiveEntry],
        display_path: str,
        index: EvidenceIndex,
        size_budget: SizeBudget,
        depth: int,
        reconstructed_out: list[ReconstructedString] | None = None,
    ) -> dict[str, Any]:
        """Run detectors and rules over one archive's entries in a single
        pass, recursing into nested archives up to
        :data:`DEFAULT_MAX_NESTING_DEPTH`.

        *entries* is consumed as a stream (see
        ``ArchiveReader.entries``) rather than a materialized list, so
        this method classifies and dispatches each entry exactly once
        as it arrives instead of iterating a list multiple times (once
        for class files, once for non-class entries, once for rule
        matching) — the latter would require every entry's bytes
        resident in memory simultaneously, which is what the generator
        conversion set out to avoid.

        *display_path* is the human-readable location prefix (e.g.
        ``outer.jar!/assets/payload.jar``) used so findings from nested
        archives can be traced back to where they actually live.

        Returns manifest metadata extracted from this archive level
        (only meaningful at depth 0 — nested archives are mods bundled
        by the outer mod, not the mod being scanned).
        """
        manifest_entries: dict[str, bytes] = {}
        manifest_names = {
            "fabric.mod.json", "mcmod.info", "META-INF/MANIFEST.MF",
        }

        # Collected for D14 (signature/manifest tamper detection),
        # which needs the whole archive's entry-name set and .SF
        # contents — gathered here during the single streaming pass
        # rather than by iterating entries a second time.
        class_entry_names: set[str] = set()
        sf_contents: dict[str, str] = {}

        match_states = [(rule_pack, rule_pack.new_match_state()) for rule_pack in self.rules]

        for entry in entries:
            if entry.name in manifest_names or entry.name.endswith("mods.toml"):
                manifest_entries[entry.name] = entry.data

            if entry.name.startswith("META-INF/") and entry.name.endswith(".SF"):
                with contextlib.suppress(Exception):
                    sf_contents[entry.name] = entry.data.decode("utf-8", errors="replace")

            for rule_pack, state in match_states:
                state.feed_entry(rule_pack.rules, entry)

            if is_java_class(entry.data):
                if entry.name.endswith(".class"):
                    class_entry_names.add(entry.name)
                self._analyze_class_entry(
                    entry, display_path, index, reconstructed_out=reconstructed_out
                )
                continue

            nested_path = f"{display_path}!/{entry.name}"

            if is_nested_archive(entry.data) and depth < self.max_nesting_depth:
                try:
                    nested_reader = ArchiveReader(entry.data, size_budget=size_budget)
                    self._analyze_archive_entries(
                        nested_reader.entries(),
                        nested_path,
                        index,
                        size_budget,
                        depth + 1,
                        reconstructed_out=reconstructed_out,
                    )
                except Exception:
                    index.add(
                        Evidence(
                            detector_id="archive",
                            severity=Severity.MEDIUM,
                            class_name="",
                            method_name="",
                            offset=0,
                            description=f"Nested archive cannot be read: {nested_path}",
                            matched_value=nested_path,
                        )
                    )
                continue

            for detector in self.detectors:
                archive_method = getattr(detector, "analyze_archive_entry", None)
                if archive_method is None:
                    continue
                evs = archive_method(entry.name, entry.data)
                for ev in evs:
                    ev.context = {**ev.context, "archive_path": nested_path}
                index.add_many(evs)

        for rule_pack, state in match_states:
            for match in rule_pack.evaluate(state):
                index.add(
                    Evidence(
                        detector_id=f"rule:{rule_pack.pack_id}:{match.rule_id}",
                        severity=match.severity,
                        class_name=match.class_name or "",
                        method_name="",
                        offset=0,
                        description=match.description,
                        matched_value=match.matched_value,
                        context={"rule_pack": rule_pack.pack_id, "rule_id": match.rule_id},
                    )
                )

        metadata: dict[str, Any] = {}
        if manifest_entries and depth == 0:
            manifest = parse_archive_manifest(manifest_entries)
            metadata["mod_id"] = manifest.mod_id
            metadata["loader"] = manifest.loader
            metadata["name"] = manifest.name
            metadata["version"] = manifest.version

        # Signature/manifest tamper checks only apply to the top-level
        # archive: a signature block found inside a nested archive
        # belongs to that inner mod's own signing, not to the outer
        # artifact being scanned.
        if depth == 0:
            from mcrataway.detectors.d14_signature_tamper import D14SignatureTamper
            d14 = D14SignatureTamper()
            if sf_contents:
                index.add_many(d14.analyze_signed_archive(class_entry_names, sf_contents))
            manifest_mf = manifest_entries.get("META-INF/MANIFEST.MF")
            if manifest_mf:
                manifest_text = manifest_mf.decode("utf-8", errors="replace")
                index.add_many(d14.analyze_manifest_class_path(manifest_text))

        return metadata

    def _analyze_class_entry(
        self,
        entry: ArchiveEntry,
        display_path: str,
        index: EvidenceIndex,
        reconstructed_out: list[ReconstructedString] | None = None,
    ) -> None:
        """Parse and run all detectors + string reconstruction on one
        Java class entry."""
        parsed = parse_class(entry.data)
        if not parsed:
            return

        entry_path = f"{display_path}!/{entry.name}"
        for detector in self.detectors:
            try:
                evs = detector.analyze_class(parsed)
            except Exception as exc:
                index.add(
                    Evidence(
                        detector_id=detector.detector_id,
                        severity=Severity.MEDIUM,
                        class_name=parsed.this_class,
                        method_name="",
                        offset=0,
                        description=(
                            f"Detector {detector.detector_id} failed on "
                            f"{entry_path}: {type(exc).__name__}: {exc}"
                        ),
                        matched_value="",
                        context={"archive_path": entry_path, "detector_error": "1"},
                    )
                )
                continue
            for ev in evs:
                ev.context = {**ev.context, "archive_path": entry_path}
            index.add_many(evs)

        reconstructed = reconstruct_strings(parsed)
        reconstructed_by_detector = self._evaluate_reconstructed_strings(parsed, reconstructed)
        index.add_many(reconstructed_by_detector)
        if reconstructed_out is not None:
            reconstructed_out.extend(reconstructed)

    def _evaluate_reconstructed_strings(
        self, class_file: Any, reconstructed: list[Any]
    ) -> list[Evidence]:
        """Run capability detectors against de-obfuscated strings.

        A hidden reference to a dangerous API (e.g. ``java.lang.Runtime``
        split into a byte array) is a *stronger* signal than the same
        string in plain text — a benign mod has no reason to hide it —
        so this only ever adds evidence, it does not replace the plain
        constant-pool scan.
        """
        if not reconstructed:
            return []

        values = [rs.value for rs in reconstructed if rs.value]
        evidence: list[Evidence] = []
        for detector in self.detectors:
            handler = getattr(detector, "analyze_reconstructed_strings", None)
            if handler is None:
                continue
            try:
                evs = handler(class_file, values)
            except Exception:
                continue
            for ev in evs:
                ev.context = {**ev.context, "reconstructed": "1"}
            evidence.extend(evs)

        # Keep a low-severity trace of the reconstruction itself for
        # forensic/report purposes (but do not let plain ldc strings —
        # handled separately — flood the report; only techniques other
        # than a bare ldc constant are traced here).
        for rs in reconstructed:
            if rs.technique == "ldc_string":
                continue
            evidence.append(
                Evidence(
                    detector_id="string_reconstruction",
                    severity=Severity.INFO,
                    class_name=rs.class_name,
                    method_name=rs.method_name,
                    offset=rs.offset,
                    description=f"Reconstructed string: {rs.value[:80]}",
                    matched_value=rs.value[:200],
                    context={"technique": rs.technique},
                )
            )
        return evidence

    def _scan_script(self, path: Path, file_hash: str) -> ArtifactResult:
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

    def _scan_config(self, path: Path, file_hash: str) -> ArtifactResult:
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
