"""Analyze one or more malware samples with full evidence retained.

A thin wrapper around :class:`~mcrataway.core.scan_engine.ScanEngine`
that keeps the per-archive :class:`~mcrataway.core.evidence.EvidenceIndex`
and the un-truncated :class:`~mcrataway.parsers.string_reconstructor.ReconstructedString`
list, both of which a normal scan discards after building the flattened
``Finding`` list.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcrataway.core.evidence import EvidenceIndex
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ArtifactResult, ScanEngine
from mcrataway.parsers.string_reconstructor import ReconstructedString


def _non_quarantining_engine(**kwargs: object) -> ScanEngine:
    """Default ScanEngine for rulegen: quarantine actions are always
    disabled. rulegen analyzes samples that are often already-known
    malware (e.g. a directory of confirmed samples used to derive a
    rule) — it must never move or delete the caller's input files as a
    side effect of analyzing them, unlike a normal protective scan."""
    quarantine = QuarantineManager(
        do_quarantine_malicious=False, do_quarantine_suspicious=False
    )
    return ScanEngine(quarantine=quarantine, **kwargs)  # type: ignore[arg-type]


@dataclass
class SampleAnalysis:
    """Result of scanning one sample with full evidence retained."""

    file_path: str
    file_hash: str
    evidence_index: EvidenceIndex
    reconstructed_strings: list[ReconstructedString]
    artifact_result: ArtifactResult


def analyze_sample(path: Path, engine: ScanEngine | None = None) -> SampleAnalysis:
    """Scan one file with full evidence retained.

    Raises ValueError if *path* is not a JAR/ZIP archive — rulegen only
    operates on archive samples, consistent with ScanEngine only
    retaining an EvidenceIndex for the archive scan path.
    """
    engine = engine or _non_quarantining_engine()
    results = engine.scan_files([path], keep_evidence_index=True)
    result = results[0]
    if result.evidence_index is None:
        raise ValueError(f"{path} did not produce an evidence index (not a JAR/ZIP archive?)")
    return SampleAnalysis(
        file_path=result.file_path,
        file_hash=result.file_hash,
        evidence_index=result.evidence_index,
        reconstructed_strings=result.reconstructed_strings or [],
        artifact_result=result,
    )


def analyze_samples(
    paths: list[Path], engine: ScanEngine | None = None, max_workers: int = 4,
) -> list[SampleAnalysis]:
    """Batch variant. Delegates to ScanEngine.scan_files's own
    concurrency rather than reimplementing it."""
    engine = engine or _non_quarantining_engine(max_workers=max_workers)
    results = engine.scan_files(paths, keep_evidence_index=True)
    analyses = []
    for result in results:
        if result.evidence_index is None:
            continue
        analyses.append(
            SampleAnalysis(
                file_path=result.file_path,
                file_hash=result.file_hash,
                evidence_index=result.evidence_index,
                reconstructed_strings=result.reconstructed_strings or [],
                artifact_result=result,
            )
        )
    return analyses
