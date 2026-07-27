"""Top-level orchestration: samples -> RuleProposal.

Two entry points, matching the two supported operating modes:

- ``generate_from_directory``: local use or a self-hosted deployment
  that has samples staged on disk.
- ``generate_from_analyses``: a self-hosted integration (e.g. a
  platform scanning its own upload stream) that already ran
  ``analyze_sample`` per upload and accumulated SampleAnalysis objects
  in memory — no directory snapshot required.

No network code anywhere in this module or its dependencies
(features.py, correlate.py, propose.py) — a future central collection
point can reuse this engine unchanged instead of being rebuilt against
it.
"""

from __future__ import annotations

from pathlib import Path

from mcrataway.constants import Severity
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.discovery.walker import FileWalker
from mcrataway.rulegen.correlate import generalize
from mcrataway.rulegen.features import extract_candidates
from mcrataway.rulegen.propose import RuleProposal, propose_rule
from mcrataway.rulegen.sample import SampleAnalysis, _non_quarantining_engine, analyze_samples


class RuleGenEngine:
    """Orchestrates sample analysis, correlation, and rule proposal."""

    def __init__(
        self,
        scan_engine: ScanEngine | None = None,
        min_sample_fraction: float = 0.6,
    ) -> None:
        self.scan_engine = scan_engine or _non_quarantining_engine()
        self.min_sample_fraction = min_sample_fraction

    def generate_from_directory(
        self,
        sample_dir: Path,
        family: str,
        walker: FileWalker | None = None,
        severity: Severity = Severity.MEDIUM,
        condition: str = "count() >= 2",
    ) -> RuleProposal:
        """Walk sample_dir, analyze every sample, generalize, propose.

        Pure directory-in, object-out — no network, no assumption about
        where sample_dir came from.
        """
        walker = walker or FileWalker(restrict_to_scan_subdirs=False)
        paths = walker.walk(sample_dir)
        analyses = analyze_samples(paths, engine=self.scan_engine)
        return self.generate_from_analyses(
            analyses, family, severity=severity, condition=condition
        )

    def generate_from_analyses(
        self,
        analyses: list[SampleAnalysis],
        family: str,
        severity: Severity = Severity.MEDIUM,
        condition: str = "count() >= 2",
    ) -> RuleProposal:
        """Lower-level entry point for callers that already ran sample
        analysis themselves — the hook a self-hosted integration calls
        directly instead of writing samples to disk first."""
        per_sample_candidates = [extract_candidates(a) for a in analyses]
        generalized = generalize(per_sample_candidates, self.min_sample_fraction)
        return propose_rule(
            generalized, family, severity=severity, condition=condition
        )
