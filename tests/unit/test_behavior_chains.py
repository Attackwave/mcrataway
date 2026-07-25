"""Tests for behavior-chain correlation (core/behavior_chains.py).

See the module docstring for the rationale: a single capability
detector firing (e.g. D04 filesystem access alone) is common in
entirely benign mods and should not weigh heavily on its own; a
*complete* multi-step behavior (e.g. D07 native load + D04 filesystem
write in the same class — staging and loading an unpacked native
payload) is a much stronger signal and should escalate.
"""

from mcrataway.constants import Severity, Verdict
from mcrataway.core.behavior_chains import evaluate_chains
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.core.verdict import VerdictAggregator


def test_complete_chain_escalates_to_critical() -> None:
    idx = EvidenceIndex()
    idx.add(Evidence("d07", Severity.HIGH, "com/evil/Loader", "", 0, "System.loadLibrary"))
    idx.add(Evidence("d04", Severity.INFO, "com/evil/Loader", "", 0, "FileOutputStream"))
    evaluate_chains(idx)

    chain_evidence = [e for e in idx.evidence if e.detector_id == "behavior_chain"]
    assert len(chain_evidence) == 1
    assert chain_evidence[0].severity == Severity.CRITICAL
    assert chain_evidence[0].context["chain"] == "native_payload_staging"


def test_complete_chain_raises_weak_links_to_medium() -> None:
    """A chain link that a detector rated INFO/LOW must be raised to at
    least MEDIUM once it is confirmed to be part of a complete chain —
    otherwise VerdictAggregator's thresholds barely notice it despite
    a demonstrated complete behavior."""
    idx = EvidenceIndex()
    idx.add(Evidence("d07", Severity.HIGH, "com/evil/Loader", "", 0, "System.loadLibrary"))
    idx.add(Evidence("d04", Severity.INFO, "com/evil/Loader", "", 0, "FileOutputStream"))
    evaluate_chains(idx)

    d04_evidence = [e for e in idx.evidence if e.detector_id == "d04"]
    assert len(d04_evidence) == 1
    assert d04_evidence[0].severity >= Severity.MEDIUM


def test_lone_medium_finding_is_downgraded() -> None:
    """A single chain-participant capability (D04) with no other link
    present must be downgraded — this is the main false-positive
    lever: a mod that merely writes a config file is not suspicious on
    that basis alone."""
    idx = EvidenceIndex()
    idx.add(
        Evidence("d04", Severity.MEDIUM, "com/example/ConfigWriter", "", 0, "writes config file")
    )
    evaluate_chains(idx)

    assert len(idx.evidence) == 1
    assert idx.evidence[0].severity == Severity.LOW
    assert idx.evidence[0].context.get("chain_downgraded") == "1"


def test_lone_high_finding_is_not_downgraded() -> None:
    """A HIGH/CRITICAL finding from a single detector (e.g. a Discord
    webhook URL) is already a strong, specific signal on its own and
    must not be softened by chain analysis — chain analysis targets
    weak/ambiguous single capabilities, not detectors that already
    concluded high confidence."""
    idx = EvidenceIndex()
    idx.add(Evidence("d02", Severity.HIGH, "com/example/Exfil", "", 0, "Discord webhook URL detected"))
    evaluate_chains(idx)

    assert len(idx.evidence) == 1
    assert idx.evidence[0].severity == Severity.HIGH
    assert "chain_downgraded" not in idx.evidence[0].context


def test_non_chain_detector_is_untouched() -> None:
    """A detector not part of any defined chain (e.g. D01 process
    execution, D13 mixin abuse) must be left alone regardless of
    severity — only detectors listed in a BehaviorChain participate in
    lone-finding downgrade logic."""
    idx = EvidenceIndex()
    idx.add(Evidence("d01", Severity.HIGH, "com/example/Exec", "", 0, "Runtime.exec() call"))
    evaluate_chains(idx)

    assert idx.evidence[0].severity == Severity.HIGH
    assert "chain_downgraded" not in idx.evidence[0].context


def test_reconstructed_evidence_is_exempt_from_downgrade() -> None:
    """Evidence already marked as coming from a reconstructed
    (de-obfuscated) string must not be downgraded — the concealment
    itself is already a stronger signal than the plain finding, and
    chain analysis should not undo that."""
    idx = EvidenceIndex()
    idx.add(
        Evidence(
            "d04",
            Severity.MEDIUM,
            "com/example/Hidden",
            "",
            0,
            "reconstructed filesystem reference",
            context={"reconstructed": "1"},
        )
    )
    evaluate_chains(idx)

    assert idx.evidence[0].severity == Severity.MEDIUM


def test_partial_chain_two_of_three_links_not_downgraded() -> None:
    """Two of three links from a chain present (but not a complete
    chain) is still a partial correlation and should be left to the
    detectors' own severities rather than downgraded as if it were a
    lone finding."""
    idx = EvidenceIndex()
    idx.add(Evidence("d02", Severity.MEDIUM, "com/example/Partial", "", 0, "network call"))
    idx.add(Evidence("d04", Severity.MEDIUM, "com/example/Partial", "", 0, "file write"))
    evaluate_chains(idx)

    severities = {e.detector_id: e.severity for e in idx.evidence}
    assert severities["d02"] == Severity.MEDIUM
    assert severities["d04"] == Severity.MEDIUM


def test_chain_escalation_drives_malicious_verdict() -> None:
    """End-to-end: a complete chain must be enough on its own to reach
    a MALICIOUS verdict via the CRITICAL behavior_chain evidence."""
    idx = EvidenceIndex()
    idx.add(Evidence("d07", Severity.HIGH, "com/evil/Loader", "", 0, "System.loadLibrary"))
    idx.add(Evidence("d04", Severity.INFO, "com/evil/Loader", "", 0, "FileOutputStream"))
    evaluate_chains(idx)

    verdict, confidence = VerdictAggregator().compute(idx)
    assert verdict == Verdict.MALICIOUS
    assert confidence > 0.5
