"""Tests for behavior-chain correlation (core/behavior_chains.py).

See the module docstring for the rationale: a single capability
detector firing (e.g. D02 network I/O alone, or D03 dynamic loading
alone) is common in entirely benign mods and should not weigh heavily
on its own; a *complete* multi-step behavior is a much stronger signal
and should escalate.

What makes a download chain specific is the destination, not the number
of links: D02 only reaches MEDIUM when the URL is hidden, reconstructed
or a known exfiltration endpoint, while a plaintext URL is what every
update checker contains. The severity gates below keep the same APIs
that appear harmlessly in every service loader and native-extraction
library (kotlinx's FastServiceLoader, javacpp's Loader, JNA's Native)
from adding up to a chain.
"""

from mcrataway.constants import Severity, Verdict
from mcrataway.core.behavior_chains import evaluate_chains
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.core.verdict import VerdictAggregator


def _loader_class(idx: EvidenceIndex, **severities: Severity) -> None:
    """Add D02/D03 findings for one class, with the given severities
    (defaults describe the full, real behavior: a hidden destination
    plus dynamic class loading)."""
    for detector_id, severity in (
        ("d02", severities.get("d02", Severity.HIGH)),
        ("d03", severities.get("d03", Severity.MEDIUM)),
    ):
        idx.add(Evidence(detector_id, severity, "com/evil/Loader", "", 0, f"{detector_id} finding"))


def test_complete_chain_escalates_to_critical() -> None:
    idx = EvidenceIndex()
    _loader_class(idx)
    evaluate_chains(idx)

    chain_evidence = [e for e in idx.evidence if e.detector_id == "behavior_chain"]
    assert len(chain_evidence) == 1
    assert chain_evidence[0].severity == Severity.CRITICAL
    assert chain_evidence[0].context["chain"] == "reload_and_execute"


def test_hidden_download_handed_to_the_os_is_a_chain() -> None:
    """The same fetch, executed as a process instead of loaded in-process
    (Dropper fixture shape): a different second half, the same hidden
    destination requirement."""
    idx = EvidenceIndex()
    idx.add(Evidence("d02", Severity.MEDIUM, "com/evil/Dropper", "", 0, "reconstructed URL"))
    idx.add(Evidence("d01", Severity.HIGH, "com/evil/Dropper", "", 8, "ProcessBuilder.start"))
    evaluate_chains(idx)

    chain_evidence = [e for e in idx.evidence if e.detector_id == "behavior_chain"]
    assert len(chain_evidence) == 1
    assert chain_evidence[0].context["chain"] == "hidden_download_and_exec"


def test_plaintext_url_plus_exec_is_not_a_chain() -> None:
    """The documented limit of the model: a plaintext URL is a string
    every update checker has, so fetching from one and running a system
    tool stays two capabilities, not a complete behavior."""
    idx = EvidenceIndex()
    idx.add(Evidence("d02", Severity.LOW, "com/evil/Updater", "", 0, 'plain "http://" URL string'))
    idx.add(Evidence("d01", Severity.HIGH, "com/evil/Updater", "", 8, "Runtime.exec"))
    evaluate_chains(idx)

    assert not [e for e in idx.evidence if e.detector_id == "behavior_chain"]


def test_complete_chain_raises_weaker_sibling_findings() -> None:
    """The weaker findings of a participating detector elsewhere in the
    same class must be raised to at least MEDIUM once the chain is
    confirmed — otherwise VerdictAggregator's thresholds barely notice
    them despite a demonstrated complete behavior."""
    idx = EvidenceIndex()
    _loader_class(idx)
    idx.add(Evidence("d02", Severity.INFO, "com/evil/Loader", "", 8, "URL construction"))
    evaluate_chains(idx)

    d02_evidence = [e for e in idx.evidence if e.detector_id == "d02"]
    assert len(d02_evidence) == 2
    assert all(e.severity >= Severity.MEDIUM for e in d02_evidence)


def test_chain_needs_meaningful_links() -> None:
    """Regression: a plaintext URL next to a Class.forName is a service
    loader — not a download-and-load chain. Rating that combination
    CRITICAL put a "complete behavior chain" finding on kotlinx's
    FastServiceLoader, flatlaf's UIDefaultsLoader and javacpp's Loader."""
    idx = EvidenceIndex()
    _loader_class(idx, d02=Severity.LOW, d03=Severity.MEDIUM)
    evaluate_chains(idx)

    assert not [e for e in idx.evidence if e.detector_id == "behavior_chain"]


def test_chain_needs_one_strong_link() -> None:
    """Both links at MEDIUM is a mod doing two ordinary things; no single
    one of them is specific enough to carry a complete behavior on its
    own."""
    idx = EvidenceIndex()
    _loader_class(idx, d02=Severity.MEDIUM, d03=Severity.MEDIUM)
    evaluate_chains(idx)

    assert not [e for e in idx.evidence if e.detector_id == "behavior_chain"]


def test_lone_medium_finding_is_downgraded() -> None:
    """A single chain-participant capability (D03 dynamic loading) with
    no other link present must be downgraded — this is the main
    false-positive lever: a mod that merely calls Class.forName is not
    suspicious on that basis alone."""
    idx = EvidenceIndex()
    idx.add(
        Evidence("d03", Severity.MEDIUM, "com/example/PluginLoader", "", 0, "Class.forName")
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
    idx.add(Evidence(
        "d02", Severity.HIGH, "com/example/Exfil", "", 0,
        "Discord webhook URL detected",
    ))
    evaluate_chains(idx)

    assert len(idx.evidence) == 1
    assert idx.evidence[0].severity == Severity.HIGH
    assert "chain_downgraded" not in idx.evidence[0].context


def test_non_chain_detector_is_untouched() -> None:
    """A detector not part of any defined chain (e.g. D13 mixin abuse)
    must be left alone regardless of severity — only detectors listed in
    a BehaviorChain participate in lone-finding downgrade logic."""
    idx = EvidenceIndex()
    idx.add(Evidence("d13", Severity.MEDIUM, "com/example/Mixin", "", 0, "session redirect"))
    evaluate_chains(idx)

    assert idx.evidence[0].severity == Severity.MEDIUM
    assert "chain_downgraded" not in idx.evidence[0].context


def test_reconstructed_evidence_is_exempt_from_downgrade() -> None:
    """Evidence already marked as coming from a reconstructed
    (de-obfuscated) string must not be downgraded — the concealment
    itself is already a stronger signal than the plain finding, and
    chain analysis should not undo that."""
    idx = EvidenceIndex()
    idx.add(
        Evidence(
            "d02",
            Severity.MEDIUM,
            "com/example/Hidden",
            "",
            0,
            "reconstructed network destination",
            context={"reconstructed": "1"},
        )
    )
    evaluate_chains(idx)

    assert idx.evidence[0].severity == Severity.MEDIUM


def test_partial_chain_is_not_downgraded() -> None:
    """Two links of a chain present, but not a complete chain (D08
    credential access + D02 network, no obfuscation link), is a partial
    correlation and should be left to the detectors' own severities
    rather than downgraded as if it were a lone finding."""
    idx = EvidenceIndex()
    idx.add(Evidence("d08", Severity.HIGH, "com/example/Partial", "", 0, "credential file path"))
    idx.add(Evidence("d02", Severity.MEDIUM, "com/example/Partial", "", 0, "network call"))
    evaluate_chains(idx)

    severities = {e.detector_id: e.severity for e in idx.evidence}
    assert severities["d08"] == Severity.HIGH
    assert severities["d02"] == Severity.MEDIUM


def test_chain_escalation_drives_malicious_verdict() -> None:
    """End-to-end: a complete chain must be enough on its own to reach
    a MALICIOUS verdict via the CRITICAL behavior_chain evidence."""
    idx = EvidenceIndex()
    _loader_class(idx)
    evaluate_chains(idx)

    verdict, confidence = VerdictAggregator().compute(idx)
    assert verdict == Verdict.MALICIOUS
    assert confidence > 0.5
