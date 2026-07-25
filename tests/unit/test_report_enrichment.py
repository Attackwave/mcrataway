"""Tests for report enrichment (task 6.6): MITRE ATT&CK mapping,
plain-language summaries, and significance-based finding ordering.
"""

from mcrataway.constants import Severity, Verdict
from mcrataway.reporting.enrichment import context_for, finding_sort_key
from mcrataway.reporting.model import Finding, FileReport


def test_known_detector_has_mitre_mapping() -> None:
    ctx = context_for("d01")
    assert ctx.mitre_id == "T1059"
    assert "command" in ctx.plain_language.lower()


def test_rule_match_has_context() -> None:
    ctx = context_for("rule:suspicious_indicators:session_token_exfil")
    assert ctx.plain_language
    assert ctx.recommended_action


def test_unknown_detector_falls_back_gracefully() -> None:
    ctx = context_for("d99_does_not_exist")
    assert ctx.plain_language
    assert ctx.recommended_action


def test_finding_to_dict_includes_enrichment() -> None:
    finding = Finding(
        detector_id="d08",
        severity=Severity.HIGH,
        description="Minecraft session access",
        file_path="mod.jar",
    )
    d = finding.to_dict()
    assert d["mitre_id"] == "T1528"
    assert "plain_language" in d
    assert "recommended_action" in d


def test_findings_sorted_most_significant_first() -> None:
    """A CRITICAL finding must sort before a HIGH finding, which must
    sort before a MEDIUM finding — regardless of the order they were
    added in (archive-encounter order, not significance order)."""
    report = FileReport(
        file_path="mod.jar",
        sha256="abc",
        verdict=Verdict.MALICIOUS,
        confidence=0.9,
        findings=[
            Finding("d04", Severity.MEDIUM, "file write", "mod.jar"),
            Finding("d01", Severity.CRITICAL, "exec", "mod.jar"),
            Finding("d02", Severity.HIGH, "network", "mod.jar"),
        ],
    )
    ordered = report.sorted_findings()
    assert [f.severity for f in ordered] == [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]


def test_behavior_chain_sorts_before_same_severity_single_finding() -> None:
    """A behavior_chain finding (a demonstrated complete, corroborated
    behavior) must sort ahead of a single-detector finding of the same
    severity — it is more conclusive."""
    key_chain = finding_sort_key(Severity.CRITICAL, "behavior_chain")
    key_single = finding_sort_key(Severity.CRITICAL, "d11")
    assert key_chain < key_single


def test_to_dict_uses_sorted_order() -> None:
    report = FileReport(
        file_path="mod.jar",
        sha256="abc",
        verdict=Verdict.MALICIOUS,
        confidence=0.9,
        findings=[
            Finding("d04", Severity.LOW, "file write", "mod.jar"),
            Finding("d01", Severity.CRITICAL, "exec", "mod.jar"),
        ],
    )
    d = report.to_dict()
    assert d["findings"][0]["severity"] == "CRITICAL"
    assert d["findings"][-1]["severity"] == "LOW"
