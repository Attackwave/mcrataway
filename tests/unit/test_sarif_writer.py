"""Tests for the SARIF report writer.

SARIF is the OASIS standard format consumed by GitHub Code Scanning,
Microsoft Defender, and other security tooling. A valid SARIF document
must have: version 2.1.0, at least one run, a tool.driver with rules,
and results whose ruleId references a declared rule.
"""

import json

from mcrataway.constants import Severity, Verdict
from mcrataway.reporting.model import FileReport, Finding, ScanReport
from mcrataway.reporting.sarif_writer import SarifWriter


def _make_report(verdict: Verdict, findings: list[Finding]) -> ScanReport:
    return ScanReport(
        scan_id="test-1",
        timestamp="2026-08-02T00:00:00Z",
        hostname="test",
        os_name="Linux",
        scanned_roots=["/tmp"],
        files=[
            FileReport(
                file_path="evil.jar",
                sha256="abc123",
                verdict=verdict,
                confidence=0.9,
                findings=findings,
            )
        ],
    )


def test_sarif_document_structure():
    report = _make_report(Verdict.MALICIOUS, [
        Finding("d01", Severity.CRITICAL, "Runtime.exec", "evil.jar"),
    ])
    sarif = SarifWriter.build(report)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "mcrataway"
    assert len(run["results"]) == 1


def test_sarif_rule_declared_before_result_references_it():
    """Every result.ruleId must appear in tool.driver.rules — a SARIF
    consumer that looks up the rule for a result must find it."""
    report = _make_report(Verdict.MALICIOUS, [
        Finding("d01", Severity.CRITICAL, "exec", "evil.jar"),
        Finding("d02", Severity.HIGH, "network", "evil.jar"),
    ])
    sarif = SarifWriter.build(report)

    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    for result in sarif["runs"][0]["results"]:
        assert result["ruleId"] in rule_ids


def test_sarif_severity_mapping():
    """CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note."""
    report = _make_report(Verdict.MALICIOUS, [
        Finding("d01", Severity.CRITICAL, "crit", "evil.jar"),
        Finding("d02", Severity.HIGH, "high", "evil.jar"),
        Finding("d04", Severity.MEDIUM, "med", "evil.jar"),
        Finding("d09", Severity.LOW, "low", "evil.jar"),
    ])
    sarif = SarifWriter.build(report)
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["d01"] == "error"
    assert levels["d02"] == "error"
    assert levels["d04"] == "warning"
    assert levels["d09"] == "note"


def test_sarif_includes_mitre_taxonomy():
    """A finding with a MITRE ATT&CK mapping must produce a taxonomy
    entry and a result relationship referencing it."""
    report = _make_report(Verdict.MALICIOUS, [
        Finding("d01", Severity.CRITICAL, "exec", "evil.jar"),
    ])
    sarif = SarifWriter.build(report)
    run = sarif["runs"][0]

    assert "taxonomies" in run
    taxa_ids = {t["id"] for t in run["taxonomies"][0]["taxa"]}
    assert "T1059" in taxa_ids

    result = run["results"][0]
    assert "relationships" in result
    assert result["relationships"][0]["target"]["id"] == "T1059"


def test_sarif_clean_file_with_no_findings_omitted():
    """A CLEAN file with no findings should not produce SARIF results
    — uploading noise to a code-scanning dashboard devalues real alerts."""
    report = ScanReport(
        scan_id="test-2", timestamp="t", hostname="h", os_name="os",
        files=[FileReport("clean.jar", "sha", Verdict.CLEAN, 1.0, [])],
    )
    sarif = SarifWriter.build(report)
    assert len(sarif["runs"][0]["results"]) == 0


def test_sarif_write_produces_valid_json(tmp_path):
    report = _make_report(Verdict.MALICIOUS, [
        Finding("d01", Severity.CRITICAL, "exec", "evil.jar"),
    ])
    out = tmp_path / "report.sarif"
    SarifWriter.write(report, out)
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
