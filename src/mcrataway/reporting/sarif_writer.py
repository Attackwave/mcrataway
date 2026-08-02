"""SARIF report writer — outputs results in the OASIS Static Analysis
Results Interchange Format (SARIF), the lingua franca of GitHub Code
Scanning, Microsoft Defender, and other security tooling.

SARIF lets mcrataway findings flow directly into a CI/CD pipeline's
existing security-result dashboard (e.g. GitHub's code-scanning tab
when uploaded via ``github/codeql-action/upload-sarif``), alongside
results from CodeQL, Semgrep, etc., without any adapter.

The mapping:
  - Each detector/rule becomes a SARIF ``rule`` in ``run.tool.driver.rules``.
  - Each Finding becomes a SARIF ``result`` with ``ruleId`` = detector_id,
    ``level`` from severity, and ``locations`` from the file path +
    class/method context.
  - MITRE ATT&CK technique IDs from reporting.enrichment become
    ``taxa`` in ``run.taxonomies``, with each result tagging its
    applicable taxon via ``relationships``.
"""

import json
from pathlib import Path
from typing import Any

from mcrataway.constants import Severity, Verdict
from mcrataway.reporting.enrichment import context_for
from mcrataway.reporting.model import ScanReport

# SARIF severity levels are a fixed enum: note, warning, error.
# INFO/LOW -> note, MEDIUM -> warning, HIGH/CRITICAL -> error.
_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

# SARIF level for a file-level verdict (used for the summary result
# when a file has no individual findings but is still SUSPICIOUS).
_VERDICT_TO_LEVEL: dict[Verdict, str] = {
    Verdict.CLEAN: "none",
    Verdict.SUSPICIOUS: "warning",
    Verdict.MALICIOUS: "error",
}


class SarifWriter:
    """Write scan reports as SARIF 2.1.0 JSON."""

    @staticmethod
    def write(report: ScanReport, path: Path) -> None:
        """Write a scan report to a SARIF 2.1.0 JSON file."""
        sarif = SarifWriter.build(report)
        with open(path, "w") as f:
            json.dump(sarif, f, indent=2, default=str)

    @staticmethod
    def build(report: ScanReport) -> dict[str, Any]:
        """Build the SARIF 2.1.0 document from a scan report."""
        rules: list[dict[str, Any]] = []
        rule_ids_seen: set[str] = set()
        results: list[dict[str, Any]] = []
        taxa: list[dict[str, Any]] = []
        taxa_ids_seen: set[str] = set()

        for file_report in report.files:
            if not file_report.findings and file_report.verdict == Verdict.CLEAN:
                continue

            for finding in file_report.findings:
                ctx = context_for(finding.detector_id)

                if finding.detector_id not in rule_ids_seen:
                    rule_ids_seen.add(finding.detector_id)
                    rules.append({
                        "id": finding.detector_id,
                        "name": finding.detector_id,
                        "shortDescription": {
                            "text": ctx.plain_language,
                        },
                        "fullDescription": {
                            "text": ctx.recommended_action,
                        },
                        "defaultConfiguration": {
                            "level": _SEVERITY_TO_SARIF_LEVEL.get(
                                finding.severity, "note"
                            ),
                        },
                    })

                # Collect MITRE taxa for the taxonomy section.
                if ctx.mitre_id and ctx.mitre_id not in taxa_ids_seen:
                    taxa_ids_seen.add(ctx.mitre_id)
                    taxa.append({
                        "id": ctx.mitre_id,
                        "name": ctx.mitre_name or ctx.mitre_id,
                    })

                location = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_report.file_path,
                        },
                    },
                }
                msg_parts = [finding.description]
                if finding.class_name:
                    msg_parts.append(f"class: {finding.class_name}")
                if finding.method_name:
                    msg_parts.append(f"method: {finding.method_name}")

                result: dict[str, Any] = {
                    "ruleId": finding.detector_id,
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(
                        finding.severity, "note"
                    ),
                    "message": {"text": " — ".join(msg_parts)},
                    "locations": [location],
                    "partialFingerprints": {
                        "primaryLocationLineHash": file_report.sha256,
                    },
                }

                if ctx.mitre_id:
                    result["relationships"] = [{
                        "target": {
                            "id": ctx.mitre_id,
                            "toolComponent": {
                                "name": "MITRE ATT&CK",
                            },
                        },
                        "kinds": ["relevant"],
                    }]

                results.append(result)

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "mcrataway",
                    "informationUri": "https://github.com/Attackwave/mcrataway",
                    "rules": rules,
                },
            },
            "results": results,
        }

        if taxa:
            run["taxonomies"] = [{
                "name": "MITRE ATT&CK",
                "version": "14",
                "taxa": taxa,
            }]

        return {
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [run],
        }
