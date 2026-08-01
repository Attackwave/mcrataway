"""Console report writer using rich."""

from pathlib import Path

from rich.console import Console
from rich.table import Table

from mcrataway.reporting.enrichment import context_for
from mcrataway.reporting.model import ScanReport


class ConsoleWriter:
    """Print scan reports to the console using rich."""

    def __init__(self) -> None:
        self.console = Console()

    def print_report(self, report: ScanReport) -> None:
        """Print a full scan report."""
        self.console.print()
        self.console.print("[bold]Scan Report[/bold]")
        self.console.print(f"  ID: {report.scan_id}")
        self.console.print(f"  Time: {report.timestamp}")
        self.console.print(f"  Host: {report.hostname}")
        self.console.print(f"  Roots: {len(report.scanned_roots)}")
        self.console.print()

        # Summary table
        summary = Table(title="Summary")
        summary.add_column("Metric")
        summary.add_column("Count")
        summary.add_row("Total Files", str(report.total_files))
        summary.add_row("Malicious", f"[red]{report.malicious_count}[/red]")
        summary.add_row("Suspicious", f"[yellow]{report.suspicious_count}[/yellow]")
        summary.add_row("Clean", f"[green]{report.clean_count}[/green]")
        self.console.print(summary)

        # Findings table — sorted most-significant-first (see
        # reporting.enrichment.finding_sort_key) rather than in
        # archive-encounter order, so the finding that would actually
        # change a user's decision appears first.
        if report.malicious_count > 0 or report.suspicious_count > 0:
            self.console.print()
            findings_table = Table(title="Findings")
            findings_table.add_column("File")
            findings_table.add_column("Verdict")
            findings_table.add_column("Severity")
            findings_table.add_column("Detector")
            findings_table.add_column("What this means")

            for file_report in report.files:
                if file_report.verdict.value == "CLEAN":
                    continue
                verdict_color = "red" if file_report.verdict.value == "MALICIOUS" else "yellow"
                for finding in file_report.sorted_findings():
                    severity_color = {
                        "CRITICAL": "bold red",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "cyan",
                    }.get(finding.severity.name, "white")
                    ctx = context_for(finding.detector_id)
                    findings_table.add_row(
                        Path(file_report.file_path).name,
                        f"[{verdict_color}]{file_report.verdict.value}[/{verdict_color}]",
                        f"[{severity_color}]{finding.severity.name}[/{severity_color}]",
                        finding.detector_id,
                        ctx.plain_language,
                    )

            self.console.print(findings_table)

        # A failed quarantine attempt is the most dangerous silent
        # failure mode this tool has: the verdict says MALICIOUS/
        # SUSPICIOUS but the file was NOT actually isolated (disk
        # full, permission denied, etc — see
        # core/quarantine.py:QuarantineOutcome.FAILED). Surface it
        # loudly here rather than leaving it only in the JSON report's
        # metadata field, where a user would have to know to look for it.
        failed = [
            f for f in report.files if f.metadata.get("quarantine_failed")
        ]
        if failed:
            self.console.print()
            self.console.print(
                "[bold red]WARNING: quarantine failed for the following "
                "file(s) — they are still on disk, unmodified:[/bold red]"
            )
            for f in failed:
                self.console.print(f"  [red]{f.file_path}[/red]")
            self.console.print(
                "[red]Check disk space and file permissions, then re-run "
                "the scan.[/red]"
            )
