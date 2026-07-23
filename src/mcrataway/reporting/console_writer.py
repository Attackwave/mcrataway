"""Console report writer using rich."""

from pathlib import Path

from rich.console import Console
from rich.table import Table

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

        # Findings table
        if report.malicious_count > 0 or report.suspicious_count > 0:
            self.console.print()
            findings_table = Table(title="Findings")
            findings_table.add_column("File")
            findings_table.add_column("Verdict")
            findings_table.add_column("Severity")
            findings_table.add_column("Detector")
            findings_table.add_column("Description")

            for file_report in report.files:
                if file_report.verdict.value == "CLEAN":
                    continue
                verdict_color = "red" if file_report.verdict.value == "MALICIOUS" else "yellow"
                for finding in file_report.findings:
                    severity_color = {
                        "CRITICAL": "bold red",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "cyan",
                    }.get(finding.severity.name, "white")
                    findings_table.add_row(
                        Path(file_report.file_path).name,
                        f"[{verdict_color}]{file_report.verdict.value}[/{verdict_color}]",
                        f"[{severity_color}]{finding.severity.name}[/{severity_color}]",
                        finding.detector_id,
                        finding.description[:60],
                    )

            self.console.print(findings_table)
