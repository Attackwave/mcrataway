"""HTML report writer — self-contained, no external assets."""

import html
from pathlib import Path

from mcrataway.reporting.model import ScanReport


class HtmlWriter:
    """Write scan reports as self-contained HTML."""

    _CSS = """
    <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
    h1 { color: #58a6ff; margin-bottom: 1rem; }
    h2 { color: #8b949e; margin: 1.5rem 0 0.5rem; }
    .summary { display: flex; gap: 1rem; margin-bottom: 2rem; }
    .card { background: #161b22; border: 1px solid #30363d;
            border-radius: 6px; padding: 1rem; flex: 1; }
    .card h3 { font-size: 2rem; }
    .card.red h3 { color: #f85149; }
    .card.yellow h3 { color: #d29922; }
    .card.green h3 { color: #3fb950; }
    table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
    th, td { padding: 0.5rem 1rem; border: 1px solid #30363d; text-align: left; }
    th { background: #161b22; color: #58a6ff; }
    tr:nth-child(even) { background: #0d1117; }
    .severity-CRITICAL { color: #f85149; font-weight: bold; }
    .severity-HIGH { color: #f85149; }
    .severity-MEDIUM { color: #d29922; }
    .severity-LOW { color: #8b949e; }
    .verdict-MALICIOUS { color: #f85149; font-weight: bold; }
    .verdict-SUSPICIOUS { color: #d29922; }
    .verdict-CLEAN { color: #3fb950; }
    .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 1rem; }
    </style>
    """

    @staticmethod
    def write(report: ScanReport, path: Path) -> None:
        """Write a scan report as self-contained HTML."""
        e = html.escape
        html_parts: list[str] = []
        html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mcrataway Scan Report — {e(report.scan_id)}</title>
{HtmlWriter._CSS}
</head>
<body>
<h1>mcrataway Scan Report</h1>
<div class="meta">
  ID: {e(report.scan_id)} | {e(report.timestamp)} | {e(report.hostname)} | {e(report.os_name)}
</div>

<div class="summary">
  <div class="card">
    <h3>{report.total_files}</h3>
    <p>Total Files</p>
  </div>
  <div class="card red">
    <h3>{report.malicious_count}</h3>
    <p>Malicious</p>
  </div>
  <div class="card yellow">
    <h3>{report.suspicious_count}</h3>
    <p>Suspicious</p>
  </div>
  <div class="card green">
    <h3>{report.clean_count}</h3>
    <p>Clean</p>
  </div>
</div>

<h2>Findings</h2>
<table>
  <thead>
    <tr><th>File</th><th>Verdict</th><th>Severity</th><th>Detector</th><th>Description</th></tr>
  </thead>
  <tbody>
""")
        for file_report in report.files:
            if file_report.verdict.value == "CLEAN" or not file_report.findings:
                continue
            for finding in file_report.findings:
                html_parts.append(
                    f"    <tr>\n"
                    f"      <td>{e(file_report.file_path)}</td>\n"
                    f"      <td class=\"verdict-{e(file_report.verdict.value)}\">"
                    f"{e(file_report.verdict.value)}</td>\n"
                    f"      <td class=\"severity-{e(finding.severity.name)}\">"
                    f"{e(finding.severity.name)}</td>\n"
                    f"      <td>{e(finding.detector_id)}</td>\n"
                    f"      <td>{e(finding.description)}</td>\n"
                    f"    </tr>\n"
                )
        html_parts.append("  </tbody>\n</table>\n</body>\n</html>")
        # Explicit UTF-8 encoding — the HTML meta tag declares
        # charset="utf-8", so writing with the platform default
        # (cp1252 on Windows) would corrupt non-ASCII evidence
        # strings (paths with umlauts, etc.).
        path.write_text("".join(html_parts), encoding="utf-8")
