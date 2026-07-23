"""Reports routes — get scan reports in JSON or HTML format."""

from typing import Any

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{job_id}")
async def get_report(
    job_id: str,
    request: Request,
    format: str = Query(default="json"),  # noqa: B008
) -> dict[str, Any]:
    """Get a scan report for a completed job."""
    from mcrataway.constants import Severity, Verdict
    from mcrataway.reporting.model import FileReport, Finding, ScanReport

    registry = request.app.state.job_registry
    job = registry.get_job(job_id)
    if not job:
        return {"error": "Job not found"}

    if format == "json":
        file_reports: list[FileReport] = []
        # Iterate job.findings (all scanned files, including CLEAN)
        # rather than job.verdicts (only MALICIOUS/SUSPICIOUS). Using
        # verdicts would silently drop every clean file from the
        # report, making clean_count always 0 and total_files wrong.
        for v in job.findings:
            # Parse the file's verdict outside the inner findings loop
            # so files with no detector findings (e.g. CLEAN files) do
            # not leave verdict_val unbound, which would crash the
            # FileReport construction with UnboundLocalError.
            try:
                verdict_val = Verdict(str(v.get("verdict", "CLEAN")).upper())
            except ValueError:
                verdict_val = Verdict.CLEAN
            findings = []
            for f in v.get("findings", []):
                # Be lenient with severity casing/values — a corrupted
                # job store or a hand-edited JSON should not crash the
                # report endpoint with a KeyError from Severity[...].
                sev_name = f.get("severity", "INFO")
                try:
                    severity = Severity[str(sev_name).upper()]
                except (KeyError, AttributeError):
                    severity = Severity.INFO
                findings.append(
                    Finding(
                        detector_id=f.get("detector_id", ""),
                        severity=severity,
                        description=f.get("description", ""),
                        file_path=f.get("file_path", ""),
                        class_name=f.get("class_name", ""),
                        method_name=f.get("method_name", ""),
                        matched_value=f.get("matched_value", ""),
                    )
                )
            file_reports.append(
                FileReport(
                    file_path=v.get("file_path", ""),
                    sha256=v.get("sha256", ""),
                    verdict=verdict_val,
                    confidence=v.get("confidence", 0.0),
                    findings=findings,
                    metadata=v.get("metadata", {}),
                )
            )

        report = ScanReport(
            scan_id=job_id,
            timestamp=job.started_at or "",
            hostname="mcrataway-server",
            os_name="Python",
            scanned_roots=job.roots,
            files=file_reports,
        )
        return report.to_dict()

    return {"error": "Format not supported"}
