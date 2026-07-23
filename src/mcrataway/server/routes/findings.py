"""Findings routes — query and list scan findings.

A *finding* in this API is a per-file result entry (``Verdict``) with
its nested list of detector findings. The optional ``severity`` filter
keeps only the file entries that contain at least one detector finding
with the requested severity.
"""

from typing import Any

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/")
async def list_findings(
    request: Request,
    severity: str | None = Query(default=None),  # noqa: B008
) -> list[dict[str, Any]]:
    """List all per-file findings across jobs, optionally filtered by severity.

    The filter compares against the severity of the *nested detector
    findings* (``finding["findings"][i]["severity"]``), not a top-level
    field, because each file entry aggregates many detector findings.
    """
    registry = request.app.state.job_registry
    wanted = severity.upper() if severity else None
    all_findings: list[dict[str, Any]] = []
    for job in registry.list_jobs():
        for finding in job.findings:
            if wanted is None:
                all_findings.append(finding)
                continue
            nested = finding.get("findings", [])
            if any(f.get("severity", "").upper() == wanted for f in nested):
                all_findings.append(finding)
    return all_findings


@router.get("/{finding_id}")
async def get_finding(finding_id: str, request: Request) -> dict[str, Any] | None:
    """Get a single per-file finding by SHA-256 or file path.

    ``finding_id`` is matched against the entry's ``sha256`` (exact) or
    the tail of its ``file_path``. SHA-256 matches are preferred because
    they are unambiguous; path-suffix matches are only used as a
    fallback for short identifiers and may collide.
    """
    registry = request.app.state.job_registry
    # First pass: exact SHA-256 match (unambiguous)
    for job in registry.list_jobs():
        for finding in job.findings:
            if finding.get("sha256", "") == finding_id:
                return dict(finding)
    # Second pass: path-suffix fallback
    for job in registry.list_jobs():
        for finding in job.findings:
            fp = finding.get("file_path", "")
            if fp and fp.endswith(finding_id):
                return dict(finding)
    return None
