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

    Keep only the latest unique finding per file path, and filter out
    files that no longer exist on disk. Jobs dismissed via
    POST /findings/clear are skipped — see JobRegistry.dismiss_all_findings.
    """
    import os
    registry = request.app.state.job_registry
    wanted = severity.upper() if severity else None
    findings_map: dict[str, dict[str, Any]] = {}

    for job in registry.list_jobs():
        if registry.is_dismissed(job.job_id):
            continue
        for finding in job.findings:
            fp = finding.get("file_path", "")
            if not fp:
                continue
            
            # If the file has been deleted or quarantined, it's no longer a threat
            if not os.path.exists(fp):
                continue
                
            if wanted is not None:
                nested = finding.get("findings", [])
                if not any(f.get("severity", "").upper() == wanted for f in nested):
                    continue
            
            # Overwrite with the latest finding for this file path
            findings_map[fp] = finding
            
    return list(findings_map.values())


@router.post("/clear")
async def clear_findings(request: Request) -> dict[str, Any]:
    """Dismiss all currently-visible findings from the Findings view.

    This does not delete any job data or affect the persisted scan
    History — it only hides them from GET /findings/ until a new scan
    produces fresh findings. See JobRegistry.dismiss_all_findings.
    """
    registry = request.app.state.job_registry
    registry.dismiss_all_findings()
    return {"success": True}


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
