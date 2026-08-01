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
    from mcrataway.server.history import build_scan_report_from_job

    registry = request.app.state.job_registry
    job = registry.get_job(job_id)
    if not job:
        return {"error": "Job not found"}

    if format == "json":
        return build_scan_report_from_job(job).to_dict()

    return {"error": "Format not supported"}
