"""History routes — list, view, and delete persisted scan reports.

Backed by server.history.HistoryStore, which survives a server
restart — unlike GET /reports/{job_id} (routes/reports.py), which
only ever reflects the currently in-memory JobRegistry.
"""

from typing import Any

from fastapi import APIRouter, Request

router = APIRouter(prefix="/history", tags=["history"])


@router.get("/")
async def list_history(request: Request) -> list[dict[str, Any]]:
    """List past scans, newest first."""
    store = request.app.state.history_store
    return [entry.to_dict() for entry in store.list_entries()]


@router.get("/{scan_id}")
async def get_history_report(scan_id: str, request: Request) -> dict[str, Any]:
    """Get the full persisted report for one past scan."""
    store = request.app.state.history_store
    report: dict[str, Any] | None = store.get_report(scan_id)
    if report is None:
        return {"error": "Scan not found"}
    return report


@router.delete("")
@router.delete("/")
@router.delete("/purge")
@router.post("/purge")
async def purge_history(request: Request) -> dict[str, Any]:
    """Permanently delete every persisted scan report."""
    store = request.app.state.history_store
    count = store.purge()
    return {"success": True, "purged_count": count}


@router.delete("/{scan_id}")
async def delete_history_entry(scan_id: str, request: Request) -> dict[str, Any]:
    """Permanently delete one past scan's persisted report."""
    store = request.app.state.history_store
    return {"success": store.delete(scan_id)}
