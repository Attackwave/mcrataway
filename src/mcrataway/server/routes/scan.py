"""Scan routes — start, stream, and query scan jobs."""

import asyncio
from typing import Any

from fastapi import APIRouter, Query, Request, WebSocket, WebSocketDisconnect

from mcrataway.constants import JobStatus
from mcrataway.discovery.os_paths import discover_roots
from mcrataway.server.jobs import JobRegistry

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/")
async def start_scan(
    request: Request,
    roots: list[str] | None = Query(default=None),  # noqa: B008
    auto_discover: bool = Query(default=False),  # noqa: B008
) -> dict[str, Any]:
    """Start a new scan job."""
    from mcrataway.server.worker import _run_scan

    registry: JobRegistry = request.app.state.job_registry
    config = request.app.state.config

    if auto_discover:
        discovered = discover_roots(config.custom_roots)
        actual_roots = [str(p) for p in discovered]
    else:
        # Only use explicitly supplied roots; do NOT fall back to
        # discover_roots when the caller did not request auto-discovery,
        # otherwise scanning the user's entire system would happen silently.
        actual_roots = list(roots) if roots else []

    job_id = registry.create_job(actual_roots)

    async def run_background() -> None:
        try:
            loop = asyncio.get_running_loop()

            def on_event(event: dict[str, Any]) -> None:
                """Thread-safe callback — forward events to the registry on the event loop."""
                if event["type"] == "progress":
                    loop.call_soon_threadsafe(
                        registry.update_progress,
                        job_id,
                        event["percent"],
                        event["scanned"],
                        event["total"],
                    )
                elif event["type"] == "verdict":
                    loop.call_soon_threadsafe(registry.add_verdict, job_id, event["verdict"])

            result = await asyncio.to_thread(
                _run_scan,
                job_id,
                actual_roots,
                auto_discover,
                {
                    "custom_roots": config.custom_roots,
                    "max_workers": config.max_workers,
                    "quarantine_suspicious": config.quarantine_suspicious,
                    "quarantine_malicious": config.quarantine_malicious,
                    "scan_archives": config.scan_archives,
                    "scan_scripts": config.scan_scripts,
                    "scan_configs": config.scan_configs,
                    "max_recursion_depth": config.max_recursion_depth,
                },
                on_event,
            )

            # Emit all per-file findings BEFORE the terminal status
            # event. The frontend closes its WebSocket on receiving
            # status=COMPLETED, so emitting findings afterwards would
            # drop every CLEAN file (and the matching finding events)
            # from the live view.
            for r in result["results"]:
                registry.add_finding(job_id, r)
            registry.update_status(job_id, JobStatus.COMPLETED)
            registry.emit_done(job_id)

        except Exception as e:
            registry.update_status(job_id, JobStatus.FAILED, error=str(e))
            registry.emit_done(job_id)

    # Store the task reference so it is not garbage-collected before completion
    task = asyncio.create_task(run_background())
    registry.track_task(job_id, task)

    return {"job_id": job_id, "status": "PENDING", "roots": actual_roots}


@router.get("/{job_id}")
async def get_job(job_id: str, request: Request) -> dict[str, Any]:
    """Get job status and partial results."""
    registry: JobRegistry = request.app.state.job_registry
    job = registry.get_job(job_id)
    if not job:
        return {"error": "Job not found"}
    return {
        "job_id": job.job_id,
        "status": job.status.value,
        "progress": job.progress,
        "total_files": job.total_files,
        "scanned_files": job.scanned_files,
        "error": job.error,
    }


@router.websocket("/{job_id}/stream")
async def stream_job(websocket: WebSocket) -> None:
    """WebSocket stream for live job progress and findings.

    Browsers cannot set custom headers on WebSocket handshakes, so we
    also accept the token as a ``?token=`` query parameter when the
    token file is configured.
    """
    from mcrataway.constants import TOKEN_FILE
    if TOKEN_FILE.exists():
        token = websocket.query_params.get("token", "")
        try:
            expected = TOKEN_FILE.read_text().strip()
        except Exception:
            expected = ""
        # Mirror auth.verify_token: an empty configured token is a
        # misconfiguration, not an open mode. compare_digest("","")
        # would return True and silently bypass auth, so deny first.
        if not expected:
            await websocket.close(code=4401)
            return
        import hmac
        if not hmac.compare_digest(token, expected):
            await websocket.close(code=4401)
            return

    registry: JobRegistry = websocket.app.state.job_registry
    job_id = websocket.path_params["job_id"]

    await websocket.accept()
    queue = await registry.subscribe(job_id)

    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
            if event.get("type") in ("done", "error"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        registry.unsubscribe(job_id, queue)
