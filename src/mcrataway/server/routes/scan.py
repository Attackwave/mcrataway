"""Scan routes — start, stream, and query scan jobs."""

import asyncio
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect

from mcrataway.constants import JobStatus
from mcrataway.discovery.os_paths import discover_roots
from mcrataway.server.jobs import JobRegistry

router = APIRouter(prefix="/scan", tags=["scan"])


def _allowed_roots(config: Any) -> set[Path]:
    """The set of roots a scan is permitted to touch: auto-discovered
    Minecraft installations plus the user's configured custom roots.

    Any *other* path — however it reached this endpoint — is rejected.
    This is a server-side allowlist, not a client-supplied one: the
    ``roots`` query parameter is treated as "which of the roots the
    user has already enabled to include this time", not as "scan
    whatever path is named here". Without this, a request that reaches
    this endpoint (e.g. via a same-origin bug, a compromised browser
    extension, or a future auth regression) could direct the scanner
    — and, if quarantine is enabled, file removal — at an arbitrary
    path on the filesystem.
    """
    allowed: set[Path] = set()
    for p in discover_roots(config.custom_roots):
        try:
            allowed.add(Path(p).resolve())
        except Exception:
            continue
    for c in config.custom_roots:
        try:
            resolved = Path(c).expanduser().resolve()
            if resolved.exists():
                allowed.add(resolved)
        except Exception:
            continue
    return allowed


@router.post("/")
async def start_scan(
    request: Request,
    roots: list[str] | None = Query(default=None),  # noqa: B008
    auto_discover: bool = Query(default=False),  # noqa: B008
) -> dict[str, Any]:
    """Start a new scan job.

    *roots*, when provided, selects a subset of the currently
    discovered/configured roots to scan this run — it is validated
    against :func:`_allowed_roots`, not used as-is, so a caller cannot
    direct the scan at an arbitrary path outside that allowlist.
    """
    from mcrataway.server.worker import _run_scan

    registry: JobRegistry = request.app.state.job_registry
    config = request.app.state.config

    allowed = _allowed_roots(config)

    if auto_discover:
        actual_roots = [str(p) for p in allowed]
    elif roots:
        # Only accept caller-supplied roots that resolve to something
        # already in the allowlist (discovered or configured custom
        # root) — do not trust arbitrary paths from the request.
        actual_roots = []
        for r in roots:
            try:
                resolved = Path(r).resolve()
            except Exception:
                continue
            if resolved in allowed:
                actual_roots.append(str(resolved))
    else:
        actual_roots = []

    job_id = registry.create_job(actual_roots)
    if job_id is None:
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many concurrent scan jobs — finish or wait for an "
                "existing scan to complete before starting another."
            ),
        )

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

    WebSocket handshakes are not routed through the HTTP middleware
    stack (``app.middleware("http")`` only wraps regular requests), so
    the Origin/DNS-rebinding check has to be duplicated here rather
    than relying on ``token_guard``.
    """
    from mcrataway.constants import TOKEN_FILE
    from mcrataway.server.auth import verify_origin_headers

    if not verify_origin_headers(
        websocket.headers.get("origin", ""), websocket.headers.get("host", "")
    ):
        await websocket.close(code=4403)
        return

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
