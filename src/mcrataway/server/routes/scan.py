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


# --- WebSocket ticket auth -------------------------------------------------
# Browsers cannot set custom headers on WebSocket handshakes, so the
# long-lived auth token would have to be passed as ``?token=`` in the
# WS URL — which leaks into access logs and Referer headers. Instead,
# the frontend fetches a short-lived, single-use ticket from this
# endpoint (a normal HTTP GET, which CAN carry the X-Mcrataway-Token
# header), then opens the WS with ``?ticket=``. The ticket is valid
# for 60 seconds and can only be used once, so a leaked ticket (from a
# log or Referer) is useless after one use or after expiry.
#
# Route order matters: /ws-ticket must be registered BEFORE /{job_id}
# or FastAPI matches "ws-ticket" as a job_id path parameter.

_TICKET_TTL_SECONDS = 60
_tickets: dict[str, float] = {}
_ticket_lock: asyncio.Lock | None = None


def _get_ticket_lock() -> asyncio.Lock:
    global _ticket_lock
    if _ticket_lock is None:
        _ticket_lock = asyncio.Lock()
    return _ticket_lock


def _purge_expired_tickets(now: float) -> None:
    """Remove expired tickets (called under _ticket_lock)."""
    expired = [t for t, exp in _tickets.items() if exp < now]
    for t in expired:
        del _tickets[t]


async def _validate_ws_ticket(ticket: str) -> bool:
    """Validate and consume a WebSocket ticket. Returns True if the
    ticket was valid (and is now consumed), False otherwise."""
    import time

    async with _get_ticket_lock():
        now = time.time()
        _purge_expired_tickets(now)
        exp = _tickets.pop(ticket, None)
        return exp is not None and exp >= now


@router.get("/ws-ticket")
async def issue_ws_ticket(request: Request) -> dict[str, Any]:
    """Issue a short-lived, single-use WebSocket ticket.

    Requires the same X-Mcrataway-Token header as other API routes
    (enforced by the ``token_guard`` middleware). The returned ticket
    can be used as ``?ticket=`` on the WebSocket handshake URL within
    60 seconds.
    """
    import secrets
    import time

    ticket = secrets.token_urlsafe(32)
    async with _get_ticket_lock():
        _purge_expired_tickets(time.time())
        _tickets[ticket] = time.time() + _TICKET_TTL_SECONDS
    return {"ticket": ticket, "expires_in": _TICKET_TTL_SECONDS}


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

        # Prefer the short-lived ticket (issued by GET /scan/ws-ticket)
        # over the long-lived token — the ticket is single-use and
        # expires in 60 seconds, so a leaked ticket (from access logs
        # or Referer) is useless. The long-lived token is accepted as
        # a fallback for non-browser clients that can't easily fetch a
        # ticket first.
        ticket = websocket.query_params.get("ticket", "")
        token = websocket.query_params.get("token", "")
        import hmac

        if ticket:
            authenticated = await _validate_ws_ticket(ticket)
        elif token:
            authenticated = hmac.compare_digest(token, expected)
        else:
            authenticated = False

        if not authenticated:
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
