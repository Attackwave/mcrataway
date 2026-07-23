"""FastAPI application factory."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from mcrataway.config import UserConfig, ensure_config_dir
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.server.auth import verify_token
from mcrataway.server.jobs import JobRegistry
from mcrataway.server.routes import findings, quarantine, reports, rules, scan, system

# Token auth middleware — only enforced if ~/.mcrataway/token exists.
# The SPA shell, static assets, and the health endpoint must remain
# accessible without a token so the UI can boot and report liveness.
#
# API routes are registered with fixed prefixes (/scan, /findings,
# /quarantine, /rules, /reports, /system). Anything that is NOT under
# one of those prefixes (and not an already-mounted API sub-path) is
# treated as a public SPA/client-side route or a static asset.
_API_PREFIXES = ("/scan", "/findings", "/quarantine", "/rules", "/reports", "/system")
_PUBLIC_PATHS = {"/", "/system/health"}
_STATIC_PREFIX = "/static"


def _is_public_path(path: str) -> bool:
    if path in _PUBLIC_PATHS or path.startswith(_STATIC_PREFIX):
        return True
    # Anything under an API prefix requires auth — even paths that
    # happen to contain a dot in their last segment (e.g. a future
    # /rules/foo.bar resource id). Outside the API prefixes, the
    # request is either a client-side SPA route (e.g. /scan-page,
    # /quarantine-page) or a static asset served from the SPA
    # fallback, and is public.
    return not any(path == p or path.startswith(p + "/") for p in _API_PREFIXES)


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    ensure_config_dir()
    config = UserConfig.load()
    job_registry = JobRegistry()
    quarantine_manager = QuarantineManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        yield
        await job_registry.shutdown()

    app = FastAPI(
        title="mcrataway",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Token auth middleware — only enforced if ~/.mcrataway/token exists.
    @app.middleware("http")
    async def token_guard(request: Request, call_next):  # type: ignore[no-untyped-def]
        if _is_public_path(request.url.path) or verify_token(request):
            return await call_next(request)
        return JSONResponse(
            status_code=401,
            content={"detail": "Invalid or missing token"},
        )

    # Mount static files (React SPA assets)
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Include routers FIRST so API routes take priority over the SPA fallback
    app.include_router(scan.router)
    app.include_router(findings.router)
    app.include_router(quarantine.router)
    app.include_router(rules.router)
    app.include_router(reports.router)
    app.include_router(system.router)

    # SPA entry point + client-side routing fallback
    if static_dir.exists():
        index_html = static_dir / "index.html"

        @app.get("/", include_in_schema=False)
        async def serve_spa() -> FileResponse:
            """Serve the React SPA entry point."""
            return FileResponse(str(index_html))

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(full_path: str) -> FileResponse:
            """Serve index.html for unknown non-API routes (client-side routing).

            Paths with a file extension (e.g. ``.js``, ``.css``) that
            were not matched by the static mount return 404 instead of
            index.html — serving HTML with a ``text/html`` MIME type
            for a missing asset causes a MIME-type error in the browser
            and a blank page.
            """
            from fastapi import HTTPException

            last_segment = full_path.rsplit("/", 1)[-1]
            if "." in last_segment:
                # Looks like an asset request that the static mount
                # did not handle — do not masquerade as HTML.
                raise HTTPException(status_code=404, detail="Asset not found")
            return FileResponse(str(index_html))

    # Store shared state
    app.state.job_registry = job_registry
    app.state.quarantine_manager = quarantine_manager
    app.state.config = config

    return app
