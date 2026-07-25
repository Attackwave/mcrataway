"""Auth — loopback-only guard and optional token validation."""

import hmac
import secrets

from fastapi import HTTPException, Request

from mcrataway.constants import TOKEN_FILE


def ensure_token() -> str:
    """Ensure an auth token exists, generating one on first run.

    A token file that is only ever created manually is a protection
    that is off by default — the API otherwise accepts every request
    (see :func:`verify_token`). Auto-generating a token at server
    startup means the API is authenticated from the very first run,
    not only after a user has discovered the (undocumented-by-default)
    manual step.
    """
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not TOKEN_FILE.exists():
        token = secrets.token_urlsafe(32)
        TOKEN_FILE.write_text(token)
        TOKEN_FILE.chmod(0o600)
        return token
    return TOKEN_FILE.read_text().strip()


def verify_token(request: Request) -> bool:
    """Verify the request token if one is configured.

    Returns True if:
    - No token file exists (open mode), or
    - The X-Mcrataway-Token header matches the token file contents.

    Comparison is constant-time via :func:`hmac.compare_digest` to
    mitigate timing-based token recovery attacks (relevant if the
    server is accidentally bound to a non-loopback interface).
    """
    if not TOKEN_FILE.exists():
        return True

    try:
        token = request.headers.get("x-mcrataway-token", "")
        expected = TOKEN_FILE.read_text().strip()
        # An empty token file (touch ~/.mcrataway/token) must NOT
        # disable auth: compare_digest("", "") returns True, which
        # would authenticate every request. Treat an empty configured
        # token as "auth misconfigured — deny all".
        if not expected:
            return False
        return hmac.compare_digest(token, expected)
    except Exception:
        return False


def require_auth(request: Request) -> None:
    """Raise 401 if token validation fails."""
    if not verify_token(request):
        raise HTTPException(status_code=401, detail="Invalid or missing token")


# Hostnames considered loopback/local, regardless of the port a user
# chose. Used as an extra guard against DNS rebinding: an
# attacker-controlled domain that resolves to 127.0.0.1 would satisfy
# a plain Origin-equals-Host check while still being an attacker page
# in the browser's eyes, so the Origin's *hostname* must additionally
# be a recognized loopback name.
_LOOPBACK_HOSTNAMES = ("127.0.0.1", "localhost", "::1")


def verify_origin_headers(origin: str, host_header: str) -> bool:
    """Reject cross-origin browser requests (CSRF / DNS-rebinding guard).

    Shared by the HTTP middleware (:func:`verify_origin`) and the
    WebSocket handshake in ``server/routes/scan.py`` — WebSocket
    connections are not routed through ``app.middleware("http")``, so
    that code path calls this directly with its own headers.

    Real browsers send an ``Origin`` header on state-changing requests
    (and increasingly on all fetches); non-browser clients (curl,
    scripts) typically do not. So:

    - No Origin header at all -> allow (not a browser CSRF vector).
    - Origin header present -> its hostname must (a) match this
      request's Host header (true same-origin) and (b) be a
      recognized loopback name — (b) alone would not stop DNS
      rebinding (an attacker domain can be made to resolve to
      127.0.0.1, satisfying same-origin while still being the
      attacker's page), and (a) alone would not stop it either if the
      server is somehow reachable under a non-loopback Host.

    Without this, any website the user has open in another tab can
    drive this locally-bound API via a simple ``fetch()`` — the
    Same-Origin Policy blocks the attacker from *reading* the
    response, but does not prevent the request (and its side effects,
    e.g. starting a scan or purging quarantine) from happening.
    """
    if not origin:
        return True

    try:
        from urllib.parse import urlparse
        parsed = urlparse(origin)
        origin_host = parsed.hostname or ""
        origin_netloc = parsed.netloc
    except Exception:
        return False

    return origin_host in _LOOPBACK_HOSTNAMES and origin_netloc == host_header


def verify_origin(request: Request) -> bool:
    """Reject cross-origin browser requests. See :func:`verify_origin_headers`."""
    return verify_origin_headers(
        request.headers.get("origin", ""), request.headers.get("host", "")
    )
