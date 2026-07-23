"""Auth — loopback-only guard and optional token validation."""

import hmac

from fastapi import HTTPException, Request

from mcrataway.constants import TOKEN_FILE


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
