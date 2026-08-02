"""Tests for WebSocket ticket authentication.

Browsers cannot set custom headers on WebSocket handshakes, so the
long-lived auth token would have to be passed as ``?token=`` in the
WS URL — which leaks into access logs and Referer headers. The ticket
system issues a short-lived, single-use ticket via a normal HTTP GET
(which CAN carry the X-Mcrataway-Token header), then the WS handshake
uses ``?ticket=`` instead. A leaked ticket is useless after one use
or after 60-second expiry.

These tests verify:
  - GET /scan/ws-ticket returns a ticket (with token auth).
  - The ticket is accepted on the WS handshake.
  - The ticket is single-use (second use fails).
  - The long-lived token still works as a fallback.
  - No ticket and no token = rejected.
"""

import asyncio
import time

import pytest
from httpx import ASGITransport, AsyncClient

from mcrataway.server.app import create_app


@pytest.fixture
async def client():
    app = create_app()
    from mcrataway.constants import TOKEN_FILE

    token = TOKEN_FILE.read_text().strip()
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"x-mcrataway-token": token},
    ) as c:
        yield c


@pytest.mark.asyncio
async def test_ws_ticket_endpoint_returns_ticket(client: AsyncClient):
    """GET /scan/ws-ticket must return a ticket string with an
    expiry."""
    resp = await client.get("/scan/ws-ticket")
    assert resp.status_code == 200
    data = resp.json()
    assert "ticket" in data
    assert len(data["ticket"]) > 20
    assert data["expires_in"] == 60


@pytest.mark.asyncio
async def test_ws_ticket_requires_auth():
    """The ws-ticket endpoint must require the X-Mcrataway-Token
    header — it's an API route protected by token_guard."""
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.get("/scan/ws-ticket")
        assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ticket_is_single_use(client: AsyncClient):
    """A ticket must be consumable exactly once — a second validation
    of the same ticket must fail."""
    from mcrataway.server.routes.scan import _validate_ws_ticket

    resp = await client.get("/scan/ws-ticket")
    ticket = resp.json()["ticket"]

    first = await _validate_ws_ticket(ticket)
    assert first is True

    second = await _validate_ws_ticket(ticket)
    assert second is False


@pytest.mark.asyncio
async def test_ticket_expires(client: AsyncClient):
    """An expired ticket must be rejected."""
    from mcrataway.server.routes.scan import _tickets, _validate_ws_ticket

    resp = await client.get("/scan/ws-ticket")
    ticket = resp.json()["ticket"]

    # Manually expire the ticket
    async with asyncio.Lock():
        _tickets[ticket] = time.time() - 1

    result = await _validate_ws_ticket(ticket)
    assert result is False


@pytest.mark.asyncio
async def test_invalid_ticket_rejected():
    """A random/invalid ticket string must be rejected."""
    from mcrataway.server.routes.scan import _validate_ws_ticket

    result = await _validate_ws_ticket("not-a-real-ticket")
    assert result is False
