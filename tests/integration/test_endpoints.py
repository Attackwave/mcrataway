"""Integration tests for FastAPI endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from mcrataway.server.app import create_app


@pytest.fixture
async def client():
    """Create an async test client, pre-authenticated with the
    auto-generated token (create_app() now provisions one on first run
    — see server.auth.ensure_token)."""
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
async def test_health(client: AsyncClient):
    resp = await client.get("/system/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_roots(client: AsyncClient):
    resp = await client.get("/system/roots")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_system_browse(client: AsyncClient):
    resp = await client.get("/system/browse")
    assert resp.status_code == 200
    data = resp.json()
    assert "current_path" in data
    assert "items" in data


@pytest.mark.asyncio
async def test_system_config(client: AsyncClient):
    resp = await client.get("/system/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "max_workers" in data


@pytest.mark.asyncio
async def test_whitelist_hash_accepts_valid_sha256(client: AsyncClient):
    valid_hash = "a" * 64
    resp = await client.post("/system/whitelist", json={"sha256": valid_hash})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert valid_hash in data["whitelisted_hashes"]

    # Idempotent: whitelisting the same hash again must not duplicate it.
    resp = await client.post("/system/whitelist", json={"sha256": valid_hash})
    data = resp.json()
    assert data["whitelisted_hashes"].count(valid_hash) == 1


@pytest.mark.asyncio
async def test_whitelist_hash_rejects_invalid_input(client: AsyncClient):
    resp = await client.post("/system/whitelist", json={"sha256": "../../etc/passwd"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is False


@pytest.mark.asyncio
async def test_rules(client: AsyncClient):
    resp = await client.get("/rules/")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 2  # At least 2 built-in packs


@pytest.mark.asyncio
async def test_scan_rejects_arbitrary_root(client: AsyncClient):
    """A root not in the discovered/custom-root allowlist must be
    silently dropped, not scanned — see
    server/routes/scan.py:_allowed_roots. Otherwise any caller that
    reaches this endpoint could direct the scanner (and, with
    quarantine enabled, file removal) at an arbitrary filesystem path.
    """
    resp = await client.post("/scan/", params={"roots": "/etc"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["roots"] == []


@pytest.mark.asyncio
async def test_scan_allows_configured_custom_root(client: AsyncClient, tmp_path):
    """A root the user has explicitly added via config.custom_roots
    must still be scannable."""
    custom_root = tmp_path / "my_mods"
    custom_root.mkdir()

    config_resp = await client.post(
        "/system/config", json={"custom_roots": [str(custom_root)]}
    )
    assert config_resp.status_code == 200

    resp = await client.post("/scan/", params={"roots": str(custom_root)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["roots"] == [str(custom_root)]


@pytest.mark.asyncio
async def test_start_scan(client: AsyncClient):
    resp = await client.post("/scan/?auto_discover=true")
    assert resp.status_code == 200
    data = resp.json()
    assert "job_id" in data
    job_id = data["job_id"]

    # Query job status - may return error if job not found yet
    resp = await client.get(f"/scan/{job_id}")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_scan_nonexistent_job(client: AsyncClient):
    resp = await client.get("/scan/nonexistent-id")
    assert resp.status_code == 200
    data = resp.json()
    assert "error" in data


@pytest.mark.asyncio
async def test_findings_empty(client: AsyncClient):
    resp = await client.get("/findings/")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_findings_filter(client: AsyncClient):
    resp = await client.get("/findings/?severity=HIGH")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_quarantine_empty(client: AsyncClient):
    resp = await client.get("/quarantine/")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


@pytest.mark.asyncio
async def test_reports_nonexistent(client: AsyncClient):
    resp = await client.get("/reports/nonexistent")
    assert resp.status_code == 200
    data = resp.json()
    assert "error" in data
