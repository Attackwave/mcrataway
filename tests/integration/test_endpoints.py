"""Integration tests for FastAPI endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from mcrataway.server.app import create_app


@pytest.fixture
async def client():
    """Create an async test client."""
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
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
async def test_rules(client: AsyncClient):
    resp = await client.get("/rules/")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 2  # At least 2 built-in packs


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
