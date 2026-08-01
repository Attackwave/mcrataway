"""Integration tests for FastAPI endpoints."""

import asyncio
import shutil
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from mcrataway.server.app import create_app

_REAL_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


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


@pytest.mark.asyncio
async def test_history_empty(client: AsyncClient):
    resp = await client.get("/history/")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_history_nonexistent_report(client: AsyncClient):
    resp = await client.get("/history/nonexistent")
    assert resp.status_code == 200
    data = resp.json()
    assert "error" in data


async def _run_scan_to_completion(client: AsyncClient, roots: list[str]) -> str:
    """Start a scan and poll GET /scan/{job_id} until it leaves
    PENDING/RUNNING. Returns the job_id. Mirrors the WebSocket-based
    wait in test_websocket.py's test_websocket_stream_live_scan, but
    via polling since this module's client is an httpx.AsyncClient
    (no WebSocket support), not a WS-capable TestClient.
    """
    config_resp = await client.post("/system/config", json={"custom_roots": roots})
    assert config_resp.status_code == 200

    resp = await client.post("/scan/", params={"roots": roots})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert job_id

    for _ in range(200):
        status_resp = await client.get(f"/scan/{job_id}")
        status = status_resp.json().get("status")
        if status in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        await asyncio.sleep(0.05)
    else:
        pytest.fail(f"scan {job_id} did not complete in time")

    return job_id


def _scratch_fixtures_dir(tmp_path: Path) -> str:
    """Copy tests/fixtures/ into a scratch directory before scanning it
    — a live scan quarantines matched jars in place, which would
    otherwise delete/rewrite the checked-in fixture files (see the
    same fix applied to test_websocket.py's fixtures_dir fixture)."""
    scratch = tmp_path / "fixtures"
    shutil.copytree(_REAL_FIXTURES_DIR, scratch)
    return str(scratch)


@pytest.mark.asyncio
async def test_history_after_completed_scan(client: AsyncClient, tmp_path: Path):
    fixtures_dir = _scratch_fixtures_dir(tmp_path)
    job_id = await _run_scan_to_completion(client, [fixtures_dir])

    list_resp = await client.get("/history/")
    assert list_resp.status_code == 200
    entries = list_resp.json()
    assert any(e["scan_id"] == job_id for e in entries)

    report_resp = await client.get(f"/history/{job_id}")
    assert report_resp.status_code == 200
    report = report_resp.json()
    assert report["scan_id"] == job_id
    assert "summary" in report
    assert "files" in report


@pytest.mark.asyncio
async def test_history_delete(client: AsyncClient, tmp_path: Path):
    fixtures_dir = _scratch_fixtures_dir(tmp_path)
    job_id = await _run_scan_to_completion(client, [fixtures_dir])

    delete_resp = await client.delete(f"/history/{job_id}")
    assert delete_resp.status_code == 200
    assert delete_resp.json() == {"success": True}

    report_resp = await client.get(f"/history/{job_id}")
    assert "error" in report_resp.json()

    delete_again_resp = await client.delete(f"/history/{job_id}")
    assert delete_again_resp.json() == {"success": False}
