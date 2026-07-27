"""Integration tests for the WebSocket scan live stream."""

import pathlib
import runpy
import shutil

import pytest
from starlette.testclient import TestClient

from mcrataway.server.app import create_app

FIXTURES_DIR = pathlib.Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def client():
    """Create a synchronous test client with WebSocket support,
    pre-authenticated with the auto-generated token (see
    server.auth.ensure_token, invoked by create_app())."""
    app = create_app()
    from mcrataway.constants import TOKEN_FILE
    token = TOKEN_FILE.read_text().strip()
    with TestClient(app, headers={"x-mcrataway-token": token}) as c:
        c.mcrataway_token = token  # type: ignore[attr-defined]
        yield c


@pytest.fixture
def fixtures_dir(tmp_path: pathlib.Path):
    """Ensure synthetic jars exist, then copy the fixtures into a scratch
    directory and return that instead of the real repo path — a live scan
    quarantines matched jars in place, which would otherwise delete the
    checked-in fixture files."""
    gen = FIXTURES_DIR / "generator.py"
    if gen.exists() and not any(FIXTURES_DIR.glob("*.jar")):
        runpy.run_path(str(gen), run_name="__main__")
    scratch = tmp_path / "fixtures"
    shutil.copytree(FIXTURES_DIR, scratch)
    return str(scratch)


def test_websocket_stream_nonexistent_job(client: TestClient):
    """WebSocket connection to a non-existent job should receive a
    terminal 'done' event immediately rather than hanging."""
    token = client.mcrataway_token  # type: ignore[attr-defined]
    with client.websocket_connect(f"/scan/nonexistent-job/stream?token={token}") as ws:
        event = ws.receive_json()
        assert event["type"] == "done"


def test_websocket_stream_live_scan(client: TestClient, fixtures_dir: str):
    """Start a scan and connect to its WebSocket stream — verify we receive
    status events and the stream terminates cleanly.

    ``roots`` is only honored by the server if it resolves to an
    already-allowed root (a discovered Minecraft install or a
    configured custom root) — see server/routes/scan.py:_allowed_roots.
    So the fixtures dir must be registered as a custom root first,
    mirroring what the UI does when a user adds a folder to scan.
    """
    token = client.mcrataway_token  # type: ignore[attr-defined]
    config_resp = client.post("/system/config", json={"custom_roots": [fixtures_dir]})
    assert config_resp.status_code == 200

    resp = client.post("/scan/", params={"roots": fixtures_dir})
    assert resp.status_code == 200
    job_data = resp.json()
    # roots must have resolved to the allowed custom root, not been
    # silently dropped by the allowlist filter.
    assert job_data["roots"] == [fixtures_dir]
    job_id = job_data["job_id"]
    assert job_id

    with client.websocket_connect(f"/scan/{job_id}/stream?token={token}") as ws:
        events: list[dict] = []
        for _ in range(100):
            event = ws.receive_json()
            events.append(event)
            if event.get("type") in ("done", "error"):
                break

    assert len(events) > 0
    status_events = [e for e in events if e.get("type") == "status"]
    assert len(status_events) > 0
    assert status_events[-1]["status"] in ("COMPLETED", "FAILED")
    progress_events = [e for e in events if e.get("type") == "progress"]
    assert any(e.get("total", 0) > 0 for e in progress_events), (
        "scan reported 0 total files — the fixtures root was not actually scanned"
    )


def test_websocket_stream_events_have_type(client: TestClient, fixtures_dir: str):
    """Every WebSocket event must have a 'type' field."""
    token = client.mcrataway_token  # type: ignore[attr-defined]
    config_resp = client.post("/system/config", json={"custom_roots": [fixtures_dir]})
    assert config_resp.status_code == 200

    resp = client.post("/scan/", params={"roots": fixtures_dir})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    with client.websocket_connect(f"/scan/{job_id}/stream?token={token}") as ws:
        for _ in range(100):
            event = ws.receive_json()
            assert "type" in event
            if event.get("type") in ("done", "error"):
                break
