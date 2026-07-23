"""Integration tests for the WebSocket scan live stream."""

import pathlib
import runpy

import pytest
from starlette.testclient import TestClient

from mcrataway.server.app import create_app

FIXTURES_DIR = pathlib.Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def client():
    """Create a synchronous test client with WebSocket support."""
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def fixtures_dir():
    """Ensure synthetic jars exist and return the fixtures directory."""
    gen = FIXTURES_DIR / "generator.py"
    if gen.exists():
        runpy.run_path(str(gen), run_name="__main__")
    return str(FIXTURES_DIR)


def test_websocket_stream_nonexistent_job(client: TestClient):
    """WebSocket connection to a non-existent job should receive a
    terminal 'done' event immediately rather than hanging."""
    with client.websocket_connect("/scan/nonexistent-job/stream") as ws:
        event = ws.receive_json()
        assert event["type"] == "done"


def test_websocket_stream_live_scan(client: TestClient, fixtures_dir: str):
    """Start a scan and connect to its WebSocket stream — verify we receive
    status events and the stream terminates cleanly."""
    resp = client.post("/scan/", params={"roots": fixtures_dir})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]
    assert job_id

    with client.websocket_connect(f"/scan/{job_id}/stream") as ws:
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


def test_websocket_stream_events_have_type(client: TestClient, fixtures_dir: str):
    """Every WebSocket event must have a 'type' field."""
    resp = client.post("/scan/", params={"roots": fixtures_dir})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    with client.websocket_connect(f"/scan/{job_id}/stream") as ws:
        for _ in range(100):
            event = ws.receive_json()
            assert "type" in event
            if event.get("type") in ("done", "error"):
                break
