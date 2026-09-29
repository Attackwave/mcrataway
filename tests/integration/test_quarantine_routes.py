"""Quarantine routes: auth, scan-root confinement and hash binding."""

import hashlib
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import mcrataway.constants as constants
from mcrataway.server.app import create_app


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    token = constants.TOKEN_FILE.read_text().strip()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"x-mcrataway-token": token},
    ) as c:
        yield c


@pytest.fixture
def scan_root(app: FastAPI, tmp_path: Path) -> Path:
    root = tmp_path / "mods"
    root.mkdir()
    assert app.state.job_registry.create_job([str(root)]) is not None
    return root


async def _quarantine(client: AsyncClient, path: Path, sha: str) -> dict[str, Any]:
    resp = await client.post(f"/quarantine/{sha}", params={"file_path": str(path)})
    assert resp.status_code == 200
    body: dict[str, Any] = resp.json()
    return body


@pytest.mark.parametrize("token", [None, "wrong-token"])
async def test_quarantine_api_requires_token(app: FastAPI, token: str | None) -> None:
    headers = {} if token is None else {"x-mcrataway-token": token}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=headers
    ) as c:
        assert (await c.get("/quarantine/")).status_code == 401
        assert (await c.post("/quarantine/purge")).status_code == 401
        assert (await c.delete("/quarantine/" + "a" * 64)).status_code == 401


async def test_unauthenticated_purge_leaves_quarantine_intact(
    app: FastAPI, client: AsyncClient, scan_root: Path
) -> None:
    mod = scan_root / "evil.jar"
    mod.write_bytes(b"malware")
    assert (await _quarantine(client, mod, _sha(b"malware")))["success"] is True

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as anon:
        assert (await anon.post("/quarantine/purge")).status_code == 401

    assert len((await client.get("/quarantine/")).json()) == 1


async def test_quarantine_and_restore_round_trip(client: AsyncClient, scan_root: Path) -> None:
    payload = b"malware" * 100
    mod = scan_root / "evil.jar"
    mod.write_bytes(payload)
    sha = _sha(payload)

    assert (await _quarantine(client, mod, sha))["success"] is True
    assert not mod.exists()
    listed = (await client.get("/quarantine/")).json()
    assert [(i["sha256"], i["original_path"]) for i in listed] == [(sha, str(mod))]

    assert (await client.post(f"/quarantine/{sha}/restore")).json() == {"success": True}
    assert mod.read_bytes() == payload
    assert (await client.get("/quarantine/")).json() == []


async def test_quarantine_rejects_hash_that_does_not_match_file(
    client: AsyncClient, scan_root: Path
) -> None:
    mod = scan_root / "innocent.jar"
    mod.write_bytes(b"content")

    body = await _quarantine(client, mod, _sha(b"something else"))

    assert body["success"] is False
    assert body["error"] == "SHA-256 mismatch"
    assert mod.read_bytes() == b"content"


async def test_quarantine_refuses_file_outside_scan_roots(
    client: AsyncClient, scan_root: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.jar"
    outside.write_bytes(b"precious")

    body = await _quarantine(client, outside, _sha(b"precious"))

    assert body["success"] is False
    assert body["error"] == "File is not inside a scan root"
    assert outside.read_bytes() == b"precious"


async def test_quarantine_refuses_dotdot_escape_from_scan_root(
    client: AsyncClient, scan_root: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.jar"
    outside.write_bytes(b"precious")

    body = await _quarantine(client, scan_root / ".." / "outside.jar", _sha(b"precious"))

    assert body["success"] is False
    assert outside.read_bytes() == b"precious"


async def test_quarantine_refuses_symlink_pointing_out_of_scan_root(
    client: AsyncClient, scan_root: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.jar"
    outside.write_bytes(b"precious")
    link = scan_root / "link.jar"
    link.symlink_to(outside)

    body = await _quarantine(client, link, _sha(b"precious"))

    assert body["success"] is False
    assert outside.read_bytes() == b"precious"
    assert link.is_symlink()


async def test_quarantine_refuses_everything_without_a_scan_job(
    client: AsyncClient, tmp_path: Path
) -> None:
    mod = tmp_path / "evil.jar"
    mod.write_bytes(b"malware")

    body = await _quarantine(client, mod, _sha(b"malware"))

    assert body["success"] is False
    assert mod.exists()


async def test_quarantine_refuses_directories_and_missing_files(
    client: AsyncClient, scan_root: Path
) -> None:
    (scan_root / "dir.jar").mkdir()

    for name in ("dir.jar", "gone.jar"):
        body = await _quarantine(client, scan_root / name, "a" * 64)
        assert body["error"] == "File not found"


async def test_quarantine_validates_hash_format_and_requires_path(
    client: AsyncClient, scan_root: Path
) -> None:
    mod = scan_root / "evil.jar"
    mod.write_bytes(b"x")

    assert (await _quarantine(client, mod, "not-a-hash"))["error"] == "Invalid SHA-256"
    assert (await _quarantine(client, mod, _sha(b"x").upper()))["error"] == "Invalid SHA-256"
    resp = await client.post(f"/quarantine/{_sha(b'x')}")
    assert resp.json()["success"] is False
    assert mod.exists()


async def test_restore_and_delete_reject_malformed_ids(client: AsyncClient) -> None:
    assert (await client.post("/quarantine/xyz/restore")).json()["error"] == "Invalid SHA-256"
    assert (await client.delete("/quarantine/xyz/restore")).json()["error"] == "Invalid SHA-256"
    assert (await client.delete("/quarantine/" + "a" * 63)).json() == {"success": False}


async def test_delete_removes_entry_permanently(client: AsyncClient, scan_root: Path) -> None:
    mod = scan_root / "evil.jar"
    mod.write_bytes(b"malware")
    sha = _sha(b"malware")
    await _quarantine(client, mod, sha)

    assert (await client.delete(f"/quarantine/{sha}")).json() == {"success": True}
    assert (await client.get("/quarantine/")).json() == []
    assert (await client.post(f"/quarantine/{sha}/restore")).json() == {"success": False}
    assert not mod.exists()


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/quarantine/purge"), ("DELETE", "/quarantine/purge"), ("DELETE", "/quarantine/")],
)
async def test_purge_variants_empty_the_quarantine(
    client: AsyncClient, scan_root: Path, method: str, path: str
) -> None:
    for name in ("a.jar", "b.jar"):
        mod = scan_root / name
        mod.write_bytes(name.encode())
        await _quarantine(client, mod, _sha(name.encode()))

    resp = await client.request(method, path)

    assert resp.json() == {"success": True, "purged_count": 2}
    assert (await client.get("/quarantine/")).json() == []
