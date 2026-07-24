"""Quarantine routes — list, quarantine, and restore files."""

import hashlib
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/quarantine", tags=["quarantine"])

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def _sha256_file(path: Path) -> str:
    """Compute the SHA-256 hash of a file, or empty string on error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except Exception:
        return ""
    return h.hexdigest()


def _is_subpath(path: Path, parent: Path) -> bool:
    """Return True if *path* is *parent* or located beneath *parent*."""
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


@router.get("/")
async def list_quarantined(request: Request) -> list[dict[str, Any]]:
    """List all quarantined items."""
    qm = request.app.state.quarantine_manager
    return [
        {
            "original_path": m.original_path,
            "sha256": m.sha256,
            "verdict": m.verdict,
            "timestamp": m.timestamp,
            "restored": m.restored,
        }
        for m in qm.list_quarantined()
    ]


@router.post("/{sha256}")
async def quarantine_file(
    sha256: str,
    request: Request,
    file_path: str = Query(default=""),  # noqa: B008
) -> dict[str, Any]:
    """Quarantine a specific file.

    Security: *file_path* must be inside one of the scan roots tracked by
    the job registry, and the SHA-256 in the URL must match the hash
    computed from the file on disk. This prevents arbitrary file
    deletion via path traversal or forged hashes.
    """
    if not _SHA256_RE.match(sha256):
        return {"success": False, "manifest": None, "error": "Invalid SHA-256"}
    qm = request.app.state.quarantine_manager
    if not file_path:
        return {"success": False, "manifest": None}

    try:
        target = Path(file_path).resolve()
    except Exception:
        return {"success": False, "manifest": None, "error": "Invalid file path"}

    # Restrict to scan roots of known jobs
    job_registry = request.app.state.job_registry
    allowed_roots: list[Path] = []
    for job in job_registry.list_jobs():
        for r in job.roots:
            try:
                allowed_roots.append(Path(r).resolve())
            except Exception:
                continue
    if not any(_is_subpath(target, root) for root in allowed_roots):
        return {
            "success": False,
            "manifest": None,
            "error": "File is not inside a scan root",
        }

    if not target.exists() or not target.is_file():
        return {"success": False, "manifest": None, "error": "File not found"}

    # Verify the URL hash matches the file's actual content
    computed = _sha256_file(target)
    if not computed or computed != sha256:
        return {"success": False, "manifest": None, "error": "SHA-256 mismatch"}

    result = type(
        "ScanResult",
        (),
        {
            "file_hash": sha256,
            "verdict": "MALICIOUS",
            "confidence": 1.0,
            "findings": [],
        },
    )()
    qresult = qm.quarantine(target, result)
    manifest = str(qresult.quarantined_path) if qresult else None
    return {"success": qresult is not None, "manifest": manifest}


@router.delete("")
@router.delete("/")
@router.delete("/purge")
@router.post("/purge")
async def purge_quarantine(request: Request) -> dict[str, Any]:
    """Permanently delete all files from quarantine."""
    qm = request.app.state.quarantine_manager
    count = qm.purge_all()
    return {"success": True, "purged_count": count}


@router.post("/{sha256}/restore")
@router.delete("/{sha256}/restore")
async def restore_file(sha256: str, request: Request) -> dict[str, Any]:
    """Restore a quarantined file to its original location."""
    if not _SHA256_RE.match(sha256):
        return {"success": False, "error": "Invalid SHA-256"}
    qm = request.app.state.quarantine_manager
    success = qm.restore(sha256)
    return {"success": success}


@router.delete("/{sha256}")
async def delete_quarantined_file(sha256: str, request: Request) -> dict[str, Any]:
    """Permanently delete a quarantined file from disk."""
    qm = request.app.state.quarantine_manager
    success = qm.delete_permanently(sha256)
    return {"success": success}
