"""Rules routes — list, edit, and test rule packs."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter(prefix="/rules", tags=["rules"])


class RuleTestRequest(BaseModel):
    file_path: str
    rule_id: str | None = None


@router.get("/")
async def list_rules() -> list[dict[str, Any]]:
    """List all loaded rule packs."""
    from mcrataway.rules.loader import RulePackLoader
    loader = RulePackLoader()
    loader.load_defaults()
    return [
        {
            "pack_id": pack.pack_id,
            "rule_count": len(pack.rules),
            "rules": [
                {
                    "id": r.rule_id,
                    "family": r.family,
                    "severity": r.severity.name,
                    "description": r.description,
                }
                for r in pack.rules
            ],
        }
        for pack in loader.packs
    ]


@router.post("/test")
async def test_rule(req: RuleTestRequest, request: Request) -> dict[str, Any]:
    """Test a rule pack against a sample file.

    *file_path* is validated against the same server-side scan-root
    allowlist as ``POST /scan/`` — without this, a caller that reaches
    this endpoint could have arbitrary files on disk read and their
    contents (via rule match output) returned, regardless of whether
    they were ever added as a scan root.
    """
    from mcrataway.parsers.archive import ArchiveReader
    from mcrataway.rules.loader import RulePackLoader
    from mcrataway.server.routes.scan import _allowed_roots

    try:
        path = Path(req.file_path).resolve()
    except Exception:
        return {"error": "Invalid file path"}

    if not path.exists():
        return {"error": "File not found"}

    allowed = _allowed_roots(request.app.state.config)
    if not any(path == root or root in path.parents for root in allowed):
        return {"error": "File is outside the allowed scan roots"}

    loader = RulePackLoader()
    loader.load_defaults()

    if path.suffix.lower() in (".jar", ".zip"):
        reader = ArchiveReader(path)
        # Materialize once: this endpoint tests a single sample file
        # against every rule pack, so the entries are iterated once
        # per pack. The scan engine's hot path (scan_engine.py) instead
        # streams entries through a single shared pass to avoid this.
        entries = list(reader.entries())

        matches: list[dict[str, Any]] = []
        for pack in loader.packs:
            if req.rule_id and req.rule_id not in {r.rule_id for r in pack.rules}:
                continue
            for match in pack.matches_archive(entries, []):
                matches.append({
                    "rule_id": match.rule_id,
                    "severity": match.severity.name,
                    "description": match.description,
                    "matched_value": match.matched_value,
                })

        return {"matches": matches}

    return {"error": "Unsupported file type"}
