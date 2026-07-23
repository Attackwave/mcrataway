"""Rules routes — list, edit, and test rule packs."""

from typing import Any

from fastapi import APIRouter
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
async def test_rule(req: RuleTestRequest) -> dict[str, Any]:
    """Test a rule pack against a sample file."""
    from pathlib import Path

    from mcrataway.parsers.archive import ArchiveReader, find_class_entries
    from mcrataway.rules.loader import RulePackLoader

    path = Path(req.file_path)
    if not path.exists():
        return {"error": "File not found"}

    loader = RulePackLoader()
    loader.load_defaults()

    if path.suffix.lower() in (".jar", ".zip"):
        reader = ArchiveReader(path)
        entries = reader.entries()
        class_entries = find_class_entries(entries)

        matches: list[dict[str, Any]] = []
        for pack in loader.packs:
            if req.rule_id and req.rule_id not in {r.rule_id for r in pack.rules}:
                continue
            for match in pack.matches_archive(entries, class_entries):
                matches.append({
                    "rule_id": match.rule_id,
                    "severity": match.severity.name,
                    "description": match.description,
                    "matched_value": match.matched_value,
                })

        return {"matches": matches}

    return {"error": "Unsupported file type"}
