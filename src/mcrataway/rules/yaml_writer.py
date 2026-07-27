"""Serialize RuleDefinition objects back to the YAML pack format.

The exact inverse of :meth:`RulePackLoader.load_pack` — kept in this
package (not in ``rulegen/``) so a consumer that only wants to export
already-loaded rules as YAML does not need to depend on the rule
generation pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from mcrataway.rules.loader import RuleDefinition

if TYPE_CHECKING:
    from mcrataway.rulegen.propose import RuleProposal


def rule_to_dict(rule: RuleDefinition) -> dict[str, Any]:
    """Convert a RuleDefinition to a dict matching the docs/RULES.md
    schema (id/family/severity/description/strings/condition)."""
    return {
        "id": rule.rule_id,
        "family": rule.family,
        "severity": rule.severity.name.lower(),
        "description": rule.description,
        "strings": rule.strings,
        "condition": rule.condition,
    }


def pack_to_yaml(pack_id: str, rules: list[RuleDefinition], description: str = "") -> str:
    """Serialize a full pack to YAML text.

    Round-trip-compatible with RulePackLoader.load_pack: parsing this
    output back through load_pack must reproduce equivalent
    RuleDefinition objects.
    """
    data: dict[str, Any] = {
        "pack_id": pack_id,
        "description": description,
        "rules": [rule_to_dict(r) for r in rules],
    }
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def write_proposal(proposal: "RuleProposal", path: Path) -> None:
    """Write one RuleProposal to *path* as YAML.

    Provenance (source_samples, generated_at, generator_version, notes)
    is emitted as a top-level 'proposal_metadata' block alongside
    pack_id/rules — not inside the rule's own fields — so the file
    stays structurally load_pack()-compatible (RulePackLoader ignores
    unknown top-level keys) while still carrying full provenance for
    human reviewers.
    """
    data: dict[str, Any] = {
        "pack_id": f"{proposal.definition.family}_proposed",
        "description": f"Auto-generated proposal for family '{proposal.definition.family}' — requires human review before use.",
        "rules": [rule_to_dict(proposal.definition)],
        "proposal_metadata": {
            "status": proposal.status,
            "source_samples": proposal.source_samples,
            "generated_at": proposal.generated_at,
            "generator_version": proposal.generator_version,
            "notes": proposal.notes,
        },
    }
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
