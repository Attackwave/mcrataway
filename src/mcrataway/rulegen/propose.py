"""Turn generalized candidate features into a rule proposal.

A RuleProposal wraps a RuleDefinition (reused as-is from rules/loader.py)
with provenance — which samples it came from, when, and by which
generator version — so a human reviewer can judge how much to trust it
before promoting it to a signed, distributed rule pack.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from mcrataway.constants import SCANNER_VERSION, Severity
from mcrataway.rulegen.features import CandidateFeature
from mcrataway.rules.loader import RuleDefinition


@dataclass
class RuleProposal:
    """A generated, unreviewed rule candidate plus its provenance."""

    definition: RuleDefinition
    status: Literal["proposed"] = "proposed"
    source_samples: list[str] = field(default_factory=list)
    generated_at: str = ""
    generator_version: str = ""
    notes: str = ""


def propose_rule(
    candidates: list[CandidateFeature],
    family: str,
    rule_id: str | None = None,
    severity: Severity = Severity.MEDIUM,
    condition: str = "count() >= 2",
) -> RuleProposal:
    """Pure function: candidates -> one RuleProposal. No I/O."""
    if rule_id is None:
        digest = hashlib.sha256(
            "|".join(sorted(c.value for c in candidates)).encode("utf-8")
        ).hexdigest()[:8]
        rule_id = f"{family}_{digest}"

    strings = [{"kind": c.kind, "value": c.value} for c in candidates]

    source_samples: set[str] = set()
    for c in candidates:
        source_samples |= c.sample_hashes

    definition = RuleDefinition(
        rule_id=rule_id,
        family=family,
        severity=severity,
        description=f"Auto-generated proposal for family '{family}' — requires human review.",
        strings=strings,
        condition=condition,
    )

    notes = f"{len(candidates)} candidate pattern(s) from {len(source_samples)} sample(s)."

    return RuleProposal(
        definition=definition,
        source_samples=sorted(source_samples),
        generated_at=datetime.now(UTC).isoformat(),
        generator_version=SCANNER_VERSION,
        notes=notes,
    )
