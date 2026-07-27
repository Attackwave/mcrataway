"""Extract rule-pattern-shaped candidate features from one sample's
analysis.

Single-sample scope only — no cross-sample logic here (see
correlate.py). A "feature" is deliberately narrow: literal/hex
substrings pulled from reconstructed strings and matched Evidence
values, plus which detectors co-fired per class as context metadata.
No automatic regex derivation or API call-sequence grammar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from mcrataway.rulegen.sample import SampleAnalysis

# Evidence produced by rule matches (detector_id="rule:<pack>:<rule_id>")
# is excluded — it is a match against an *existing* rule, not a raw
# signal to build a *new* rule from.
_RULE_MATCH_PREFIX = "rule:"

# Evidence/matched_value entries too short to be a useful literal
# pattern on their own (avoids proposing single-character noise).
_MIN_VALUE_LENGTH = 4

# Java method/member names so generic that nearly every class file
# contains them — proposing these as standalone literal patterns would
# make a rule fire on almost any JAR regardless of family. They are
# only useful in combination with a distinguishing owner class, which
# is proposed as a separate candidate.
_GENERIC_MEMBER_NAMES = {
    "<init>", "<clinit>", "start", "run", "get", "set", "exec",
    "load", "close", "open", "read", "write", "call", "init",
}


@dataclass
class CandidateFeature:
    """One normalized, rule-pattern-shaped observation extracted from
    one or more samples."""

    kind: Literal["literal", "regex", "hex"]
    value: str
    source: Literal["constant_pool", "reconstructed_string", "capability_flag"]
    technique: str = ""
    sample_hashes: set[str] = field(default_factory=set)
    detector_ids: set[str] = field(default_factory=set)


def extract_candidates(analysis: SampleAnalysis) -> list[CandidateFeature]:
    """Pull literal candidates out of one sample's evidence and
    reconstructed strings."""
    candidates: dict[str, CandidateFeature] = {}

    def _add(value: str, source: Literal["constant_pool", "reconstructed_string"], technique: str, detector_id: str) -> None:
        value = value.strip()
        if len(value) < _MIN_VALUE_LENGTH:
            return
        if not value.isprintable():
            # Failed/garbled decryption (e.g. a cipher reconstruction
            # that didn't recover valid text) — not a usable literal
            # pattern for a human-reviewable rule.
            return
        if value in _GENERIC_MEMBER_NAMES:
            return
        existing = candidates.get(value)
        if existing is None:
            existing = CandidateFeature(kind="literal", value=value, source=source, technique=technique)
            candidates[value] = existing
        existing.sample_hashes.add(analysis.file_hash)
        existing.detector_ids.add(detector_id)

    for ev in analysis.evidence_index.evidence:
        if ev.detector_id.startswith(_RULE_MATCH_PREFIX):
            continue
        if not ev.matched_value:
            continue
        technique = ev.context.get("technique", "")
        source: Literal["constant_pool", "reconstructed_string"] = (
            "reconstructed_string" if ev.detector_id == "string_reconstruction" else "constant_pool"
        )

        invoke_owner = ev.context.get("invoke_owner")
        invoke_name = ev.context.get("invoke_name")
        if invoke_owner or invoke_name:
            # ev.matched_value here is a synthesized "owner.name(desc)"
            # display string built for human-readable reports — it
            # never appears as a contiguous substring in the class
            # file, since owner/name/descriptor are separate constant
            # pool entries. Use the actual constant pool values
            # instead, which are independently matchable substrings.
            if invoke_owner:
                _add(invoke_owner, source, technique, ev.detector_id)
            if invoke_name:
                _add(invoke_name, source, technique, ev.detector_id)
        else:
            _add(ev.matched_value, source, technique, ev.detector_id)

    for rs in analysis.reconstructed_strings:
        if rs.technique == "ldc_string":
            continue
        _add(rs.value, "reconstructed_string", rs.technique, "string_reconstruction")

    return list(candidates.values())
