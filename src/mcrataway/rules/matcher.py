"""Rule matcher — string/multi-string/regex/hex matching against archive entries."""

from __future__ import annotations

import re
from typing import Any

from mcrataway.constants import Severity
from mcrataway.parsers.archive import ArchiveEntry

# Maximum text length scanned by a single regex (1 MB)
_MAX_REGEX_TEXT = 1024 * 1024

# Regex patterns that can cause catastrophic backtracking (ReDoS)
_REDO_PATTERNS = re.compile(
    r"(\(([^()]*\+[^()]*)+\)|\(([^()]*\*)[^()]*\)\+|(\.\+)\+|(\.\*)\+)"
)


class StringPattern:
    """A single string pattern to match."""

    def __init__(self, kind: str, value: str) -> None:
        self.kind = kind
        self.value = value

    def matches(self, text: str) -> list[str]:
        """Check if the pattern matches the given text. Returns matched values."""
        if self.kind == "literal":
            if self.value in text:
                return [self.value]
        elif self.kind == "regex":
            try:
                if _REDO_PATTERNS.search(self.value):
                    return []
                return re.findall(self.value, text[:_MAX_REGEX_TEXT], re.IGNORECASE)
            except re.error:
                pass
        elif self.kind == "hex":
            try:
                hex_bytes = bytes.fromhex(self.value.replace(" ", ""))
                if hex_bytes in text.encode("utf-8", errors="replace"):
                    return [self.value]
            except ValueError:
                pass
        return []


class RuleMatcher:
    """Matches a rule definition against archive entries."""

    def __init__(
        self,
        rule_id: str,
        family: str,
        severity: Severity,
        description: str,
        patterns: list[StringPattern],
        condition: str = "",
    ) -> None:
        self.rule_id = rule_id
        self.family = family
        self.severity = severity
        self.description = description
        self.patterns = patterns
        self.condition = condition

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RuleMatcher:
        """Create a matcher from a rule dictionary."""
        strings = data.get("strings", [])
        patterns = [
            StringPattern(kind=s.get("kind", "literal"), value=s.get("value", ""))
            for s in strings
        ]
        return cls(
            rule_id=str(data.get("id", "")),
            family=str(data.get("family", "")),
            severity=Severity[str(data.get("severity", "medium")).upper()],
            description=str(data.get("description", "")),
            patterns=patterns,
            condition=str(data.get("condition", "")),
        )

    def match(self, entries: list[ArchiveEntry]) -> dict[int, list[str]]:
        """Match all patterns against all entries. Returns {pattern_idx: matched_values}."""
        combined = "\n".join(e.data.decode("utf-8", errors="replace") for e in entries)
        results: dict[int, list[str]] = {}

        for idx, pattern in enumerate(self.patterns):
            matches = pattern.matches(combined)
            if matches:
                results[idx] = matches[:5]

        return results

    def evaluate(self, entries: list[ArchiveEntry]) -> dict[str, Any] | None:
        """Evaluate the rule against entries. Returns match info or None."""
        matches = self.match(entries)

        if not self._check_condition(matches):
            return None

        matched_values = []
        for vals in matches.values():
            matched_values.extend(vals)

        return {
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "description": self.description,
            "matched_value": matched_values[0][:200] if matched_values else "",
            "context": {
                "family": self.family,
                "matched_count": len(matches),
                "total_strings_matched": sum(len(v) for v in matches.values()),
            },
        }

    def _check_condition(self, matches: dict[int, list[str]]) -> bool:
        """Evaluate the condition against match results."""
        if not self.condition:
            return bool(matches)

        condition = self.condition.strip().lower()
        if condition == "all":
            return len(matches) == len(self.patterns)
        if condition == "any":
            return bool(matches)

        count_match = re.search(r"count\s*\(\s*\)\s*>=\s*(\d+)", condition)
        if count_match:
            threshold = int(count_match.group(1))
            return len(matches) >= threshold

        return bool(matches)
