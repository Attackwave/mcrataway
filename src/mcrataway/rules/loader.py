"""Rule pack loader and matcher — YAML-defined signature rules."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcrataway.constants import Severity
from mcrataway.parsers.archive import ArchiveEntry, is_java_class

# Maximum text length scanned by a single regex (1 MB)
_MAX_REGEX_TEXT = 1024 * 1024

# Regex patterns that can cause catastrophic backtracking (ReDoS)
_REDO_PATTERNS = re.compile(
    r"(\(([^()]*\+[^()]*)+\)|\(([^()]*\*)[^()]*\)\+|(\.\+)\+|(\.\*)\+)"
)


@dataclass
class RuleMatch:
    """A single rule match result."""

    rule_id: str
    severity: Severity
    description: str
    class_name: str = ""
    matched_value: str = ""
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleDefinition:
    """A single rule from a YAML pack."""

    rule_id: str
    family: str
    severity: Severity
    description: str
    strings: list[dict[str, str]] = field(default_factory=list)
    condition: str = ""


class RulePack:
    """A loaded set of rules from a YAML file."""

    def __init__(self, pack_id: str, rules: list[RuleDefinition]) -> None:
        self.pack_id = pack_id
        self.rules = rules

    def matches_archive(
        self,
        entries: list[ArchiveEntry],
        class_entries: list[ArchiveEntry],
    ) -> list[RuleMatch]:
        """Check all rules against archive entries."""
        matches: list[RuleMatch] = []

        # Build string index from all entries
        all_strings: list[str] = []
        class_names: list[str] = []

        for entry in entries:
            try:
                if is_java_class(entry.data[:4]):
                    class_names.append(entry.name)
            except Exception:
                pass

            # Decode entry data as UTF-8 for string scanning
            try:
                text = entry.data.decode("utf-8", errors="replace")
                all_strings.append(text)
            except Exception:
                pass

        for rule in self.rules:
            match_result = self._check_rule(rule, all_strings, class_names)
            if match_result:
                matches.append(match_result)

        return matches

    def _check_rule(
        self,
        rule: RuleDefinition,
        all_strings: list[str],
        class_names: list[str],
    ) -> RuleMatch | None:
        """Check a single rule against the string index."""
        if not rule.strings:
            return None

        matches: dict[int, list[str]] = {}  # string_idx -> matched_values
        combined_text = "\n".join(all_strings)
        combined_classes = "\n".join(class_names)
        full_text = combined_text + "\n" + combined_classes

        for idx, s_def in enumerate(rule.strings):
            kind = s_def.get("kind", "literal")
            value = s_def.get("value", "")

            if kind == "literal":
                if value in full_text:
                    matches[idx] = [value]
            elif kind == "regex":
                try:
                    # Block obvious ReDoS patterns
                    if _REDO_PATTERNS.search(value):
                        continue
                    pattern = re.compile(value, re.IGNORECASE)
                    # Limit input text length to prevent ReDoS
                    found = pattern.findall(full_text[:_MAX_REGEX_TEXT])
                    if found:
                        matches[idx] = found[:5]
                except re.error:
                    pass
            elif kind == "hex":
                try:
                    hex_bytes = bytes.fromhex(value.replace(" ", ""))
                    if hex_bytes in full_text.encode("utf-8", errors="replace"):
                        matches[idx] = [value]
                except ValueError:
                    pass

        # Evaluate condition
        if self._evaluate_condition(rule.condition, matches, len(rule.strings)):
            matched_values = []
            for vals in matches.values():
                matched_values.extend(vals)

            return RuleMatch(
                rule_id=rule.rule_id,
                severity=rule.severity,
                description=rule.description,
                matched_value=matched_values[0][:200] if matched_values else "",
                context={
                    "family": rule.family,
                    "matched_count": len(matches),
                    "total_strings_matched": sum(len(v) for v in matches.values()),
                },
            )

        return None

    @staticmethod
    def _evaluate_condition(
        condition: str,
        matches: dict[int, list[str]],
        total_strings: int,
    ) -> bool:
        """Evaluate a rule condition against match results."""
        if not condition:
            # No condition = any string match is sufficient
            return bool(matches)

        # Simple condition parsing:
        # "all" = all strings must match
        # "any" = any string must match
        # "count(X) >= N" = at least N strings must match
        condition = condition.strip().lower()

        if condition == "all":
            return len(matches) == total_strings
        if condition == "any":
            return bool(matches)

        # Parse "count(...) >= N"
        count_match = re.search(r"count\s*\(\s*\)\s*>=\s*(\d+)", condition)
        if count_match:
            threshold = int(count_match.group(1))
            return len(matches) >= threshold

        return bool(matches)


class RulePackLoader:
    """Load rule packs from YAML files."""

    def __init__(self) -> None:
        self.packs: list[RulePack] = []

    def load_defaults(self) -> None:
        """Load the built-in and user-downloaded rule packs."""
        packs_dir = Path(__file__).parent / "packs"
        for yaml_file in sorted(packs_dir.glob("*.yaml")):
            self.load_pack(yaml_file)

        from mcrataway.constants import CONFIG_DIR
        user_rules_dir = CONFIG_DIR / "rules"
        if user_rules_dir.exists():
            for yaml_file in sorted(user_rules_dir.glob("*.yaml")):
                self.load_pack(yaml_file)

    def load_pack(self, path: Path) -> None:
        """Load a single rule pack from a YAML file."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except Exception:
            return

        if not isinstance(data, dict):
            return

        pack_id = data.get("pack_id", path.stem)
        rules: list[RuleDefinition] = []

        for rule_data in data.get("rules", []):
            severity_str = rule_data.get("severity", "medium").upper()
            severity = getattr(Severity, severity_str, Severity.MEDIUM)

            rules.append(
                RuleDefinition(
                    rule_id=rule_data.get("id", ""),
                    family=rule_data.get("family", ""),
                    severity=severity,
                    description=rule_data.get("description", ""),
                    strings=rule_data.get("strings", []),
                    condition=rule_data.get("condition", ""),
                )
            )

        if rules:
            self.packs.append(RulePack(pack_id, rules))

    def all_rules(self) -> list[RulePack]:
        """Return all loaded rule packs."""
        return list(self.packs)
