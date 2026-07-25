"""Rule pack loader and matcher — YAML-defined signature rules.

Rule matching is streaming/per-entry rather than "decode every entry
to text, concatenate, and regex the result": the scan engine now
iterates archive entries one at a time (see
``parsers.archive.ArchiveReader.entries``, a generator) specifically
to avoid holding every entry's bytes in memory simultaneously, and
concatenating everything back into one string here would undo that.
A :class:`RuleMatchState` accumulates per-rule match state across
calls to :meth:`RulePack.feed_entry`, one entry at a time; patterns
that would need to span an entry boundary are handled via a small
sliding-window tail (see :class:`RuleMatchState`) rather than by
requiring the whole archive in memory at once.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import regex
import yaml

from mcrataway.constants import Severity
from mcrataway.parsers.archive import ArchiveEntry, is_java_class

# Maximum text length scanned by a single regex per entry (1 MB) —
# still bounds worst-case regex cost per entry even though entries are
# now processed one at a time rather than as one giant blob.
_MAX_REGEX_TEXT = 1024 * 1024

# Hard wall-clock budget for a single regex evaluation. The
# ReDoS-pattern heuristic below (_REDO_PATTERNS) catches known-bad
# *shapes* but, like any such heuristic, cannot catch every pattern
# that exhibits catastrophic backtracking on some input — it is a
# static approximation of a runtime property. This timeout is the
# actual backstop: the `regex` module (unlike stdlib `re`) can abort a
# match in progress after this many seconds, so even a pattern that
# slips past the heuristic cannot hang a scan indefinitely.
_REGEX_TIMEOUT_SECONDS = 1.0

# Regex patterns that can cause catastrophic backtracking (ReDoS).
# A first line of defense (skip obviously bad patterns before ever
# running them) — the per-match timeout above is the backstop for
# patterns this heuristic does not catch.
_REDO_PATTERNS = re.compile(
    r"(\(([^()]*\+[^()]*)+\)|\(([^()]*\*)[^()]*\)\+|(\.\+)\+|(\.\*)\+)"
)

# Sliding-window tail length carried between entries so a literal or
# short regex pattern that happens to straddle an entry boundary (rare
# in practice, since entries are independent files, but cheap to
# cover) is not missed. Bounded well below _MAX_REGEX_TEXT.
_TAIL_WINDOW = 256


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


class StringPattern:
    """A single string pattern to match, evaluated against one chunk of text.

    Regex patterns are compiled once at construction time rather than
    on every :meth:`matches` call — with per-entry streaming matching,
    a rule pattern is now evaluated once per archive entry rather than
    once for the whole archive, so recompiling the same pattern
    hundreds of times per scan was measurable overhead.
    """

    def __init__(self, kind: str, value: str) -> None:
        self.kind = kind
        self.value = value
        self._compiled: "regex.Pattern[str] | None" = None
        self._hex_bytes: bytes | None = None
        self._redos_blocked = False

        if kind == "regex":
            if _REDO_PATTERNS.search(value):
                self._redos_blocked = True
            else:
                try:
                    self._compiled = regex.compile(value, regex.IGNORECASE)
                except regex.error:
                    self._compiled = None
        elif kind == "hex":
            try:
                self._hex_bytes = bytes.fromhex(value.replace(" ", ""))
            except ValueError:
                self._hex_bytes = None

    def matches(self, text: str, raw_data: bytes = b"") -> list[str]:
        """Check if the pattern matches the given text chunk. Returns matched values.

        *raw_data*, if given, is used for ``hex`` patterns instead of
        re-encoding *text* — matching against the actual original
        bytes rather than a decode-then-reencode round trip, which can
        silently corrupt byte sequences that are not valid UTF-8 (the
        exact case a hex pattern, e.g. an Ethereum function selector,
        is often looking for).
        """
        if self.kind == "literal":
            if self.value in text:
                return [self.value]
        elif self.kind == "regex":
            if self._redos_blocked or self._compiled is None:
                return []
            try:
                # `regex` (not stdlib `re`) supports timeout=, which
                # aborts a runaway match rather than hanging the scan —
                # the backstop for ReDoS patterns _REDO_PATTERNS misses.
                found: list[str] = self._compiled.findall(
                    text[:_MAX_REGEX_TEXT], timeout=_REGEX_TIMEOUT_SECONDS
                )
                return found
            except TimeoutError:
                return []
        elif self.kind == "hex":
            if self._hex_bytes is None:
                return []
            haystack = raw_data if raw_data else text.encode("utf-8", errors="replace")
            if self._hex_bytes in haystack:
                return [self.value]
        return []


class RuleMatchState:
    """Accumulates match state for one :class:`RulePack` across a stream
    of archive entries, without holding all entry text in memory.

    A ``_tail`` of the last :data:`_TAIL_WINDOW` characters of decoded
    text is kept per rule pack (not per entry) so literal/regex
    patterns that straddle an entry boundary still match; this is a
    deliberate, bounded trade-off against requiring the whole archive
    concatenated in memory.
    """

    def __init__(self) -> None:
        # rule_id -> {pattern_idx -> matched values (deduped, capped)}
        self._matches: dict[str, dict[int, list[str]]] = {}
        self._class_names: list[str] = []
        self._tail = ""
        # rule_id -> compiled StringPattern list, built once on first
        # use rather than reconstructed (and every regex recompiled)
        # for every single archive entry.
        self._compiled_patterns: dict[str, list[StringPattern]] = {}

    def _patterns_for(self, rule: "RuleDefinition") -> list[StringPattern]:
        compiled = self._compiled_patterns.get(rule.rule_id)
        if compiled is None:
            compiled = [
                StringPattern(kind=s.get("kind", "literal"), value=s.get("value", ""))
                for s in rule.strings
            ]
            self._compiled_patterns[rule.rule_id] = compiled
        return compiled

    def feed_entry(self, rules: list["RuleDefinition"], entry: ArchiveEntry) -> None:
        """Feed one archive entry's content into the accumulated state.

        Note: an earlier version of this method tried to skip
        decode()+findall() for entries that "look binary" (few
        printable bytes in a leading sample), to cut per-entry regex
        overhead. That heuristic was dropped after testing against a
        real compiled .class file: the constant pool's length-prefixed
        binary structure dominates a leading byte sample even when the
        class contains exactly the string literals (e.g.
        "java.lang.Runtime", "getAccessToken") that rules are meant to
        catch, so it silently produced false negatives on the most
        important case — a malicious class file. Correctness comes
        first; regex cost here is bounded by _MAX_REGEX_TEXT per entry
        regardless.
        """
        if is_java_class(entry.data):
            self._class_names.append(entry.name)

        try:
            text = entry.data.decode("utf-8", errors="replace")
        except Exception:
            return

        # Prepend the tail from the previous entry so boundary-straddling
        # patterns still match, then keep a new tail for next time.
        chunk = self._tail + "\n" + text if self._tail else text
        self._tail = text[-_TAIL_WINDOW:] if len(text) >= _TAIL_WINDOW else text

        for rule in rules:
            if not rule.strings:
                continue
            rule_matches = self._matches.setdefault(rule.rule_id, {})
            patterns = self._patterns_for(rule)
            for idx, pattern in enumerate(patterns):
                if idx in rule_matches and len(rule_matches[idx]) >= 5:
                    continue  # already capped for this rule/pattern
                found = pattern.matches(chunk, raw_data=entry.data)
                if found:
                    existing = rule_matches.setdefault(idx, [])
                    for f in found:
                        if len(existing) >= 5:
                            break
                        existing.append(f)

    def result_for(self, rule: "RuleDefinition") -> dict[int, list[str]]:
        return self._matches.get(rule.rule_id, {})

    @property
    def class_names(self) -> list[str]:
        return self._class_names


class RulePack:
    """A loaded set of rules from a YAML file."""

    def __init__(self, pack_id: str, rules: list[RuleDefinition]) -> None:
        self.pack_id = pack_id
        self.rules = rules

    def new_match_state(self) -> RuleMatchState:
        """Create a fresh streaming match state for one archive scan."""
        return RuleMatchState()

    def evaluate(self, state: RuleMatchState) -> list[RuleMatch]:
        """Evaluate all rules against accumulated streaming match state."""
        matches: list[RuleMatch] = []
        for rule in self.rules:
            match_result = self._check_rule(rule, state)
            if match_result:
                matches.append(match_result)
        return matches

    def matches_archive(
        self,
        entries: list[ArchiveEntry],
        class_entries: list[ArchiveEntry],
    ) -> list[RuleMatch]:
        """Convenience wrapper for callers that already have the full
        entry list materialized (e.g. the rule-testing API endpoint).
        The scan engine's hot path uses :meth:`new_match_state` +
        :meth:`RuleMatchState.feed_entry` directly to avoid requiring
        every entry to be resident in memory at once.
        """
        state = self.new_match_state()
        for entry in entries:
            state.feed_entry(self.rules, entry)
        return self.evaluate(state)

    def _check_rule(
        self,
        rule: RuleDefinition,
        state: RuleMatchState,
    ) -> RuleMatch | None:
        """Check a single rule against accumulated match state."""
        if not rule.strings:
            return None

        matches = state.result_for(rule)

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
            new_pack = RulePack(pack_id, rules)
            for idx, existing in enumerate(self.packs):
                if existing.pack_id == pack_id:
                    self.packs[idx] = new_pack
                    return
            self.packs.append(new_pack)

    def all_rules(self) -> list[RulePack]:
        """Return all loaded rule packs."""
        return list(self.packs)
