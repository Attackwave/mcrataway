"""Unit tests for the rule matching in rules/loader.py.

Historically this tested a separate, parallel implementation in
rules/matcher.py (RuleMatcher) that duplicated RulePack's logic but
was never actually used by the scan engine — a dead code path kept
alive only by its own tests. It has been consolidated into
RulePack/RuleDefinition (loader.py), which the scan engine actually
uses, so these tests now exercise that.
"""

from mcrataway.constants import Severity
from mcrataway.parsers.archive import ArchiveEntry
from mcrataway.rules.loader import RuleDefinition, RulePack, StringPattern


class TestStringPattern:
    def test_literal_match(self) -> None:
        pattern = StringPattern("literal", "Runtime.getRuntime")
        assert pattern.matches("String s = Runtime.getRuntime().exec(cmd)")

    def test_literal_no_match(self) -> None:
        pattern = StringPattern("literal", "nonexistent")
        assert pattern.matches("just a normal string") == []

    def test_regex_match(self) -> None:
        pattern = StringPattern("regex", r"Runtime\.getRuntime.*exec")
        assert pattern.matches("Runtime.getRuntime().exec(cmd)")

    def test_regex_case_insensitive(self) -> None:
        pattern = StringPattern("regex", r"runtime\.getruntime")
        assert pattern.matches("Runtime.getRuntime()")

    def test_hex_match(self) -> None:
        pattern = StringPattern("hex", "52756e74696d65")  # "Runtime"
        assert pattern.matches("Runtime exec")

    def test_regex_timeout_is_handled_gracefully(self) -> None:
        """A regex evaluation that exceeds the timeout backstop must
        return no matches rather than propagate TimeoutError — the
        ReDoS-shape heuristic (_REDO_PATTERNS) cannot catch every
        pathological pattern, so this timeout is the actual backstop
        against a runaway match hanging a scan."""
        from unittest.mock import MagicMock

        pattern = StringPattern("regex", "some_pattern")
        assert pattern._compiled is not None
        mock_compiled = MagicMock()
        mock_compiled.findall.side_effect = TimeoutError
        pattern._compiled = mock_compiled

        assert pattern.matches("some text to match") == []


def _rule_pack(rule: RuleDefinition) -> RulePack:
    return RulePack(pack_id="test_pack", rules=[rule])


class TestRulePackMatching:
    def sample_entries(self) -> list[ArchiveEntry]:
        data = b"Runtime.getRuntime().exec(cmd)"
        size = len(data)
        return [
            ArchiveEntry(name="test.class", data=data, offset=0, size=size, compressed_size=size)
        ]

    def test_match_literal(self) -> None:
        rule = RuleDefinition(
            rule_id="RULE_001",
            family="test",
            severity=Severity.CRITICAL,
            description="Test",
            strings=[{"kind": "literal", "value": "Runtime"}],
        )
        pack = _rule_pack(rule)
        matches = pack.matches_archive(self.sample_entries(), [])
        assert len(matches) == 1
        assert matches[0].rule_id == "RULE_001"
        assert matches[0].severity == Severity.CRITICAL

    def test_no_match(self) -> None:
        rule = RuleDefinition(
            rule_id="RULE_002",
            family="test",
            severity=Severity.MEDIUM,
            description="No match",
            strings=[{"kind": "literal", "value": "nonexistent_pattern"}],
        )
        pack = _rule_pack(rule)
        assert pack.matches_archive(self.sample_entries(), []) == []

    def test_condition_all_matches(self) -> None:
        rule = RuleDefinition(
            rule_id="ALL_001",
            family="test",
            severity=Severity.HIGH,
            description="All patterns",
            strings=[
                {"kind": "literal", "value": "Runtime"},
                {"kind": "literal", "value": "exec"},
            ],
            condition="all",
        )
        pack = _rule_pack(rule)
        assert len(pack.matches_archive(self.sample_entries(), [])) == 1

    def test_condition_all_fails(self) -> None:
        rule = RuleDefinition(
            rule_id="ALL_002",
            family="test",
            severity=Severity.HIGH,
            description="All patterns",
            strings=[
                {"kind": "literal", "value": "Runtime"},
                {"kind": "literal", "value": "nonexistent"},
            ],
            condition="all",
        )
        pack = _rule_pack(rule)
        assert pack.matches_archive(self.sample_entries(), []) == []

    def test_condition_count_threshold(self) -> None:
        rule = RuleDefinition(
            rule_id="COUNT_001",
            family="test",
            severity=Severity.HIGH,
            description="Count threshold",
            strings=[
                {"kind": "literal", "value": "Runtime"},
                {"kind": "literal", "value": "exec"},
                {"kind": "literal", "value": "cmd"},
            ],
            condition="count() >= 2",
        )
        pack = _rule_pack(rule)
        assert len(pack.matches_archive(self.sample_entries(), [])) == 1

    def test_condition_count_below_threshold(self) -> None:
        rule = RuleDefinition(
            rule_id="COUNT_002",
            family="test",
            severity=Severity.HIGH,
            description="Count threshold",
            strings=[{"kind": "literal", "value": "Runtime"}],
            condition="count() >= 5",
        )
        pack = _rule_pack(rule)
        assert pack.matches_archive(self.sample_entries(), []) == []

    def test_empty_condition_defaults_to_any(self) -> None:
        rule = RuleDefinition(
            rule_id="EMPTY_001",
            family="test",
            severity=Severity.MEDIUM,
            description="No condition",
            strings=[{"kind": "literal", "value": "Runtime"}],
        )
        pack = _rule_pack(rule)
        assert len(pack.matches_archive(self.sample_entries(), [])) == 1

    def test_streaming_matches_across_multiple_entries(self) -> None:
        """Patterns from different entries must both count toward a
        multi-string condition — matching must not be entry-local."""
        entries = [
            ArchiveEntry(name="a.txt", data=b"Runtime reference here", offset=0, size=22, compressed_size=22),
            ArchiveEntry(name="b.txt", data=b"exec call happens here", offset=0, size=22, compressed_size=22),
        ]
        rule = RuleDefinition(
            rule_id="STREAM_001",
            family="test",
            severity=Severity.HIGH,
            description="Cross-entry",
            strings=[
                {"kind": "literal", "value": "Runtime"},
                {"kind": "literal", "value": "exec"},
            ],
            condition="all",
        )
        pack = _rule_pack(rule)
        assert len(pack.matches_archive(entries, [])) == 1
