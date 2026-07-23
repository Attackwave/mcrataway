"""Unit tests for rules/matcher.py."""

import pytest

from mcrataway.constants import Severity
from mcrataway.parsers.archive import ArchiveEntry
from mcrataway.rules.matcher import RuleMatcher, StringPattern


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


class TestRuleMatcher:
    @pytest.fixture()
    def sample_entries(self) -> list[ArchiveEntry]:
        data = b"Runtime.getRuntime().exec(cmd)"
        size = len(data)
        return [
            ArchiveEntry(name="test.class", data=data, offset=0, size=size, compressed_size=size)
        ]

    def test_from_dict(self) -> None:
        rule = RuleMatcher.from_dict({
            "id": "RULE_001",
            "family": "test_family",
            "severity": "critical",
            "description": "Test rule",
            "strings": [
                {"kind": "literal", "value": "Runtime"},
            ],
        })
        assert rule.rule_id == "RULE_001"
        assert rule.severity == Severity.CRITICAL
        assert len(rule.patterns) == 1

    def test_match_literal(self, sample_entries: list[ArchiveEntry]) -> None:
        rule = RuleMatcher.from_dict({
            "id": "RULE_001",
            "family": "test",
            "severity": "critical",
            "description": "Test",
            "strings": [{"kind": "literal", "value": "Runtime"}],
        })
        matches = rule.match(sample_entries)
        assert len(matches) == 1

    def test_evaluate_match(self, sample_entries: list[ArchiveEntry]) -> None:
        rule = RuleMatcher.from_dict({
            "id": "RULE_001",
            "family": "test",
            "severity": "critical",
            "description": "Process execution",
            "strings": [{"kind": "literal", "value": "Runtime"}],
        })
        result = rule.evaluate(sample_entries)
        assert result is not None
        assert result["rule_id"] == "RULE_001"
        assert result["severity"] == "CRITICAL"

    def test_evaluate_no_match(self, sample_entries: list[ArchiveEntry]) -> None:
        rule = RuleMatcher.from_dict({
            "id": "RULE_002",
            "family": "test",
            "severity": "medium",
            "description": "No match",
            "strings": [{"kind": "literal", "value": "nonexistent_pattern"}],
        })
        assert rule.evaluate(sample_entries) is None

    def test_condition_all_matches(self, sample_entries: list[ArchiveEntry]) -> None:
        rule = RuleMatcher(
            rule_id="ALL_001",
            family="test",
            severity=Severity.HIGH,
            description="All patterns",
            patterns=[
                StringPattern("literal", "Runtime"),
                StringPattern("literal", "exec"),
            ],
            condition="all",
        )
        result = rule.evaluate(sample_entries)
        assert result is not None

    def test_condition_all_fails(self, sample_entries: list[ArchiveEntry]) -> None:
        rule = RuleMatcher(
            rule_id="ALL_002",
            family="test",
            severity=Severity.HIGH,
            description="All patterns",
            patterns=[
                StringPattern("literal", "Runtime"),
                StringPattern("literal", "nonexistent"),
            ],
            condition="all",
        )
        assert rule.evaluate(sample_entries) is None

    def test_condition_count_threshold(self, sample_entries: list[ArchiveEntry]) -> None:
        rule = RuleMatcher(
            rule_id="COUNT_001",
            family="test",
            severity=Severity.HIGH,
            description="Count threshold",
            patterns=[
                StringPattern("literal", "Runtime"),
                StringPattern("literal", "exec"),
                StringPattern("literal", "cmd"),
            ],
            condition="count() >= 2",
        )
        result = rule.evaluate(sample_entries)
        assert result is not None

    def test_condition_count_below_threshold(self, sample_entries: list[ArchiveEntry]) -> None:
        rule = RuleMatcher(
            rule_id="COUNT_002",
            family="test",
            severity=Severity.HIGH,
            description="Count threshold",
            patterns=[
                StringPattern("literal", "Runtime"),
            ],
            condition="count() >= 5",
        )
        assert rule.evaluate(sample_entries) is None

    def test_empty_condition_defaults_to_any(self, sample_entries: list[ArchiveEntry]) -> None:
        rule = RuleMatcher(
            rule_id="EMPTY_001",
            family="test",
            severity=Severity.MEDIUM,
            description="No condition",
            patterns=[StringPattern("literal", "Runtime")],
        )
        result = rule.evaluate(sample_entries)
        assert result is not None
