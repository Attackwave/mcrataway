"""Unit tests for rules loader and matcher."""


from mcrataway.constants import Severity
from mcrataway.parsers.archive import ArchiveEntry
from mcrataway.rules.loader import RuleDefinition, RulePack, RulePackLoader


def _make_archive_entry(name: str, content: str) -> ArchiveEntry:
    return ArchiveEntry(
        name=name,
        data=content.encode("utf-8"),
        offset=0,
        size=len(content),
        compressed_size=len(content),
    )


def test_rule_match_literal():
    rule = RuleDefinition(
        rule_id="test_literal",
        family="test",
        severity=Severity.HIGH,
        description="test",
        strings=[{"kind": "literal", "value": "evil_url"}],
        condition="any",
    )
    pack = RulePack("test_pack", [rule])
    entries = [_make_archive_entry("Test.class", "some evil_url here")]
    matches = pack.matches_archive(entries, [])
    assert len(matches) == 1
    assert matches[0].rule_id == "test_literal"


def test_rule_match_regex():
    rule = RuleDefinition(
        rule_id="test_regex",
        family="test",
        severity=Severity.MEDIUM,
        description="test",
        strings=[{"kind": "regex", "value": "evil[_-]url"}],
        condition="any",
    )
    pack = RulePack("test_pack", [rule])
    entries = [_make_archive_entry("Test.class", "some evil-url here")]
    matches = pack.matches_archive(entries, [])
    assert len(matches) == 1


def test_rule_match_hex():
    rule = RuleDefinition(
        rule_id="test_hex",
        family="test",
        severity=Severity.HIGH,
        description="test",
        strings=[{"kind": "hex", "value": "6576696c"}],  # "evil"
        condition="any",
    )
    pack = RulePack("test_pack", [rule])
    entries = [_make_archive_entry("Test.class", "some evil here")]
    matches = pack.matches_archive(entries, [])
    assert len(matches) == 1


def test_rule_no_match():
    rule = RuleDefinition(
        rule_id="test_no_match",
        family="test",
        severity=Severity.HIGH,
        description="test",
        strings=[{"kind": "literal", "value": "not_present"}],
        condition="any",
    )
    pack = RulePack("test_pack", [rule])
    entries = [_make_archive_entry("Test.class", "safe content")]
    matches = pack.matches_archive(entries, [])
    assert len(matches) == 0


def test_rule_condition_count():
    rule = RuleDefinition(
        rule_id="test_count",
        family="test",
        severity=Severity.HIGH,
        description="test",
        strings=[
            {"kind": "literal", "value": "str1"},
            {"kind": "literal", "value": "str2"},
            {"kind": "literal", "value": "str3"},
        ],
        condition="count() >= 2",
    )
    pack = RulePack("test_pack", [rule])
    # Only 2 of 3 strings present
    entries = [_make_archive_entry("Test.class", "str1 and str2")]
    matches = pack.matches_archive(entries, [])
    assert len(matches) == 1


def test_rule_condition_count_fails():
    rule = RuleDefinition(
        rule_id="test_count_fail",
        family="test",
        severity=Severity.HIGH,
        description="test",
        strings=[
            {"kind": "literal", "value": "str1"},
            {"kind": "literal", "value": "str2"},
            {"kind": "literal", "value": "str3"},
        ],
        condition="count() >= 3",
    )
    pack = RulePack("test_pack", [rule])
    entries = [_make_archive_entry("Test.class", "str1 only")]
    matches = pack.matches_archive(entries, [])
    assert len(matches) == 0


def test_rule_pack_loader_defaults():
    loader = RulePackLoader()
    loader.load_defaults()
    assert len(loader.packs) >= 2


def test_rule_pack_all_rules():
    loader = RulePackLoader()
    loader.load_defaults()
    rules = loader.all_rules()
    assert all(isinstance(r, RulePack) for r in rules)
    for pack in rules:
        assert len(pack.rules) > 0
