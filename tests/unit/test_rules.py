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


def test_rule_pack_deduplication(tmp_path):
    yaml_content_1 = "pack_id: my_pack\nrules:\n  - id: r1\n    severity: high\n    description: test1\n    strings:\n      - kind: literal\n        value: foo\n"
    yaml_content_2 = "pack_id: my_pack\nrules:\n  - id: r2\n    severity: low\n    description: test2\n    strings:\n      - kind: literal\n        value: bar\n"

    file1 = tmp_path / "pack1.yaml"
    file2 = tmp_path / "pack2.yaml"
    file1.write_text(yaml_content_1)
    file2.write_text(yaml_content_2)

    loader = RulePackLoader()
    loader.load_pack(file1)
    assert len(loader.packs) == 1
    assert loader.packs[0].rules[0].rule_id == "r1"

    loader.load_pack(file2)
    assert len(loader.packs) == 1
    assert loader.packs[0].rules[0].rule_id == "r2"
