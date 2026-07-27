"""Round-trip tests for rules/yaml_writer.py."""

from pathlib import Path

import yaml

from mcrataway.constants import Severity
from mcrataway.rules.loader import RuleDefinition, RulePackLoader
from mcrataway.rules.yaml_writer import pack_to_yaml, rule_to_dict, write_proposal


def _make_rule(rule_id: str, kind: str, value: str) -> RuleDefinition:
    return RuleDefinition(
        rule_id=rule_id,
        family="test_family",
        severity=Severity.HIGH,
        description="A test rule.",
        strings=[{"kind": kind, "value": value}],
        condition="any",
    )


def test_rule_to_dict_matches_schema():
    rule = _make_rule("r1", "literal", "evil_string")
    d = rule_to_dict(rule)
    assert d == {
        "id": "r1",
        "family": "test_family",
        "severity": "high",
        "description": "A test rule.",
        "strings": [{"kind": "literal", "value": "evil_string"}],
        "condition": "any",
    }


def test_pack_to_yaml_round_trip_literal(tmp_path: Path):
    rule = _make_rule("literal_rule", "literal", "some_literal")
    yaml_text = pack_to_yaml("my_pack", [rule], description="desc")
    out = tmp_path / "pack.yaml"
    out.write_text(yaml_text)

    loader = RulePackLoader()
    loader.load_pack(out)
    packs = loader.all_rules()
    assert len(packs) == 1
    assert packs[0].pack_id == "my_pack"
    assert len(packs[0].rules) == 1
    loaded = packs[0].rules[0]
    assert loaded.rule_id == rule.rule_id
    assert loaded.family == rule.family
    assert loaded.severity == rule.severity
    assert loaded.description == rule.description
    assert loaded.strings == rule.strings
    assert loaded.condition == rule.condition


def test_pack_to_yaml_round_trip_all_string_kinds(tmp_path: Path):
    rules = [
        _make_rule("r_literal", "literal", "abc"),
        _make_rule("r_regex", "regex", "ab.*c"),
        _make_rule("r_hex", "hex", "ce6d41de"),
    ]
    yaml_text = pack_to_yaml("multi_kind_pack", rules)
    out = tmp_path / "pack.yaml"
    out.write_text(yaml_text)

    loader = RulePackLoader()
    loader.load_pack(out)
    loaded_rules = {r.rule_id: r for r in loader.all_rules()[0].rules}
    for original in rules:
        loaded = loaded_rules[original.rule_id]
        assert loaded.strings == original.strings
        assert loaded.severity == original.severity


def test_pack_to_yaml_is_valid_yaml():
    rule = _make_rule("r1", "literal", "x")
    text = pack_to_yaml("p", [rule])
    data = yaml.safe_load(text)
    assert data["pack_id"] == "p"
    assert data["rules"][0]["id"] == "r1"


def test_write_proposal_is_load_pack_compatible(tmp_path: Path):
    from mcrataway.rulegen.propose import RuleProposal

    rule = _make_rule("proposed_rule", "literal", "candidate_string")
    proposal = RuleProposal(
        definition=rule,
        source_samples=["abc123"],
        generated_at="2026-01-01T00:00:00+00:00",
        generator_version="2.0.0",
        notes="1 candidate pattern(s) from 1 sample(s).",
    )
    out = tmp_path / "family.proposed.yaml"
    write_proposal(proposal, out)

    loader = RulePackLoader()
    loader.load_pack(out)
    packs = loader.all_rules()
    assert len(packs) == 1
    assert packs[0].rules[0].rule_id == "proposed_rule"

    raw = yaml.safe_load(out.read_text())
    assert raw["proposal_metadata"]["status"] == "proposed"
    assert raw["proposal_metadata"]["source_samples"] == ["abc123"]
