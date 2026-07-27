"""Tests for the rulegen pipeline (sample analysis, feature extraction,
correlation, and rule proposal)."""

import struct
import zipfile
from pathlib import Path

from mcrataway.core.scan_engine import ScanEngine
from mcrataway.rules.loader import RulePackLoader
from mcrataway.rulegen.correlate import generalize
from mcrataway.rulegen.engine import RuleGenEngine
from mcrataway.rulegen.features import CandidateFeature, extract_candidates
from mcrataway.rulegen.propose import propose_rule
from mcrataway.rulegen.sample import analyze_sample, analyze_samples


def _build_class_raw(cp_strings: list[str]) -> bytes:
    all_strings = ["com/test/A", "java/lang/Object", "m", "()V", "Code"] + cp_strings
    pool = struct.pack(">H", len(all_strings) + 1)
    for s in all_strings:
        encoded = s.encode("utf-8")
        pool += struct.pack(">BH", 1, len(encoded)) + encoded
    bc = struct.pack(">B", 177)
    code_info = struct.pack(">HHI", 2, 2, len(bc)) + bc + struct.pack(">HH", 0, 0)
    code_attr = struct.pack(">HI", 5, len(code_info)) + code_info
    method = struct.pack(">HHH", 0x0001, 3, 4) + struct.pack(">H", 1) + code_attr
    body = struct.pack(">HHH", 0x0001, 1, 2)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 1) + method
    body += struct.pack(">H", 0)
    return b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 52) + pool + body


def _make_jar(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


def _make_suspicious_jar(path: Path, extra_strings: list[str]) -> None:
    class_data = _build_class_raw([
        "getSession",
        "getAccessToken",
        "https://evil.example.com/collect",
        "session.json",
        *extra_strings,
    ])
    _make_jar(path, {"com/test/Steal.class": class_data})


# --- ScanEngine.keep_evidence_index -----------------------------------


def test_scan_files_without_keep_evidence_index_defaults_to_none(tmp_path: Path):
    jar_path = tmp_path / "suspicious.jar"
    _make_suspicious_jar(jar_path, [])

    engine = ScanEngine()
    results = engine.scan_files([jar_path])
    assert results[0].evidence_index is None
    assert results[0].reconstructed_strings is None


def test_scan_files_with_keep_evidence_index_returns_index(tmp_path: Path):
    jar_path = tmp_path / "suspicious.jar"
    _make_suspicious_jar(jar_path, [])

    engine = ScanEngine()
    results = engine.scan_files([jar_path], keep_evidence_index=True)
    assert results[0].evidence_index is not None
    assert len(results[0].evidence_index.evidence) > 0
    assert results[0].reconstructed_strings is not None


# --- rulegen/sample.py ---------------------------------------------------


def test_analyze_sample_retains_full_evidence(tmp_path: Path):
    jar_path = tmp_path / "suspicious.jar"
    _make_suspicious_jar(jar_path, [])

    analysis = analyze_sample(jar_path)
    assert analysis.file_hash
    assert len(analysis.evidence_index.evidence) > 0


def test_analyze_samples_batch(tmp_path: Path):
    jar1 = tmp_path / "a.jar"
    jar2 = tmp_path / "b.jar"
    _make_suspicious_jar(jar1, [])
    _make_suspicious_jar(jar2, [])

    analyses = analyze_samples([jar1, jar2])
    assert len(analyses) == 2


# --- rulegen/features.py --------------------------------------------------


def test_extract_candidates_pulls_matched_values(tmp_path: Path):
    jar_path = tmp_path / "suspicious.jar"
    _make_suspicious_jar(jar_path, [])

    analysis = analyze_sample(jar_path)
    candidates = extract_candidates(analysis)
    assert any(c.value == "https://evil.example.com/collect" for c in candidates)
    for c in candidates:
        assert analysis.file_hash in c.sample_hashes


def test_extract_candidates_excludes_rule_matches(tmp_path: Path):
    jar_path = tmp_path / "suspicious.jar"
    _make_suspicious_jar(jar_path, [])

    analysis = analyze_sample(jar_path)
    candidates = extract_candidates(analysis)
    assert not any(det.startswith("rule:") for c in candidates for det in c.detector_ids)


# --- rulegen/correlate.py -------------------------------------------------


def test_generalize_single_sample_keeps_everything():
    candidates = [
        CandidateFeature(kind="literal", value="a", source="constant_pool"),
        CandidateFeature(kind="literal", value="b", source="constant_pool"),
    ]
    result = generalize([candidates])
    assert {c.value for c in result} == {"a", "b"}


def test_generalize_keeps_common_drops_unique():
    shared = "shared_c2_string"
    sample_a = [
        CandidateFeature(kind="literal", value=shared, source="constant_pool", sample_hashes={"hash_a"}),
        CandidateFeature(kind="literal", value="only_in_a", source="constant_pool", sample_hashes={"hash_a"}),
    ]
    sample_b = [
        CandidateFeature(kind="literal", value=shared, source="constant_pool", sample_hashes={"hash_b"}),
        CandidateFeature(kind="literal", value="only_in_b", source="constant_pool", sample_hashes={"hash_b"}),
    ]
    sample_c = [
        CandidateFeature(kind="literal", value=shared, source="constant_pool", sample_hashes={"hash_c"}),
    ]

    result = generalize([sample_a, sample_b, sample_c], min_sample_fraction=0.6)
    values = {c.value for c in result}
    assert shared in values
    assert "only_in_a" not in values
    assert "only_in_b" not in values

    merged_shared = next(c for c in result if c.value == shared)
    assert merged_shared.sample_hashes == {"hash_a", "hash_b", "hash_c"}


def test_generalize_empty_input():
    assert generalize([]) == []


# --- rulegen/propose.py ---------------------------------------------------


def test_propose_rule_builds_definition():
    candidates = [
        CandidateFeature(kind="literal", value="evil_marker", source="constant_pool", sample_hashes={"h1"}),
    ]
    proposal = propose_rule(candidates, family="my_family")
    assert proposal.status == "proposed"
    assert proposal.definition.family == "my_family"
    assert proposal.definition.strings == [{"kind": "literal", "value": "evil_marker"}]
    assert proposal.source_samples == ["h1"]
    assert proposal.generated_at


# --- rulegen/engine.py (end-to-end) --------------------------------------


def test_generate_from_directory_end_to_end(tmp_path: Path):
    jar_path = tmp_path / "suspicious.jar"
    _make_suspicious_jar(jar_path, [])

    engine = RuleGenEngine()
    proposal = engine.generate_from_directory(tmp_path, family="synthetic_family")

    assert proposal.definition.family == "synthetic_family"
    assert len(proposal.definition.strings) > 0
    assert proposal.status == "proposed"


def test_generate_from_analyses_matches_generate_from_directory(tmp_path: Path):
    jar_path = tmp_path / "suspicious.jar"
    _make_suspicious_jar(jar_path, [])

    engine = RuleGenEngine()
    analyses = analyze_samples([jar_path])
    proposal = engine.generate_from_analyses(analyses, family="synthetic_family")

    assert len(proposal.definition.strings) > 0


# --- proposed/ directory isolation from RulePackLoader.load_defaults ------


def test_proposed_subdir_not_loaded_by_load_defaults(tmp_path: Path, monkeypatch):
    from mcrataway.rules.yaml_writer import write_proposal
    from mcrataway.rulegen.propose import RuleProposal
    from mcrataway.rules.loader import RuleDefinition
    from mcrataway.constants import Severity

    user_rules_dir = tmp_path / "rules"
    proposed_dir = user_rules_dir / "proposed"
    proposed_dir.mkdir(parents=True)

    rule = RuleDefinition(
        rule_id="should_not_load",
        family="test",
        severity=Severity.MEDIUM,
        description="d",
        strings=[{"kind": "literal", "value": "x"}],
        condition="any",
    )
    proposal = RuleProposal(definition=rule)
    write_proposal(proposal, proposed_dir / "test.proposed.yaml")

    import mcrataway.constants as constants_module
    monkeypatch.setattr(constants_module, "CONFIG_DIR", tmp_path)

    loader = RulePackLoader()
    loader.load_defaults()
    rule_ids = {r.rule_id for pack in loader.all_rules() for r in pack.rules}
    assert "should_not_load" not in rule_ids
