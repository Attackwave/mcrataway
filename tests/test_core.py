"""Expanded tests for parsers, detectors, rules, engine, and quarantine."""

import struct
from pathlib import Path

from mcrataway.constants import Severity, Verdict
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.core.verdict import VerdictAggregator
from mcrataway.detectors.d01_process_exec import D01ProcessExec
from mcrataway.detectors.d02_network_io import D02NetworkIO
from mcrataway.detectors.d08_credential_theft import D08CredentialTheft
from mcrataway.detectors.d11_onchain_c2 import D11OnchainC2
from mcrataway.parsers.classfile import parse_class
from mcrataway.parsers.instructions import decode_bytecode
from mcrataway.rules.loader import RulePackLoader

# --- Helpers to build synthetic .class bytecode ---

def _build_constant_pool(strings: list[str]) -> tuple[bytes, int]:
    """Build a minimal constant pool with given UTF8 strings.
    Returns (pool_bytes, count)."""
    pool = struct.pack(">H", 1 + len(strings))  # count (1-indexed, slot 0 unused)
    idx = 1
    for s in strings:
        encoded = s.encode("utf-8")
        pool += struct.pack(">BH", 1, len(encoded))  # tag=Utf8, length
        pool += encoded
        idx += 1
    return pool, idx


def _build_class(
    class_name: str,
    method_name: str,
    bytecode: bytes,
    extra_strings: list[str] | None = None,
) -> bytes:
    """Build a minimal valid .class file with given bytecode.

    Constant pool layout (1-indexed):
        1 -> class_name (Utf8)
        2 -> "java/lang/Object" (Utf8)
        3 -> method_name (Utf8)
        4 -> "()V" (Utf8)
        5 -> "Code" (Utf8)   <-- used as the Code attribute name
        6+ -> extra_strings

    Structure:
    - magic (4)
    - minor/major (4)
    - constant pool count (2) + entries
    - access flags (2)
    - this_class index (2)
    - super_class index (2)
    - interfaces count (2) = 0
    - fields count (2) = 0
    - methods count (2) + 1 method
    - attributes count (2) = 0
    """
    all_strings = [class_name, "java/lang/Object", method_name, "()V", "Code"]
    if extra_strings:
        all_strings.extend(extra_strings)

    pool_data, cp_count = _build_constant_pool(all_strings)

    # Method bytecode attribute
    code_attr = struct.pack(">HHI", 0, 1, len(bytecode))  # max_stack=0, max_locals=1
    code_attr += bytecode
    code_attr += struct.pack(">HH", 0, 0)  # exception table count=0, attrs count=0

    # Code attribute wrapper — name index 5 points at the "Code" Utf8 entry
    code_attr_name_idx = 5
    code_attr_full = struct.pack(">HI", code_attr_name_idx, len(code_attr))
    code_attr_full += code_attr

    # Method
    method = struct.pack(">HHH", 0x0001, 3, 4)  # access=public, name_idx=3, desc_idx=4
    method += struct.pack(">H", 1)  # attributes_count=1 (no extra length —
    # each attribute already carries its own name_idx + length header inside
    # code_attr_full, per the JVM class file format)
    method += code_attr_full

    # Class body
    body = struct.pack(">H", 0x0001)  # access=public
    body += struct.pack(">H", 1)  # this_class=1
    body += struct.pack(">H", 2)  # super_class=2
    body += struct.pack(">H", 0)  # interfaces=0
    body += struct.pack(">H", 0)  # fields=0
    body += struct.pack(">H", 1)  # methods=1
    body += method
    body += struct.pack(">H", 0)  # class attrs=0

    return b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 52) + pool_data + body


class TestSyntheticClassParser:
    def test_parse_synthetic_class(self):
        """Test parsing a synthetically built .class file."""
        bc = struct.pack(">B", 177)  # return opcode
        data = _build_class("com/test/Synth", "test", bc)
        parsed = parse_class(data)
        # The synthetic builder may not perfectly resolve class names
        # but it should parse without crashing
        assert parsed is not None
        assert len(parsed.methods) == 1


class TestBytecodeInstructions:
    def test_decode_return(self):
        bc = struct.pack(">B", 177)  # return
        instrs = decode_bytecode(bc)
        assert len(instrs) == 1
        assert instrs[0].opcode == 177
        assert instrs[0].opcode_name == "return"

    def test_decode_bipush(self):
        bc = struct.pack(">BB", 16, 42)  # bipush 42
        instrs = decode_bytecode(bc)
        assert len(instrs) == 1
        assert instrs[0].opcode == 16
        assert instrs[0].operand_value == 42


class TestDetectors:
    def test_d01_no_false_positive(self):
        bc = struct.pack(">B", 177)  # return
        parsed = parse_class(_build_class("com/test/Safe", "safe", bc))
        assert parsed is not None
        det = D01ProcessExec()
        evs = det.analyze_class(parsed)
        assert len(evs) == 0

    def test_d02_no_false_positive(self):
        bc = struct.pack(">B", 177)
        parsed = parse_class(_build_class("com/test/Safe", "safe", bc))
        assert parsed is not None
        det = D02NetworkIO()
        evs = det.analyze_class(parsed)
        assert len(evs) == 0

    def test_d08_no_false_positive(self):
        bc = struct.pack(">B", 177)
        parsed = parse_class(_build_class("com/test/Safe", "safe", bc))
        assert parsed is not None
        det = D08CredentialTheft()
        evs = det.analyze_class(parsed)
        assert len(evs) == 0

    def test_d11_no_false_positive(self):
        bc = struct.pack(">B", 177)
        parsed = parse_class(_build_class("com/test/Safe", "safe", bc))
        assert parsed is not None
        det = D11OnchainC2()
        evs = det.analyze_class(parsed)
        assert len(evs) == 0


class TestRuleLoader:
    def test_load_defaults(self):
        loader = RulePackLoader()
        loader.load_defaults()
        assert len(loader.packs) >= 2
        for pack in loader.packs:
            assert len(pack.rules) > 0

    def test_rule_has_required_fields(self):
        loader = RulePackLoader()
        loader.load_defaults()
        for pack in loader.packs:
            for rule in pack.rules:
                assert rule.rule_id, "Rule must have an id"
                assert rule.severity, "Rule must have a severity"
                assert rule.description, "Rule must have a description"


class TestScanEngine:
    def test_scan_empty_list(self):
        engine = ScanEngine()
        results = engine.scan_files([])
        assert results == []

    def test_scan_nonexistent_file(self):
        engine = ScanEngine()
        results = engine.scan_files([Path("/nonexistent/file.jar")])
        # Nonexistent files return a SUSPICIOUS verdict with empty hash
        assert len(results) == 1
        assert results[0].file_hash == ""


class TestQuarantine:
    def test_list_empty(self, tmp_path):
        qm = QuarantineManager(quarantine_dir=tmp_path)
        assert qm.list_quarantined() == []

    def test_restore_nonexistent(self, tmp_path):
        qm = QuarantineManager(quarantine_dir=tmp_path)
        assert qm.restore("nonexistent_sha256") is False


class TestVerdict:
    def test_clean(self):
        idx = EvidenceIndex()
        agg = VerdictAggregator()
        v, c = agg.compute(idx)
        assert v == Verdict.CLEAN
        assert c == 1.0

    def test_one_low_is_clean(self):
        idx = EvidenceIndex()
        idx.add(Evidence(
            detector_id="d01",
            severity=Severity.LOW,
            class_name="com/test/A",
            method_name="m",
            offset=0,
            description="x",
        ))
        agg = VerdictAggregator()
        v, c = agg.compute(idx)
        assert v == Verdict.CLEAN
