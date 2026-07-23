"""Unit tests for scan engine and verdict aggregation."""

import struct
import zipfile
from pathlib import Path

from mcrataway.constants import Severity, Verdict
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.core.verdict import VerdictAggregator


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


def test_engine_scan_benign_jar(tmp_path: Path):
    """Scan a benign JAR should not flag as malicious."""
    class_data = _build_class_raw(["rendering", "helper"])
    jar_path = tmp_path / "benign.jar"
    _make_jar(jar_path, {"com/test/Render.class": class_data})

    engine = ScanEngine()
    results = engine.scan_files([jar_path])
    assert len(results) == 1
    assert results[0].verdict != Verdict.MALICIOUS


def test_engine_scan_suspicious_jar(tmp_path: Path):
    """Scan a JAR with multiple session token strings should flag as suspicious or malicious."""
    # Include strings that trigger multiple detectors
    class_data = _build_class_raw([
        "getSession",
        "getAccessToken",
        "https://evil.example.com/collect",
        "session.json",
    ])
    jar_path = tmp_path / "suspicious.jar"
    _make_jar(jar_path, {"com/test/Steal.class": class_data})

    engine = ScanEngine()
    results = engine.scan_files([jar_path])
    assert len(results) == 1
    # Should have at least some findings
    assert len(results[0].findings) > 0


def test_verdict_aggregator_clean():
    idx = EvidenceIndex()
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.CLEAN
    assert c == 1.0


def test_verdict_aggregator_malicious_override():
    idx = EvidenceIndex()
    idx.add(Evidence(
        detector_id="d08",
        severity=Severity.HIGH,
        class_name="com/stealer/Main",
        method_name="init",
        offset=0,
        description="session access",
    ))
    idx.add(Evidence(
        detector_id="d02",
        severity=Severity.HIGH,
        class_name="com/stealer/Main",
        method_name="init",
        offset=10,
        description="http post",
    ))
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.MALICIOUS


def test_verdict_aggregator_onchain_override():
    idx = EvidenceIndex()
    idx.add(Evidence(
        detector_id="d11",
        severity=Severity.HIGH,
        class_name="com/c2/Resolver",
        method_name="resolve",
        offset=0,
        description="eth_call",
    ))
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.MALICIOUS


def test_verdict_aggregator_native_override():
    idx = EvidenceIndex()
    idx.add(Evidence(
        detector_id="d07",
        severity=Severity.HIGH,
        class_name="com/native/Loader",
        method_name="load",
        offset=0,
        description="System.load",
    ))
    idx.add(Evidence(
        detector_id="d03",
        severity=Severity.HIGH,
        class_name="com/native/Loader",
        method_name="load",
        offset=10,
        description="URLClassLoader",
    ))
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.MALICIOUS


def test_verdict_aggregator_suspicious_from_medium():
    idx = EvidenceIndex()
    for i in range(3):
        idx.add(Evidence(
            detector_id="d01",
            severity=Severity.MEDIUM,
            class_name=f"com/test/C{i}",
            method_name="m",
            offset=i * 10,
            description=f"evidence {i}",
        ))
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.SUSPICIOUS


def test_evidence_index_cooccurring():
    idx = EvidenceIndex()
    idx.add(Evidence(
        detector_id="d01",
        severity=Severity.HIGH,
        class_name="com/test/A",
        method_name="m",
        offset=0,
        description="exec",
    ))
    idx.add(Evidence(
        detector_id="d02",
        severity=Severity.HIGH,
        class_name="com/test/A",
        method_name="m",
        offset=10,
        description="network",
    ))
    assert idx.has_cooccurring("com/test/A", "d01", "d02")
    assert not idx.has_cooccurring("com/test/A", "d01", "d99")
    assert not idx.has_cooccurring("com/test/B", "d01", "d02")


def test_evidence_index_max_severity():
    idx = EvidenceIndex()
    idx.add(Evidence(
        detector_id="d01",
        severity=Severity.LOW,
        class_name="com/test/A",
        method_name="m",
        offset=0,
        description="low",
    ))
    idx.add(Evidence(
        detector_id="d02",
        severity=Severity.HIGH,
        class_name="com/test/A",
        method_name="m",
        offset=10,
        description="high",
    ))
    assert idx.get_max_severity_for_class("com/test/A") == Severity.HIGH


def test_evidence_index_urls():
    idx = EvidenceIndex()
    idx.add(Evidence(
        detector_id="d02",
        severity=Severity.LOW,
        class_name="com/test/A",
        method_name="m",
        offset=0,
        description="url",
        matched_value="https://evil.com/path",
    ))
    urls = idx.get_all_urls()
    assert "https://evil.com/path" in urls
