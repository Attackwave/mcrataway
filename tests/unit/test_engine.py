"""Unit tests for scan engine and verdict aggregation."""

import struct
import zipfile
from pathlib import Path

from mcrataway.constants import Severity, Verdict
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.core.verdict import VerdictAggregator
from mcrataway.parsers.classfile import parse_class
from mcrataway.parsers.string_reconstructor import ReconstructedString


def _build_class_raw(cp_strings: list[str], bytecode: bytes | None = None) -> bytes:
    all_strings = ["com/test/A", "java/lang/Object", "m", "()V", "Code"] + cp_strings
    pool = struct.pack(">H", len(all_strings) + 1)
    for s in all_strings:
        encoded = s.encode("utf-8")
        pool += struct.pack(">BH", 1, len(encoded)) + encoded
    bc = bytecode if bytecode is not None else struct.pack(">B", 177)
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


def test_plain_constant_pool_string_is_not_obfuscation(tmp_path: Path):
    """A plain literal that merely mentions an exec class name — Netty's
    "java.lang.RuntimeException", or any "getRuntimeMXBean" JMX call —
    must not be read as a deliberately hidden API reference. The
    reconstruction pass also hands ordinary ldc constants to the
    detectors, which rate everything they receive as obfuscated; that
    made a bundled library's exception-name constant a CRITICAL finding
    and the mod MALICIOUS."""
    class_data = _build_class_raw(
        ["java.lang.RuntimeException", "getRuntimeMXBean"],
        bytecode=bytes([0x12, 6, 0x57, 0xB1]),  # ldc #6; pop; return
    )
    jar_path = tmp_path / "plain.jar"
    _make_jar(jar_path, {"com/test/Plain.class": class_data})

    results = ScanEngine().scan_files([jar_path])
    assert len(results) == 1
    assert results[0].verdict == Verdict.CLEAN


def test_decoded_strings_still_reach_the_detectors(tmp_path: Path):
    """The pass's positive control: a genuinely decoded string is still
    evaluated, and its evidence is marked as reconstructed — which is
    what forces MALICIOUS for a hidden dangerous-API reference."""
    engine = ScanEngine()
    parsed = parse_class(_build_class_raw(["x"]))
    assert parsed is not None
    hidden = [
        ReconstructedString(
            method_name="m",
            class_name="com/test/A",
            offset=0,
            value="java.lang.Runtime",
            technique="xor_cipher",
        )
    ]

    evidence = engine._evaluate_reconstructed_strings(parsed, hidden)

    assert any(e.severity == Severity.CRITICAL for e in evidence)


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


def test_verdict_aggregator_weak_cooccurrence_is_not_malicious():
    """Regression: credential access + network in the same class only
    forces MALICIOUS when both are real findings. A LOW "mentions a
    cookie file" next to an INFO network observation describes an HTTP
    client, which is what it made MALICIOUS before."""
    idx = EvidenceIndex()
    idx.add(Evidence(
        detector_id="d08",
        severity=Severity.LOW,
        class_name="com/example/HttpClient",
        method_name="get",
        offset=0,
        description="Cookies",
    ))
    idx.add(Evidence(
        detector_id="d02",
        severity=Severity.INFO,
        class_name="com/example/HttpClient",
        method_name="get",
        offset=10,
        description="java/net/URL",
    ))
    agg = VerdictAggregator()
    v, _ = agg.compute(idx)
    assert v != Verdict.MALICIOUS


def test_verdict_aggregator_suspicious_from_medium():
    # 4 MEDIUM findings from 4 *distinct* detectors — the distinct-
    # detector dedup means 3 MEDIUMs from the same detector (e.g. D10
    # firing across 3 classes) counts as 1 capability, not 3. This
    # test uses 4 different detectors to cross the SUSPICIOUS
    # threshold of medium_count=4.
    idx = EvidenceIndex()
    for i, det_id in enumerate(("d01", "d02", "d03", "d04")):
        idx.add(Evidence(
            detector_id=det_id,
            severity=Severity.MEDIUM,
            class_name=f"com/test/C{i}",
            method_name="m",
            offset=i * 10,
            description=f"evidence {i}",
        ))
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.SUSPICIOUS


def test_verdict_aggregator_one_detector_repeating_high_is_not_malicious():
    # D01 reporting Runtime.exec five times across a bundle of
    # command-line tools is ONE capability. MALICIOUS's high_count=2
    # means two *different* detectors each rated something HIGH.
    idx = EvidenceIndex()
    for i in range(5):
        idx.add(Evidence(
            detector_id="d01",
            severity=Severity.HIGH,
            class_name=f"com/test/C{i}",
            method_name="exec",
            offset=i * 10,
            description="Runtime.exec() call detected",
        ))
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.SUSPICIOUS
    assert c <= 0.9


def test_verdict_aggregator_two_distinct_high_detectors_is_malicious():
    idx = EvidenceIndex()
    for i, det_id in enumerate(("d01", "d07")):
        idx.add(Evidence(
            detector_id=det_id,
            severity=Severity.HIGH,
            class_name=f"com/test/C{i}",
            method_name="m",
            offset=i * 10,
            description=f"evidence {i}",
        ))
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.MALICIOUS


def test_verdict_aggregator_target_based_repeats_count_separately():
    # D08 is the exception: each HIGH names a different victim (a wallet
    # file, a cookie database), so reading two of them is the attack
    # getting worse, not the same finding counted twice.
    idx = EvidenceIndex()
    for i in range(2):
        idx.add(Evidence(
            detector_id="d08",
            severity=Severity.HIGH,
            class_name=f"com/test/C{i}",
            method_name="steal",
            offset=i * 10,
            description=f"credential path {i}",
        ))
    agg = VerdictAggregator()
    v, c = agg.compute(idx)
    assert v == Verdict.MALICIOUS


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
