"""Tests for AES-with-embedded-key string reconstruction.

A class of malware hides C2 URLs and other strings in AES-encrypted
byte arrays, with the decryption key embedded as a byte-array literal
in the same method. A benign mod has no reason to AES-encrypt a string
with a hardcoded key in its own bytecode — legitimate crypto uses keys
derived from passwords or external sources, not embedded byte arrays.

These tests verify:
  - The AES fixture (AesHiddenUrl.jar) is scanned as SUSPICIOUS, not
    CLEAN — the reconstructed URL is detected and escalated.
  - The `aes_embedded_key` technique is recorded in the evidence.
  - The reconstruction actually decrypts the correct URL.
  - No false positives on benign mods that use javax.crypto legitimately
    (e.g. for config encryption with external keys).
"""

from pathlib import Path

import pytest

from mcrataway.constants import Severity, Verdict
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.rules.loader import RulePackLoader

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "javac_fixtures"


def _make_engine(tmp_path: Path) -> ScanEngine:
    loader = RulePackLoader()
    loader.load_defaults()
    qm = QuarantineManager(
        quarantine_dir=tmp_path / "q", do_quarantine_malicious=False
    )
    return ScanEngine(rules=loader.all_rules(), quarantine=qm, max_workers=1)


def _scan_fixture(tmp_path: Path, name: str):
    jar = FIXTURES_DIR / f"{name}.jar"
    if not jar.exists():
        pytest.skip(
            f"{jar} missing — run `python tests/build_javac_fixtures.py` "
            "(requires a JDK) to regenerate javac fixtures"
        )
    engine = _make_engine(tmp_path)
    return engine._scan_single(jar)


def test_aes_hidden_url_is_suspicious(tmp_path: Path) -> None:
    """An AES-encrypted URL with an embedded key must not scan CLEAN —
    a benign mod has no reason to hide a URL behind AES with a
    hardcoded key."""
    result = _scan_fixture(tmp_path, "AesHiddenUrl")
    assert result.verdict != Verdict.CLEAN, (
        f"AesHiddenUrl scanned CLEAN — AES-encrypted URL with embedded "
        f"key was not detected. Findings: "
        f"{[(f.detector_id, f.severity.name) for f in result.findings]}"
    )


def test_aes_reconstruction_decrypts_correct_url(tmp_path: Path) -> None:
    """The AES reconstruction must actually decrypt the URL — not just
    detect that AES is used, but recover the plaintext."""
    result = _scan_fixture(tmp_path, "AesHiddenUrl")
    aes_findings = [
        f for f in result.findings
        if f.context.get("technique") == "aes_embedded_key"
    ]
    assert len(aes_findings) >= 1, "No aes_embedded_key finding produced"
    assert any("evil.example.com" in f.matched_value for f in aes_findings), (
        f"AES reconstruction didn't recover the URL. Got: "
        f"{[f.matched_value for f in aes_findings]}"
    )


def test_aes_reconstruction_is_high_severity(tmp_path: Path) -> None:
    """The string_reconstruction evidence for an AES-embedded-key
    technique must be HIGH — INFO would let it be silently ignored by
    the verdict aggregator."""
    result = _scan_fixture(tmp_path, "AesHiddenUrl")
    aes_high = [
        f for f in result.findings
        if f.context.get("technique") == "aes_embedded_key"
        and f.severity == Severity.HIGH
    ]
    assert len(aes_high) >= 1, (
        "aes_embedded_key reconstruction should be HIGH severity, got: "
        f"{[(f.severity.name, f.context.get('technique')) for f in result.findings]}"
    )


def test_benign_mod_with_crypto_not_aes_escalated(tmp_path: Path) -> None:
    """A mod that uses javax.crypto.Cipher for legitimate purposes
    (e.g. signature verification) without AES-encrypted string arrays
    should not produce aes_embedded_key findings.

    Uses the BenignLwjglMod fixture (which has no AES-encrypted arrays)
    as a sanity check that the detector doesn't false-positive on
    ordinary crypto usage.
    """
    result = _scan_fixture(tmp_path, "BenignLwjglMod")
    aes_findings = [
        f for f in result.findings
        if f.context.get("technique") == "aes_embedded_key"
    ]
    assert not aes_findings, (
        "BenignLwjglMod produced aes_embedded_key findings — false positive"
    )
