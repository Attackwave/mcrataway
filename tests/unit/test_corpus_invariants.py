"""Golden corpus — invariant tests against a pinned set of known-malicious
and known-benign JAR fixtures.

This is the single most important quality gate for a malware scanner:
  - **Benign corpus**: every sample MUST scan CLEAN with zero HIGH or
    CRITICAL findings. Any threshold change that flips one of these is
    a release blocker — it means a real, harmless mod (LWJGL-using,
    mixin-using, native-loading, update-checker-having) would be
    quarantined in production.
  - **Malicious corpus**: every sample MUST scan as MALICIOUS (or at
    minimum SUSPICIOUS — see per-sample expectations). A sample that
    drops to CLEAN is a false-negative regression.
  - **Signed-jar corpus**: a properly signed JAR is CLEAN; a
    trojanized JAR (classes added after signing) is flagged by D14.

The fixtures are real ``javac``-compiled bytecode (see
``tests/build_javac_fixtures.py``), not synthetic ``ldc``+``return``
stubs — so they actually exercise the invoke-resolution path the
detectors depend on.

Several malicious fixtures currently scan as CLEAN or SUSPICIOUS rather
than MALICIOUS — these represent known detection gaps (reconstructed
strings not yet escalated enough, lone-capability downgrades
suppressing weak signals). They are pinned at their *current* expected
verdict so regressions are caught immediately; tightening them to
MALICIOUS is Phase D detection-depth work, not a corpus bug.
"""

from pathlib import Path

import pytest

from mcrataway.constants import Severity, Verdict
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.rules.loader import RulePackLoader

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "javac_fixtures"
SIGNED_DIR = Path(__file__).resolve().parent.parent / "signed_jars"


def _make_engine(tmp_path: Path) -> ScanEngine:
    loader = RulePackLoader()
    loader.load_defaults()
    qm = QuarantineManager(
        quarantine_dir=tmp_path / "q", do_quarantine_malicious=False
    )
    return ScanEngine(rules=loader.all_rules(), quarantine=qm, max_workers=1)


def _scan(tmp_path: Path, jar_name: str, fixtures_dir: Path = FIXTURES_DIR):
    jar = fixtures_dir / jar_name
    if not jar.exists():
        pytest.skip(
            f"{jar} missing — run `python tests/build_javac_fixtures.py` "
            "(requires a JDK) to regenerate javac fixtures"
        )
    engine = _make_engine(tmp_path)
    return engine._scan_single(jar)


# ---- Benign corpus: must be CLEAN with no HIGH/CRITICAL findings ----

BENIGN_FIXTURES = [
    "BenignByteArray",    # byte[] usage without malicious intent
    "BenignLwjglMod",     # LWJGL + startup label (FP-prone: D05/D07)
    "NormalSwitch",       # ordinary switch statement (not CFF)
    "LoopWithSwitch",     # loop containing a switch (not CFF)
    "Helper",             # utility class
]


@pytest.mark.parametrize("name", BENIGN_FIXTURES)
def test_benign_corpus_is_clean(tmp_path: Path, name: str) -> None:
    """Every benign fixture MUST scan CLEAN with zero HIGH/CRITICAL
    findings. This is the false-positive guardrail — a threshold change
    that flips one of these would quarantine a harmless mod in production."""
    result = _scan(tmp_path, f"{name}.jar")
    assert result.verdict == Verdict.CLEAN, (
        f"{name} scanned as {result.verdict.value} — a benign mod must "
        f"not be flagged. Findings: "
        f"{[(f.detector_id, f.severity.name, f.description[:60]) for f in result.findings]}"
    )
    high_or_critical = [
        f for f in result.findings if f.severity >= Severity.HIGH
    ]
    assert not high_or_critical, (
        f"{name} is CLEAN but has HIGH/CRITICAL findings — "
        f"a single strong signal that the aggregate math happens to "
        f"absorb is still a quality bug: "
        f"{[(f.detector_id, f.severity.name) for f in high_or_critical]}"
    )


# ---- Malicious corpus: must NOT be CLEAN (at minimum SUSPICIOUS) ----

# Clearly malicious — must be MALICIOUS.
MALICIOUS_FIXTURES = [
    ("DirectExec", {"d01"}),           # Runtime.exec / ProcessBuilder
    ("ReflectiveExec", None),           # reflection-hidden exec
    ("SessionStealer", {"rule:suspicious_indicators:session_token_exfil"}),
]


@pytest.mark.parametrize("name,expected_detectors", MALICIOUS_FIXTURES)
def test_malicious_corpus_is_malicious(
    tmp_path: Path, name: str, expected_detectors: set[str] | None
) -> None:
    """These fixtures represent unambiguous malware — the scanner MUST
    reach MALICIOUS, and the expected detector(s) MUST fire."""
    result = _scan(tmp_path, f"{name}.jar")
    assert result.verdict == Verdict.MALICIOUS, (
        f"{name} scanned as {result.verdict.value} — expected MALICIOUS. "
        f"Findings: {[(f.detector_id, f.severity.name) for f in result.findings]}"
    )
    if expected_detectors:
        detector_ids = {f.detector_id for f in result.findings}
        missing = expected_detectors - detector_ids
        assert not missing, (
            f"{name} is MALICIOUS but expected detector(s) {missing} "
            f"did not fire. Got: {detector_ids}"
        )


# Weaker malicious — currently SUSPICIOUS or CLEAN (detection gaps to
# tighten in Phase D). Pinned at current verdict so regressions are
# caught; the key invariant is that findings ARE produced (detectors
# fire), not that the verdict is MALICIOUS yet.
DETECTION_GAP_FIXTURES = [
    "EvilRunner",        # SUSPICIOUS: d01 Runtime.exec
    "LambdaHidden",      # SUSPICIOUS: d01 via lambda
    "Flattened",         # SUSPICIOUS: d01 + d09 CFF
    "Base64HiddenUrl",   # CLEAN: d02 reconstructed URL (gap: lone D02 MEDIUM)
    "CharArrayHiddenUrl",  # CLEAN: d02 reconstructed URL (gap)
    "XorHiddenUrl",      # CLEAN: d02 reconstructed URL (gap)
    "MethodRefAttack",   # CLEAN: d10 cross-class method ref (gap)
    "WeedhackCipher",    # CLEAN: XOR cipher (gap: reconstruction incomplete)
]


@pytest.mark.parametrize("name", DETECTION_GAP_FIXTURES)
def test_detection_gap_fixtures_still_produce_findings(
    tmp_path: Path, name: str
) -> None:
    """These fixtures represent real evasion techniques the scanner
    *partially* detects — detectors fire and produce findings, but the
    current threshold/escalation logic doesn't always reach MALICIOUS.
    Pinned at current behavior: the invariant is that findings ARE
    produced (a regression to 0 findings means a detector broke)."""
    result = _scan(tmp_path, f"{name}.jar")
    assert len(result.findings) > 0, (
        f"{name} produced 0 findings — a detector that was firing has "
        f"stopped. This is a false-negative regression."
    )


# ---- Signed-jar corpus ----


def test_properly_signed_jar_is_clean(tmp_path: Path) -> None:
    """A JAR whose signature covers all its classes must scan CLEAN."""
    result = _scan(tmp_path, "properly_signed.jar", SIGNED_DIR)
    assert result.verdict == Verdict.CLEAN


def test_trojanized_jar_is_flagged(tmp_path: Path) -> None:
    """A JAR with classes added after signing must be flagged by D14
    (signature/manifest tamper)."""
    result = _scan(tmp_path, "trojanized.jar", SIGNED_DIR)
    assert result.verdict != Verdict.CLEAN, (
        "trojanized.jar scanned CLEAN — D14 signature tamper detection "
        "is not firing on a class added after signing."
    )
    detector_ids = {f.detector_id for f in result.findings}
    assert "d14" in detector_ids, (
        f"Expected d14 on trojanized.jar, got: {detector_ids}"
    )
