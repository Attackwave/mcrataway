"""Tests against real javac-compiled class files.

Unlike the synthetic fixtures in tests/fixtures/generator.py (which
only ever emit `ldc_w` + `return` and never a real `invoke*`
instruction — see build_javac_fixtures.py's module docstring), these
JARs contain genuine bytecode produced by a real Java compiler, so
they actually exercise the invoke-resolution path that D01, D02, D03,
D06, D07, D10 depend on via resolve_invokes().

Also covers the evasion techniques identified during the code review
(nested archives, magic-byte class detection bypassing the .class
extension check, reflection-hidden strings) and the false-positive
regression on entirely benign LWJGL-using code, plus a monotonicity
invariant for VerdictAggregator.
"""

import io
import zipfile
from pathlib import Path

import pytest

from mcrataway.constants import Verdict
from mcrataway.core.evidence import Evidence, EvidenceIndex
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.core.verdict import VerdictAggregator
from mcrataway.rules.loader import RulePackLoader

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "javac_fixtures"


def _class_bytes(name: str) -> bytes:
    """Extract the single .class entry from a prebuilt javac fixture JAR."""
    jar_path = FIXTURES_DIR / f"{name}.jar"
    if not jar_path.exists():
        pytest.skip(
            f"{jar_path} missing — run "
            "`python tests/build_javac_fixtures.py` (requires a JDK) "
            "to (re)generate javac fixtures"
        )
    with zipfile.ZipFile(jar_path) as zf:
        names = zf.namelist()
        assert len(names) == 1
        return zf.read(names[0])


@pytest.fixture()
def engine(tmp_path: Path) -> ScanEngine:
    loader = RulePackLoader()
    loader.load_defaults()
    qm = QuarantineManager(quarantine_dir=tmp_path / "q", do_quarantine_malicious=False)
    return ScanEngine(rules=loader.all_rules(), quarantine=qm, max_workers=1)


def _make_jar(tmp_path: Path, jar_name: str, entries: dict[str, bytes]) -> Path:
    path = tmp_path / jar_name
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


class TestRealBytecodeDetection:
    """Detectors must fire on genuine invoke* instructions, not just
    constant-pool string matches."""

    def test_process_exec_hiding_its_destination_is_malicious(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        """DirectExec calls Runtime.exec and ProcessBuilder.start (two D01
        HIGHs, one capability) and hides a URL in a byte array. Fetching
        from a concealed destination and running something in the same
        class is the staged-download behavior, so the chain carries it to
        MALICIOUS: this fixture was written as malware. The counting rule
        alone would rate it SUSPICIOUS, which is what the plaintext-URL
        chain test pins as the model's limit."""
        jar = _make_jar(tmp_path, "direct.jar", {"DirectExec.class": _class_bytes("DirectExec")})
        result = engine._scan_single(jar)
        assert result.verdict == Verdict.MALICIOUS
        detector_ids = {f.detector_id for f in result.findings}
        assert "d01" in detector_ids  # Runtime.exec / ProcessBuilder
        assert "d07" in detector_ids  # System.loadLibrary
        chains = [
            e.context.get("chain")
            for e in result.findings
            if e.detector_id == "behavior_chain"
        ]
        assert "hidden_download_and_exec" in chains

    def test_hidden_download_that_runs_the_payload_is_malicious(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        """Staged-download malware (the Dropper fixture): a hidden URL, the
        payload written to a temp file, then handed to the OS. Each of the
        three is ordinary on its own — a hidden destination plus execution
        is the complete behavior, and it has to stay MALICIOUS. Regression
        for the chain links: requiring the plain file write at MEDIUM by
        severity meant the chain no longer matched staged downloads."""
        jar = _make_jar(tmp_path, "dropper.jar", {"Dropper.class": _class_bytes("Dropper")})
        result = engine._scan_single(jar)
        assert result.verdict == Verdict.MALICIOUS
        chains = [
            e.context.get("chain")
            for e in result.findings
            if e.detector_id == "behavior_chain"
        ]
        assert "hidden_download_and_exec" in chains

    def test_hidden_download_that_loads_the_payload_is_malicious(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        """The fractureiser Stage-1/2 shape (the Reloader fixture): the
        same fetch, but the payload is loaded as code in-process instead
        of executed as a process."""
        jar = _make_jar(tmp_path, "reloader.jar", {"Reloader.class": _class_bytes("Reloader")})
        result = engine._scan_single(jar)
        assert result.verdict == Verdict.MALICIOUS
        chains = [
            e.context.get("chain")
            for e in result.findings
            if e.detector_id == "behavior_chain"
        ]
        assert "reload_and_execute" in chains

    def test_hidden_string_is_reconstructed_and_scored(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        """The byte-array-hidden URL in DirectExec.hiddenUrl() must be
        both reconstructed and reflected in evidence, not silently
        dropped after decoding."""
        jar = _make_jar(tmp_path, "direct.jar", {"DirectExec.class": _class_bytes("DirectExec")})
        result = engine._scan_single(jar)
        reconstructed = [
            f for f in result.findings if f.detector_id == "string_reconstruction"
        ]
        assert any("evil.com" in f.matched_value for f in reconstructed)

    def test_xml_decoder_and_lookup_define_class_are_detected(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        """XMLDecoder.readObject() (arbitrary object graph from XML) and
        Lookup.defineClass() (a class defined straight from a byte array)
        are invoke-only entry points: neither is visible in the constant
        pool alone, and both are absent from the hand-assembled
        fixtures."""
        jar = _make_jar(
            tmp_path, "unsafe.jar", {"UnsafeLookup.class": _class_bytes("UnsafeLookup")}
        )
        result = engine._scan_single(jar)
        found = {(f.detector_id, f.severity.name) for f in result.findings}
        assert ("d06", "HIGH") in found
        # D03 rates the Lookup call MEDIUM; a lone MEDIUM is downgraded
        # to LOW by the behavior-chain pass, so assert the detector
        # fired rather than the post-processing severity.
        assert any(det == "d03" for det, _ in found)
        assert result.verdict != Verdict.CLEAN


class TestEvasionTechniques:
    """Regression tests for the evasion techniques found during review:
    nested archives and non-.class-extension payloads were both
    silently skipped (verdict CLEAN, 0 findings) before the fix."""

    def test_nested_archive_payload_is_detected(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        """A malicious class hidden inside an inner JAR (Forge JarJar /
        Fabric nested-jars style, or fractureiser Stage-0 style payload
        staging) must still be scanned."""
        inner_buf = io.BytesIO()
        with zipfile.ZipFile(inner_buf, "w") as zf:
            zf.writestr("com/evil/DirectExec.class", _class_bytes("DirectExec"))

        outer = tmp_path / "outer.jar"
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("assets/payload.jar", inner_buf.getvalue())
            zf.writestr("fabric.mod.json", b'{"id":"innocent","name":"Innocent Mod"}')

        result = engine._scan_single(outer)
        assert result.verdict != Verdict.CLEAN
        assert any(f.detector_id == "d01" for f in result.findings)
        # The path prefix must trace back into the nested archive so a
        # user can locate the actual malicious file.
        assert any(
            "payload.jar!/com/evil/DirectExec.class" in f.context.get("archive_path", "")
            for f in result.findings
        )

    def test_class_under_wrong_extension_is_detected(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        """A real Java class stored under a non-.class name (e.g. a
        ClassLoader that reads bytes itself via defineClass) must still
        be recognized by its magic bytes, not skipped because of its
        file extension."""
        jar = _make_jar(tmp_path, "disguised.jar", {"assets/model.bin": _class_bytes("DirectExec")})
        result = engine._scan_single(jar)
        assert result.verdict != Verdict.CLEAN
        assert any(f.detector_id == "d01" for f in result.findings)

    def test_reflection_hidden_exec_is_not_clean(
        self, engine: ScanEngine, tmp_path: Path
    ) -> None:
        """Process execution reached only via reflection, with the
        target class name hidden in a byte array, must not come back
        CLEAN — even though no direct Runtime/ProcessBuilder invoke
        exists in the bytecode, the reconstructed strings
        ("java.lang.Runtime", "getRuntime", "exec") combined with
        Class.forName in the same class is exactly the pattern
        VerdictAggregator._static_override now escalates."""
        jar = _make_jar(
            tmp_path, "refl.jar",
            {"ReflectiveExec.class": _class_bytes("ReflectiveExec")},
        )
        result = engine._scan_single(jar)
        assert result.verdict != Verdict.CLEAN


class TestFalsePositiveRegression:
    """A mod that only uses LWJGL and has a startup-screen label must
    not be flagged as malicious — regression test for the D05/D07
    over-broad substring matching bug (bare "startup"/"so"/"dll"
    matches trip on virtually every graphical mod)."""

    def test_benign_lwjgl_mod_is_clean(self, engine: ScanEngine, tmp_path: Path) -> None:
        jar = _make_jar(
            tmp_path, "benign.jar", {"BenignLwjglMod.class": _class_bytes("BenignLwjglMod")}
        )
        result = engine._scan_single(jar)
        assert result.verdict == Verdict.CLEAN


class TestVerdictMonotonicity:
    """Invariant: adding more corroborating evidence must never lower
    the reported confidence, and a higher-severity finding must never
    soften the verdict. The old ratio-based confidence formula
    violated this (more MEDIUM evidence could reduce confidence)."""

    def test_more_evidence_never_lowers_confidence(self) -> None:
        from mcrataway.constants import Severity

        agg = VerdictAggregator()

        def make_index(medium_count: int) -> EvidenceIndex:
            idx = EvidenceIndex()
            for i in range(medium_count):
                idx.add(Evidence("d09", Severity.MEDIUM, "A", "", 0, f"x{i}"))
            return idx

        prev_confidence = 0.0
        for count in range(5, 10):
            verdict, confidence = agg.compute(make_index(count))
            if verdict == Verdict.CLEAN:
                continue
            assert confidence >= prev_confidence, (
                f"confidence decreased from {prev_confidence} to {confidence} "
                f"when going from fewer to {count} MEDIUM findings"
            )
            prev_confidence = confidence

    def test_critical_finding_does_not_downgrade_verdict(self) -> None:
        from mcrataway.constants import Severity

        agg = VerdictAggregator()
        idx = EvidenceIndex()
        idx.add(Evidence("d11", Severity.CRITICAL, "A", "", 0, "onchain selector"))
        verdict, confidence = agg.compute(idx)
        assert verdict == Verdict.MALICIOUS
        assert confidence >= 0.5
