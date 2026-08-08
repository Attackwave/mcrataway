"""Script files (.js/.ts/.lua/.mcfunction) bundled inside a JAR must get
the same script analysis as an identical file sitting loose on disk.

Regression test: ScanEngine._analyze_archive_entries used to only run
class-file analysis, nested-archive recursion, and generic per-detector
archive_entry hooks on non-class entries — a script file packed inside
a mod JAR (e.g. a KubeJS script bundled as a resource) skipped the
dedicated analyze_script() checks entirely (Java.type("java.lang.Runtime"),
eval(), fetch(), etc.), even though the identical file loose in kubejs/
or scripts/ was fully analyzed via FileWalker + ScanEngine._scan_script().
"""

import hashlib
import zipfile
from pathlib import Path

from mcrataway.core.scan_engine import ScanEngine

_SUSPICIOUS_JS = b'Java.type("java.lang.Runtime").getRuntime().exec("calc.exe");'


def _make_jar(tmp_path: Path, entry_name: str, entry_data: bytes) -> Path:
    jar_path = tmp_path / "test_mod.jar"
    with zipfile.ZipFile(jar_path, "w") as zf:
        zf.writestr("fabric.mod.json", '{"id": "test_mod", "version": "1.0"}')
        zf.writestr(entry_name, entry_data)
    return jar_path


def test_suspicious_script_inside_jar_is_flagged(tmp_path: Path) -> None:
    jar_path = _make_jar(tmp_path, "assets/test_mod/kubejs/startup.js", _SUSPICIOUS_JS)
    file_hash = hashlib.sha256(jar_path.read_bytes()).hexdigest()

    engine = ScanEngine(scan_scripts=True)
    result = engine._scan_archive(jar_path, file_hash)

    script_findings = [f for f in result.findings if f.detector_id.startswith("script:")]
    assert script_findings, "expected a script: finding for the embedded suspicious .js entry"
    assert any(f.detector_id == "script:runtime_exec" for f in script_findings)


def test_scan_scripts_false_skips_embedded_script_analysis(tmp_path: Path) -> None:
    jar_path = _make_jar(tmp_path, "assets/test_mod/kubejs/startup.js", _SUSPICIOUS_JS)
    file_hash = hashlib.sha256(jar_path.read_bytes()).hexdigest()

    engine = ScanEngine(scan_scripts=False)
    result = engine._scan_archive(jar_path, file_hash)

    script_findings = [f for f in result.findings if f.detector_id.startswith("script:")]
    assert not script_findings, "scan_scripts=False must skip embedded script analysis"


def test_benign_script_inside_jar_has_no_script_findings(tmp_path: Path) -> None:
    jar_path = _make_jar(
        tmp_path, "assets/test_mod/kubejs/startup.js", b"console.log('hello world');"
    )
    file_hash = hashlib.sha256(jar_path.read_bytes()).hexdigest()

    engine = ScanEngine(scan_scripts=True)
    result = engine._scan_archive(jar_path, file_hash)

    script_findings = [f for f in result.findings if f.detector_id.startswith("script:")]
    assert not script_findings
