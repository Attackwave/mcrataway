"""Tests for modloader nested-jar manifest awareness.

A modloader's manifest (Fabric ``fabric.mod.json`` ``jars`` array,
Forge JarJar ``META-INF/jarjar/metadata.json``) declares which nested
JARs the mod legitimately bundles. A nested archive that is NOT in
this list has no benign explanation — legitimate packaging always
declares its inner jars, and an attacker staging a payload as an
unlisted inner JAR is the exact evasion technique fractureiser
Stage-0 used.

These tests verify:
  - Declared nested jars are NOT flagged (no false positive on legit
    Fabric/Forge packaging).
  - Undeclared nested jars ARE flagged as MEDIUM.
  - JarJar metadata.json parsing extracts declared paths correctly.
  - Fabric ``jars`` array parsing extracts declared paths correctly.
"""

import io
import json
import zipfile
from pathlib import Path

from mcrataway.constants import Severity
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.parsers.manifest import (
    parse_fabric_mod_json,
    parse_jarjar_metadata,
)
from mcrataway.rules.loader import RulePackLoader


def _make_engine(tmp_path: Path) -> ScanEngine:
    loader = RulePackLoader()
    loader.load_defaults()
    qm = QuarantineManager(
        quarantine_dir=tmp_path / "q", do_quarantine_malicious=False
    )
    return ScanEngine(rules=loader.all_rules(), quarantine=qm, max_workers=1)


def _make_jar(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def _make_inner_jar() -> bytes:
    """A minimal valid inner JAR (just a manifest)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    return buf.getvalue()


def test_fabric_mod_json_jars_array_extracted():
    """The ``jars`` array in fabric.mod.json must be parsed into
    declared_nested_jars so the scan engine can distinguish declared
    nested deps from undeclared payload archives."""
    data = json.dumps({
        "schemaVersion": 1,
        "id": "testmod",
        "version": "1.0",
        "jars": [
            {"file": "META-INF/jars/dependency.jar"},
            {"file": "META-INF/jars/other.jar"},
        ],
    }).encode()
    meta = parse_fabric_mod_json(data)
    assert meta.declared_nested_jars == [
        "META-INF/jars/dependency.jar",
        "META-INF/jars/other.jar",
    ]


def test_jarjar_metadata_json_parsed():
    """Forge JarJar's metadata.json must be parsed for declared paths."""
    data = json.dumps({
        "jars": [
            {"identifier": {"path": "META-INF/jars/lib1.jar"}},
            {"identifier": {"path": "META-INF/jars/lib2.jar"}},
        ],
    }).encode()
    paths = parse_jarjar_metadata(data)
    assert paths == ["META-INF/jars/lib1.jar", "META-INF/jars/lib2.jar"]


def test_jarjar_metadata_json_plain_path_field():
    """Older JarJar variants use a top-level ``path`` field."""
    data = json.dumps({
        "jars": [
            {"path": "META-INF/jars/legacy.jar"},
        ],
    }).encode()
    paths = parse_jarjar_metadata(data)
    assert paths == ["META-INF/jars/legacy.jar"]


def test_jarjar_metadata_json_invalid_returns_empty():
    """Parse failure must return an empty list, not raise — an
    undeclared nested jar is suspicious, so failing to parse must not
    silently mark everything as 'declared'."""
    assert parse_jarjar_metadata(b"not json") == []
    assert parse_jarjar_metadata(b"") == []


def test_declared_nested_jar_not_flagged(tmp_path: Path) -> None:
    """A nested JAR that IS listed in fabric.mod.json's ``jars`` array
    must NOT produce an 'undeclared nested archive' finding — this is
    legitimate Fabric packaging."""
    engine = _make_engine(tmp_path)
    inner = _make_inner_jar()
    jar = _make_jar(tmp_path / "mod.jar", {
        "fabric.mod.json": json.dumps({
            "schemaVersion": 1,
            "id": "testmod",
            "version": "1.0",
            "jars": [{"file": "META-INF/jars/dep.jar"}],
        }).encode(),
        "META-INF/jars/dep.jar": inner,
    })
    result = engine._scan_single(jar)
    undeclared = [
        f for f in result.findings
        if f.context.get("undeclared_nested") == "1"
    ]
    assert not undeclared, (
        f"Declared nested jar was flagged as undeclared: "
        f"{[(f.matched_value, f.description) for f in undeclared]}"
    )


def test_undeclared_nested_jar_flagged(tmp_path: Path) -> None:
    """A nested JAR that is NOT listed in any modloader manifest must
    produce an 'undeclared nested archive' MEDIUM finding — this is
    the exact evasion technique fractureiser Stage-0 used."""
    engine = _make_engine(tmp_path)
    inner = _make_inner_jar()
    jar = _make_jar(tmp_path / "mod.jar", {
        "fabric.mod.json": json.dumps({
            "schemaVersion": 1,
            "id": "testmod",
            "version": "1.0",
            # No jars array — no declared nested jars
        }).encode(),
        "META-INF/jars/payload.jar": inner,
    })
    result = engine._scan_single(jar)
    undeclared = [
        f for f in result.findings
        if f.context.get("undeclared_nested") == "1"
    ]
    assert len(undeclared) == 1
    assert undeclared[0].matched_value == "META-INF/jars/payload.jar"
    assert undeclared[0].severity == Severity.MEDIUM


def test_jarjar_declared_nested_jar_not_flagged(tmp_path: Path) -> None:
    """A nested JAR declared in Forge JarJar's metadata.json must not
    be flagged as undeclared."""
    engine = _make_engine(tmp_path)
    inner = _make_inner_jar()
    jar = _make_jar(tmp_path / "mod.jar", {
        "META-INF/jarjar/metadata.json": json.dumps({
            "jars": [
                {"identifier": {"path": "META-INF/jars/forge_dep.jar"}},
            ],
        }).encode(),
        "META-INF/jars/forge_dep.jar": inner,
    })
    result = engine._scan_single(jar)
    undeclared = [
        f for f in result.findings
        if f.context.get("undeclared_nested") == "1"
    ]
    assert not undeclared


def test_no_manifest_all_nested_jars_flagged(tmp_path: Path) -> None:
    """With no modloader manifest at all, every nested archive is
    undeclared and should be flagged."""
    engine = _make_engine(tmp_path)
    inner = _make_inner_jar()
    jar = _make_jar(tmp_path / "mod.jar", {
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
        "assets/payload1.jar": inner,
        "assets/payload2.jar": inner,
    })
    result = engine._scan_single(jar)
    undeclared = [
        f for f in result.findings
        if f.context.get("undeclared_nested") == "1"
    ]
    assert len(undeclared) == 2
    names = {f.matched_value for f in undeclared}
    assert names == {"assets/payload1.jar", "assets/payload2.jar"}
