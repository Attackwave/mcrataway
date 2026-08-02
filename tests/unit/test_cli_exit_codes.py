"""Tests for CLI exit-code behavior (--fail-on).

A scanner used in CI/CD must signal findings via its exit code, not
just console output — otherwise `mcrataway scan --auto` in a pipeline
returns success even when every mod is MALICIOUS, defeating the
purpose of automated verification.

Exit code contract:
  0 = scan completed, no findings at/above the --fail-on threshold
  1 = operational error (no paths, bad config, etc.)
  2 = scan completed, but findings at/above the threshold were present

Uses the prebuilt javac fixtures (tests/javac_fixtures/) — copies each
into a per-test temp dir before scanning, because a MALICIOUS verdict
with default quarantine enabled would *move* the fixture out of the
shared fixtures dir and break subsequent tests.
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from mcrataway.cli import main
from mcrataway.constants import Verdict

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "javac_fixtures"


def _copy_fixture(name: str, tmp_path: Path) -> Path:
    """Copy a javac fixture into tmp_path so quarantine can't move the
    shared original."""
    src = FIXTURES_DIR / f"{name}.jar"
    if not src.exists():
        pytest.skip(
            f"{src} missing — run `python tests/build_javac_fixtures.py` "
            "(requires a JDK) to regenerate javac fixtures"
        )
    dst = tmp_path / f"{name}.jar"
    dst.write_bytes(src.read_bytes())
    return dst


def test_scan_clean_dir_exits_zero(tmp_path: Path) -> None:
    clean = _copy_fixture("BenignLwjglMod", tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(clean), "--fail-on", "malicious"])
    assert result.exit_code == 0, result.output


def test_scan_malicious_exits_two_with_default_fail_on(tmp_path: Path) -> None:
    bad = _copy_fixture("SessionStealer", tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(bad)])
    assert result.exit_code == 2, result.output


def test_scan_malicious_exits_zero_with_fail_on_none(tmp_path: Path) -> None:
    bad = _copy_fixture("SessionStealer", tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(bad), "--fail-on", "none"])
    assert result.exit_code == 0, result.output


def test_scan_no_paths_exits_one() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan"])
    assert result.exit_code == 1


def test_verdict_values_are_strings() -> None:
    assert Verdict.MALICIOUS.value == "MALICIOUS"
    assert Verdict.CLEAN.value == "CLEAN"
