"""Tests for CLI exit-code behavior (--fail-on).

A scanner used in CI/CD must signal findings via its exit code, not
just console output — otherwise `mcrataway scan --auto` in a pipeline
returns success even when every mod is MALICIOUS, defeating the
purpose of automated verification.

Exit code contract:
  0 = scan completed, no findings at/above the --fail-on threshold
  1 = operational error (no paths, bad config, etc.)
  2 = scan completed, but findings at/above the threshold were present
"""

from pathlib import Path

from click.testing import CliRunner

from mcrataway.cli import main
from tests.fixtures.generator import generate_benign_mod, generate_session_stealer


def test_scan_clean_dir_exits_zero(tmp_path: Path) -> None:
    clean = generate_benign_mod(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(clean), "--fail-on", "malicious"])
    assert result.exit_code == 0, result.output


def test_scan_malicious_exits_two_with_default_fail_on(tmp_path: Path) -> None:
    bad = generate_session_stealer(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(bad)])
    assert result.exit_code == 2, result.output


def test_scan_malicious_exits_zero_with_fail_on_none(tmp_path: Path) -> None:
    bad = generate_session_stealer(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(bad), "--fail-on", "none"])
    assert result.exit_code == 0, result.output


def test_scan_no_paths_exits_one() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan"])
    assert result.exit_code == 1
