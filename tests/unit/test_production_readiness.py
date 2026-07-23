"""Tests for production readiness features: concurrency, whitelisting, rule updates, limits."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from mcrataway.config import UserConfig
from mcrataway.constants import Verdict
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.rules.updater import RuleUpdater


def test_whitelisted_hash_scan_skips(tmp_path: Path) -> None:
    test_file = tmp_path / "clean_mod.jar"
    test_file.write_bytes(b"dummy data")

    engine = ScanEngine()
    hash_val = engine._hash_file(test_file)

    engine_whitelisted = ScanEngine(whitelisted_hashes={hash_val})
    results = engine_whitelisted.scan_files([test_file])

    assert len(results) == 1
    assert results[0].verdict == Verdict.CLEAN
    assert results[0].metadata.get("whitelisted") is True


def test_excluded_path_scan_skips(tmp_path: Path) -> None:
    test_file = tmp_path / "ignored.jar"
    test_file.write_bytes(b"dummy data")

    engine = ScanEngine(excluded_paths=["*ignored.jar"])
    results = engine.scan_files([test_file])

    assert len(results) == 1
    assert results[0].verdict == Verdict.CLEAN
    assert results[0].metadata.get("excluded") is True


def test_concurrent_scan_files(tmp_path: Path) -> None:
    f1 = tmp_path / "file1.txt"
    f2 = tmp_path / "file2.txt"
    f1.write_text("config key=val")
    f2.write_text("config key=val2")

    engine = ScanEngine(max_workers=2)
    results = engine.scan_files([f1, f2])

    assert len(results) == 2
    paths = {r.file_path for r in results}
    assert str(f1) in paths
    assert str(f2) in paths


def test_user_config_whitelisting() -> None:
    cfg = UserConfig(whitelisted_hashes=["abc123hash"], excluded_paths=["/tmp/*"])
    assert "abc123hash" in cfg.whitelisted_hashes
    assert "/tmp/*" in cfg.excluded_paths


def test_rule_updater(tmp_path: Path) -> None:
    updater = RuleUpdater(target_dir=tmp_path)
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"pack_id: test_pack\nrules: []"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        files = updater.fetch_remote_rules(urls=["http://example.com/rules.yaml"])
        assert len(files) == 1
        assert files[0].exists()


def test_single_file_walker(tmp_path: Path) -> None:
    from mcrataway.discovery.walker import FileWalker

    jar_file = tmp_path / "test.jar"
    jar_file.write_bytes(b"dummy")

    walker = FileWalker()
    discovered = walker.walk(jar_file)
    assert len(discovered) == 1
    assert discovered[0] == jar_file
