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


def test_rule_updater_rejects_unsigned_pack(tmp_path: Path) -> None:
    """An unsigned (or invalid-signature) rule pack must be discarded,
    not written to disk — otherwise a compromised download channel
    could silently ship rules that wave through malware or quarantine
    arbitrary benign mods. See rules/signing.py and rules/updater.py.
    """
    updater = RuleUpdater(target_dir=tmp_path)
    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"pack_id: test_pack\nrules: []"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        files = updater.fetch_remote_rules(urls=["http://example.com/rules.yaml"])
        assert len(files) == 0
        assert not (tmp_path / "remote_pack_1.yaml").exists()


def test_rule_updater_accepts_validly_signed_pack(tmp_path: Path) -> None:
    """A pack signed with a key in the trust root must be accepted and
    written to disk together with its signature."""
    from mcrataway.rules import signing

    priv_b64, pub_b64 = signing.generate_keypair()
    content = b"pack_id: test_pack\nrules: []"
    sig_b64 = signing.sign_data(content, priv_b64)

    updater = RuleUpdater(target_dir=tmp_path)
    with patch.object(signing, "TRUSTED_PUBLIC_KEYS_B64", (pub_b64,)), patch(
        "urllib.request.urlopen"
    ) as mock_urlopen:

        def make_response(data: bytes) -> MagicMock:
            resp = MagicMock()
            resp.status = 200
            resp.read.return_value = data
            return resp

        # First call fetches the pack, second fetches its .sig sibling.
        mock_urlopen.return_value.__enter__.side_effect = [
            make_response(content),
            make_response(sig_b64.encode("ascii")),
        ]

        files = updater.fetch_remote_rules(urls=["http://example.com/rules.yaml"])
        assert len(files) == 1
        assert files[0].exists()
        assert files[0].read_bytes() == content
        assert files[0].with_name(files[0].name + ".sig").exists()


def test_large_archive_does_not_hold_all_entries_in_memory(tmp_path: Path) -> None:
    """Regression test for the ArchiveReader generator conversion:
    scanning a large multi-entry archive must not require every
    entry's decompressed bytes resident in memory simultaneously.

    Before the fix, ArchiveReader.entries() returned a fully
    materialized list, so scanning a 400 MB JAR measurably drove
    process RSS up by ~400 MB. This test uses a smaller archive (to
    keep the test fast) and asserts peak RSS growth stays well below
    the archive's total uncompressed size, which would not hold if
    entries were all resident at once.
    """
    import os
    import resource
    import zipfile

    from mcrataway.core.quarantine import QuarantineManager

    archive = tmp_path / "large.jar"
    chunk = os.urandom(1024 * 1024)  # 1 MB, incompressible
    entry_count = 60  # 60 MB total uncompressed
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as zf:
        for i in range(entry_count):
            zf.writestr(f"data/blob{i}.bin", chunk)

    qm = QuarantineManager(quarantine_dir=tmp_path / "q", do_quarantine_malicious=False)
    engine = ScanEngine(quarantine=qm, max_workers=1)

    before_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    engine._scan_single(archive)
    after_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    growth_mb = (after_kb - before_kb) / 1024
    total_uncompressed_mb = entry_count  # 1 MB per entry
    assert growth_mb < total_uncompressed_mb * 0.5, (
        f"RSS grew {growth_mb:.0f} MB scanning a {total_uncompressed_mb} MB archive — "
        "entries appear to be held in memory simultaneously rather than streamed"
    )


def test_single_file_walker(tmp_path: Path) -> None:
    from mcrataway.discovery.walker import FileWalker

    jar_file = tmp_path / "test.jar"
    jar_file.write_bytes(b"dummy")

    walker = FileWalker()
    discovered = walker.walk(jar_file)
    assert len(discovered) == 1
    assert discovered[0] == jar_file
