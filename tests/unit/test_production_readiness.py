"""Tests for production readiness features: concurrency, whitelisting, rule updates, limits."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mcrataway.config import UserConfig
from mcrataway.constants import Verdict
from mcrataway.core.quarantine import QuarantineManager, QuarantineOutcome
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


def test_quarantine_distinguishes_failure_from_harmless_outcomes(tmp_path: Path) -> None:
    """QuarantineManager.quarantine() must not collapse a real failure
    (copy error) and a harmless outcome (already quarantined, source
    missing) into the same indistinguishable None — see
    core/quarantine.py's QuarantineOutcome. A caller (e.g.
    ScanEngine.maybe_quarantine) that only checks "is there a
    manifest" cannot tell a genuinely failed isolation from a
    no-op, which previously meant a MALICIOUS verdict with a failed
    quarantine attempt produced no visible warning at all.
    """
    qm = QuarantineManager(quarantine_dir=tmp_path / "quarantine")

    class FakeResult:
        file_hash = "b" * 64
        verdict = "MALICIOUS"
        confidence = 1.0
        findings: list = []

    # Source missing.
    missing = tmp_path / "does_not_exist.jar"
    result = qm.quarantine(missing, FakeResult())
    assert result.outcome is QuarantineOutcome.SOURCE_MISSING
    assert not result

    # Successful quarantine.
    sample = tmp_path / "sample.jar"
    sample.write_bytes(b"dummy")
    result = qm.quarantine(sample, FakeResult())
    assert result.outcome is QuarantineOutcome.SUCCESS
    assert result
    assert result.manifest is not None

    # Re-quarantining the same hash is a no-op, not a failure.
    sample2 = tmp_path / "sample2.jar"
    sample2.write_bytes(b"dummy")
    result = qm.quarantine(sample2, FakeResult())
    assert result.outcome is QuarantineOutcome.ALREADY_QUARANTINED
    assert not result

    # A genuine failure (copy raises) must be reported as FAILED, not
    # silently swallowed as if nothing happened.
    sample3 = tmp_path / "sample3.jar"
    sample3.write_bytes(b"dummy")

    class OtherResult:
        file_hash = "c" * 64
        verdict = "MALICIOUS"
        confidence = 1.0
        findings: list = []

    with patch("shutil.copy2", side_effect=OSError("disk full")):
        result = qm.quarantine(sample3, OtherResult())
    assert result.outcome is QuarantineOutcome.FAILED
    assert not result
    assert sample3.exists(), "original file must survive a failed quarantine attempt"


def test_scan_engine_surfaces_failed_quarantine_in_metadata(tmp_path: Path) -> None:
    """A quarantine failure during a scan must be visible on the
    ArtifactResult, not silently dropped — this is what CLI/server
    reporting reads to warn the user that a MALICIOUS file is still on
    disk despite the verdict."""
    test_file = tmp_path / "malicious.jar"
    test_file.write_bytes(b"dummy data")

    quarantine = QuarantineManager(quarantine_dir=tmp_path / "quarantine")
    engine = ScanEngine(quarantine=quarantine)

    class FakeResult:
        verdict = Verdict.MALICIOUS
        file_hash = "d" * 64
        confidence = 1.0
        findings: list = []
        metadata: dict = {}

    fake_result = FakeResult()
    with patch("shutil.copy2", side_effect=OSError("disk full")):
        engine.maybe_quarantine(test_file, fake_result)  # type: ignore[arg-type]

    assert fake_result.metadata.get("quarantine_failed") is True
    assert test_file.exists()


def test_user_config_whitelisting() -> None:
    cfg = UserConfig(whitelisted_hashes=["abc123hash"], excluded_paths=["/tmp/*"])
    assert "abc123hash" in cfg.whitelisted_hashes
    assert "/tmp/*" in cfg.excluded_paths


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX file permission bits are not meaningful on Windows",
)
def test_user_config_save_sets_restrictive_permissions(tmp_path: Path) -> None:
    """config.yaml can contain scanned paths and quarantine locations
    — on a multi-user system these should not be world/group readable,
    matching the treatment TOKEN_FILE already gets in server/auth.py.
    """
    cfg = UserConfig(custom_roots=["/home/someuser/mods"])
    config_path = tmp_path / "config.yaml"
    cfg.save(config_path)

    mode = config_path.stat().st_mode & 0o777
    assert mode == 0o600


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


def test_rule_updater_rejects_downgrade_of_versioned_pack(tmp_path: Path) -> None:
    """A validly-signed pack must still be rejected if its pack_version
    is not newer than the last accepted version for that URL — a
    signature only proves who published a file, not that it's the
    most recent one. Without this, an attacker in control of the
    download channel (compromised mirror, repo takeover) could replay
    an old, validly-signed pack that lacks detection for a
    since-added malware family.
    """
    from mcrataway.rules import signing

    priv_b64, pub_b64 = signing.generate_keypair()
    old_content = b"pack_id: test_pack\npack_version: '2026-01-01'\nrules: []"
    new_content = b"pack_id: test_pack\npack_version: '2026-06-01'\nrules: []"
    old_sig = signing.sign_data(old_content, priv_b64)
    new_sig = signing.sign_data(new_content, priv_b64)

    updater = RuleUpdater(target_dir=tmp_path)

    def make_response(data: bytes) -> MagicMock:
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = data
        return resp

    with patch.object(signing, "TRUSTED_PUBLIC_KEYS_B64", (pub_b64,)), patch(
        "urllib.request.urlopen"
    ) as mock_urlopen:
        # First fetch: accept the newer pack.
        mock_urlopen.return_value.__enter__.side_effect = [
            make_response(new_content),
            make_response(new_sig.encode("ascii")),
        ]
        files = updater.fetch_remote_rules(urls=["http://example.com/rules.yaml"])
        assert len(files) == 1
        assert files[0].read_bytes() == new_content

        # Second fetch: an older, but still validly-signed pack is
        # served on the same URL (rollback attack) — must be rejected,
        # and the previously-installed newer content must survive.
        mock_urlopen.return_value.__enter__.side_effect = [
            make_response(old_content),
            make_response(old_sig.encode("ascii")),
        ]
        files = updater.fetch_remote_rules(urls=["http://example.com/rules.yaml"])
        assert len(files) == 0
        assert (tmp_path / "remote_pack_1.yaml").read_bytes() == new_content


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="resource module (ru_maxrss) is Unix-only; no stdlib equivalent on Windows",
)
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

    ru_maxrss's unit is platform-dependent: kilobytes on Linux, bytes
    on macOS (both documented in `man getrusage` / Darwin's manpage;
    there is no portable way to query the unit itself), so it is
    normalized to KB per-platform before comparing.
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

    rss_unit_divisor = 1024 if sys.platform == "darwin" else 1  # bytes -> KB on macOS

    before_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / rss_unit_divisor
    engine._scan_single(archive)
    after_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / rss_unit_divisor

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
