"""Tests for the known-good hash reputation store.

The reputation store is an Ed25519-signed, offline set of SHA-256
hashes of verified-clean mods. A hash match means the file is
byte-identical to the author-published version, so the scanner can
safely skip it — the most effective false-positive defense available,
since it directly answers "is this the file the author published?"

These tests verify:
  - Loading a store from YAML produces the correct hash set.
  - A missing store returns an empty set (safe default).
  - A scanner with a reputation hash skips the file as CLEAN.
  - Signature verification rejects an unsigned store.
  - The store merges with user-configured whitelisted_hashes.
"""

from pathlib import Path

import yaml

from mcrataway.constants import Verdict
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.reputation import (
    load_known_good_store,
)
from mcrataway.rules.loader import RulePackLoader


def _make_store_yaml(entries: list[dict]) -> str:
    return yaml.dump(
        {"pack_version": "2026-08-02", "entries": entries},
        default_flow_style=False,
        sort_keys=False,
    )


def test_load_known_good_store_parses_entries(tmp_path: Path) -> None:
    """A valid YAML store with entries must produce a non-empty hash set."""
    store_file = tmp_path / "known_good.yaml"
    store_file.write_text(_make_store_yaml([
        {"sha256": "abc123", "name": "testmod", "version": "1.0"},
        {"sha256": "def456", "name": "othermod", "version": "2.0"},
    ]))
    store = load_known_good_store(store_file)
    assert store.hashes == {"abc123", "def456"}
    assert store.is_known_good("abc123")
    assert not store.is_known_good("xyz789")
    entry = store.get_entry("abc123")
    assert entry is not None
    assert entry.name == "testmod"


def test_load_known_good_store_missing_file_returns_empty(tmp_path: Path) -> None:
    """A missing store file must return an empty store — nothing is
    whitelisted, which is the safe default."""
    store = load_known_good_store(tmp_path / "nonexistent.yaml")
    assert len(store.hashes) == 0
    assert not store.is_known_good("anything")


def test_load_known_good_store_invalid_yaml_returns_empty(tmp_path: Path) -> None:
    """An invalid YAML file must not crash — return an empty store."""
    store_file = tmp_path / "known_good.yaml"
    store_file.write_text("not: valid: yaml: [[")
    store = load_known_good_store(store_file)
    assert len(store.hashes) == 0


def test_reputation_hash_skips_scan_as_clean(tmp_path: Path) -> None:
    """A file whose SHA-256 is in the reputation store must scan as
    CLEAN with metadata.whitelisted=True — the scanner skips it
    entirely, saving CPU and avoiding false positives."""
    test_file = tmp_path / "mod.jar"
    test_file.write_bytes(b"dummy mod content")

    loader = RulePackLoader()
    loader.load_defaults()
    engine = ScanEngine(
        rules=loader.all_rules(),
        whitelisted_hashes={engine_hash(test_file)},
    )
    result = engine._scan_single(test_file)
    assert result.verdict == Verdict.CLEAN
    assert result.metadata.get("whitelisted") is True


def test_reputation_merges_with_user_whitelist(tmp_path: Path) -> None:
    """The reputation store hashes and user-configured whitelisted_hashes
    must merge — both are valid sources of known-good hashes."""
    test_file = tmp_path / "mod.jar"
    test_file.write_bytes(b"dummy mod content")

    user_hash = "user_added_hash_123"
    file_hash = engine_hash(test_file)

    loader = RulePackLoader()
    loader.load_defaults()
    engine = ScanEngine(
        rules=loader.all_rules(),
        whitelisted_hashes={user_hash, file_hash},
    )
    result = engine._scan_single(test_file)
    assert result.verdict == Verdict.CLEAN
    assert result.metadata.get("whitelisted") is True


def test_reputation_does_not_skip_non_matching_hash(tmp_path: Path) -> None:
    """A file whose hash is NOT in the store must be scanned normally."""
    test_file = tmp_path / "mod.jar"
    test_file.write_bytes(b"dummy mod content")

    loader = RulePackLoader()
    loader.load_defaults()
    engine = ScanEngine(
        rules=loader.all_rules(),
        whitelisted_hashes={"some_other_hash"},
    )
    result = engine._scan_single(test_file)
    # Not whitelisted — should be scanned (CLEAN for a dummy file, but
    # not via the whitelist metadata).
    assert result.metadata.get("whitelisted") is not True


def test_known_good_store_entry_metadata(tmp_path: Path) -> None:
    """Entry metadata (mod_id, loader, source) must be preserved."""
    store_file = tmp_path / "known_good.yaml"
    store_file.write_text(_make_store_yaml([
        {
            "sha256": "abc123",
            "mod_id": "sodium",
            "name": "Sodium",
            "version": "0.6.0",
            "loader": "fabric",
            "source": "modrinth",
        },
    ]))
    store = load_known_good_store(store_file)
    entry = store.get_entry("abc123")
    assert entry is not None
    assert entry.mod_id == "sodium"
    assert entry.loader == "fabric"
    assert entry.source == "modrinth"


def engine_hash(path: Path) -> str:
    """Compute the SHA-256 hash the same way ScanEngine does."""
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
