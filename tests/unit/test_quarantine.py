"""QuarantineManager: restore/delete safety and round-trip invariants."""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from mcrataway.core.quarantine import QuarantineManager, QuarantineOutcome


@dataclass
class _Result:
    file_hash: str
    verdict: str = "malicious"
    confidence: float = 0.9
    findings: list[object] = field(default_factory=list)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _quarantine(qm: QuarantineManager, path: Path) -> str:
    sha = _sha(path.read_bytes())
    assert qm.quarantine(path, _Result(sha)).outcome is QuarantineOutcome.SUCCESS
    return sha


@pytest.fixture
def qm(tmp_path: Path) -> QuarantineManager:
    return QuarantineManager(quarantine_dir=tmp_path / "quarantine")


# Explicit ids: pytest derives ids from bytes values and exports them via
# PYTEST_CURRENT_TEST, which overflows Windows' 32767-char env var limit.
@pytest.mark.parametrize(
    "payload",
    [b"x", b"\x00\xff" * 4096, bytes(range(256)) * 17],
    ids=["1-byte", "8k-binary", "4k-all-byte-values"],
)
def test_quarantine_then_restore_is_byte_identical(
    tmp_path: Path, qm: QuarantineManager, payload: bytes
) -> None:
    mod = tmp_path / "mods" / "evil.jar"
    mod.parent.mkdir()
    mod.write_bytes(payload)

    sha = _quarantine(qm, mod)
    assert not mod.exists()
    assert mod.with_suffix(".jar.quarantined").exists()
    assert [m.sha256 for m in qm.list_quarantined()] == [sha]

    assert qm.restore(sha) is True
    assert mod.read_bytes() == payload
    assert not mod.with_suffix(".jar.quarantined").exists()
    assert qm.list_quarantined() == []


def test_restore_recreates_missing_parent_directory(tmp_path: Path, qm: QuarantineManager) -> None:
    mod = tmp_path / "mods" / "evil.jar"
    mod.parent.mkdir()
    mod.write_bytes(b"payload")
    sha = _quarantine(qm, mod)
    mod.with_suffix(".jar.quarantined").unlink()
    mod.parent.rmdir()

    assert qm.restore(sha) is True
    assert mod.read_bytes() == b"payload"


def test_restore_never_clobbers_a_recreated_file(tmp_path: Path, qm: QuarantineManager) -> None:
    mod = tmp_path / "evil.jar"
    mod.write_bytes(b"malware")
    sha = _quarantine(qm, mod)
    mod.write_bytes(b"fresh reinstall")

    assert qm.restore(sha) is False
    assert mod.read_bytes() == b"fresh reinstall"
    assert [m.sha256 for m in qm.list_quarantined()] == [sha]


@pytest.mark.parametrize(
    "bad_id", ["../../etc", "..", "", "a" * 63, "A" * 64, "g" * 64, ("a" * 64) + "/../x"]
)
def test_restore_rejects_ids_that_are_not_lowercase_sha256(
    tmp_path: Path, qm: QuarantineManager, bad_id: str
) -> None:
    assert qm.restore(bad_id) is False


@pytest.mark.parametrize("bad_id", ["../outside", "..", "", "a" * 63, "../" + "a" * 64])
def test_delete_permanently_cannot_escape_quarantine_dir(
    tmp_path: Path, qm: QuarantineManager, bad_id: str
) -> None:
    qm.quarantine_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")

    assert qm.delete_permanently(bad_id) is False
    assert (outside / "keep.txt").read_text() == "keep"


def test_delete_permanently_accepts_uppercase_hash_and_removes_placeholder(
    tmp_path: Path, qm: QuarantineManager
) -> None:
    mod = tmp_path / "evil.jar"
    mod.write_bytes(b"malware")
    sha = _quarantine(qm, mod)

    assert qm.delete_permanently(sha.upper()) is True
    assert qm.list_quarantined() == []
    assert not mod.with_suffix(".jar.quarantined").exists()
    assert not (qm.quarantine_dir / sha).exists()


def test_delete_permanently_unknown_hash_returns_false(qm: QuarantineManager) -> None:
    qm.quarantine_dir.mkdir()
    assert qm.delete_permanently("a" * 64) is False


def test_purge_all_counts_entries_and_removes_placeholders(
    tmp_path: Path, qm: QuarantineManager
) -> None:
    mods = []
    for i in range(3):
        mod = tmp_path / f"m{i}.jar"
        mod.write_bytes(f"malware-{i}".encode())
        _quarantine(qm, mod)
        mods.append(mod)
    (qm.quarantine_dir / "stray.txt").write_text("stray")

    assert qm.purge_all() == 4
    assert list(qm.quarantine_dir.iterdir()) == []
    assert not any(m.with_suffix(".jar.quarantined").exists() for m in mods)


def test_purge_all_on_missing_dir_is_a_noop(qm: QuarantineManager) -> None:
    assert qm.purge_all() == 0


def test_list_skips_corrupt_manifests_and_entries_without_payload(
    tmp_path: Path, qm: QuarantineManager
) -> None:
    good = tmp_path / "good.jar"
    good.write_bytes(b"good")
    good_sha = _quarantine(qm, good)

    corrupt = qm.quarantine_dir / ("b" * 64)
    corrupt.mkdir()
    (corrupt / "manifest.json").write_text("{not json")

    orphan = tmp_path / "orphan.jar"
    orphan.write_bytes(b"orphan")
    orphan_sha = _quarantine(qm, orphan)
    (qm.quarantine_dir / orphan_sha / "orphan.jar").unlink()

    assert [m.sha256 for m in qm.list_quarantined()] == [good_sha]


def test_restore_with_corrupt_manifest_keeps_payload(tmp_path: Path, qm: QuarantineManager) -> None:
    mod = tmp_path / "evil.jar"
    mod.write_bytes(b"malware")
    sha = _quarantine(qm, mod)
    (qm.quarantine_dir / sha / "manifest.json").write_text("{not json")

    assert qm.restore(sha) is False
    assert (qm.quarantine_dir / sha / "evil.jar").read_bytes() == b"malware"


def test_restore_with_missing_payload_returns_false(tmp_path: Path, qm: QuarantineManager) -> None:
    mod = tmp_path / "evil.jar"
    mod.write_bytes(b"malware")
    sha = _quarantine(qm, mod)
    (qm.quarantine_dir / sha / "evil.jar").unlink()

    assert qm.restore(sha) is False
    assert not mod.exists()


def test_manifest_records_original_path_and_hash(tmp_path: Path, qm: QuarantineManager) -> None:
    mod = tmp_path / "evil.jar"
    mod.write_bytes(b"malware")
    sha = _quarantine(qm, mod)

    data = json.loads((qm.quarantine_dir / sha / "manifest.json").read_text())
    assert data["original_path"] == str(mod)
    assert data["sha256"] == sha
    assert data["restored"] is False


def test_restore_does_not_follow_traversal_to_a_forged_manifest(
    tmp_path: Path, qm: QuarantineManager
) -> None:
    qm.quarantine_dir.mkdir()
    forged = tmp_path / "forged"
    forged.mkdir()
    (forged / "payload.bin").write_bytes(b"payload")
    target = tmp_path / "planted.bin"
    (forged / "manifest.json").write_text(
        json.dumps({"original_path": str(target), "quarantined_path": "payload.bin"})
    )

    assert qm.restore("../forged") is False
    assert not target.exists()
    assert (forged / "payload.bin").exists()
