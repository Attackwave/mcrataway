"""Tests for the server scan path (server/worker.py ``_run_scan``).

A scan started from the web UI must behave like the same scan run from
the CLI: quarantine into the configured directory, write verdicts to the
audit log, and honor the user's whitelist. The worker used to reimplement
the per-file loop over ``ScanEngine._scan_single``, which lost all three
(plus ``max_workers`` parallelism and the bytecode-cache cleanup).
"""

import shutil
from pathlib import Path

from mcrataway.config import UserConfig
from mcrataway.constants import QUARANTINE_DIR
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.reporting.audit_log import read_audit_log
from mcrataway.server.worker import _run_scan

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _scratch(tmp_path: Path, name: str = "session_stealer.jar") -> tuple[Path, Path]:
    """Copy a fixture jar into a scratch dir — a live scan quarantines
    matched jars in place, which would delete the checked-in fixture."""
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    target = scratch / name
    shutil.copy2(_FIXTURES / name, target)
    return scratch, target


def test_worker_scan_quarantines_into_configured_dir(tmp_path: Path) -> None:
    """A GUI scan must quarantine into the user's configured folder, not
    the default one the UI does not list."""
    configured = tmp_path / "custom_quarantine"
    scratch, jar = _scratch(tmp_path)
    config = UserConfig(quarantine_dir=str(configured), quarantine_malicious=True)

    result = _run_scan("job-quarantine", [str(scratch)], False, dict(config.__dict__))

    entry = result["results"][0]
    assert entry["verdict"] == "MALICIOUS"
    assert not jar.exists()
    assert (configured / entry["sha256"] / "manifest.json").exists()
    assert not (QUARANTINE_DIR / entry["sha256"]).exists()


def test_worker_scan_writes_audit_verdicts(tmp_path: Path) -> None:
    """Every file a GUI scan touches must appear in the audit log, not
    just quarantine actions — the audit trail has to answer "what did the
    scanner conclude about this file?" for UI scans too."""
    scratch, jar = _scratch(tmp_path, "benign_mod.jar")
    config = UserConfig(quarantine_malicious=False)

    _run_scan("job-audit", [str(scratch)], False, dict(config.__dict__))

    verdicts = [e for e in read_audit_log() if e["event_type"] == "scan_verdict"]
    assert any(e["file_path"] == str(jar) for e in verdicts), verdicts


def test_scan_files_calls_on_result_for_every_artifact(tmp_path: Path) -> None:
    """``on_result`` is what the server's live progress and threat feed
    are built on — it must fire once per scanned file."""
    _, jar = _scratch(tmp_path)
    engine = ScanEngine(
        quarantine=QuarantineManager(do_quarantine_malicious=False),
        max_workers=1,
    )
    seen = []

    results = engine.scan_files([jar], on_result=seen.append)

    assert [r.file_path for r in seen] == [r.file_path for r in results]
    assert len(seen) == 1
