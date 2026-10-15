"""Scan worker — runs scan jobs off the event loop with real-time progress."""

import asyncio
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcrataway.config import UserConfig
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ArtifactResult, ScanEngine
from mcrataway.discovery.os_paths import discover_roots
from mcrataway.discovery.walker import FileWalker, is_game_layout_root
from mcrataway.rules.loader import RulePackLoader


def _run_scan(
    job_id: str,
    roots: list[str],
    auto_discover: bool,
    config_dict: dict[str, Any],
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run a scan job synchronously. Called via asyncio.to_thread.

    If *on_event* is provided, it is called for each progress and finding
    event so the caller can forward them to subscribers in real time.
    """
    config = UserConfig(**config_dict)

    if auto_discover:
        discovered = discover_roots(config.custom_roots)
        root_paths = [Path(r) for r in roots] if roots else discovered
    else:
        root_paths = [Path(r) for r in roots]

    rule_loader = RulePackLoader()
    rule_loader.load_defaults()

    quarantine_mgr = QuarantineManager(
        quarantine_dir=config.quarantine_dir,
        do_quarantine_malicious=config.quarantine_malicious,
        do_quarantine_suspicious=config.quarantine_suspicious,
    )

    from mcrataway.reputation import load_known_good_store

    reputation_store = load_known_good_store()
    all_whitelisted = set(config.whitelisted_hashes) | reputation_store.hashes

    engine = ScanEngine(
        rules=rule_loader.all_rules(),
        quarantine=quarantine_mgr,
        max_workers=config.max_workers,
        whitelisted_hashes=all_whitelisted,
        excluded_paths=config.excluded_paths,
        max_nesting_depth=config.max_recursion_depth,
        scan_scripts=config.scan_scripts,
    )

    # restrict_to_scan_subdirs is decided per root, not once for the
    # whole scan: the GUI always sends auto_discover=false (it passes an
    # explicit `roots` list either way — see routes/scan.py), so keying
    # this off that flag meant every GUI scan walked every selected root
    # in full, including auto-discovered .minecraft installs. A launcher
    # root scanned in full picks up unrelated launcher-internal folders
    # (e.g. an embedded browser's extension cache) that "check scripts
    # inside mods" was never meant to reach — restrict those, but keep
    # walking arbitrary user-supplied paths (e.g. a mod backup folder)
    # in full since they aren't a known launcher layout.
    all_files: list[Path] = []
    for root in root_paths:
        walker = FileWalker(
            scan_archives=config.scan_archives,
            scan_scripts=config.scan_scripts,
            scan_configs=config.scan_configs,
            max_depth=config.max_recursion_depth,
            restrict_to_scan_subdirs=auto_discover or is_game_layout_root(root),
        )
        all_files.extend(walker.walk(root))

    results: list[dict[str, Any]] = []
    total = len(all_files)
    # Send an initial 0% progress event so the UI does not appear
    # frozen before the first file has been scanned.
    if on_event:
        on_event({
            "type": "progress",
            "scanned": 0,
            "total": total,
            "percent": 100.0 if total == 0 else 0.0,
        })

    # on_result runs on the engine's worker threads — the counter it
    # shares is serialized here, for the same reason the CLI wraps its
    # rich.progress callback in a lock (see cli.py).
    progress_lock = threading.Lock()
    scanned = 0

    def on_result(result: ArtifactResult) -> None:
        """Turn one finished artifact into a report entry and a live event."""
        nonlocal scanned
        entry: dict[str, Any] = {
            "file_path": result.file_path,
            "sha256": result.file_hash,
            "verdict": result.verdict.value,
            "confidence": result.confidence,
            "findings": [f.to_dict() for f in result.findings],
            "metadata": result.metadata,
        }
        results.append(entry)
        with progress_lock:
            scanned += 1
            done = scanned
        if on_event:
            progress = done / total if total else 1.0
            on_event({
                "type": "progress",
                "scanned": done,
                "total": total,
                "percent": round(progress * 100, 1),
            })
            if entry["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
                on_event({"type": "verdict", "verdict": entry})

    # Delegating to the engine rather than looping over _scan_single()
    # keeps quarantine/audit logging, the bytecode-cache cleanup, and
    # max_workers parallelism in one place — the manual loop dropped all
    # three.
    engine.scan_files(all_files, on_result=on_result)

    return {
        "job_id": job_id,
        "total_files": len(all_files),
        "results": results,
    }


async def run_scan_async(
    job_id: str,
    roots: list[str],
    auto_discover: bool,
    config_dict: dict[str, Any],
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run a scan job off the event loop via asyncio.to_thread."""
    return await asyncio.to_thread(
        _run_scan,
        job_id,
        roots,
        auto_discover,
        config_dict,
        on_event,
    )
