"""Scan worker — runs scan jobs off the event loop with real-time progress."""

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcrataway.config import UserConfig
from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.discovery.os_paths import discover_roots
from mcrataway.discovery.walker import FileWalker
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
        do_quarantine_malicious=config.quarantine_malicious,
        do_quarantine_suspicious=config.quarantine_suspicious,
    )

    engine = ScanEngine(
        rules=rule_loader.all_rules(),
        quarantine=quarantine_mgr,
        max_workers=config.max_workers,
        whitelisted_hashes=config.whitelisted_hashes,
        excluded_paths=config.excluded_paths,
    )

    walker = FileWalker(
        scan_archives=config.scan_archives,
        scan_scripts=config.scan_scripts,
        scan_configs=config.scan_configs,
        max_depth=config.max_recursion_depth,
        # User-supplied roots (no auto-discovery) should be walked in
        # full; auto-discovered roots keep the scan-subdir restriction
        # so we do not traverse the user's entire home directory.
        restrict_to_scan_subdirs=auto_discover,
    )

    all_files: list[Path] = []
    for root in root_paths:
        all_files.extend(walker.walk(root))

    results: list[dict[str, Any]] = []
    total = len(all_files)
    # Send an initial 0% progress event so the UI does not appear
    # frozen for the first 10 files (the modulo gate below would
    # otherwise suppress output until i == 9).
    if on_event:
        on_event({
            "type": "progress",
            "scanned": 0,
            "total": total,
            "percent": 100.0 if total == 0 else 0.0,
        })

    for i, file_path in enumerate(all_files):
        entry: dict[str, Any]
        try:
            result = engine._scan_single(file_path, "")
            engine.maybe_quarantine(file_path, result)
            entry = {
                "file_path": result.file_path,
                "sha256": result.file_hash,
                "verdict": result.verdict.value,
                "confidence": result.confidence,
                "findings": [f.to_dict() for f in result.findings],
                "metadata": result.metadata,
            }
            results.append(entry)

            # Real-time progress on every single file for smooth progress bar updates
            if on_event:
                progress = (i + 1) / total if total else 1.0
                on_event({
                    "type": "progress",
                    "scanned": i + 1,
                    "total": total,
                    "percent": round(progress * 100, 1),
                })

            if on_event and entry["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
                on_event({"type": "verdict", "verdict": entry})

        except Exception as exc:
            # Surface the failure instead of swallowing it silently so
            # the job report is not falsely "all clean".
            entry = {
                "file_path": str(file_path),
                "sha256": "",
                "verdict": "SUSPICIOUS",
                "confidence": 0.3,
                "findings": [
                    {
                        "detector_id": "scan_engine",
                        "severity": "MEDIUM",
                        "description": f"Scan failed: {type(exc).__name__}: {exc}",
                        "file_path": str(file_path),
                        "class_name": "",
                        "method_name": "",
                        "matched_value": "",
                    }
                ],
                "metadata": {},
            }
            results.append(entry)
            if on_event:
                on_event({"type": "verdict", "verdict": entry})
            continue

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
