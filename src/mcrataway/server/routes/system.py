"""System routes — health, roots discovery, directory browser, config management, and rule updates."""

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

from mcrataway.config import UserConfig
from mcrataway.constants import SCANNER_VERSION
from mcrataway.discovery.os_paths import discover_roots
from mcrataway.rules.updater import RuleUpdater

router = APIRouter(prefix="/system", tags=["system"])


class ConfigUpdateModel(BaseModel):
    max_workers: int | None = None
    quarantine_suspicious: bool | None = None
    quarantine_malicious: bool | None = None
    scan_archives: bool | None = None
    scan_scripts: bool | None = None
    scan_configs: bool | None = None
    max_recursion_depth: int | None = None
    whitelisted_hashes: list[str] | None = None
    excluded_paths: list[str] | None = None
    disabled_rules: list[str] | None = None


@router.get("/health")
async def health() -> dict[str, str]:
    """Health check."""
    return {"status": "ok", "version": SCANNER_VERSION}


@router.get("/roots")
async def get_roots() -> list[str]:
    """Get discovered Minecraft installation roots."""
    return [str(r) for r in discover_roots()]


@router.get("/browse")
async def browse_directory(path: str = Query(default="")) -> dict[str, Any]:
    """Browse directories and scannable items for the UI folder picker."""
    if not path:
        target = Path.home()
    else:
        target = Path(path)

    if not target.exists() or not target.is_dir():
        target = Path.home()

    items: list[dict[str, Any]] = []
    parent = str(target.parent) if target.parent != target else ""

    try:
        entries = sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        for entry in entries:
            if entry.name.startswith(".") and entry.name not in (".minecraft",):
                continue
            is_dir = entry.is_dir()
            is_jar = entry.suffix.lower() in (".jar", ".zip")
            if is_dir or is_jar:
                items.append({
                    "name": entry.name,
                    "path": str(entry),
                    "is_dir": is_dir,
                    "is_archive": is_jar,
                })
    except (PermissionError, OSError):
        pass

    return {
        "current_path": str(target),
        "parent_path": parent,
        "items": items,
    }


@router.get("/config")
async def get_config(request: Request) -> dict[str, Any]:
    """Get current user configuration."""
    config: UserConfig = request.app.state.config
    return config.__dict__


@router.post("/config")
async def update_config(model: ConfigUpdateModel, request: Request) -> dict[str, Any]:
    """Update user configuration."""
    config: UserConfig = request.app.state.config
    for key, val in model.model_dump(exclude_unset=True).items():
        if hasattr(config, key) and val is not None:
            setattr(config, key, val)

    config.save()
    request.app.state.config = config
    return {"success": True, "config": config.__dict__}


@router.post("/update-rules")
async def update_rules() -> dict[str, Any]:
    """Fetch latest remote signature rules."""
    updater = RuleUpdater()
    downloaded = updater.fetch_remote_rules()
    return {
        "success": True,
        "downloaded_count": len(downloaded),
        "files": [str(p) for p in downloaded],
    }
