"""Dependency injection for the mcrataway FastAPI application."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from fastapi import Request

from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.reporting.console_writer import ConsoleWriter
from mcrataway.reporting.html_writer import HtmlWriter
from mcrataway.reporting.json_writer import JsonWriter
from mcrataway.rules.loader import RulePack, RulePackLoader

if TYPE_CHECKING:
    pass


def get_scan_engine() -> ScanEngine:
    """Get or create the singleton ScanEngine."""
    fn = cast("Any", get_scan_engine)
    if not hasattr(fn, "_instance"):
        fn._instance = ScanEngine()
    return cast(ScanEngine, fn._instance)


def get_quarantine() -> QuarantineManager:
    """Get or create the QuarantineManager.

    Uses the same default as :class:`QuarantineManager` itself (the
    ``QUARANTINE_DIR`` constant, ``~/.mcrataway/quarantine``) unless
    ``MCRATAWAY_QUARANTINE_DIR`` is set — consistent with
    :func:`mcrataway.server.app.create_app`.
    """
    fn = cast("Any", get_quarantine)
    if not hasattr(fn, "_instance"):
        override = os.environ.get("MCRATAWAY_QUARANTINE_DIR")
        fn._instance = (
            QuarantineManager(Path(override)) if override else QuarantineManager()
        )
    return cast(QuarantineManager, fn._instance)


def get_rule_packs() -> list[RulePack]:
    """Get loaded rule packs."""
    fn = cast("Any", get_rule_packs)
    if not hasattr(fn, "_instance"):
        loader = RulePackLoader()
        loader.load_defaults()
        fn._instance = loader.all_rules()
    return cast(list[RulePack], fn._instance)


def get_json_writer() -> JsonWriter:
    """Get the JSON writer."""
    fn = cast("Any", get_json_writer)
    if not hasattr(fn, "_instance"):
        fn._instance = JsonWriter()
    return cast(JsonWriter, fn._instance)


def get_html_writer() -> HtmlWriter:
    """Get the HTML writer."""
    fn = cast("Any", get_html_writer)
    if not hasattr(fn, "_instance"):
        fn._instance = HtmlWriter()
    return cast(HtmlWriter, fn._instance)


def get_console_writer() -> ConsoleWriter:
    """Get the console writer."""
    fn = cast("Any", get_console_writer)
    if not hasattr(fn, "_instance"):
        fn._instance = ConsoleWriter()
    return cast(ConsoleWriter, fn._instance)


async def get_current_user(request: Request) -> str:
    """Extract the current user from the request (placeholder for auth)."""
    return "anonymous"


def reset_dependencies() -> None:
    """Reset all singleton instances. Useful for testing."""
    for dep in (
        get_scan_engine,
        get_quarantine,
        get_rule_packs,
        get_json_writer,
        get_html_writer,
        get_console_writer,
    ):
        fn = cast("Any", dep)
        if hasattr(fn, "_instance"):
            delattr(fn, "_instance")
