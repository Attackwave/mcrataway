"""Unit tests for server/deps.py."""

from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.reporting.console_writer import ConsoleWriter
from mcrataway.reporting.html_writer import HtmlWriter
from mcrataway.reporting.json_writer import JsonWriter
from mcrataway.rules.loader import RulePack
from mcrataway.server.deps import (
    get_console_writer,
    get_html_writer,
    get_json_writer,
    get_quarantine,
    get_rule_packs,
    get_scan_engine,
    reset_dependencies,
)


class TestDependencies:
    def teardown_method(self) -> None:
        reset_dependencies()

    def test_get_scan_engine_singleton(self) -> None:
        engine1 = get_scan_engine()
        engine2 = get_scan_engine()
        assert engine1 is engine2

    def test_get_quarantine_singleton(self) -> None:
        q1 = get_quarantine()
        q2 = get_quarantine()
        assert q1 is q2

    def test_get_rule_packs_singleton(self) -> None:
        packs1 = get_rule_packs()
        packs2 = get_rule_packs()
        assert packs1 is packs2

    def test_get_json_writer_singleton(self) -> None:
        w1 = get_json_writer()
        w2 = get_json_writer()
        assert w1 is w2

    def test_get_html_writer_singleton(self) -> None:
        w1 = get_html_writer()
        w2 = get_html_writer()
        assert w1 is w2

    def test_get_console_writer_singleton(self) -> None:
        w1 = get_console_writer()
        w2 = get_console_writer()
        assert w1 is w2

    def test_reset_dependencies(self) -> None:
        engine = get_scan_engine()
        reset_dependencies()
        new_engine = get_scan_engine()
        assert engine is not new_engine

    def test_scan_engine_returns_correct_type(self) -> None:
        engine = get_scan_engine()
        assert isinstance(engine, ScanEngine)

    def test_quarantine_returns_correct_type(self) -> None:
        q = get_quarantine()
        assert isinstance(q, QuarantineManager)

    def test_json_writer_returns_correct_type(self) -> None:
        w = get_json_writer()
        assert isinstance(w, JsonWriter)

    def test_html_writer_returns_correct_type(self) -> None:
        w = get_html_writer()
        assert isinstance(w, HtmlWriter)

    def test_console_writer_returns_correct_type(self) -> None:
        w = get_console_writer()
        assert isinstance(w, ConsoleWriter)

    def test_rule_packs_returns_correct_type(self) -> None:
        packs = get_rule_packs()
        assert isinstance(packs, list)
        if packs:
            assert isinstance(packs[0], RulePack)
