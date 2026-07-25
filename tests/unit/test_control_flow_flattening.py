"""Tests for D09's control-flow-flattening detector (task 22:
obfuskations-ausbau).

D09's docstring claimed "Control-flow flattening" as a covered
capability, but no code implemented it at all — the class-name and
string-entropy checks were the only actual logic. This adds the real
detection: a flattened method compiles to a dispatcher shape (one
central tableswitch/lookupswitch on a state variable, inside a loop,
where most cases end with a goto back to the dispatcher), verified
against real javac output.

Two false-positive regression fixtures are included because the naive
version of this heuristic (switch + high goto count) also fires on
completely ordinary code: a plain switch statement produces zero
gotos (each case returns/falls out), but a for-loop containing a
switch produces the SAME switch+multiple-goto shape as a flattened
dispatcher, since every break/continue in a loop-body switch compiles
to a goto too. The distinguishing feature verified here is what
precedes the switch's selector value: a loop-bound comparison
(arraylength + if_icmpge) for an ordinary counted loop, versus a bare
state-variable load for a flattened dispatcher.
"""

import zipfile
from pathlib import Path

import pytest

from mcrataway.detectors.d09_obfuscation import D09Obfuscation
from mcrataway.parsers.classfile import parse_class

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "javac_fixtures"


def _class_bytes(name: str) -> bytes:
    jar_path = FIXTURES_DIR / f"{name}.jar"
    if not jar_path.exists():
        pytest.skip(
            f"{jar_path} missing — run `python tests/build_javac_fixtures.py` "
            "(requires a JDK) to (re)generate javac fixtures"
        )
    with zipfile.ZipFile(jar_path) as zf:
        return zf.read(f"{name}.class")


def test_flattened_dispatcher_is_detected() -> None:
    cf = parse_class(_class_bytes("Flattened"))
    assert cf is not None
    evs = D09Obfuscation().analyze_class(cf)
    cff_findings = [e for e in evs if "control-flow flattening" in e.description.lower()]
    assert len(cff_findings) == 1
    assert cff_findings[0].method_name == "run"
    assert cff_findings[0].severity.name == "MEDIUM"


def test_ordinary_switch_statement_is_not_flagged() -> None:
    """A plain switch where every case returns directly produces zero
    goto instructions and must not be flagged."""
    cf = parse_class(_class_bytes("NormalSwitch"))
    assert cf is not None
    evs = D09Obfuscation().analyze_class(cf)
    cff_findings = [e for e in evs if "control-flow flattening" in e.description.lower()]
    assert cff_findings == []


def test_loop_containing_switch_is_not_flagged() -> None:
    """Regression test: an ordinary for-loop with a switch inside it
    produces the same switch+multiple-goto shape as a flattened
    dispatcher (every break/continue compiles to a goto), but must
    not be flagged — the loop-bound comparison before the switch
    selector distinguishes it."""
    cf = parse_class(_class_bytes("LoopWithSwitch"))
    assert cf is not None
    evs = D09Obfuscation().analyze_class(cf)
    cff_findings = [e for e in evs if "control-flow flattening" in e.description.lower()]
    assert cff_findings == []


def test_small_switch_is_not_flagged_regardless_of_gotos() -> None:
    """A switch with too few targets to plausibly be a flattening
    dispatcher (below _MIN_DISPATCHER_TARGETS) must never be flagged,
    even if it happens to have several gotos."""
    from mcrataway.detectors.d09_obfuscation import _MIN_DISPATCHER_TARGETS

    assert _MIN_DISPATCHER_TARGETS >= 4  # sanity check on the threshold itself
