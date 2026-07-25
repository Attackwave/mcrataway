"""Tests for invokedynamic/BootstrapMethods resolution (task 6:
obfuscation ausbau — invokedynamic/lambda chain resolution).

Before this, ClassFile never parsed the BootstrapMethods attribute at
all (it was silently skipped along with every other class-level
attribute), so an invokedynamic call site's constant-pool operand
could never be traced to the real method a lambda or method reference
ultimately invokes — resolve_invokes() returned an empty owner/name
for it. That meant a capability split into a separate class and
reached only via a method reference (e.g. ``Runnable r =
EvilRunner::detonate``) was invisible to every detector that inspects
resolved invoke targets, even though the lambda-body case (where the
target is a synthetic method in the *same* class) happened to still
work by accident, since detectors iterate every method in a class
regardless of how it's reached.

Uses real javac-compiled fixtures (tests/javac_fixtures/) so the
actual BootstrapMethods/CONSTANT_InvokeDynamic/CONSTANT_MethodHandle
bytecode shapes a real JDK produces are what gets tested.
"""

import zipfile
from pathlib import Path

import pytest

from mcrataway.detectors.d01_process_exec import D01ProcessExec
from mcrataway.detectors.d10_reflection_indirect import D10ReflectionIndirect
from mcrataway.parsers.classfile import parse_class
from mcrataway.parsers.instructions import resolve_invokedynamic_target, resolve_invokes

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


class TestBootstrapMethodsParsing:
    def test_lambda_class_has_bootstrap_methods(self) -> None:
        cf = parse_class(_class_bytes("LambdaHidden"))
        assert cf is not None
        assert len(cf.bootstrap_methods) == 1

    def test_bootstrap_method_ref_resolves_to_lambda_metafactory(self) -> None:
        cf = parse_class(_class_bytes("LambdaHidden"))
        assert cf is not None
        bm = cf.bootstrap_methods[0]
        ref_kind, owner, name, _desc = cf.constant_pool.resolve_method_handle(
            bm.method_ref_index
        )
        assert owner == "java/lang/invoke/LambdaMetafactory"
        assert name == "metafactory"
        assert ref_kind == 6  # REF_invokeStatic

    def test_non_lambda_class_has_no_bootstrap_methods(self) -> None:
        cf = parse_class(_class_bytes("EvilRunner"))
        assert cf is not None
        assert cf.bootstrap_methods == []


class TestInvokedynamicTargetResolution:
    def test_lambda_body_in_same_class_resolves(self) -> None:
        """The invokedynamic call site in run() must resolve to the
        real lambda-body method (a synthetic method in the SAME
        class), not come back empty."""
        cf = parse_class(_class_bytes("LambdaHidden"))
        assert cf is not None
        run_method = next(m for m in cf.methods if m.name == "run")
        invokes = resolve_invokes(run_method.bytecode, cf.constant_pool, cf.bootstrap_methods)

        resolved_targets = {(inv.owner, inv.name) for inv in invokes}
        assert ("LambdaHidden", "lambda$run$0") in resolved_targets

    def test_without_bootstrap_methods_invokedynamic_is_unresolved(self) -> None:
        """Sanity check that the resolution is actually doing work:
        omitting bootstrap_methods must fall back to the old
        behavior (invokedynamic simply not resolved), confirming the
        new argument is what makes the difference."""
        cf = parse_class(_class_bytes("LambdaHidden"))
        assert cf is not None
        run_method = next(m for m in cf.methods if m.name == "run")
        invokes = resolve_invokes(run_method.bytecode, cf.constant_pool, bootstrap_methods=None)

        resolved_targets = {(inv.owner, inv.name) for inv in invokes}
        assert ("LambdaHidden", "lambda$run$0") not in resolved_targets

    def test_cross_class_method_reference_resolves_to_real_class(self) -> None:
        """The key regression case: MethodRefAttack.trigger() never
        mentions EvilRunner/Runtime/exec anywhere in its own directly-
        resolved invokes — the connection only exists through the
        invokedynamic call site's bootstrap method argument."""
        cf = parse_class(_class_bytes("MethodRefAttack"))
        assert cf is not None
        trigger_method = next(m for m in cf.methods if m.name == "trigger")
        invokes = resolve_invokes(
            trigger_method.bytecode, cf.constant_pool, cf.bootstrap_methods
        )

        resolved_targets = {(inv.owner, inv.name) for inv in invokes}
        assert ("EvilRunner", "detonate") in resolved_targets


class TestD01StillCatchesLambdaBody:
    """D01 already worked for the lambda-body case by accident (it
    iterates every method in the class regardless of how it's
    reached), but confirm that still holds now that invokedynamic
    itself is also resolved — the fix must not have broken this."""

    def test_direct_exec_inside_lambda_body_is_still_detected(self) -> None:
        cf = parse_class(_class_bytes("LambdaHidden"))
        assert cf is not None
        evs = D01ProcessExec().analyze_class(cf)
        assert any(e.method_name == "lambda$run$0" for e in evs)


class TestD10CrossClassMethodReference:
    def test_cross_class_reference_is_flagged(self) -> None:
        cf = parse_class(_class_bytes("MethodRefAttack"))
        assert cf is not None
        evs = D10ReflectionIndirect().analyze_class(cf)
        cross_class = [e for e in evs if e.context.get("cross_class_method_ref") == "1"]
        assert len(cross_class) == 1
        assert cross_class[0].context["target_class"] == "EvilRunner"
        assert cross_class[0].severity.name == "LOW"

    def test_same_class_lambda_body_is_not_flagged_as_cross_class(self) -> None:
        """A lambda whose body stays in the same class (the ordinary,
        overwhelmingly common case) must not trip the cross-class
        signal — only a reference resolving to a genuinely different
        class should."""
        cf = parse_class(_class_bytes("LambdaHidden"))
        assert cf is not None
        evs = D10ReflectionIndirect().analyze_class(cf)
        cross_class = [e for e in evs if e.context.get("cross_class_method_ref") == "1"]
        assert cross_class == []


class TestInvokedynamicTargetResolutionEdgeCases:
    def test_unresolvable_cp_index_returns_none(self) -> None:
        cf = parse_class(_class_bytes("LambdaHidden"))
        assert cf is not None
        result = resolve_invokedynamic_target(9999, cf.constant_pool, cf.bootstrap_methods)
        assert result is None

    def test_out_of_range_bootstrap_index_returns_none(self) -> None:
        """A CONSTANT_InvokeDynamic entry with a bootstrap_method_attr_index
        beyond the actual bootstrap_methods list (malformed/truncated
        class file) must not raise, just return None."""
        cf = parse_class(_class_bytes("LambdaHidden"))
        assert cf is not None

        invokedynamic_entries = [
            idx
            for idx, entry in cf.constant_pool.entries.items()
            if entry.bootstrap_method_attr_index is not None
        ]
        assert invokedynamic_entries

        entry = cf.constant_pool.entries[invokedynamic_entries[0]]
        original = entry.bootstrap_method_attr_index
        entry.bootstrap_method_attr_index = 9999
        try:
            result = resolve_invokedynamic_target(
                invokedynamic_entries[0], cf.constant_pool, cf.bootstrap_methods
            )
            assert result is None
        finally:
            entry.bootstrap_method_attr_index = original
