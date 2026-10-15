"""Guard test for the dashboard's HTML rendering.

``static/index.html`` is a single-file dashboard with no JS toolchain and
no browser in CI, so nothing else would catch a newly added render that
puts a scanned file's name, class name, matched string or archive entry
name into ``innerHTML`` unescaped. Those strings are chosen by whoever
wrote the scanned archive, and the API token lives in the page's
localStorage — one unescaped interpolation is full API access (purge
quarantine, whitelist a payload, delete history).

The rule this test enforces: every ``${...}`` inside an ``innerHTML``
template literal is wrapped in ``esc()``, listed in
``_SAFE_INTERPOLATIONS``, or is a template literal whose own
interpolations satisfy the same rule.

shortcut: hand-rolled scanner, not a JS parser — it does not understand
string or regex literals, so an expression holding a brace inside a
string would confuse it. The count assertion makes a pattern change fail
loudly instead of silently disabling the guard.
"""

import re
from pathlib import Path

_INDEX = (
    Path(__file__).resolve().parent.parent.parent
    / "src"
    / "mcrataway"
    / "server"
    / "static"
    / "index.html"
)

# Interpolations that may appear raw: numbers this dashboard produces
# itself, or a choice between two literals it writes itself. Never a
# string supplied by a scanned file, a rule pack or an API response.
_SAFE_INTERPOLATIONS = {
    "file.findings.length",
    "item.restored ? 'Restored' : 'Isolated'",
    "pack.rule_count",
    "entry.summary.malicious",
    "entry.summary.suspicious",
}


def _read_interpolation(source: str, start: int) -> tuple[str, int]:
    """Read from just after ``${`` to its matching ``}``."""
    depth = 0
    i = start
    while i < len(source):
        char = source[i]
        if char == "\\":
            i += 2
            continue
        if char == "`":
            _, i = _read_template_body(source, i + 1)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            if depth == 0:
                return source[start:i], i + 1
            depth -= 1
        i += 1
    raise AssertionError("unterminated interpolation")


def _read_template_body(source: str, start: int) -> tuple[str, int]:
    """Read from just after an opening backtick to its closing backtick.

    Returns the body and the index just past the closing backtick. The
    body keeps nested template literals as text so their interpolations
    are checked too.
    """
    i = start
    while i < len(source):
        if source[i] == "\\":
            i += 2
            continue
        if source[i] == "`":
            return source[start:i], i + 1
        if source.startswith("${", i):
            _, i = _read_interpolation(source, i + 2)
            continue
        i += 1
    raise AssertionError("unterminated template literal")


def _expressions_in(source: str) -> list[str]:
    """Every ``${...}`` expression in *source*, at any nesting depth."""
    found: list[str] = []
    i = 0
    while i < len(source):
        if source[i] == "\\":
            i += 2
            continue
        if source.startswith("${", i):
            expression, i = _read_interpolation(source, i + 2)
            found.append(expression)
            found.extend(_expressions_in(expression))
            continue
        i += 1
    return found


def _innerhtml_expressions(source: str) -> list[str]:
    """Every interpolation inside a template literal assigned to innerHTML."""
    found: list[str] = []
    for match in re.finditer(r"innerHTML\s*=\s*`", source):
        body, _ = _read_template_body(source, match.end())
        found.extend(_expressions_in(body))
    return found


def _is_safe(expression: str) -> bool:
    stripped = expression.strip()
    if stripped.startswith("esc(") or stripped in _SAFE_INTERPOLATIONS:
        return True
    nested = _expressions_in(stripped)
    return bool(nested) and all(_is_safe(n) for n in nested)


def test_every_innerhtml_interpolation_is_escaped() -> None:
    expressions = _innerhtml_expressions(_INDEX.read_text(encoding="utf-8"))
    assert len(expressions) >= 20, (
        f"only {len(expressions)} render sites found — the scanner no longer "
        "matches index.html, so it is not guarding anything"
    )
    unescaped = [e for e in expressions if not _is_safe(e)]
    assert not unescaped, f"unescaped innerHTML interpolation(s): {unescaped}"


def test_innerhtml_is_only_assigned_a_template_or_cleared() -> None:
    """A ``innerHTML = "..." + value`` concatenation would slip past the
    escaping rule above, so no such assignment may exist."""
    source = _INDEX.read_text(encoding="utf-8")
    strays = [
        value.strip()
        for value in re.findall(r"innerHTML\s*=\s*([^\s`\n][^`\n]*)", source)
        if value.strip() not in ("'';", '"";')
    ]
    assert not strays, f"innerHTML assigned a non-template value: {strays}"
