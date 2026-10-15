"""Config-file scanning: an embedded script is a call, not a mention.

CONFIG_EXTENSIONS covers .json/.toml/.yml/.yaml/.mcmeta/.txt, so a
substring match on "eval(" flagged changelogs, comments and localisation
strings that merely talk about the function — and with "quarantine
suspicious" enabled, a flagged config is moved into the vault like a
payload. The detector therefore requires a call with an argument.
"""

from pathlib import Path

import pytest

from mcrataway.constants import Verdict
from mcrataway.core.scan_engine import ScanEngine


@pytest.fixture
def engine() -> ScanEngine:
    return ScanEngine(rules=[])


def _scan_config(engine: ScanEngine, tmp_path: Path, text: str, suffix: str = ".json"):
    path = tmp_path / f"config{suffix}"
    path.write_text(text)
    return engine._scan_config(path, "hash-of-nothing")


@pytest.mark.parametrize(
    "payload",
    [
        '{"script": "eval(payload)"}',
        "value = eval(input)",
        '{"url": "javascript:alert(1)"}',
        # Browsers tolerate the space after the colon; the URI still
        # carries a call, so it is still a payload.
        '{"url": "javascript: alert(1)"}',
    ],
    ids=["eval-call", "eval-call-toml", "javascript-url", "javascript-url-spaced"],
)
def test_config_with_an_embedded_call_is_suspicious(
    engine: ScanEngine, tmp_path: Path, payload: str
) -> None:
    result = _scan_config(engine, tmp_path, payload)

    assert result.verdict is Verdict.SUSPICIOUS
    assert [f.detector_id for f in result.findings] == ["config:embedded_script"]


@pytest.mark.parametrize(
    "benign",
    [
        "# do not use eval( in your scripts\nkey: value\n",
        "// eval() support was removed in 1.2\n{}\n",
        '{"notes": "javascript: URIs are stripped by the loader"}',
        "value = evaluation_mode\n",
        '{"eval": "nothing callable here"}',
    ],
    ids=["yaml-comment", "js-comment", "javascript-in-comment", "evaluation", "eval-key"],
)
def test_config_that_merely_mentions_a_call_is_clean(
    engine: ScanEngine, tmp_path: Path, benign: str
) -> None:
    result = _scan_config(engine, tmp_path, benign)

    assert result.verdict is Verdict.CLEAN
    assert result.findings == []
