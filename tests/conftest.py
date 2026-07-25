"""Shared test fixtures.

Isolates all mcrataway config/quarantine/token state under a temp
directory for every test. ``mcrataway.constants`` resolves
``CONFIG_DIR = Path.home() / ".mcrataway"`` once at import time, so
merely patching ``$HOME`` at test time would not affect an
already-imported module — the constants themselves (and the
already-derived QUARANTINE_DIR/TOKEN_FILE/CONFIG_FILE) must be
patched directly. Without this, anything that touches the server app
(which now auto-generates an auth token on first run) would read and
write the real developer's ``~/.mcrataway`` directory.
"""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_mcrataway_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect all mcrataway user-config paths to a per-test temp dir."""
    home = tmp_path / "mcrataway_home"
    config_dir = home / ".mcrataway"
    quarantine_dir = config_dir / "quarantine"
    token_file = config_dir / "token"
    config_file = config_dir / "config.yaml"

    import mcrataway.constants as constants_mod

    monkeypatch.setattr(constants_mod, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(constants_mod, "QUARANTINE_DIR", quarantine_dir)
    monkeypatch.setattr(constants_mod, "TOKEN_FILE", token_file)
    monkeypatch.setattr(constants_mod, "CONFIG_FILE", config_file)

    # Modules that imported these names directly (``from ... import X``)
    # hold their own reference and are not affected by patching the
    # constants module above — patch those call sites too.
    import mcrataway.config as config_mod

    monkeypatch.setattr(config_mod, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", config_file)
    monkeypatch.setattr(config_mod, "QUARANTINE_DIR", quarantine_dir)

    import mcrataway.core.quarantine as quarantine_mod

    monkeypatch.setattr(quarantine_mod, "QUARANTINE_DIR", quarantine_dir)

    import mcrataway.server.auth as auth_mod

    monkeypatch.setattr(auth_mod, "TOKEN_FILE", token_file)

    import mcrataway.rules.updater as updater_mod

    monkeypatch.setattr(updater_mod, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(updater_mod, "RULES_DIR", config_dir / "rules")

    return home
