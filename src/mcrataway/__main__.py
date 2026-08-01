"""CLI entry point."""

import os
import sys
from pathlib import Path


def _apply_home_dir_override() -> None:
    """Read --home-dir out of argv, export it as MCRATAWAY_HOME, and persist it.

    Must run before `mcrataway.cli` (and everything it imports, down to
    `mcrataway.constants`) is imported: CONFIG_DIR and every path derived
    from it are fixed at import time, so by the time Click could parse
    this as a normal option it would already be too late.

    Persisting to the pointer file (same path as
    mcrataway.constants.HOME_POINTER_FILE, duplicated here since we can't
    import mcrataway.constants yet at this point) means a --home-dir given
    once is remembered on subsequent plain `mcrataway` calls, instead of
    silently forking into a second tree back under ~/.mcrataway.
    """
    argv = sys.argv[1:]
    home_dir = None
    for i, arg in enumerate(argv):
        if arg == "--home-dir" and i + 1 < len(argv):
            home_dir = argv[i + 1]
            break
        if arg.startswith("--home-dir="):
            home_dir = arg.split("=", 1)[1]
            break

    if home_dir is None:
        return

    pointer_file = Path.home() / ".config" / "mcrataway" / "home_dir"

    if home_dir == "default":
        # Escape hatch back to ~/.mcrataway: forget the persisted override
        # instead of treating the literal string "default" as a path.
        pointer_file.unlink(missing_ok=True)
        return

    os.environ["MCRATAWAY_HOME"] = home_dir
    pointer_file.parent.mkdir(parents=True, exist_ok=True)
    pointer_file.write_text(home_dir)


_apply_home_dir_override()

from mcrataway.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
