"""Recursive file discovery with filtering by extension and subfolder."""

from pathlib import Path

from mcrataway.constants import (
    ARCHIVE_EXTENSIONS,
    CONFIG_EXTENSIONS,
    SCAN_SUBDIRS,
    SCRIPT_EXTENSIONS,
)

# Directory names that mark a path as a known Minecraft install layout
# (client launcher root, mod-loader instance folder). Used to decide
# per-root whether a scan should restrict itself to SCAN_SUBDIRS or walk
# everything — see is_game_layout_root().
_GAME_ROOT_NAMES = {".minecraft", "instances", "PrismLauncher"}


def is_game_layout_root(path: Path) -> bool:
    """Whether *path* itself looks like a known Minecraft install root.

    Used to decide, per scan target, whether FileWalker should restrict
    itself to SCAN_SUBDIRS (mods/, config/, etc.) or walk the directory
    in full. A user-supplied path that happens to point at a real
    ``.minecraft``/``instances``/``PrismLauncher`` folder should get the
    same restriction as an auto-discovered root — scanning it in full
    would otherwise walk unrelated launcher-internal folders (browser
    cache, logs, saves' region files, ...) that were never part of
    "check scripts inside mods".
    """
    return path.name in _GAME_ROOT_NAMES


class FileWalker:
    """Walk Minecraft roots and collect scannable files.

    ``restrict_to_scan_subdirs`` controls whether descending into a
    directory on depth >= 1 requires one of its path components to
    match :data:`SCAN_SUBDIRS`. Auto-discovered Minecraft installations
    should keep this enabled so we do not walk the user's home dir.
    User-supplied custom roots should set it to ``False`` so nested
    layouts like ``/backup/mods-archive/2023/jan/foo.jar`` are scanned
    fully.
    """

    def __init__(
        self,
        scan_archives: bool = True,
        scan_scripts: bool = True,
        scan_configs: bool = True,
        max_depth: int = 50,
        restrict_to_scan_subdirs: bool = True,
    ) -> None:
        self.scan_archives = scan_archives
        self.scan_scripts = scan_scripts
        self.scan_configs = scan_configs
        self.max_depth = max_depth
        self.restrict_to_scan_subdirs = restrict_to_scan_subdirs

    def walk(self, root: Path) -> list[Path]:
        """Collect all scannable files under root (directory or single file)."""
        if not root.exists():
            return []
        if root.is_file():
            return [root] if self._should_scan(root) else []
        if not root.is_dir():
            return []

        results: list[Path] = []
        self._walk_dir(root, results, depth=0, root=root)
        return results

    def _should_descend(self, entry: Path) -> bool:
        """Check if a directory should be descended into."""
        name = entry.name
        if name in (
            ".git",
            "node_modules",
            "__pycache__",
            ".mcrataway",
            "assets",
            "libraries",
            "logs",
            "crash-reports",
            "versions",
        ):
            return False
        if name == "natives":
            return False
        return not name.startswith(".")

    def _should_scan(self, entry: Path) -> bool:
        """Check if a file should be scanned."""
        suffix = entry.suffix.lower()
        if self.scan_archives and suffix in ARCHIVE_EXTENSIONS:
            return True
        if self.scan_scripts and suffix in SCRIPT_EXTENSIONS:
            return True
        return bool(self.scan_configs and suffix in CONFIG_EXTENSIONS)

    def _is_in_scan_dir(self, entry: Path, root: Path) -> bool:
        """Check whether *entry* sits inside a scannable folder of *root*.

        Only the part of the path below *root* counts. Testing the whole
        path instead lets a component **above** the root — a root living
        under ``/home/user/config/`` is the everyday case — match for
        every single entry, which switches the restriction off for the
        entire tree instead of scoping it.
        """
        if root.name in SCAN_SUBDIRS:
            # The root is a scannable folder itself (a custom root
            # pointing straight at a `mods/` directory, say), so
            # everything under it is in scope.
            return True
        try:
            parts = entry.relative_to(root).parts
        except ValueError:
            return False
        return bool(set(parts) & SCAN_SUBDIRS)

    def _walk_dir(self, current: Path, results: list[Path], depth: int, root: Path) -> None:
        if depth > self.max_depth:
            return

        try:
            entries = sorted(current.iterdir(), key=lambda e: e.name)
        except PermissionError:
            return

        for entry in entries:
            try:
                # Never follow symlinks — a malicious mod could link to
                # /etc/passwd, /dev/zero, or create infinite recursion.
                if entry.is_symlink():
                    continue
                if entry.is_file() and self._should_scan(entry):
                    results.append(entry)
                elif (
                    entry.is_dir()
                    and self._should_descend(entry)
                    and (
                        depth == 0
                        or not self.restrict_to_scan_subdirs
                        or self._is_in_scan_dir(entry, root)
                    )
                ):
                    # On depth 0 always descend. For deeper levels,
                    # honor restrict_to_scan_subdirs: when disabled
                    # (user-supplied root), descend unconditionally so
                    # arbitrary nested layouts are scanned.
                    self._walk_dir(entry, results, depth + 1, root)
            except (PermissionError, OSError):
                continue
