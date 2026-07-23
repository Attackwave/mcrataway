"""Recursive file discovery with filtering by extension and subfolder."""

from pathlib import Path

from mcrataway.constants import (
    ARCHIVE_EXTENSIONS,
    CONFIG_EXTENSIONS,
    SCAN_SUBDIRS,
    SCRIPT_EXTENSIONS,
)


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
        self._walk_dir(root, results, depth=0)
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

    def _is_in_scan_dir(self, entry: Path) -> bool:
        """Check if file is within a known scannable subdirectory."""
        parts = set(entry.parts)
        return bool(parts & SCAN_SUBDIRS)

    def _walk_dir(self, current: Path, results: list[Path], depth: int) -> None:
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
                        or self._is_in_scan_dir(entry)
                    )
                ):
                    # On depth 0 always descend. For deeper levels,
                    # honor restrict_to_scan_subdirs: when disabled
                    # (user-supplied root), descend unconditionally so
                    # arbitrary nested layouts are scanned.
                    self._walk_dir(entry, results, depth + 1)
            except (PermissionError, OSError):
                continue
