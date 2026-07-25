"""JAR/ZIP archive parser — reads entries in memory without disk extraction."""

import io
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

# Maximum uncompressed size per entry (100 MB)
MAX_ENTRY_SIZE = 100 * 1024 * 1024

# Maximum compression ratio (100:1) — typical jars are 2:1 to 10:1
MAX_COMPRESSION_RATIO = 100

# Maximum total uncompressed size across all entries (500 MB)
MAX_TOTAL_SIZE = 500 * 1024 * 1024


@dataclass
class ArchiveEntry:
    """A single entry inside an archive."""

    name: str
    data: bytes
    offset: int
    size: int
    compressed_size: int


class ArchiveReader:
    """Read zip/jar files as in-memory streams.

    *source* may be a filesystem path (top-level archive) or raw
    ``bytes`` (a nested archive already held in memory, e.g. a JAR
    found inside another JAR) — nested archives do not exist on disk,
    so they cannot be opened by path.
    """

    def __init__(
        self,
        source: Path | bytes,
        size_budget: "SizeBudget | None" = None,
    ) -> None:
        self.source = source
        # Shared across recursive nested-archive reads so a zip bomb
        # cannot bypass the total-size cap by nesting archives: each
        # level individually stays under MAX_TOTAL_SIZE, but without a
        # shared budget the *product* of the levels is unbounded.
        self.size_budget = size_budget if size_budget is not None else SizeBudget()

    def _open(self) -> zipfile.ZipFile:
        if isinstance(self.source, bytes):
            return zipfile.ZipFile(io.BytesIO(self.source), "r")
        return zipfile.ZipFile(self.source, "r")

    def entries(self) -> Iterator[ArchiveEntry]:
        """Yield entries from the archive one at a time, without holding
        every entry's decompressed bytes in memory simultaneously.

        This is a generator rather than a list: a large archive with
        many entries previously had every entry's ``data`` resident in
        memory at once (measured: a 400 MB JAR drove RSS from ~15 MB
        to ~417 MB), which multiplies badly with ``max_workers``
        concurrent scans. Consumers that need every entry available at
        once (e.g. rule matching that must inspect the whole archive)
        should call :func:`read_archive` / materialize explicitly and
        document why; most consumers only need one entry at a time.

        Guards against zip bombs by enforcing per-entry and total size
        limits plus a maximum compression ratio. Entries that exceed a
        budget are skipped (not silently dropped for the rest of the
        archive) via ``continue`` — a single oversized entry must not
        prevent every entry after it in the central directory from
        being scanned.
        """
        with self._open() as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                # Reject entries with path traversal sequences
                if ".." in info.filename or info.filename.startswith("/"):
                    self.size_budget.record_skip(info.filename, "path_traversal")
                    continue

                # Check uncompressed size before reading
                if info.file_size > MAX_ENTRY_SIZE:
                    self.size_budget.record_skip(info.filename, "entry_too_large")
                    continue

                # Check compression ratio before reading
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_COMPRESSION_RATIO:
                        self.size_budget.record_skip(info.filename, "compression_ratio")
                        continue

                # Check total size budget — shared across nested
                # archives, so continue (not break): entries after this
                # one in the central directory may still be small
                # enough to fit, and skipping past a single big entry
                # must not blind the scanner to everything behind it.
                if not self.size_budget.reserve(info.file_size):
                    self.size_budget.record_skip(info.filename, "total_budget_exceeded")
                    continue

                try:
                    data = zf.read(info.filename)
                except (zipfile.BadZipFile, RuntimeError, OSError):
                    self.size_budget.record_skip(info.filename, "read_error")
                    continue

                # Double-check the actual decompressed size matches
                if len(data) > MAX_ENTRY_SIZE:
                    self.size_budget.record_skip(info.filename, "entry_too_large")
                    continue

                yield ArchiveEntry(
                    name=info.filename,
                    data=data,
                    offset=info.header_offset,
                    size=info.file_size,
                    compressed_size=info.compress_size,
                )

    def entries_names(self) -> list[str]:
        """Return just the names of all entries."""
        with self._open() as zf:
            return [i.filename for i in zf.infolist() if not i.is_dir()]


class SizeBudget:
    """Tracks a shared uncompressed-size budget across nested archives.

    A nested zip bomb can stay under :data:`MAX_TOTAL_SIZE` at every
    individual level while the product across levels is unbounded.
    Sharing one budget instance across all recursive
    :class:`ArchiveReader` calls for a single top-level artifact closes
    that gap. Also records why entries were skipped so the scan report
    can distinguish "not scanned" from "scanned and clean".
    """

    def __init__(self, limit: int = MAX_TOTAL_SIZE) -> None:
        self.limit = limit
        self.used = 0
        self.skipped: list[tuple[str, str]] = []

    def reserve(self, size: int) -> bool:
        """Attempt to reserve *size* bytes. Returns False if it would exceed the budget."""
        if self.used + size > self.limit:
            return False
        self.used += size
        return True

    def record_skip(self, name: str, reason: str) -> None:
        self.skipped.append((name, reason))


def read_archive(path: Path) -> list[ArchiveEntry]:
    """Convenience function to read all entries from an archive.

    Materializes the full entry list — only use this where every
    entry genuinely needs to be resident in memory at once (e.g.
    ad-hoc inspection tooling). The scan engine's hot path iterates
    :meth:`ArchiveReader.entries` directly to avoid this.
    """
    return list(ArchiveReader(path).entries())


# Default maximum recursion depth for nested archives (JAR-in-JAR).
# Matches the historical default of FileWalker/config.max_recursion_depth
# in spirit, but is intentionally much smaller: nesting depth for
# legitimate mod packaging (Forge JarJar, Fabric nested jars) is 1-2
# levels; anything deeper is almost certainly evasion, not packaging.
DEFAULT_MAX_NESTING_DEPTH = 6


def has_manifest(entries: list[ArchiveEntry]) -> bool:
    """Check if archive contains a MANIFEST.MF with a Main-Class entry."""
    for e in entries:
        if e.name == "META-INF/MANIFEST.MF" or e.name == "MANIFEST.MF":
            return b"Main-Class" in e.data
    return False


def find_entries_by_suffix(entries: list[ArchiveEntry], suffix: str) -> list[ArchiveEntry]:
    """Filter entries by their file suffix."""
    return [e for e in entries if e.name.lower().endswith(suffix)]


def is_java_class(data: bytes) -> bool:
    """Check if bytes start with the Java class magic."""
    return data[:4] == b"\xCA\xFE\xBA\xBE"


def find_class_entries(entries: list[ArchiveEntry]) -> list[ArchiveEntry]:
    """Return entries that are Java class files.

    Identified by magic bytes, not the ``.class`` extension: a
    ClassLoader that reads bytes directly via ``defineClass`` does not
    care about the entry name, so relying on the extension lets an
    attacker hide a payload class under any other name (e.g.
    ``model.bin``).
    """
    return [e for e in entries if is_java_class(e.data)]


# ZIP local file header magic — used to detect a nested archive by
# content rather than by the ``.jar``/``.zip`` extension, since an
# attacker can rename an inner archive to avoid detection.
_ZIP_MAGIC = b"PK\x03\x04"


def is_nested_archive(data: bytes) -> bool:
    """Check if bytes look like a ZIP/JAR archive (nested archive detection)."""
    return data[:4] == _ZIP_MAGIC


def find_nested_archive_entries(entries: list[ArchiveEntry]) -> list[ArchiveEntry]:
    """Return entries that are themselves ZIP/JAR archives, by content."""
    return [e for e in entries if is_nested_archive(e.data)]
