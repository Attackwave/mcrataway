"""JAR/ZIP archive parser — reads entries in memory without disk extraction."""

import zipfile
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
    """Read zip/jar files as in-memory streams."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def entries(self) -> list[ArchiveEntry]:
        """Read all entries from the archive without extracting to disk.

        Guards against zip bombs by enforcing per-entry and total size
        limits plus a maximum compression ratio.
        """
        entries: list[ArchiveEntry] = []
        total_size = 0

        with zipfile.ZipFile(self.path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                # Reject entries with path traversal sequences
                if ".." in info.filename or info.filename.startswith("/"):
                    continue

                # Check uncompressed size before reading
                if info.file_size > MAX_ENTRY_SIZE:
                    continue

                # Check compression ratio before reading
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_COMPRESSION_RATIO:
                        continue

                # Check total size budget
                if total_size + info.file_size > MAX_TOTAL_SIZE:
                    break

                try:
                    data = zf.read(info.filename)
                except (zipfile.BadZipFile, RuntimeError, OSError):
                    continue

                # Double-check the actual decompressed size matches
                if len(data) > MAX_ENTRY_SIZE:
                    continue

                total_size += len(data)
                entries.append(
                    ArchiveEntry(
                        name=info.filename,
                        data=data,
                        offset=info.header_offset,
                        size=info.file_size,
                        compressed_size=info.compress_size,
                    )
                )
        return entries

    def entries_names(self) -> list[str]:
        """Return just the names of all entries."""
        with zipfile.ZipFile(self.path, "r") as zf:
            return [i.filename for i in zf.infolist() if not i.is_dir()]


def read_archive(path: Path) -> list[ArchiveEntry]:
    """Convenience function to read all entries from an archive."""
    return ArchiveReader(path).entries()


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
    """Return entries that are Java class files."""
    return [e for e in entries if e.name.endswith(".class") and is_java_class(e.data)]
