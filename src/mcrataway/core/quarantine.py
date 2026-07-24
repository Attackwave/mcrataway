"""Quarantine manager — moves malicious files to a safe directory with manifest."""

import contextlib
import json
import re
import shutil
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcrataway.constants import QUARANTINE_DIR

# SHA-256 hashes are 64 lowercase hex characters
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


@dataclass
class QuarantineManifest:
    """Metadata for a quarantined file."""

    original_path: str
    sha256: str
    quarantined_path: str
    verdict: str
    confidence: float
    findings: list[dict[str, Any]]
    timestamp: str
    restored: bool = False


class QuarantineManager:
    """Manages quarantine of suspicious and malicious files."""

    def __init__(
        self,
        quarantine_dir: Path | None = None,
        do_quarantine_malicious: bool = True,
        do_quarantine_suspicious: bool = False,
    ) -> None:
        self.quarantine_dir = quarantine_dir or QUARANTINE_DIR
        self.do_quarantine_malicious = do_quarantine_malicious
        self.do_quarantine_suspicious = do_quarantine_suspicious

    def quarantine(
        self,
        path: Path,
        result: object,  # ArtifactResult
    ) -> QuarantineManifest | None:
        """Move a file to quarantine and write manifest.

        Refuses to re-quarantine a hash that is already present in the
        quarantine directory: a second file with identical content
        would otherwise overwrite the first manifest (losing the first
        original_path) and the restore step would only reinstate the
        most recently quarantined copy.
        """
        if not path.exists():
            return None

        sha256 = getattr(result, "file_hash", "")
        if not sha256:
            return None

        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        quarantine_path = self.quarantine_dir / sha256
        manifest_path = quarantine_path / "manifest.json"
        if manifest_path.exists():
            # Already quarantined — refuse to clobber the existing
            # entry to preserve the first original_path and avoid
            # data loss on restore.
            return None
        quarantine_path.mkdir(parents=True, exist_ok=True)

        # Preserve relative path structure, but make the filename unique
        # within the quarantine subdir in case the same basename appears
        # in different scans (the SHA dir already disambiguates content,
        # this guards against same-hash re-runs leaving stale copies).
        rel = path.name
        target = quarantine_path / rel

        try:
            # Step 1: copy the file into quarantine FIRST. If this
            # fails we leave the original untouched.
            shutil.copy2(path, target)

            # Step 2: build the manifest and write it. The manifest is
            # what makes the entry visible in list_quarantined() and
            # restorable; write it before destroying the original so a
            # crash between steps does not leave an orphaned copy.
            manifest = QuarantineManifest(
                original_path=str(path),
                sha256=sha256,
                quarantined_path=str(target),
                verdict=str(getattr(result, "verdict", "")),
                confidence=getattr(result, "confidence", 0.0),
                findings=[f.to_dict() for f in getattr(result, "findings", [])],
                timestamp=datetime.now(UTC).isoformat(),
            )
            manifest_path = quarantine_path / "manifest.json"
            manifest_path.write_text(json.dumps(asdict(manifest), indent=2))

            # Step 3: replace the original with a placeholder. This is
            # the destructive step — if unlink fails (read-only FS,
            # permission denied) we must roll back the quarantine copy
            # and manifest so the user does not get a false sense of
            # security (mod still active) AND a leaky orphan entry.
            placeholder = path.with_suffix(path.suffix + ".quarantined")
            try:
                placeholder.write_text(
                    f"This file has been quarantined by mcrataway.\n"
                    f"Original: {path}\n"
                    f"SHA-256: {sha256}\n"
                    f"Quarantine: {target}\n"
                    f"Date: {datetime.now(UTC).isoformat()}\n"
                )
                path.unlink()
            except Exception:
                # Roll back: remove the quarantine copy + manifest +
                # placeholder so the entry does not linger.
                with contextlib.suppress(Exception):
                    target.unlink(missing_ok=True)
                with contextlib.suppress(Exception):
                    manifest_path.unlink(missing_ok=True)
                with contextlib.suppress(Exception):
                    if placeholder.exists():
                        placeholder.unlink()
                return None

            return manifest

        except Exception:
            return None

    def restore(self, sha256: str) -> bool:
        """Restore a quarantined file to its original location."""
        if not _SHA256_RE.match(sha256):
            return False
        quarantine_path = self.quarantine_dir / sha256
        manifest_path = quarantine_path / "manifest.json"

        if not manifest_path.exists():
            return False

        try:
            manifest_data = json.loads(manifest_path.read_text())
            original_path = Path(manifest_data["original_path"])
            quarantined_name = Path(manifest_data["quarantined_path"]).name
            source = quarantine_path / quarantined_name

            if not source.exists():
                return False

            # Refuse to clobber an existing file at the original path —
            # the user may have recreated it (e.g. Minecraft reinstalled
            # the mod). Restoring would silently destroy their new copy.
            if original_path.exists():
                return False

            # Restore original file
            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(original_path))

            # Remove placeholder if it exists
            placeholder = original_path.with_suffix(original_path.suffix + ".quarantined")
            if placeholder.exists():
                placeholder.unlink()

            # Update manifest
            manifest_data["restored"] = True
            manifest_data["restore_timestamp"] = datetime.now(UTC).isoformat()
            manifest_path.write_text(json.dumps(manifest_data, indent=2))

            return True

        except Exception:
            return False

    def list_quarantined(self) -> list[QuarantineManifest]:
        """List all quarantined items."""
        results: list[QuarantineManifest] = []
        if not self.quarantine_dir.exists():
            return results

        for item in self.quarantine_dir.iterdir():
            if item.is_dir():
                manifest_path = item / "manifest.json"
                if manifest_path.exists():
                    try:
                        data = json.loads(manifest_path.read_text())
                        # Only pass known fields; ignore extras like restore_timestamp
                        results.append(QuarantineManifest(
                            original_path=data["original_path"],
                            sha256=data["sha256"],
                            quarantined_path=data["quarantined_path"],
                            verdict=data["verdict"],
                            confidence=data["confidence"],
                            findings=data["findings"],
                            timestamp=data["timestamp"],
                            restored=data.get("restored", False),
                        ))
                    except Exception:
                        continue

        return results

    def delete_permanently(self, item_id: str) -> bool:
        """Permanently delete a quarantined item from disk."""
        item_id_clean = item_id.strip()
        if not item_id_clean or not self.quarantine_dir.exists():
            return False

        quarantine_path = self.quarantine_dir / item_id_clean
        if not quarantine_path.exists():
            found = [p for p in self.quarantine_dir.iterdir() if p.name.lower() == item_id_clean.lower()]
            if found:
                quarantine_path = found[0]
            else:
                return False

        # Attempt to remove placeholder if manifest exists
        manifest_path = quarantine_path / "manifest.json" if quarantine_path.is_dir() else None
        if manifest_path and manifest_path.exists():
            try:
                manifest_data = json.loads(manifest_path.read_text())
                original_path = Path(manifest_data.get("original_path", ""))
                if str(original_path):
                    placeholder = original_path.with_suffix(original_path.suffix + ".quarantined")
                    if placeholder.exists():
                        placeholder.unlink(missing_ok=True)
            except Exception:
                pass

        try:
            if quarantine_path.is_dir():
                shutil.rmtree(quarantine_path)
            elif quarantine_path.is_file():
                quarantine_path.unlink()
            return True
        except Exception:
            return False

    def purge_all(self) -> int:
        """Permanently delete all items in quarantine."""
        deleted_count = 0
        if not self.quarantine_dir.exists():
            return 0
        for item in list(self.quarantine_dir.iterdir()):
            if self.delete_permanently(item.name):
                deleted_count += 1
            else:
                try:
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                    deleted_count += 1
                except Exception:
                    pass
        return deleted_count
