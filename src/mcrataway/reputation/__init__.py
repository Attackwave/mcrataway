"""Known-good hash reputation store — offline lookup of verified-clean
mod hashes.

The most effective false-positive defense is knowing what the
unmodified, author-published version of a mod looks like. A SHA-256
match against a curated set of clean mods from Modrinth/CurseForge
directly answers "is this the file the author published?" — and if
yes, the scanner can safely skip it even if its bytecode contains
patterns that look suspicious in isolation (native loading, network
access, reflection — all common in legitimate mods).

The store is fetched between scans (never during — see plan §6.4's
"no network during scan" stance), verified against the same Ed25519
trust root as rule packs, and stored at
``~/.mcrataway/reputation/known_good.yaml``. A signed-but-stale store
is still usable: hashes don't expire, and a compromised download
channel cannot add fraudulent "clean" hashes for malware without a
valid signature.

The store is opt-in (default off) to respect users who don't want
network fetches; when enabled, it merges with the user's manual
``whitelisted_hashes`` config.
"""

import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from mcrataway.constants import CONFIG_DIR
from mcrataway.rules.signing import verify_signature

logger = logging.getLogger(__name__)

REPUTATION_DIR = CONFIG_DIR / "reputation"
KNOWN_GOOD_FILE = REPUTATION_DIR / "known_good.yaml"

# Default URL for the known-good hash set. Like DEFAULT_RULE_URLS, this
# points at the project's own repo; the file and its .sig sibling are
# maintained by a CI workflow (see .github/workflows/sign-rules.yml,
# which can be extended to sign reputation files too). An empty or
# missing file is the safe default — nothing is whitelisted.
DEFAULT_KNOWN_GOOD_URL = (
    "https://raw.githubusercontent.com/Attackwave/mcrataway/main/"
    "src/mcrataway/reputation/known_good.yaml"
)


@dataclass
class KnownGoodEntry:
    """A single known-good mod entry."""

    sha256: str
    mod_id: str = ""
    name: str = ""
    version: str = ""
    loader: str = ""
    source: str = ""  # "modrinth", "curseforge", "manual"


@dataclass
class KnownGoodStore:
    """In-memory representation of the known-good hash set."""

    entries: dict[str, KnownGoodEntry] = field(default_factory=dict)
    pack_version: str = ""

    @property
    def hashes(self) -> set[str]:
        """The set of all known-good SHA-256 hashes."""
        return set(self.entries.keys())

    def is_known_good(self, sha256: str) -> bool:
        """Check whether a SHA-256 hash is in the known-good set."""
        return sha256 in self.entries

    def get_entry(self, sha256: str) -> KnownGoodEntry | None:
        """Get the metadata entry for a known-good hash, or None."""
        return self.entries.get(sha256)


def load_known_good_store(path: Path | None = None) -> KnownGoodStore:
    """Load the known-good hash store from disk.

    Returns an empty store if the file doesn't exist or is invalid —
    a missing store means nothing is whitelisted, which is the safe
    default.
    """
    path = path or KNOWN_GOOD_FILE
    if not path.exists():
        return KnownGoodStore()

    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        logger.warning("Could not parse known-good store at %s", path)
        return KnownGoodStore()

    if not isinstance(data, dict):
        return KnownGoodStore()

    store = KnownGoodStore(pack_version=str(data.get("pack_version", "")))
    entries = data.get("entries", [])
    if not isinstance(entries, list):
        return store

    for entry_data in entries:
        if not isinstance(entry_data, dict):
            continue
        sha = entry_data.get("sha256", "")
        if not sha:
            continue
        store.entries[sha] = KnownGoodEntry(
            sha256=sha,
            mod_id=str(entry_data.get("mod_id", "")),
            name=str(entry_data.get("name", "")),
            version=str(entry_data.get("version", "")),
            loader=str(entry_data.get("loader", "")),
            source=str(entry_data.get("source", "")),
        )

    return store


class ReputationUpdater:
    """Fetches and verifies the known-good hash store from a remote
    source, using the same Ed25519 signature verification as rule packs.

    The store is fetched between scans (never during), so network
    latency and availability don't affect scan performance. Only a
    signature-verified store is written to disk; on verification
    failure, the previous version (if any) is left untouched.
    """

    def __init__(self, target_dir: Path | None = None) -> None:
        self.target_dir = target_dir or REPUTATION_DIR
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self._file_path = self.target_dir / "known_good.yaml"

    def fetch_known_good(
        self, url: str | None = None, timeout: int = 15
    ) -> bool:
        """Download and verify the known-good hash store.

        Returns True if a new store was installed, False if the fetch
        or verification failed (in which case the previous version is
        left untouched).
        """
        url = url or DEFAULT_KNOWN_GOOD_URL
        try:
            content = self._fetch_bytes(url, timeout)
            signature_b64 = self._fetch_bytes(url + ".sig", timeout).decode(
                "ascii", errors="replace"
            ).strip()
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            logger.warning("Failed to fetch known-good store from %s: %s", url, err)
            return False

        if not verify_signature(content, signature_b64):
            logger.warning(
                "Rejected known-good store from %s: signature missing or invalid "
                "(previous version, if any, was left unchanged)",
                url,
            )
            return False

        self._file_path.write_bytes(content)
        self._file_path.with_name(self._file_path.name + ".sig").write_text(signature_b64)
        logger.info("Known-good hash store updated from %s", url)
        return True

    @staticmethod
    def _fetch_bytes(url: str, timeout: int) -> bytes:
        req = urllib.request.Request(
            url, headers={"User-Agent": "mcrataway-scanner/1.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                raise urllib.error.URLError(f"HTTP {response.status}")
            data: bytes = response.read()
            return data
