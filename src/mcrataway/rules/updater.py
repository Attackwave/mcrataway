"""Rule pack dynamic updater — fetches signatures from remote URLs or repositories."""

import json
import logging
import urllib.error
import urllib.request
from pathlib import Path

import yaml

from mcrataway.constants import CONFIG_DIR
from mcrataway.rules.signing import verify_signature

logger = logging.getLogger(__name__)

RULES_DIR = CONFIG_DIR / "rules"

# The version-state file (see RuleUpdater._version_state_file) tracks
# the last accepted pack_version per source URL, so a signed but
# *older* pack cannot be served again later (a rollback/downgrade
# attack: the signature only proves who published a file, not that it
# is the most recent one — an attacker in control of the download
# channel, e.g. a compromised mirror or repo takeover, could replay an
# old, validly-signed pack that lacks detection for a since-added
# malware family).

DEFAULT_RULE_URLS = [
    "https://raw.githubusercontent.com/Attackwave/mcrataway/main/src/mcrataway/rules/packs/suspicious_indicators.yaml",
    "https://raw.githubusercontent.com/Attackwave/mcrataway/main/src/mcrataway/rules/packs/minecraft_families.yaml",
]


class RuleUpdater:
    """Fetches and manages custom or dynamic YAML rule packs.

    Every downloaded rule pack must carry a valid detached signature
    (a ``<name>.yaml.sig`` fetched from ``<url> + ".sig"``) verified
    against the trust root in :mod:`mcrataway.rules.signing`. A rule
    pack that fails verification — missing signature, corrupt
    signature, or signed by an untrusted key — is discarded and the
    previously installed version (if any) is left untouched. Remote
    rules are therefore never accepted unsigned, and a compromised
    download channel cannot silently swap in rules that wave through
    real malware or quarantine arbitrary benign mods.
    """

    def __init__(self, target_dir: Path | None = None) -> None:
        self.target_dir = target_dir or RULES_DIR
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self._version_state_file = self.target_dir / ".pack_versions.json"

    def fetch_remote_rules(self, urls: list[str] | None = None, timeout: int = 10) -> list[Path]:
        """Download and verify remote rule files into the target rules directory.

        Only signature-verified packs are written to disk; on
        verification failure the previous on-disk version (if any) is
        left in place rather than overwritten. If a pack declares an
        optional top-level ``pack_version`` field, an update is also
        rejected when its version is not greater than the last
        accepted version for that URL — this blocks a rollback attack
        where a compromised download channel replays an older,
        validly-signed pack. Packs without a ``pack_version`` field
        (e.g. older packs, or ones from before this field existed) are
        accepted as before, with no downgrade protection — this is a
        best-effort defense, not a hard requirement of the format.
        """
        urls = urls or DEFAULT_RULE_URLS
        downloaded: list[Path] = []
        version_state = self._load_version_state()

        for idx, url in enumerate(urls):
            filename = f"remote_pack_{idx + 1}.yaml"
            destination = self.target_dir / filename
            try:
                content = self._fetch_bytes(url, timeout)
                signature_b64 = self._fetch_bytes(url + ".sig", timeout).decode(
                    "ascii", errors="replace"
                ).strip()
            except (urllib.error.URLError, TimeoutError, OSError) as err:
                logger.warning("Failed to fetch rule pack from %s: %s", url, err)
                continue

            if not verify_signature(content, signature_b64):
                logger.warning(
                    "Rejected rule pack from %s: signature missing or invalid "
                    "(previous version, if any, was left unchanged)",
                    url,
                )
                continue

            new_version = self._extract_pack_version(content)
            old_version = version_state.get(url)
            if new_version is not None and old_version is not None and new_version <= old_version:
                logger.warning(
                    "Rejected rule pack from %s: pack_version %r is not newer "
                    "than the last accepted version %r (possible downgrade/"
                    "rollback of a validly-signed but outdated pack)",
                    url, new_version, old_version,
                )
                continue

            destination.write_bytes(content)
            destination.with_name(destination.name + ".sig").write_text(signature_b64)
            if new_version is not None:
                version_state[url] = new_version
            downloaded.append(destination)

        self._save_version_state(version_state)
        return downloaded

    @staticmethod
    def _extract_pack_version(content: bytes) -> str | None:
        """Read the optional top-level ``pack_version`` field without
        going through RulePackLoader (which only extracts rules, not
        pack-level metadata). Versions are compared as strings, so an
        ISO-8601 date (``"2026-08-01"``) or a zero-padded integer
        (``"0007"``) both sort correctly; an unpadded plain integer
        does not, so publishers should use one of those two forms.
        """
        try:
            data = yaml.safe_load(content)
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        version = data.get("pack_version")
        return str(version) if version is not None else None

    def _load_version_state(self) -> dict[str, str]:
        try:
            raw = json.loads(self._version_state_file.read_text())
            if isinstance(raw, dict):
                return {str(k): str(v) for k, v in raw.items()}
        except Exception:
            pass
        return {}

    def _save_version_state(self, state: dict[str, str]) -> None:
        try:
            self._version_state_file.write_text(json.dumps(state))
        except OSError:
            logger.warning(
                "Could not persist rule pack version state to %s",
                self._version_state_file,
            )

    @staticmethod
    def _fetch_bytes(url: str, timeout: int) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "mcrataway-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                raise urllib.error.URLError(f"HTTP {response.status}")
            data: bytes = response.read()
            return data
