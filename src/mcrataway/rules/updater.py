"""Rule pack dynamic updater — fetches signatures from remote URLs or repositories."""

import logging
from pathlib import Path
import urllib.request
import urllib.error

from mcrataway.constants import CONFIG_DIR
from mcrataway.rules.signing import verify_signature

logger = logging.getLogger(__name__)

RULES_DIR = CONFIG_DIR / "rules"

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

    def fetch_remote_rules(self, urls: list[str] | None = None, timeout: int = 10) -> list[Path]:
        """Download and verify remote rule files into the target rules directory.

        Only signature-verified packs are written to disk; on
        verification failure the previous on-disk version (if any) is
        left in place rather than overwritten.
        """
        urls = urls or DEFAULT_RULE_URLS
        downloaded: list[Path] = []

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

            destination.write_bytes(content)
            destination.with_name(destination.name + ".sig").write_text(signature_b64)
            downloaded.append(destination)

        return downloaded

    @staticmethod
    def _fetch_bytes(url: str, timeout: int) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "mcrataway-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                raise urllib.error.URLError(f"HTTP {response.status}")
            data: bytes = response.read()
            return data
