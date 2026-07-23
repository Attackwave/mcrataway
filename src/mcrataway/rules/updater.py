"""Rule pack dynamic updater — fetches signatures from remote URLs or repositories."""

import logging
from pathlib import Path
import urllib.request
import urllib.error

from mcrataway.constants import CONFIG_DIR

logger = logging.getLogger(__name__)

RULES_DIR = CONFIG_DIR / "rules"

DEFAULT_RULE_URLS = [
    "https://raw.githubusercontent.com/Attackwave/mcrataway/main/src/mcrataway/rules/packs/suspicious_indicators.yaml",
    "https://raw.githubusercontent.com/Attackwave/mcrataway/main/src/mcrataway/rules/packs/minecraft_families.yaml",
]


class RuleUpdater:
    """Fetches and manages custom or dynamic YAML rule packs."""

    def __init__(self, target_dir: Path | None = None) -> None:
        self.target_dir = target_dir or RULES_DIR
        self.target_dir.mkdir(parents=True, exist_ok=True)

    def fetch_remote_rules(self, urls: list[str] | None = None, timeout: int = 10) -> list[Path]:
        """Download remote rule files into the target rules directory."""
        urls = urls or DEFAULT_RULE_URLS
        downloaded: list[Path] = []

        for idx, url in enumerate(urls):
            filename = f"remote_pack_{idx + 1}.yaml"
            destination = self.target_dir / filename
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "mcrataway-scanner/1.0"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    if response.status == 200:
                        content = response.read()
                        destination.write_bytes(content)
                        downloaded.append(destination)
            except (urllib.error.URLError, TimeoutError, OSError) as err:
                logger.warning("Failed to fetch rule pack from %s: %s", url, err)

        return downloaded
