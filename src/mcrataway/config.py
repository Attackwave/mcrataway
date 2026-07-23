"""User configuration management."""

from pathlib import Path

import yaml

from mcrataway.constants import CONFIG_DIR, CONFIG_FILE, DEFAULT_HOST, DEFAULT_PORT, QUARANTINE_DIR


class UserConfig:
    """Holds user-adjustable scanner settings."""

    def __init__(
        self,
        custom_roots: list[str] | None = None,
        max_workers: int = 4,
        quarantine_suspicious: bool = False,
        quarantine_malicious: bool = True,
        server_host: str = DEFAULT_HOST,
        server_port: int = DEFAULT_PORT,
        scan_archives: bool = True,
        scan_scripts: bool = True,
        scan_configs: bool = True,
        max_recursion_depth: int = 50,
        whitelisted_hashes: list[str] | None = None,
        excluded_paths: list[str] | None = None,
        disabled_rules: list[str] | None = None,
    ) -> None:
        self.custom_roots = custom_roots or []
        self.max_workers = max_workers
        self.quarantine_suspicious = quarantine_suspicious
        self.quarantine_malicious = quarantine_malicious
        self.server_host = server_host
        self.server_port = server_port
        self.scan_archives = scan_archives
        self.scan_scripts = scan_scripts
        self.scan_configs = scan_configs
        self.max_recursion_depth = max_recursion_depth
        self.whitelisted_hashes = whitelisted_hashes or []
        self.excluded_paths = excluded_paths or []
        self.disabled_rules = disabled_rules or []

    @classmethod
    def load(cls, path: Path | None = None) -> "UserConfig":
        path = path or CONFIG_FILE
        if not path.exists():
            return cls()
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                return cls()
            # Filter to known keys to avoid TypeError on unknown fields
            valid_keys = {
                "custom_roots",
                "max_workers",
                "quarantine_suspicious",
                "quarantine_malicious",
                "server_host",
                "server_port",
                "scan_archives",
                "scan_scripts",
                "scan_configs",
                "max_recursion_depth",
                "whitelisted_hashes",
                "excluded_paths",
                "disabled_rules",
            }
            filtered = {k: v for k, v in data.items() if k in valid_keys}
            return cls(**filtered)
        except Exception:
            return cls()

    def save(self, path: Path | None = None) -> None:
        path = path or CONFIG_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(self.__dict__, f, default_flow_style=False)


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
