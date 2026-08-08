"""User configuration management."""

import contextlib
from pathlib import Path

import yaml

from mcrataway.constants import CONFIG_DIR, CONFIG_FILE, QUARANTINE_DIR


class UserConfig:
    """Holds user-adjustable scanner settings."""

    def __init__(
        self,
        custom_roots: list[str] | None = None,
        excluded_roots: list[str] | None = None,
        auto_discover_enabled: bool = True,
        max_workers: int = 4,
        quarantine_suspicious: bool = False,
        quarantine_malicious: bool = True,
        scan_archives: bool = True,
        scan_scripts: bool = True,
        scan_configs: bool = True,
        max_recursion_depth: int = 50,
        whitelisted_hashes: list[str] | None = None,
        excluded_paths: list[str] | None = None,
        disabled_rules: list[str] | None = None,
        quarantine_dir: str | None = None,
        history_max_entries: int = 50,
        date_format: str = "YYYY-MM-DD",
        time_format: str = "24h",
    ) -> None:
        self.custom_roots = custom_roots or []
        # Auto-discovered roots (os_paths.discover_roots()) the user has
        # dismissed from the Scan Engine's Target Directories list. Unlike
        # excluded_paths (a glob filter applied to individual files during
        # a scan), this hides a whole discovered install path from the UI
        # entirely — discovered roots have no "Remove" button by default
        # since they aren't config-backed and would otherwise just
        # reappear unchanged on the next server start/roots refresh.
        self.excluded_roots = excluded_roots or []
        # Global kill switch for auto-discovery (os_paths.discover_roots()),
        # for users who only ever scan custom_roots and don't want any
        # auto-detected installs showing up at all — a coarser complement
        # to excluded_roots, which dismisses discovered paths one at a time.
        self.auto_discover_enabled = auto_discover_enabled
        self.max_workers = max_workers
        self.quarantine_suspicious = quarantine_suspicious
        self.quarantine_malicious = quarantine_malicious
        self.scan_archives = scan_archives
        self.scan_scripts = scan_scripts
        self.scan_configs = scan_configs
        self.max_recursion_depth = max_recursion_depth
        self.whitelisted_hashes = whitelisted_hashes or []
        self.excluded_paths = excluded_paths or []
        self.disabled_rules = disabled_rules or []
        self.quarantine_dir = quarantine_dir or str(QUARANTINE_DIR)
        self.history_max_entries = history_max_entries
        self.date_format = date_format
        self.time_format = time_format

    @classmethod
    def load(cls, path: Path | None = None) -> "UserConfig":
        path = path or CONFIG_FILE
        if not path.exists():
            default_cfg = cls()
            with contextlib.suppress(Exception):
                default_cfg.save(path)
            return default_cfg
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                return cls()
            # Filter to known keys to avoid TypeError on unknown fields
            valid_keys = {
                "custom_roots",
                "excluded_roots",
                "auto_discover_enabled",
                "max_workers",
                "quarantine_suspicious",
                "quarantine_malicious",
                "scan_archives",
                "scan_scripts",
                "scan_configs",
                "max_recursion_depth",
                "whitelisted_hashes",
                "excluded_paths",
                "disabled_rules",
                "quarantine_dir",
                "history_max_entries",
                "date_format",
                "time_format",
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
        # Matches TOKEN_FILE's permissions (see server/auth.py): the
        # config can contain scanned paths and quarantine locations,
        # which on a multi-user system reveal information about what
        # the user has been scanning/finding to other local accounts.
        with contextlib.suppress(OSError):
            path.chmod(0o600)


def ensure_config_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
