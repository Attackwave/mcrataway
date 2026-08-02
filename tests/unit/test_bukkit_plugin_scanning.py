"""Tests for Bukkit/Spigot/Paper server-side plugin scanning.

Server plugins are a large real threat surface — backdoored plugins
with Runtime.exec, RCON abuse, and config exfiltration are common.
The detection logic (D01–D14) runs on any JAR, so the gaps are:
discovery (plugins/ directories), plugin.yml parsing, and
server-specific threat patterns.

These tests verify:
  - Server root discovery finds directories with plugins/ or
    server.properties+mods/.
  - plugin.yml parsing extracts main class, name, version, commands.
  - A plugin JAR with plugin.yml is scanned with correct loader
    metadata.
"""

from pathlib import Path

import yaml

from mcrataway.core.quarantine import QuarantineManager
from mcrataway.core.scan_engine import ScanEngine
from mcrataway.discovery.os_paths import _is_server_root, discover_plugin_dirs
from mcrataway.parsers.manifest import parse_archive_manifest, parse_plugin_yml
from mcrataway.rules.loader import RulePackLoader


class TestServerRootDiscovery:
    """Server root discovery must find Bukkit/Spigot/Paper installs."""

    def test_directory_with_plugins_is_server_root(self, tmp_path: Path) -> None:
        (tmp_path / "plugins").mkdir()
        assert _is_server_root(tmp_path)

    def test_directory_with_mods_and_properties_is_server_root(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "mods").mkdir()
        (tmp_path / "server.properties").write_text("motd=test")
        assert _is_server_root(tmp_path)

    def test_plain_directory_is_not_server_root(self, tmp_path: Path) -> None:
        assert not _is_server_root(tmp_path)

    def test_directory_with_only_mods_is_not_server_root(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "mods").mkdir()
        assert not _is_server_root(tmp_path)

    def test_discover_plugin_dirs_finds_plugins_subdir(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """discover_plugin_dirs must return the plugins/ subdirectory
        of a discovered server root, not the root itself."""
        server_root = tmp_path / "my-server"
        server_root.mkdir()
        (server_root / "plugins").mkdir()
        (server_root / "server.properties").write_text("motd=test")

        # Mock discover_roots to return our test server root
        monkeypatch.setattr(
            "mcrataway.discovery.os_paths.discover_roots",
            lambda custom=None: [server_root],
        )
        plugin_dirs = discover_plugin_dirs()
        assert server_root / "plugins" in plugin_dirs


class TestPluginYmlParsing:
    """plugin.yml parsing must extract the main class and metadata."""

    def test_parse_plugin_yml_basic(self) -> None:
        """A minimal plugin.yml must parse into ModMetadata with
        loader='bukkit' and the main class set."""
        yml = yaml.dump({
            "name": "TestPlugin",
            "version": "1.0.0",
            "main": "com.example.TestPlugin",
            "api-version": "1.20",
        })
        meta = parse_plugin_yml(yml.encode())
        assert meta.loader == "bukkit"
        assert meta.main_class == "com.example.TestPlugin"
        assert meta.name == "TestPlugin"
        assert meta.version == "1.0.0"

    def test_parse_plugin_yml_with_commands(self) -> None:
        """Commands declared in plugin.yml must be extracted as
        entrypoints — a plugin with commands like 'exec' or 'shell'
        is worth recording for investigation."""
        yml = yaml.dump({
            "name": "BackdoorPlugin",
            "version": "1.0",
            "main": "com.evil.Backdoor",
            "commands": {
                "exec": {"description": "Run a command"},
                "shell": {"description": "Open a shell"},
            },
        })
        meta = parse_plugin_yml(yml.encode())
        assert "exec" in meta.entrypoints
        assert "shell" in meta.entrypoints

    def test_parse_plugin_yml_invalid_returns_bukkit_loader(self) -> None:
        """Invalid YAML must not crash — return a minimal metadata
        with loader='bukkit' so the scanner knows this is a plugin."""
        meta = parse_plugin_yml(b"not: valid: yaml: [[")
        assert meta.loader == "bukkit"

    def test_parse_archive_manifest_prefers_plugin_yml(self) -> None:
        """When plugin.yml is present alongside MANIFEST.MF, the
        plugin.yml takes precedence (it's the modloader-specific
        manifest for Bukkit plugins)."""
        entries = {
            "plugin.yml": yaml.dump({
                "name": "TestPlugin",
                "version": "1.0",
                "main": "com.example.TestPlugin",
            }).encode(),
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\nMain-Class: com.example.Main\n",
        }
        meta = parse_archive_manifest(entries)
        assert meta.loader == "bukkit"
        assert meta.main_class == "com.example.TestPlugin"


class TestPluginJarScanning:
    """A plugin JAR with plugin.yml must be scanned with correct
    loader metadata and the same detection logic as client mods."""

    def test_plugin_jar_has_bukkit_loader_metadata(self, tmp_path: Path) -> None:
        """Scanning a JAR with plugin.yml must set loader='bukkit'
        in the result metadata."""
        import zipfile

        jar = tmp_path / "test-plugin.jar"
        with zipfile.ZipFile(jar, "w") as zf:
            zf.writestr("plugin.yml", yaml.dump({
                "name": "TestPlugin",
                "version": "1.0",
                "main": "com.example.TestPlugin",
            }))
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

        loader = RulePackLoader()
        loader.load_defaults()
        qm = QuarantineManager(
            quarantine_dir=tmp_path / "q", do_quarantine_malicious=False
        )
        engine = ScanEngine(
            rules=loader.all_rules(), quarantine=qm, max_workers=1
        )
        result = engine._scan_single(jar)
        assert result.metadata.get("loader") == "bukkit"
        assert result.metadata.get("name") == "TestPlugin"
