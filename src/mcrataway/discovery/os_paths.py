"""Cross-platform Minecraft installation root discovery.

Discovers both client-side installations (vanilla .minecraft, Prism,
MultiMC, ATLauncher, CurseForge, Modrinth App) and server-side
installations (Bukkit/Spigot/Paper server directories containing a
``plugins/`` folder). Server plugins are a large real threat surface
— backdoored plugins with ``Runtime.exec``, RCON abuse, and config
exfiltration are common — and the detection logic (D01–D14) runs on
any JAR, so discovering ``plugins/`` directories is all that's needed
to extend coverage to server-side malware.
"""

import os
from pathlib import Path


def _expand(p: str) -> Path | None:
    """Expand a path string and return the Path if it exists."""
    expanded = Path(p).expanduser()
    return expanded if expanded.exists() else None


def _resolve_env(p: str) -> Path | None:
    """Expand env vars, home, and check existence."""
    resolved = os.path.expandvars(p)
    return _expand(resolved)


def _is_server_root(path: Path) -> bool:
    """Heuristic: a directory that looks like a Minecraft server
    installation. Checks for ``plugins/`` (Bukkit/Spigot/Paper) or
    ``mods/`` (Forge/Fabric server) alongside a server JAR or
    ``server.properties`` — enough to distinguish a server install
    from a random directory that happens to contain a ``plugins``
    subfolder."""
    if (path / "plugins").is_dir():
        return True
    return (path / "mods").is_dir() and (path / "server.properties").exists()


def discover_roots(custom: list[str] | None = None) -> list[Path]:
    """Auto-discover all known Minecraft installation roots.

    Includes both client-side (vanilla, launchers) and server-side
    (Bukkit/Spigot/Paper) installations.
    """
    roots: set[Path] = set()

    if custom:
        for c in custom:
            p = _resolve_env(c)
            if p:
                roots.add(p)

    roots.update(_discover_linux())
    roots.update(_discover_windows())
    roots.update(_discover_macos())
    roots.update(_discover_server_roots())

    return sorted(roots, key=str)


def discover_plugin_dirs(custom: list[str] | None = None) -> list[Path]:
    """Auto-discover Bukkit/Spigot/Paper plugin directories.

    Returns the ``plugins/`` directories of discovered server
    installations, not the server roots themselves — the scanner
    walks these directories for ``.jar`` files (plugins).
    """
    plugin_dirs: list[Path] = []
    for root in discover_roots(custom):
        plugins = root / "plugins"
        if plugins.is_dir():
            plugin_dirs.append(plugins)
    return plugin_dirs


def _discover_server_roots() -> list[Path]:
    """Discover Bukkit/Spigot/Paper server installations.

    Server admins typically run servers from a dedicated directory
    (often under ``~/server``, ``~/minecraft-server``, ``/opt``,
    or a Docker volume). The discovery checks common locations and
    also scans the home directory one level deep for directories
    that look like server roots (contain ``plugins/`` or
    ``server.properties``).
    """
    results: list[Path] = []
    home = Path.home()

    # Common explicit server paths
    for p in [
        home / "server",
        home / "minecraft-server",
        home / "mc-server",
        home / "paper-server",
        home / "spigot-server",
        Path("/opt/minecraft-server"),
        Path("/opt/server"),
    ]:
        if p.exists() and _is_server_root(p):
            results.append(p)

    # Scan home directory one level deep for server-like directories.
    # Bounded to avoid traversing large home trees — only top-level
    # subdirectories are checked.
    try:
        for child in home.iterdir():
            if child.is_dir() and _is_server_root(child):
                results.append(child)
    except (PermissionError, OSError):
        pass

    return results


def _discover_linux() -> list[Path]:
    results: list[Path] = []
    home = Path.home()

    vanilla = home / ".minecraft"
    if vanilla.exists():
        results.append(vanilla)

    base_local = home / ".local" / "share"
    for launcher_path in [
        base_local / "PrismLauncher" / "instances",
        base_local / "MultiMC" / "instances",
        base_local / "ATLauncher" / "Packs",
        home / ".local" / "modrinth-app",
    ]:
        if launcher_path.exists():
            results.append(launcher_path)

    curse = home / ".config" / "curseforge"
    if curse.exists():
        results.append(curse)

    for flatpak_var in [
        home / ".var" / "app" / "com.mojang.Minecraft" / ".minecraft",
        home / ".var" / "app" / "org.prismlauncher.PrismLauncher" / "PrismLauncher" / "instances",
    ]:
        if flatpak_var.exists():
            results.append(flatpak_var)

    return results


def _discover_windows() -> list[Path]:
    results: list[Path] = []
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    userprofile = os.environ.get("USERPROFILE", "")

    for p in [
        f"{appdata}/.minecraft",
        f"{localappdata}/PrismLauncher/instances",
        f"{localappdata}/MultiMC/instances",
        f"{localappdata}/ATLauncher/Packs",
        f"{userprofile}/.minecraft",
    ]:
        found = _resolve_env(p)
        if found:
            results.append(found)

    if localappdata:
        curse_base = Path(localappdata) / "CurseForge"
        if curse_base.exists():
            try:
                for child in curse_base.iterdir():
                    if (child / "Instances").exists():
                        results.append(child / "Instances")
            except (PermissionError, OSError):
                pass

    return results


def _discover_macos() -> list[Path]:
    results: list[Path] = []
    home = Path.home()
    app_support = home / "Library" / "Application Support"

    for p in [
        app_support / "minecraft",
        app_support / "PrismLauncher" / "instances",
        app_support / "MultiMC" / "instances",
        app_support / "ATLauncher" / "Packs",
    ]:
        if p.exists():
            results.append(p)

    return results
