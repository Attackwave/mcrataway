"""Cross-platform Minecraft installation root discovery."""

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


def discover_roots(custom: list[str] | None = None) -> list[Path]:
    """Auto-discover all known Minecraft installation roots."""
    roots: set[Path] = set()

    if custom:
        for c in custom:
            p = _resolve_env(c)
            if p:
                roots.add(p)

    roots.update(_discover_linux())
    roots.update(_discover_windows())
    roots.update(_discover_macos())

    return sorted(roots, key=str)


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
