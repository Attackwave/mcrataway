"""Parse mod manifest files: fabric.mod.json, mcmod.info, mods.toml,
META-INF, plugin.yml (Bukkit/Spigot/Paper)."""

import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class ModMetadata:
    """Extracted mod metadata."""

    loader: str | None = None  # "fabric", "forge", "quilt", "bukkit", "unknown"
    mod_id: str | None = None
    name: str | None = None
    version: str | None = None
    authors: list[str] = field(default_factory=list)
    entrypoints: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    mixins: list[str] = field(default_factory=list)
    main_class: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    declared_nested_jars: list[str] = field(default_factory=list)


def parse_fabric_mod_json(data: bytes) -> ModMetadata:
    """Parse a fabric.mod.json file."""
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ModMetadata(loader="fabric")

    meta = ModMetadata(loader="fabric", raw=obj)
    meta.mod_id = obj.get("id")
    meta.name = obj.get("name")
    meta.version = obj.get("version", "unknown")
    meta.authors = obj.get("authors", [])
    if isinstance(meta.authors, str):
        meta.authors = [meta.authors]

    entrypoints = obj.get("entrypoints", {})
    if isinstance(entrypoints, dict):
        for group in entrypoints.values():
            if isinstance(group, list):
                for ep in group:
                    ep_val = ep.get("value", "") if isinstance(ep, dict) else str(ep)
                    meta.entrypoints.append(ep_val)

    deps = obj.get("depends", {})
    if isinstance(deps, dict):
        meta.dependencies = list(deps.keys())

    mixins = obj.get("mixins", [])
    if isinstance(mixins, list):
        meta.mixins = [str(m) for m in mixins]

    jars = obj.get("jars", [])
    if isinstance(jars, list):
        for jar in jars:
            if isinstance(jar, dict) and "file" in jar:
                meta.declared_nested_jars.append(str(jar["file"]))
            elif isinstance(jar, str):
                meta.declared_nested_jars.append(jar)

    return meta


def parse_mcmod_info(data: bytes) -> ModMetadata:
    """Parse a Forge mcmod.info file."""
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ModMetadata(loader="forge")

    meta = ModMetadata(loader="forge", raw=obj)

    mod_list = obj.get("modList", obj.get("mods", []))
    if isinstance(mod_list, list) and mod_list:
        first = mod_list[0] if isinstance(mod_list[0], dict) else {}
        meta.mod_id = first.get("modid")
        meta.name = first.get("name")
        meta.version = first.get("version", "unknown")
        authors_raw = first.get("authorList", first.get("authors", []))
        meta.authors = authors_raw if isinstance(authors_raw, list) else []
        if isinstance(meta.authors, str):
            meta.authors = [meta.authors]

    return meta


def parse_mods_toml(data: bytes) -> ModMetadata:
    """Parse a Forge mods.toml file (basic TOML subset)."""
    meta = ModMetadata(loader="forge")
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return meta

    mod_id_match = re.search(r'modId\s*=\s*"([^"]+)"', text)
    if mod_id_match:
        meta.mod_id = mod_id_match.group(1)

    name_match = (
        re.search(r'displayName\s*=\s*"([^"]+)"', text)
        or re.search(r'^\s*name\s*=\s*"([^"]+)"', text, re.MULTILINE)
    )
    if name_match:
        meta.name = name_match.group(1)

    version_match = re.search(r'version\s*=\s*"([^"]+)"', text)
    if version_match:
        meta.version = version_match.group(1)

    return meta


_MANIFEST_KEYS = {
    "Main-Class": "main_class",
    "FMLModType": "loader",
    "Implementation-Version": "version",
    "Implementation-Title": "name",
}


def _apply_manifest_field(meta: ModMetadata, key: str, value: str) -> None:
    """Apply a single MANIFEST.MF key/value pair to *meta* in place."""
    if key == "Main-Class":
        meta.main_class = value
        meta.loader = "vanilla"
    elif key == "FMLModType":
        meta.loader = "forge"
    elif key == "Implementation-Version":
        meta.version = value
    elif key == "Implementation-Title":
        meta.name = value


def parse_manifest_mf(data: bytes) -> ModMetadata:
    """Parse a META-INF/MANIFEST.MF file.

    Supports RFC-822 style continuation lines: any line that starts with
    a single space is a continuation of the previous attribute's value
    and is appended (with the leading space stripped) to it.
    """
    meta = ModMetadata()
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return meta

    current_key: str | None = None
    current_value: str = ""

    for line in text.splitlines():
        if line.startswith(" "):
            # Continuation of the previous attribute value
            if current_key is not None:
                current_value += line[1:]
                _apply_manifest_field(meta, current_key, current_value)
            continue
        if ":" not in line:
            current_key = None
            current_value = ""
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        current_key = key
        current_value = value
        _apply_manifest_field(meta, key, value)

    return meta


def parse_jarjar_metadata(data: bytes) -> list[str]:
    """Parse a Forge JarJar ``META-INF/jarjar/metadata.json`` file.

    Returns the list of declared nested-jar paths. JarJar's format
    stores them under ``jars[].identifier.path`` (or a plain
    ``jars[].path`` in older variants). An empty list on parse failure
    is the safe default — an undeclared nested jar is suspicious, so
    failing to parse the manifest must not silently mark everything as
    "declared".
    """
    try:
        obj = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    jars = obj.get("jars", [])
    if not isinstance(jars, list):
        return []

    paths: list[str] = []
    for jar in jars:
        if not isinstance(jar, dict):
            continue
        identifier = jar.get("identifier", {})
        if isinstance(identifier, dict):
            path = identifier.get("path")
            if isinstance(path, str):
                paths.append(path)
        path = jar.get("path")
        if isinstance(path, str):
            paths.append(path)
    return paths


def parse_plugin_yml(data: bytes) -> ModMetadata:
    """Parse a Bukkit/Spigot/Paper ``plugin.yml`` file.

    Server-side plugins declare their main class, API version,
    commands, and permissions in this file. The ``main`` field is
    the entry point class — a plugin that declares a ``main`` class
    in a package like ``com.evil.backdoor`` with broad permissions
    is a signal worth recording.
    """
    meta = ModMetadata(loader="bukkit")
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return meta

    # Basic YAML subset parsing (plugin.yml is simple enough that a
    # full YAML parser isn't needed — and yaml.safe_load would work
    # too, but this keeps the manifest parser dependency-free for
    # this path).
    try:
        obj = yaml.safe_load(text)
    except Exception:
        return meta

    if not isinstance(obj, dict):
        return meta

    meta.raw = obj
    meta.main_class = str(obj.get("main", ""))
    meta.name = str(obj.get("name", ""))
    meta.version = str(obj.get("version", "unknown"))

    authors = obj.get("authors", [])
    if isinstance(authors, list):
        meta.authors = [str(a) for a in authors]
    elif isinstance(authors, str):
        meta.authors = [authors]

    commands = obj.get("commands", {})
    if isinstance(commands, dict):
        meta.entrypoints = list(commands.keys())

    return meta


def parse_archive_manifest(entries: dict[str, bytes]) -> ModMetadata:
    """Detect and parse the mod manifest from archive entries.

    Also extracts declared nested-jar paths from Forge JarJar's
    ``META-INF/jarjar/metadata.json`` when present, merging them into
    the returned metadata regardless of which loader the mod uses —
    a Fabric mod can still bundle JarJar-format nested jars.
    """
    if "fabric.mod.json" in entries:
        meta: ModMetadata = parse_fabric_mod_json(entries["fabric.mod.json"])
    elif "mcmod.info" in entries:
        meta = parse_mcmod_info(entries["mcmod.info"])
    elif "plugin.yml" in entries:
        meta = parse_plugin_yml(entries["plugin.yml"])
    elif "META-INF/MANIFEST.MF" in entries:
        meta = parse_manifest_mf(entries["META-INF/MANIFEST.MF"])
    else:
        meta = ModMetadata()
        for key in entries:
            if key.endswith("mods.toml"):
                meta = parse_mods_toml(entries[key])
                break

    jarjar_key = "META-INF/jarjar/metadata.json"
    if jarjar_key in entries:
        meta.declared_nested_jars.extend(parse_jarjar_metadata(entries[jarjar_key]))

    return meta