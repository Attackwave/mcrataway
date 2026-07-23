"""Parse mod manifest files: fabric.mod.json, mcmod.info, mods.toml, META-INF."""

import json
import re
from dataclasses import dataclass, field
from typing import Any


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


def parse_archive_manifest(entries: dict[str, bytes]) -> ModMetadata:
    """Detect and parse the mod manifest from archive entries."""
    if "fabric.mod.json" in entries:
        return parse_fabric_mod_json(entries["fabric.mod.json"])

    if "mcmod.info" in entries:
        return parse_mcmod_info(entries["mcmod.info"])

    for key in entries:
        if key.endswith("mods.toml"):
            return parse_mods_toml(entries[key])

    if "META-INF/MANIFEST.MF" in entries:
        return parse_manifest_mf(entries["META-INF/MANIFEST.MF"])

    return ModMetadata()
