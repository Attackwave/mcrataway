"""FileWalker's ``restrict_to_scan_subdirs`` scoping.

Auto-discovered Minecraft roots (and roots that look like a launcher
layout) are walked restricted to the known scannable folders — mods/,
config/, ..., never the launcher's browser cache or logs. That
restriction is scoped to the root being walked; anything above the root
is none of its business.
"""

from pathlib import Path

from mcrataway.discovery.walker import FileWalker


def _touch(root: Path, *rels: str) -> None:
    for rel in rels:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")


def _walk(root: Path) -> set[str]:
    walker = FileWalker(restrict_to_scan_subdirs=True)
    # as_posix(): the expectation describes the layout, not the separator.
    return {p.relative_to(root).as_posix() for p in walker.walk(root)}


def test_restriction_is_scoped_to_the_root_not_to_its_ancestors(tmp_path: Path) -> None:
    """A path component *above* the root — here ``config`` — must not
    match for every entry below it. Matching on the whole path switched
    the restriction off for the entire tree instead of scoping it, so an
    unrelated sibling folder was walked in full."""
    root = tmp_path / "config" / "instances"
    _touch(root, "pack/mods/x.jar", "pack/other/y.jar")

    assert _walk(root) == {"pack/mods/x.jar"}


def test_restriction_keeps_walking_below_a_matching_folder(tmp_path: Path) -> None:
    """Launcher layout: mods/, config/ and saves/ are walked, including
    their nested directories; an unrelated sibling is not."""
    root = tmp_path / ".minecraft"
    _touch(
        root,
        "mods/a.jar",
        "mods/sub/deep.jar",
        "config/c.yml",
        "webcache/Default/js/x.js",
    )

    assert _walk(root) == {"mods/a.jar", "mods/sub/deep.jar", "config/c.yml"}


def test_a_root_that_is_itself_a_scan_folder_is_walked_in_full(tmp_path: Path) -> None:
    """A root pointing straight at a ``mods/`` directory must stay fully
    in scope — the root's own name is a match that has to keep counting."""
    root = tmp_path / "mods"
    _touch(root, "sub/x.jar", "sub/deeper/y.jar")

    assert _walk(root) == {"sub/x.jar", "sub/deeper/y.jar"}
