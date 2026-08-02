"""Unit tests for individual detectors."""

import struct

from mcrataway.detectors.d03_dynamic_loading import D03DynamicLoading
from mcrataway.detectors.d04_filesystem_jar_mod import D04FilesystemJarMod
from mcrataway.detectors.d05_persistence import D05Persistence
from mcrataway.detectors.d06_deserialization import D06Deserialization
from mcrataway.detectors.d07_native_jni import D07NativeJni
from mcrataway.detectors.d09_obfuscation import D09Obfuscation
from mcrataway.detectors.d10_reflection_indirect import D10ReflectionIndirect
from mcrataway.detectors.d12_resourcepack_exploit import D12ResourcepackExploit
from mcrataway.parsers.classfile import parse_class


def _build_class(cp_strings: list[str]) -> bytes:
    """Build a minimal .class file with given constant pool strings."""
    all_strings = ["com/test/A", "java/lang/Object", "m", "()V", "Code"] + cp_strings
    pool = struct.pack(">H", len(all_strings) + 1)
    for s in all_strings:
        encoded = s.encode("utf-8")
        pool += struct.pack(">BH", 1, len(encoded)) + encoded

    bc = struct.pack(">B", 177)
    code_info = struct.pack(">HHI", 2, 2, len(bc)) + bc + struct.pack(">HH", 0, 0)
    code_attr = struct.pack(">HI", 5, len(code_info)) + code_info
    method = struct.pack(">HHH", 0x0001, 3, 4) + struct.pack(">H", 1) + code_attr
    body = struct.pack(">HHH", 0x0001, 1, 2)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 1) + method
    body += struct.pack(">H", 0)
    return b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 52) + pool + body


def test_d03_no_false_positive():
    data = _build_class(["safe_string"])
    parsed = parse_class(data)
    assert parsed is not None
    assert len(D03DynamicLoading().analyze_class(parsed)) == 0


def test_d04_no_false_positive():
    data = _build_class(["safe_string"])
    parsed = parse_class(data)
    assert parsed is not None
    assert len(D04FilesystemJarMod().analyze_class(parsed)) == 0


def test_d04_detects_credential_path():
    data = _build_class([".minecraft/launcher_accounts.json"])
    parsed = parse_class(data)
    assert parsed is not None
    evs = D04FilesystemJarMod().analyze_class(parsed)
    assert len(evs) > 0


def test_d05_detects_persistence():
    data = _build_class(["SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"])
    parsed = parse_class(data)
    assert parsed is not None
    evs = D05Persistence().analyze_class(parsed)
    assert len(evs) > 0


def test_d05_detects_schtasks():
    data = _build_class(["schtasks /create"])
    parsed = parse_class(data)
    assert parsed is not None
    evs = D05Persistence().analyze_class(parsed)
    assert len(evs) > 0


def test_d06_no_false_positive():
    data = _build_class(["safe_string"])
    parsed = parse_class(data)
    assert parsed is not None
    assert len(D06Deserialization().analyze_class(parsed)) == 0


def test_d07_no_false_positive():
    data = _build_class(["safe_string"])
    parsed = parse_class(data)
    assert parsed is not None
    assert len(D07NativeJni().analyze_class(parsed)) == 0


def test_d09_detects_obfuscated_name():
    data = _build_class([])
    # Manually modify the class name to be obfuscated
    parsed = parse_class(data)
    assert parsed is not None
    parsed.this_class = "a/b/c/d/e/f"
    evs = D09Obfuscation().analyze_class(parsed)
    assert len(evs) > 0


def test_d09_no_false_positive_normal_name():
    data = _build_class([])
    parsed = parse_class(data)
    assert parsed is not None
    evs = D09Obfuscation().analyze_class(parsed)
    assert len(evs) == 0


def test_d10_no_false_positive():
    data = _build_class(["safe_string"])
    parsed = parse_class(data)
    assert parsed is not None
    assert len(D10ReflectionIndirect().analyze_class(parsed)) == 0


def test_d12_archive_entry_png():
    det = D12ResourcepackExploit()
    # Large PNG should trigger
    evs = det.analyze_archive_entry("texture.png", b"\x89PNG" + b"\x00" * 2000000)
    assert len(evs) > 0


def test_d12_archive_entry_small_png():
    det = D12ResourcepackExploit()
    evs = det.analyze_archive_entry("texture.png", b"\x89PNG" + b"\x00" * 100)
    assert len(evs) == 0


def test_d12_archive_entry_mcmeta_with_eval():
    det = D12ResourcepackExploit()
    import json
    data = json.dumps({"pack": {"pack_format": 1, "description": "eval(malicious)"}}).encode()
    evs = det.analyze_archive_entry("pack.json", data)
    assert len(evs) > 0


def test_d13_mixin_targeting_session_flagged():
    """A mixin config whose declared mixin class name suggests it
    targets auth-sensitive classes (Session, YggdrasilAuthentication)
    must be flagged — this is the largest blind spot the other
    detectors have, since a Mixin can rewrite the method that already
    holds a session token without ever calling any of the APIs
    D01-D11 look for.

    Note: "MinecraftClient" was removed from the sensitive-target list
    because virtually every rendering/input mod has a "MinecraftClientMixin"
    that targets it for non-auth purposes (camera, input, tick hooks).
    Only auth-specific classes (Session, Yggdrasil, packet encoder/decoder)
    are flagged now.
    """
    import json

    from mcrataway.detectors.d13_mixin_coremod import D13MixinCoremod

    det = D13MixinCoremod()
    config = json.dumps({
        "package": "com.evil.mixins",
        "mixins": ["MixinSession", "MixinYggdrasilAuthenticationService"],
    }).encode()
    evs = det.analyze_archive_entry("evil.mixins.json", config)
    assert len(evs) == 2
    assert all(e.severity.name == "MEDIUM" for e in evs)
    assert any("Session" in e.description for e in evs)
    assert any("YggdrasilAuthentication" in e.description for e in evs)


def test_d13_mixin_targeting_benign_class_not_flagged():
    import json

    from mcrataway.detectors.d13_mixin_coremod import D13MixinCoremod

    det = D13MixinCoremod()
    config = json.dumps({
        "package": "com.example.mixins",
        "mixins": ["MixinBlockRenderer", "MixinParticleEffect"],
    }).encode()
    evs = det.analyze_archive_entry("example.mixins.json", config)
    assert len(evs) == 0


def test_d13_malformed_mixin_json_does_not_crash():
    from mcrataway.detectors.d13_mixin_coremod import D13MixinCoremod

    det = D13MixinCoremod()
    assert det.analyze_archive_entry("broken.mixins.json", b"{not valid json") == []


def test_d13_coremod_manifest_declaration_flagged():
    """FMLCorePlugin in the manifest registers a ClassLoader transformer
    with bytecode-rewrite access before any other mod code runs — none
    of the bytecode-level detectors analyze this capability."""
    from mcrataway.detectors.d13_mixin_coremod import D13MixinCoremod

    det = D13MixinCoremod()
    manifest = b"Manifest-Version: 1.0\nFMLCorePlugin: com.evil.CorePlugin\n"
    evs = det.analyze_archive_entry("META-INF/MANIFEST.MF", manifest)
    assert len(evs) == 1
    assert evs[0].severity.name == "MEDIUM"


def test_d13_ordinary_manifest_not_flagged():
    from mcrataway.detectors.d13_mixin_coremod import D13MixinCoremod

    det = D13MixinCoremod()
    manifest = b"Manifest-Version: 1.0\nMain-Class: com.example.Mod\n"
    evs = det.analyze_archive_entry("META-INF/MANIFEST.MF", manifest)
    assert len(evs) == 0
