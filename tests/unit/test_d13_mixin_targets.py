"""Tests for D13 Mixin/Coremod detector — target allowlist and
@Redirect/@Overwrite escalation.

A Mixin can rewrite bytecode in the game itself at load time — a
malicious Mixin targeting the session-token accessor never needs to
call any API D01–D11 watch for; it just edits the method that already
has the token. These tests verify the detector:

  - Flags @Redirect/@Overwrite on auth-sensitive targets as CRITICAL.
  - Flags @Mixin into auth-sensitive targets (without @Redirect) as HIGH.
  - Rates network-packet targets (PacketEncoder/Decoder) as MEDIUM.
  - Does NOT flag rendering mods that happen to reference auth classes
    as method parameters (not @Mixin targets).
  - Does NOT flag benign "MinecraftClientMixin" classes (too broad).
"""

import json
import struct

from mcrataway.constants import Severity
from mcrataway.detectors.d13_mixin_coremod import D13MixinCoremod
from mcrataway.parsers.classfile import parse_class


def _make_mixin_class(class_name: str, extra_cp_strings: list[str]) -> bytes:
    """Build a minimal .class file with proper Class_info entries so
    ``this_class`` resolves correctly.

    Constant-pool layout (1-indexed):
      1 -> Utf8: class_name
      2 -> Class: points at CP#1 (this_class)
      3 -> Utf8: "java/lang/Object"
      4 -> Class: points at CP#3 (super_class)
      5 -> Utf8: "mixinMethod"
      6 -> Utf8: "()V"
      7 -> Utf8: "Code"
      8+ -> Utf8: extra_cp_strings
    """
    all_utf8 = [class_name, "java/lang/Object", "mixinMethod", "()V", "Code"] + extra_cp_strings
    # Build the constant pool: Utf8 entries interleaved with Class entries
    pool_parts: list[bytes] = []
    pool_parts.append(struct.pack(">H", 1 + len(all_utf8) + 2))  # +2 for Class entries

    # CP#1: Utf8 class_name
    encoded = class_name.encode("utf-8")
    pool_parts.append(struct.pack(">BH", 1, len(encoded)) + encoded)
    # CP#2: Class -> CP#1
    pool_parts.append(struct.pack(">BH", 7, 1))
    # CP#3: Utf8 java/lang/Object
    encoded = b"java/lang/Object"
    pool_parts.append(struct.pack(">BH", 1, len(encoded)) + encoded)
    # CP#4: Class -> CP#3
    pool_parts.append(struct.pack(">BH", 7, 3))
    # CP#5+: Utf8 entries for the rest
    for s in all_utf8[2:]:  # skip class_name and Object (already added)
        encoded = s.encode("utf-8")
        pool_parts.append(struct.pack(">BH", 1, len(encoded)) + encoded)

    pool = b"".join(pool_parts)

    # Code attribute: max_stack=1, max_locals=1, code_length=1, return
    code_attr = struct.pack(">HHI", 1, 1, 1) + b"\xb1"
    code_attr += struct.pack(">HH", 0, 0)

    # Method: access=public, name_idx=7 (mixinMethod), desc_idx=8 (()V)
    method = struct.pack(">HHH", 0x0001, 7, 8)
    method += struct.pack(">H", 1)  # attributes_count
    method += struct.pack(">HI", 9, len(code_attr))  # Code attr name_idx=9
    method += code_attr

    # Class body: access, this_class=2, super_class=4, interfaces=0, fields=0, methods=1, attrs=0
    body = struct.pack(">HHHHHH", 0x0001, 2, 4, 0, 0, 1)
    body += method
    body += struct.pack(">H", 0)

    return b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 52) + pool + body


class TestD13MixinTargetAllowlist:
    """The target allowlist must be narrow enough to not flag benign
    mods, but broad enough to catch auth-targeting mixins."""

    def test_redirect_on_auth_target_is_critical(self):
        """@Redirect on an auth-sensitive target (Session) must be
        CRITICAL — this is the exact pattern a malicious Mixin uses
        to replace the behavior of a method that holds credentials."""
        data = _make_mixin_class(
            "com/evil/MixinSession",
            [
                "Lorg/spongepowered/asm/mixin/Mixin;",
                "Lorg/spongepowered/asm/mixin/injection/Redirect;",
                "Lnet/minecraft/client/util/Session;",
            ],
        )
        parsed = parse_class(data)
        assert parsed is not None
        evs = D13MixinCoremod().analyze_class(parsed)
        crits = [e for e in evs if e.severity == Severity.CRITICAL]
        assert len(crits) == 1
        assert "Session" in crits[0].matched_value
        assert crits[0].context.get("annotation") == "redirect_or_overwrite"

    def test_mixin_into_auth_target_without_redirect_is_high(self):
        """@Mixin into Session without @Redirect/@Overwrite is HIGH
        (the mixin can @Inject and intercept the credential)."""
        data = _make_mixin_class(
            "com/evil/MixinSession",
            [
                "Lorg/spongepowered/asm/mixin/Mixin;",
                "Lnet/minecraft/client/util/Session;",
            ],
        )
        parsed = parse_class(data)
        assert parsed is not None
        evs = D13MixinCoremod().analyze_class(parsed)
        highs = [e for e in evs if e.severity == Severity.HIGH]
        assert len(highs) == 1
        assert "Session" in highs[0].matched_value

    def test_mixin_into_packet_encoder_is_medium(self):
        """PacketEncoder/Decoder targets are MEDIUM — many legitimate
        networking mods (Fabric API, malilib) target these."""
        data = _make_mixin_class(
            "com/example/MixinPacketEncoder",
            [
                "Lorg/spongepowered/asm/mixin/Mixin;",
                "Lnet/minecraft/network/PacketEncoder;",
            ],
        )
        parsed = parse_class(data)
        assert parsed is not None
        evs = D13MixinCoremod().analyze_class(parsed)
        meds = [e for e in evs if e.severity == Severity.MEDIUM]
        assert len(meds) == 1
        assert "PacketEncoder" in meds[0].matched_value

    def test_rendering_mod_with_session_param_not_flagged(self):
        """A rendering mod whose @Inject method receives Session as a
        parameter (not as the @Mixin target) must NOT be flagged —
        the Session reference is in the method descriptor, not in the
        @Mixin annotation's value. Without @Redirect/@Overwrite, the
        class name must also suggest the target."""
        data = _make_mixin_class(
            "com/example/MixinLoadingOverlay",
            [
                "Lorg/spongepowered/asm/mixin/Mixin;",
                "Lnet/minecraft/class_332;",  # Yggdrasil, as a param type
                "(Lnet/minecraft/class_332;IIFLCallbackInfo;)V",
            ],
        )
        parsed = parse_class(data)
        assert parsed is not None
        evs = D13MixinCoremod().analyze_class(parsed)
        # No @Redirect/@Overwrite, and class name is "LoadingOverlay"
        # not "Session" or "Yggdrasil" → no match.
        assert all(e.severity != Severity.HIGH for e in evs)
        assert all(e.severity != Severity.CRITICAL for e in evs)

    def test_intermediary_word_boundary_matching(self):
        """class_321 (Session) must NOT match class_3218 (ServerWorld)
        — the word boundary after the number prevents this false
        positive."""
        data = _make_mixin_class(
            "com/example/MixinServerWorld",
            [
                "Lorg/spongepowered/asm/mixin/Mixin;",
                "Lnet/minecraft/class_3218;",  # ServerWorld, NOT Session
            ],
        )
        parsed = parse_class(data)
        assert parsed is not None
        evs = D13MixinCoremod().analyze_class(parsed)
        assert all(e.severity != Severity.HIGH for e in evs)
        assert all(e.severity != Severity.CRITICAL for e in evs)


class TestD13MixinConfig:
    """*.mixins.json config analysis."""

    def test_mixin_config_targeting_session_flagged(self):
        det = D13MixinCoremod()
        config = json.dumps({
            "package": "com.evil.mixins",
            "mixins": ["MixinSession"],
        }).encode()
        evs = det.analyze_archive_entry("evil.mixins.json", config)
        assert len(evs) == 1
        assert evs[0].severity == Severity.MEDIUM
        assert "Session" in evs[0].description

    def test_mixin_config_targeting_minecraftclient_not_flagged(self):
        """MinecraftClient is too broad a target — every rendering/input
        mod has a MinecraftClientMixin. It must not be flagged."""
        det = D13MixinCoremod()
        config = json.dumps({
            "package": "com.benign.mixins",
            "mixins": ["MinecraftClientMixin"],
        }).encode()
        evs = det.analyze_archive_entry("benign.mixins.json", config)
        assert all(e.detector_id != "d13" for e in evs)

    def test_mixin_config_targeting_packet_encoder_flagged_medium(self):
        det = D13MixinCoremod()
        config = json.dumps({
            "package": "com.example.mixins",
            "mixins": ["MixinPacketEncoder"],
        }).encode()
        evs = det.analyze_archive_entry("net.mixins.json", config)
        assert len(evs) == 1
        assert evs[0].severity == Severity.MEDIUM


class TestD13CoremodManifest:
    """FMLCorePlugin manifest analysis."""

    def test_coremod_declared_flagged(self):
        det = D13MixinCoremod()
        manifest = b"Manifest-Version: 1.0\nFMLCorePlugin: com.evil.CoreMod\n"
        evs = det.analyze_archive_entry("META-INF/MANIFEST.MF", manifest)
        assert len(evs) == 1
        assert evs[0].severity == Severity.MEDIUM
        assert "FMLCorePlugin" in evs[0].description

    def test_no_coremod_not_flagged(self):
        det = D13MixinCoremod()
        manifest = b"Manifest-Version: 1.0\nMain-Class: com.example.Main\n"
        evs = det.analyze_archive_entry("META-INF/MANIFEST.MF", manifest)
        assert all(e.detector_id != "d13" for e in evs)
