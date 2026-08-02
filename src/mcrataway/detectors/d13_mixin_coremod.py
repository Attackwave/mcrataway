"""D13 — Mixin/coremod abuse detector.

Catches:
- Fabric/Forge Mixin configs (*.mixins.json) targeting security-sensitive
  classes (session/auth/network handling) — this is the largest blind
  spot in the other detectors, since Mixins let a mod rewrite bytecode
  in the game itself (or another mod) at load time, so a malicious
  Mixin targeting e.g. the session-token accessor never needs to call
  any of the APIs D01-D11 look for. It just edits the method that
  already has the token.
- @Redirect and @Overwrite annotations on auth-sensitive targets —
  these fully replace or reroute behavior at the injection point, as
  opposed to @Inject (which runs alongside the original method).
- FMLCorePlugin / coremod declarations in META-INF/MANIFEST.MF, which
  is Forge's older (pre-Mixin) equivalent capability.

This detector operates on archive entries (mixin JSON configs, the
manifest) and on individual parsed classes (for @Mixin/@Redirect
annotation analysis), since the "target" a Mixin edits is declared
both in JSON config and in the class's @Mixin annotation.
"""

import json
import re

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile

# Auth-sensitive target class fragments — narrowed from the previous
# broad list (which included "MinecraftClient" and "Session" and thus
# matched every rendering/input mod). Only classes that hold or access
# credentials, auth tokens, or the auth handshake belong here: a mixin
# into MinecraftClient for camera/rendering is normal; a mixin into
# YggdrasilAuthenticationService or the Session token accessor is not.
#
# Both Mojang obfuscated (class_NNN / method_NNN, "intermediary" naming
# used by Fabric before remapping) and Yarn-remapped names are listed,
# since a shipped mod jar may reference either depending on the mapping
# it was built against.
_SENSITIVE_AUTH_TARGETS = (
    # Yarn names
    "YggdrasilAuthenticationService",
    "YggdrasilUserApiService",
    "MinecraftSession",
    "net/minecraft/client/util/Session",
    "net/minecraft/util/Session",
    # Intermediary names — verified against Yarn's intermediary mapping:
    #   class_320 = MinecraftClient (NOT here — too broad, every rendering mod targets it)
    #   class_321 = Session (the actual session/token holder)
    #   class_332 = YggdrasilAuthenticationService
    #   class_45 = YggdrasilUserApiService
    # class_3218 (ServerWorld), class_4587/4588/4597 (screens) are NOT
    # auth-sensitive and were incorrectly listed before.
    "class_321",  # Session (intermediary)
    "class_332",  # YggdrasilAuthenticationService (intermediary)
    "class_45",  # YggdrasilUserApiService (intermediary)
)

# For mixin *config* class-name matching (JSON configs, where the mixin
# class is named after its target, e.g. "MixinSession"), these bare
# fragments are safe to match — a class literally named "MixinSession"
# or "MixinYggdrasil" is not ambiguous the way "session" as a substring
# in arbitrary code is. This is separate from _ALL_SENSITIVE_TARGETS
# (used for constant-pool type-descriptor matching) to avoid the broad
# substring false positives that the previous version suffered from.
_SENSITIVE_CONFIG_NAME_FRAGMENTS = (
    "Session",
    "YggdrasilAuthenticationService",
    "YggdrasilUserApiService",
    "PacketEncoder",
    "PacketDecoder",
)

# Network-packet handling targets — a mixin here *can* intercept/modify
# outbound packets (e.g. session tokens sent to servers), but many
# legitimate networking optimization mods (malilib, noxesium, Fabric
# API itself) mixin into PacketEncoder/PacketDecoder for non-malicious
# reasons (packet compression, batching, custom payload registration).
# These are rated MEDIUM (not HIGH) — suspicious enough to record, but
# not enough to drive MALICIOUS on their own.
_SENSITIVE_NETWORK_TARGETS = (
    "PacketEncoder",
    "PacketDecoder",
    "class_2538",  # PacketEncoder (intermediary)
    "class_2540",  # PacketDecoder (intermediary)
)

_ALL_SENSITIVE_TARGETS = _SENSITIVE_AUTH_TARGETS + _SENSITIVE_NETWORK_TARGETS

# Intermediary class IDs that need word-boundary matching —
# "class_45" must not match "class_4587", and "class_321" must not
# match "class_3218". Built dynamically from _SENSITIVE_AUTH_TARGETS.
_INTERMEDIARY_IDS = tuple(
    frag for frag in _SENSITIVE_AUTH_TARGETS if frag.startswith("class_")
)


def _matches_sensitive_target(class_path: str) -> str | None:
    """Check whether a class path references an auth- or network-
    sensitive target. Returns the matched fragment, or None."""
    matched = _matches_auth_target(class_path)
    if matched:
        return matched
    for frag in _SENSITIVE_NETWORK_TARGETS:
        if frag in class_path:
            return frag
    return None


def _matches_auth_target(class_path: str) -> str | None:
    """Check whether a class path references an auth-sensitive target
    (Session, Yggdrasil). Uses word-boundary matching for intermediary
    IDs to avoid class_321 matching class_3218."""
    for frag in _SENSITIVE_AUTH_TARGETS:
        if frag in _INTERMEDIARY_IDS:
            idx = class_path.find(frag)
            if idx < 0:
                continue
            after = idx + len(frag)
            if after < len(class_path) and class_path[after].isdigit():
                continue
            return frag
        else:
            if frag in class_path:
                return frag
    return None


def _matches_network_target(class_path: str) -> str | None:
    """Check whether a class path references a network-packet target
    (PacketEncoder/Decoder)."""
    for frag in _SENSITIVE_NETWORK_TARGETS:
        if frag in class_path:
            return frag
    return None

# Mixin annotation type descriptors (as they appear in the constant
# pool of a compiled mixin class).
_MIXIN_ANNOTATION = "org/spongepowered/asm/mixin/Mixin;"
_REDIRECT_ANNOTATION = "org/spongepowered/asm/mixin/injection/Redirect;"
_OVERWRITE_ANNOTATION = "org/spongepowered/asm/mixin/Overwrite;"
_HIGH_IMPACT_ANNOTATIONS = (_REDIRECT_ANNOTATION, _OVERWRITE_ANNOTATION)

# Regex to extract a class reference from a JVM type descriptor like
# "Lnet/minecraft/client/util/Session;" — captures the inner path.
_TYPE_DESC_RE = re.compile(r"L([\w/$]+);")


class D13MixinCoremod(Detector):
    @property
    def detector_id(self) -> str:
        return "d13"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        """Analyze a mixin class for high-impact annotations on
        auth-sensitive targets.

        A @Mixin annotation's ``value`` element holds the target class
        as a type descriptor (e.g. ``Lnet/minecraft/client/util/Session;``).
        When @Redirect or @Overwrite is also present in the same class
        and the target is auth-sensitive (Session, Yggdrasil, packet
        encoder/decoder), this is CRITICAL — the mixin is replacing
        the behavior of a method that holds or processes credentials,
        without ever calling any API D01–D11 watch for.

        Without @Redirect/@Overwrite, a type-descriptor match on its
        own is ambiguous: the sensitive class might appear as a method
        *parameter* (the mixin injects into a method that receives a
        Session object) rather than as the @Mixin *target* (the class
        being rewritten). In that case, require the mixin class name
        itself to suggest the target (e.g. ``MixinSession``) to avoid
        false positives from rendering mods whose methods happen to
        receive auth objects as parameters.
        """
        evidence: list[Evidence] = []
        cp = class_file.constant_pool
        strings = cp.all_strings()

        has_mixin = any(_MIXIN_ANNOTATION in s for s in strings)
        if not has_mixin:
            return evidence

        has_high_impact = any(
            ann in s for s in strings for ann in _HIGH_IMPACT_ANNOTATIONS
        )

        # Extract auth-sensitive type-descriptor references from the
        # constant pool. With @Redirect/@Overwrite, any such reference
        # is a strong signal (the annotation means behavior replacement
        # is happening on something). Without it, the reference might
        # just be a method parameter type, so we also check the mixin
        # class's own name.
        auth_targets: list[str] = []
        network_targets: list[str] = []
        for s in strings:
            for match in _TYPE_DESC_RE.finditer(s):
                class_path = match.group(1)
                if _matches_auth_target(class_path):
                    auth_targets.append(class_path)
                elif _matches_network_target(class_path):
                    network_targets.append(class_path)

        # For non-high-impact mixins, require the class name to also
        # suggest the target (e.g. "MixinSession"). This filters out
        # rendering mods whose @Inject methods receive Session as a
        # parameter but don't target Session itself.
        class_name_lower = class_file.this_class.lower()
        if not has_high_impact:
            auth_targets = [
                t for t in auth_targets
                if any(frag.lower() in class_name_lower
                       for frag in _SENSITIVE_CONFIG_NAME_FRAGMENTS)
            ]

        if not auth_targets and not network_targets and not has_high_impact:
            return evidence

        # Deduplicate
        unique_auth = sorted(set(auth_targets))
        unique_network = sorted(set(network_targets))

        for target in unique_auth:
            if has_high_impact:
                evidence.append(
                    self._add_evidence(
                        class_file, "", 0,
                        (
                            f"Mixin @Redirect/@Overwrite on auth-sensitive "
                            f"target: {target} — this can replace the behavior "
                            f"of a method that holds or processes credentials "
                            f"without calling any API other detectors watch for"
                        ),
                        Severity.CRITICAL,
                        matched_value=target,
                        context={
                            "mixin_target": target,
                            "annotation": "redirect_or_overwrite",
                        },
                    )
                )
            else:
                evidence.append(
                    self._add_evidence(
                        class_file, "", 0,
                        (
                            f"Mixin targets auth-sensitive class: {target} — "
                            f"a mixin into session/auth code can intercept "
                            f"credentials even without @Redirect/@Overwrite"
                        ),
                        Severity.HIGH,
                        matched_value=target,
                        context={"mixin_target": target},
                    )
                )

        for target in unique_network:
            evidence.append(
                self._add_evidence(
                    class_file, "", 0,
                    (
                        f"Mixin targets network-packet class: {target} — "
                        f"can intercept/modify outbound packets, but many "
                        f"legitimate networking mods also target these"
                    ),
                    Severity.MEDIUM,
                    matched_value=target,
                    context={"mixin_target": target},
                )
            )

        return evidence

    def analyze_archive_entry(self, entry_name: str, entry_data: bytes) -> list[Evidence]:
        """Parse *.mixins.json configs and flag ones targeting
        security-sensitive classes."""
        evidence: list[Evidence] = []

        if entry_name.endswith(".mixins.json"):
            evidence.extend(self._analyze_mixin_config(entry_name, entry_data))
        elif entry_name in ("META-INF/MANIFEST.MF", "MANIFEST.MF"):
            evidence.extend(self._analyze_manifest_coremod(entry_name, entry_data))

        return evidence

    def _analyze_mixin_config(self, entry_name: str, entry_data: bytes) -> list[Evidence]:
        try:
            config = json.loads(entry_data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []

        if not isinstance(config, dict):
            return []

        package = config.get("package", "")
        mixin_class_names: list[str] = []
        for key in ("mixins", "client", "server"):
            classes = config.get(key)
            if isinstance(classes, list):
                mixin_class_names.extend(str(c) for c in classes)

        evidence: list[Evidence] = []
        for class_name in mixin_class_names:
            # The mixin's own class name conventionally hints at its
            # target (e.g. "MixinSession" targeting Session) — but only
            # match against the narrowed auth-sensitive list, not the
            # broad "MinecraftClient"/"Session" fragments that matched
            # every rendering/input mod.
            for fragment in _SENSITIVE_CONFIG_NAME_FRAGMENTS:
                if fragment in class_name:
                    evidence.append(
                        Evidence(
                            detector_id=self.detector_id,
                            severity=Severity.MEDIUM,
                            class_name=f"{package}.{class_name}" if package else class_name,
                            method_name="",
                            offset=0,
                            description=(
                                f"Mixin config {entry_name} declares a mixin class "
                                f"whose name suggests it targets {fragment}: {class_name}"
                            ),
                            matched_value=class_name,
                            context={"mixin_config": entry_name},
                        )
                    )
                    break

        return evidence

    def _analyze_manifest_coremod(self, entry_name: str, entry_data: bytes) -> list[Evidence]:
        try:
            text = entry_data.decode("utf-8", errors="replace")
        except Exception:
            return []

        evidence: list[Evidence] = []
        coremod_keys = ("FMLCorePlugin", "FMLCorePluginContainsFMLMod")
        for line in text.splitlines():
            for key in coremod_keys:
                if line.strip().startswith(key):
                    evidence.append(
                        Evidence(
                            detector_id=self.detector_id,
                            severity=Severity.MEDIUM,
                            class_name="",
                            method_name="",
                            offset=0,
                            description=(
                                f"Coremod declared in manifest ({key}) — coremods "
                                "register a ClassLoader transformer with full "
                                "bytecode-rewrite access before other mod code runs, "
                                "which the bytecode-level detectors do not analyze"
                            ),
                            matched_value=line.strip()[:200],
                            context={"manifest_key": key},
                        )
                    )
        return evidence
