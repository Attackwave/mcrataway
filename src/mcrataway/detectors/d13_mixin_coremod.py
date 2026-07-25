"""D13 — Mixin/coremod abuse detector.

Catches:
- Fabric/Forge Mixin configs (*.mixins.json) targeting security-sensitive
  classes (session/auth/network handling) — this is the largest blind
  spot in the other detectors, since Mixins let a mod rewrite bytecode
  in the game itself (or another mod) at load time, so a malicious
  Mixin targeting e.g. the session-token accessor never needs to call
  any of the APIs D01-D11 look for. It just edits the method that
  already has the token.
- FMLCorePlugin / coremod declarations in META-INF/MANIFEST.MF, which
  is Forge's older (pre-Mixin) equivalent capability: a coremod can
  register its own ClassLoader transformer with full bytecode access
  before any other mod code runs.

This detector operates on archive entries (mixin JSON configs, the
manifest) rather than on individual parsed classes, since the
"target" a Mixin edits is declared in JSON, not derivable from the
Mixin class's own bytecode alone.
"""

import json

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile

# Fully-qualified (dotted, as Mixin configs write them) or partial
# target-class fragments that indicate a mixin is rewriting
# session/auth/network-critical game code. Includes both Mojang
# obfuscated (class_NNN / method_NNN, "intermediary" naming used by
# Fabric before remapping) and Yarn-remapped names, since a shipped
# mod jar may reference either depending on the mapping it was built
# against.
_SENSITIVE_TARGET_FRAGMENTS = (
    "Session",
    "MinecraftClient",
    "class_310",  # MinecraftClient (intermediary)
    "YggdrasilAuthenticationService",
    "YggdrasilUserApiService",
    "SocketAddress",
    "ClientConnection",
    "class_2535",  # ClientConnection (intermediary)
    "NetworkState",
    "PacketEncoder",
    "PacketDecoder",
    "AbstractSocketConnection",
)

# Mixin annotation types that fully replace or reroute behavior at the
# injection point, as opposed to @Inject (which runs alongside the
# original method) — @Redirect and @Overwrite are far more capable of
# silently substituting attacker logic for a security-relevant call.
_HIGH_IMPACT_MIXIN_ANNOTATIONS = ("@Redirect", "@Overwrite")


class D13MixinCoremod(Detector):
    @property
    def detector_id(self) -> str:
        return "d13"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        """Flag @Redirect/@Overwrite annotations referencing sensitive
        targets found via the constant pool of a mixin class itself —
        a coarse signal, since annotation *targets* (method
        descriptors) are not fully resolved here, but the combination
        of a high-impact Mixin annotation string and a sensitive class
        name in the same constant pool is already informative.
        """
        evidence: list[Evidence] = []
        cp = class_file.constant_pool
        strings = cp.all_strings()

        has_high_impact_annotation = any(
            ann in s for s in strings for ann in _HIGH_IMPACT_MIXIN_ANNOTATIONS
        )
        if not has_high_impact_annotation:
            return evidence

        matched_targets = {
            frag for s in strings for frag in _SENSITIVE_TARGET_FRAGMENTS if frag in s
        }
        for target in matched_targets:
            evidence.append(
                self._add_evidence(
                    class_file,
                    "",
                    0,
                    f"Mixin class references high-impact annotation "
                    f"(@Redirect/@Overwrite) alongside sensitive target: {target}",
                    Severity.HIGH,
                    matched_value=target,
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
            # The Mixin's own class name conventionally hints at its
            # target (e.g. "MixinMinecraftClient" targeting
            # MinecraftClient) — this is a naming convention, not a
            # guarantee, but it is what a human reviewer would also
            # use as a first signal without decompiling the mixin.
            for fragment in _SENSITIVE_TARGET_FRAGMENTS:
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
