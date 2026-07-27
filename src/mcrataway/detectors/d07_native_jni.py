"""D07 — Native/JNI loading detector.

Catches:
- System.load / System.loadLibrary
- Embedded .dll / .so / .dylib entries
- JNIC pattern: .dat LZMA resources + temp DLL

Design note: LWJGL, GLFW, OpenAL, and JOML — used by essentially every
Minecraft mod that touches rendering or audio — reference native
library filenames in their bootstrap code. A bare substring match on
".so"/".dll"/".dylib" therefore fires on nearly every mod. Extension
references are only escalated when they co-occur with actual native
payload *staging* (createTempFile + deleteOnExit in the same class),
which is the real behavioral signature of dropping and loading an
unpacked native library at runtime.
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes

# Well-known legitimate native-library basenames bundled by common
# Minecraft rendering/audio/math libraries — a reference to one of
# these alone should not be escalated.
_KNOWN_BENIGN_LIB_SUBSTRINGS = (
    "lwjgl", "glfw", "openal", "joml", "jemalloc", "opengl32", "stb",
)

_STAGING_INDICATORS = ("createTempFile", "deleteOnExit")


class D07NativeJni(Detector):
    @property
    def detector_id(self) -> str:
        return "d07"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
            for inv in invokes:
                if inv.owner == "java/lang/System" and inv.name in ("load", "loadLibrary"):
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Native library loading: System.{inv.name}()",
                            Severity.HIGH,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )

        all_strings = cp.all_strings()
        evidence.extend(self._scan_strings(class_file, all_strings, obfuscated=False))
        return evidence

    def analyze_reconstructed_strings(
        self, class_file: ClassFile, strings: list[str]
    ) -> list[Evidence]:
        return self._scan_strings(class_file, strings, obfuscated=True)

    def _scan_strings(
        self, class_file: ClassFile, strings: list[str], obfuscated: bool
    ) -> list[Evidence]:
        # Single pass over `strings`: the staging check needs to see
        # every string before extension references can be finally
        # classified (has_staging affects their severity), so JNIC and
        # extension candidates are collected in the same loop and
        # evidence is only built once has_staging is known — three
        # separate loops over the same (potentially large) constant
        # pool are collapsed into one.
        has_staging = False
        ext_candidates: list[str] = []
        jnic_candidates: list[str] = []

        for s in strings:
            for ind in _STAGING_INDICATORS:
                if ind in s:
                    has_staging = True
                    break

            lowered = s.lower()
            for ext in (".dll", ".so", ".dylib"):
                idx = lowered.find(ext)
                if idx == -1:
                    continue
                end = idx + len(ext)
                if end != len(lowered) and lowered[end].isalnum():
                    continue  # not actually a file extension boundary
                ext_candidates.append(s)
                break

            if "JNICLoader" in s:
                jnic_candidates.append(s)

        evidence: list[Evidence] = []
        prefix = "Obfuscated " if obfuscated else ""

        seen_refs: set[str] = set()
        for s in ext_candidates:
            if s in seen_refs:
                continue
            seen_refs.add(s)
            lowered = s.lower()

            is_known_benign = any(k in lowered for k in _KNOWN_BENIGN_LIB_SUBSTRINGS)
            if is_known_benign and not has_staging:
                continue  # e.g. "lwjgl64.dll" with no staging behavior — noise

            if has_staging:
                severity = Severity.CRITICAL if obfuscated else Severity.HIGH
                desc = "native payload staging (temp file + native load)"
            elif is_known_benign:
                severity = Severity.INFO
                desc = "known library reference"
            else:
                severity = Severity.MEDIUM if obfuscated else Severity.LOW
                desc = "native library reference"

            evidence.append(
                self._add_evidence(
                    class_file, "", 0,
                    f"{prefix}Native library reference ({desc}): {s[:200]}",
                    severity,
                    matched_value=s[:200],
                )
            )

        jnic_severity = Severity.CRITICAL if obfuscated else Severity.HIGH
        for s in jnic_candidates:
            evidence.append(
                self._add_evidence(
                    class_file, "", 0,
                    f"{prefix}JNIC native loader indicator: JNICLoader",
                    jnic_severity,
                    matched_value=s[:200],
                )
            )

        return evidence
