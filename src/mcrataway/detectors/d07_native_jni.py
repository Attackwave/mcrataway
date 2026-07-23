"""D07 — Native/JNI loading detector.

Catches:
- System.load / System.loadLibrary
- Embedded .dll / .so / .dylib entries
- JNIC pattern: .dat LZMA resources + temp DLL
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


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

            invokes = resolve_invokes(method.bytecode, cp)
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
                        )
                    )

        # Check for native library extensions in constant pool
        native_extensions = [".dll", ".so", ".dylib"]
        for s in cp.all_strings():
            for ext in native_extensions:
                if ext in s.lower():
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"Native library reference: {s[:200]}",
                            Severity.INFO,
                            matched_value=s[:200],
                        )
                    )

        # JNIC loader detection
        jnic_indicators = ["JNICLoader"]
        for s in cp.all_strings():
            for indicator in jnic_indicators:
                if indicator in s:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"JNIC native loader indicator: {indicator}",
                            Severity.HIGH,
                            matched_value=s[:200],
                        )
                    )

        return evidence
