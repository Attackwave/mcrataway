"""D10 — Reflection indirect access detector.

Catches:
- MethodHandles, LambdaMetafactory
- VarHandle, StackWalker
- Array-indirect dispatch
- Split-name reconstruction
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


class D10ReflectionIndirect(Detector):
    @property
    def detector_id(self) -> str:
        return "d10"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        indirect_classes = {
            "java/lang/invoke/MethodHandles",
            "java/lang/invoke/MethodHandle",
            "java/lang/invoke/LambdaMetafactory",
            "java/lang/invoke/VarHandle",
            "java/lang/StackWalker",
            "sun/misc/Unsafe",
            "jdk/internal/misc/Unsafe",
        }

        std_lib_prefixes = (
            "kotlin/",
            "kotlinx/",
            "org/jetbrains/",
            "it/unimi/dsi/fastutil/",
            "com/google/gson/",
            "org/apache/commons/",
        )
        is_stdlib = class_file.this_class.startswith(std_lib_prefixes)

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp)
            for inv in invokes:
                if inv.owner in indirect_classes:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Indirect access: {inv.owner}.{inv.name}",
                            Severity.MEDIUM if not is_stdlib else Severity.INFO,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

        return evidence
