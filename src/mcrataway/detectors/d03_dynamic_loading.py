"""D03 — Dynamic class loading detector.

Catches:
- URLClassLoader
- ClassLoader.defineClass
- Class.forName with dynamic strings
- In-memory class loading patterns
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


class D03DynamicLoading(Detector):
    @property
    def detector_id(self) -> str:
        return "d03"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        dangerous_classes = {
            "java/net/URLClassLoader",
            "java/security/SecureClassLoader",
        }

        dangerous_methods = {
            ("java/lang/ClassLoader", "defineClass"),
            ("java/lang/Class", "forName"),
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
                if inv.owner in dangerous_classes:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Dynamic class loading via {inv.owner}.{inv.name}",
                            Severity.HIGH if not is_stdlib else Severity.MEDIUM,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

                if (inv.owner, inv.name) in dangerous_methods:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Dynamic class resolution: {inv.owner}.{inv.name}",
                            Severity.MEDIUM if not is_stdlib else Severity.INFO,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

        return evidence
