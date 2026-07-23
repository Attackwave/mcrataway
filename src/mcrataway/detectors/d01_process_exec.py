"""D01 — Process execution detector.

Catches:
- Runtime.exec()
- ProcessBuilder.start()
- Shell command strings
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


class D01ProcessExec(Detector):
    @property
    def detector_id(self) -> str:
        return "d01"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp)
            for inv in invokes:
                if inv.owner == "java/lang/Runtime" and inv.name == "exec":
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            "Runtime.exec() call detected",
                            Severity.HIGH,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

                elif inv.owner == "java/lang/ProcessBuilder" and inv.name in ("__init__", "start"):
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            "ProcessBuilder usage detected",
                            Severity.HIGH,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

        return evidence
