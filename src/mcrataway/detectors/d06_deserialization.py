"""D06 — Unsafe deserialization detector.

Catches:
- ObjectInputStream.readObject() (BleedingPipe-style RCE)
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


class D06Deserialization(Detector):
    @property
    def detector_id(self) -> str:
        return "d06"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp)
            for inv in invokes:
                if inv.owner == "java/io/ObjectInputStream" and inv.name == "readObject":
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            "Unsafe deserialization: ObjectInputStream.readObject()",
                            Severity.MEDIUM,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        )
                    )

        return evidence
