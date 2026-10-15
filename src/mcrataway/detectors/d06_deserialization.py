"""D06 — Unsafe deserialization detector.

Catches:
- ObjectInputStream.readObject() (BleedingPipe-style RCE)
- java.beans.XMLDecoder.readObject() — the same primitive over XML,
  which deserializes arbitrary object graphs from attacker-controlled
  input (no module, no allowlist) and is never used by a mod for its
  own configuration files.
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes

# Deserialization entry points that reconstruct an arbitrary object
# graph: a HIGH finding on their own, because the input stream is the
# attacker's by definition.
_DANGEROUS_DESERIALIZERS = {
    ("java/io/ObjectInputStream", "readObject"): "ObjectInputStream.readObject()",
    ("java/beans/XMLDecoder", "readObject"): "java.beans.XMLDecoder.readObject()",
}


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

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
            for inv in invokes:
                api = _DANGEROUS_DESERIALIZERS.get((inv.owner, inv.name))
                if api is None:
                    continue
                evidence.append(
                    self._add_evidence(
                        class_file,
                        method.name,
                        inv.offset,
                        f"Unsafe deserialization: {api}",
                        Severity.HIGH if inv.owner == "java/beans/XMLDecoder" else Severity.MEDIUM,
                        matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                        context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                    )
                )

        return evidence
