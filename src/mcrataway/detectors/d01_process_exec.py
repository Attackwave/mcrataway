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

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
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
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )

                elif inv.owner == "java/lang/ProcessBuilder" and inv.name in ("<init>", "start"):
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            "ProcessBuilder usage detected",
                            Severity.HIGH,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )

        return evidence

    def analyze_reconstructed_strings(
        self, class_file: ClassFile, strings: list[str]
    ) -> list[Evidence]:
        """Flag de-obfuscated references to process-execution APIs.

        A benign mod has no reason to hide "java.lang.Runtime" or
        "ProcessBuilder" in a byte array — the concealment itself is
        the signal, so this is rated CRITICAL rather than the HIGH used
        for the equivalent plain-text/bytecode match.
        """
        evidence: list[Evidence] = []
        indicators = (
            "java.lang.Runtime",
            "java/lang/Runtime",
            "getRuntime",
            "ProcessBuilder",
        )
        for s in strings:
            for indicator in indicators:
                if indicator in s:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"Obfuscated reference to process execution API: {indicator}",
                            Severity.CRITICAL,
                            matched_value=s[:200],
                        )
                    )
        return evidence
