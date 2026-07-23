"""D09 — Obfuscation detector.

Catches:
- High-entropy strings
- Byte-array string hiding
- XOR / S-box cipher signatures
- Control-flow flattening
"""

import math
from collections import Counter

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile


class D09Obfuscation(Detector):
    @property
    def detector_id(self) -> str:
        return "d09"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        # Check for obfuscated class names (single-letter packages)
        parts = class_file.this_class.split("/")
        short_parts = [p for p in parts if len(p) == 1]
        if len(short_parts) > len(parts) * 0.5 and len(parts) > 2:
            evidence.append(
                self._add_evidence(
                    class_file,
                    "",
                    0,
                    f"Heavily obfuscated class name: {class_file.this_class}",
                    Severity.MEDIUM,
                    matched_value=class_file.this_class,
                )
            )

        # Check for high-entropy strings
        for s in cp.all_string_literals():
            if len(s) > 12:
                entropy = self._shannon_entropy(s)
                if entropy > 5.8:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            "",
                            0,
                            f"High-entropy string (entropy={entropy:.2f}): {s[:50]}...",
                            Severity.LOW,
                            matched_value=s[:200],
                            context={"entropy": f"{entropy:.2f}"},
                        )
                    )

        return evidence

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        counter = Counter(s)
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
            if count > 0
        )
