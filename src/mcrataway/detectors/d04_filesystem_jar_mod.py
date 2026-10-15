"""D04 — Filesystem and JAR modification detector.

Reports every filesystem, stream and archive API call at INFO: it is
volume for the weighted score, not a verdict. Credential-file paths
are D08's signal, not this detector's.
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import resolve_invokes


class D04FilesystemJarMod(Detector):
    @property
    def detector_id(self) -> str:
        return "d04"

    def analyze_class(self, class_file: ClassFile) -> list[Evidence]:
        evidence: list[Evidence] = []
        cp = class_file.constant_pool

        filesystem_classes = {
            "java/util/zip/ZipOutputStream",
            "java/util/zip/ZipFile",
            "java/util/jar/JarFile",
            "java/util/jar/JarOutputStream",
            "java/nio/file/Files",
            "java/nio/file/Paths",
            "java/io/FileOutputStream",
            "java/io/FileInputStream",
            "java/io/RandomAccessFile",
        }

        for method in class_file.methods:
            if not method.bytecode:
                continue

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
            for inv in invokes:
                if inv.owner in filesystem_classes:
                    evidence.append(
                        self._add_evidence(
                            class_file,
                            method.name,
                            inv.offset,
                            f"Filesystem/JAR operation: {inv.owner}.{inv.name}",
                            Severity.INFO,
                            matched_value=f"{inv.owner}.{inv.name}{inv.descriptor}",
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )

        # Credential-file paths are D08's signal, not this detector's.
        # Reporting "launcher_accounts.json" here as well gave a single
        # constant two HIGH findings from two detectors, which by itself
        # already crossed the MALICIOUS threshold.
        return evidence
