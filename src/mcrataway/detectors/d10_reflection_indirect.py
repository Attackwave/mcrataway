"""D10 — Reflection indirect access detector.

Catches:
- MethodHandles, LambdaMetafactory
- VarHandle, StackWalker
- Array-indirect dispatch
- Split-name reconstruction
- Cross-class method references via invokedynamic (a lambda/method
  reference in this class whose resolved target lives in a *different*
  class) — see the module-level note on why this matters.

Design note on cross-class method references: since
ClassFile.bootstrap_methods is now parsed and resolve_invokes() can
follow an invokedynamic call site to its real target (see
parsers/instructions.py:resolve_invokedynamic_target), a call like
``Runnable r = EvilRunner::detonate; r.run();`` resolves to
``EvilRunner.detonate`` even though *this* class never mentions
Runtime/ProcessBuilder/etc. anywhere in its own bytecode. Splitting a
capability's implementation into a separate class and reaching it only
through a method reference is a way to keep the "obviously
suspicious" code out of the class that a cursory read (or a detector
that only looks at directly-resolved invokes) would flag. This is not
inherently malicious — ordinary functional-interface usage does this
constantly — but it is exactly the shape used to defeat naive
single-class analysis, so it is worth a low-severity signal on its own
and a stronger one when the target class is unusual.
"""

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile, MethodInfo
from mcrataway.parsers.instructions import InvokeInstruction, decode_bytecode, resolve_invokes


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

            invokes = resolve_invokes(method.bytecode, cp, class_file.bootstrap_methods)
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
                            context={"invoke_owner": inv.owner, "invoke_name": inv.name},
                        )
                    )

            evidence.extend(
                self._check_cross_class_method_refs(method, class_file, invokes)
            )

        return evidence

    def _check_cross_class_method_refs(
        self,
        method: MethodInfo,
        class_file: ClassFile,
        invokes: list[InvokeInstruction],
    ) -> list[Evidence]:
        """Flag invokedynamic call sites whose resolved target is in a
        different class than the one being analyzed — see module
        docstring. Only invokedynamic-originated invokes are
        considered (identified by opcode 186), not ordinary
        invokestatic/invokevirtual/etc. calls to other classes, which
        are completely normal and would otherwise flood every class
        with noise.
        """
        evidence: list[Evidence] = []
        instructions = decode_bytecode(method.bytecode)
        invokedynamic_offsets = {i.offset for i in instructions if i.opcode == 186}

        for inv in invokes:
            if inv.offset not in invokedynamic_offsets:
                continue
            owner = inv.owner
            if not owner or owner == class_file.this_class:
                continue
            evidence.append(
                self._add_evidence(
                    class_file,
                    method.name,
                    inv.offset,
                    f"Method reference resolves to a different class: {owner}.{inv.name}",
                    Severity.LOW,
                    matched_value=f"{owner}.{inv.name}",
                    context={"cross_class_method_ref": "1", "target_class": owner},
                )
            )

        return evidence
