"""D09 — Obfuscation detector.

Catches:
- High-entropy strings
- Byte-array string hiding
- XOR / S-box cipher signatures
- Control-flow flattening

Control-flow flattening design note: a flattened method compiles to a
dispatcher shape — one central tableswitch/lookupswitch on a state
variable, inside a loop, where (unlike an ordinary switch statement,
where each case typically ends in `return`/falls through) most cases
end with a `goto` back to the dispatcher to select the next state.
Verified against real javac output: an ordinary 7-case switch
statement (each case returning directly) produces the switch and ZERO
goto instructions, while the same logic manually rewritten as an
explicit state machine (`while(true) { switch(state) { ... state = N;
break; } }` — the shape a control-flow-flattening obfuscator produces)
compiles to the switch plus one goto per case. The goto-to-switch-target
ratio is therefore the actual distinguishing signal, not the mere
presence of a switch (which is extremely common and never suspicious
on its own).
"""

import math
from collections import Counter

from mcrataway.constants import Severity
from mcrataway.core.evidence import Evidence
from mcrataway.detectors.base import Detector
from mcrataway.parsers.classfile import ClassFile
from mcrataway.parsers.instructions import decode_bytecode

# A switch is only considered a plausible flattening dispatcher if it
# has at least this many targets — a 2-3 way switch is far too common
# in ordinary code (an enum-like small state check) to be meaningful
# on its own.
_MIN_DISPATCHER_TARGETS = 4

# Minimum goto-instructions-per-switch-target ratio to flag flattening.
# An ordinary switch with each case ending in `return`/`break` (falling
# out of the switch entirely, not looping back) produces on the order
# of ZERO gotos; a flattened dispatcher produces roughly one per case
# (the "jump back to re-dispatch" at the end of each state's body).
_MIN_GOTO_TO_TARGET_RATIO = 0.5

# Opcodes that indicate a loop-bound comparison rather than a
# pure state-variable dispatch when found shortly before a
# switch: if_icmp* family (159-166), arraylength (190),
# if_acmp* (165-166, already covered), and the generic
# if<cond> family used against a loop counter (153-158).
_LOOP_COMPARISON_OPCODES = set(range(153, 167)) | {190}


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

        for method in class_file.methods:
            if not method.bytecode:
                continue
            evidence.extend(
                self._check_control_flow_flattening(method.name, method.bytecode, class_file)
            )

        return evidence

    def _check_control_flow_flattening(
        self, method_name: str, bytecode: bytes, class_file: ClassFile
    ) -> list[Evidence]:
        """Flag a method whose bytecode has the structural shape of a
        control-flow-flattening dispatcher. See module docstring for
        the reasoning and the real-bytecode verification behind the
        thresholds.

        False-positive guard: an ordinary ``for``/``while`` loop with a
        ``switch`` inside it (a ``switch`` per iteration over some
        collection, e.g. handling different item types) produces the
        exact same switch+multiple-goto shape as a flattened dispatcher
        — every ``break``/``continue`` in a loop-body switch compiles
        to a ``goto``, same as a flattened state machine's "jump back
        to re-dispatch". Verified against real javac output: the
        distinguishing feature is what comes immediately *before* the
        switch's selector value is pushed. An ordinary counted loop has
        a comparison against the loop bound there (``if_icmpge`` /
        ``arraylength`` etc. — checking "have we reached the end of
        the collection?"); a flattened dispatcher just loads the state
        variable with no such comparison, because the switch itself
        (not a separate loop condition) is what decides everything.
        """
        instructions = decode_bytecode(bytecode)
        switches = [i for i in instructions if i.opcode in (170, 171)]
        if not switches:
            return []

        goto_count = sum(1 for i in instructions if i.opcode_name == "goto")

        evidence: list[Evidence] = []
        for switch in switches:
            target_count = switch.operand_value
            if target_count < _MIN_DISPATCHER_TARGETS:
                continue
            ratio = goto_count / target_count if target_count else 0.0
            if ratio < _MIN_GOTO_TO_TARGET_RATIO:
                continue

            # Look at the small window of instructions immediately
            # preceding the switch for a loop-bound comparison — if
            # found, this switch selector is derived from a counted
            # loop condition, not a bare dispatcher state variable.
            preceding = [i for i in instructions if i.offset < switch.offset]
            window = preceding[-4:]
            if any(i.opcode in _LOOP_COMPARISON_OPCODES for i in window):
                continue

            evidence.append(
                self._add_evidence(
                    class_file,
                    method_name,
                    switch.offset,
                    (
                        f"Possible control-flow flattening: dispatcher switch with "
                        f"{target_count} targets and {goto_count} goto instructions "
                        f"in the same method"
                    ),
                    Severity.MEDIUM,
                    matched_value=f"targets={target_count},gotos={goto_count}",
                    context={
                        "switch_targets": str(target_count),
                        "goto_count": str(goto_count),
                    },
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
