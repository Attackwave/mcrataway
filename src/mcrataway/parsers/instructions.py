"""Java bytecode instruction decoder and invoke resolver."""

import functools
import struct
from dataclasses import dataclass

from mcrataway.constants import (
    INVOKE_OPCODES,
    OPCODE_NAMES,
)
from mcrataway.parsers.constant_pool import ConstantPool

# Branch opcodes (ifeq..goto, ifnull, ifnonnull) — 2-byte signed offset
_BRANCH_OPCODES = set(range(153, 169)) | {198, 199}

# Upper bound for any plausible switch table. The JVM spec caps
# tableswitch at 16384 entries; we keep a generous hard limit so a
# malicious `high - low + 1` of ~2 billion cannot drive `pos` backwards
# or trigger an effectively-unbounded read.
_MAX_SWITCH_ENTRIES = 65536


@dataclass
class Instruction:
    offset: int
    opcode: int
    opcode_name: str
    operand: bytes = b""
    operand_value: int = 0


@dataclass
class InvokeInstruction:
    offset: int
    opcode: int
    owner: str
    name: str
    descriptor: str
    cp_index: int


@functools.lru_cache(maxsize=16384)
def decode_bytecode(code: bytes) -> list[Instruction]:
    """Decode raw bytecode into a list of Instructions.

    Defensive against malformed inputs: ``tableswitch``/``lookupswitch``
    jump-table sizes are bounded and the loop aborts if ``pos`` ever
    stops advancing, so a malicious class file cannot trigger an
    infinite loop by claiming ``high < low`` or ``npairs < 0``.
    """
    instructions: list[Instruction] = []
    pos = 0
    while pos < len(code):
        opcode = code[pos]
        opcode_name = OPCODE_NAMES.get(opcode, f"unknown_{opcode}")
        pos += 1
        last_pos = pos  # track progress to detect stuck decoding

        operand = b""
        operand_value = 0

        if opcode == 16:  # bipush
            operand = code[pos : pos + 1]
            operand_value = struct.unpack(">b", operand)[0] if len(operand) == 1 else 0
            pos += 1

        elif opcode == 17:  # sipush
            operand = code[pos : pos + 2]
            operand_value = struct.unpack(">h", operand)[0] if len(operand) == 2 else 0
            pos += 2

        elif opcode == 18:  # ldc
            operand = code[pos : pos + 1]
            operand_value = operand[0] if len(operand) == 1 else 0
            pos += 1

        elif opcode in (19, 20):  # ldc_w, ldc2_w
            operand = code[pos : pos + 2]
            operand_value = struct.unpack(">H", operand)[0] if len(operand) == 2 else 0
            pos += 2

        elif opcode == 188 or opcode in (21, 22, 23, 24, 25, 54, 55, 56, 57, 58, 169):
            # 1-byte operand opcodes: newarray, iload..aload, istore..astore,
            # and ret (169) — all read a single u1 index. `ret` is
            # deprecated since Java 7 but still legal and seen in
            # obfuscated/legacy bytecode; without it here the index
            # byte would be misread as the next opcode.
            operand = code[pos : pos + 1]
            operand_value = operand[0] if len(operand) == 1 else 0
            pos += 1

        elif opcode == 132:  # iinc
            # JVM spec: iinc index:u1 const:s1 — 2 operand bytes, NOT 3.
            # The previous code used `>Hb` (3 bytes) and `pos += 3`,
            # which shifted every subsequent instruction by 1 byte
            # and corrupted the rest of the bytecode stream.
            operand = code[pos : pos + 2]
            if len(operand) == 2:
                operand_value = struct.unpack(">Bb", operand)[0]
            pos += 2

        elif opcode in _BRANCH_OPCODES:
            operand = code[pos : pos + 2]
            operand_value = struct.unpack(">h", operand)[0] if len(operand) == 2 else 0
            pos += 2

        elif opcode == 170:  # tableswitch
            padding = (4 - (pos % 4)) % 4
            pos += padding
            struct.unpack(">i", code[pos : pos + 4])[0]
            pos += 4
            low = struct.unpack(">i", code[pos : pos + 4])[0]
            pos += 4
            high = struct.unpack(">i", code[pos : pos + 4])[0]
            pos += 4
            jump_count = high - low + 1
            # Guard against malformed/malicious class files: a signed
            # `high < low` would make jump_count negative and `pos`
            # would run backwards, creating an infinite loop.
            if jump_count < 0 or jump_count > _MAX_SWITCH_ENTRIES:
                break
            pos += jump_count * 4

        elif opcode == 171:  # lookupswitch
            padding = (4 - (pos % 4)) % 4
            pos += padding
            struct.unpack(">i", code[pos : pos + 4])[0]
            pos += 4
            npairs = struct.unpack(">i", code[pos : pos + 4])[0]
            pos += 4
            # Same DoS guard as tableswitch: negative npairs would
            # rewind pos and could loop forever.
            if npairs < 0 or npairs > _MAX_SWITCH_ENTRIES:
                break
            pos += npairs * 8

        elif opcode == 197:  # multianewarray
            operand = code[pos : pos + 3]
            if len(operand) == 3:
                operand_value = struct.unpack(">HB", operand)[0]
            pos += 3

        elif opcode in (187, 189, 192, 193):  # new, anewarray, checkcast, instanceof
            operand = code[pos : pos + 2]
            operand_value = struct.unpack(">H", operand)[0] if len(operand) == 2 else 0
            pos += 2

        elif opcode in INVOKE_OPCODES:
            operand = code[pos : pos + 2]
            operand_value = struct.unpack(">H", operand)[0] if len(operand) == 2 else 0
            pos += 2

            if opcode == 185:  # invokeinterface
                pos += 2  # count + 0

        elif opcode in (178, 179, 180, 181):  # getstatic, putstatic, getfield, putfield
            operand = code[pos : pos + 2]
            operand_value = struct.unpack(">H", operand)[0] if len(operand) == 2 else 0
            pos += 2

        elif opcode in (200, 201):  # goto_w, jsr_w
            operand = code[pos : pos + 4]
            operand_value = struct.unpack(">i", operand)[0] if len(operand) == 4 else 0
            pos += 4

        elif opcode == 196:  # wide
            wide_start = pos - 1  # offset of the `wide` opcode itself
            pos += 1
            wide_opcode = code[pos - 1] if pos <= len(code) else 0
            if wide_opcode in (21, 22, 23, 24, 25, 54, 55, 56, 57, 58, 169):
                pos += 2
            elif wide_opcode == 132:
                pos += 4

            instructions.append(
                Instruction(
                    offset=wide_start,
                    opcode=opcode,
                    opcode_name=opcode_name,
                    operand=b"",
                    operand_value=wide_opcode,
                )
            )
            continue

        instructions.append(
            Instruction(
                offset=pos - len(operand) - 1,
                opcode=opcode,
                opcode_name=opcode_name,
                operand=operand,
                operand_value=operand_value,
            )
        )

        # Safety net: if a malformed opcode path failed to advance pos
        # (e.g. truncated operand), break instead of spinning forever.
        if pos < last_pos:
            break

    return instructions


def resolve_invokes(bytecode: bytes, cp: ConstantPool) -> list[InvokeInstruction]:
    """Find and resolve all invoke* instructions in bytecode."""
    instructions = decode_bytecode(bytecode)
    invokes: list[InvokeInstruction] = []

    for instr in instructions:
        if instr.opcode in INVOKE_OPCODES:
            owner, name, desc = cp.resolve_method_ref(instr.operand_value)
            invokes.append(
                InvokeInstruction(
                    offset=instr.offset,
                    opcode=instr.opcode,
                    owner=owner,
                    name=name,
                    descriptor=desc,
                    cp_index=instr.operand_value,
                )
            )

    return invokes


def get_invoke_name(opcode: int) -> str:
    """Human-readable name for an invoke opcode."""
    return {
        182: "invokevirtual",
        183: "invokespecial",
        184: "invokestatic",
        185: "invokeinterface",
        186: "invokedynamic",
    }.get(opcode, "unknown")


def _push_int_value(
    instr: Instruction,
    cp: ConstantPool | None = None,
) -> int | None:
    """Extract the integer value pushed by common push instructions.

    Supports ``bipush``, ``sipush``, ``iconst_m1..iconst_5``, and
    ``ldc``/``ldc_w`` loading an integer constant from the constant
    pool (requires *cp* to be supplied). Returns ``None`` if the
    instruction does not push a usable integer.
    """
    op = instr.opcode
    if op == 16:  # bipush
        return instr.operand_value
    if op == 17:  # sipush
        return instr.operand_value
    if 2 <= op <= 8:  # iconst_m1..iconst_5
        # opcode 2 = iconst_m1 (-1), 3 = iconst_0 (0), ..., 8 = iconst_5 (5)
        return op - 3
    if op in (18, 19) and cp is not None:
        # ldc / ldc_w loading an Integer constant from the constant
        # pool. Some obfuscators use this instead of bipush to push
        # byte-array element values.
        idx = instr.operand_value
        try:
            val = cp.get_integer(idx)
        except Exception:
            val = None
        if val is None:
            return None
        # get_integer may return an int already; coerce defensively.
        try:
            return int(val)
        except (TypeError, ValueError):
            return None
    return None


def extract_newarray_bytes(
    bytecode: bytes,
    cp: ConstantPool | None = None,
) -> list[tuple[int, list[int]]]:
    """Find newarray + dup/bipush/bastore sequences and extract byte arrays.

    Detects the ``new byte[]{...}`` pattern produced by javac. The
    element values are stored AFTER the newarray instruction via
    repeated ``(dup?, index-push, value-push, bastore)`` tuples, not
    before it. Pass the class's :class:`ConstantPool` as *cp* to also
    recognise ``ldc``/``ldc_w`` integer pushes (used by some
    obfuscators) as element values.

    Returns a list of ``(offset, byte_values)`` ordered by array index.
    """
    instructions = decode_bytecode(bytecode)
    results: list[tuple[int, list[int]]] = []

    i = 0
    while i < len(instructions):
        instr = instructions[i]

        if instr.opcode == 188:  # newarray
            array_type = instr.operand_value
            if array_type == 8:  # byte
                values_by_index: dict[int, int] = {}
                j = i + 1
                while j < len(instructions) and len(values_by_index) < 5000:
                    # Optional dup of the array reference
                    if instructions[j].opcode == 89:  # dup
                        j += 1
                        if j >= len(instructions):
                            break
                    # Index push
                    idx = _push_int_value(instructions[j], cp)
                    if idx is None:
                        break
                    j += 1
                    if j >= len(instructions):
                        break
                    # Value push
                    val = _push_int_value(instructions[j], cp)
                    if val is None:
                        break
                    j += 1
                    if j >= len(instructions):
                        break
                    # bastore terminator
                    if instructions[j].opcode != 84:  # bastore
                        break
                    j += 1
                    values_by_index[idx] = val & 0xFF

                if values_by_index:
                    max_idx = max(values_by_index)
                    byte_values = [
                        values_by_index.get(k, 0)
                        for k in range(max_idx + 1)
                    ]
                    results.append((instr.offset, byte_values))

        i += 1

    return results


def extract_ldc_strings(bytecode: bytes, cp: ConstantPool) -> list[tuple[int, str]]:
    """Find all LDC instructions that load string constants."""
    instructions = decode_bytecode(bytecode)
    strings: list[tuple[int, str]] = []

    for instr in instructions:
        if instr.opcode in (18, 19):  # ldc, ldc_w
            s = cp.get_string_literal(instr.operand_value)
            if not s:
                s = cp.get_utf8(instr.operand_value)
            if s:
                strings.append((instr.offset, s))

    return strings
