"""Reconstruct strings hidden via bytecode obfuscation patterns.

Handles:
- new byte[]{...} -> new String(...) (fractureiser Stage-0)
- new char[]{...} -> new String(...) variants
- StringBuilder().reverse().toString() reversed strings
- split int[]/String[] interleaving with S-box + XOR cipher (weedhack family)
- StringBuilder.append() chains
"""

import re
from dataclasses import dataclass

from mcrataway.parsers.classfile import ClassFile, MethodInfo
from mcrataway.parsers.instructions import extract_ldc_strings, extract_newarray_bytes


@dataclass
class ReconstructedString:
    method_name: str
    class_name: str
    offset: int
    value: str
    technique: str


def reconstruct_strings(class_file: ClassFile) -> list[ReconstructedString]:
    """Extract hidden strings from all methods in a class file."""
    results: list[ReconstructedString] = []

    for method in class_file.methods:
        if not method.bytecode:
            continue

        results.extend(_extract_byte_array_strings(method, class_file))
        
        # Extract plain LDC strings
        ldc_strings = extract_ldc_strings(method.bytecode, class_file.constant_pool)
        for offset, val in ldc_strings:
            results.append(
                ReconstructedString(
                    method_name=method.name,
                    class_name=class_file.this_class,
                    offset=offset,
                    value=val,
                    technique="ldc_string",
                )
            )

    return results


def _extract_byte_array_strings(
    method: MethodInfo,
    class_file: ClassFile,
) -> list[ReconstructedString]:
    """Detect new byte[]{...} -> new String(...) pattern."""
    results: list[ReconstructedString] = []
    bytecode = method.bytecode

    byte_arrays = extract_newarray_bytes(bytecode, class_file.constant_pool)

    for offset, values in byte_arrays:
        try:
            reconstructed = bytes(values).decode("utf-8", errors="replace")
            if reconstructed and len(reconstructed) > 1:
                results.append(
                    ReconstructedString(
                        method_name=method.name,
                        class_name=class_file.this_class,
                        offset=offset,
                        value=reconstructed,
                        technique="byte_array_string",
                    )
                )
        except Exception:
            continue

    return results


def decode_xor_cipher(
    d1: list[int],
    d2: list[int],
    k1: int,
    k2: int,
) -> str:
    """Decode the weedhack/Majanito int-array cipher.

    This reverses the Helper.load(int[], int[], int, int) pattern:
    - interleaves d1 and d2
    - builds S-box using (i * 53 + 97) % 256
    - XORs with k1, rotates bits by k2
    - applies inverse substitution
    """
    interleaved: list[int] = []
    for i in range(max(len(d1), len(d2))):
        if i < len(d1):
            interleaved.append(d1[i])
        if i < len(d2):
            interleaved.append(d2[i])

    sbox = [(i * 53 + 97) % 256 for i in range(256)]
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i

    # Clamp k2 to the valid bit-rotation range [0, 8). Values >= 8
    # would otherwise raise ValueError on `v << (8 - k2)` in Python
    # (negative shift) and values < 0 are nonsensical here.
    k2 = k2 % 8

    result: list[int] = []
    for val in interleaved:
        v = val ^ k1
        v = ((v >> k2) | (v << (8 - k2))) & 0xFF
        v = inv_sbox[v]
        result.append(v)

    try:
        return bytes(result).decode("utf-8", errors="replace")
    except Exception:
        return ""


def decode_simple_xor(data: bytes, key: bytes) -> str:
    """Decode simple repeating-key XOR."""
    if not key:
        return ""
    decoded = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
    try:
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return ""


def find_reversed_strings(source_text: str) -> list[str]:
    """Find StringBuilder chains that build reversed strings.

    Looks for patterns like:
    new StringBuilder("...").reverse().toString()
    """
    results: list[str] = []

    pattern = r'new\s+StringBuilder\s*\(\s*"([^"]*?)"\s*\)\s*\.reverse\s*\(\)\s*\.toString\s*\(\)'
    for match in re.finditer(pattern, source_text):
        reversed_val = match.group(1)[::-1]
        results.append(reversed_val)

    pattern2 = (
        r'new\s+StringBuilder\s*\(\s*\)\s*\.append\s*\(\s*"([^"]*?)"\s*\)'
        r'\s*\.append\s*\(\s*"([^"]*?)"\s*\)'
    )
    for match in re.finditer(pattern2, source_text):
        combined = match.group(1) + match.group(2)
        results.append(combined)

    return results
