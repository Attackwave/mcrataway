"""Reconstruct strings hidden via bytecode obfuscation patterns.

Handles:
- new byte[]{...} -> new String(...) (fractureiser Stage-0)
- new char[]{...} -> new String(...) variants
- StringBuilder().reverse().toString() reversed strings
- split int[]/String[] interleaving with S-box + XOR cipher (weedhack family)
- StringBuilder.append() chains
- Base64.getDecoder().decode(...) on a constant-pool string literal
"""

import base64
import re
from dataclasses import dataclass

from mcrataway.parsers.classfile import ClassFile, MethodInfo
from mcrataway.parsers.instructions import (
    decode_bytecode,
    extract_ldc_strings,
    extract_newarray_bytes,
    extract_newarray_ints,
    resolve_invokes,
)


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
        results.extend(_extract_char_array_strings(method, class_file))
        results.extend(_extract_weedhack_cipher_strings(method, class_file))
        results.extend(_extract_base64_strings(method, class_file))
        results.extend(_extract_generic_xor_strings(method, class_file))

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
    """Detect new byte[]{...} -> new String(...) pattern.

    Only accepts arrays that decode as *clean* UTF-8 (no replacement
    characters) — a byte array that is itself further encrypted (XOR,
    etc.) decodes as garbage under plain UTF-8 and is left for
    :func:`_extract_generic_xor_strings` to attempt instead. Requiring
    "no replacement chars" here (rather than the previous
    ``errors="replace"``, which accepted mojibake with embedded
    replacement characters as a "successful" reconstruction) is what
    makes that distinction possible.
    """
    results: list[ReconstructedString] = []
    bytecode = method.bytecode

    byte_arrays = extract_newarray_bytes(bytecode, class_file.constant_pool)

    for offset, values in byte_arrays:
        try:
            reconstructed = bytes(values).decode("utf-8")
            if reconstructed and len(reconstructed) > 1 and _is_plausible_text(reconstructed):
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


def _extract_char_array_strings(
    method: MethodInfo,
    class_file: ClassFile,
) -> list[ReconstructedString]:
    """Detect ``new char[]{...} -> new String(...)`` pattern.

    Same javac-generated (dup?, index-push, value-push, castore) shape
    as the byte-array case, just with 16-bit char elements instead of
    8-bit bytes — a variant seen in some obfuscators that avoid the
    (better-known) byte-array string-hiding signature.
    """
    results: list[ReconstructedString] = []
    char_arrays = extract_newarray_ints(method.bytecode, array_type=5, cp=class_file.constant_pool)

    for offset, values in char_arrays:
        try:
            reconstructed = "".join(chr(v) for v in values if 0 <= v <= 0x10FFFF)
            if reconstructed and len(reconstructed) > 1:
                results.append(
                    ReconstructedString(
                        method_name=method.name,
                        class_name=class_file.this_class,
                        offset=offset,
                        value=reconstructed,
                        technique="char_array_string",
                    )
                )
        except Exception:
            continue

    return results


def _extract_weedhack_cipher_strings(
    method: MethodInfo,
    class_file: ClassFile,
) -> list[ReconstructedString]:
    """Detect the weedhack/Majanito ``Helper.load(int[], int[], int, int)``
    call pattern and actually decode it via :func:`decode_xor_cipher`.

    Before this, decode_xor_cipher existed and correctly implemented
    the S-box/XOR inverse, but nothing in the codebase ever called it
    — the two int[] arrays and two int keys it needs were never
    extracted from bytecode, so the weedhack family's string-hiding
    cipher was never actually decoded despite the decoder being
    present.

    Recognizes: two ``int[]`` array literals (see
    ``extract_newarray_ints`` with ``array_type=10``) followed by two
    integer pushes, all immediately preceding an ``invokestatic``
    whose descriptor is ``([I[III)Ljava/lang/String;`` — i.e. exactly
    the ``load(int[], int[], int, int): String`` shape.
    """
    results: list[ReconstructedString] = []
    bytecode = method.bytecode
    cp = class_file.constant_pool

    int_arrays = extract_newarray_ints(bytecode, array_type=10, cp=cp)
    if len(int_arrays) < 2:
        return results

    instructions = decode_bytecode(bytecode)
    invokes = resolve_invokes(bytecode, cp, class_file.bootstrap_methods)

    for inv in invokes:
        if inv.descriptor != "([I[III)Ljava/lang/String;":
            continue

        # Walk backwards from the invoke to find the two integer
        # pushes (k2, then k1, in reverse encounter order) that
        # immediately precede it — the two int[] arrays were already
        # constructed and stored earlier via astore, so only the two
        # trailing int pushes remain adjacent to the call site.
        call_idx = next(
            (idx for idx, instr in enumerate(instructions) if instr.offset == inv.offset), None
        )
        if call_idx is None or call_idx < 2:
            continue

        k2 = _push_int_value_public(instructions[call_idx - 1], cp)
        k1 = _push_int_value_public(instructions[call_idx - 2], cp)
        if k1 is None or k2 is None:
            continue

        # The two int[] arrays nearest (in bytecode offset) before
        # this call site are assumed to be d1, d2 in that order — the
        # javac-generated code constructs and stores them in source
        # order immediately before the call.
        candidate_arrays = [
            (offset, values) for offset, values in int_arrays if offset < inv.offset
        ]
        if len(candidate_arrays) < 2:
            continue
        candidate_arrays.sort(key=lambda pair: pair[0])
        d1_offset, d1 = candidate_arrays[-2]
        d2_offset, d2 = candidate_arrays[-1]

        decoded = decode_xor_cipher(d1, d2, k1, k2)
        if decoded and len(decoded) > 1:
            results.append(
                ReconstructedString(
                    method_name=method.name,
                    class_name=class_file.this_class,
                    offset=d1_offset,
                    value=decoded,
                    technique="weedhack_xor_cipher",
                )
            )

    return results


def _extract_base64_strings(
    method: MethodInfo,
    class_file: ClassFile,
) -> list[ReconstructedString]:
    """Detect constant-pool string literals that decode as valid Base64
    in a method that also calls ``java.util.Base64``.

    Deliberately conservative: this only decodes literals that (a)
    look like Base64 (length is a multiple of 4, only valid alphabet
    characters) and (b) produce valid UTF-8 when decoded — plenty of
    unrelated short constant-pool strings would otherwise coincidentally
    "successfully" base64-decode into garbage. Gating on a Base64 API
    call in the same method additionally avoids flooding evidence for
    every literal that happens to look base64-ish across the whole class.
    """
    results: list[ReconstructedString] = []
    bytecode = method.bytecode
    cp = class_file.constant_pool

    invokes = resolve_invokes(bytecode, cp, class_file.bootstrap_methods)
    uses_base64_api = any(inv.owner == "java/util/Base64" for inv in invokes)
    if not uses_base64_api:
        return results

    ldc_strings = extract_ldc_strings(bytecode, cp)
    for offset, val in ldc_strings:
        if not _looks_like_base64(val):
            continue
        try:
            decoded_bytes = base64.b64decode(val, validate=True)
            decoded = decoded_bytes.decode("utf-8")
        except Exception:
            continue
        if decoded and decoded != val:
            results.append(
                ReconstructedString(
                    method_name=method.name,
                    class_name=class_file.this_class,
                    offset=offset,
                    value=decoded,
                    technique="base64_string",
                )
            )

    return results


# Repeating-key length candidates tried for the generic XOR cipher, in
# ascending order (shortest first, since a shorter key that still
# produces plausible text is more likely correct — a longer key is
# more likely to spuriously "work" by chance on a short ciphertext).
# Bounded at 16: obfuscators overwhelmingly use very short XOR keys
# (single-byte to ~8 bytes); trying longer keys mostly just multiplies
# false-positive risk without matching realistic samples.
_XOR_KEY_LENGTH_CANDIDATES = range(1, 17)

# Minimum ciphertext length worth attempting generic XOR on at all —
# below this, garbage input decodes as "plausible text" by chance too
# often (e.g. a 2-byte array XORed with almost anything can look like
# a valid 2-character ASCII string).
_MIN_XOR_CIPHERTEXT_LENGTH = 6


def _extract_generic_xor_strings(
    method: MethodInfo,
    class_file: ClassFile,
) -> list[ReconstructedString]:
    """Detect a repeating-key XOR cipher where the key is itself a
    plain string/byte literal elsewhere in the same class — a much
    more common obfuscation shape in the wild than the specific
    weedhack S-box cipher, and one this scanner had no generic
    coverage for before (only that one specific, hand-matched family).

    Deliberately conservative to keep false positives low: only
    considered are byte arrays that did NOT already decode as clean
    UTF-8 (see :func:`_extract_byte_array_strings` — those are already
    handled, and are not further XORed here), only against short
    (<=32 byte) candidate keys already present as constant-pool
    literals in the same class, and the result must look like
    plausible readable text (:func:`_is_plausible_text`) or this
    reports nothing. This means it will miss ciphers where the key
    lives in a different class, is itself computed at runtime, or
    where the key is longer than 32 bytes — those require deeper
    dataflow analysis this scanner does not attempt.
    """
    results: list[ReconstructedString] = []
    bytecode = method.bytecode
    cp = class_file.constant_pool

    byte_arrays = extract_newarray_bytes(bytecode, cp)
    if not byte_arrays:
        return results

    # Candidate keys: every Utf8 constant-pool string short enough to
    # plausibly be a XOR key, encoded as bytes. Short strings meant as
    # normal text (e.g. "OK", "true") are unavoidably included too —
    # the plausibility check on the *decoded output* is what keeps
    # false positives down, not filtering the key candidates further.
    candidate_keys = [
        s.encode("utf-8")
        for s in cp.all_strings()
        if 1 <= len(s) <= 32
    ]
    if not candidate_keys:
        return results

    for offset, values in byte_arrays:
        ciphertext = bytes(v & 0xFF for v in values)
        if len(ciphertext) < _MIN_XOR_CIPHERTEXT_LENGTH:
            continue

        # Skip arrays _extract_byte_array_strings already accepted as
        # plausible plain text — those are not XOR-obfuscated, just
        # plain hidden strings, and re-reporting them here would be
        # pure noise. Checking _is_plausible_text (not just "decodes
        # without UnicodeDecodeError") matters: arbitrary ciphertext
        # bytes very often happen to be valid UTF-8 too (most
        # single-byte values are legal ASCII), so a bare decode
        # success does not mean this array is actually the hidden
        # plain string rather than still-encrypted ciphertext.
        try:
            plain_attempt = ciphertext.decode("utf-8")
            if _is_plausible_text(plain_attempt):
                continue  # already valid plain text — not an XOR cipher
        except UnicodeDecodeError:
            pass

        decoded = _try_xor_candidate_keys(ciphertext, candidate_keys)
        if decoded is not None:
            results.append(
                ReconstructedString(
                    method_name=method.name,
                    class_name=class_file.this_class,
                    offset=offset,
                    value=decoded,
                    technique="generic_xor_cipher",
                )
            )

    return results


def _try_xor_candidate_keys(
    ciphertext: bytes, candidate_keys: list[bytes]
) -> str | None:
    """Try each candidate key at each length in
    _XOR_KEY_LENGTH_CANDIDATES against *ciphertext*, returning the
    first plausible-looking decode, or None if nothing plausible was
    found. Trying key *lengths* rather than only whole candidate keys
    matters because obfuscators commonly derive the actual repeating
    key from a prefix/substring of a longer constant-pool string
    (e.g. a class name or a build identifier) rather than storing the
    exact key as its own literal.
    """
    seen_keys: set[bytes] = set()
    for key in candidate_keys:
        for key_len in _XOR_KEY_LENGTH_CANDIDATES:
            if key_len > len(key):
                break
            truncated = key[:key_len]
            if truncated in seen_keys:
                continue
            seen_keys.add(truncated)

            decoded_str = decode_simple_xor(ciphertext, truncated)
            if decoded_str and _is_plausible_text(decoded_str):
                return decoded_str

    return None


# A decoded XOR result is only reported if it looks like genuine
# readable text, not merely printable ASCII — a bare "printable
# characters only" check is far too permissive for a brute-force
# search: trying dozens of candidate keys against the same ciphertext
# means *something* printable-but-meaningless comes out almost every
# time (most single-byte XOR outputs land in the printable ASCII
# range purely by chance), so a weaker check reports the WRONG key's
# garbage before ever reaching the correct one. Requiring a majority
# of alphanumeric-or-space characters (as opposed to a scattershot of
# punctuation/symbols) is what actual URLs, hostnames, file paths, and
# words look like, and what random XOR noise overwhelmingly does not.
_PLAUSIBLE_TEXT_RE = re.compile(r'^[\x20-\x7E\t\n\r]+$')
_ALPHANUMERIC_OR_SPACE_RE = re.compile(r'[A-Za-z0-9 ./:_\-]')


def _is_plausible_text(s: str) -> bool:
    if len(s) < 4 or not _PLAUSIBLE_TEXT_RE.match(s):
        return False
    alnum_count = len(_ALPHANUMERIC_OR_SPACE_RE.findall(s))
    return (alnum_count / len(s)) >= 0.85


_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


def _looks_like_base64(s: str) -> bool:
    return len(s) >= 8 and len(s) % 4 == 0 and bool(_BASE64_RE.match(s))


def _push_int_value_public(instr: object, cp: object) -> int | None:
    """Local re-export of instructions._push_int_value.

    That helper is intentionally private to the instructions module
    (it is an implementation detail of array-literal extraction), but
    the weedhack cipher pattern above needs the same push-value
    resolution for the two trailing integer key arguments.
    """
    from mcrataway.parsers.instructions import _push_int_value

    return _push_int_value(instr, cp)  # type: ignore[arg-type]


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
