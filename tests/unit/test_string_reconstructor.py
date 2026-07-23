"""Unit tests for string reconstructor."""

import struct

from mcrataway.parsers.classfile import parse_class
from mcrataway.parsers.string_reconstructor import (
    decode_simple_xor,
    decode_xor_cipher,
    reconstruct_strings,
)


def _make_class_with_ldc(strings: list[str]) -> bytes:
    """Build a class with LDC string loads."""
    all_strings = ["com/test/A", "java/lang/Object", "m", "()V", "Code"] + strings
    pool = struct.pack(">H", len(all_strings) + 1)
    for s in all_strings:
        encoded = s.encode("utf-8")
        pool += struct.pack(">BH", 1, len(encoded)) + encoded

    # Build bytecode with ldc_w instructions (index 6+i in pool)
    bc = bytearray()
    for i in range(len(strings)):
        bc += struct.pack(">BH", 19, 6 + i)  # ldc_w
    bc += struct.pack(">B", 177)  # return

    code_info = struct.pack(">HHI", 2, 2, len(bc)) + bytes(bc) + struct.pack(">HH", 0, 0)
    code_attr = struct.pack(">HI", 5, len(code_info)) + code_info
    method = struct.pack(">HHH", 0x0001, 3, 4) + struct.pack(">H", 1) + code_attr
    body = struct.pack(">HHH", 0x0001, 1, 2)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 1) + method
    body += struct.pack(">H", 0)
    return b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 52) + pool + body


def test_reconstruct_ldc_strings():
    data = _make_class_with_ldc(["https://evil.com", "getToken", "session"])
    parsed = parse_class(data)
    assert parsed is not None
    results = reconstruct_strings(parsed)
    values = [r.value for r in results]
    assert "https://evil.com" in values
    assert "getToken" in values


def test_reconstruct_no_strings():
    """Class with no strings should return empty list."""
    all_strings = ["com/test/A", "java/lang/Object", "m", "()V", "Code"]
    pool = struct.pack(">H", len(all_strings) + 1)
    for s in all_strings:
        encoded = s.encode("utf-8")
        pool += struct.pack(">BH", 1, len(encoded)) + encoded

    bc = struct.pack(">B", 177)  # return
    code_info = struct.pack(">HHI", 1, 1, len(bc)) + bc + struct.pack(">HH", 0, 0)
    code_attr = struct.pack(">HI", 5, len(code_info)) + code_info
    method = struct.pack(">HHH", 0x0001, 3, 4) + struct.pack(">H", 1) + code_attr
    body = struct.pack(">HHH", 0x0001, 1, 2)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 1) + method
    body += struct.pack(">H", 0)
    data = b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 52) + pool + body

    parsed = parse_class(data)
    assert parsed is not None
    results = reconstruct_strings(parsed)
    # Only class/method/descriptor strings, no LDC strings
    ldc_results = [r for r in results if r.technique == "ldc_string"]
    assert len(ldc_results) == 0


def test_decode_xor_cipher():
    """Test the weedhack-style cipher decoder."""
    # Use valid parameters (k2 must be < 8 for bit rotation)
    result = decode_xor_cipher([1, 2, 3, 4], [5, 6, 7, 8], 42, 3)
    assert isinstance(result, str)


def test_decode_simple_xor():
    assert decode_simple_xor(b"\x00\x00\x00", b"key") == "key"[:3]
    assert decode_simple_xor(b"", b"key") == ""
