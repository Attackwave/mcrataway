"""Unit tests for classfile parser."""

import struct

from mcrataway.parsers.classfile import parse_class


def _build_class_raw(class_name: str, method_name: str, cp_strings: list[str]) -> bytes:
    """Build a minimal .class file with correct constant pool indices."""
    all_strings = [class_name, "java/lang/Object", method_name, "()V", "Code"] + cp_strings
    cp_count = len(all_strings) + 1

    pool = struct.pack(">H", cp_count)
    for s in all_strings:
        encoded = s.encode("utf-8")
        pool += struct.pack(">BH", 1, len(encoded)) + encoded

    bc = bytearray()
    for i in range(len(cp_strings)):
        bc += struct.pack(">BH", 19, 6 + i)
    bc += struct.pack(">B", 177)

    code_info = struct.pack(">HHI", 2, 2, len(bc)) + bytes(bc) + struct.pack(">HH", 0, 0)
    code_attr = struct.pack(">HI", 5, len(code_info)) + code_info
    method = struct.pack(">HHH", 0x0001, 3, 4) + struct.pack(">H", 1) + code_attr

    # Class structure: access, this_class, super_class, interfaces, fields,
    # methods, class_attrs
    body = struct.pack(">HHH", 0x0001, 1, 2)  # access, this_class, super_class
    body += struct.pack(">H", 0)  # interfaces_count
    body += struct.pack(">H", 0)  # fields_count
    body += struct.pack(">H", 1)  # methods_count
    body += method
    body += struct.pack(">H", 0)  # class_attrs_count

    return b"\xCA\xFE\xBA\xBE" + struct.pack(">HH", 0, 52) + pool + body


def test_parse_valid_class():
    data = _build_class_raw("com/test/Hello", "greet", ["hello"])
    parsed = parse_class(data)
    assert parsed is not None
    assert parsed.minor_version == 0
    assert parsed.major_version == 52
    assert len(parsed.methods) == 1
    assert parsed.methods[0].name == "greet"
    # Bytecode should contain the return instruction
    assert len(parsed.methods[0].bytecode) > 0
    assert struct.pack(">B", 177) in parsed.methods[0].bytecode


def test_parse_invalid_magic():
    assert parse_class(b"\xDE\xAD\xBE\xEF") is None
    assert parse_class(b"") is None
    assert parse_class(b"\xCA\xFE\xBA\xBE\x00") is None


def test_parse_constant_pool_strings():
    data = _build_class_raw("com/test/A", "m", ["url", "exec", "token"])
    parsed = parse_class(data)
    assert parsed is not None
    strings = parsed.constant_pool.all_strings()
    assert "url" in strings
    assert "exec" in strings
    assert "token" in strings


def test_parse_class_interfaces():
    """Test that interfaces list is parsed (even if empty)."""
    data = _build_class_raw("com/test/IFace", "run", [])
    parsed = parse_class(data)
    assert parsed is not None
    assert isinstance(parsed.interfaces, list)
