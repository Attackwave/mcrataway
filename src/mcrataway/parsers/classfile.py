"""Java .class file parser — pure Python, no external deps."""

import struct
from dataclasses import dataclass, field

from mcrataway.constants import (
    ACC_NATIVE,
    ACC_SYNTHETIC,
    JAVA_CLASS_MAGIC,
)
from mcrataway.parsers.constant_pool import ConstantPool


@dataclass
class FieldInfo:
    access_flags: int
    name: str
    descriptor: str
    is_synthetic: bool = False


@dataclass
class MethodInfo:
    access_flags: int
    name: str
    descriptor: str
    bytecode: bytes = b""
    max_stack: int = 0
    max_locals: int = 0
    is_native: bool = False
    is_synthetic: bool = False


@dataclass
class ClassFile:
    minor_version: int
    major_version: int
    constant_pool: ConstantPool
    access_flags: int
    this_class: str
    super_class: str
    interfaces: list[str]
    fields: list[FieldInfo]
    methods: list[MethodInfo]
    attributes: dict[str, bytes] = field(default_factory=dict)
    is_synthetic: bool = False


def parse_class(data: bytes) -> ClassFile | None:
    """Parse a .class file from bytes. Returns None on malformed input."""
    if len(data) < 8 or data[:4] != JAVA_CLASS_MAGIC:
        return None

    pos = 4
    try:
        minor, major = struct.unpack(">HH", data[pos : pos + 4])
        pos += 4

        cp_count = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        if cp_count > 65535 or cp_count < 1:
            return None

        constant_pool = ConstantPool()
        consumed = constant_pool.parse(data[pos:], cp_count)
        pos += consumed

        access_flags = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        this_class_idx = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        super_class_idx = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2

        iface_count = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        interfaces: list[str] = []
        for _ in range(iface_count):
            idx = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            interfaces.append(constant_pool.get_class_name(idx))

        field_count = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        fields: list[FieldInfo] = []
        for _ in range(field_count):
            af = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            ni = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            di = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            attrs_consumed = _skip_attributes(data, pos)
            pos += attrs_consumed
            fields.append(
                FieldInfo(
                    access_flags=af,
                    name=constant_pool.get_utf8(ni),
                    descriptor=constant_pool.get_utf8(di),
                    is_synthetic=bool(af & ACC_SYNTHETIC),
                )
            )

        method_count = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        methods: list[MethodInfo] = []
        for _ in range(method_count):
            af = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            ni = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2
            di = struct.unpack(">H", data[pos : pos + 2])[0]
            pos += 2

            method_name = constant_pool.get_utf8(ni)
            method_desc = constant_pool.get_utf8(di)
            is_native = bool(af & ACC_NATIVE)

            bytecode = b""
            max_stack = 0
            max_locals = 0

            if not is_native:
                attr_count = _safe_unpack(">H", data, pos)
                pos += 2
                for _ in range(attr_count):
                    name_idx = _safe_unpack(">H", data, pos)
                    pos += 2
                    attr_name = constant_pool.get_utf8(name_idx)
                    length = _safe_unpack(">I", data, pos)
                    pos += 4

                    if attr_name == "Code" and length > 0:
                        max_stack = _safe_unpack(">H", data, pos)
                        pos += 2
                        max_locals = _safe_unpack(">H", data, pos)
                        pos += 2
                        code_length = _safe_unpack(">I", data, pos)
                        pos += 4
                        bytecode = data[pos : pos + code_length]
                        pos += code_length

                        exc_count = _safe_unpack(">H", data, pos)
                        pos += 2 + exc_count * 8

                        code_attr_count = _safe_unpack(">H", data, pos)
                        pos += 2
                        for _ in range(code_attr_count):
                            consumed = _skip_one_attribute(data, pos)
                            pos += consumed
                    else:
                        pos += length
            else:
                consumed = _skip_attributes(data, pos)
                pos += consumed

            methods.append(
                MethodInfo(
                    access_flags=af,
                    name=method_name,
                    descriptor=method_desc,
                    bytecode=bytecode,
                    max_stack=max_stack,
                    max_locals=max_locals,
                    is_native=is_native,
                    is_synthetic=bool(af & ACC_SYNTHETIC),
                )
            )

        consumed = _skip_attributes(data, pos)
        pos += consumed

        return ClassFile(
            minor_version=minor,
            major_version=major,
            constant_pool=constant_pool,
            access_flags=access_flags,
            this_class=constant_pool.get_class_name(this_class_idx),
            super_class=constant_pool.get_class_name(super_class_idx),
            interfaces=interfaces,
            fields=fields,
            methods=methods,
            is_synthetic=bool(access_flags & ACC_SYNTHETIC),
        )

    except (struct.error, IndexError, KeyError, UnicodeDecodeError, ValueError):
        return None


def _safe_unpack(fmt: str, data: bytes, pos: int, default: int = 0) -> int:
    """Safe struct unpack that returns default on error."""
    try:
        size = struct.calcsize(fmt)
        if pos + size > len(data):
            return default
        result = struct.unpack(fmt, data[pos : pos + size])
        return int(result[0])
    except (struct.error, ValueError):
        return default


def _skip_one_attribute(data: bytes, pos: int) -> int:
    """Skip one attribute and return bytes consumed."""
    try:
        struct.unpack(">H", data[pos : pos + 2])[0]
        length = struct.unpack(">I", data[pos + 2 : pos + 6])[0]
        return int(6 + length)
    except (struct.error, IndexError):
        return 0


def _skip_attributes(data: bytes, pos: int) -> int:
    """Skip all attributes at current position. Returns bytes consumed."""
    try:
        count = struct.unpack(">H", data[pos : pos + 2])[0]
        pos += 2
        total = 2
        for _ in range(count):
            consumed = _skip_one_attribute(data, pos)
            pos += consumed
            total += consumed
        return total
    except (struct.error, IndexError):
        return 0
