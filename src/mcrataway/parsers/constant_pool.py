"""Java class-file constant pool parser."""

import struct
from dataclasses import dataclass
from typing import Any

from mcrataway.constants import (
    CONSTANT_Class,
    CONSTANT_Double,
    CONSTANT_Fieldref,
    CONSTANT_Float,
    CONSTANT_Integer,
    CONSTANT_InterfaceMethodref,
    CONSTANT_InvokeDynamic,
    CONSTANT_Long,
    CONSTANT_MethodHandle,
    CONSTANT_Methodref,
    CONSTANT_MethodType,
    CONSTANT_NameAndType,
    CONSTANT_String,
    CONSTANT_Utf8,
)


@dataclass
class ConstantPoolEntry:
    """A single constant pool entry."""

    tag: int
    index: int
    value: Any = None
    name_index: int | None = None
    descriptor_index: int | None = None
    class_index: int | None = None
    string_index: int | None = None
    reference_kind: int | None = None
    reference_index: int | None = None
    name_and_type_index: int | None = None


class ConstantPool:
    """Parsed constant pool from a .class file."""

    def __init__(self) -> None:
        self.entries: dict[int, ConstantPoolEntry] = {}
        self._utf8_cache: dict[int, str] = {}

    def parse(self, data: bytes, count: int) -> int:
        """Parse count-1 entries from data starting at current position.
        Returns bytes consumed."""
        pos = 0
        i = 1
        while i < count:
            try:
                tag = struct.unpack(">B", data[pos : pos + 1])[0]
                pos += 1
                entry = ConstantPoolEntry(tag=tag, index=i)

                if tag == CONSTANT_Utf8:
                    length = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2
                    value = data[pos : pos + length].decode("utf-8", errors="replace")
                    pos += length
                    entry.value = value
                    self._utf8_cache[i] = value

                elif tag == CONSTANT_Integer:
                    entry.value = struct.unpack(">i", data[pos : pos + 4])[0]
                    pos += 4

                elif tag == CONSTANT_Float:
                    entry.value = struct.unpack(">f", data[pos : pos + 4])[0]
                    pos += 4

                elif tag == CONSTANT_Long:
                    entry.value = struct.unpack(">q", data[pos : pos + 8])[0]
                    pos += 8
                    self.entries[i] = entry
                    i += 2  # Long occupies two slots
                    continue

                elif tag == CONSTANT_Double:
                    entry.value = struct.unpack(">d", data[pos : pos + 8])[0]
                    pos += 8
                    self.entries[i] = entry
                    i += 2  # Double occupies two slots
                    continue

                elif tag == CONSTANT_Class:
                    entry.name_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2

                elif tag == CONSTANT_String:
                    entry.string_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2

                elif tag in (CONSTANT_Fieldref, CONSTANT_Methodref, CONSTANT_InterfaceMethodref):
                    entry.class_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2
                    entry.name_and_type_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2

                elif tag == CONSTANT_NameAndType:
                    entry.name_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2
                    entry.descriptor_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2

                elif tag == CONSTANT_MethodHandle:
                    entry.reference_kind = struct.unpack(">B", data[pos : pos + 1])[0]
                    pos += 1
                    entry.reference_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2

                elif tag == CONSTANT_MethodType:
                    entry.descriptor_index = struct.unpack(">H", data[pos : pos + 2])[0]
                    pos += 2

                elif tag == CONSTANT_InvokeDynamic:
                    pos += 4  # bootstrap_method_attr_index + name_and_type_index

                else:
                    return pos  # unknown tag, stop gracefully

                self.entries[i] = entry
                i += 1

            except (struct.error, IndexError, UnicodeDecodeError):
                return pos

        return pos

    def get_utf8(self, index: int) -> str:
        """Resolve a Utf8 constant by index."""
        if index in self._utf8_cache:
            return self._utf8_cache[index]
        entry = self.entries.get(index)
        if entry and entry.tag == CONSTANT_Utf8:
            self._utf8_cache[index] = entry.value or ""
            return entry.value or ""
        return ""

    def get_class_name(self, index: int) -> str:
        """Resolve a Class reference to its fully qualified name."""
        entry = self.entries.get(index)
        if entry and entry.tag == CONSTANT_Class:
            return self.get_utf8(entry.name_index or 0)
        return ""

    def get_string_literal(self, index: int) -> str:
        """Resolve a String constant to its value."""
        entry = self.entries.get(index)
        if entry and entry.tag == CONSTANT_String:
            return self.get_utf8(entry.string_index or 0)
        return ""

    def get_integer(self, index: int) -> int | None:
        """Resolve an Integer constant to its value, or None if not Integer."""
        entry = self.entries.get(index)
        if entry and entry.tag == CONSTANT_Integer and entry.value is not None:
            try:
                return int(entry.value)
            except (TypeError, ValueError):
                return None
        return None

    def resolve_method_ref(self, ref_index: int) -> tuple[str, str, str]:
        """Resolve a method/field reference to (owner, name, descriptor)."""
        entry = self.entries.get(ref_index)
        if not entry:
            return ("", "", "")

        class_name = self.get_class_name(entry.class_index or 0)
        nat_entry = self.entries.get(getattr(entry, "name_and_type_index", 0))
        if not nat_entry:
            return (class_name, "", "")

        name = self.get_utf8(nat_entry.name_index or 0)
        descriptor = self.get_utf8(nat_entry.descriptor_index or 0)
        return (class_name, name, descriptor)

    def all_strings(self) -> list[str]:
        """Return all Utf8 string values in the constant pool."""
        strings: list[str] = []
        for entry in self.entries.values():
            if entry.tag == CONSTANT_Utf8 and entry.value:
                strings.append(entry.value)
        return strings

    def all_string_literals(self) -> list[str]:
        """Return all String constant values."""
        strings: list[str] = []
        for entry in self.entries.values():
            if entry.tag == CONSTANT_String:
                s = self.get_string_literal(entry.index)
                if s:
                    strings.append(s)
        return strings
