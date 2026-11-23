"""Bounds-checked little/big-endian reads over an immutable byte buffer.

Binary parsers consume attacker-controlled offsets and counts. Every read
goes through here so a bad offset becomes a ParseError instead of an
IndexError, a silent wrap-around (negative index) or a short slice.
"""
from __future__ import annotations

import struct

from .errors import ParseError


class Reader:
    def __init__(self, data: bytes, little_endian: bool = True):
        self.data = data
        self.size = len(data)
        self.prefix = "<" if little_endian else ">"

    def bytes(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ParseError(
                f"read of {size} bytes at offset {offset:#x} is outside the file "
                f"({self.size:#x} bytes)"
            )
        return self.data[offset:offset + size]

    def unpack(self, fmt: str, offset: int) -> tuple:
        fmt = self.prefix + fmt
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > self.size:
            raise ParseError(
                f"read of {size} bytes at offset {offset:#x} is outside the file "
                f"({self.size:#x} bytes)"
            )
        return struct.unpack_from(fmt, self.data, offset)

    def u8(self, offset: int) -> int:
        return self.unpack("B", offset)[0]

    def u16(self, offset: int) -> int:
        return self.unpack("H", offset)[0]

    def u32(self, offset: int) -> int:
        return self.unpack("I", offset)[0]

    def u64(self, offset: int) -> int:
        return self.unpack("Q", offset)[0]

    def cstring(self, offset: int, limit: int = 4096) -> str:
        """NUL-terminated string starting at offset (at most `limit` bytes)."""
        if offset < 0 or offset >= self.size:
            raise ParseError(f"string offset {offset:#x} is outside the file")
        end = self.data.find(b"\0", offset, offset + limit)
        if end == -1:
            end = min(offset + limit, self.size)
        return self.data[offset:end].decode("utf-8", errors="replace")
