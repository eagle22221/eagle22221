"""Quake / Quake II / Half-Life PAK.

    0   char magic[4] = "PACK"
    4   int32 directory offset
    8   int32 directory length in bytes (64 per entry)
    directory entry: char name[56] (NUL terminated), int32 offset, int32 size
"""
from __future__ import annotations

import struct
from typing import Any, BinaryIO, Iterator, List

from ..errors import ParseError, UnsupportedError
from ._base import Archive, ArchiveEntry, PlanItem, decode_name, range_chunks, read_at

_ENTRY = 64
_NAME = 56
_MAX_OFFSET = 0x7FFFFFFF        # the engine reads offsets as signed 32-bit


class PakArchive(Archive):
    format = "quake-pak"

    @staticmethod
    def matches(head: bytes, fh: BinaryIO, size: int) -> bool:
        return head[:4] == b"PACK"

    def _load(self, fh: BinaryIO, size: int, head: bytes) -> None:
        if len(head) < 12:
            raise ParseError("truncated PAK header")
        dir_offset, dir_len = struct.unpack_from("<II", head, 4)
        if dir_len % _ENTRY:
            raise ParseError(
                f"PAK directory length {dir_len} is not a multiple of {_ENTRY} "
                "(not a Quake PAK, or corrupt)")
        if dir_offset < 12 or dir_offset + dir_len > size:
            raise ParseError(
                f"PAK directory at offset {dir_offset:#x} (+{dir_len} bytes) is outside "
                f"the file ({size} bytes)")
        count = dir_len // _ENTRY
        self._check_count(count)
        table = read_at(fh, dir_offset, dir_len, size, "PAK directory")
        for i in range(count):
            base = i * _ENTRY
            raw = table[base:base + _NAME].split(b"\0", 1)[0]
            offset, length = struct.unpack_from("<II", table, base + _NAME)
            broken = None
            if offset + length > size:
                broken = (f"data at offset {offset:#x} (+{length} bytes) is outside "
                          f"the file ({size} bytes)")
            self._add(ArchiveEntry(decode_name(raw), length, offset, False, False),
                      (raw, offset, length), broken)
        self._finish()

    def _chunks(self, handle: Any, index: int) -> Iterator[bytes]:
        _raw, offset, length = self._records[index]
        return range_chunks(handle, offset, length, repr(self.entries[index].name))

    def _check_new_name(self, name: str) -> None:
        super()._check_new_name(name)
        if len(name.encode("utf-8")) > _NAME - 1:
            raise UnsupportedError(
                f"PAK entry names are limited to {_NAME - 1} bytes: {name!r}")

    def _write(self, handle: Any, out: BinaryIO, plan: List[PlanItem]) -> None:
        out.write(bytes(12))
        position = 12
        directory = []
        for item in plan:
            raw = self._records[item.index][0] if item.index is not None \
                else item.name.encode("utf-8")
            if item.data is not None:
                out.write(item.data)
                length = len(item.data)
            else:
                length = self._copy_entry(handle, item.index, out)
            directory.append(raw.ljust(_NAME, b"\0") + struct.pack("<II", position, length))
            position += length
            if position > _MAX_OFFSET:
                raise UnsupportedError("PAK archives cannot exceed 2 GiB (32-bit offsets)")
        out.write(b"".join(directory))
        out.seek(0)
        out.write(b"PACK" + struct.pack("<II", position, len(directory) * _ENTRY))
