"""Doom WAD (IWAD / PWAD).

    0   char magic[4] = "IWAD" or "PWAD"
    4   int32 lump count
    8   int32 directory offset
    directory entry: int32 offset, int32 size, char name[8] (NUL padded)

Lump names are not paths and are not unique: every map has a THINGS lump, and
zero-length marker lumps (MAP01, S_START, ...) give the following lumps their
meaning. Order therefore matters and is always preserved; repeated names are
listed as NAME#2, NAME#3, ...
"""
from __future__ import annotations

import struct
from typing import Any, BinaryIO, Iterator, List

from ..errors import ParseError, UnsupportedError
from ._base import Archive, ArchiveEntry, PlanItem, range_chunks, read_at

_ENTRY = 16
_MAX_OFFSET = 0x7FFFFFFF
_PLAIN = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-+.#[]")


class WadArchive(Archive):
    format = "doom-wad"

    @staticmethod
    def matches(head: bytes, fh: BinaryIO, size: int) -> bool:
        return head[:4] in (b"IWAD", b"PWAD")

    def _load(self, fh: BinaryIO, size: int, head: bytes) -> None:
        if len(head) < 12:
            raise ParseError("truncated WAD header")
        self._magic = head[:4]
        count, dir_offset = struct.unpack_from("<II", head, 4)
        if count > _MAX_OFFSET:
            raise ParseError(f"WAD lump count {count - (1 << 32)} is negative")
        if dir_offset < 12 or dir_offset + count * _ENTRY > size:
            raise ParseError(
                f"WAD directory at offset {dir_offset:#x} ({count} lumps) is outside "
                f"the file ({size} bytes)")
        self._check_count(count, "lumps")
        table = read_at(fh, dir_offset, count * _ENTRY, size, "WAD directory")
        for i in range(count):
            offset, length = struct.unpack_from("<II", table, i * _ENTRY)
            raw = table[i * _ENTRY + 8:i * _ENTRY + 16].split(b"\0", 1)[0]
            broken = None
            if length and offset + length > size:
                broken = (f"data at offset {offset:#x} (+{length} bytes) is outside "
                          f"the file ({size} bytes)")
            self._add(ArchiveEntry(raw.decode("latin-1"), length,
                                   offset if length else None, False, False),
                      (raw, offset, length), broken)
        self.notes.append(
            f"{self._magic.decode('ascii')}: lump order is significant (markers, maps) "
            "and is preserved; additions are appended at the end")
        self._finish()

    def _chunks(self, handle: Any, index: int) -> Iterator[bytes]:
        _raw, offset, length = self._records[index]
        if not length:
            return iter(())
        return range_chunks(handle, offset, length, repr(self.entries[index].name))

    def _extract_name(self, index: int) -> str:
        """Lump names may hold any byte ('\\' is a real sprite frame letter):
        everything that is not a plain file-name character is %XX-escaped."""
        name = self.entries[index].name
        out = "".join(c if c in _PLAIN else "%%%02X" % ord(c) for c in name)
        if out in ("", ".", ".."):
            out = "".join("%%%02X" % ord(c) for c in name) or "%00"
        return out

    def _check_new_name(self, name: str) -> None:
        try:
            raw = name.encode("latin-1")
        except UnicodeEncodeError:
            raw = b""
        if not 1 <= len(raw) <= 8 or b"\0" in raw or name != name.upper():
            raise UnsupportedError(
                f"WAD lump names are 1 to 8 upper-case Latin-1 characters: {name!r}")

    def _write(self, handle: Any, out: BinaryIO, plan: List[PlanItem]) -> None:
        out.write(bytes(12))
        position = 12
        directory = []
        for item in plan:
            raw = self._records[item.index][0] if item.index is not None \
                else item.name.encode("latin-1")
            if item.data is not None:
                out.write(item.data)
                length = len(item.data)
            else:
                length = self._copy_entry(handle, item.index, out)
            directory.append(struct.pack("<II", position if length else 0, length)
                             + raw.ljust(8, b"\0"))
            position += length
            if position > _MAX_OFFSET:
                raise UnsupportedError("WAD files cannot exceed 2 GiB (32-bit offsets)")
        out.write(b"".join(directory))
        out.seek(0)
        out.write(self._magic + struct.pack("<II", len(directory), position))
