"""Godot PCK ("GDPC"), written from the engine's own reader and writer
(core/io/file_access_pack.cpp, editor/export/editor_export_platform.cpp).

    0    "GDPC"
    4    u32 pack format: 1 = Godot 3.x, 2 = Godot 4.0-4.4, 3 = Godot 4.5+
    8    u32 engine major, minor, patch
    20   format 2+: u32 pack flags (1 = directory encrypted, 2 = file base is
         relative to the pack start, 4 = sparse bundle), u64 file base
         format 3:  u64 directory offset (relative to the pack start)
    ...  16 reserved u32
    ...  u32 file count, then per file:
           u32 path length (padded to 4 with NULs), path ("res://...")
           u64 offset   format 1: absolute in the file
                        format 2+: relative to the file base
           u64 size, 16 bytes MD5
           format 2+: u32 flags (1 = encrypted, 2 = removal marker)

A pack embedded in an executable is the same structure followed by
u64 pack size + "GDPC" at the very end of the file; the pack starts at
file size - 12 - pack size. Format 1 offsets, and the format 2 file base
without the relative flag, are then absolute offsets in the executable.

Encrypted directories and files are detected and reported, never decrypted.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Any, BinaryIO, Iterator, List, NamedTuple, Optional

from ..errors import ParseError, UnsupportedError
from ._base import (
    Archive, ArchiveEntry, PlanItem, copy_range, limit, range_chunks, read_at,
)

MAGIC = b"GDPC"
PACK_DIR_ENCRYPTED, PACK_REL_FILEBASE, PACK_SPARSE_BUNDLE = 1, 2, 4
FILE_ENCRYPTED, FILE_REMOVAL = 1, 2
_ALIGN = 16                     # PCK_PADDING in the exporter
_MAX_PATH = 4096
_FOOTER = 12
_EXE_MAGICS = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


class _File(NamedTuple):
    raw: bytes          # path bytes exactly as stored (without NUL padding)
    offset: int         # absolute offset in the container
    size: int
    md5: bytes
    flags: int


def find_pack(head: bytes, fh: BinaryIO, size: int) -> Optional[int]:
    """Offset of the pack: 0 for a .pck file, or the start of a pack embedded
    at the end of an executable. None if there is neither."""
    if head[:4] == MAGIC:
        return 0
    if size < _FOOTER + 20:
        return None
    fh.seek(size - _FOOTER)
    tail = fh.read(_FOOTER)
    if tail[8:] != MAGIC:
        return None
    start = size - _FOOTER - struct.unpack("<Q", tail[:8])[0]
    if start <= 0 or start + 20 > size - _FOOTER:
        return None
    fh.seek(start)
    return start if fh.read(4) == MAGIC else None


def _md5(data: bytes) -> bytes:
    try:
        return hashlib.md5(data, usedforsecurity=False).digest()
    except (TypeError, ValueError):         # MD5 unavailable (FIPS builds)
        return bytes(16)


class PckArchive(Archive):
    format = "godot-pck"

    @staticmethod
    def matches(head: bytes, fh: BinaryIO, size: int) -> bool:
        return find_pack(head, fh, size) is not None

    def _load(self, fh: BinaryIO, size: int, head: bytes) -> None:
        start = find_pack(head, fh, size)
        if start is None:
            raise ParseError("Godot pack signature not found")
        self._start, self._size = start, size
        self._head = read_at(fh, start, 20, size, "PCK header")
        fmt, major, minor, patch = struct.unpack_from("<4I", self._head, 4)
        self._fmt = fmt
        if fmt not in (1, 2, 3):
            raise UnsupportedError(
                f"Godot pack format version {fmt} is not supported (vex reads "
                "formats 1 to 3, Godot 3.x and 4.x)")
        pos = start + 20
        self._flags, file_base = 0, 0
        if fmt >= 2:
            self._flags, file_base = struct.unpack(
                "<IQ", read_at(fh, pos, 12, size, "PCK header"))
            pos += 12
            if fmt == 3 or self._flags & PACK_REL_FILEBASE:
                file_base += start
        if fmt == 3:
            (dir_offset,) = struct.unpack("<Q", read_at(fh, pos, 8, size, "PCK header"))
            pos = start + dir_offset
            self._reserved = b""
        else:
            self._reserved = read_at(fh, pos, 64, size, "PCK header")
            pos += 64
        if self._flags & PACK_DIR_ENCRYPTED:
            raise UnsupportedError(
                "the index (directory) of this Godot pack is encrypted with a key "
                "compiled into the game; vex does not decrypt packs or recover keys")
        if self._flags & PACK_SPARSE_BUNDLE:
            raise UnsupportedError(
                "this Godot pack is a sparse bundle (file data is stored outside the "
                "pack), which vex does not support")

        (count,) = struct.unpack("<I", read_at(fh, pos, 4, size, "PCK file count"))
        pos += 4
        fixed = 32 if fmt == 1 else 36
        if count * (4 + fixed) > size - pos:
            raise ParseError(
                f"Godot pack declares {count} files but only {size - pos} bytes follow "
                "its header")
        self._check_count(count, "files")
        directory_start = pos
        removals = 0
        for _ in range(count):
            (length,) = struct.unpack("<I", read_at(fh, pos, 4, size, "PCK directory"))
            if length > _MAX_PATH:
                raise ParseError(f"Godot pack path length {length} is implausible")
            row = read_at(fh, pos + 4, length + fixed, size, "PCK directory")
            pos += 4 + length + fixed
            if pos - directory_start > limit("MAX_INDEX_SIZE"):
                raise UnsupportedError("Godot pack directory exceeds vex.archives.MAX_INDEX_SIZE")
            raw = row[:length].split(b"\0", 1)[0]
            offset, length_, = struct.unpack_from("<QQ", row, length)
            md5 = row[length + 16:length + 32]
            flags = struct.unpack_from("<I", row, length + 32)[0] if fmt >= 2 else 0
            if fmt >= 2:
                offset += file_base
            name = raw.decode("utf-8", errors="replace")
            if name.startswith("res://"):
                name = name[6:]
            broken = None
            if offset + length_ > size:
                broken = (f"data at offset {offset:#x} (+{length_} bytes) is outside "
                          f"the file ({size} bytes)")
            removals += bool(flags & FILE_REMOVAL)
            self._add(ArchiveEntry(name, length_, offset, False, bool(flags & FILE_ENCRYPTED)),
                      _File(raw, offset, length_, md5, flags), broken)
        if fmt == 2 and self.entries and pos > file_base:
            raise ParseError(
                "Godot pack directory runs past the start of the file data "
                "(file count or file base is corrupt)")

        self._embedded = start > 0
        self.notes.append(f"Godot {major}.{minor}.{patch}, pack format {fmt}")
        if self._embedded:
            kind = "executable" if head.startswith(_EXE_MAGICS) else "file"
            self.notes.append(f"embedded in {kind} at offset {start:#x}")
            self.notes.append(
                "repacking writes a copy of the whole file with the new pack and a "
                "corrected footer in place of the old one (a code signature on the "
                "executable, if any, will no longer match)")
        if removals:
            self.notes.append(f"{removals} entries are removal markers of a patch pack")
        if fmt == 3:
            self._read_only(
                "pack format 3 (Godot 4.5+) is read-only in vex: listing and "
                "extraction work, repacking is not implemented")
        self._finish()

    def _chunks(self, handle: Any, index: int) -> Iterator[bytes]:
        record: _File = self._records[index]
        return range_chunks(handle, record.offset, record.size,
                            repr(self.entries[index].name))

    def _check_new_name(self, name: str) -> None:
        super()._check_new_name(name)
        if len(name.encode("utf-8")) + 6 > _MAX_PATH:
            raise UnsupportedError(f"path too long for a Godot pack: {name!r}")

    def _write(self, handle: Any, out: BinaryIO, plan: List[PlanItem]) -> None:
        start, fmt = self._start, self._fmt
        if start:
            copy_range(handle, out, 0, start, "data before the pack")
        records: List[_File] = self._records
        prefixed = not records or any(r.raw.startswith(b"res://") for r in records)
        paths = [records[item.index].raw if item.index is not None
                 else (b"res://" if prefixed else b"") + item.name.encode("utf-8")
                 for item in plan]
        fixed = 32 if fmt == 1 else 36
        header_size = 88 if fmt == 1 else 100
        directory_size = sum(4 + len(p) + (-len(p) % 4) + fixed for p in paths)
        # File data starts at a multiple of 16 counted from the start of the
        # file, as in the exporter, and every file is padded to 16.
        data_base = start + header_size + directory_size
        data_base += -data_base % _ALIGN

        out.seek(data_base)
        position = data_base
        rows = []
        for item, raw in zip(plan, paths):
            if item.data is not None:
                out.write(item.data)
                length, md5 = len(item.data), _md5(item.data)
                flags = records[item.index].flags if item.index is not None else 0
            else:
                length = self._copy_entry(handle, item.index, out)
                md5, flags = records[item.index].md5, records[item.index].flags
            rows.append((raw, position, length, md5, flags))
            position += length
            padding = -position % _ALIGN
            out.write(bytes(padding))
            position += padding
        if self._embedded:
            # Never let the file get shorter: the executable may carry a
            # section header ("pck") that still describes the old extent.
            padding = max(-(position - start) % 8, self._size - _FOOTER - position)
            padding += -(position + padding - start) % 8
            out.write(bytes(padding))
            position += padding
            out.write(struct.pack("<Q", position - start) + MAGIC)

        out.seek(start)
        out.write(self._head)
        if fmt == 2:
            stored = data_base - start if self._flags & PACK_REL_FILEBASE else data_base
            out.write(struct.pack("<IQ", self._flags, stored))
        out.write(self._reserved + struct.pack("<I", len(rows)))
        for raw, offset, length, md5, flags in rows:
            padding = -len(raw) % 4
            out.write(struct.pack("<I", len(raw) + padding) + raw + bytes(padding))
            out.write(struct.pack("<QQ", offset if fmt == 1 else offset - data_base, length))
            out.write(md5)
            if fmt >= 2:
                out.write(struct.pack("<I", flags))
