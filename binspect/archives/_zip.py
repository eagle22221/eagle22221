"""ZIP family (.zip .pk3 .pk4 .love .jar .apk .kpf ...), read and written with
the standard library's zipfile. A ZIP appended to another file (a LÖVE game
fused to its executable, a self-extractor, a launch4j-wrapped JAR) is found
through the end-of-central-directory record, as zipfile itself does.

Encrypted entries (ZipCrypto, WinZip AES) are reported and never decrypted.
"""
from __future__ import annotations

import os
import struct
import time
import zipfile
import zlib
from typing import Any, BinaryIO, Iterator, List, NamedTuple, Optional

from ..errors import ParseError, UnsupportedError
from ._base import CHUNK, Archive, ArchiveEntry, PlanItem, copy_range, limit

_EOCD = b"PK\x05\x06"
_EOCD_SIZE = 22
_LOCATOR64_SIZE = 20
_EOCD64_SIZE = 56
_CENTRAL_MIN = 46               # a central directory header without name/extra/comment
_ZIP64_LIMIT = 0x7FFFFFFF
# Deflate cannot expand by more than 1032:1; a header claiming more is lying.
_DEFLATE_MAX_RATIO = 1032

# Everything zipfile (and the codecs under it) is known to raise on bad input.
_ZIP_ERRORS = (zipfile.BadZipFile, zipfile.LargeZipFile, struct.error, zlib.error,
               ValueError, EOFError, IndexError, KeyError, OverflowError,
               UnicodeError, RecursionError, MemoryError, AttributeError, TypeError)


class _Tail(NamedTuple):
    eocd: int           # file offset of the end-of-central-directory record
    cd_start: int       # where the central directory really starts in the file
    cd_size: int
    cd_offset: int      # where the record says it starts (relative to the ZIP data)
    count: int


def zip_tail(fh: BinaryIO, size: int) -> Optional[_Tail]:
    """Locate and sanity-check the end-of-central-directory record, reading
    at most the last 64 KiB of the file."""
    if size < _EOCD_SIZE:
        return None
    span = min(size, _EOCD_SIZE + 0xFFFF)
    fh.seek(size - span)
    tail = fh.read(span)
    at = tail.rfind(_EOCD)
    if at < 0 or at + _EOCD_SIZE > len(tail):
        return None
    eocd = size - span + at
    _disk, _cd_disk, _here, count, cd_size, cd_offset, _comment = \
        struct.unpack_from("<4H2LH", tail, at + 4)
    cd_end = eocd
    if eocd >= _LOCATOR64_SIZE + _EOCD64_SIZE:
        fh.seek(eocd - _LOCATOR64_SIZE - _EOCD64_SIZE)
        zip64 = fh.read(_EOCD64_SIZE + _LOCATOR64_SIZE)
        if zip64[:4] == b"PK\x06\x06" and zip64[_EOCD64_SIZE:_EOCD64_SIZE + 4] == b"PK\x06\x07":
            count, _count_total, cd_size, cd_offset = struct.unpack_from("<4Q", zip64, 24)
            cd_end = eocd - _LOCATOR64_SIZE - _EOCD64_SIZE
    cd_start = cd_end - cd_size
    if cd_start < 0:
        return None
    if cd_size:
        fh.seek(cd_start)
        if fh.read(4) != b"PK\x01\x02":
            return None
    elif count:
        return None
    return _Tail(eocd, cd_start, cd_size, cd_offset, count)


class _RawNameInfo(zipfile.ZipInfo):
    """A ZipInfo that writes its name with the exact bytes of the source
    entry. zipfile re-encodes non-ASCII names as UTF-8, which changes the
    bytes of names stored in a legacy code page (Shift-JIS, cp437, ...) that
    a game looks up byte for byte."""

    def _encodeFilenameFlags(self):          # noqa: N802 (zipfile's internal name)
        return self._raw_name, self.flag_bits


def _strip_zip64_extra(extra: bytes) -> bytes:
    """Drop ZIP64 extended-information fields (id 1): zipfile adds its own."""
    out, pos = b"", 0
    while pos + 4 <= len(extra):
        kind, length = struct.unpack_from("<HH", extra, pos)
        if kind != 1:
            out += extra[pos:pos + 4 + length]
        pos += 4 + length
    return out


def _clone(info: zipfile.ZipInfo) -> zipfile.ZipInfo:
    """A fresh header carrying the metadata of a source entry."""
    date_time = info.date_time if info.date_time[0] >= 1980 else (1980, 1, 1, 0, 0, 0)
    legacy = not info.flag_bits & 0x800 and not info.orig_filename.isascii()
    if legacy:
        new: zipfile.ZipInfo = _RawNameInfo(info.filename, date_time)
        new._raw_name = info.orig_filename.encode("cp437")      # type: ignore[attr-defined]
    else:
        new = zipfile.ZipInfo(info.filename, date_time)
    new.compress_type = info.compress_type
    new.comment = info.comment
    new.extra = _strip_zip64_extra(info.extra)
    new.create_system = info.create_system
    new.external_attr = info.external_attr
    new.internal_attr = info.internal_attr
    return new


class _Rebased:
    """A view of a file whose position 0 is `base` bytes in. zipfile writes
    the offsets it sees, so the result is a ZIP with offsets relative to the
    start of the ZIP data: exactly what `cat stub.exe game.zip` produces."""

    def __init__(self, fh: BinaryIO, base: int):
        self._fh, self._base = fh, base

    def tell(self) -> int:
        return self._fh.tell() - self._base

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            return self._fh.seek(offset + self._base) - self._base
        return self._fh.seek(offset, whence) - self._base

    def write(self, data) -> int:
        return self._fh.write(data)

    def read(self, size: int = -1) -> bytes:
        return self._fh.read(size)

    def flush(self) -> None:
        self._fh.flush()

    def seekable(self) -> bool:
        return True

    def close(self) -> None:
        pass


class ZipArchive(Archive):
    format = "zip"

    @staticmethod
    def matches(head: bytes, fh: BinaryIO, size: int) -> bool:
        return head[:4] in (b"PK\x03\x04", _EOCD) or zip_tail(fh, size) is not None

    def _load(self, fh: BinaryIO, size: int, head: bytes) -> None:
        tail = zip_tail(fh, size)
        if tail is None:
            raise ParseError(
                "ZIP end-of-central-directory record is missing or inconsistent "
                "(truncated or corrupt archive)")
        maximum = limit("MAX_ENTRIES")
        if max(tail.count, tail.cd_size // _CENTRAL_MIN) > maximum:
            raise UnsupportedError(
                f"ZIP central directory describes more than "
                f"binspect.archives.MAX_ENTRIES ({maximum}) entries")
        self._size = size
        self._relative = tail.cd_start != tail.cd_offset
        self._positions: List[int] = []
        with self._session() as zf:
            infos = zf.infolist()
            self._check_count(len(infos))
            for position, info in enumerate(infos):
                if info.is_dir():
                    continue
                broken = self._implausible(info)
                self._positions.append(position)
                self._add(ArchiveEntry(info.filename, info.file_size, None,
                                       info.compress_type != zipfile.ZIP_STORED,
                                       bool(info.flag_bits & 0x1)),
                          (position, info.orig_filename), broken)
            self._prefix = min((i.header_offset for i in infos), default=tail.cd_start)
        self._prefix = max(0, min(self._prefix, size))
        if self._prefix:
            if head[:2] == b"MZ" or head[:4] == b"\x7fELF":
                self.notes.append(f"embedded in executable at offset {self._prefix:#x}")
            else:
                self.notes.append(
                    f"ZIP data starts at offset {self._prefix:#x}, after "
                    f"{self._prefix} bytes of other data (kept on repack)")
        lower = self.path.lower()
        if lower.endswith((".apk", ".aab", ".xapk")):
            self.notes.append(
                "Android package: a repacked APK is unsigned and unaligned; run "
                "zipalign and apksigner on it before installing")
        elif any(e.name.upper().startswith("META-INF/") and e.name.upper().endswith(
                (".SF", ".RSA", ".DSA", ".EC")) for e in self.entries):
            self.notes.append(
                "signed JAR: signature files in META-INF/ no longer match after a "
                "repack; remove them or re-sign")
        self._finish()

    def _implausible(self, info: zipfile.ZipInfo) -> Optional[str]:
        if info.flag_bits & 0x1:
            return None
        if info.compress_size > self._size:
            return (f"claims {info.compress_size} bytes of stored data in a "
                    f"{self._size}-byte file")
        if info.compress_type == zipfile.ZIP_STORED and info.file_size != info.compress_size:
            return (f"stored (uncompressed) entry claims {info.file_size} bytes but "
                    f"holds {info.compress_size}")
        if info.compress_type == zipfile.ZIP_DEFLATED and \
                info.file_size > info.compress_size * _DEFLATE_MAX_RATIO + 1024:
            return (f"claims {info.file_size} bytes from {info.compress_size} bytes of "
                    "deflate data, more than deflate can produce")
        return None

    # -- reading ---------------------------------------------------------------

    def _open_handle(self) -> zipfile.ZipFile:
        try:
            return zipfile.ZipFile(self.path, "r")
        except (FileNotFoundError, PermissionError, IsADirectoryError):
            raise
        except NotImplementedError as exc:
            raise UnsupportedError(f"unsupported ZIP feature: {exc}") from None
        except _ZIP_ERRORS + (OSError,) as exc:
            raise ParseError(f"corrupt ZIP archive: {exc}") from None

    def _info(self, zf: zipfile.ZipFile, index: int) -> zipfile.ZipInfo:
        position, orig_name = self._records[index]
        infos = zf.infolist()
        if position >= len(infos) or infos[position].orig_filename != orig_name:
            raise ParseError(f"{self.path} changed on disk since it was opened")
        return infos[position]

    def _chunks(self, handle: zipfile.ZipFile, index: int) -> Iterator[bytes]:
        info = self._info(handle, index)
        name = self.entries[index].name
        try:
            with handle.open(info) as member:
                while True:
                    chunk = member.read(CHUNK)
                    if not chunk:
                        break
                    yield chunk
        except NotImplementedError as exc:
            raise UnsupportedError(f"{name!r}: {exc}") from None
        except RuntimeError as exc:
            raise UnsupportedError(f"{name!r}: {exc}") from None
        except _ZIP_ERRORS + (OSError,) as exc:
            raise ParseError(f"{name!r}: corrupt ZIP entry: {exc}") from None

    # -- writing ---------------------------------------------------------------

    def _write(self, handle: zipfile.ZipFile, out: BinaryIO, plan: List[PlanItem]) -> None:
        infos = handle.infolist()
        if self._prefix:
            with open(self.path, "rb") as source:
                copy_range(source, out, 0, self._prefix, "data before the ZIP")
        target: Any = _Rebased(out, self._prefix) if self._relative and self._prefix else out
        by_position = {self._positions[item.index]: item
                       for item in plan if item.index is not None}
        files = [i for i in infos if not i.is_dir()]
        stored_only = bool(files) and all(i.compress_type == zipfile.ZIP_STORED for i in files)
        try:
            with zipfile.ZipFile(target, "w", allowZip64=True) as dst:
                dst.comment = handle.comment
                for position, info in enumerate(infos):
                    if info.is_dir():
                        dst.writestr(_clone(info), b"")
                        continue
                    item = by_position.get(position)
                    if item is None:
                        continue                    # removed
                    new = _clone(info)
                    if item.data is not None:
                        self._store(dst, new, item.data)
                    else:
                        size = self.entries[item.index].size
                        with dst.open(new, "w", force_zip64=size >= _ZIP64_LIMIT) as member:
                            self._copy_entry(handle, item.index, member)
                for item in plan:
                    if item.index is not None:
                        continue
                    new = zipfile.ZipInfo(item.name, time.localtime()[:6])
                    new.compress_type = zipfile.ZIP_STORED if stored_only \
                        else zipfile.ZIP_DEFLATED
                    new.external_attr = 0o644 << 16
                    self._store(dst, new, item.data or b"")
        except NotImplementedError as exc:
            raise UnsupportedError(f"cannot write this ZIP: {exc}") from None
        except _ZIP_ERRORS as exc:
            raise ParseError(f"cannot rewrite ZIP archive: {exc}") from None

    @staticmethod
    def _store(dst: zipfile.ZipFile, info: zipfile.ZipInfo, data: bytes) -> None:
        with dst.open(info, "w", force_zip64=len(data) >= _ZIP64_LIMIT) as member:
            member.write(data)
