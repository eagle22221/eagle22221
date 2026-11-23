"""Ren'Py RPA-2.0 / RPA-3.0, written from Ren'Py's loader and archiver
(renpy/loader.py, launcher/game/archiver.rpy).

    RPA-3.0:  b"RPA-3.0 %016x %08x\\n" % (index offset, key)
    RPA-2.0:  b"RPA-2.0 %016x\\n" % index offset

The index is zlib(pickle({name: [(offset, length[, prefix])]})); in RPA-3.0
offset and length are XORed with the key. File data sits between the header
and the index.

The index is a *pickle*, i.e. a program for Python's unpickler. It is loaded
with an unpickler that refuses every global, so it can only ever build
dicts, lists, tuples, strings, bytes and numbers; the result is then checked
for exactly the shape above.
"""
from __future__ import annotations

import io
import pickle
import re
import zlib
from typing import Any, BinaryIO, Iterator, List, NamedTuple, Tuple

from ..errors import ParseError, UnsupportedError
from ._base import Archive, ArchiveEntry, PlanItem, decode_name, limit, range_chunks, read_at

_ANY = re.compile(rb"RPA-\d+\.\d+ ")
# Ren'Py itself slices the header at fixed positions ([8:24] and [25:33]).
_V3 = re.compile(rb"RPA-3\.0 ([0-9a-fA-F]{16}).([0-9a-fA-F]{8})", re.DOTALL)
_V2 = re.compile(rb"RPA-2\.0 ([0-9a-fA-F]{16})")
_MAX_SEGMENTS = 4096


class _Forbidden(pickle.UnpicklingError):
    pass


class _IndexUnpickler(pickle.Unpickler):
    """Unpickler for untrusted RPA indexes: no global may be resolved, so no
    class can be instantiated and no function can be called."""

    def find_class(self, module: str, name: str) -> Any:
        raise _Forbidden(f"the Python global {module}.{name}")

    def persistent_load(self, pid: Any) -> Any:
        raise _Forbidden("a persistent object")


def _unpickle(data: bytes) -> Any:
    try:
        return _IndexUnpickler(io.BytesIO(data), fix_imports=False, encoding="bytes").load()
    except _Forbidden as exc:
        raise ParseError(
            f"RPA index is not plain data: it references {exc}. Refusing to load it "
            "(a pickle that needs globals can run arbitrary code)") from None
    except Exception as exc:        # the unpickler raises nearly anything on bad input
        raise ParseError(f"corrupt RPA index: {type(exc).__name__}: {exc}") from None


class _Segment(NamedTuple):
    offset: int
    length: int         # bytes this segment contributes, prefix included
    prefix: bytes


class RpaArchive(Archive):
    format = "renpy-rpa"

    @staticmethod
    def matches(head: bytes, fh: BinaryIO, size: int) -> bool:
        return _ANY.match(head) is not None

    def _load(self, fh: BinaryIO, size: int, head: bytes) -> None:
        version = head[:7].decode("ascii", "replace")
        if version == "RPA-3.0":
            match = _V3.match(head)
            if not match:
                raise ParseError("malformed RPA-3.0 header (index offset or key is not hex)")
            index_offset, self._key = int(match.group(1), 16), int(match.group(2), 16)
            self._header_size = 34
        elif version == "RPA-2.0":
            match = _V2.match(head)
            if not match:
                raise ParseError("malformed RPA-2.0 header (index offset is not hex)")
            index_offset, self._key = int(match.group(1), 16), 0
            self._header_size = 25
        else:
            raise UnsupportedError(
                f"{version} archives are not supported (only RPA-2.0 and RPA-3.0); a "
                "different version usually means the developer changed the format")
        self._version = version
        if not self._header_size - 1 <= index_offset < size:
            raise ParseError(
                f"RPA index offset {index_offset:#x} is outside the file ({size} bytes)")
        maximum = limit("MAX_INDEX_SIZE")
        if size - index_offset > maximum:
            raise UnsupportedError("RPA index exceeds binspect.archives.MAX_INDEX_SIZE")
        blob = read_at(fh, index_offset, size - index_offset, size, "RPA index")
        inflater = zlib.decompressobj()
        try:
            raw = inflater.decompress(blob, maximum)
        except zlib.error as exc:
            raise ParseError(f"RPA index is not valid zlib data: {exc}") from None
        if inflater.unconsumed_tail:
            raise UnsupportedError(
                "RPA index expands beyond binspect.archives.MAX_INDEX_SIZE "
                f"({maximum} bytes)")
        if not inflater.eof:
            raise ParseError("RPA index is truncated (incomplete zlib stream)")

        index = _unpickle(raw)
        if type(index) is not dict:
            raise ParseError("RPA index is not a dictionary")
        self._check_count(len(index))
        prefixed = 0
        for key, value in index.items():
            if type(key) is bytes:
                name = decode_name(key)
            elif type(key) is str:
                name = key
            else:
                raise ParseError("RPA index has a file name that is not a string")
            segments = self._segments(name, value)
            prefixed += any(s.prefix for s in segments)
            broken = None
            for segment in segments:
                stored = max(0, segment.length - len(segment.prefix))
                if segment.offset + stored > size:
                    broken = (f"data at offset {segment.offset:#x} (+{stored} bytes) is "
                              f"outside the file ({size} bytes)")
            self._add(ArchiveEntry(name, sum(s.length for s in segments),
                                   segments[0].offset if len(segments) == 1 else None,
                                   False, False), segments, broken)
        self.notes.append(
            f"{version}" + (f", key {self._key:#010x}" if version == "RPA-3.0" else ""))
        if prefixed:
            self.notes.append(
                f"{prefixed} entries carry prefix bytes in the index; they are read the "
                "way Ren'Py up to 8.1 and unrpa do (prefix, then length minus prefix "
                "bytes from the file). Ren'Py 8.2+ reads the full length after the prefix")
        self._finish()

    def _segments(self, name: str, value: Any) -> List[_Segment]:
        if type(value) not in (list, tuple) or not 1 <= len(value) <= _MAX_SEGMENTS:
            raise ParseError(f"RPA index entry for {name!r} is not a list of parts")
        segments = []
        for part in value:
            if type(part) not in (list, tuple) or len(part) not in (2, 3) \
                    or type(part[0]) is not int or type(part[1]) is not int:
                raise ParseError(f"RPA index entry for {name!r} is malformed")
            offset, length = part[0] ^ self._key, part[1] ^ self._key
            prefix = part[2] if len(part) == 3 else b""
            if prefix is None:
                prefix = b""
            elif type(prefix) is str:
                try:
                    prefix = prefix.encode("latin-1")
                except UnicodeEncodeError:
                    raise ParseError(f"RPA index entry for {name!r} is malformed") from None
            elif type(prefix) is not bytes:
                raise ParseError(f"RPA index entry for {name!r} is malformed")
            if offset < 0 or length < 0:
                raise ParseError(f"RPA index entry for {name!r} has a negative offset or length")
            segments.append(_Segment(offset, length, prefix))
        return segments

    def _chunks(self, handle: Any, index: int) -> Iterator[bytes]:
        what = repr(self.entries[index].name)
        for segment in self._records[index]:
            prefix = segment.prefix[:segment.length]
            if prefix:
                yield prefix
            yield from range_chunks(handle, segment.offset, segment.length - len(prefix), what)

    def _write(self, handle: Any, out: BinaryIO, plan: List[PlanItem]) -> None:
        out.write(bytes(self._header_size))
        position = self._header_size
        index = {}
        for item in plan:
            if item.data is not None:
                out.write(item.data)
                length = len(item.data)
            else:
                length = self._copy_entry(handle, item.index, out)
            # (offset, length) pairs in a protocol-2 pickle: plain containers
            # and integers only, which every Ren'Py (Python 2 or 3) loads.
            index[item.name] = [(position ^ self._key, length ^ self._key)]
            position += length
        out.write(zlib.compress(pickle.dumps(index, 2)))
        out.seek(0)
        if self._version == "RPA-3.0":
            out.write(b"RPA-3.0 %016x %08x\n" % (position, self._key))
        else:
            out.write(b"RPA-2.0 %016x\n" % position)
