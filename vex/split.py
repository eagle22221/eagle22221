"""Saving the parts of a program as separate files: `vex split`.

A program is cut into three groups of pieces: the regions of its layout
(which, put back together, are the original file), the complete files found
embedded in it, and for Windows programs its resources. Bytes are only ever
copied: nothing is decompressed, decrypted or run, and the analysed file is
never written to.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct
import zlib
from bisect import bisect_right
from typing import Dict, List, Optional, Tuple

from . import views
from .errors import VexError
from .model import Binary

INDEX_NAME = "index.txt"
_MAX_NAME = 64                      # characters of a region name kept in a file name


# --- embedded files -----------------------------------------------------------
#
# The scanner runs over whatever bytes a hostile file holds, so every probe
# reads only inside the buffer and does a bounded amount of work per byte.
# Where the specification makes walks from different starting points run into
# each other (PNG chunks, GIF blocks, ELF tables, ZIP end records), what an
# earlier walk learned is kept, so the scan stays linear instead of quadratic.

_SIGNATURE = re.compile(rb"\x89PNG\r\n\x1a\n|GIF8[79]a|RIFF|PK\x03\x04|MZ|\x7fELF")
_RIFF_FORMS = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}
_BE32, _LE32 = struct.Struct(">I"), struct.Struct("<I")
_ZIP_END = struct.Struct("<IIH")            # directory size, directory offset, comment length
_COFF = struct.Struct("<H12xHH")            # sections, optional header size, characteristics
_PE_SECTION = struct.Struct("<16xII16x")    # raw size, raw pointer
_PE_DLL = 0x2000
_SHT_NOBITS = 8
_BLOCK = 256                                # ELF table entries summarised per cache entry
_MAX_BLOCKS = 1 << 16

# Marks left on visited positions: a later walk that reaches one stops there.
_PNG_SEEN, _GIF_SOFT, _GIF_HARD, _SUB_SOFT, _SUB_HARD = 1, 2, 4, 8, 16


def _elf_layouts() -> Dict[Tuple[int, int], tuple]:
    """(class, data encoding) -> header size, offset of e_phoff, and structs for
    the header fields (phoff, shoff, phentsize, phnum, shentsize, shnum), a
    program header (offset, file size) and a section header (type, offset, size)."""
    out = {}
    for encoding, order in ((1, "<"), (2, ">")):
        out[1, encoding] = (52, 28, struct.Struct(order + "II6xHHHH"),
                            struct.Struct(order + "4xI8xI12x"),
                            struct.Struct(order + "4xI8xII16x"))
        out[2, encoding] = (64, 32, struct.Struct(order + "QQ6xHHHH"),
                            struct.Struct(order + "8xQ16xQ16x"),
                            struct.Struct(order + "4xI16xQQ24x"))
    return out


_ELF = _elf_layouts()


def _colour_table(flags: int) -> int:
    """Bytes taken by the GIF colour table that a flags byte announces."""
    return 3 << ((flags & 7) + 1) if flags & 0x80 else 0


class _Carver:
    """Finds complete files inside a buffer; see `carve`."""

    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)
        self._marks: Optional[bytearray] = None         # one byte per file offset
        self._zips: Optional[Dict[int, int]] = None     # archive start -> end
        self._blocks: Dict[tuple, int] = {}
        self._probes = {0x89: self._png, 0x47: self._gif, 0x52: self._riff,
                        0x50: self._zip, 0x4D: self._pe, 0x7F: self._elf}

    def hits(self) -> List[Tuple[int, int, str]]:
        out, at = [], 1                     # offset 0 is the program itself
        while True:
            match = _SIGNATURE.search(self.data, at)
            if match is None:
                return out
            at = match.start()
            found = self._probes[self.data[at]](at)
            if found:                       # (extension, length), inside the file
                out.append((at, found[1], found[0]))
                at += 1
            else:
                at += 1

    def _marked(self) -> bytearray:
        if self._marks is None:
            self._marks = bytearray(self.size)
        return self._marks

    def _png(self, o: int) -> Optional[Tuple[str, int]]:
        data, size = self.data, self.size
        if o + 33 > size or data[o + 8:o + 16] != b"\0\0\0\rIHDR" or \
                zlib.crc32(data[o + 12:o + 29]) != _BE32.unpack_from(data, o + 29)[0]:
            return None
        # A chunk chain reads the same wherever it was entered: a chunk already
        # walked from leads nowhere (had it led to IEND, the scan would have
        # resumed after that file and never come back here).
        marks, at = self._marked(), o + 33
        while at + 12 <= size and not marks[at] & _PNG_SEEN:
            marks[at] |= _PNG_SEEN
            end = at + 12 + _BE32.unpack_from(data, at)[0]
            if end > size:
                return None
            if data[at + 4:at + 8] == b"IEND":
                return "png", end - o
            at = end
        return None

    def _gif(self, o: int) -> Optional[Tuple[str, int]]:
        data, size = self.data, self.size
        if o + 13 > size:
            return None
        # Marks, as for PNG, with one twist: a walk that has not met an image
        # yet fails at the trailer, one that has does not. "Soft" marks are
        # left by the first kind and only stop walks of that kind; "hard"
        # marks are left by the second kind and stop every walk.
        marks, at, image = self._marked(), o + 13 + _colour_table(data[o + 10]), False
        while at < size:
            if marks[at] & (_GIF_HARD if image else _GIF_HARD | _GIF_SOFT):
                return None
            marks[at] |= _GIF_HARD if image else _GIF_SOFT
            kind = data[at]
            if kind == 0x3B:                            # trailer
                return ("gif", at + 1 - o) if image else None
            if kind == 0x2C:                            # image descriptor
                if at + 10 > size:
                    return None
                image = True
                at += 11 + _colour_table(data[at + 9])  # ... colours, LZW code size
            elif kind == 0x21:                          # extension and its label
                at += 2
            else:
                return None
            stop, seen = (_SUB_HARD, _SUB_HARD) if image else \
                (_SUB_HARD | _SUB_SOFT, _SUB_SOFT)
            while True:                                 # data sub-blocks
                if at >= size or marks[at] & stop:
                    return None
                marks[at] |= seen
                length = data[at]
                at += 1 + length
                if not length:
                    break
        return None

    def _riff(self, o: int) -> Optional[Tuple[str, int]]:
        if o + 12 > self.size:
            return None
        ext = _RIFF_FORMS.get(self.data[o + 8:o + 12])
        length = _LE32.unpack_from(self.data, o + 4)[0] + 8
        return (ext, length) if ext and length >= 12 and o + length <= self.size else None

    def _zip(self, o: int) -> Optional[Tuple[str, int]]:
        if self._zips is None:
            self._zips = self._zip_ends()
        end = self._zips.get(o)
        return None if end is None else ("zip", end - o)

    def _zip_ends(self) -> Dict[int, int]:
        """For every archive start an end-of-central-directory record vouches
        for: the end of the first such record (comment included)."""
        data, size, ends = self.data, self.size, {}
        at = data.find(b"PK\x05\x06")
        while at != -1:
            if at + 22 <= size:
                cd_size, cd_offset, comment = _ZIP_END.unpack_from(data, at + 12)
                start = at - cd_offset - cd_size
                if start > 0 and start not in ends and at + 22 + comment <= size \
                        and data.startswith(b"PK\x03\x04", start) \
                        and data.startswith(b"PK\x01\x02", start + cd_offset):
                    ends[start] = at + 22 + comment
            at = data.find(b"PK\x05\x06", at + 4)
        return ends

    def _pe(self, o: int) -> Optional[Tuple[str, int]]:
        data, size = self.data, self.size
        if o + 64 > size:
            return None
        pe = o + _LE32.unpack_from(data, o + 60)[0]
        if pe + 88 > size or not data.startswith(b"PE\0\0", pe):
            return None
        count, optional, flags = _COFF.unpack_from(data, pe + 6)
        table = pe + 24 + optional
        if not 1 <= count <= 96 or table + 40 * count > size:
            return None
        length = max(raw + pointer for raw, pointer in
                     _PE_SECTION.iter_unpack(data[table:table + 40 * count]))
        length = max(length, _LE32.unpack_from(data, pe + 84)[0])       # SizeOfHeaders
        if length < 512 or o + length > size:
            return None
        return ("dll" if flags & _PE_DLL else "exe"), length

    def _elf(self, o: int) -> Optional[Tuple[str, int]]:
        data, size = self.data, self.size
        if o + 7 > size or data[o + 6] != 1:
            return None
        layout = _ELF.get((data[o + 4], data[o + 5]))
        if layout is None or o + layout[0] > size:
            return None
        _header_size, fields_at, fields, segment, section = layout
        phoff, shoff, phentsize, phnum, shentsize, shnum = fields.unpack_from(data, o + fields_at)
        if (phnum and phentsize != segment.size) or (shnum and shentsize != section.size):
            return None
        length = max(phoff + phnum * phentsize, shoff + shnum * shentsize)
        if o + length > size:
            return None
        length = max(length, self._furthest(o + phoff, phnum, segment),
                     self._furthest(o + shoff, shnum, section))
        return ("elf", length) if length >= 84 and o + length <= size else None

    def _furthest(self, start: int, count: int, entry: struct.Struct) -> int:
        """Largest offset + size over the `count` table entries at `start`
        (inside the file). Many headers may point into one table, so full runs
        of _BLOCK entries are worked out once and remembered."""
        best = 0
        while count:
            run = min(count, _BLOCK - start // entry.size % _BLOCK)
            if run < _BLOCK:
                value = self._reach(start, run, entry)
            else:
                value = self._blocks.get((entry, start))
                if value is None:
                    if len(self._blocks) >= _MAX_BLOCKS:
                        self._blocks.clear()
                    value = self._blocks[entry, start] = self._reach(start, run, entry)
            best = max(best, value)
            start += run * entry.size
            count -= run
        return best

    def _reach(self, start: int, count: int, entry: struct.Struct) -> int:
        rows = entry.iter_unpack(self.data[start:start + count * entry.size])
        return max((row[-2] + row[-1] for row in rows
                    if len(row) == 2 or row[0] != _SHT_NOBITS), default=0)


def carve(data: bytes) -> List[Tuple[int, int, str]]:
    """Complete files inside `data`: (offset, length, extension), in file
    order and never overlapping. Offset 0 is not looked at. Safe on any bytes."""
    return _Carver(data).hits()


# --- pieces ---------------------------------------------------------------------

def _safe(name: str) -> str:
    """A region name as part of a file name: no separators, dots-only tricks
    are harmless behind the number prefix, and never too long for a file name."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:_MAX_NAME] or "unnamed"


def _piece(binary: Binary, path: Optional[str], kind: str, name: str, offset: int,
           size: int, note: str, data) -> dict:
    return {"path": path, "kind": kind, "name": name, "offset": offset, "size": size,
            "address": views.hx(binary.offset_to_vaddr(offset)), "note": note, "data": data}


def _resources(binary: Binary) -> List[dict]:
    """One piece per PE resource, named as `vex resources extract` names them.
    Nothing at all when any of them cannot be read."""
    from . import resources
    out, taken = [], set()
    try:
        for res in resources.list_resources(binary):
            icon = res.type == "GROUP_ICON"
            data = resources.icon_file(binary, res) if icon \
                else resources.read_resource(binary, res)
            stem = "".join(ch if ch.isalnum() or ch in "-_" else "_"
                           for ch in f"{res.type}_{res.name.lstrip('#')}_{res.language}")
            unique, n = stem, 1
            while unique.lower() in taken:          # two resources, one file name
                n += 1
                unique = f"{stem}_{n}"
            taken.add(unique.lower())
            out.append(_piece(binary, f"resources/{unique}{'.ico' if icon else '.bin'}",
                              "resource", f"{res.type} {res.name}", res.offset, len(data),
                              f"language {res.language}", data))
    except Exception:                               # broken resources: skip the group
        return []
    return out


def plan(binary: Binary) -> List[dict]:
    """Every piece of a program, in order: parts, embedded files, resources.

    Each piece is the dict the result reports plus `data`, the bytes to
    write (None for a piece that is not saved). Nothing touches the disk.
    """
    whole = memoryview(binary.data)
    regions = views.layout(binary)["regions"]
    pieces = []
    for number, region in enumerate(regions):
        offset, size = region["offset"], region["size"]
        if region["kind"] == "padding" and binary.data.count(0, offset, offset + size) == size:
            pieces.append(_piece(binary, None, "padding", region["name"], offset, size,
                                 "zero padding, not saved", None))
        else:
            pieces.append(_piece(binary, f"parts/{number:02d}_{_safe(region['name'])}.bin",
                                 region["kind"], region["name"], offset, size, "",
                                 whole[offset:offset + size]))
    starts = [region["offset"] for region in regions]
    for number, (offset, size, ext) in enumerate(carve(binary.data)):
        inside = regions[bisect_right(starts, offset) - 1]["name"]
        pieces.append(_piece(binary, f"embedded/{number:03d}_0x{offset:08x}.{ext}", "embedded",
                             f"{ext} file", offset, size, f"found inside {inside}",
                             whole[offset:offset + size]))
    return pieces + _resources(binary)


def _public(piece: dict) -> dict:
    return {key: value for key, value in piece.items() if key != "data"}


def preview(binary: Binary, pieces: Optional[List[dict]] = None) -> dict:
    """What `split` would report, without writing anything (`dest` is None)."""
    pieces = plan(binary) if pieces is None else pieces
    saved = [p for p in pieces if p["path"] is not None]
    return {"dest": None, "count": len(saved), "bytes": sum(len(p["data"]) for p in saved),
            "index": INDEX_NAME, "pieces": [_public(p) for p in pieces]}


def _plain(text: str) -> str:
    """Text for one cell of the index: printable ASCII, so that no name taken
    from a hostile file can start a new line or steer a terminal."""
    return re.sub(r"[^\x20-\x7e]", "?", text)


def index_text(binary: Binary, pieces: List[dict]) -> str:
    """The contents of index.txt: a line about the source file, then one row
    per piece. Each group (parts, embedded files, resources) is aligned on
    its own, so its rows do not depend on what the other groups hold."""
    name = os.path.basename(binary.path) if binary.path else "<memory>"
    lines = [f"{_plain(name)}: {binary.size} bytes, "
             f"SHA-256 {hashlib.sha256(binary.data).hexdigest()}"]
    groups: Dict[str, List[tuple]] = {}
    for p in pieces:
        group = p["kind"] if p["kind"] in ("embedded", "resource") else "part"
        groups.setdefault(group, []).append(
            (f"0x{p['offset']:08x}", str(p["size"]), p["kind"], p["path"] or "-",
             _plain(p["name"]), _plain(p["note"])))
    for rows in groups.values():
        widths = [max(len(row[i]) for row in rows) for i in range(6)]
        for row in rows:
            cells = [cell.rjust(width) if i == 1 else cell.ljust(width)
                     for i, (cell, width) in enumerate(zip(row, widths))]
            lines.append("  ".join(cells).rstrip())
    return "\n".join(lines) + "\n"


def split(binary: Binary, dest: str, pieces: Optional[List[dict]] = None) -> dict:
    """Save every piece of a program, and index.txt, into the folder `dest`.

    The folder is created when missing; one that already holds anything is
    refused before a single byte is written.
    """
    try:
        if os.path.lexists(dest) and not (os.path.isdir(dest) and not os.listdir(dest)):
            raise VexError(f"{dest} is not empty; choose a new or empty folder")
        pieces = plan(binary) if pieces is None else pieces
        result = preview(binary, pieces)
        os.makedirs(dest, exist_ok=True)
        for p in pieces:
            if p["path"] is not None:
                target = os.path.join(dest, *p["path"].split("/"))
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "xb") as f:
                    f.write(p["data"])
        with open(os.path.join(dest, INDEX_NAME), "xb") as f:
            f.write(index_text(binary, pieces).encode("utf-8"))
    except OSError as exc:
        raise VexError(f"cannot write to {dest}: {exc.strerror or exc}") from None
    result["dest"] = os.path.abspath(dest)
    return result
