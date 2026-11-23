"""Resources embedded in Windows programs: icons, version information,
manifests, string tables and raw data.

A PE file keeps its resources in a three-level tree (type / name / language)
whose leaves point at the data. Every offset in that tree comes from the
file and may be hostile, so the walk is bounded: exactly three levels, a
budget for the number of entries, no directory visited as its own ancestor,
and every offset checked against the section that holds the tree. A broken
entry is skipped (and noted in `binary.warnings`); the rest is returned.

replace_resource() writes a modified copy of a program with one resource
swapped for new data, growing the image when the data no longer fits.
"""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, Union

from .errors import BinspectError, LocationError, ParseError, UnsupportedError
from .model import Binary
from .patch import PathLike, save_copy
from .reader import Reader

# Standard resource types (RT_* in winuser.h).
RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRING",
    7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
    12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
    19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML",
    24: "MANIFEST",
}

# Name of the section replace_resource() appends when data has to move.
NEW_SECTION_NAME = ".rsrc2"

_DIR_RESOURCE, _DIR_SECURITY, _DIR_DEBUG = 2, 4, 6
_SUBDIRECTORY = 0x80000000          # high bit of a directory entry's offset
_NAMED = 0x80000000                 # high bit of a directory entry's name
_SCN_INITIALIZED_DATA, _SCN_MEM_READ = 0x40, 0x40000000

_MAX_RESOURCES = 65536              # leaves reported for one file
_MAX_ENTRIES = 4 * _MAX_RESOURCES   # directory entries examined for one file
_MAX_WARNINGS = 8                   # problems reported for one file
_MAX_VERSION_SIZE = 1 << 20         # version resources are a few kilobytes
_MAX_SECTIONS = 96                  # limit of the Windows loader
_MAX_DEBUG_ENTRIES = 4096


@dataclass
class Resource:
    type: str        # "ICON", "VERSION", ... for standard types, "#<n>" for other
                     # integer IDs, the name itself for named types
    name: str        # "#<n>" for integer IDs, otherwise the string name
    language: int    # LANGID, e.g. 1033 (English, US)
    offset: int      # file offset of the data
    size: int
    codepage: int


# --- PE headers ---------------------------------------------------------------

@dataclass
class _Section:
    header: int      # file offset of the 40-byte section header
    name: str
    vsize: int
    rva: int
    raw_size: int
    raw_ptr: int     # where the loader reads the section from
    raw_end: int     # end of its data in the file, as the header states it


class _Headers:
    """File offsets of the header fields this module reads or rewrites."""

    def __init__(self, data: bytes):
        r = Reader(data)
        pe = r.u32(0x3C)
        if data[:2] != b"MZ" or r.bytes(pe, 4) != b"PE\0\0":
            raise ParseError("not a PE file")
        self.coff = pe + 4                      # IMAGE_FILE_HEADER
        self.nsections = r.u16(self.coff + 2)
        self.symtab, self.nsymbols = r.unpack("II", self.coff + 8)
        opt_size = r.u16(self.coff + 16)
        self.opt = self.coff + 20               # optional header
        magic = r.u16(self.opt)
        if magic not in (0x10B, 0x20B):
            raise ParseError(f"unsupported optional header magic {magic:#x}")
        self.section_align, self.file_align = r.unpack("II", self.opt + 32)
        self.headers_size = r.u32(self.opt + 60)
        count = self.opt + (108 if magic == 0x20B else 92)
        self.dirs = count + 4                   # data directory table
        self.ndirs = max(0, min(r.u32(count), 16, (self.opt + opt_size - self.dirs) // 8))
        self.section_table = self.opt + opt_size
        # Fields at the same place in PE32 and PE32+.
        self.size_of_initialized_data = self.opt + 8
        self.size_of_image = self.opt + 56
        self.checksum = self.opt + 64

    def directory(self, data: bytes, index: int) -> Tuple[int, int]:
        if index >= self.ndirs:
            return 0, 0
        return Reader(data).unpack("II", self.dirs + 8 * index)

    def sections(self, data: bytes) -> List[_Section]:
        r = Reader(data)
        found = []
        for i in range(self.nsections):
            off = self.section_table + 40 * i
            name = r.bytes(off, 8).split(b"\0", 1)[0].decode("utf-8", errors="replace")
            vsize, rva, raw_size, raw_ptr = r.unpack("IIII", off + 8)
            raw_end = raw_ptr + raw_size
            if self.file_align >= 0x200:
                raw_ptr &= ~0x1FF               # the loader ignores the low 9 bits
            found.append(_Section(off, name, vsize, rva, raw_size, raw_ptr, raw_end))
        return found


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _backed(binary: Binary, rva: int) -> Optional[Tuple[int, int]]:
    """(file offset, file-backed bytes available from there) for an RVA."""
    vaddr = binary.image_base + rva
    for start, offset, size in binary.maps:
        if start <= vaddr < start + size:
            return offset + (vaddr - start), size - (vaddr - start)
    return None


# --- walking the resource tree ------------------------------------------------

class _Walk:
    """One bounded pass over the resource directory of a PE image."""

    def __init__(self, binary: Binary):
        self.binary = binary
        self.r = Reader(binary.data)
        self.problems: List[str] = []
        self.found: List[Tuple[Resource, int]] = []    # (resource, offset of its data entry)
        self.entries_left = _MAX_ENTRIES
        self.stopped = False
        self.base = self.span = 0
        if binary.format != "PE":
            return
        try:
            rva, _size = _Headers(binary.data).directory(binary.data, _DIR_RESOURCE)
        except ParseError:
            return
        if not rva:
            return
        root = _backed(binary, rva)
        if root is None:
            self.problems.append(f"directory at RVA {rva:#x} is not inside the image")
            return
        self.base, self.span = root
        self._directory(0, (), ())

    def _at(self, rel: int, size: int, what: str) -> int:
        """File offset of `size` bytes at an offset relative to the root
        directory; ParseError when they leave the section holding the tree."""
        if rel < 0 or rel + size > self.span:
            raise ParseError(f"{what} at offset {rel:#x} lies outside the resource section")
        return self.base + rel

    def _key(self, name: int) -> Union[int, str]:
        """An entry's ID, or its name (a length-prefixed UTF-16 string)."""
        if not name & _NAMED:
            return name
        rel = name & 0x7FFFFFFF
        length = self.r.u16(self._at(rel, 2, "name"))
        raw = self.r.bytes(self._at(rel + 2, 2 * length, "name"), 2 * length)
        return raw.decode("utf-16-le", errors="replace")

    def _directory(self, rel: int, path: tuple, ancestors: tuple) -> None:
        level = len(path) + 1                   # 1 = types, 2 = names, 3 = languages
        try:
            named, ids = self.r.unpack("HH", self._at(rel, 16, "directory") + 12)
        except ParseError as exc:
            self.problems.append(str(exc))
            return
        for i in range(named + ids):
            if self.stopped:
                return
            if self.entries_left <= 0:
                self._stop(f"more than {_MAX_ENTRIES} directory entries")
                return
            self.entries_left -= 1
            try:
                name, target = self.r.unpack(
                    "II", self._at(rel + 16 + 8 * i, 8, "directory entry"))
            except ParseError:
                self.problems.append(
                    f"directory at offset {rel:#x} claims {named + ids} entries, "
                    f"only {i} fit in the resource section")
                return
            try:
                key = self._key(name)
            except ParseError as exc:
                self.problems.append(str(exc))
                continue
            if target & _SUBDIRECTORY:
                child = target & 0x7FFFFFFF
                if level == 3:
                    self.problems.append(
                        f"directory at offset {rel:#x} nests deeper than the three "
                        "levels (type, name, language) of the format")
                elif child == rel or child in ancestors:
                    self.problems.append(
                        f"directory at offset {child:#x} contains itself (cycle)")
                else:
                    self._directory(child, path + (key,), ancestors + (rel,))
            elif level != 3:
                self.problems.append(
                    f"directory at offset {rel:#x} has data above the language level")
            else:
                self._leaf(path + (key,), target)

    def _leaf(self, path: tuple, rel: int) -> None:
        kind, name, language = path
        try:
            entry = self._at(rel, 16, "data entry")
        except ParseError as exc:
            self.problems.append(str(exc))
            return
        rva, size, codepage, _reserved = self.r.unpack("IIII", entry)
        where = _backed(self.binary, rva)
        if where is None or where[1] < size:
            self.problems.append(
                f"data at RVA {rva:#x} ({size} bytes) is not inside the image")
            return
        if len(self.found) >= _MAX_RESOURCES:
            self._stop(f"more than {_MAX_RESOURCES} resources")
            return
        self.found.append((Resource(
            type=RESOURCE_TYPES.get(kind, f"#{kind}") if isinstance(kind, int) else kind,
            name=f"#{name}" if isinstance(name, int) else name,
            language=language if isinstance(language, int) else 0,
            offset=where[0], size=size, codepage=codepage), entry))

    def _stop(self, why: str) -> None:
        self.stopped = True
        self.problems.append(why + "; the rest of the tree is ignored")

    def report(self) -> None:
        """Note the problems in binary.warnings (once, however often we walk)."""
        shown = self.problems[:_MAX_WARNINGS]
        if len(self.problems) > _MAX_WARNINGS:
            shown.append(f"{len(self.problems) - _MAX_WARNINGS} more problems")
        for problem in shown:
            warning = "resources: " + problem
            if warning not in self.binary.warnings:
                self.binary.warnings.append(warning)


# --- reading -------------------------------------------------------------------

def list_resources(binary: Binary) -> List[Resource]:
    """Every resource of a PE image, in the order of its resource tree.

    Empty for ELF files and for PE files without a resource directory. A
    corrupt tree never raises: entries that cannot be read are left out and
    described in `binary.warnings`.
    """
    walk = _Walk(binary)
    walk.report()
    return [resource for resource, _entry in walk.found]


def read_resource(binary: Binary, resource: Resource) -> bytes:
    """The raw data of a resource (ParseError when it is not inside the file)."""
    return Reader(binary.data).bytes(resource.offset, resource.size)


def _wide_string(data: bytes, start: int, end: int) -> Tuple[str, int]:
    """The NUL-terminated UTF-16 string in data[start:end] and the offset just
    after its terminator."""
    stop = start
    while stop + 2 <= end and data[stop:stop + 2] != b"\0\0":
        stop += 2
    return data[start:stop].decode("utf-16-le", errors="replace"), stop + 2


def _version_nodes(data: bytes, start: int, end: int) -> Iterator[Tuple[str, int, int, int]]:
    """Sibling nodes of a VS_VERSIONINFO tree in data[start:end], each as
    (key, declared value length, offset of the value, end of the node).
    A node is: WORD length, WORD value length, WORD type, UTF-16 key, value,
    children; everything aligned to 4 bytes."""
    offset = start
    while offset + 6 <= end:
        length, value_length = struct.unpack_from("<HH", data, offset)
        if length < 6:
            return                              # cannot advance: corrupt
        node_end = min(offset + length, end)
        key, after_key = _wide_string(data, offset + 6, node_end)
        yield key, value_length, _align(after_key, 4), node_end
        offset = _align(offset + length, 4)


def _string_file_info(data: bytes) -> Dict[str, str]:
    data = data[:_MAX_VERSION_SIZE]
    info: Dict[str, str] = {}
    for _root, fixed_size, fixed, root_end in _version_nodes(data, 0, len(data)):
        # The root's value is the binary VS_FIXEDFILEINFO; its children follow.
        for key, _, children, block_end in _version_nodes(
                data, _align(fixed + fixed_size, 4), root_end):
            if key != "StringFileInfo":
                continue
            for _language, _, strings, table_end in _version_nodes(data, children, block_end):
                for name, value_length, value, node_end in _version_nodes(
                        data, strings, table_end):
                    # The declared length is unreliable (characters or bytes,
                    # depending on the compiler): read up to the terminator.
                    text = _wide_string(data, value, node_end)[0] if value_length else ""
                    if name:
                        info.setdefault(name, text)
        break                                   # one VS_VERSIONINFO per resource
    return info


def version_info(binary: Binary) -> Dict[str, str]:
    """The StringFileInfo pairs of the program's version resource, such as
    CompanyName, FileDescription, FileVersion and ProductName. Empty when
    there is no (readable) version resource. With several languages, the
    first one in the file wins."""
    for resource in list_resources(binary):
        if resource.type == "VERSION":
            try:
                info = _string_file_info(read_resource(binary, resource))
            except ParseError:
                continue
            if info:
                return info
    return {}


def icon_file(binary: Binary, group: Resource) -> bytes:
    """A complete .ico file rebuilt from a GROUP_ICON resource and the ICON
    resources it references.

    A group entry whose ICON resource is missing is left out. Raises
    UnsupportedError when `group` is not a GROUP_ICON resource and
    ParseError when the group is corrupt or none of its images exist.
    """
    if group.type != "GROUP_ICON":
        raise UnsupportedError(
            f"an icon file is built from a GROUP_ICON resource, not from {group.type}")
    r = Reader(read_resource(binary, group))
    _reserved, kind, count = r.unpack("HHH", 0)
    if kind != 1:
        raise ParseError(f"icon group has type {kind}, expected 1 (icon)")
    icons: Dict[str, List[Resource]] = {}
    for resource in list_resources(binary):
        if resource.type == "ICON":
            icons.setdefault(resource.name, []).append(resource)
    entries, images = [], []
    for i in range(count):
        try:
            # width, height, colours, reserved, planes, bit count, size, icon ID
            fields = r.unpack("BBBBHHIH", 6 + 14 * i)
        except ParseError:
            break                               # the group lists more than it holds
        candidates = icons.get(f"#{fields[7]}")
        if not candidates:
            continue
        same_language = [c for c in candidates if c.language == group.language]
        try:
            image = read_resource(binary, (same_language or candidates)[0])
        except ParseError:
            continue
        entries.append(fields[:6])
        images.append(image)
    if not images:
        raise ParseError("icon group references no icon image present in the file")
    out = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    offset = 6 + 16 * len(images)
    for fields, image in zip(entries, images):
        out += struct.pack("<BBBBHHII", *fields, len(image), offset)
        offset += len(image)
    for image in images:
        out += image
    return bytes(out)


# --- writing -------------------------------------------------------------------

def pe_checksum(data: bytes) -> int:
    """The value the CheckSum field of a PE image should hold (the algorithm
    of CheckSumMappedFile: the field itself counts as zero)."""
    image = bytearray(data)
    field = _Headers(image).checksum
    image[field:field + 4] = bytes(4)
    return _checksum(image)


def _checksum(image: bytearray) -> int:
    # The sum of all little-endian 16-bit words with end-around carry, plus
    # the file length. Since 0x10000 = 1 (mod 0xFFFF), that folded sum is the
    # whole file read as one little-endian number, modulo 0xFFFF (where a
    # non-zero multiple of 0xFFFF folds to 0xFFFF, not to 0).
    value = int.from_bytes(image, "little")
    folded = value % 0xFFFF or (0xFFFF if value else 0)
    return (folded + len(image)) & 0xFFFFFFFF


def _end_of_section_data(headers: _Headers, sections: List[_Section]) -> int:
    return max([s.raw_end for s in sections if s.raw_size], default=headers.headers_size)


def _strip_signature(image: bytearray, headers: _Headers, sections: List[_Section]) -> None:
    """Remove the Authenticode signature: it cannot survive a modification."""
    offset, size = headers.directory(image, _DIR_SECURITY)     # a file offset, not an RVA
    if not offset and not size:
        return
    struct.pack_into("<II", image, headers.dirs + 8 * _DIR_SECURITY, 0, 0)
    # Cut the certificates out only when they are what the directory says: the
    # last thing in the file, after everything the headers account for.
    accounted = _end_of_section_data(headers, sections)
    if headers.symtab and headers.nsymbols:
        accounted = max(accounted, headers.symtab + 18 * headers.nsymbols + 4)
    if size and accounted <= offset < len(image) and not any(image[offset + size:]):
        del image[offset:]


def _insert(image: bytearray, headers: _Headers, binary: Binary, at: int, blob: bytes) -> None:
    """Insert `blob` at file offset `at`, the end of the section data, and
    correct the file pointers to what follows (symbol table, debug data)."""
    if not blob:
        return
    debug = []
    rva, size = headers.directory(image, _DIR_DEBUG)
    where = _backed(binary, rva) if rva else None
    if where is not None:
        for i in range(min(size // 28, where[1] // 28, _MAX_DEBUG_ENTRIES)):
            # IMAGE_DEBUG_DIRECTORY, 28 bytes, PointerToRawData last
            pointer = where[0] + 28 * i + 24
            if struct.unpack_from("<I", image, pointer)[0] >= at:
                debug.append(pointer)
    image[at:at] = blob
    for pointer in debug:
        struct.pack_into("<I", image, pointer,
                         struct.unpack_from("<I", image, pointer)[0] + len(blob))
    if headers.symtab >= at:
        struct.pack_into("<I", image, headers.coff + 8, headers.symtab + len(blob))


def _place_in_padding(image: bytearray, headers: _Headers, sections: List[_Section],
                      new: bytes) -> Optional[Tuple[int, int]]:
    """Put `new` into the unused bytes between the VirtualSize and the raw
    size of the section holding the resource directory. Returns (RVA, file
    offset), or None when there is no such room."""
    rva, size = headers.directory(image, _DIR_RESOURCE)
    section = next((s for s in sections
                    if s.rva <= rva < s.rva + max(s.vsize, s.raw_size)), None)
    alignment = headers.section_align
    if section is None or not section.vsize or alignment < 1:
        return None
    start = _align(section.vsize, 8)
    end = start + len(new)
    raw_end = section.raw_ptr + section.raw_size
    if (end > section.raw_size or raw_end > len(image)
            or any(image[section.raw_ptr + section.vsize:raw_end])
            # Stay inside the pages the section already occupies in memory.
            or _align(end, alignment) != _align(section.vsize, alignment)):
        return None
    offset = section.raw_ptr + start
    image[offset:offset + len(new)] = new
    struct.pack_into("<I", image, section.header + 8, end)             # VirtualSize
    if rva + size < section.rva + end:
        struct.pack_into("<I", image, headers.dirs + 8 * _DIR_RESOURCE + 4,
                         section.rva + end - rva)
    return section.rva + start, offset


def _place_at_end(image: bytearray, headers: _Headers, sections: List[_Section],
                  binary: Binary, new: bytes) -> Tuple[int, int]:
    """Put `new` into a section appended to the image (or into the one a
    previous call appended, grown as needed). Returns (RVA, file offset)."""
    file_align, section_align = headers.file_align, headers.section_align
    if (file_align & (file_align - 1) or section_align & (section_align - 1)
            or not 0x200 <= file_align <= 0x10000
            or section_align < 0x1000 or section_align < file_align or not sections):
        raise UnsupportedError(
            "cannot add a section to this image: unusual section layout "
            f"(file alignment {file_align:#x}, section alignment {section_align:#x})")
    data_end = _end_of_section_data(headers, sections)
    if data_end > len(image):
        raise ParseError("section data extends past the end of the file")
    last = max(sections, key=lambda s: s.rva)
    tail = image[last.raw_ptr + last.vsize:last.raw_ptr + last.raw_size]
    if (last.name == NEW_SECTION_NAME and last.raw_size and last.vsize
            and last.raw_end == data_end and not any(tail)):
        # A section added by an earlier call: append to it instead of adding more.
        section, start = last, _align(last.vsize, 8)
        vsize = start + len(new)
        raw_size = max(last.raw_size, _align(vsize, file_align))
        added = raw_size - last.raw_size
        _insert(image, headers, binary, data_end, bytes(added))
    else:
        slot = headers.section_table + 40 * headers.nsections
        first_data = min([s.raw_ptr for s in sections if s.raw_size] + [len(image)])
        if (headers.nsections >= _MAX_SECTIONS or any(image[slot:slot + 40])
                or slot + 40 > min(headers.headers_size, first_data)):
            raise UnsupportedError(
                "the new data does not fit in the resource section and the PE "
                "header has no room for another section header")
        start, vsize = 0, len(new)
        added = raw_size = _align(vsize, file_align)
        raw_ptr = _align(data_end, file_align)
        # Sections must follow each other without a gap in memory.
        rva = last.rva + max(_align(last.vsize or last.raw_size, section_align), section_align)
        section = _Section(slot, NEW_SECTION_NAME, vsize, rva, raw_size, raw_ptr,
                           raw_ptr + raw_size)
        _insert(image, headers, binary, data_end, bytes(raw_ptr - data_end + raw_size))
        struct.pack_into("<8sIIIIIIHHI", image, slot, NEW_SECTION_NAME.encode(), 0,
                         section.rva, 0, raw_ptr, 0, 0, 0, 0,
                         _SCN_INITIALIZED_DATA | _SCN_MEM_READ)
        struct.pack_into("<H", image, headers.coff + 2, headers.nsections + 1)
    image_size = _align(section.rva + vsize, section_align)
    if image_size >= 1 << 32:
        raise UnsupportedError("the image would grow beyond 4 GiB")
    offset = section.raw_ptr + start
    image[offset:offset + len(new)] = new
    struct.pack_into("<I", image, section.header + 8, vsize)
    struct.pack_into("<I", image, section.header + 16, raw_size)
    struct.pack_into("<I", image, headers.size_of_image, image_size)
    initialized = struct.unpack_from("<I", image, headers.size_of_initialized_data)[0]
    struct.pack_into("<I", image, headers.size_of_initialized_data,
                     (initialized + added) & 0xFFFFFFFF)
    return section.rva + start, offset


def _replaced(binary: Binary, wanted: Resource, new: bytes) -> Tuple[bytes, Resource]:
    """The image of `binary` with one resource replaced, and that resource."""
    found = _Walk(binary).found
    identity = (wanted.type, wanted.name, wanted.language)
    matches = [(r, e) for r, e in found if (r.type, r.name, r.language) == identity]
    if not matches:
        raise LocationError(
            f"the file has no resource of type {wanted.type} named {wanted.name} "
            f"in language {wanted.language}")
    # Only a corrupt tree has two resources with one identity; take the one meant.
    target, entry = next((m for m in matches if m[0].offset == wanted.offset), matches[0])
    old_end = target.offset + target.size
    shared = any(e != entry and r.size and r.offset < old_end and target.offset < r.offset + r.size
                 for r, e in found)

    image = bytearray(binary.data)
    headers = _Headers(image)
    sections = headers.sections(image)
    _strip_signature(image, headers, sections)
    if len(new) <= target.size and not (shared and new):
        offset = target.offset
        if not shared:
            image[offset:old_end] = new + bytes(target.size - len(new))
        struct.pack_into("<I", image, entry + 4, len(new))                 # Size
    else:
        if not shared:
            image[target.offset:old_end] = bytes(target.size)             # erase the old copy
        rva, offset = (_place_in_padding(image, headers, sections, new)
                       or _place_at_end(image, headers, sections, binary, new))
        struct.pack_into("<II", image, entry, rva, len(new))               # OffsetToData, Size
    if struct.unpack_from("<I", image, headers.checksum)[0]:
        struct.pack_into("<I", image, headers.checksum, 0)
        struct.pack_into("<I", image, headers.checksum, _checksum(image))
    return bytes(image), replace(target, offset=offset, size=len(new))


def replace_resource(src_path: PathLike, dst_path: PathLike, resource: Resource,
                     new_data: bytes) -> Resource:
    """Write a copy of the PE file `src_path` to `dst_path` in which the data
    of `resource` is `new_data`; returns the resource as it is in the copy.

    The resource is identified by its type, name and language. Where the new
    data goes:

    * It fits in the space of the old data: rewritten in place. The Size of
      the resource's data entry is updated and the rest of the old space is
      zeroed. (Not used when another resource shares those bytes.)
    * Otherwise the data moves and the data entry's RVA is pointed at it; the
      old bytes are zeroed unless another resource shares them. Preferred
      home: the unused zero padding at the end of the resource section's raw
      data (its VirtualSize is raised).
    * No room there: a new read-only section named ".rsrc2" is appended to
      the image (section header, NumberOfSections, SizeOfImage and
      SizeOfInitializedData updated, file and section alignment respected).
      Later calls extend that section instead of adding another. Data that
      follows the sections in the file - a COFF symbol table, an installer's
      appended payload - stays at the end of the file, moved back by the size
      of the new section data, and the symbol-table and debug-data file
      pointers are corrected. UnsupportedError when the header has no free
      slot for another section header.

    Authenticode: any modification invalidates a signature, so a signed file
    is written out unsigned. The certificate directory entry is zeroed and the
    certificate table removed when it is the last thing in the file (if other
    data follows it, the bytes stay in place, unreferenced). A non-zero PE
    CheckSum is recomputed; a zero one stays zero.

    The copy is written atomically. With `dst_path == src_path` the original
    is first saved as `<src>.bak` unless that file exists (see
    binspect.patch.save_copy). Before anything is written the result is
    parsed again and the resource read back. Errors: LocationError when the
    file has no such resource, UnsupportedError for non-PE files or images
    that cannot be grown, ParseError for corrupt ones. Nothing is written on
    error.
    """
    from . import load_bytes

    src = os.fspath(src_path)
    binary = load_bytes(Path(src).read_bytes(), src)
    if binary.format != "PE":
        raise UnsupportedError(
            f"{binary.format} files have no Windows resources; only PE files do")
    new = bytes(new_data)
    image, updated = _replaced(binary, resource, new)
    # Trust nothing: the copy must parse, and the resource must read back.
    try:
        check = load_bytes(image, src)
        intact = (any(r == updated for r, _entry in _Walk(check).found)
                  and read_resource(check, updated) == new)
    except BinspectError:
        intact = False
    if not intact:
        raise ParseError(
            "the layout of this image is inconsistent (overlapping sections or "
            "resource data inside the headers); the resource was not replaced")
    save_copy(src, dst_path, image)
    return updated
