"""Format-independent description of a loaded binary.

The ELF and PE parsers both produce a Binary, so everything downstream
(strings, disassembly, cross-references, the CLI) is written once.
All addresses are absolute virtual addresses as the code itself sees them:
for PE that means image base + RVA.
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte: 0.0 (constant) to 8.0 (random).
    Compressed or encrypted data sits close to 8."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(n / total * math.log2(n / total) for n in Counter(data).values())


@dataclass
class Section:
    name: str
    vaddr: int          # 0 when the section is not loaded into memory
    vsize: int          # size in memory
    offset: int         # file offset
    size: int           # bytes present in the file (0 for .bss-style sections)
    perms: str          # "r-x" style; "---" when not loaded
    type: str = ""


@dataclass
class Segment:
    """ELF program header (PE files have none)."""
    type: str
    vaddr: int
    vsize: int
    offset: int
    size: int
    perms: str


@dataclass
class Symbol:
    name: str
    address: int
    size: int
    type: str                       # func, object, notype, ...
    binding: str                    # local, global, weak
    section: Optional[str] = None


@dataclass
class Import:
    name: str
    library: Optional[str] = None
    address: Optional[int] = None   # GOT slot (ELF) or IAT slot (PE)
    ordinal: Optional[int] = None   # PE import by ordinal
    version: Optional[str] = None   # ELF symbol version, e.g. GLIBC_2.2.5
    delayed: bool = False           # PE delay-load import


@dataclass
class Export:
    name: str
    address: Optional[int]          # None for forwarded exports
    ordinal: Optional[int] = None
    forwarder: Optional[str] = None  # "OTHERDLL.Function" when forwarded


class Binary:
    def __init__(self, data: bytes, path: Optional[str] = None):
        self.data = data
        self.path = path
        self.format = ""
        self.arch = "unknown"
        self.bits = 0
        self.endian = "little"
        self.kind = "unknown"
        self.entry: Optional[int] = None
        self.image_base = 0
        self.sections: List[Section] = []
        self.segments: List[Segment] = []
        self.symbols: List[Symbol] = []
        self.imports: List[Import] = []
        self.exports: List[Export] = []
        self.libraries: List[str] = []
        self.security: Dict[str, object] = {}
        self.metadata: Dict[str, object] = {}
        self.warnings: List[str] = []
        # Exact (start, end) function bounds when the format records them
        # (Windows x64 exception table).
        self.function_ranges: List[Tuple[int, int]] = []
        # Parts of the file that are not sections: (name, offset, size, kind).
        self.regions: List[Tuple[str, int, int, str]] = []
        # File-backed address ranges: (vaddr, file offset, size in file).
        self.maps: List[Tuple[int, int, int]] = []

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def hashes(self) -> Dict[str, str]:
        return {name: hashlib.new(name, self.data).hexdigest()
                for name in ("md5", "sha1", "sha256")}

    def section_entropy(self, section: Section) -> float:
        return entropy(self.section_data(section))

    def note_overlay(self, end_of_image: int) -> None:
        """Record data appended after the last byte the format accounts for
        (installers, self-extractors and droppers keep payloads there)."""
        if 0 < end_of_image < len(self.data):
            self.metadata["overlay"] = {"offset": end_of_image,
                                        "size": len(self.data) - end_of_image}

    def add_map(self, vaddr: int, offset: int, size: int) -> None:
        """Register a file-backed range, clipped to what the file really holds."""
        if offset < 0 or offset >= len(self.data):
            return
        size = min(size, len(self.data) - offset)
        if size > 0:
            self.maps.append((vaddr, offset, size))

    def _map_for(self, vaddr: int) -> Optional[Tuple[int, int, int]]:
        for m in self.maps:
            if m[0] <= vaddr < m[0] + m[2]:
                return m
        return None

    def vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        m = self._map_for(vaddr)
        return None if m is None else m[1] + (vaddr - m[0])

    def offset_to_vaddr(self, offset: int) -> Optional[int]:
        for vaddr, off, size in self.maps:
            if off <= offset < off + size:
                return vaddr + (offset - off)
        return None

    def read(self, vaddr: int, size: int) -> bytes:
        """Up to `size` bytes at a virtual address; shorter (or empty) when the
        range is not backed by the file. Never crosses into an unrelated range."""
        m = self._map_for(vaddr)
        if m is None or size <= 0:
            return b""
        start = m[1] + (vaddr - m[0])
        available = m[2] - (vaddr - m[0])
        return self.data[start:start + min(size, available)]

    def executable_ranges(self) -> List[Tuple[int, int]]:
        """(vaddr, size) of every file-backed range holding code."""
        ranges = [(s.vaddr, s.size) for s in self.sections
                  if "x" in s.perms and s.size and s.vaddr]
        if not ranges:      # no section headers: fall back to executable segments
            ranges = [(s.vaddr, s.size) for s in self.segments
                      if s.type == "LOAD" and "x" in s.perms and s.size]
        return sorted(ranges)

    def is_address(self, vaddr: int) -> bool:
        """True when vaddr lies in the loaded image (file-backed or not)."""
        if self._map_for(vaddr) is not None or self.section_at(vaddr) is not None:
            return True
        return any(s.type == "LOAD" and s.vaddr <= vaddr < s.vaddr + s.vsize
                   for s in self.segments)

    def section_at(self, vaddr: int) -> Optional[Section]:
        for s in self.sections:
            if s.vaddr and s.vaddr <= vaddr < s.vaddr + max(s.vsize, 1):
                return s
        return None

    def section_data(self, section: Section) -> bytes:
        return self.data[section.offset:section.offset + section.size]
