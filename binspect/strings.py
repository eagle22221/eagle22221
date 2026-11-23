"""Printable-string extraction (ASCII and UTF-16LE) with light tagging of
strings that usually matter in reverse engineering: URLs, IP addresses,
e-mail addresses, file paths and Windows registry keys."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .model import Binary

_PRINTABLE = rb"[\x20-\x7e\t]"

_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,9}://[^\s\"'<>]{3,}")
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
_EMAIL = re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_REGISTRY = re.compile(r"\b(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\", re.IGNORECASE)
_WIN_PATH = re.compile(r"(?<![A-Za-z])[A-Za-z]:\\[^\s:*?\"<>|]+|\\\\[\w.$-]+\\[\w.$-]+")
_UNIX_PATH = re.compile(r"(?<![\w/.:])/(?:[\w.+-]+/)+[\w.+-]*|(?<![\w/.:])/(?:etc|bin|tmp|usr|var|dev|proc|home|lib|opt|root|sys)/?[\w.+-]*")


@dataclass
class FoundString:
    offset: int
    vaddr: Optional[int]
    section: Optional[str]
    encoding: str               # "ascii" or "utf16"
    text: str
    tags: List[str] = field(default_factory=list)


def classify(text: str) -> List[str]:
    """Tags for a string; empty when it looks like nothing special."""
    tags = []
    if _URL.search(text):
        tags.append("url")
    for m in _IPV4.finditer(text):
        if all(int(octet) <= 255 for octet in m.groups()):
            tags.append("ipv4")
            break
    if _EMAIL.search(text):
        tags.append("email")
    if _REGISTRY.search(text):
        tags.append("registry")
    elif "url" not in tags and (_WIN_PATH.search(text) or _UNIX_PATH.search(text)):
        tags.append("path")
    return tags


def extract(binary: Binary, min_length: int = 4, encoding: str = "all") -> List[FoundString]:
    """All printable strings of at least `min_length` characters, by file offset.

    encoding: "ascii", "utf16" or "all".
    """
    min_length = max(1, int(min_length))
    data = binary.data
    raw = []
    if encoding in ("all", "ascii"):
        pattern = re.compile(_PRINTABLE + b"{%d,}" % min_length)
        raw += [(m.start(), "ascii", m.group().decode("ascii")) for m in pattern.finditer(data)]
    if encoding in ("all", "utf16"):
        pattern = re.compile(b"(?:" + _PRINTABLE + b"\\x00){%d,}" % min_length)
        raw += [(m.start(), "utf16", m.group().decode("utf-16-le"))
                for m in pattern.finditer(data)]
    raw.sort(key=lambda item: item[0])

    # File-offset lookup tables, so each string costs a binary search.
    by_offset = sorted((s.offset, s.offset + s.size, s.name) for s in binary.sections if s.size)
    starts = [s[0] for s in by_offset]

    def section_of(offset: int) -> Optional[str]:
        i = bisect.bisect_right(starts, offset) - 1
        while i >= 0:                       # sections may nest or overlap
            if by_offset[i][0] <= offset < by_offset[i][1]:
                return by_offset[i][2]
            i -= 1
        return None

    return [
        FoundString(offset, binary.offset_to_vaddr(offset), section_of(offset),
                    kind, text, classify(text))
        for offset, kind, text in raw
    ]
