"""Game and program asset containers: open, list, extract and repack.

Supported (unencrypted) formats:

    "zip"        ZIP family via zipfile (.zip .pk3 .pk4 .love .jar .apk .kpf),
                 also when appended to an executable
    "quake-pak"  Quake / Quake II / Half-Life PAK
    "doom-wad"   Doom IWAD / PWAD
    "godot-pck"  Godot PCK, standalone or embedded at the end of an executable
    "asar"       Electron ASAR
    "renpy-rpa"  Ren'Py RPA-2.0 / RPA-3.0

    archive = open_archive("game.pck")
    for entry in archive.entries: ...
    data = archive.read("icon.png")
    archive.extract("out/")
    archive.repack("modded.pck", replacements={"icon.png": new_bytes})

Nothing here decrypts anything: encrypted entries and encrypted indexes are
reported (ArchiveEntry.encrypted, UnsupportedError) and left alone.

Errors are BinspectError subclasses: UnknownFormatError (not a supported
container), ParseError (corrupt or hostile container; UnsafeEntryError for
entry names that would escape the extraction directory), UnsupportedError
(encrypted, over a size limit, or not possible for this archive) and
LocationError (no such entry). Only failures of the operating system itself
(file missing, permission denied, disk full) surface as OSError.
"""
from __future__ import annotations

import os
import struct
import zlib
from typing import BinaryIO, List, Optional, Type

from ..errors import BinspectError, ParseError, UnknownFormatError
from ._base import Archive, ArchiveEntry, UnsafeEntryError

__all__ = [
    "Archive", "ArchiveEntry", "UnsafeEntryError",
    "open_archive", "is_archive", "detect_format",
    "DEFAULT_MAX_ENTRY_SIZE", "DEFAULT_MAX_TOTAL_SIZE", "MAX_ENTRIES", "MAX_INDEX_SIZE",
]

# Zip-bomb guards for Archive.read()/extract(). Both are defaults: every
# Archive has max_entry_size / max_total_size attributes, and extract() and
# read() take per-call overrides.
DEFAULT_MAX_ENTRY_SIZE = 1 << 30        # one entry: 1 GiB
DEFAULT_MAX_TOTAL_SIZE = 8 << 30        # one extract() call: 8 GiB

# Guards for the listing itself, which lives in memory.
MAX_ENTRIES = 1_000_000                 # entries in one archive
MAX_INDEX_SIZE = 256 << 20              # bytes of index (JSON / pickle / directory)

_HEAD = 64


def _formats() -> List[Type[Archive]]:
    """Format classes in detection order: signatures at the start of the
    file first, then the ones found from the end of the file."""
    from ._asar import AsarArchive
    from ._pak import PakArchive
    from ._pck import PckArchive
    from ._rpa import RpaArchive
    from ._wad import WadArchive
    from ._zip import ZipArchive
    return [PakArchive, WadArchive, RpaArchive, PckArchive, AsarArchive, ZipArchive]


def _detect(fh: BinaryIO, size: int, head: bytes) -> Optional[Type[Archive]]:
    for cls in _formats():
        if cls.matches(head, fh, size):
            return cls
    return None


def detect_format(path) -> Optional[str]:
    """The format name ("zip", "quake-pak", ...) if `path` looks like a
    supported container, else None. A cheap signature check (it reads the
    first bytes and, for containers found from the end, the last 64 KiB);
    never raises. open_archive() may still reject the file as corrupt,
    encrypted or of an unsupported version."""
    try:
        with open(os.fspath(path), "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            cls = _detect(fh, size, fh.read(_HEAD))
        return cls.format if cls else None
    except Exception:           # by contract: unreadable means "not an archive"
        return None


def is_archive(path) -> bool:
    """True if `path` looks like a supported container. Never raises."""
    return detect_format(path) is not None


def open_archive(path) -> Archive:
    """Open a container and list its entries (entry data is read on demand).
    UnknownFormatError if `path` is not a supported container."""
    path = os.fspath(path)
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        head = fh.read(_HEAD)
        cls = _detect(fh, size, head)
        if cls is None:
            raise UnknownFormatError(
                "file is empty" if not size else
                "not a supported asset container (ZIP, Quake PAK, Doom WAD, Godot PCK, "
                "Electron ASAR, Ren'Py RPA)")
        archive = cls(path)
        try:
            archive._load(fh, size, head)
        except (BinspectError, OSError):
            raise
        except (struct.error, zlib.error, ValueError, LookupError, OverflowError,
                EOFError, RecursionError, MemoryError, ArithmeticError) as exc:
            # Safety net: a parser must not let a raw exception out.
            raise ParseError(f"corrupt {cls.format} archive: {exc!r}") from None
    return archive
