"""Shared machinery for asset containers: the public Archive type, safe
extraction, repacking, and the bounded I/O helpers every format parser uses.

A container's index is attacker-controlled. The rules followed here and in
the format modules:
  * nothing is read with a size taken from the file before that size has been
    checked against the real file size;
  * entry data is only ever read as ranges of the file, in chunks;
  * names from the file are never used as filesystem paths without going
    through safe_parts().
"""
from __future__ import annotations

import contextlib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any, BinaryIO, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple,
)

from ..errors import LocationError, ParseError, UnsupportedError

CHUNK = 1 << 20


class UnsafeEntryError(ParseError):
    """An entry name (or the state of the destination directory) would make
    extraction write outside the destination. Nothing is written."""


@dataclass
class ArchiveEntry:
    name: str               # path inside the archive, forward slashes, no leading slash
    size: int               # uncompressed size in bytes
    offset: Optional[int]   # file offset of the stored data in the container, None if n/a
    compressed: bool
    encrypted: bool


@dataclass
class PlanItem:
    """One entry of the archive a repack is about to write."""
    index: Optional[int]    # position in the source archive; None for an addition
    name: str
    data: Optional[bytes]   # new content; None copies the source entry


def limit(name: str) -> int:
    """A size limit, looked up on the package at call time so callers can
    adjust binspect.archives.MAX_ENTRIES and friends."""
    import binspect.archives as package
    return int(getattr(package, name))


def human(size: int) -> str:
    for unit in ("bytes", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size} bytes"


# -- bounded I/O ---------------------------------------------------------------

def file_size(fh: BinaryIO) -> int:
    return os.fstat(fh.fileno()).st_size


def read_at(fh: BinaryIO, offset: int, size: int, total: int, what: str) -> bytes:
    """Exactly `size` bytes at `offset`. The range is checked against the
    real file size first, so a bogus size never becomes an allocation."""
    if offset < 0 or size < 0 or offset + size > total:
        raise ParseError(
            f"{what} at offset {offset:#x} (+{size} bytes) is outside the file "
            f"({total} bytes)")
    fh.seek(offset)
    data = fh.read(size)
    if len(data) != size:
        raise ParseError(f"{what} at offset {offset:#x}: the file ends early")
    return data


def range_chunks(fh: BinaryIO, offset: int, size: int, what: str) -> Iterator[bytes]:
    """The bytes [offset, offset + size) of the file in chunks."""
    total = file_size(fh)
    if offset < 0 or size < 0 or offset + size > total:
        raise ParseError(
            f"{what}: data at offset {offset:#x} (+{size} bytes) is outside the file "
            f"({total} bytes)")
    fh.seek(offset)
    left = size
    while left:
        chunk = fh.read(min(CHUNK, left))
        if not chunk:
            raise ParseError(f"{what}: the file ends early")
        left -= len(chunk)
        yield chunk


def copy_range(src: BinaryIO, dst: BinaryIO, offset: int, size: int, what: str) -> None:
    for chunk in range_chunks(src, offset, size, what):
        dst.write(chunk)


# -- names ---------------------------------------------------------------------

_DRIVE = re.compile(r"^[A-Za-z]:")


def unsafe_reason(name: str) -> Optional[str]:
    """Why an entry name must not be turned into a path, or None if it may."""
    if not name:
        return "empty name"
    if "\0" in name:
        return "NUL byte"
    if "\\" in name:
        return "backslash"
    if name.startswith("/"):
        return "absolute path"
    for part in name.split("/"):
        if part == "":
            return "empty path component"
        if part in (".", ".."):
            return f"'{part}' path component"
        if _DRIVE.match(part):
            return "drive letter"
    return None


def safe_parts(name: str) -> Tuple[str, ...]:
    """The path components of an entry name that is safe to create below a
    destination directory; UnsafeEntryError for anything else."""
    reason = unsafe_reason(name)
    if reason:
        raise UnsafeEntryError(
            f"unsafe entry name {name!r} ({reason}): refusing to extract it")
    return tuple(name.split("/"))


def decode_name(raw: bytes) -> str:
    """Stored name bytes as text: UTF-8 when valid, otherwise Latin-1 (which
    cannot fail). The raw bytes are what gets written back on a repack."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def unique_names(raw: Sequence[str]) -> Tuple[List[str], int]:
    """Names for a listing in which every entry must be addressable: the
    first holder of a name keeps it, later ones get '#2', '#3', ...
    Returns the names and how many had to be renamed."""
    taken: Set[str] = set(raw)
    used: Set[str] = set()
    counters: Dict[str, int] = {}
    out: List[str] = []
    renamed = 0
    for name in raw:
        if name not in used:
            used.add(name)
            out.append(name)
            continue
        n = counters.get(name, 1)
        while True:
            n += 1
            candidate = f"{name}#{n}"
            if candidate not in used and candidate not in taken:
                break
        counters[name] = n
        used.add(candidate)
        out.append(candidate)
        renamed += 1
    return out, renamed


# -- the archive ---------------------------------------------------------------

class Archive:
    """An opened asset container. Listing is done once when it is opened;
    entry data is read from the file on demand.

    The file is opened for each read()/extract()/repack() call and closed
    again, so an Archive holds no file handle. Used as a context manager it
    keeps one handle open for the duration of the block, which is faster for
    many read() calls (not thread-safe while held)."""

    format = ""

    def __init__(self, path: str):
        self.path: str = str(path)
        self.entries: List[ArchiveEntry] = []
        self.writable: bool = True
        self.notes: List[str] = []
        self.max_entry_size: int = limit("DEFAULT_MAX_ENTRY_SIZE")
        self.max_total_size: int = limit("DEFAULT_MAX_TOTAL_SIZE")
        self._records: List[Any] = []           # per-entry format data, parallel to entries
        self._by_name: Dict[str, int] = {}
        self._broken: Dict[int, str] = {}       # entries whose data cannot be in the file
        self._readonly_reason = ""
        self._held: Any = None

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.format} {self.path!r}: {len(self.entries)} entries>"

    # -- hooks for the format modules -----------------------------------------

    @staticmethod
    def matches(head: bytes, fh: BinaryIO, size: int) -> bool:
        raise NotImplementedError

    def _load(self, fh: BinaryIO, size: int, head: bytes) -> None:
        raise NotImplementedError

    def _open_handle(self) -> Any:
        return open(self.path, "rb")

    def _close_handle(self, handle: Any) -> None:
        handle.close()

    def _chunks(self, handle: Any, index: int) -> Iterator[bytes]:
        """The content of entry `index`, in chunks."""
        raise NotImplementedError

    def _extract_name(self, index: int) -> str:
        """The relative path an entry is extracted to."""
        return self.entries[index].name

    def _check_new_name(self, name: str) -> None:
        """UnsupportedError if the format cannot store an added entry `name`."""
        reason = unsafe_reason(name)
        if reason:
            raise UnsupportedError(f"cannot add an entry named {name!r} ({reason})")

    def _write(self, handle: Any, out: BinaryIO, plan: List[PlanItem]) -> None:
        raise NotImplementedError

    # -- helpers for the format modules ---------------------------------------

    def _add(self, entry: ArchiveEntry, record: Any, broken: Optional[str] = None) -> None:
        if broken:
            self._broken[len(self.entries)] = broken
        self.entries.append(entry)
        self._records.append(record)

    def _check_count(self, count: int, what: str = "entries") -> None:
        maximum = limit("MAX_ENTRIES")
        if count > maximum:
            raise UnsupportedError(
                f"{self.format} archive declares {count} {what}, more than "
                f"binspect.archives.MAX_ENTRIES ({maximum})")

    def _finish(self) -> None:
        """Called once the listing is complete."""
        names, renamed = unique_names([e.name for e in self.entries])
        for entry, name in zip(self.entries, names):
            entry.name = name
        self._by_name = {entry.name: i for i, entry in enumerate(self.entries)}
        if renamed:
            self.notes.append(
                f"{renamed} entries share a name with an earlier entry and are "
                "listed with a #N suffix")
        if self._broken:
            self.notes.append(
                f"{len(self._broken)} entries point outside the file (truncated or "
                "corrupt archive) and cannot be read")
        if any(e.encrypted for e in self.entries):
            count = sum(e.encrypted for e in self.entries)
            self._read_only(
                f"{count} entries are encrypted; binspect does not decrypt them and "
                "cannot repack this archive")

    def _read_only(self, reason: str) -> None:
        self.writable = False
        if not self._readonly_reason:
            self._readonly_reason = reason
        if reason not in self.notes:
            self.notes.append(reason)

    def _copy_entry(self, handle: Any, index: int, out: BinaryIO) -> int:
        """Stream a source entry into `out`; returns the number of bytes."""
        self._check_entry(index, None)
        entry = self.entries[index]
        written = 0
        for chunk in self._chunks(handle, index):
            written += len(chunk)
            if written > entry.size:
                break
            out.write(chunk)
        if written != entry.size:
            raise ParseError(
                f"{entry.name!r}: the archive holds {written} bytes, its index says "
                f"{entry.size}")
        return written

    # -- context manager -------------------------------------------------------

    def __enter__(self) -> "Archive":
        if self._held is None:
            self._held = self._open_handle()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        handle, self._held = self._held, None
        if handle is not None:
            self._close_handle(handle)

    @contextlib.contextmanager
    def _session(self) -> Iterator[Any]:
        if self._held is not None:
            yield self._held
            return
        handle = self._open_handle()
        try:
            yield handle
        finally:
            self._close_handle(handle)

    # -- lookups and checks ----------------------------------------------------

    def _lookup(self, name: str, action: str = "read") -> int:
        index = self._by_name.get(name) if isinstance(name, str) else None
        if index is None:
            raise LocationError(f"cannot {action} {name!r}: no such entry in {self.path}")
        return index

    def _check_entry(self, index: int, maximum: Optional[int]) -> None:
        entry = self.entries[index]
        if entry.encrypted:
            raise UnsupportedError(
                f"{entry.name!r} is encrypted; binspect does not decrypt archive "
                "contents (no key recovery, no DRM removal)")
        if index in self._broken:
            raise ParseError(f"{entry.name!r}: {self._broken[index]}")
        if maximum is not None and entry.size > maximum:
            raise UnsupportedError(
                f"{entry.name!r} is {human(entry.size)}, over the per-entry limit of "
                f"{human(maximum)}; pass a larger max_entry_size / max_size (or set "
                "Archive.max_entry_size) if this is expected")

    # -- reading ---------------------------------------------------------------

    def read(self, name: str, *, max_size: Optional[int] = None) -> bytes:
        """The content of one entry. Refuses entries larger than `max_size`
        (default: self.max_entry_size)."""
        index = self._lookup(name)
        self._check_entry(index, self.max_entry_size if max_size is None else max_size)
        entry = self.entries[index]
        parts: List[bytes] = []
        total = 0
        with self._session() as handle:
            for chunk in self._chunks(handle, index):
                total += len(chunk)
                if total > entry.size:
                    break
                parts.append(chunk)
        if total != entry.size:
            raise ParseError(
                f"{entry.name!r}: the archive holds {total} bytes, its index says {entry.size}")
        return b"".join(parts)

    def extract(self, dest_dir, names: Optional[Iterable[str]] = None, *,
                max_entry_size: Optional[int] = None,
                max_total_size: Optional[int] = None) -> List[Path]:
        """Write entries (all, or the named ones) below `dest_dir` and return
        the paths written. Every name, size and limit is checked before the
        first byte is written; unsafe names raise UnsafeEntryError."""
        if names is None:
            indices = list(range(len(self.entries)))
        else:
            if isinstance(names, str):
                names = [names]
            indices = list(dict.fromkeys(self._lookup(n, "extract") for n in names))
        per_entry = self.max_entry_size if max_entry_size is None else max_entry_size
        total_limit = self.max_total_size if max_total_size is None else max_total_size

        jobs: List[Tuple[int, Tuple[str, ...]]] = []
        total = 0
        for index in indices:
            self._check_entry(index, per_entry)
            jobs.append((index, safe_parts(self._extract_name(index))))
            total += self.entries[index].size
            if total > total_limit:
                raise UnsupportedError(
                    f"extracting would write more than {human(total_limit)} in total; "
                    "pass a larger max_total_size (or set Archive.max_total_size) if "
                    "this is expected")

        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        root = dest.resolve()
        written: List[Path] = []
        with self._session() as handle:
            for index, parts in jobs:
                written.append(self._extract_one(handle, index, root, parts))
        return written

    def _extract_one(self, handle: Any, index: int, root: Path, parts: Tuple[str, ...]) -> Path:
        entry = self.entries[index]
        # Create the parent directories one component at a time: a symbolic
        # link anywhere on the way would lead out of the destination.
        current = root
        for part in parts[:-1]:
            current = current / part
            if current.is_symlink():
                raise UnsafeEntryError(
                    f"{entry.name!r}: {current} is a symbolic link; refusing to write through it")
            if not current.exists():
                current.mkdir()
            elif not current.is_dir():
                raise UnsafeEntryError(
                    f"{entry.name!r}: {current} exists and is not a directory")
        target = current / parts[-1]
        if target.is_symlink():
            raise UnsafeEntryError(
                f"{entry.name!r}: {target} is a symbolic link; refusing to write through it")
        if target.is_dir():
            raise UnsafeEntryError(f"{entry.name!r}: {target} is a directory")
        if target.parent.resolve() != current:
            raise UnsafeEntryError(f"{entry.name!r} would be written outside {root}")
        flags = (os.O_WRONLY | os.O_CREAT | os.O_TRUNC
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
        fd = os.open(str(target), flags, 0o666)
        try:
            with os.fdopen(fd, "wb") as out:
                self._copy_entry(handle, index, out)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(str(target))
            raise
        return target

    # -- repacking -------------------------------------------------------------

    def repack(self, out_path, replacements: Optional[Dict[str, bytes]] = None,
               additions: Optional[Dict[str, bytes]] = None,
               removals: Optional[Iterable[str]] = None) -> None:
        """Write a complete new archive of the same format to `out_path`.
        Unchanged entries keep their content and order, additions go last.
        The source file is never modified; `out_path` must be another file."""
        if not self.writable:
            raise UnsupportedError(
                self._readonly_reason or f"this {self.format} archive cannot be repacked")
        out = Path(out_path)
        if _same_file(out, Path(self.path)):
            raise UnsupportedError(
                "refusing to repack onto the source archive itself; write to a "
                "different path and replace the original afterwards")

        removed: Set[int] = set()
        if isinstance(removals, str):
            removals = [removals]
        for name in removals or ():
            removed.add(self._lookup(name, "remove"))
        replaced: Dict[int, bytes] = {}
        for name, data in (replacements or {}).items():
            index = self._lookup(name, "replace")
            if index in removed:
                raise LocationError(f"{name!r} is both replaced and removed")
            replaced[index] = bytes(data)

        plan: List[PlanItem] = [
            PlanItem(i, entry.name, replaced.get(i))
            for i, entry in enumerate(self.entries) if i not in removed]
        kept = {item.name for item in plan}
        for name, data in (additions or {}).items():
            if not isinstance(name, str):
                raise UnsupportedError(f"entry names must be strings, not {type(name).__name__}")
            if name in kept:
                raise LocationError(
                    f"cannot add {name!r}: the archive already has an entry of that "
                    "name (use replacements)")
            self._check_new_name(name)
            kept.add(name)
            plan.append(PlanItem(None, name, bytes(data)))
        for item in plan:
            if item.index is not None and item.data is None:
                self._check_entry(item.index, None)
        self._check_plan(plan)

        fd, tmp = tempfile.mkstemp(prefix=out.name + ".", suffix=".tmp",
                                   dir=str(out.parent) if str(out.parent) else ".")
        try:
            with os.fdopen(fd, "wb") as dst, self._session() as handle:
                self._write(handle, dst, plan)
            with contextlib.suppress(OSError):
                shutil.copymode(self.path, tmp)
            os.replace(tmp, str(out))
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def _check_plan(self, plan: List[PlanItem]) -> None:
        """Format-specific validation before anything is written."""


def _same_file(a: Path, b: Path) -> bool:
    try:
        if a.exists() and b.exists() and os.path.samefile(str(a), str(b)):
            return True
    except OSError:
        pass
    try:
        return a.resolve() == b.resolve()
    except (OSError, RuntimeError):
        return os.path.abspath(str(a)) == os.path.abspath(str(b))
