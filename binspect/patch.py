"""Modify bytes in an executable without breaking it.

Everything here overwrites bytes in place: nothing is inserted, so no offset
or address in the file moves and its size never changes. A patch is located
by file offset or by virtual address (translated with the binary's own
section/segment mapping), validated completely, and only then written.

Output files are written atomically (temp file next to the destination, then
os.replace). When a file is modified in place, the original is first saved
as `<file>.bak`; an existing backup is never overwritten, because it is the
only pristine copy.

The patcher is deliberately general-purpose: it writes the bytes it is given
at the place it is told. Patching a signed Windows program invalidates its
Authenticode signature, and a PE checksum (only verified for drivers and a
few system files) is not updated.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union

from .errors import BinspectError, LocationError, UnknownFormatError, UnsupportedError
from .model import Binary

PathLike = Union[str, "os.PathLike[str]"]

_ENCODINGS = {"ascii": ("ascii", b"\0"), "utf16": ("utf-16-le", b"\0\0")}

# No-op instructions as the bytes of a little-endian image.
_X86_NOP = b"\x90"
_AARCH64_NOP = bytes.fromhex("1f2003d5")        # nop (hint #0), 0xD503201F
_ARM_NOP = bytes.fromhex("00f020e3")            # nop, ARM (A32) encoding 0xE320F000
_EF_ARM_BE8 = 0x00800000                        # ELF e_flags: big-endian data, LE code


@dataclass
class PatchResult:
    offset: int               # file offset that was written
    vaddr: Optional[int]      # virtual address of that offset, if it has one
    old: bytes
    new: bytes


# --- writing files ----------------------------------------------------------

def _same_file(src: str, dst: str) -> bool:
    if os.path.realpath(src) == os.path.realpath(dst):
        return True
    try:
        return os.path.samefile(src, dst)       # other spellings, case-insensitive disks
    except OSError:
        return False                            # dst does not exist yet


def _write_atomically(path: str, data: Optional[bytes], like: str) -> str:
    """Write `data` (or a copy of the file `like` when data is None) to a temp
    file in the directory of `path`, flushed to disk and with the permission
    bits of `like`. Returns the temp file's name; the caller renames it."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            if data is None:
                with open(like, "rb") as original:
                    shutil.copyfileobj(original, f)
            else:
                f.write(data)
            f.flush()
            os.fsync(f.fileno())
        try:
            shutil.copymode(like, tmp)
        except OSError:
            pass                                # e.g. a file system without modes
    except BaseException:
        _remove(tmp)
        raise
    return tmp


def _remove(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _back_up(src: str) -> None:
    """Save `src` as `<src>.bak` unless a backup already exists."""
    backup = src + ".bak"
    if os.path.lexists(backup):
        return
    tmp = _write_atomically(backup, None, src)
    try:
        try:
            os.link(tmp, backup)                # fails instead of overwriting
        except FileExistsError:
            pass                                # somebody else just made one: keep it
        except OSError:
            # No hard links here (FAT, some network shares): fall back to rename.
            if not os.path.lexists(backup):
                os.replace(tmp, backup)
                return
    finally:
        _remove(tmp)


def save_copy(src_path: PathLike, dst_path: PathLike, data: bytes) -> None:
    """Write `data`, a modified image of the file `src_path`, to `dst_path`.

    The write is atomic: the bytes go to a temp file in the destination
    directory, which then replaces `dst_path` in one step, so a crash leaves
    either the old file or the new one, never half of each. The output gets
    the permission bits of the source. When the destination is the source
    file itself, the original is first saved as `<src>.bak`, unless that file
    already exists (an existing backup is never overwritten).
    """
    src, dst = os.fspath(src_path), os.fspath(dst_path)
    in_place = _same_file(src, dst)
    if in_place:
        dst = os.path.realpath(dst)             # replace the file, not a link to it
    tmp = _write_atomically(dst, bytes(data), src)
    try:
        if in_place:
            _back_up(src)
        os.replace(tmp, dst)
    except BaseException:
        _remove(tmp)
        raise


# --- locating ---------------------------------------------------------------

def _try_load(data: bytes, path: str) -> Optional[Binary]:
    """The parsed binary, or None when the file is not a (readable) ELF or PE:
    such a file has no virtual addresses but can still be patched by offset."""
    from . import load_bytes
    try:
        return load_bytes(data, path)
    except BinspectError:
        return None


def _locate(data: bytes, path: str, size: int, offset: Optional[int],
            vaddr: Optional[int]) -> PatchResult:
    """Validate a patch location; returns it with `old` filled in."""
    if (offset is None) == (vaddr is None):
        raise LocationError("give exactly one of offset= (file offset) or "
                            "vaddr= (virtual address)")
    if size <= 0:
        raise LocationError("patch data is empty: there is nothing to write")
    if vaddr is not None:
        from . import load_bytes
        try:
            binary = load_bytes(data, path)
        except UnknownFormatError:
            raise LocationError(
                "virtual addresses need an ELF or PE file; patch this file "
                "by file offset instead") from None
        offset = binary.vaddr_to_offset(vaddr)
        if offset is None:
            raise LocationError(
                f"address {vaddr:#x} is not backed by bytes in the file (unmapped, "
                "or zero-initialised memory such as .bss)")
        available = len(binary.read(vaddr, size))
        if available < size:
            raise LocationError(
                f"only {available} of the {size} bytes at {vaddr:#x} are backed by "
                "the file; the patch would run past the end of its section or segment")
    else:
        assert offset is not None
        if offset < 0 or offset + size > len(data):
            raise LocationError(
                f"{size} bytes at file offset {offset:#x} do not lie inside the "
                f"file ({len(data):#x} bytes); a patch never changes the file size")
        binary = _try_load(data, path)
        vaddr = binary.offset_to_vaddr(offset) if binary is not None else None
    return PatchResult(offset=offset, vaddr=vaddr, old=data[offset:offset + size], new=b"")


# --- public API -------------------------------------------------------------

def apply_patch(src_path: PathLike, dst_path: PathLike, data: bytes, *,
                offset: Optional[int] = None,
                vaddr: Optional[int] = None) -> PatchResult:
    """Overwrite `len(data)` bytes of the file `src_path` and write the result
    to `dst_path`.

    Exactly one of `offset` (file offset) and `vaddr` (virtual address) says
    where. A virtual address is translated with the ELF/PE mapping of the
    file and must be backed by file bytes for the whole length; an offset
    must lie completely inside the file and works for any file, executable
    or not. Nothing is inserted and the file size never changes. Anything
    else raises LocationError before a single byte is written.

    The copy is written atomically; with `dst_path == src_path` the original
    is first saved as `<src>.bak` (see save_copy).
    """
    src = os.fspath(src_path)
    new = bytes(data)
    original = Path(src).read_bytes()
    result = _locate(original, src, len(new), offset, vaddr)
    result.new = new
    end = result.offset + len(new)
    save_copy(src, dst_path, original[:result.offset] + new + original[end:])
    return result


def nop_bytes(binary: Binary, length: int) -> bytes:
    """Exactly `length` bytes of no-op instructions for the binary's CPU.

    x86 and x86_64 use the one-byte 0x90. AArch64 and 32-bit ARM have
    four-byte instructions, so `length` must be a multiple of 4 there
    (LocationError otherwise). The ARM filler is the ARM-mode (A32) nop; it
    is not valid in Thumb code. Byte order follows the binary: big-endian
    ARM images get big-endian instructions unless they are BE8 images, whose
    code is little-endian, as AArch64 code always is. Other architectures
    raise UnsupportedError.
    """
    if length < 0:
        raise LocationError(f"cannot produce {length} bytes of no-ops")
    arch = binary.arch
    if arch in ("x86", "x86_64"):
        unit = _X86_NOP
    elif arch == "aarch64":
        unit = _AARCH64_NOP
    elif arch == "arm":
        unit = _ARM_NOP if _arm_code_is_little_endian(binary) else _ARM_NOP[::-1]
    else:
        raise UnsupportedError(f"no no-op encoding known for architecture {arch or 'unknown'!r}")
    if length % len(unit):
        raise LocationError(
            f"{arch} instructions are {len(unit)} bytes long; {length} bytes "
            "would leave a partial instruction")
    return unit * (length // len(unit))


def _arm_code_is_little_endian(binary: Binary) -> bool:
    if binary.endian != "big":
        return True
    # ARMv6+ "BE8" executables are big-endian files whose code is little-endian.
    header = binary.data
    if binary.format == "ELF" and len(header) >= 40 and header[4] == 1:
        return bool(int.from_bytes(header[36:40], "big") & _EF_ARM_BE8)
    return False


def replace_string(src_path: PathLike, dst_path: PathLike, old: str, new: str,
                   encoding: str = "ascii") -> List[PatchResult]:
    """Replace every occurrence of the text `old` by `new`, in place.

    `encoding` is "ascii" or "utf16" (UTF-16LE, the wide strings of Windows
    programs). Occurrences are found by a plain byte search for the encoded
    text, so text inside a longer string matches too. Because nothing in an
    executable can move, `new` may not be longer than `old`; shorter text is
    padded with NUL characters to the old length, which ends a C string
    early. Returns one PatchResult per occurrence, in file order.

    LocationError: `new` is longer than `old`, `old` is empty or does not
    occur, or the text cannot be written in the encoding. Nothing is written
    in those cases. Same atomic-write and backup rules as apply_patch.
    """
    if encoding not in _ENCODINGS:
        raise UnsupportedError(
            f"unknown string encoding {encoding!r} (use 'ascii' or 'utf16')")
    codec, nul = _ENCODINGS[encoding]
    try:
        old_bytes, new_bytes = old.encode(codec), new.encode(codec)
    except UnicodeEncodeError as exc:
        raise LocationError(f"text cannot be written as {encoding}: {exc}") from None
    if not old_bytes:
        raise LocationError("the text to replace is empty")
    if len(new_bytes) > len(old_bytes):
        raise LocationError(
            f"the new text is longer than the old one ({len(new_bytes)} > "
            f"{len(old_bytes)} bytes): strings can only be replaced in place by "
            "equal or shorter text, because nothing after them may move")
    new_bytes += nul * ((len(old_bytes) - len(new_bytes)) // len(nul))

    src = os.fspath(src_path)
    original = Path(src).read_bytes()
    offsets = []
    position = original.find(old_bytes)
    while position != -1:
        offsets.append(position)
        position = original.find(old_bytes, position + len(old_bytes))
    if not offsets:
        raise LocationError(f"the {encoding} text {old!r} does not occur in the file")

    binary = _try_load(original, src)
    image = bytearray(original)
    results = []
    for position in offsets:
        image[position:position + len(old_bytes)] = new_bytes
        results.append(PatchResult(
            offset=position,
            vaddr=binary.offset_to_vaddr(position) if binary is not None else None,
            old=old_bytes, new=new_bytes))
    save_copy(src, dst_path, bytes(image))
    return results
