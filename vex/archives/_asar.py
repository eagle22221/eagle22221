"""Electron ASAR, written from electron/asar (disk.ts, pickle.ts).

The file starts with two Chromium "pickles" and then the file data:

    0   u32 4                     payload size of the size pickle
    4   u32 header pickle size    = 8 + JSON length rounded up to 4
    8   u32 payload size          = header pickle size - 4
    12  u32 JSON length
    16  JSON (UTF-8), NUL padded to a multiple of 4
    8 + header pickle size: file data

The JSON is a tree: {"files": {name: node}} where a node is a directory
({"files": {...}}), a symbolic link ({"link": target}) or a file
({"size": n, "offset": "decimal string"} with optional "executable",
"integrity", or "unpacked": true for files kept next to the archive in
<archive>.unpacked/). Offsets count from the start of the file data.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, NamedTuple, Optional, Tuple

from ..errors import ParseError, UnsupportedError
from ._base import (
    CHUNK, Archive, ArchiveEntry, PlanItem, UnsafeEntryError, limit, range_chunks, read_at,
    unsafe_reason,
)

_MAX_DEPTH = 256
_BLOCK = 4 * 1024 * 1024        # integrity block size used by @electron/asar
_UINT32 = 0xFFFFFFFF
_DIGITS = re.compile(r"[0-9]{1,20}\Z")


class _Node(NamedTuple):
    parts: Tuple[str, ...]
    offset: Optional[int]       # absolute; None for unpacked files
    size: int


def _header_fields(head: bytes) -> Optional[Tuple[int, int]]:
    """(header pickle size, JSON length) if the first 16 bytes are the two
    pickle headers of an ASAR archive."""
    if len(head) < 17:
        return None
    four, header_size, payload, json_len = struct.unpack_from("<4I", head)
    if four != 4 or header_size != payload + 4 or json_len + 4 > payload or json_len < 2:
        return None
    if head[16:17] != b"{":
        return None
    return header_size, json_len


def _files(files: Dict[str, Any]) -> Iterator[Tuple[Tuple[str, ...], Dict[str, Any], str, Any]]:
    """Every node of the tree in document order, without recursion:
    (path parts, the "files" dict holding it, its key, the node)."""
    stack: List[Tuple[Iterator[Tuple[str, Any]], Tuple[str, ...], Dict[str, Any]]] = [
        (iter(list(files.items())), (), files)]
    while stack:
        items, parts, holder = stack[-1]
        try:
            key, node = next(items)
        except StopIteration:
            stack.pop()
            continue
        yield parts + (key,), holder, key, node
        if isinstance(node, dict) and isinstance(node.get("files"), dict):
            if len(stack) >= _MAX_DEPTH:
                raise ParseError(f"ASAR header nests directories deeper than {_MAX_DEPTH}")
            stack.append((iter(list(node["files"].items())), parts + (key,), node["files"]))


def _is_file(node: Any) -> bool:
    return isinstance(node, dict) and "files" not in node and "link" not in node


def _integrity(data: bytes) -> Dict[str, Any]:
    blocks = [hashlib.sha256(data[i:i + _BLOCK]).hexdigest()
              for i in range(0, len(data), _BLOCK)] or [hashlib.sha256(b"").hexdigest()]
    return {"algorithm": "SHA256", "hash": hashlib.sha256(data).hexdigest(),
            "blockSize": _BLOCK, "blocks": blocks}


class AsarArchive(Archive):
    format = "asar"

    @staticmethod
    def matches(head: bytes, fh: BinaryIO, size: int) -> bool:
        return _header_fields(head) is not None

    def _load(self, fh: BinaryIO, size: int, head: bytes) -> None:
        fields = _header_fields(head)
        if fields is None:
            raise ParseError("not an ASAR header")
        header_size, json_len = fields
        if 8 + header_size > size:
            raise ParseError(
                f"ASAR header ({header_size} bytes) is larger than the file ({size} bytes)")
        if json_len > limit("MAX_INDEX_SIZE"):
            raise UnsupportedError("ASAR header exceeds vex.archives.MAX_INDEX_SIZE")
        raw = read_at(fh, 16, json_len, size, "ASAR header")
        try:
            header = json.loads(raw.decode("utf-8"))
        except (ValueError, RecursionError) as exc:      # includes bad UTF-8 and bad JSON
            raise ParseError(f"ASAR header is not valid JSON: {exc}") from None
        if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
            raise ParseError('ASAR header has no "files" object')
        self._header = header
        self._data_base = 8 + header_size
        maximum = limit("MAX_ENTRIES")
        nodes = links = unpacked = 0
        self._integrity = False
        for parts, _holder, _key, node in _files(header["files"]):
            nodes += 1
            if nodes > maximum:
                self._check_count(nodes, "header nodes")
            if not isinstance(node, dict):
                raise ParseError(f"ASAR header entry {'/'.join(parts)!r} is not an object")
            if "files" in node:
                if not isinstance(node["files"], dict):
                    raise ParseError(f"ASAR directory {'/'.join(parts)!r} is malformed")
                continue
            if "link" in node:
                links += 1
                continue
            length = node.get("size")
            if type(length) is not int or length < 0:
                raise ParseError(f"ASAR entry {'/'.join(parts)!r} has no valid size")
            self._integrity = self._integrity or "integrity" in node
            broken = None
            if node.get("unpacked"):
                unpacked += 1
                offset = None
            else:
                stored = node.get("offset")
                if isinstance(stored, str) and _DIGITS.match(stored):
                    offset = self._data_base + int(stored)
                elif type(stored) is int and stored >= 0:
                    offset = self._data_base + stored
                else:
                    raise ParseError(f"ASAR entry {'/'.join(parts)!r} has no valid offset")
                if offset + length > size:
                    broken = (f"data at offset {offset:#x} (+{length} bytes) is outside "
                              f"the file ({size} bytes)")
            self._add(ArchiveEntry("/".join(parts), length, offset, False, False),
                      _Node(parts, offset, length), broken)
        self._check_count(len(self.entries))
        if unpacked:
            self.notes.append(
                f"{unpacked} files are marked unpacked: they live next to the archive in "
                f"{Path(self.path).name}.unpacked/, which must accompany a repacked archive")
        if links:
            self.notes.append(
                f"{links} symbolic links are not listed (they are kept on repack)")
        if self._integrity:
            self.notes.append(
                "the header carries per-file integrity hashes: repack updates them, but "
                "an app with ASAR integrity validation enabled also stores a hash of the "
                "whole header in its executable, which vex does not update")
        self._finish()

    # -- reading ---------------------------------------------------------------

    def _unpacked_path(self, index: int) -> Path:
        record: _Node = self._records[index]
        name = self.entries[index].name
        for part in record.parts:
            if "/" in part or unsafe_reason(part):
                raise UnsafeEntryError(
                    f"unsafe unpacked entry name {name!r}: refusing to look it up on disk")
        base = Path(self.path + ".unpacked")
        target = base.joinpath(*record.parts)
        try:
            resolved_base, resolved = base.resolve(), target.resolve()
        except (OSError, RuntimeError):
            resolved_base, resolved = base, None
        if resolved is None or resolved_base not in resolved.parents or not resolved.is_file():
            raise ParseError(
                f"{name!r} is stored outside the archive and was not found at {target}")
        return resolved

    def _chunks(self, handle: Any, index: int) -> Iterator[bytes]:
        record: _Node = self._records[index]
        if record.offset is not None:
            return range_chunks(handle, record.offset, record.size,
                                repr(self.entries[index].name))
        return self._unpacked_chunks(self._unpacked_path(index), record.size)

    @staticmethod
    def _unpacked_chunks(path: Path, size: int) -> Iterator[bytes]:
        left = size + 1                 # one extra byte reveals a longer file
        with open(path, "rb") as source:
            while left > 0:
                chunk = source.read(min(CHUNK, left))
                if not chunk:
                    break
                left -= len(chunk)
                yield chunk

    # -- writing ---------------------------------------------------------------

    def _check_plan(self, plan: List[PlanItem]) -> None:
        for item in plan:
            if item.index is not None and item.data is not None \
                    and self._records[item.index].offset is None:
                raise UnsupportedError(
                    f"{item.name!r} is stored outside the archive (unpacked): replace the "
                    f"file in {Path(self.path).name}.unpacked/ instead")
            if item.data is not None and len(item.data) > _UINT32:
                raise UnsupportedError("ASAR cannot hold files larger than 4 GiB")

    def _write(self, handle: Any, out: BinaryIO, plan: List[PlanItem]) -> None:
        try:
            tree = json.loads(json.dumps(self._header))         # private deep copy
        except (ValueError, RecursionError) as exc:
            raise ParseError(f"ASAR header cannot be rewritten: {exc}") from None
        originals = [(holder, key, node) for _parts, holder, key, node in _files(tree["files"])
                     if _is_file(node)]
        kept = {item.index: item for item in plan if item.index is not None}
        source: Dict[int, Any] = {}             # id(node) -> bytes or source entry index
        for index, (holder, key, node) in enumerate(originals):
            item = kept.get(index)
            if item is None:
                del holder[key]
            elif item.data is not None:
                node["size"] = len(item.data)
                if "integrity" in node:
                    node["integrity"] = _integrity(item.data)
                source[id(node)] = item.data
            else:
                source[id(node)] = index
        for item in plan:
            if item.index is not None:
                continue
            parts = item.name.split("/")
            files = tree["files"]
            for part in parts[:-1]:
                child = files.get(part)
                if child is None:
                    child = files[part] = {"files": {}}
                elif not isinstance(child, dict) or not isinstance(child.get("files"), dict):
                    raise UnsupportedError(
                        f"cannot add {item.name!r}: {part!r} is not a directory in the archive")
                files = child["files"]
            if parts[-1] in files:
                raise UnsupportedError(
                    f"cannot add {item.name!r}: the archive already has a directory or "
                    "link of that name")
            data = item.data or b""
            node = {"size": len(data), "offset": "0"}
            if self._integrity:
                node["integrity"] = _integrity(data)
            files[parts[-1]] = node
            source[id(node)] = data

        order = []
        cursor = 0
        for _parts, _holder, _key, node in _files(tree["files"]):
            if not _is_file(node) or node.get("unpacked"):
                continue
            if node["size"] > _UINT32:
                raise UnsupportedError("ASAR cannot hold files larger than 4 GiB")
            node["offset"] = str(cursor)
            cursor += node["size"]
            order.append(node)

        try:
            raw = json.dumps(tree, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError:              # lone surrogates: escape instead
            raw = json.dumps(tree, separators=(",", ":")).encode("ascii")
        aligned = (len(raw) + 3) & ~3
        out.write(struct.pack("<4I", 4, aligned + 8, aligned + 4, len(raw)))
        out.write(raw + bytes(aligned - len(raw)))
        for node in order:
            payload = source[id(node)]
            if isinstance(payload, int):
                self._copy_entry(handle, payload, out)
            else:
                out.write(payload)
