"""Plain, JSON-ready views of a binary. The command line (--json and text)
and the web interface are both rendered from these, so they cannot disagree.

Addresses are hex strings ("0x140001000"): JSON numbers lose precision
above 2**53, which 64-bit addresses can exceed.
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from . import strings as strings_mod
from .analysis import Analysis
from .errors import BinspectError, LocationError
from .model import Binary, entropy

# key -> (label, meaning). "protect": yes is good. "risk": a value is a
# warning sign. "info": neither good nor bad.
SECURITY_LABELS = {
    "nx": ("Non-executable stack/data (NX, DEP)", "protect"),
    "pie": ("Position-independent executable (PIE)", "protect"),
    "relro": ("Read-only relocations (RELRO)", "protect"),
    "canary": ("Stack canary", "protect"),
    "fortify": ("Fortified libc calls (FORTIFY_SOURCE)", "protect"),
    "stripped": ("Symbols stripped", "info"),
    "rpath": ("RPATH", "risk"),
    "runpath": ("RUNPATH", "risk"),
    "aslr": ("Address randomisation (ASLR)", "protect"),
    "high_entropy_va": ("High-entropy 64-bit ASLR", "protect"),
    "cfg": ("Control Flow Guard", "protect"),
    "seh": ("Structured exception handling used", "info"),
    "force_integrity": ("Forced code-integrity checks", "info"),
    "signed": ("Authenticode signature present", "info"),
    "dotnet": (".NET (managed) assembly", "info"),
}


def hx(value: Optional[int]) -> Optional[str]:
    return None if value is None else f"{value:#x}"


def _compile(pattern: Optional[str]):
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise BinspectError(f"invalid regular expression {pattern!r}: {exc}") from None


def _security_details(b: Binary) -> List[dict]:
    rows = []
    for key, value in b.security.items():
        label, meaning = SECURITY_LABELS.get(key, (key, "info"))
        if value is None and meaning == "risk":
            continue
        if meaning == "protect":
            state = "neutral" if value is None else \
                "good" if value in (True, "full") else \
                "warn" if value == "partial" else "bad"
        elif meaning == "risk":
            state = "warn"
        else:
            state = "neutral"
        shown = "n/a" if value is None else "yes" if value is True else \
            "no" if value is False else str(value)
        rows.append({"key": key, "label": label, "value": shown, "state": state})
    return rows


def info(b: Binary) -> dict:
    return {
        "path": b.path,
        "name": os.path.basename(b.path) if b.path else None,
        "format": b.format, "arch": b.arch, "bits": b.bits, "endian": b.endian,
        "kind": b.kind,
        "entry": hx(b.entry), "image_base": hx(b.image_base),
        "size": b.size, "entropy": round(entropy(b.data), 3),
        "hashes": b.hashes,
        "libraries": list(b.libraries),
        "security": dict(b.security),
        "security_details": _security_details(b),
        "metadata": dict(b.metadata),
        "counts": {"sections": len(b.sections), "symbols": len(b.symbols),
                   "imports": len(b.imports), "exports": len(b.exports)},
        "warnings": list(b.warnings),
    }


def sections(b: Binary) -> List[dict]:
    return [{
        "name": s.name, "address": hx(s.vaddr) if s.vaddr else None, "vsize": s.vsize,
        "offset": s.offset, "size": s.size, "perms": s.perms, "type": s.type,
        "entropy": round(b.section_entropy(s), 3),
    } for s in b.sections]


def segments(b: Binary) -> List[dict]:
    return [{"type": s.type, "address": hx(s.vaddr), "vsize": s.vsize,
             "offset": s.offset, "size": s.size, "perms": s.perms} for s in b.segments]


def imports(b: Binary) -> List[dict]:
    return [{"library": i.library, "name": i.name, "address": hx(i.address),
             "ordinal": i.ordinal, "version": i.version, "delayed": i.delayed}
            for i in b.imports]


def exports(b: Binary) -> List[dict]:
    return [{"name": e.name, "address": hx(e.address), "ordinal": e.ordinal,
             "forwarder": e.forwarder} for e in b.exports]


def symbols(b: Binary, pattern: Optional[str] = None) -> List[dict]:
    rx = _compile(pattern)
    return [{"name": s.name, "address": hx(s.address), "size": s.size, "type": s.type,
             "binding": s.binding, "section": s.section}
            for s in sorted(b.symbols, key=lambda s: s.address)
            if rx is None or rx.search(s.name)]


def strings(b: Binary, min_length: int = 4, encoding: str = "all",
            pattern: Optional[str] = None, tagged: bool = False) -> List[dict]:
    rx = _compile(pattern)
    return [{"offset": s.offset, "address": hx(s.vaddr), "section": s.section,
             "encoding": s.encoding, "text": s.text, "tags": s.tags}
            for s in strings_mod.extract(b, min_length, encoding)
            if (rx is None or rx.search(s.text)) and (s.tags or not tagged)]


def functions(a: Analysis, pattern: Optional[str] = None) -> List[dict]:
    rx = _compile(pattern)
    return [{"address": hx(f.address), "size": f.size, "name": f.name, "source": f.source}
            for f in a.functions if rx is None or rx.search(f.name)]


def disassembly(a: Analysis, location: Optional[str] = None,
                count: Optional[int] = None) -> dict:
    """Listing at a location (default: the entry point). A whole function when
    the location is a function start and no count is given."""
    b = a.binary
    funcs = {f.address: f for f in a.functions}      # also registers names
    if location is None:
        if b.entry is not None:
            address = b.entry
        elif b.executable_ranges():
            address = b.executable_ranges()[0][0]
        else:
            raise LocationError("this file has no entry point or code section; "
                                "give a location")
    else:
        found = a.resolve(location)
        address = next((x for x in found if a.dis._in_code(x)), found[0])
    function = funcs.get(address)
    if count is None and function is not None:
        insns = a.disassemble_function(function)
    else:
        insns = a.dis.disassemble(address, count=count or 32)
    return {
        "address": hx(address),
        "name": a.label(address),
        "function": None if function is None else
        {"address": hx(function.address), "size": function.size, "name": function.name},
        "instructions": [{
            "address": hx(i.address), "bytes": i.raw.hex(), "mnemonic": i.mnemonic,
            "operands": i.operands, "kind": i.kind, "target": hx(i.target),
            "refs": [hx(r) for r in i.refs], "comment": i.comment,
            "label": funcs[i.address].name if i.address in funcs else None,
        } for i in insns],
    }


def xrefs(a: Analysis, target: Optional[str] = None, string: Optional[str] = None) -> List[dict]:
    if string:
        addresses = a.string_addresses(string)
        if not addresses:
            raise LocationError(f"no string containing {string!r} with an address")
    elif target:
        addresses = a.resolve(target)
    else:
        raise LocationError("xrefs needs a target: an address, a name, or --string TEXT")
    return [{"address": hx(x.address), "kind": x.kind, "function": x.function,
             "text": x.text} for x in a.xrefs(addresses)]


def hexdump(b: Binary, address: Optional[int] = None, offset: Optional[int] = None,
            length: int = 256) -> dict:
    """Rows of 16 bytes starting at a file offset or a virtual address."""
    if offset is None:
        if address is None:
            address = b.entry if b.entry is not None else None
        offset = 0 if address is None else b.vaddr_to_offset(address)
        if offset is None:
            raise LocationError(f"address {address:#x} is not backed by the file")
    if not 0 <= offset < max(b.size, 1):
        raise LocationError(f"offset {offset:#x} is outside the file ({b.size:#x} bytes)")
    data = b.data[offset:offset + max(0, length)]
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        rows.append({
            "offset": offset + i,
            "address": hx(b.offset_to_vaddr(offset + i)),
            "hex": " ".join(f"{c:02x}" for c in chunk),
            "ascii": "".join(chr(c) if 0x20 <= c <= 0x7E else "." for c in chunk),
        })
    return {"offset": offset, "length": len(data), "rows": rows}


def layout(b: Binary) -> dict:
    """The file as consecutive, non-overlapping regions, for drawing it to scale."""
    items = [(off, size, name, kind) for name, off, size, kind in b.regions]
    for s in b.sections:
        if s.size:
            kind = "code" if "x" in s.perms else "data" if s.perms != "---" else "meta"
            items.append((s.offset, s.size, s.name or "(unnamed)", kind))
    overlay = b.metadata.get("overlay")
    if overlay:
        items.append((overlay["offset"], overlay["size"], "overlay", "overlay"))
    regions = []
    cursor = 0
    for off, size, name, kind in sorted(items, key=lambda i: (i[0], -i[1])):
        end = min(off + size, b.size)
        if end <= cursor:
            continue                # fully inside something already drawn
        if off > cursor:
            regions.append({"name": "padding", "offset": cursor, "size": off - cursor,
                            "kind": "padding"})
        start = max(off, cursor)
        regions.append({"name": name, "offset": start, "size": end - start, "kind": kind})
        cursor = end
    if cursor < b.size:
        regions.append({"name": "padding", "offset": cursor, "size": b.size - cursor,
                        "kind": "padding"})
    return {"size": b.size, "regions": regions}


def report(b: Binary, a: Optional[Analysis]) -> Dict[str, object]:
    return {
        "info": info(b),
        "sections": sections(b),
        "imports": imports(b),
        "exports": exports(b),
        "strings": strings(b, tagged=True),
        "functions": functions(a) if a is not None else None,
    }
