"""Whole-program analysis built on one linear sweep of the code:
function discovery, name resolution and cross-references."""
from __future__ import annotations

import bisect
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from . import strings as strings_mod
from .disasm import Disassembler, Instruction
from .errors import LocationError
from .model import Binary


@dataclass
class Function:
    address: int
    size: int
    name: str
    source: str     # symbol, export, pdata, libc_start_main, entry, call


@dataclass
class Xref:
    address: int
    kind: str                   # call, jump, data
    function: Optional[str]     # "main+0x4c", or None outside known functions
    text: str                   # the referencing instruction


class Analysis:
    def __init__(self, binary: Binary):
        self.binary = binary
        self.dis = Disassembler(binary)
        self._functions: Optional[List[Function]] = None
        self._starts: List[int] = []
        # (address, kind, refs, text) for every instruction that mentions an address
        self._index: List[Tuple[int, str, Tuple[int, ...], str]] = []
        self._thunks: Dict[int, object] = {}

    # -- sweep ----------------------------------------------------------------

    def _sweep(self) -> Tuple[set, Optional[int]]:
        b, dis = self.binary, self.dis
        calls = set()
        main = None
        start_slots = {i.address for i in b.imports
                       if i.name == "__libc_start_main" and i.address is not None}
        last_arg = None             # most recent "lea rdi, [rip+x]" (1st C argument)
        prev = None
        for insn in dis.sweep():
            if insn.refs:
                self._index.append((insn.address, insn.kind, tuple(insn.refs), insn.text))
                if insn.kind == "call" and insn.target is not None and dis._in_code(insn.target):
                    calls.add(insn.target)
                slot_ref = insn.kind in ("call", "jump") and insn.target is None
                if slot_ref and insn.kind == "jump" and insn.refs[0] in dis._slots:
                    # "jmp [import slot]" at a function boundary is a PLT entry
                    # or import thunk; inside a function it is a tail call.
                    start = insn.address
                    boundary = prev is None or prev.kind in ("ret", "jump") or \
                        prev.mnemonic in ("int3", "nop", ".byte", "endbr64", "endbr32", "hlt")
                    if prev is not None and prev.mnemonic in ("endbr64", "endbr32"):
                        start = prev.address
                    if boundary:
                        self._thunks[start] = dis._slots[insn.refs[0]]
                if main is None and start_slots and b.arch == "x86_64":
                    if insn.mnemonic in ("lea", "mov") and \
                            insn.operands.startswith(("rdi, ", "edi, ")):
                        last_arg = insn.refs[0]
                    elif insn.kind == "call" and last_arg is not None and (
                            insn.refs[0] in start_slots
                            or (insn.target is not None
                                and getattr(dis.thunk_import(insn.target), "name", "")
                                == "__libc_start_main")):
                        main = last_arg
            prev = insn
        return calls, main

    # -- functions ------------------------------------------------------------

    @property
    def functions(self) -> List[Function]:
        if self._functions is None:
            self._functions = self._find_functions()
            self._starts = [f.address for f in self._functions]
            self.dis.add_names(self._functions)
        return self._functions

    def _find_functions(self) -> List[Function]:
        b, dis = self.binary, self.dis
        calls, main = self._sweep()
        found: Dict[int, List] = {}             # address -> [name, size, source]

        def add(address, name, size, source):
            if dis._in_code(address):
                found.setdefault(address, [name, size, source])

        for s in b.symbols:
            if s.type == "func":
                add(s.address, s.name, s.size, "symbol")
        for e in b.exports:
            if e.address is not None:
                add(e.address, e.name, 0, "export")
        for begin, end in b.function_ranges:
            add(begin, None, end - begin, "pdata")
            if not found.get(begin, [0, 1])[1]:
                found[begin][1] = end - begin   # exact size for a named function
        if main is not None:
            add(main, "main", 0, "libc_start_main")
        if b.entry is not None:
            add(b.entry, "entry", 0, "entry")
        for target in sorted(calls):
            add(target, None, 0, "call")

        starts = sorted(found)
        ranges = b.executable_ranges()
        out = []
        for i, address in enumerate(starts):
            name, size, source = found[address]
            if not name:
                name = dis.thunk_at(address) or f"sub_{address:x}"
            if not size:
                limit = next(s + n for s, n in ranges if s <= address < s + n)
                if i + 1 < len(starts):
                    limit = min(limit, starts[i + 1])
                size = limit - address
            out.append(Function(address, size, name, source))
        return out

    def function_at(self, address: int) -> Optional[Function]:
        """The function whose body contains address."""
        funcs = self.functions
        i = bisect.bisect_right(self._starts, address) - 1
        if i >= 0 and address < funcs[i].address + funcs[i].size:
            return funcs[i]
        return None

    def disassemble_function(self, function: Function) -> List[Instruction]:
        return self.dis.disassemble(function.address, end=function.address + function.size)

    def label(self, address: int) -> Optional[str]:
        """"function+0x12" for code, else whatever name the address has."""
        f = self.function_at(address)
        if f is not None:
            off = address - f.address
            return f.name if off == 0 else f"{f.name}+{off:#x}"
        return self.dis.name_at(address)

    # -- name resolution ------------------------------------------------------

    def resolve(self, text: str) -> List[int]:
        """Addresses for a user-supplied location: a hex/decimal address, a
        symbol, function or export name, "entry", or an import name
        (optionally "library!name"), which yields its stub and its slot."""
        text = text.strip()
        b = self.binary
        try:
            return [int(text, 0)]
        except ValueError:
            pass
        found = {s.address for s in b.symbols if s.name == text}
        found |= {e.address for e in b.exports if e.name == text and e.address is not None}
        found |= {f.address for f in self.functions if f.name == text}
        if not found and text == "entry" and b.entry is not None:
            found.add(b.entry)
        library, _, name = text.rpartition("!")
        for imp in b.imports:
            if imp.name != name or (library and (imp.library or "").lower() != library.lower()):
                continue
            if imp.address is not None:
                found.add(imp.address)
            found |= {a for a, t in self._thunks.items() if t is imp}
        if not found:
            raise LocationError(
                f"cannot resolve {text!r}: not an address, symbol, function or import name")
        return sorted(found)

    def string_addresses(self, text: str) -> List[int]:
        """Addresses of strings containing text (for xref lookups by content)."""
        return [s.vaddr for s in strings_mod.extract(self.binary)
                if text in s.text and s.vaddr is not None]

    # -- cross-references -----------------------------------------------------

    def xrefs(self, addresses: Iterable[int]) -> List[Xref]:
        """Every instruction that calls, jumps to, or mentions any address."""
        targets = set(addresses)
        self.functions                      # make sure the sweep has run
        out = []
        for address, kind, refs, text in self._index:
            if targets.intersection(refs):
                out.append(Xref(address, kind if kind in ("call", "jump") else "data",
                                self.label(address), text))
        return out
