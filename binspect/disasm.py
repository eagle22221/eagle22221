"""Disassembly (via Capstone) with the annotations a reverse engineer wants:
who is being called, which import a slot belongs to, which string a pointer
refers to.

Operands are analysed from Capstone's text output rather than its detail
structures: it is one code path for every architecture and roughly an order
of magnitude faster in Python, which matters when sweeping a large program
for cross-references.
"""
from __future__ import annotations

import bisect
import re
from typing import Dict, Iterator, List, Optional, Tuple

from .errors import LocationError, MissingDependencyError, UnsupportedError
from .model import Binary, Import

_X86_PREFIXES = {"bnd", "notrack", "rep", "repe", "repne", "lock", "data16", "addr32"}
_RIP = re.compile(r"\[rip(?: ([+-]) (0x[0-9a-f]+))?\]")
_ABS_MEM = re.compile(r"\[(?:[a-z0-9]+\*[1248] \+ )?(0x[0-9a-f]+)\]")
_TRAILING_IMM = re.compile(r"(?:^|, )(0x[0-9a-f]+)$")
_HASH_IMM = re.compile(r"#(0x[0-9a-f]+|\d+)")
_A64_MEM = re.compile(r"\[(x\d+), #(0x[0-9a-f]+|\d+)\]")
_A64_ADD = re.compile(r"^x\d+, (x\d+), #(0x[0-9a-f]+|\d+)$")

_A64_CALLS = {"bl", "blr"}
_A64_JUMPS = {"b", "br", "cbz", "cbnz", "tbz", "tbnz"}
_ARM_CALLS = {"bl", "blx"}

_STRING_PREVIEW = 60
_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t", '"': '\\"', "\\": "\\\\"}


class Instruction:
    __slots__ = ("address", "size", "raw", "mnemonic", "operands", "kind",
                 "target", "refs", "comment")

    def __init__(self, address: int, size: int, raw: bytes, mnemonic: str, operands: str):
        self.address = address
        self.size = size
        self.raw = raw
        self.mnemonic = mnemonic
        self.operands = operands
        self.kind = ""                      # "call", "jump", "ret" or ""
        self.target: Optional[int] = None   # destination of a direct call/jump
        self.refs: List[int] = []           # every address the instruction mentions
        self.comment = ""

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.operands}".strip()


def import_label(imp: Import, is_pe: bool) -> str:
    return f"{imp.library}!{imp.name}" if is_pe and imp.library else imp.name


class Disassembler:
    def __init__(self, binary: Binary):
        try:
            import capstone as cs
        except ImportError:
            raise MissingDependencyError(
                "disassembly needs the Capstone engine: pip install capstone") from None
        self.binary = binary
        self.arch = binary.arch
        big = cs.CS_MODE_BIG_ENDIAN if binary.endian == "big" else cs.CS_MODE_LITTLE_ENDIAN
        table = {
            "x86": (cs.CS_ARCH_X86, cs.CS_MODE_32),
            "x86_64": (cs.CS_ARCH_X86, cs.CS_MODE_64),
            "aarch64": (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
            "arm": (cs.CS_ARCH_ARM,
                    (cs.CS_MODE_THUMB if binary.format == "PE" else cs.CS_MODE_ARM) | big),
            "mips": (cs.CS_ARCH_MIPS,
                     (cs.CS_MODE_MIPS64 if binary.bits == 64 else cs.CS_MODE_MIPS32) | big),
            "ppc": (cs.CS_ARCH_PPC, cs.CS_MODE_32 | big),
            "ppc64": (cs.CS_ARCH_PPC, cs.CS_MODE_64 | big),
        }
        if self.arch not in table:
            raise UnsupportedError(f"no disassembler for CPU architecture {self.arch!r}")
        self._md = cs.Cs(*table[self.arch])
        self._md.skipdata = True            # undecodable bytes become ".byte" lines
        self._mask = (1 << binary.bits) - 1 if binary.bits else (1 << 64) - 1
        self._is_pe = binary.format == "PE"
        self._code = binary.executable_ranges()
        self._slots: Dict[int, Import] = {
            i.address: i for i in binary.imports if i.address is not None}
        self._thunks: Dict[int, Optional[Import]] = {}
        self._exact: Dict[int, str] = {}
        self._extents: List[Tuple[int, int, str]] = []      # (start, end, name), sorted
        self._starts: List[int] = []
        self._build_names()

    # -- names ----------------------------------------------------------------

    def _in_code(self, address: int) -> bool:
        return any(start <= address < start + size for start, size in self._code)

    def _build_names(self) -> None:
        b = self.binary
        ranked = sorted(b.symbols, key=lambda s: (
            s.type != "func", s.binding == "local", s.name))
        for s in ranked:
            self._exact.setdefault(s.address, s.name)
        for e in b.exports:
            if e.address is not None:
                self._exact.setdefault(e.address, e.name)
        if b.entry is not None:
            self._exact.setdefault(b.entry, "entry")
        sized = {s.address: s.size for s in b.symbols if s.size}
        self._set_extents(sized)

    def _set_extents(self, sizes: Dict[int, int]) -> None:
        """Give every named address an extent, so inner addresses can be shown
        as name+offset. Unsized code labels run to the next label."""
        code_starts = sorted(a for a in self._exact if self._in_code(a))
        extents = []
        for address, name in self._exact.items():
            size = sizes.get(address, 0)
            if not size and self._in_code(address):
                nxt = bisect.bisect_right(code_starts, address)
                limit = next(start + length for start, length in self._code
                             if start <= address < start + length)
                if nxt < len(code_starts):
                    limit = min(limit, code_starts[nxt])
                size = limit - address
            if size:
                extents.append((address, address + size, name))
        extents.sort()
        self._extents = extents
        self._starts = [e[0] for e in extents]

    def add_names(self, functions) -> None:
        """Adopt names and sizes found by function discovery."""
        sizes = {s.address: s.size for s in self.binary.symbols if s.size}
        for f in functions:
            self._exact.setdefault(f.address, f.name)
            if f.size:
                sizes.setdefault(f.address, f.size)
        self._set_extents(sizes)

    def name_at(self, address: int) -> Optional[str]:
        """Symbolic name for an address: "main", "main+0x1c", "puts@plt"."""
        name = self._exact.get(address)
        if name:
            return name
        thunk = self.thunk_at(address)
        if thunk is not None:
            return thunk
        i = bisect.bisect_right(self._starts, address) - 1
        if i >= 0:
            start, end, name = self._extents[i]
            if address < end:
                return f"{name}+{address - start:#x}"
        return None

    def thunk_import(self, address: int) -> Optional[Import]:
        """The import a jump stub (PLT entry / import thunk) at address leads to."""
        if address in self._thunks:
            return self._thunks[address]
        result = None
        if self._slots and self._in_code(address):
            code = self.binary.read(address, 24)
            for count, (addr, size, mnemonic, ops) in enumerate(
                    self._md.disasm_lite(code, address)):
                if mnemonic in ("endbr64", "endbr32") and count == 0:
                    continue
                insn = Instruction(addr, size, b"", mnemonic, ops)
                self._analyse(insn, {})
                if insn.kind == "jump" and insn.target is None and insn.refs:
                    result = self._slots.get(insn.refs[0])
                break
        self._thunks[address] = result
        return result

    def thunk_at(self, address: int) -> Optional[str]:
        imp = self.thunk_import(address)
        if imp is None:
            return None
        return f"{imp.name}@{'thunk' if self._is_pe else 'plt'}"

    # -- decoding -------------------------------------------------------------

    def disassemble(self, address: int, count: Optional[int] = None,
                    end: Optional[int] = None) -> List[Instruction]:
        """Decode from address: `count` instructions, or up to (not including)
        `end`. With neither, 32 instructions."""
        if self.binary.vaddr_to_offset(address) is None:
            raise LocationError(f"address {address:#x} is not inside the file")
        if end is None and count is None:
            count = 32
        length = end - address if end is not None else count * 16
        out = []
        for insn in self._decode(self.binary.read(address, max(length, 0)), address):
            if count is not None and len(out) >= count:
                break
            self._annotate(insn)
            out.append(insn)
        return out

    def sweep(self) -> Iterator[Instruction]:
        """Every instruction in every executable range, in address order.
        Linear sweep: fast and complete for compiler output; data embedded in
        code may decode as junk instructions."""
        for start, size in self._code:
            yield from self._decode(self.binary.read(start, size), start)

    def _decode(self, code: bytes, address: int) -> Iterator[Instruction]:
        state: dict = {}
        base = address
        for addr, size, mnemonic, ops in self._md.disasm_lite(code, address):
            insn = Instruction(addr, size, code[addr - base:addr - base + size], mnemonic, ops)
            if mnemonic != ".byte":
                self._analyse(insn, state)
            yield insn

    # -- operand analysis -----------------------------------------------------

    def _plausible(self, value: int) -> bool:
        """Is an immediate likely an address? Position-independent images are
        based at 0, where small constants would all look like addresses."""
        return self.binary.image_base > 0 and value >= self.binary.image_base \
            and self.binary.is_address(value)

    def _analyse(self, insn: Instruction, state: dict) -> None:
        if self.arch in ("x86", "x86_64"):
            self._analyse_x86(insn)
        elif self.arch == "aarch64":
            self._analyse_a64(insn, state)
        elif self.arch == "arm":
            self._analyse_arm(insn)

    def _analyse_x86(self, insn: Instruction) -> None:
        words = [w for w in insn.mnemonic.split() if w not in _X86_PREFIXES]
        op = words[-1] if words else ""
        ops = insn.operands
        if op == "call":
            insn.kind = "call"
        elif op.startswith("j") or op.startswith("loop"):
            insn.kind = "jump"
        elif op in ("ret", "retf", "retfq", "iret", "iretd", "iretq"):
            insn.kind = "ret"
            return
        if "0x" not in ops and "[rip]" not in ops:
            return
        if insn.kind in ("call", "jump") and re.fullmatch(r"0x[0-9a-f]+", ops):
            insn.target = int(ops, 16)
            insn.refs.append(insn.target)
            return
        m = _RIP.search(ops)
        if m:
            disp = int(m.group(2), 16) if m.group(2) else 0
            if m.group(1) == "-":
                disp = -disp
            insn.refs.append((insn.address + insn.size + disp) & self._mask)
        else:
            m = _ABS_MEM.search(ops)
            if m and self._plausible(int(m.group(1), 16)):
                insn.refs.append(int(m.group(1), 16))
        m = _TRAILING_IMM.search(ops)
        if m and insn.kind == "":
            value = int(m.group(1), 16)
            if value not in insn.refs and self._plausible(value):
                insn.refs.append(value)

    def _analyse_a64(self, insn: Instruction, state: dict) -> None:
        op, ops = insn.mnemonic, insn.operands
        pages = state.setdefault("pages", {})
        index = state["index"] = state.get("index", 0) + 1
        if op in _A64_CALLS:
            insn.kind = "call"
        elif op in _A64_JUMPS or op.startswith("b."):
            insn.kind = "jump"
        elif op in ("ret", "eret"):
            insn.kind = "ret"
            return
        if insn.kind:
            found = _HASH_IMM.findall(ops)
            if found and op not in ("blr", "br"):
                insn.target = int(found[-1], 0)
                insn.refs.append(insn.target)
            return
        if op == "adr":
            found = _HASH_IMM.findall(ops)
            if found:
                insn.refs.append(int(found[-1], 0))
        elif op == "adrp":
            found = _HASH_IMM.findall(ops)
            if found:
                pages[ops.split(",")[0]] = (int(found[-1], 0), index)
        elif pages:
            # adrp loads a page address; the low 12 bits come from a following
            # add or from the displacement of a load/store.
            m = _A64_ADD.match(ops) if op == "add" else _A64_MEM.search(ops)
            if m and m.group(1) in pages:
                page, seen = pages[m.group(1)]
                if index - seen <= 4:
                    insn.refs.append(page + int(m.group(2), 0))

    def _analyse_arm(self, insn: Instruction) -> None:
        op = insn.mnemonic.split(".")[0]
        if op in _ARM_CALLS:
            insn.kind = "call"
        elif op == "bx" and insn.operands == "lr":
            insn.kind = "ret"
        elif op.startswith("b") and op not in ("bic", "bics", "bkpt", "bfc", "bfi"):
            insn.kind = "jump"
        found = _HASH_IMM.findall(insn.operands)
        if insn.kind in ("call", "jump") and found:
            insn.target = int(found[-1], 0)
            insn.refs.append(insn.target)

    # -- annotation -----------------------------------------------------------

    def string_at(self, address: int) -> Optional[str]:
        """Quoted preview of a NUL-terminated ASCII or UTF-16 string at address
        (data only: code bytes that happen to be printable are ignored)."""
        if self._in_code(address):
            return None
        data = self.binary.read(address, 4 * _STRING_PREVIEW)
        for step in (1, 2):
            chars = []
            for i in range(0, len(data) - step + 1, step):
                c = data[i]
                if step == 2 and data[i + 1] != 0:
                    break
                if not (0x20 <= c <= 0x7E or c in (9, 10, 13)):
                    break
                chars.append(chr(c))
            end = len(chars) * step
            terminated = data[end:end + step] == bytes(step) or end >= len(data) - step
            if len(chars) >= 4 and terminated and any(ch > " " for ch in chars):
                text = "".join(chars)
                cut = text[:_STRING_PREVIEW]
                body = "".join(_ESCAPES.get(ch, ch) for ch in cut)
                return f'"{body}{"..." if len(text) > _STRING_PREVIEW else ""}"'
        return None

    def describe(self, address: int) -> str:
        """Annotation for a data address: import, name and/or string."""
        imp = self._slots.get(address)
        if imp is not None:
            return import_label(imp, self._is_pe)
        parts = []
        name = self._exact.get(address)
        if name:
            parts.append(name)
        text = self.string_at(address)
        if text:
            parts.append(text)
        if not parts:
            name = self.name_at(address)
            if name:
                parts.append(name)
        return " ".join(parts)

    def _annotate(self, insn: Instruction) -> None:
        if insn.target is not None:
            insn.comment = self.name_at(insn.target) or ""
        elif insn.refs:
            insn.comment = self.describe(insn.refs[0])
