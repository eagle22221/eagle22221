"""ELF parser (Linux executables, shared libraries, object files).

Pure Python. Works from the program headers first, because the section
header table is optional at run time and is often removed from stripped or
tampered binaries; sections only add detail (names, static symbols).
"""
from __future__ import annotations

import re
import struct
from typing import Dict, List, Optional, Tuple

from .errors import ParseError
from .model import Binary, Export, Import, Section, Segment, Symbol
from .reader import Reader

_MACHINES = {
    2: "sparc", 3: "x86", 8: "mips", 20: "ppc", 21: "ppc64", 22: "s390x",
    40: "arm", 43: "sparc64", 62: "x86_64", 183: "aarch64", 243: "riscv",
    258: "loongarch",
}

_SEGMENT_TYPES = {
    0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB",
    6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO", 0x6474E553: "GNU_PROPERTY",
}

_SECTION_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH",
    6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL", 10: "SHLIB", 11: "DYNSYM",
    14: "INIT_ARRAY", 15: "FINI_ARRAY", 16: "PREINIT_ARRAY", 17: "GROUP",
    18: "SYMTAB_SHNDX", 0x6FFFFFF6: "GNU_HASH", 0x6FFFFFFD: "VERDEF",
    0x6FFFFFFE: "VERNEED", 0x6FFFFFFF: "VERSYM",
}

_SYMBOL_TYPES = {
    0: "notype", 1: "object", 2: "func", 3: "section", 4: "file",
    5: "common", 6: "tls", 10: "ifunc",
}
_SYMBOL_BINDINGS = {0: "local", 1: "global", 2: "weak", 10: "unique"}

ET_REL, ET_EXEC, ET_DYN, ET_CORE = 1, 2, 3, 4
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
PT_GNU_STACK, PT_GNU_RELRO = 0x6474E551, 0x6474E552
SHT_SYMTAB, SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_DYNSYM = 2, 6, 7, 8, 11
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2

DT_NEEDED, DT_PLTRELSZ, DT_HASH, DT_STRTAB, DT_SYMTAB = 1, 2, 4, 5, 6
DT_RELA, DT_RELASZ, DT_STRSZ, DT_SYMENT, DT_SONAME, DT_RPATH = 7, 8, 10, 11, 14, 15
DT_REL, DT_RELSZ, DT_PLTREL, DT_JMPREL, DT_BIND_NOW = 17, 18, 20, 23, 24
DT_RUNPATH, DT_FLAGS, DT_FLAGS_1 = 29, 30, 0x6FFFFFFB
DT_VERSYM, DT_VERNEED, DT_VERNEEDNUM = 0x6FFFFFF0, 0x6FFFFFFE, 0x6FFFFFFF
DF_BIND_NOW, DF_1_NOW, DF_1_PIE = 0x8, 0x1, 0x08000000

# Relocation types that fill an import's GOT slot (GLOB_DAT, JUMP_SLOT).
_SLOT_RELOCS = {
    "x86": {6, 7}, "x86_64": {6, 7}, "arm": {21, 22},
    "aarch64": {1025, 1026}, "riscv": {5}, "ppc64": {21}, "ppc": {20, 21},
}

# ARM/AArch64 "mapping symbols" mark code/data boundaries; they are not names.
_MAPPING_SYMBOL = re.compile(r"^\$[adtx](\..*)?$")

_MAX_CHAIN = 4096       # upper bound for linked structures in hostile files
_SOFT_ERRORS = (ParseError, struct.error, IndexError, ValueError, OverflowError)


def parse(data: bytes, path: Optional[str] = None) -> Binary:
    return _ElfParser(data, path).parse()


class _ElfParser:
    def __init__(self, data: bytes, path: Optional[str]):
        self.b = Binary(data, path)
        self.b.format = "ELF"
        self.r = Reader(data)
        self.is64 = True
        self.phdrs: List[dict] = []
        self.shdrs: List[dict] = []
        self.dyn: List[Tuple[int, int]] = []
        self.has_symtab = False
        self._seen_symbols: set = set()

    # -- driver ---------------------------------------------------------------

    def parse(self) -> Binary:
        self._header()                      # the only part allowed to fail hard
        for label, step in (
            ("program headers", self._segments),
            ("section headers", self._sections),
            ("dynamic section", self._dynamic),
            ("symbol table", self._static_symbols),
            ("notes", self._metadata),
        ):
            try:
                step()
            except _SOFT_ERRORS as exc:
                self.b.warnings.append(f"{label}: {exc}")
        self._classify()
        self._security()
        self._overlay()
        return self.b

    def _overlay(self) -> None:
        end = self.e_phoff + self.e_phnum * self.e_phentsize if self.phdrs else 0
        self.b.regions.append(("headers", 0, max(end, 64 if self.is64 else 52), "headers"))
        if self.shdrs:
            table = self.e_shnum * self.e_shentsize
            self.b.regions.append(("section headers", self.e_shoff, table, "meta"))
            end = max(end, self.e_shoff + table)
        for p in self.phdrs:
            end = max(end, p["offset"] + p["filesz"])
        for sh in self.shdrs:
            if sh["type"] != SHT_NOBITS:
                end = max(end, sh["offset"] + sh["size"])
        self.b.note_overlay(end)

    # -- header ---------------------------------------------------------------

    def _header(self) -> None:
        d = self.b.data
        if len(d) < 16:
            raise ParseError("truncated ELF header")
        ei_class, ei_data = d[4], d[5]
        if ei_class not in (1, 2):
            raise ParseError(f"invalid ELF class {ei_class}")
        if ei_data not in (1, 2):
            raise ParseError(f"invalid ELF data encoding {ei_data}")
        self.is64 = ei_class == 2
        self.r = Reader(d, little_endian=ei_data == 1)
        self.b.bits = 64 if self.is64 else 32
        self.b.endian = "little" if ei_data == 1 else "big"
        fmt = "HHIQQQIHHHHHH" if self.is64 else "HHIIIIIHHHHHH"
        try:
            (self.e_type, machine, _version, entry, self.e_phoff, self.e_shoff,
             _flags, _ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize,
             self.e_shnum, self.e_shstrndx) = self.r.unpack(fmt, 16)
        except ParseError:
            raise ParseError("truncated ELF header") from None
        self.b.arch = _MACHINES.get(machine, f"unknown({machine})")
        self.b.entry = entry or None

    # -- program headers ------------------------------------------------------

    def _segments(self) -> None:
        if not self.e_phoff or not self.e_phnum:
            return
        min_size = 56 if self.is64 else 32
        if self.e_phentsize < min_size:
            raise ParseError(f"program header entry size {self.e_phentsize} is too small")
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type, flags, offset, vaddr, _paddr, filesz, memsz, align = \
                    self.r.unpack("IIQQQQQQ", off)
            else:
                p_type, offset, vaddr, _paddr, filesz, memsz, flags, align = \
                    self.r.unpack("IIIIIIII", off)
            self.phdrs.append(dict(type=p_type, flags=flags, offset=offset,
                                   vaddr=vaddr, filesz=filesz, memsz=memsz, align=align))
            perms = ("r" if flags & 4 else "-") + ("w" if flags & 2 else "-") + \
                    ("x" if flags & 1 else "-")
            self.b.segments.append(Segment(
                type=_SEGMENT_TYPES.get(p_type, f"{p_type:#x}"),
                vaddr=vaddr, vsize=memsz, offset=offset, size=filesz, perms=perms))
            if p_type == PT_LOAD:
                self.b.add_map(vaddr, offset, filesz)
        loads = [p["vaddr"] for p in self.phdrs if p["type"] == PT_LOAD]
        self.b.image_base = min(loads) if loads else 0

    # -- section headers ------------------------------------------------------

    def _sections(self) -> None:
        if not self.e_shoff or not self.e_shnum:
            return
        min_size = 64 if self.is64 else 40
        if self.e_shentsize < min_size:
            raise ParseError(f"section header entry size {self.e_shentsize} is too small")
        if self.e_shoff + self.e_shnum * self.e_shentsize > self.r.size:
            raise ParseError("section header table extends past the end of the file; "
                             "sections ignored")
        fmt = "IIQQQQIIQQ" if self.is64 else "IIIIIIIIII"
        raw = []
        for i in range(self.e_shnum):
            (name, sh_type, flags, addr, offset, size, link, info, _align, entsize) = \
                self.r.unpack(fmt, self.e_shoff + i * self.e_shentsize)
            raw.append(dict(name_off=name, type=sh_type, flags=flags, addr=addr,
                            offset=offset, size=size, link=link, info=info,
                            entsize=entsize, name=""))
        if self.e_shstrndx < len(raw):
            strtab = raw[self.e_shstrndx]
            for sh in raw:
                try:
                    if sh["name_off"] < strtab["size"]:
                        sh["name"] = self.r.cstring(strtab["offset"] + sh["name_off"], 256)
                except ParseError:
                    pass
        self.shdrs = raw
        for sh in raw[1:]:
            alloc = bool(sh["flags"] & SHF_ALLOC)
            perms = "---"
            if alloc:
                perms = "r" + ("w" if sh["flags"] & SHF_WRITE else "-") + \
                        ("x" if sh["flags"] & SHF_EXEC else "-")
            in_file = 0 if sh["type"] == SHT_NOBITS else sh["size"]
            in_file = max(0, min(in_file, self.r.size - sh["offset"]))
            self.b.sections.append(Section(
                name=sh["name"], vaddr=sh["addr"] if alloc else 0,
                vsize=sh["size"] if alloc else 0, offset=sh["offset"], size=in_file,
                perms=perms, type=_SECTION_TYPES.get(sh["type"], f"{sh['type']:#x}")))
        if not self.phdrs:
            # Object files have no program headers; map loadable sections
            # that were given an address so reads by address still work.
            for sh in raw[1:]:
                if sh["flags"] & SHF_ALLOC and sh["type"] != SHT_NOBITS and sh["addr"]:
                    self.b.add_map(sh["addr"], sh["offset"], sh["size"])

    def _section_name(self, index: int) -> Optional[str]:
        if index == SHN_ABS:
            return "ABS"
        if index == SHN_COMMON:
            return "COMMON"
        if 0 < index < len(self.shdrs):
            return self.shdrs[index]["name"] or None
        return None

    def _section_of_type(self, sh_type: int) -> Optional[dict]:
        return next((s for s in self.shdrs if s["type"] == sh_type), None)

    # -- dynamic linking information ------------------------------------------

    def _dynamic(self) -> None:
        seg = next((p for p in self.phdrs if p["type"] == PT_DYNAMIC), None)
        if seg is not None:
            start, size = seg["offset"], seg["filesz"]
        else:
            sec = self._section_of_type(SHT_DYNAMIC)
            if sec is None:
                return
            start, size = sec["offset"], sec["size"]
        entsize, fmt = (16, "qQ") if self.is64 else (8, "iI")
        try:
            for off in range(start, start + size - entsize + 1, entsize):
                tag, val = self.r.unpack(fmt, off)
                if tag == 0:
                    break
                self.dyn.append((tag, val))
        except ParseError as exc:
            self.b.warnings.append(f"dynamic section truncated: {exc}")
        info: Dict[int, int] = {}
        for tag, val in self.dyn:
            info.setdefault(tag, val)
        self.dyn_info = info

        dynsym_sec = self._section_of_type(SHT_DYNSYM)
        strtab_off = self._file_offset(info.get(DT_STRTAB))
        if strtab_off is None and dynsym_sec and dynsym_sec["link"] < len(self.shdrs):
            strtab_off = self.shdrs[dynsym_sec["link"]]["offset"]

        def dynstr(index: int) -> str:
            if strtab_off is None:
                raise ParseError("dynamic string table not found")
            return self.r.cstring(strtab_off + index)

        for tag, val in self.dyn:
            try:
                if tag == DT_NEEDED:
                    self.b.libraries.append(dynstr(val))
                elif tag == DT_SONAME:
                    self.b.metadata["soname"] = dynstr(val)
                elif tag == DT_RPATH:
                    self.b.metadata["rpath"] = dynstr(val)
                elif tag == DT_RUNPATH:
                    self.b.metadata["runpath"] = dynstr(val)
            except ParseError as exc:
                self.b.warnings.append(f"dynamic string: {exc}")

        symbols = self._dynamic_symbols(info, dynsym_sec, strtab_off, dynstr)
        versions = self._symbol_versions(info, len(symbols), dynstr)
        slots = self._import_slots(info)

        for index, sym in enumerate(symbols):
            if index == 0 or not sym["name"]:
                continue
            if sym["shndx"] == SHN_UNDEF:
                library, version = versions.get(index, (None, None))
                self.b.imports.append(Import(
                    name=sym["name"], library=library, version=version,
                    address=slots.get(index)))
            else:
                exported = (sym["bind"] in (1, 2, 10) and sym["vis"] in (0, 3)
                            and sym["type"] in (0, 1, 2, 6, 10))
                if exported:
                    self.b.exports.append(Export(name=sym["name"], address=sym["value"]))
                self._add_symbol(sym)

    def _file_offset(self, vaddr: Optional[int]) -> Optional[int]:
        if vaddr is None:
            return None
        return self.b.vaddr_to_offset(vaddr)

    def _read_symbol(self, off: int, strtab) -> dict:
        if self.is64:
            name, info, other, shndx, value, size = self.r.unpack("IBBHQQ", off)
        else:
            name, value, size, info, other, shndx = self.r.unpack("IIIBBH", off)
        try:
            text = strtab(name) if name else ""
        except ParseError:
            text = ""
        return dict(name=text, value=value, size=size, type=info & 0xF,
                    bind=info >> 4, vis=other & 3, shndx=shndx)

    def _dynamic_symbols(self, info, dynsym_sec, strtab_off, dynstr) -> List[dict]:
        entsize = info.get(DT_SYMENT) or (24 if self.is64 else 16)
        if entsize < (24 if self.is64 else 16):
            raise ParseError(f"dynamic symbol entry size {entsize} is too small")
        table = self._file_offset(info.get(DT_SYMTAB))
        count = 0
        if dynsym_sec is not None:
            if table is None:
                table = dynsym_sec["offset"]
            count = dynsym_sec["size"] // entsize
        elif table is not None:
            hash_off = self._file_offset(info.get(DT_HASH))
            if hash_off is not None:
                count = self.r.u32(hash_off + 4)        # nchain == symbol count
            elif strtab_off is not None and strtab_off > table:
                # No count is stored without section headers or DT_HASH; the
                # string table conventionally follows the symbol table.
                count = (strtab_off - table) // entsize
        if table is None:
            return []
        count = min(count, max(0, (self.r.size - table) // entsize))
        return [self._read_symbol(table + i * entsize, dynstr) for i in range(count)]

    def _symbol_versions(self, info, nsyms, dynstr) -> Dict[int, Tuple[str, str]]:
        """Map dynamic symbol index -> (library, version) via .gnu.version(_r)."""
        versym = self._file_offset(info.get(DT_VERSYM))
        verneed = self._file_offset(info.get(DT_VERNEED))
        if versym is None or verneed is None:
            return {}
        by_index: Dict[int, Tuple[str, str]] = {}
        try:
            off = verneed
            for _ in range(min(info.get(DT_VERNEEDNUM, 0), _MAX_CHAIN)):
                _ver, cnt, file_off, aux, nxt = self.r.unpack("HHIII", off)
                library = dynstr(file_off)
                aux_off = off + aux
                for _ in range(min(cnt, _MAX_CHAIN)):
                    _hash, _flags, other, name_off, aux_next = self.r.unpack("IHHII", aux_off)
                    by_index[other & 0x7FFF] = (library, dynstr(name_off))
                    if not aux_next:
                        break
                    aux_off += aux_next
                if not nxt:
                    break
                off += nxt
        except ParseError as exc:
            self.b.warnings.append(f"symbol versions: {exc}")
        result = {}
        for i in range(nsyms):
            try:
                idx = self.r.u16(versym + 2 * i) & 0x7FFF
            except ParseError:
                break
            if idx in by_index:
                result[i] = by_index[idx]
        return result

    def _import_slots(self, info) -> Dict[int, int]:
        """Map dynamic symbol index -> address of the GOT slot the loader fills."""
        wanted = _SLOT_RELOCS.get(self.b.arch)
        slots: Dict[int, int] = {}
        tables = []
        if DT_JMPREL in info:      # PLT relocations first: they are the call slots
            tables.append((info[DT_JMPREL], info.get(DT_PLTRELSZ, 0),
                           info.get(DT_PLTREL) == DT_RELA))
        if DT_RELA in info:
            tables.append((info[DT_RELA], info.get(DT_RELASZ, 0), True))
        if DT_REL in info:
            tables.append((info[DT_REL], info.get(DT_RELSZ, 0), False))
        for vaddr, size, has_addend in tables:
            off = self._file_offset(vaddr)
            if off is None:
                continue
            if self.is64:
                entsize, fmt = (24, "QQq") if has_addend else (16, "QQ")
            else:
                entsize, fmt = (12, "IIi") if has_addend else (8, "II")
            try:
                for pos in range(off, off + size - entsize + 1, entsize):
                    fields = self.r.unpack(fmt, pos)
                    r_offset, r_info = fields[0], fields[1]
                    sym, r_type = (r_info >> 32, r_info & 0xFFFFFFFF) if self.is64 \
                        else (r_info >> 8, r_info & 0xFF)
                    if sym and (wanted is None or r_type in wanted):
                        slots.setdefault(sym, r_offset)
            except ParseError as exc:
                self.b.warnings.append(f"relocations truncated: {exc}")
        return slots

    # -- static symbols -------------------------------------------------------

    def _add_symbol(self, sym: dict) -> None:
        """Record a defined, named symbol once (.dynsym and .symtab overlap)."""
        if not sym["name"] or sym["shndx"] == SHN_UNDEF:
            return
        if sym["type"] in (3, 4) or _MAPPING_SYMBOL.match(sym["name"]):
            return
        key = (sym["name"], sym["value"])
        if key in self._seen_symbols:
            return
        self._seen_symbols.add(key)
        self.b.symbols.append(Symbol(
            name=sym["name"], address=sym["value"], size=sym["size"],
            type=_SYMBOL_TYPES.get(sym["type"], str(sym["type"])),
            binding=_SYMBOL_BINDINGS.get(sym["bind"], str(sym["bind"])),
            section=self._section_name(sym["shndx"])))

    def _static_symbols(self) -> None:
        symtab = self._section_of_type(SHT_SYMTAB)
        if symtab is None:
            return
        self.has_symtab = True
        if symtab["link"] >= len(self.shdrs):
            raise ParseError("symbol table has no string table")
        strtab = self.shdrs[symtab["link"]]

        def name_at(index: int) -> str:
            if index >= strtab["size"]:
                raise ParseError("symbol name outside string table")
            return self.r.cstring(strtab["offset"] + index)

        entsize = symtab["entsize"] or (24 if self.is64 else 16)
        if entsize < (24 if self.is64 else 16):
            raise ParseError(f"symbol entry size {entsize} is too small")
        files: List[str] = []
        for i in range(1, symtab["size"] // entsize):
            sym = self._read_symbol(symtab["offset"] + i * entsize, name_at)
            if sym["type"] == 4 and sym["name"] and sym["name"] not in files:
                files.append(sym["name"])
            self._add_symbol(sym)
        if files:
            self.b.metadata["source_files"] = files

    # -- metadata -------------------------------------------------------------

    def _metadata(self) -> None:
        interp = next((p for p in self.phdrs if p["type"] == PT_INTERP), None)
        if interp is not None:
            try:
                self.b.metadata["interpreter"] = self.r.cstring(interp["offset"],
                                                                 interp["filesz"] or 1)
            except ParseError as exc:
                self.b.warnings.append(f"interpreter: {exc}")
        notes = [(p["offset"], p["filesz"], p["align"]) for p in self.phdrs
                 if p["type"] == PT_NOTE]
        if not notes:
            notes = [(s["offset"], s["size"], 4) for s in self.shdrs if s["type"] == SHT_NOTE]
        for offset, size, align in notes:
            try:
                self._notes(offset, size, 8 if align == 8 else 4)
            except ParseError as exc:
                self.b.warnings.append(f"notes: {exc}")
        comment = next((s for s in self.shdrs if s["name"] == ".comment"), None)
        if comment is not None and comment["type"] != SHT_NOBITS:
            raw = self.r.bytes(comment["offset"], min(comment["size"], 65536))
            found: List[str] = []
            for part in raw.split(b"\0"):
                text = part.decode("utf-8", errors="replace").strip()
                if text and text not in found:
                    found.append(text)
            if found:
                self.b.metadata["compiler"] = found

    def _notes(self, offset: int, size: int, align: int) -> None:
        pos, end = offset, offset + size

        def pad(n: int) -> int:
            return (n + align - 1) & ~(align - 1)

        while pos + 12 <= end:
            namesz, descsz, n_type = self.r.unpack("III", pos)
            name = self.r.bytes(pos + 12, namesz).rstrip(b"\0")
            desc_off = pos + 12 + pad(namesz)
            desc = self.r.bytes(desc_off, descsz)
            if name == b"GNU" and n_type == 3:
                self.b.metadata["build_id"] = desc.hex()
            pos = desc_off + pad(descsz)

    # -- classification and security ------------------------------------------

    def _classify(self) -> None:
        flags1 = getattr(self, "dyn_info", {}).get(DT_FLAGS_1, 0)
        has_interp = any(p["type"] == PT_INTERP for p in self.phdrs)
        if self.e_type == ET_EXEC:
            self.b.kind = "executable"
        elif self.e_type == ET_DYN:
            self.b.kind = "executable" if (has_interp or flags1 & DF_1_PIE) \
                else "shared library"
        elif self.e_type == ET_REL:
            self.b.kind = "relocatable"
        elif self.e_type == ET_CORE:
            self.b.kind = "core"

    def _security(self) -> None:
        info = getattr(self, "dyn_info", {})
        stack = next((p for p in self.phdrs if p["type"] == PT_GNU_STACK), None)
        relro = any(p["type"] == PT_GNU_RELRO for p in self.phdrs)
        bind_now = (DT_BIND_NOW in info or info.get(DT_FLAGS, 0) & DF_BIND_NOW
                    or info.get(DT_FLAGS_1, 0) & DF_1_NOW)
        names = {i.name for i in self.b.imports} | {s.name for s in self.b.symbols}
        pie: Optional[bool]
        if self.e_type == ET_DYN:
            pie = True if self.b.kind == "executable" else None
        else:
            pie = False
        self.b.security = {
            "nx": stack is not None and not stack["flags"] & 1,
            "pie": pie,
            "relro": ("full" if bind_now else "partial") if relro else "none",
            "canary": bool(names & {"__stack_chk_fail", "__stack_chk_guard",
                                    "__stack_chk_fail_local"}),
            "fortify": any(n.endswith("_chk") for n in names),
            "stripped": not self.has_symtab,
            "rpath": self.b.metadata.get("rpath"),
            "runpath": self.b.metadata.get("runpath"),
        }
