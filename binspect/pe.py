"""PE parser (Windows executables, DLLs and drivers; PE32 and PE32+).

Pure Python. Only the DOS/COFF/optional headers are mandatory; every data
directory (imports, exports, debug, ...) is parsed independently so one
corrupt table costs a warning, not the whole analysis.
"""
from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .errors import ParseError, UnknownFormatError
from .model import Binary, Export, Import, Section, Symbol
from .reader import Reader

_MACHINES = {
    0x14C: "x86", 0x8664: "x86_64", 0x1C0: "arm", 0x1C2: "arm", 0x1C4: "arm",
    0xAA64: "aarch64", 0x200: "ia64", 0x5032: "riscv", 0x5064: "riscv",
}

_SUBSYSTEMS = {
    1: "native", 2: "gui", 3: "console", 5: "os2", 7: "posix", 9: "windows-ce",
    10: "efi-application", 11: "efi-boot-driver", 12: "efi-runtime-driver",
    13: "efi-rom", 14: "xbox", 16: "boot-application",
}

DIR_EXPORT, DIR_IMPORT, DIR_EXCEPTION, DIR_SECURITY = 0, 1, 3, 4
DIR_DEBUG, DIR_DELAY_IMPORT, DIR_CLR = 6, 13, 14

FILE_RELOCS_STRIPPED, FILE_DLL = 0x0001, 0x2000
DLLCHAR_HIGH_ENTROPY_VA, DLLCHAR_DYNAMIC_BASE, DLLCHAR_FORCE_INTEGRITY = 0x20, 0x40, 0x80
DLLCHAR_NX_COMPAT, DLLCHAR_NO_SEH, DLLCHAR_GUARD_CF = 0x100, 0x400, 0x4000
SCN_CODE, SCN_DATA, SCN_BSS = 0x20, 0x40, 0x80
SCN_EXECUTE, SCN_READ, SCN_WRITE = 0x20000000, 0x40000000, 0x80000000

_MAX_ENTRIES = 65536     # upper bound for any table in a hostile file
_SOFT_ERRORS = (ParseError, struct.error, IndexError, ValueError, OverflowError)


def parse(data: bytes, path: Optional[str] = None) -> Binary:
    return _PeParser(data, path).parse()


class _PeParser:
    def __init__(self, data: bytes, path: Optional[str]):
        self.b = Binary(data, path)
        self.b.format = "PE"
        self.r = Reader(data)
        self.dirs: List[Tuple[int, int]] = []
        self.raw_sections: List[dict] = []

    # -- driver ---------------------------------------------------------------

    def parse(self) -> Binary:
        self._headers()                     # the only part allowed to fail hard
        for label, step in (
            ("section table", self._sections),
            ("import directory", self._imports),
            ("delay-import directory", self._delay_imports),
            ("export directory", self._exports),
            ("COFF symbol table", self._coff_symbols),
            ("exception directory", self._exception_table),
            ("debug directory", self._debug),
        ):
            try:
                step()
            except _SOFT_ERRORS as exc:
                self.b.warnings.append(f"{label}: {exc}")
        self._security()
        self._imphash()
        self._overlay()
        return self.b

    def _overlay(self) -> None:
        end = self.headers_size
        regions = self.b.regions
        regions.append(("headers", 0, min(self.headers_size, self.r.size), "headers"))
        for s in self.b.sections:
            end = max(end, s.offset + s.size)
        if self.symtab_off and self.nsymbols:
            strings = self.symtab_off + self.nsymbols * 18
            try:
                table_end = strings + max(self.r.u32(strings), 4)
            except ParseError:
                table_end = strings
            regions.append(("symbol table", self.symtab_off,
                            table_end - self.symtab_off, "meta"))
            end = max(end, table_end)
        cert_off, cert_size = self._dir(DIR_SECURITY)      # a file offset, not an RVA
        if cert_off and cert_size:
            regions.append(("certificates", cert_off, cert_size, "meta"))
            end = max(end, cert_off + cert_size)
        # Linkers pad the file to the file alignment; zero padding is not data.
        align = self.file_align if self.file_align >= 0x200 else 1
        padded = min((end + align - 1) // align * align, self.r.size)
        if not any(self.b.data[end:padded]):
            end = padded
        self.b.note_overlay(end)

    def _imphash(self) -> None:
        """pefile-compatible import hash, used to cluster related malware."""
        parts = []
        for imp in self.b.imports:
            if imp.delayed:
                continue
            library = (imp.library or "").lower()
            stem, _, ext = library.rpartition(".")
            if stem and ext in ("dll", "ocx", "sys"):
                library = stem
            if imp.ordinal is not None:
                if library in ("ws2_32", "wsock32", "oleaut32"):
                    return      # pefile names these ordinals from a table we lack
                parts.append(f"{library}.ord{imp.ordinal}")
            else:
                parts.append(f"{library}.{imp.name.lower()}")
        if parts:
            self.b.metadata["imphash"] = hashlib.md5(",".join(parts).encode()).hexdigest()

    # -- headers --------------------------------------------------------------

    def _headers(self) -> None:
        r = self.r
        not_pe = UnknownFormatError("MZ file without a PE header (DOS executable?)")
        if r.size < 0x40:
            raise not_pe
        pe = r.u32(0x3C)
        if pe + 4 > r.size or r.bytes(pe, 4) != b"PE\0\0":
            raise not_pe
        try:
            (machine, self.nsections, timestamp, self.symtab_off, self.nsymbols,
             opt_size, self.characteristics) = r.unpack("HHIIIHH", pe + 4)
            opt = pe + 24
            magic = r.u16(opt)
            if magic not in (0x10B, 0x20B):
                raise ParseError(f"unsupported optional header magic {magic:#x}")
            self.is64 = magic == 0x20B
            linker_major, linker_minor = r.unpack("BB", opt + 2)
            entry_rva = r.u32(opt + 16)
            if self.is64:
                image_base = r.u64(opt + 24)
            else:
                image_base = r.u32(opt + 28)
            self.section_align, self.file_align = r.unpack("II", opt + 32)
            _image_size, self.headers_size, checksum, subsystem, self.dll_chars = \
                r.unpack("IIIHH", opt + 56)
            ndirs_off = opt + (108 if self.is64 else 92)
            ndirs = min(r.u32(ndirs_off), 16)
        except ParseError as exc:
            if "magic" in str(exc):
                raise
            raise ParseError("truncated PE header") from None
        for i in range(ndirs):
            off = ndirs_off + 4 + i * 8
            if off + 8 > opt + opt_size or off + 8 > r.size:
                break
            self.dirs.append(r.unpack("II", off))
        self.section_table = opt + opt_size

        b = self.b
        b.bits = 64 if self.is64 else 32
        b.arch = _MACHINES.get(machine, f"unknown({machine:#x})")
        b.image_base = image_base
        b.entry = image_base + entry_rva if entry_rva else None
        if self.characteristics & FILE_DLL:
            b.kind = "dll"
        elif subsystem == 1:
            b.kind = "driver"
        else:
            b.kind = "executable"
        b.metadata["timestamp"] = datetime.fromtimestamp(
            timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        b.metadata["subsystem"] = _SUBSYSTEMS.get(subsystem, f"unknown({subsystem})")
        b.metadata["linker_version"] = f"{linker_major}.{linker_minor}"
        b.metadata["checksum"] = checksum
        b.add_map(image_base, 0, self.headers_size)

    def _dir(self, index: int) -> Tuple[int, int]:
        return self.dirs[index] if index < len(self.dirs) else (0, 0)

    def _offset(self, rva: int, what: str) -> int:
        """File offset of an RVA, or ParseError naming the structure involved."""
        off = self.b.vaddr_to_offset(self.b.image_base + rva)
        if off is None:
            raise ParseError(f"{what} at RVA {rva:#x} is not inside the image")
        return off

    # -- sections -------------------------------------------------------------

    def _sections(self) -> None:
        b = self.b
        align = self.section_align or 0x1000
        for i in range(self.nsections):
            off = self.section_table + i * 40
            raw_name = self.r.bytes(off, 8)
            vsize, rva, raw_size, raw_ptr = self.r.unpack("IIII", off + 8)
            flags = self.r.u32(off + 36)
            name = raw_name.split(b"\0", 1)[0].decode("utf-8", errors="replace")
            if self.file_align >= 0x200:
                raw_ptr &= ~0x1FF           # the loader ignores the low 9 bits
            in_file = max(0, min(raw_size, self.r.size - raw_ptr))
            mapped = in_file
            if vsize:
                mapped = min(in_file, (vsize + align - 1) & ~(align - 1))
            perms = ("r" if flags & SCN_READ else "-") + \
                    ("w" if flags & SCN_WRITE else "-") + \
                    ("x" if flags & SCN_EXECUTE else "-")
            kind = "code" if flags & SCN_CODE else "data" if flags & SCN_DATA \
                else "bss" if flags & SCN_BSS else ""
            self.raw_sections.append(dict(name=name, rva=rva))
            b.sections.append(Section(
                name=name, vaddr=b.image_base + rva, vsize=vsize or raw_size,
                offset=raw_ptr, size=in_file, perms=perms, type=kind))
            b.add_map(b.image_base + rva, raw_ptr, mapped)

    # -- imports --------------------------------------------------------------

    def _thunks(self, lookup_rva: int, iat_rva: int, library: str, delayed: bool) -> None:
        size, fmt, ordinal_flag = (8, "Q", 1 << 63) if self.is64 else (4, "I", 1 << 31)
        off = self._offset(lookup_rva, f"import names of {library}")
        for i in range(_MAX_ENTRIES):
            (value,) = self.r.unpack(fmt, off + i * size)
            if value == 0:
                break
            slot = self.b.image_base + iat_rva + i * size
            if value & ordinal_flag:
                ordinal = value & 0xFFFF
                imp = Import(name=f"#{ordinal}", ordinal=ordinal)
            else:
                name_off = self._offset(value & 0x7FFFFFFF, f"import name in {library}")
                imp = Import(name=self.r.cstring(name_off + 2, 512))
            imp.library, imp.address, imp.delayed = library, slot, delayed
            self.b.imports.append(imp)

    def _add_library(self, name: str) -> None:
        if name not in self.b.libraries:
            self.b.libraries.append(name)

    def _imports(self) -> None:
        rva, _size = self._dir(DIR_IMPORT)
        if not rva:
            return
        off = self._offset(rva, "import directory")
        for i in range(_MAX_ENTRIES):
            lookup, _stamp, _chain, name_rva, iat = self.r.unpack("IIIII", off + i * 20)
            if not name_rva and not iat:
                break
            library = self.r.cstring(self._offset(name_rva, "import library name"), 512)
            self._add_library(library)
            try:
                self._thunks(lookup or iat, iat, library, delayed=False)
            except ParseError as exc:
                self.b.warnings.append(f"imports of {library}: {exc}")

    def _delay_imports(self) -> None:
        rva, _size = self._dir(DIR_DELAY_IMPORT)
        if not rva:
            return
        off = self._offset(rva, "delay-import directory")
        for i in range(_MAX_ENTRIES):
            attrs, name, _hmod, iat, names, _bound, _unload, _stamp = \
                self.r.unpack("IIIIIIII", off + i * 32)
            if not name:
                break
            if not attrs & 1:               # old format stores absolute addresses
                base = self.b.image_base
                name, iat, names = name - base, iat - base, names - base
            library = self.r.cstring(self._offset(name, "delay-import library name"), 512)
            self._add_library(library)
            try:
                self._thunks(names, iat, library, delayed=True)
            except ParseError as exc:
                self.b.warnings.append(f"delay imports of {library}: {exc}")

    # -- exports --------------------------------------------------------------

    def _exports(self) -> None:
        rva, size = self._dir(DIR_EXPORT)
        if not rva:
            return
        off = self._offset(rva, "export directory")
        (_flags, _stamp, _major, _minor, name_rva, base, nfuncs, nnames,
         funcs_rva, names_rva, ords_rva) = self.r.unpack("IIHHIIIIIII", off)
        if name_rva:
            try:
                self.b.metadata["dll_name"] = self.r.cstring(
                    self._offset(name_rva, "export DLL name"), 512)
            except ParseError:
                pass
        nfuncs, nnames = min(nfuncs, _MAX_ENTRIES), min(nnames, _MAX_ENTRIES)
        names = {}
        if nnames:
            names_off = self._offset(names_rva, "export name table")
            ords_off = self._offset(ords_rva, "export ordinal table")
            for i in range(nnames):
                index = self.r.u16(ords_off + 2 * i)
                try:
                    names[index] = self.r.cstring(
                        self._offset(self.r.u32(names_off + 4 * i), "export name"), 512)
                except ParseError:
                    continue
        if not nfuncs:
            return
        funcs_off = self._offset(funcs_rva, "export address table")
        for i in range(nfuncs):
            func_rva = self.r.u32(funcs_off + 4 * i)
            if not func_rva:
                continue
            ordinal = base + i
            name = names.get(i, f"#{ordinal}")
            if rva <= func_rva < rva + size:
                # An address inside the export directory is a forwarder string.
                target = self.r.cstring(self._offset(func_rva, "export forwarder"), 512)
                self.b.exports.append(Export(name, None, ordinal, forwarder=target))
            else:
                self.b.exports.append(Export(name, self.b.image_base + func_rva, ordinal))

    # -- COFF symbols (MinGW and some LLVM builds keep them) -------------------

    def _coff_symbols(self) -> None:
        if not self.symtab_off or not self.nsymbols:
            return
        count = min(self.nsymbols, max(0, (self.r.size - self.symtab_off) // 18))
        strings = self.symtab_off + self.nsymbols * 18
        section_names = {s["name"] for s in self.raw_sections}
        i = 0
        while i < count:
            off = self.symtab_off + i * 18
            raw_name = self.r.bytes(off, 8)
            value, section, sym_type, storage, naux = self.r.unpack("IhHBB", off + 8)
            i += 1 + naux
            if storage not in (2, 3) or not 0 < section <= len(self.raw_sections):
                continue
            if raw_name[:4] == b"\0\0\0\0":
                try:
                    name = self.r.cstring(strings + struct.unpack_from("<I", raw_name, 4)[0])
                except ParseError:
                    continue
            else:
                name = raw_name.rstrip(b"\0").decode("utf-8", errors="replace")
            if not name or (storage == 3 and name in section_names):
                continue
            target = self.raw_sections[section - 1]
            self.b.symbols.append(Symbol(
                name=name, address=self.b.image_base + target["rva"] + value, size=0,
                type="func" if sym_type & 0x30 == 0x20 else "notype",
                binding="global" if storage == 2 else "local",
                section=target["name"]))

    # -- function ranges, debug info ------------------------------------------

    def _exception_table(self) -> None:
        rva, size = self._dir(DIR_EXCEPTION)
        if not rva or self.b.arch != "x86_64":
            return
        off = self._offset(rva, "exception directory")
        base = self.b.image_base
        ranges = []
        for i in range(min(size // 12, (self.r.size - off) // 12)):
            begin, end, _unwind = self.r.unpack("III", off + i * 12)
            if begin and begin < end:
                ranges.append((base + begin, base + end))
        self.b.function_ranges = sorted(set(ranges))

    def _debug(self) -> None:
        rva, size = self._dir(DIR_DEBUG)
        if not rva:
            return
        off = self._offset(rva, "debug directory")
        for i in range(min(size // 28, _MAX_ENTRIES)):
            _flags, _stamp, _major, _minor, kind, data_size, _addr, ptr = \
                self.r.unpack("IIHHIIII", off + i * 28)
            if kind != 2 or data_size < 24:     # 2 = CodeView
                continue
            signature = self.r.bytes(ptr, 4)
            path_off = {b"RSDS": 24, b"NB10": 16}.get(signature)
            if path_off is not None:
                self.b.metadata["pdb_path"] = self.r.cstring(ptr + path_off, 1024)
                return

    # -- security -------------------------------------------------------------

    def _security(self) -> None:
        chars = self.dll_chars
        relocatable = not self.characteristics & FILE_RELOCS_STRIPPED
        aslr = bool(chars & DLLCHAR_DYNAMIC_BASE) and relocatable
        cert_off, cert_size = self._dir(DIR_SECURITY)
        self.b.security = {
            "aslr": aslr,
            "high_entropy_va": aslr and bool(chars & DLLCHAR_HIGH_ENTROPY_VA),
            "nx": bool(chars & DLLCHAR_NX_COMPAT),
            "cfg": bool(chars & DLLCHAR_GUARD_CF),
            "seh": not chars & DLLCHAR_NO_SEH,
            "force_integrity": bool(chars & DLLCHAR_FORCE_INTEGRITY),
            "signed": bool(cert_off and cert_size),
            "dotnet": bool(self._dir(DIR_CLR)[0]),
        }
