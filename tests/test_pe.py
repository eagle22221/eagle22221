"""PE parsing. Expected values were read from the committed fixtures with
llvm-readobj/llvm-objdump, never computed by vex itself."""
import pytest

import vex
from conftest import fixture_bytes

# Header field offsets in the 64-bit fixtures (e_lfanew = 0x78):
#   optional header starts at 0x78 + 4 + 20 = 0x90
#   DllCharacteristics      = 0x90 + 70       = 0xD6
#   data directory table    = 0x90 + 112      = 0x100 (8 bytes per entry)
DLL_CHARACTERISTICS = 0xD6
DATA_DIRECTORIES = 0x100


def patched(name, offset, value: bytes) -> bytes:
    data = bytearray(fixture_bytes(name))
    data[offset:offset + len(value)] = value
    return bytes(data)


# --- identification --------------------------------------------------------

@pytest.mark.parametrize(
    "name, arch, bits, kind, entry, base",
    [
        ("hello_pe64.exe", "x86_64", 64, "executable", 0x140001060, 0x140000000),
        ("hello_pe32.exe", "x86", 32, "executable", 0x401050, 0x400000),
        ("sample.dll", "x86_64", 64, "dll", 0x180001020, 0x180000000),
    ],
)
def test_identifies_architecture_kind_entry_and_base(load_fixture, name, arch, bits, kind, entry, base):
    b = load_fixture(name)
    assert (b.format, b.arch, b.bits, b.endian) == ("PE", arch, bits, "little")
    assert b.kind == kind
    assert b.entry == entry
    assert b.image_base == base


# --- sections --------------------------------------------------------------

def test_sections_use_absolute_addresses_and_permissions(load_fixture):
    b = load_fixture("hello_pe64.exe")
    got = [(s.name, s.vaddr, s.vsize, s.offset, s.size, s.perms) for s in b.sections]
    assert got == [
        (".text", 0x140001000, 0xB6, 0x400, 0x200, "r-x"),
        (".rdata", 0x140002000, 0x13C, 0x600, 0x200, "r--"),
        (".pdata", 0x140003000, 0x18, 0x800, 0x200, "r--"),
    ]
    assert b.segments == []


def test_writable_section_permission(load_fixture):
    data = next(s for s in load_fixture("netprobe.exe").sections if s.name == ".data")
    assert data.perms == "rw-"


def test_virtual_address_maps_to_file_offset(load_fixture):
    b = load_fixture("hello_pe64.exe")
    assert b.vaddr_to_offset(0x140002030) == 0x630
    assert b.offset_to_vaddr(0x630) == 0x140002030
    assert b.read(0x140002030, 5) == b"Hello"
    assert b.vaddr_to_offset(0x150000000) is None


def test_headers_are_readable_at_the_image_base(load_fixture):
    assert load_fixture("hello_pe64.exe").read(0x140000000, 2) == b"MZ"


# --- imports ---------------------------------------------------------------

def test_imports_carry_library_and_iat_slot(load_fixture):
    b = load_fixture("hello_pe64.exe")
    assert [(i.library, i.name, i.address) for i in b.imports] == [
        ("KERNEL32.dll", "ExitProcess", 0x1400020D0),
        ("KERNEL32.dll", "GetStdHandle", 0x1400020D8),
        ("KERNEL32.dll", "WriteFile", 0x1400020E0),
    ]
    assert b.libraries == ["KERNEL32.dll"]


def test_32_bit_import_table_uses_4_byte_thunks(load_fixture):
    b = load_fixture("hello_pe32.exe")
    assert [(i.name, i.address) for i in b.imports] == [
        ("ExitProcess", 0x4020A8), ("GetStdHandle", 0x4020AC), ("WriteFile", 0x4020B0),
    ]


def test_import_by_ordinal_has_no_name_but_an_ordinal(load_fixture):
    imp = next(i for i in load_fixture("netprobe.exe").imports if i.library == "WS2_32.dll")
    assert (imp.name, imp.ordinal, imp.address, imp.delayed) == ("#115", 115, 0x140002108, False)


def test_delay_loaded_import_is_listed_and_flagged(load_fixture):
    b = load_fixture("netprobe.exe")
    imp = next(i for i in b.imports if i.library == "USER32.dll")
    assert (imp.name, imp.address, imp.delayed) == ("MessageBoxA", 0x140003010, True)
    assert b.libraries == ["KERNEL32.dll", "WS2_32.dll", "USER32.dll"]


# --- exports ---------------------------------------------------------------

def test_exports_carry_ordinal_address_and_forwarder(load_fixture):
    b = load_fixture("sample.dll")
    assert [(e.name, e.ordinal, e.address, e.forwarder) for e in b.exports] == [
        ("sample_add", 7, 0x180001000, None),
        ("sample_greet", 8, 0x180001010, None),
        ("sample_sleep", 9, None, "KERNEL32.Sleep"),
    ]
    assert b.metadata["dll_name"] == "sample.dll"


def test_executable_without_export_table_has_no_exports(load_fixture):
    assert load_fixture("hello_pe64.exe").exports == []


# --- symbols and function ranges -------------------------------------------

def test_coff_symbol_table_yields_function_names(load_fixture):
    by_name = {s.name: s for s in load_fixture("hello_pe64.exe").symbols}
    assert (by_name["print"].address, by_name["print"].type) == (0x140001020, "func")
    assert by_name["print"].section == ".text"
    assert (by_name["entry"].address, by_name["entry"].binding) == (0x140001060, "global")
    assert (by_name["banner"].address, by_name["banner"].binding) == (0x140002030, "local")
    assert by_name["banner"].type == "notype"


def test_binary_without_coff_symbols_has_empty_symbol_list(load_fixture):
    assert load_fixture("hello_pe32.exe").symbols == []


def test_exception_table_gives_exact_function_ranges(load_fixture):
    assert load_fixture("hello_pe64.exe").function_ranges == [
        (0x140001020, 0x140001060), (0x140001060, 0x140001089),
    ]
    assert load_fixture("hello_pe32.exe").function_ranges == []


# --- metadata --------------------------------------------------------------

def test_metadata_reports_timestamp_and_subsystem(load_fixture):
    md = load_fixture("hello_pe64.exe").metadata
    assert md["timestamp"] == "2023-11-14T22:13:20Z"
    assert md["subsystem"] == "console"
    assert load_fixture("sample.dll").metadata["subsystem"] == "gui"


def test_pdb_path_is_recovered_from_debug_directory(load_fixture):
    assert load_fixture("sample.dll").metadata["pdb_path"] == "C:\\build\\sample.pdb"
    assert "pdb_path" not in load_fixture("hello_pe64.exe").metadata


# --- security --------------------------------------------------------------

def test_hardened_image_reports_mitigations(load_fixture):
    sec = load_fixture("hello_pe64.exe").security
    assert sec["aslr"] is True
    assert sec["high_entropy_va"] is True
    assert sec["nx"] is True
    assert sec["cfg"] is False
    assert sec["seh"] is True
    assert sec["signed"] is False
    assert sec["dotnet"] is False


def test_unhardened_image_reports_no_aslr_or_dep(load_fixture):
    sec = load_fixture("hello_pe32.exe").security
    assert sec["aslr"] is False
    assert sec["nx"] is False
    assert sec["high_entropy_va"] is False


def test_control_flow_guard_and_no_seh_flags_are_read():
    flags = (0x8160 | 0x4000 | 0x0400).to_bytes(2, "little")
    sec = vex.load_bytes(patched("hello_pe64.exe", DLL_CHARACTERISTICS, flags)).security
    assert sec["cfg"] is True
    assert sec["seh"] is False


def test_certificate_table_marks_image_as_signed():
    data = fixture_bytes("hello_pe64.exe")
    entry = len(data).to_bytes(4, "little") + (16).to_bytes(4, "little")
    data = patched("hello_pe64.exe", DATA_DIRECTORIES + 4 * 8, entry) + bytes(16)
    assert vex.load_bytes(data).security["signed"] is True


def test_clr_header_marks_image_as_dotnet():
    entry = (0x2000).to_bytes(4, "little") + (0x48).to_bytes(4, "little")
    data = patched("hello_pe64.exe", DATA_DIRECTORIES + 14 * 8, entry)
    assert vex.load_bytes(data).security["dotnet"] is True


# --- malformed input -------------------------------------------------------

def test_dos_executable_without_pe_header_is_not_a_supported_format():
    with pytest.raises(vex.UnknownFormatError):
        vex.load_bytes(b"MZ" + bytes(62) + b"This program cannot be run in DOS mode")


def test_pe_header_offset_outside_file_is_rejected():
    data = patched("hello_pe64.exe", 0x3C, (0x7FFFFFF0).to_bytes(4, "little"))
    with pytest.raises(vex.VexError):
        vex.load_bytes(data)


def test_truncated_optional_header_is_a_parse_error():
    with pytest.raises(vex.ParseError):
        vex.load_bytes(fixture_bytes("hello_pe64.exe")[:0xA0])


def test_corrupt_import_directory_degrades_to_a_warning():
    # Point the import directory far outside the image.
    entry = (0x7FFF0000).to_bytes(4, "little") + (0x28).to_bytes(4, "little")
    b = vex.load_bytes(patched("hello_pe64.exe", DATA_DIRECTORIES + 1 * 8, entry))
    assert b.imports == []
    assert b.entry == 0x140001060
    assert any("import" in w.lower() for w in b.warnings)


def test_section_data_past_end_of_file_is_clipped():
    # Truncate inside .rdata: the section is still listed, with fewer bytes.
    b = vex.load_bytes(fixture_bytes("hello_pe64.exe")[:0x680])
    rdata = next(s for s in b.sections if s.name == ".rdata")
    assert rdata.size == 0x80
    assert b.read(0x140002030, 5) == b"Hello"


def test_raw_data_pointer_is_rounded_down_like_the_windows_loader_does():
    # .rdata is the 2nd section header (0x180 + 40); PointerToRawData is at +20.
    data = patched("hello_pe64.exe", 0x180 + 40 + 20, (0x610).to_bytes(4, "little"))
    assert vex.load_bytes(data).read(0x140002030, 5) == b"Hello"


def test_aslr_needs_relocations_to_be_present():
    # COFF Characteristics is at 0x78 + 4 + 18; bit 0 = relocations stripped.
    data = patched("hello_pe64.exe", 0x8E, (0x23).to_bytes(2, "little"))
    assert vex.load_bytes(data).security["aslr"] is False
