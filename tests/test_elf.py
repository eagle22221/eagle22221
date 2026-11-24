"""ELF parsing. Expected values were read from the committed fixtures with
readelf/objdump, never computed by vex itself."""
import pytest

import vex
from conftest import fixture_bytes


# --- identification --------------------------------------------------------

@pytest.mark.parametrize(
    "name, arch, bits, kind, entry",
    [
        ("hello_elf64", "x86_64", 64, "executable", 0x10E0),
        ("bare_elf32", "x86", 32, "executable", 0x401120),
        ("bare_arm64", "aarch64", 64, "executable", 0x2101A0),
        ("libsample.so", "x86_64", 64, "shared library", None),
    ],
)
def test_identifies_architecture_kind_and_entry(load_fixture, name, arch, bits, kind, entry):
    b = load_fixture(name)
    assert (b.format, b.arch, b.bits, b.endian) == ("ELF", arch, bits, "little")
    assert b.kind == kind
    assert b.entry == entry


def test_image_base_is_lowest_loaded_address(load_fixture):
    assert load_fixture("hello_elf64").image_base == 0
    assert load_fixture("bare_elf32").image_base == 0x400000


# --- sections and segments -------------------------------------------------

def test_sections_carry_address_offset_size_and_permissions(load_fixture):
    b = load_fixture("hello_elf64")
    by_name = {s.name: s for s in b.sections}
    text = by_name[".text"]
    assert (text.vaddr, text.offset, text.size, text.perms) == (0x10E0, 0x10E0, 0x1D7, "r-x")
    assert by_name[".rodata"].perms == "r--"
    assert by_name[".data"].perms == "rw-"
    assert by_name[".comment"].perms == "---"
    assert len(b.sections) == 30  # 31 headers minus the leading NULL entry


def test_bss_occupies_memory_but_no_file_bytes(load_fixture):
    bss = next(s for s in load_fixture("hello_elf64").sections if s.name == ".bss")
    assert (bss.vsize, bss.size, bss.type) == (8, 0, "NOBITS")


def test_segments_list_program_headers(load_fixture):
    b = load_fixture("hello_elf64")
    assert len(b.segments) == 13
    loads = [s for s in b.segments if s.type == "LOAD"]
    assert [(s.vaddr, s.perms) for s in loads] == [
        (0x0, "r--"), (0x1000, "r-x"), (0x2000, "r--"), (0x3D98, "rw-"),
    ]


def test_virtual_address_maps_to_file_offset_through_segments(load_fixture):
    b = load_fixture("hello_elf64")
    # .data lives at vaddr 0x4000 but file offset 0x3000
    assert b.vaddr_to_offset(0x4008) == 0x3008
    assert b.offset_to_vaddr(0x3008) == 0x4008
    assert b.vaddr_to_offset(0x900000) is None


def test_read_returns_bytes_at_virtual_address(load_fixture):
    b = load_fixture("hello_elf64")
    assert b.read(0x2004, 18) == b"s3cr3t-fixture-key"
    assert load_fixture("bare_elf32").read(0x4000D4, 10) == b"bare-metal"


# --- symbols ---------------------------------------------------------------

def test_function_symbols_have_address_size_and_binding(load_fixture):
    b = load_fixture("hello_elf64")
    by_name = {s.name: s for s in b.symbols}
    main = by_name["main"]
    assert (main.address, main.size, main.type, main.binding) == (0x11F2, 197, "func", "global")
    assert main.section == ".text"
    assert by_name["check_password"].address == 0x11D1
    assert by_name["deregister_tm_clones"].binding == "local"


def test_symbols_exclude_undefined_and_unnamed_entries(load_fixture):
    names = [s.name for s in load_fixture("hello_elf64").symbols]
    assert "puts" not in names          # undefined: an import, not a symbol
    assert "" not in names
    assert all(not n.startswith("puts@") for n in names)


def test_32_bit_symbol_layout_is_decoded(load_fixture):
    by_name = {s.name: s for s in load_fixture("bare_elf32").symbols}
    assert (by_name["checksum"].address, by_name["checksum"].size) == (0x4010F0, 33)
    assert (by_name["msg"].type, by_name["msg"].size) == ("object", 27)


def test_stripped_binary_has_no_static_symbols(load_fixture):
    b = load_fixture("hello_elf64_stripped")
    assert b.symbols == []
    assert b.security["stripped"] is True
    assert load_fixture("hello_elf64").security["stripped"] is False


# --- imports / exports / libraries -----------------------------------------

def test_imports_name_library_version_and_got_slot(load_fixture):
    b = load_fixture("hello_elf64")
    by_name = {i.name: i for i in b.imports}
    puts = by_name["puts"]
    assert (puts.library, puts.version, puts.address) == ("libc.so.6", "GLIBC_2.2.5", 0x3FB8)
    assert by_name["__libc_start_main"].version == "GLIBC_2.34"
    assert by_name["__libc_start_main"].address == 0x3FD8   # GLOB_DAT slot
    assert by_name["__gmon_start__"].library is None        # unversioned weak
    assert len(b.imports) == 10


def test_needed_libraries(load_fixture):
    assert load_fixture("hello_elf64").libraries == ["libc.so.6"]
    assert load_fixture("bare_elf32").libraries == []


def test_shared_library_exports_only_visible_defined_symbols(load_fixture):
    b = load_fixture("libsample.so")
    assert [(e.name, e.address) for e in b.exports] == [
        ("sample_add", 0x1101), ("sample_greet", 0x1109),
    ]
    assert b.metadata["soname"] == "libsample.so.1"


def test_imports_survive_removal_of_section_headers():
    # sstrip-style binaries keep only program headers; the dynamic segment
    # must be enough to recover imports.
    data = bytearray(fixture_bytes("hello_elf64"))
    data[0x28:0x30] = bytes(8)      # e_shoff
    data[0x3C:0x40] = bytes(4)      # e_shnum, e_shstrndx
    b = vex.load_bytes(bytes(data))
    assert b.sections == []
    assert b.libraries == ["libc.so.6"]
    by_name = {i.name: i for i in b.imports}
    assert by_name["puts"].address == 0x3FB8
    assert by_name["puts"].version == "GLIBC_2.2.5"


# --- metadata --------------------------------------------------------------

def test_metadata_reports_interpreter_build_id_and_compiler(load_fixture):
    md = load_fixture("hello_elf64").metadata
    assert md["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert md["build_id"] == "14ca7f51d842c01be7f85f98eb001f1c6ddb8232"
    assert md["compiler"] == ["GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0"]


# --- security --------------------------------------------------------------

def test_hardened_binary_reports_all_mitigations(load_fixture):
    sec = load_fixture("hello_elf64").security
    assert sec["nx"] is True
    assert sec["pie"] is True
    assert sec["relro"] == "full"
    assert sec["canary"] is True
    assert sec["fortify"] is True


def test_unhardened_static_binary_reports_no_mitigations(load_fixture):
    sec = load_fixture("bare_elf32").security
    assert sec["nx"] is False          # linked with -z execstack
    assert sec["pie"] is False
    assert sec["relro"] == "none"
    assert sec["canary"] is False
    assert sec["fortify"] is False


def test_relro_without_bind_now_is_partial(load_fixture):
    assert load_fixture("libsample.so").security["relro"] == "partial"


# --- malformed input -------------------------------------------------------

def test_unknown_format_is_rejected():
    with pytest.raises(vex.UnknownFormatError):
        vex.load_bytes(b"this is not a binary at all, just text")


def test_empty_file_is_rejected():
    with pytest.raises(vex.UnknownFormatError):
        vex.load_bytes(b"")


def test_truncated_elf_header_is_a_parse_error():
    with pytest.raises(vex.ParseError):
        vex.load_bytes(fixture_bytes("hello_elf64")[:40])


def test_section_table_past_end_of_file_degrades_to_a_warning():
    data = bytearray(fixture_bytes("hello_elf64"))
    data[0x28:0x30] = (0x7FFFFFF0).to_bytes(8, "little")   # e_shoff far past EOF
    b = vex.load_bytes(bytes(data))
    assert b.sections == []
    assert b.entry == 0x10E0
    assert any("section" in w.lower() for w in b.warnings)


def test_source_file_names_are_recovered_from_file_symbols(load_fixture):
    assert load_fixture("bare_elf32").metadata["source_files"] == ["bare.c"]
    assert "hello.c" in load_fixture("hello_elf64").metadata["source_files"]


def test_arm_mapping_symbols_are_not_reported_as_names(load_fixture):
    names = {s.name for s in load_fixture("bare_arm64").symbols}
    assert names == {"msg", "checksum", "_start", "result"}


def test_dynamic_only_symbols_are_kept_when_static_table_is_stripped():
    import subprocess, shutil, tempfile, pathlib
    # A stripped shared library still names its exports through .dynsym.
    if shutil.which("strip") is None:
        pytest.skip("strip not available")
    from conftest import fixture_path
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "libsample_stripped.so"
        subprocess.run(["strip", "-o", str(out), str(fixture_path("libsample.so"))], check=True)
        b = vex.load(out)
    assert b.security["stripped"] is True
    assert {(s.name, s.address) for s in b.symbols} == {
        ("sample_add", 0x1101), ("sample_greet", 0x1109)}


def test_symbol_present_in_both_tables_is_listed_once(load_fixture):
    names = [s.name for s in load_fixture("libsample.so").symbols]
    assert names.count("sample_add") == 1
    assert "hidden_helper" in names      # static-only symbol is still listed
