"""Function discovery, name resolution and cross-references. Expected
addresses were read from objdump / llvm-objdump for the committed fixtures."""
import pytest

import binspect
from binspect.analysis import Analysis


@pytest.fixture(scope="module")
def elf(load_fixture):
    return Analysis(load_fixture("hello_elf64"))


@pytest.fixture(scope="module")
def stripped(load_fixture):
    return Analysis(load_fixture("hello_elf64_stripped"))


@pytest.fixture(scope="module")
def pe(load_fixture):
    return Analysis(load_fixture("hello_pe64.exe"))


def table(analysis):
    return {f.address: (f.name, f.size, f.source) for f in analysis.functions}


# --- function discovery ----------------------------------------------------

def test_functions_from_symbols_keep_name_and_size(elf):
    t = table(elf)
    assert t[0x11F2] == ("main", 197, "symbol")
    assert t[0x11C9] == ("add_numbers", 8, "symbol")
    assert [f.address for f in elf.functions] == sorted(t)


def test_plt_stubs_are_listed_as_named_functions(elf):
    assert table(elf)[0x10A0] == ("puts@plt", 16, "call")


def test_stripped_binary_recovers_functions_from_calls(stripped):
    t = table(stripped)
    assert t[0x10E0] == ("entry", 0x30, "entry")           # next function at 0x1110
    assert t[0x11C9] == ("sub_11c9", 8, "call")
    assert t[0x11D1] == ("sub_11d1", 33, "call")


def test_main_is_recovered_from_the_libc_start_call(stripped):
    assert table(stripped)[0x11F2] == ("main", 0xC5, "libc_start_main")   # to the end of .text (0x12B7)


def test_windows_exception_table_gives_exact_sizes(pe):
    t = table(pe)
    assert t[0x140001020] == ("print", 0x40, "symbol")
    assert t[0x140001060] == ("entry", 0x29, "symbol")
    assert t[0x140001000] == ("text_length", 0x20, "symbol")


def test_pe_without_symbols_names_entry_and_call_targets(load_fixture):
    t = table(Analysis(load_fixture("hello_pe32.exe")))
    assert t[0x401050][0] == "entry"
    assert t[0x401000] == ("sub_401000", 0x20, "call")
    assert t[0x401020] == ("sub_401020", 0x30, "call")


def test_dll_functions_are_named_after_exports(load_fixture):
    t = table(Analysis(load_fixture("sample.dll")))
    assert t[0x180001000] == ("sample_add", 0x10, "export")
    assert t[0x180001010][0] == "sample_greet"
    assert t[0x180001020][0] == "entry"


def test_function_containing_an_address(elf):
    assert elf.function_at(0x1250).name == "main"
    assert elf.function_at(0x11F2).name == "main"
    assert elf.function_at(0x2038) is None             # data, not code


# --- name resolution -------------------------------------------------------

def test_resolve_accepts_entry_hex_symbol_and_function_names(elf, stripped):
    assert elf.resolve("entry") == [0x10E0]
    assert elf.resolve("0x11f2") == [0x11F2]
    assert elf.resolve("main") == [0x11F2]
    assert stripped.resolve("sub_11d1") == [0x11D1]
    assert stripped.resolve("main") == [0x11F2]


def test_resolve_import_gives_stub_and_slot(elf, pe):
    assert elf.resolve("puts") == [0x10A0, 0x3FB8]
    assert pe.resolve("WriteFile") == [0x1400010A0, 0x1400020E0]
    assert pe.resolve("kernel32.dll!WriteFile") == [0x1400010A0, 0x1400020E0]


def test_resolve_unknown_name_is_an_error(elf):
    with pytest.raises(binspect.LocationError, match="no_such_thing"):
        elf.resolve("no_such_thing")


# --- cross-references ------------------------------------------------------

def test_xrefs_to_an_imported_function(elf):
    got = [(x.address, x.kind, x.function) for x in elf.xrefs(elf.resolve("puts"))]
    assert got == [
        (0x10A4, "jump", "puts@plt+0x4"),
        (0x123E, "call", "main+0x4c"),
        (0x1246, "call", "main+0x54"),
        (0x1264, "call", "main+0x72"),
    ]


def test_xrefs_to_a_string_find_the_code_that_uses_it(elf):
    refs = elf.xrefs([0x2038])
    assert [(x.address, x.kind, x.function) for x in refs] == [(0x1237, "data", "main+0x45")]
    assert refs[0].text == "lea rdi, [rip + 0xdfa]"


def test_xrefs_to_a_local_function(elf):
    assert [(x.address, x.kind) for x in elf.xrefs(elf.resolve("check_password"))] == [
        (0x1254, "call")]


def test_xrefs_to_a_windows_api(pe):
    got = [(x.address, x.kind, x.function) for x in pe.xrefs(pe.resolve("WriteFile"))]
    assert got == [(0x140001052, "call", "print+0x32"), (0x1400010A0, "jump", "WriteFile@thunk")]


def test_xrefs_to_unreferenced_address_is_empty(elf):
    assert elf.xrefs([0x2000]) == []        # _IO_stdin_used: no code mentions it


def test_strings_matching_text_give_addresses_for_xref_lookup(elf):
    assert elf.string_addresses("binspect ELF") == [0x2038]
    assert elf.string_addresses("nothing like this") == []


def test_tail_call_through_import_slot_is_not_mistaken_for_a_thunk(pe):
    # entry ends with "jmp [ExitProcess]" at 0x140001082: a tail call inside
    # a function, unlike the stand-alone thunk at 0x1400010B0.
    assert pe.resolve("ExitProcess") == [0x1400010B0, 0x1400020D0]


def test_main_is_recovered_in_non_pie_binaries_too(load_fixture):
    # Non-PIE _start uses "mov rdi, 0x4011bf" rather than a rip-relative lea.
    a = Analysis(load_fixture("hello_elf64_nopie_stripped"))
    assert table(a)[0x4011BF][0::2] == ("main", "libc_start_main")
    assert a.resolve("main") == [0x4011BF]
