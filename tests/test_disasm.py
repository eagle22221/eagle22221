"""Disassembly and annotation. Expected instructions were read from
objdump / llvm-objdump output for the committed fixtures."""
import sys

import pytest

import binspect
from binspect.disasm import Disassembler
from conftest import fixture_bytes


@pytest.fixture(scope="module")
def elf(load_fixture):
    return Disassembler(load_fixture("hello_elf64"))


@pytest.fixture(scope="module")
def pe(load_fixture):
    return Disassembler(load_fixture("hello_pe64.exe"))


def at(dis, address):
    return dis.disassemble(address, count=1)[0]


def test_decodes_instructions_in_intel_syntax(elf):
    got = [(i.address, i.size, i.mnemonic, i.operands) for i in elf.disassemble(0x11C9, count=3)]
    assert got == [
        (0x11C9, 4, "endbr64", ""),
        (0x11CD, 3, "lea", "eax, [rdi + rsi]"),
        (0x11D0, 1, "ret", ""),
    ]
    assert elf.disassemble(0x11C9, count=1)[0].raw == bytes.fromhex("f30f1efa")


def test_end_address_bounds_the_listing(elf):
    assert [i.address for i in elf.disassemble(0x11C9, end=0x11D1)] == [0x11C9, 0x11CD, 0x11D0]


def test_direct_call_is_annotated_with_the_callee_name(elf):
    insn = at(elf, 0x1254)
    assert (insn.kind, insn.target, insn.comment) == ("call", 0x11D1, "check_password")


def test_call_through_plt_stub_names_the_import(elf):
    insn = at(elf, 0x123E)
    assert (insn.kind, insn.target, insn.comment) == ("call", 0x10A0, "puts@plt")


def test_jump_inside_a_function_is_shown_as_offset_from_its_start(elf):
    insn = at(elf, 0x124E)
    assert (insn.mnemonic, insn.kind, insn.target, insn.comment) == ("jle", "jump", 0x125D, "main+0x6b")


def test_return_is_classified(elf):
    assert at(elf, 0x11D0).kind == "ret"


def test_rip_relative_reference_shows_the_string_it_points_to(elf):
    insn = at(elf, 0x1237)
    assert insn.refs == [0x2038]
    assert insn.comment == '"Hello from the binspect ELF fixture"'


def test_reference_to_named_data_shows_name_and_string(pe):
    insn = at(pe, 0x140001064)          # lea rcx, [rip + 0xfc5]  -> banner
    assert insn.refs == [0x140002030]
    assert insn.comment == 'banner "Hello from the binspect PE fixture\\r\\n"'


def test_indirect_call_through_import_table_names_dll_and_function(pe):
    insn = at(pe, 0x140001035)
    assert (insn.kind, insn.target, insn.refs) == ("call", None, [0x1400020D8])
    assert insn.comment == "KERNEL32.dll!GetStdHandle"


def test_import_thunk_gets_a_name(pe):
    assert pe.name_at(0x140001090) == "GetStdHandle@thunk"


def test_32_bit_absolute_operands_are_resolved(load_fixture):
    dis = Disassembler(load_fixture("hello_pe32.exe"))
    assert at(dis, 0x401034).comment == "KERNEL32.dll!GetStdHandle"
    push = at(dis, 0x401050)            # push 0x402028
    assert push.refs == [0x402028]
    assert push.comment == '"Hello from the binspect PE fixture\\r\\n"'


def test_small_immediates_are_not_mistaken_for_addresses(elf):
    # mov ecx, 0x20 in a PIE whose headers are mapped at address 0
    assert at(elf, 0x1220).refs == []


def test_arm64_branch_and_address_materialisation(load_fixture):
    dis = Disassembler(load_fixture("bare_arm64"))
    bl = at(dis, 0x2101B0)
    assert (bl.kind, bl.target, bl.comment) == ("call", 0x210174, "checksum")
    adr = at(dis, 0x2101A8)
    assert adr.refs == [0x200158]
    assert adr.comment == 'msg "bare-metal fixture says hi"'
    # adrp x8, 0x220000 ; str w0, [x8, #0x1c0]  -> result
    pair = dis.disassemble(0x2101B4, count=2)
    assert pair[1].refs == [0x2201C0]
    assert pair[1].comment == "result"


def test_undecodable_bytes_are_shown_as_data_and_decoding_continues():
    data = bytearray(fixture_bytes("hello_elf64"))
    data[0x11C9] = 0x06                 # PUSH ES: invalid in 64-bit mode
    dis = Disassembler(binspect.load_bytes(bytes(data)))
    first, second = dis.disassemble(0x11C9, count=2)
    assert (first.mnemonic, first.operands, first.size) == (".byte", "0x06", 1)
    assert second.address == 0x11CA


def test_address_outside_the_file_is_an_error(elf):
    with pytest.raises(binspect.LocationError):
        elf.disassemble(0x900000, count=4)


def test_name_at_covers_exact_inner_and_unknown_addresses(elf):
    assert elf.name_at(0x11F2) == "main"
    assert elf.name_at(0x11F2 + 0x10) == "main+0x10"
    assert elf.name_at(0x11F2 + 197) is None       # one past the end of main
    assert elf.name_at(0x10E0) == "_start"


def test_entry_point_is_named_when_symbols_are_stripped(load_fixture):
    assert Disassembler(load_fixture("hello_elf64_stripped")).name_at(0x10E0) == "entry"


def test_sweep_covers_all_executable_code_once(elf):
    addresses = [i.address for i in elf.sweep()]
    assert addresses == sorted(set(addresses))
    assert addresses[0] == 0x1000                  # .init is the first code
    assert {0x10E0, 0x11F2, 0x12B2}.issubset(addresses)
    assert max(addresses) < 0x12C5                 # end of .fini


def test_missing_capstone_is_reported_clearly(load_fixture, monkeypatch):
    monkeypatch.setitem(sys.modules, "capstone", None)
    with pytest.raises(binspect.MissingDependencyError, match="pip install capstone"):
        Disassembler(load_fixture("hello_elf64"))


def test_unknown_cpu_is_reported_clearly(load_fixture):
    data = bytearray(fixture_bytes("hello_elf64"))
    data[0x12:0x14] = (0x1234).to_bytes(2, "little")      # e_machine
    with pytest.raises(binspect.UnsupportedError):
        Disassembler(binspect.load_bytes(bytes(data)))


def test_string_preview_reads_data_but_never_code(elf):
    assert elf.string_at(0x2004) == '"s3cr3t-fixture-key"'
    data = bytearray(fixture_bytes("hello_elf64"))
    data[0x11C9:0x11CE] = b"ABCD\0"        # printable bytes inside .text
    assert Disassembler(binspect.load_bytes(bytes(data))).string_at(0x11C9) is None


def test_long_strings_are_truncated_in_previews(load_fixture):
    dis = Disassembler(load_fixture("hello_pe64.exe"))
    data = bytearray(fixture_bytes("hello_pe64.exe"))
    data[0x630:0x630 + 80] = b"A" * 79 + b"\0"
    long = Disassembler(binspect.load_bytes(bytes(data)))
    assert long.string_at(0x140002030) == '"' + "A" * 60 + '..."'
    assert dis.string_at(0x140002000) == '"Wide fixture string"'      # UTF-16
