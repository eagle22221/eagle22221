"""Byte patching. Offsets, addresses and original bytes were read from the
committed fixtures with `strings -t x`, `readelf -S -l` and a hex dump; the
no-op encodings come from `echo nop | llvm-mc -triple=<arch> -show-encoding`.

  hello_elf64     "s3cr3t-fixture-key" at offset 0x2004 = vaddr 0x2004
                  .data  vaddr 0x4000 = offset 0x3000, 0x10 bytes
                  .bss   vaddr 0x4010, no bytes in the file
                  the last LOAD segment's file bytes end at vaddr 0x4010
                  .comment at offset 0x3010 is not loaded (no address)
  hello_pe64.exe  image base 0x140000000
                  "Hello from the binspect PE fixture" at 0x630 = 0x140002030
                  UTF-16 "Wide fixture string" at offset 0x600
                  .rdata is mapped at 0x140002000..0x140002200
"""
import os
import shutil
import stat

import pytest

import binspect
from binspect import patch
from binspect.errors import BinspectError, LocationError, UnsupportedError
from binspect.model import Binary
from conftest import fixture_bytes, fixture_path


@pytest.fixture
def elf(tmp_path):
    path = tmp_path / "hello_elf64"
    shutil.copyfile(fixture_path("hello_elf64"), path)
    return path


@pytest.fixture
def pe(tmp_path):
    path = tmp_path / "hello_pe64.exe"
    shutil.copyfile(fixture_path("hello_pe64.exe"), path)
    return path


def differing_offsets(a: bytes, b: bytes):
    assert len(a) == len(b)
    return [i for i in range(len(a)) if a[i] != b[i]]


def only_entries(directory):
    return sorted(p.name for p in directory.iterdir())


# --- apply_patch: locating --------------------------------------------------

def test_patch_by_file_offset_overwrites_exactly_those_bytes(elf, tmp_path):
    out = tmp_path / "out"
    result = patch.apply_patch(elf, out, b"PUBLIC", offset=0x2004)
    assert result == patch.PatchResult(offset=0x2004, vaddr=0x2004,
                                       old=b"s3cr3t", new=b"PUBLIC")
    original, modified = fixture_bytes("hello_elf64"), out.read_bytes()
    assert modified[0x2004:0x2016] == b"PUBLIC-fixture-key"
    assert differing_offsets(original, modified) == [0x2004, 0x2005, 0x2006, 0x2007,
                                                     0x2008, 0x2009]


def test_patch_by_virtual_address_uses_the_pe_mapping(pe, tmp_path):
    out = tmp_path / "out.exe"
    result = patch.apply_patch(pe, out, b"HOWDY", vaddr=0x140002030)
    assert result == patch.PatchResult(offset=0x630, vaddr=0x140002030,
                                       old=b"Hello", new=b"HOWDY")
    assert out.read_bytes()[0x630:0x63A] == b"HOWDY from"
    # "Hello" -> "HOWDY": the leading H is the same byte.
    assert differing_offsets(fixture_bytes("hello_pe64.exe"), out.read_bytes()) == \
        [0x631, 0x632, 0x633, 0x634]


def test_patch_by_virtual_address_in_elf_data_segment(elf, tmp_path):
    # .data: vaddr 0x4000 is file offset 0x3000 (the segment is not identity-mapped).
    out = tmp_path / "out"
    result = patch.apply_patch(elf, out, b"\xAA\xBB", vaddr=0x4008)
    assert (result.offset, result.vaddr, result.old) == (0x3008, 0x4008, b"\x08\x40")
    assert out.read_bytes()[0x3008:0x300A] == b"\xAA\xBB"


def test_offset_outside_any_loaded_range_has_no_address(elf, tmp_path):
    result = patch.apply_patch(elf, tmp_path / "out", b"gcc", offset=0x3010)
    assert (result.offset, result.vaddr, result.old) == (0x3010, None, b"GCC")


def test_the_file_size_never_changes(elf, tmp_path):
    out = tmp_path / "out"
    patch.apply_patch(elf, out, b"\0" * 64, offset=16232 - 64)   # up to the last byte
    assert out.stat().st_size == 16232


def test_file_that_is_neither_elf_nor_pe_is_patchable_by_offset(tmp_path):
    src = tmp_path / "data.bin"
    src.write_bytes(b"0123456789")
    result = patch.apply_patch(src, tmp_path / "out.bin", b"ab", offset=3)
    assert result == patch.PatchResult(offset=3, vaddr=None, old=b"34", new=b"ab")
    assert (tmp_path / "out.bin").read_bytes() == b"012ab56789"


def test_result_bytes_are_immutable_copies(elf, tmp_path):
    result = patch.apply_patch(elf, tmp_path / "out", bytearray(b"xy"), offset=0x2004)
    assert type(result.new) is bytes and type(result.old) is bytes


# --- apply_patch: refusals (nothing may be written) --------------------------

def refused(src, tmp_path, data, **where):
    out = tmp_path / "must-not-exist"
    before = src.read_bytes()
    with pytest.raises(LocationError):
        patch.apply_patch(src, out, data, **where)
    assert not out.exists()
    assert src.read_bytes() == before
    assert only_entries(tmp_path) == [src.name]         # no temp file, no backup


def test_offset_and_vaddr_together_are_refused(elf, tmp_path):
    refused(elf, tmp_path, b"x", offset=0x2004, vaddr=0x2004)


def test_neither_offset_nor_vaddr_is_refused(elf, tmp_path):
    refused(elf, tmp_path, b"x")


def test_bss_address_is_refused_because_it_has_no_file_bytes(elf, tmp_path):
    refused(elf, tmp_path, b"\x01", vaddr=0x4010)


def test_patch_running_past_the_file_backed_part_of_a_segment_is_refused(elf, tmp_path):
    # 8 bytes at 0x400C would need 0x4010..0x4013, which is .bss.
    refused(elf, tmp_path, b"\x01" * 8, vaddr=0x400C)


def test_patch_running_past_the_end_of_a_pe_section_is_refused(pe, tmp_path):
    refused(pe, tmp_path, b"\x01" * 16, vaddr=0x1400021F8)


def test_patch_ending_exactly_at_the_end_of_a_mapped_range_is_allowed(pe, tmp_path):
    result = patch.apply_patch(pe, tmp_path / "out.exe", b"\x01" * 8, vaddr=0x1400021F8)
    assert result.offset == 0x7F8


def test_unmapped_address_is_refused(pe, tmp_path):
    refused(pe, tmp_path, b"\x01", vaddr=0x150000000)


@pytest.mark.parametrize("offset, size", [(16232, 1), (16231, 2), (-1, 1), (1 << 40, 4)])
def test_offset_outside_the_file_is_refused(elf, tmp_path, offset, size):
    refused(elf, tmp_path, b"\x01" * size, offset=offset)


def test_empty_patch_is_refused(elf, tmp_path):
    refused(elf, tmp_path, b"", offset=0x2004)


def test_virtual_address_in_an_unknown_file_format_is_refused(tmp_path):
    src = tmp_path / "data.bin"
    src.write_bytes(b"0123456789")
    refused(src, tmp_path, b"ab", vaddr=3)


def test_missing_source_file_is_an_os_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        patch.apply_patch(tmp_path / "nope", tmp_path / "out", b"x", offset=0)
    assert only_entries(tmp_path) == []


# --- backups and atomic writes ----------------------------------------------

def test_patching_in_place_keeps_the_original_as_bak(elf, tmp_path):
    patch.apply_patch(elf, elf, b"PUBLIC", offset=0x2004)
    assert elf.read_bytes()[0x2004:0x200A] == b"PUBLIC"
    assert (tmp_path / "hello_elf64.bak").read_bytes() == fixture_bytes("hello_elf64")
    assert only_entries(tmp_path) == ["hello_elf64", "hello_elf64.bak"]


def test_existing_backup_is_never_overwritten(elf, tmp_path):
    patch.apply_patch(elf, elf, b"PUBLIC", offset=0x2004)
    patch.apply_patch(elf, elf, b"second", offset=0x2004)
    assert elf.read_bytes()[0x2004:0x200A] == b"second"
    # Still the pristine original, not the once-patched file.
    assert (tmp_path / "hello_elf64.bak").read_bytes() == fixture_bytes("hello_elf64")


def test_backup_written_by_the_user_is_left_alone(elf, tmp_path):
    (tmp_path / "hello_elf64.bak").write_bytes(b"my own backup")
    patch.apply_patch(elf, elf, b"PUBLIC", offset=0x2004)
    assert (tmp_path / "hello_elf64.bak").read_bytes() == b"my own backup"


def test_same_file_spelled_differently_still_gets_a_backup(elf, tmp_path):
    other_spelling = tmp_path / "sub" / ".." / "hello_elf64"
    (tmp_path / "sub").mkdir()
    patch.apply_patch(elf, other_spelling, b"PUBLIC", offset=0x2004)
    assert (tmp_path / "hello_elf64.bak").read_bytes() == fixture_bytes("hello_elf64")


def test_writing_a_copy_leaves_the_source_alone_and_makes_no_backup(elf, tmp_path):
    out = tmp_path / "patched"
    patch.apply_patch(elf, out, b"PUBLIC", offset=0x2004)
    assert elf.read_bytes() == fixture_bytes("hello_elf64")
    assert only_entries(tmp_path) == ["hello_elf64", "patched"]


def test_paths_may_be_plain_strings(elf, tmp_path):
    patch.apply_patch(str(elf), str(tmp_path / "out"), b"PUBLIC", offset=0x2004)
    assert (tmp_path / "out").read_bytes()[0x2004:0x200A] == b"PUBLIC"


def test_output_keeps_the_permissions_of_the_source(elf, tmp_path):
    os.chmod(elf, 0o750)
    out = tmp_path / "out"
    patch.apply_patch(elf, out, b"PUBLIC", offset=0x2004)
    assert stat.S_IMODE(out.stat().st_mode) == 0o750
    patch.apply_patch(elf, elf, b"PUBLIC", offset=0x2004)
    assert stat.S_IMODE(elf.stat().st_mode) == 0o750


def test_output_is_written_to_a_temp_file_in_the_destination_directory(elf, tmp_path, monkeypatch):
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    out = dest_dir / "out"
    calls = []
    real_replace = os.replace

    def spy(src, dst, *args, **kwargs):
        # At the moment of the rename the complete new content is already on disk.
        calls.append((os.path.dirname(os.path.abspath(src)), os.path.abspath(dst),
                      open(src, "rb").read()[0x2004:0x200A], os.path.exists(dst)))
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "replace", spy)
    patch.apply_patch(elf, out, b"PUBLIC", offset=0x2004)
    assert calls == [(str(dest_dir), str(out), b"PUBLIC", False)]
    assert only_entries(dest_dir) == ["out"]


def test_crash_while_replacing_leaves_the_destination_untouched(elf, tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.write_bytes(b"previous content")

    def boom(src, dst, *args, **kwargs):
        raise OSError("simulated crash")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="simulated crash"):
        patch.apply_patch(elf, out, b"PUBLIC", offset=0x2004)
    assert out.read_bytes() == b"previous content"
    assert only_entries(tmp_path) == ["hello_elf64", "out"]     # temp file cleaned up


def test_crash_while_patching_in_place_leaves_the_original_intact(elf, tmp_path, monkeypatch):
    real_replace = os.replace

    def boom(src, dst, *args, **kwargs):
        if str(dst).endswith(".bak"):
            return real_replace(src, dst, *args, **kwargs)
        raise OSError("simulated crash")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="simulated crash"):
        patch.apply_patch(elf, elf, b"PUBLIC", offset=0x2004)
    assert elf.read_bytes() == fixture_bytes("hello_elf64")
    leftovers = [n for n in only_entries(tmp_path) if n not in ("hello_elf64", "hello_elf64.bak")]
    assert leftovers == []


# --- nop_bytes --------------------------------------------------------------

def fake_binary(arch, endian="little", fmt="ELF", bits=32, data=b""):
    b = Binary(data)
    b.format, b.arch, b.endian, b.bits = fmt, arch, endian, bits
    return b


def test_x86_nops_are_single_bytes(load_fixture):
    assert patch.nop_bytes(load_fixture("hello_elf64"), 5) == b"\x90\x90\x90\x90\x90"
    assert patch.nop_bytes(load_fixture("hello_pe32.exe"), 3) == b"\x90\x90\x90"
    assert patch.nop_bytes(load_fixture("bare_elf32"), 1) == b"\x90"


def test_aarch64_nops_are_four_byte_instructions(load_fixture):
    assert patch.nop_bytes(load_fixture("bare_arm64"), 8) == \
        bytes.fromhex("1f2003d5 1f2003d5")


def test_arm_nops_follow_the_byte_order_of_the_binary():
    assert patch.nop_bytes(fake_binary("arm"), 8) == bytes.fromhex("00f020e3 00f020e3")
    assert patch.nop_bytes(fake_binary("arm", endian="big"), 4) == bytes.fromhex("e320f000")
    assert patch.nop_bytes(fake_binary("arm", fmt="PE"), 4) == bytes.fromhex("00f020e3")


def test_big_endian_arm_be8_images_keep_little_endian_code():
    # ELF32 big-endian header with EF_ARM_BE8 (0x00800000) in e_flags at offset 36.
    header = bytearray(52)
    header[0:6] = b"\x7fELF\x01\x02"
    header[36:40] = (0x05800000).to_bytes(4, "big")
    be8 = fake_binary("arm", endian="big", data=bytes(header))
    assert patch.nop_bytes(be8, 4) == bytes.fromhex("00f020e3")


def test_aarch64_code_is_little_endian_even_in_big_endian_images():
    assert patch.nop_bytes(fake_binary("aarch64", endian="big", bits=64), 4) == \
        bytes.fromhex("1f2003d5")


@pytest.mark.parametrize("arch, length", [("aarch64", 6), ("aarch64", 1), ("arm", 7)])
def test_partial_instruction_is_refused_on_fixed_width_architectures(arch, length):
    with pytest.raises(LocationError):
        patch.nop_bytes(fake_binary(arch), length)


@pytest.mark.parametrize("arch", ["riscv", "mips", "unknown", "unknown(0x1234)", ""])
def test_unknown_architecture_is_unsupported(arch):
    with pytest.raises(UnsupportedError):
        patch.nop_bytes(fake_binary(arch), 4)


def test_zero_and_negative_lengths(load_fixture):
    assert patch.nop_bytes(load_fixture("hello_elf64"), 0) == b""
    assert patch.nop_bytes(load_fixture("bare_arm64"), 0) == b""
    with pytest.raises(LocationError):
        patch.nop_bytes(load_fixture("hello_elf64"), -1)


def test_nops_can_be_applied_as_a_patch(tmp_path):
    # bare_arm64: first instruction at offset 0x174 (vaddr 0x210174) is 09 00 40 39.
    b = binspect.load(fixture_path("bare_arm64"))
    out = tmp_path / "out"
    result = patch.apply_patch(fixture_path("bare_arm64"), out, patch.nop_bytes(b, 4),
                               vaddr=0x210174)
    assert (result.offset, result.old) == (0x174, bytes.fromhex("09004039"))
    assert out.read_bytes()[0x174:0x178] == bytes.fromhex("1f2003d5")


# --- replace_string ---------------------------------------------------------

def test_shorter_ascii_replacement_is_padded_with_nul(elf, tmp_path):
    out = tmp_path / "out"
    results = patch.replace_string(elf, out, "s3cr3t-fixture-key", "public")
    assert results == [patch.PatchResult(
        offset=0x2004, vaddr=0x2004, old=b"s3cr3t-fixture-key",
        new=b"public" + b"\0" * 12)]
    modified = out.read_bytes()
    assert modified[0x2004:0x2017] == b"public" + b"\0" * 13     # 12 pad + old terminator
    assert modified[0x2017:0x201E] == b"user-%d"                 # neighbour untouched
    assert len(modified) == 16232


def test_equal_length_replacement_changes_only_the_string(elf, tmp_path):
    out = tmp_path / "out"
    results = patch.replace_string(elf, out, "s3cr3t-fixture-key", "S3CR3T-FIXTURE-KEY")
    assert [(r.offset, r.new) for r in results] == [(0x2004, b"S3CR3T-FIXTURE-KEY")]
    changed = differing_offsets(fixture_bytes("hello_elf64"), out.read_bytes())
    assert changed and min(changed) >= 0x2004 and max(changed) < 0x2016


def test_longer_replacement_is_refused_with_an_explanation(elf, tmp_path):
    out = tmp_path / "out"
    with pytest.raises(LocationError, match="equal or shorter"):
        patch.replace_string(elf, out, "s3cr3t-fixture-key", "s3cr3t-fixture-key!")
    assert not out.exists()
    assert only_entries(tmp_path) == ["hello_elf64"]


def test_string_that_does_not_occur_is_refused(elf, tmp_path):
    out = tmp_path / "out"
    with pytest.raises(LocationError):
        patch.replace_string(elf, out, "no such text in the file", "x")
    assert not out.exists()
    assert only_entries(tmp_path) == ["hello_elf64"]


def test_every_occurrence_is_replaced_and_reported(elf, tmp_path):
    # `grep -obUa GLIBC_2.3.4 hello_elf64` -> offsets 1382, 13614, 13862.
    out = tmp_path / "out"
    results = patch.replace_string(elf, out, "GLIBC_2.3.4", "GLIBC_9.9.9")
    assert [(r.offset, r.vaddr) for r in results] == [(1382, 1382), (13614, None), (13862, None)]
    assert all(r.old == b"GLIBC_2.3.4" and r.new == b"GLIBC_9.9.9" for r in results)
    modified = out.read_bytes()
    assert modified.count(b"GLIBC_9.9.9") == 3 and modified.count(b"GLIBC_2.3.4") == 0


def test_utf16_string_is_replaced_with_wide_padding(pe, tmp_path):
    out = tmp_path / "out.exe"
    results = patch.replace_string(pe, out, "Wide fixture string", "Wide", encoding="utf16")
    assert results == [patch.PatchResult(
        offset=0x600, vaddr=0x140002000,
        old="Wide fixture string".encode("utf-16-le"),
        new=b"W\0i\0d\0e\0" + b"\0" * 30)]
    modified = out.read_bytes()
    assert modified[0x600:0x630] == b"W\0i\0d\0e\0" + b"\0" * 40
    assert modified[0x630:0x635] == b"Hello"
    assert len(modified) == 3072


def test_ascii_search_does_not_match_utf16_text_and_vice_versa(pe, tmp_path):
    with pytest.raises(LocationError):
        patch.replace_string(pe, tmp_path / "a", "Wide fixture string", "x")
    with pytest.raises(LocationError):
        patch.replace_string(pe, tmp_path / "b", "KERNEL32.dll", "x", encoding="utf16")


def test_text_that_is_part_of_a_longer_string_is_matched(pe, tmp_path):
    out = tmp_path / "out.exe"
    results = patch.replace_string(pe, out, "Hello", "Howdy")
    assert [(r.offset, r.vaddr) for r in results] == [(0x630, 0x140002030)]
    assert out.read_bytes()[0x630:0x652] == b"Howdy from the binspect PE fixture"


def test_empty_search_text_is_refused(elf, tmp_path):
    with pytest.raises(LocationError):
        patch.replace_string(elf, tmp_path / "out", "", "")
    assert not (tmp_path / "out").exists()


def test_text_that_cannot_be_encoded_is_refused(elf, tmp_path):
    with pytest.raises(LocationError):
        patch.replace_string(elf, tmp_path / "out", "s3cr3t-fixture-key", "sécurité")
    with pytest.raises(LocationError):
        patch.replace_string(elf, tmp_path / "out", "clé", "x")
    assert not (tmp_path / "out").exists()


def test_unknown_encoding_is_refused(elf, tmp_path):
    with pytest.raises(BinspectError):
        patch.replace_string(elf, tmp_path / "out", "s3cr3t-fixture-key", "x", encoding="utf8")
    assert not (tmp_path / "out").exists()


def test_replacing_a_string_in_place_makes_one_backup(elf, tmp_path):
    patch.replace_string(elf, elf, "s3cr3t-fixture-key", "public")
    patch.replace_string(elf, elf, "public", "open")
    assert elf.read_bytes()[0x2004:0x2008] == b"open"
    assert (tmp_path / "hello_elf64.bak").read_bytes() == fixture_bytes("hello_elf64")
    assert only_entries(tmp_path) == ["hello_elf64", "hello_elf64.bak"]


def test_string_in_a_file_of_unknown_format_has_no_address(tmp_path):
    src = tmp_path / "save.dat"
    src.write_bytes(b"name=player one;")
    results = patch.replace_string(src, tmp_path / "out.dat", "player one", "p1")
    assert results == [patch.PatchResult(offset=5, vaddr=None, old=b"player one",
                                         new=b"p1" + b"\0" * 8)]
    assert (tmp_path / "out.dat").read_bytes() == b"name=p1" + b"\0" * 8 + b";"
