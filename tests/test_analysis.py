"""Hashes, entropy and overlay detection. Reference digests come from
md5sum/sha1sum/sha256sum and pefile, run on the committed fixtures."""
import pytest

import binspect
from conftest import fixture_bytes


def test_file_hashes_match_coreutils(load_fixture):
    assert load_fixture("hello_pe64.exe").hashes == {
        "md5": "ba17a8b0244c9de58301a23ae0901668",
        "sha1": "79b8f19e9db6efe09483c583b8c12e6ede1fc24a",
        "sha256": "20ee2725bbc4d0d77368c07da01ceb90a635d045f4ff367e2dea3b90c68512ee",
    }


@pytest.mark.parametrize(
    "data, expected",
    [
        (b"", 0.0),
        (bytes(1000), 0.0),
        (b"ab" * 500, 1.0),
        (bytes(range(256)) * 4, 8.0),
        (b"aaab" * 100, 0.8113),
    ],
)
def test_entropy_in_bits_per_byte(data, expected):
    assert binspect.entropy(data) == pytest.approx(expected, abs=1e-4)


def test_section_entropy_uses_the_bytes_of_that_section(load_fixture):
    b = load_fixture("hello_pe64.exe")
    pdata = next(s for s in b.sections if s.name == ".pdata")
    raw = fixture_bytes("hello_pe64.exe")[0x800:0xA00]
    assert b.section_entropy(pdata) == pytest.approx(binspect.entropy(raw))
    assert 0 < b.section_entropy(pdata) < 2      # 24 meaningful bytes, rest zero


def test_import_hash_matches_pefile(load_fixture):
    assert load_fixture("hello_pe64.exe").metadata["imphash"] == \
        "733671eb2f1ac029df421a54678f7279"
    assert "imphash" not in load_fixture("sample.dll").metadata   # no imports


def test_import_hash_is_omitted_when_it_would_need_ordinal_name_tables(load_fixture):
    # pefile maps WS2_32 ordinals to names with a lookup table binspect does
    # not carry; a wrong hash would be worse than none.
    assert "imphash" not in load_fixture("netprobe.exe").metadata


def test_no_overlay_in_ordinary_binaries(load_fixture):
    # hello_pe64.exe keeps a COFF symbol table after its last section; that
    # is part of the format, not appended data.
    assert "overlay" not in load_fixture("hello_pe64.exe").metadata
    assert "overlay" not in load_fixture("hello_elf64").metadata
    assert "overlay" not in load_fixture("bare_elf32").metadata


def test_appended_data_is_reported_as_overlay():
    pe = binspect.load_bytes(fixture_bytes("hello_pe64.exe") + b"X" * 100)
    assert pe.metadata["overlay"] == {"offset": 3072, "size": 100}
    elf = binspect.load_bytes(fixture_bytes("hello_elf64") + b"X" * 64)
    assert elf.metadata["overlay"] == {"offset": 16232, "size": 64}


def test_certificate_table_is_not_an_overlay():
    data = bytearray(fixture_bytes("hello_pe64.exe"))
    data[0x120:0x128] = len(data).to_bytes(4, "little") + (16).to_bytes(4, "little")
    b = binspect.load_bytes(bytes(data) + bytes(16))
    assert "overlay" not in b.metadata
