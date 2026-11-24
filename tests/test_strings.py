"""String extraction. Offsets were read from the fixtures with `strings -t x`."""
import pytest

from vex import strings


def find(found, text):
    return next(s for s in found if s.text == text)


def test_ascii_string_reports_offset_address_and_section(load_fixture):
    s = find(strings.extract(load_fixture("hello_elf64")),
             "Hello from the binspect ELF fixture")
    assert (s.offset, s.vaddr, s.section, s.encoding) == (0x2038, 0x2038, ".rodata", "ascii")


def test_pe_string_address_includes_image_base(load_fixture):
    s = find(strings.extract(load_fixture("hello_pe64.exe")),
             "https://example.com/update/check")
    assert (s.offset, s.vaddr, s.section) == (0x660, 0x140002060, ".rdata")


def test_utf16_strings_are_found_and_labelled(load_fixture):
    s = find(strings.extract(load_fixture("hello_pe64.exe")), "Wide fixture string")
    assert (s.offset, s.vaddr, s.encoding) == (0x600, 0x140002000, "utf16")


def test_string_outside_any_loaded_range_has_no_address(load_fixture):
    s = find(strings.extract(load_fixture("hello_elf64")),
             "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0")
    assert (s.offset, s.vaddr, s.section) == (0x3010, None, ".comment")


def test_encoding_filter_selects_one_kind(load_fixture):
    b = load_fixture("hello_pe64.exe")
    ascii_only = [s.text for s in strings.extract(b, encoding="ascii")]
    wide_only = [s.text for s in strings.extract(b, encoding="utf16")]
    assert "Wide fixture string" not in ascii_only
    assert "KERNEL32.dll" in ascii_only
    assert wide_only == ["Wide fixture string"]


def test_minimum_length_drops_shorter_strings(load_fixture):
    texts = [s.text for s in strings.extract(load_fixture("hello_elf64"), min_length=30)]
    assert "Hello from the binspect ELF fixture" in texts
    assert "s3cr3t-fixture-key" not in texts          # 18 characters
    assert all(len(t) >= 30 for t in texts)


def test_results_are_ordered_by_file_offset(load_fixture):
    offsets = [s.offset for s in strings.extract(load_fixture("hello_pe64.exe"))]
    assert offsets == sorted(offsets)


def test_strings_in_binary_are_tagged(load_fixture):
    found = strings.extract(load_fixture("hello_elf64"))
    assert find(found, "Visit http://example.com/docs for help").tags == ["url"]
    assert find(found, "/lib64/ld-linux-x86-64.so.2").tags == ["path"]
    assert find(found, "s3cr3t-fixture-key").tags == []


@pytest.mark.parametrize(
    "text, tags",
    [
        ("connect to 192.168.1.10 now", ["ipv4"]),
        ("999.1.1.1", []),                                   # octet out of range
        ("version 1.2.3", []),
        ("mail admin@example.org", ["email"]),
        ("C:\\Windows\\System32\\cmd.exe", ["path"]),
        ("/etc/passwd", ["path"]),
        ("HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", ["registry"]),
        ("ftp://files.example.net/a.bin", ["url"]),
        ("hello world", []),
        ("a/b", []),
    ],
)
def test_classify(text, tags):
    assert strings.classify(text) == tags


@pytest.mark.parametrize("text", ["puts@GLIBC_2.2.5", "__cxa_finalize@GLIBC_2.2.5", "name@plt", "a@b"])
def test_versioned_symbol_names_are_not_email_addresses(text):
    assert "email" not in strings.classify(text)
