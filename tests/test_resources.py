"""Windows resources of resdemo.exe (built by tests/fixtures/build_resources.sh).

Every expected value was read from the committed fixture with independent
tools, never computed by binspect: `llvm-readobj --file-headers --sections
--coff-resources --symbols`, the pefile module (offsets, hashes, version
strings, checksums) and a hex dump. Layout of the fixture:

  e_lfanew 0x78; COFF header 0x7C (NumberOfSections 0x7E, PointerToSymbolTable
  0x84); optional header 0x90 (SizeOfInitializedData 0x98, SizeOfImage 0xC8,
  SizeOfHeaders 0xCC, CheckSum 0xD0); data directories 0x100 (resources 0x110,
  certificates 0x120); section table 0x180..0x220, headers end at 0x400.

  section   RVA     VirtualSize  file offset  raw size
  .text     0x1000  0x16         0x400        0x200
  .rdata    0x2000  0x93         0x600        0x200
  .rsrc     0x3000  0xB80        0x800        0xC00     (0x80 bytes of padding)
  .reloc    0x4000  0xC          0x1400       0x200
  COFF symbol table at 0x1600 (15 symbols), file size 0x1800.

  resource directory (file offsets): root 0x800 with entries at 0x810 + 8*i
  (LEVELDATA, ICON, STRING, RCDATA, GROUP_ICON, VERSION, MANIFEST); ICON type
  directory 0x860; language directory of ICON #1 at 0x920 (entry 0x930);
  data entries (RVA, Size, CodePage, Reserved) at 0xA00 + 16*k in tree order.
"""
import hashlib
import os
import shutil
import signal
import struct
from contextlib import contextmanager
from pathlib import Path

import pytest

import binspect
from binspect import resources
from binspect.errors import BinspectError, LocationError, ParseError, UnsupportedError
from binspect.resources import Resource
from conftest import fixture_bytes, fixture_path

SRC = Path(__file__).parent / "fixtures" / "src"

# (type, name, language, file offset, size, codepage) in tree order.
ALL = [
    Resource("LEVELDATA", "#1", 1033, 0xDA8, 12, 0),
    Resource("ICON", "#1", 1033, 0xAE0, 296, 0),
    Resource("ICON", "#2", 1033, 0xC08, 304, 0),
    Resource("STRING", "#1", 1031, 0x1318, 100, 0),
    Resource("STRING", "#1", 1033, 0x1250, 112, 0),
    Resource("STRING", "#2", 1033, 0x12C0, 88, 0),
    Resource("RCDATA", "SETTINGS", 1033, 0xD90, 24, 0),
    Resource("RCDATA", "#101", 1033, 0xD60, 43, 0),
    Resource("GROUP_ICON", "#1", 1033, 0xD38, 34, 0),
    Resource("VERSION", "#1", 1033, 0xDB8, 720, 0),
    Resource("MANIFEST", "#1", 1033, 0x1088, 456, 0),
]
LEVELDATA, ICON1, ICON2, STRING_DE, STRING_EN, STRING2, SETTINGS, RCDATA101, \
    GROUP, VERSION, MANIFEST = ALL

# Header fields (file offsets).
NUM_SECTIONS, SYMTAB_PTR, NUM_SYMBOLS = 0x7E, 0x84, 0x88
SIZE_OF_INIT_DATA, SIZE_OF_IMAGE, SIZE_OF_HEADERS, CHECKSUM = 0x98, 0xC8, 0xCC, 0xD0
RESOURCE_DIR, SECURITY_DIR = 0x110, 0x120
RSRC_HEADER, FREE_HEADER_SLOT = 0x1D0, 0x220
# Data entries of the resources the tests modify.
ENTRY_SETTINGS, ENTRY_RCDATA101, ENTRY_VERSION, ENTRY_MANIFEST = 0xA60, 0xA70, 0xA90, 0xAA0

SETTINGS_DATA = b"volume=7\r\nfullscreen=0\r\n"
RCDATA101_DATA = b"binspect-rcdata-fixture-payload-0123456789\0"


def u16(value):
    return struct.pack("<H", value)


def u32(*values):
    return struct.pack("<%dI" % len(values), *values)


def patched(edits, name="resdemo.exe") -> bytes:
    data = bytearray(fixture_bytes(name))
    for offset, value in edits.items():
        data[offset:offset + len(value)] = value
    return bytes(data)


def listing(data: bytes):
    return resources.list_resources(binspect.load_bytes(data))


def without(*dropped):
    return [r for r in ALL if r not in dropped]


@contextmanager
def time_limit(seconds):
    """Turn an endless loop into a test failure instead of a hung test run."""
    if not hasattr(signal, "setitimer"):
        yield
        return

    def expired(signum, frame):
        pytest.fail(f"did not finish within {seconds} s")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@pytest.fixture
def exe(tmp_path):
    path = tmp_path / "resdemo.exe"
    shutil.copyfile(fixture_path("resdemo.exe"), path)
    return path


def only_entries(directory):
    return sorted(p.name for p in directory.iterdir())


# --- listing ----------------------------------------------------------------

def test_lists_every_resource_in_tree_order(load_fixture):
    assert resources.list_resources(load_fixture("resdemo.exe")) == ALL


def test_resource_fields_are_plain_values(load_fixture):
    r = resources.list_resources(load_fixture("resdemo.exe"))[6]
    assert (r.type, r.name, r.language, r.offset, r.size, r.codepage) == \
        ("RCDATA", "SETTINGS", 1033, 0xD90, 24, 0)


@pytest.mark.parametrize("name", ["hello_elf64", "libsample.so", "bare_arm64"])
def test_elf_files_have_no_resources(load_fixture, name):
    assert resources.list_resources(load_fixture(name)) == []


@pytest.mark.parametrize("name", ["hello_pe64.exe", "hello_pe32.exe", "sample.dll"])
def test_pe_without_a_resource_directory_has_no_resources(load_fixture, name):
    b = load_fixture(name)
    assert resources.list_resources(b) == []
    assert b.warnings == []


def test_listing_a_clean_file_adds_no_warnings(load_fixture):
    b = load_fixture("resdemo.exe")
    resources.list_resources(b)
    assert b.warnings == []


# RT_* constants from winuser.h (the same table as pefile.RESOURCE_TYPE).
@pytest.mark.parametrize("type_id, label", [
    (1, "CURSOR"), (2, "BITMAP"), (3, "ICON"), (4, "MENU"), (5, "DIALOG"),
    (6, "STRING"), (7, "FONTDIR"), (8, "FONT"), (9, "ACCELERATOR"), (10, "RCDATA"),
    (11, "MESSAGETABLE"), (12, "GROUP_CURSOR"), (14, "GROUP_ICON"), (16, "VERSION"),
    (17, "DLGINCLUDE"), (19, "PLUGPLAY"), (20, "VXD"), (21, "ANICURSOR"),
    (22, "ANIICON"), (23, "HTML"), (24, "MANIFEST"),
    (0, "#0"), (13, "#13"), (15, "#15"), (18, "#18"), (25, "#25"), (240, "#240"),
    (4660, "#4660"),
])
def test_well_known_type_ids_get_their_standard_names(type_id, label):
    # 0x840: the type ID of the last root entry (MANIFEST, 24).
    found = listing(patched({0x840: u32(type_id)}))
    assert found[-1] == Resource(label, "#1", 1033, 0x1088, 456, 0)
    assert found[:-1] == ALL[:-1]


def test_codepage_comes_from_the_data_entry():
    found = listing(patched({ENTRY_RCDATA101 + 8: u32(1252)}))
    assert found[7] == Resource("RCDATA", "#101", 1033, 0xD60, 43, 1252)


# --- reading ----------------------------------------------------------------

def test_read_resource_returns_the_raw_bytes(load_fixture):
    b = load_fixture("resdemo.exe")
    assert resources.read_resource(b, RCDATA101) == RCDATA101_DATA
    assert resources.read_resource(b, SETTINGS) == SETTINGS_DATA
    assert resources.read_resource(b, LEVELDATA) == bytes.fromhex("4C564C31 02010403 08070605")
    assert resources.read_resource(b, GROUP) == bytes.fromhex(
        "00000100 02001010 10000100 04002801 00000100 20200200 01000100 30010000 0200")


def test_manifest_is_the_file_named_in_the_rc_script(load_fixture):
    data = resources.read_resource(load_fixture("resdemo.exe"), MANIFEST)
    assert data == (SRC / "resdemo.manifest").read_bytes()
    assert hashlib.sha256(data).hexdigest() == \
        "441e6af1761644ba38bd69d460a8e5cc9c08e5ff8c19d999a8738da735385aa7"


@pytest.mark.parametrize("resource, digest", [
    (ICON1, "a231fe83d9410e36b027001ecaddc3edeceffa120e1e8ac049f884748775f549"),
    (ICON2, "db95a54e2aa380701a9f9e80612001f3319dd162f1b0f8a89b46e94076ed3710"),
    (STRING_DE, "68400d8fe8577894e7f7521a8955773f45f958222055fd8a0c65c61e0d6ec20d"),
    (STRING_EN, "902558fca24cf0fb1aefbb4754827933f006e8cb75b84e5a149688e5a066fa33"),
    (STRING2, "a382c9a12a4fcd1080f8361f5ee87844e864283a26a604f044ed959219c0ce41"),
    (VERSION, "d9eba95e4191ec1e54ee30065c85ea9a3c1b2d0b61ffd0383663b8b283ff48a0"),
])
def test_resource_data_matches_pefile(load_fixture, resource, digest):
    data = resources.read_resource(load_fixture("resdemo.exe"), resource)
    assert len(data) == resource.size
    assert hashlib.sha256(data).hexdigest() == digest


def test_string_table_block_holds_length_prefixed_utf16(load_fixture):
    data = resources.read_resource(load_fixture("resdemo.exe"), STRING_DE)
    # Block #1 holds string IDs 0..15: ID 0 is empty, ID 1 has 34 characters.
    assert data[:4] == b"\x00\x00\x22\x00"
    assert data[4:4 + 68].decode("utf-16-le") == "Hallo aus der Zeichenfolgentabelle"


@pytest.mark.parametrize("offset, size", [(0x1800, 1), (0x17FF, 2), (-1, 1), (1 << 40, 4)])
def test_reading_a_resource_outside_the_file_is_a_parse_error(load_fixture, offset, size):
    bogus = Resource("RCDATA", "#1", 1033, offset, size, 0)
    with pytest.raises(ParseError):
        resources.read_resource(load_fixture("resdemo.exe"), bogus)


# --- version information ----------------------------------------------------

def test_version_info_returns_the_string_file_info_pairs(load_fixture):
    assert resources.version_info(load_fixture("resdemo.exe")) == {
        "CompanyName": "Binspect Fixtures",
        "FileDescription": "Resource demo fixture",
        "FileVersion": "1.2.3.4",
        "InternalName": "resdemo",
        "LegalCopyright": "Public domain",
        "OriginalFilename": "resdemo.exe",
        "ProductName": "Binspect Resource Demo",
        "ProductVersion": "1.2",
    }


@pytest.mark.parametrize("name", ["hello_pe64.exe", "hello_elf64", "sample.dll"])
def test_version_info_is_empty_without_a_version_resource(load_fixture, name):
    assert resources.version_info(load_fixture(name)) == {}


def test_version_info_is_empty_when_the_version_resource_is_removed():
    # Retype the VERSION entry of the root directory (0x838) as RCDATA.
    b = binspect.load_bytes(patched({0x838: u32(10)}))
    assert resources.version_info(b) == {}


def test_version_string_with_empty_value_is_reported_as_empty():
    # "ProductVersion" node at resource offset 0x260: wLength 0x2C, wValueLength 4.
    # Declare that the node has no value.
    b = binspect.load_bytes(patched({0xDB8 + 0x262: u16(0)}))
    info = resources.version_info(b)
    assert info["ProductVersion"] == ""
    assert info["ProductName"] == "Binspect Resource Demo"


def test_version_value_is_cut_at_its_terminator_whatever_the_declared_length():
    # "FileVersion" node at resource offset 0x130: text "1.2.3.4" at 0x150.
    # Old resource compilers store a byte count (16) instead of a character count (8).
    b = binspect.load_bytes(patched({0xDB8 + 0x132: u16(16)}))
    assert resources.version_info(b)["FileVersion"] == "1.2.3.4"


@pytest.mark.parametrize("edits", [
    {0xDB8: u16(0)},                    # root node claims zero length
    {0xDB8: u16(0xFFFF)},               # root node longer than the resource
    {0xDB8 + 0x5C: u16(0)},             # StringFileInfo with zero length
    {0xDB8 + 0x5C: u16(3)},             # shorter than its own header
    {0xDB8 + 0x80: u16(0xFFFF)},        # string table longer than its parent
    {0xDB8 + 0x98: u16(0)},             # first string with zero length
    {0xDB8 + 0x98: u16(0xFFFF)},
    {ENTRY_VERSION + 4: u32(5)},        # resource truncated to 5 bytes
    {ENTRY_VERSION + 4: u32(0)},
    {ENTRY_VERSION + 4: u32(0x61)},     # cut in the middle of a key
])
def test_corrupt_version_resource_never_raises(edits):
    b = binspect.load_bytes(patched(edits))
    with time_limit(10):
        info = resources.version_info(b)
    assert isinstance(info, dict)
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in info.items())


def test_version_info_survives_any_single_corrupt_byte():
    original = fixture_bytes("resdemo.exe")
    with time_limit(60):
        for offset in range(0xDB8, 0xDB8 + 720):
            for value in (0x00, 0xFF):
                data = bytearray(original)
                data[offset] = value
                info = resources.version_info(binspect.load_bytes(bytes(data)))
                assert isinstance(info, dict)


# --- icons ------------------------------------------------------------------

def test_icon_file_rebuilds_the_ico_that_went_into_the_resource_compiler(load_fixture):
    ico = resources.icon_file(load_fixture("resdemo.exe"), GROUP)
    assert ico == (SRC / "resdemo.ico").read_bytes()
    assert hashlib.sha256(ico).hexdigest() == \
        "5772693f5907cdc02c9c04a91fe60006c9b0e043252fb7b114d605a374c2a642"


def test_icon_file_layout(load_fixture):
    b = load_fixture("resdemo.exe")
    ico = resources.icon_file(b, GROUP)
    assert len(ico) == 6 + 2 * 16 + 296 + 304
    assert ico[:6] == bytes.fromhex("0000 0100 0200")
    # width, height, colours, reserved, planes, bit count, size, offset of the image
    assert struct.unpack_from("<BBBBHHII", ico, 6) == (16, 16, 16, 0, 1, 4, 296, 38)
    assert struct.unpack_from("<BBBBHHII", ico, 22) == (32, 32, 2, 0, 1, 1, 304, 334)
    assert ico[38:334] == resources.read_resource(b, ICON1)
    assert ico[334:] == resources.read_resource(b, ICON2)


@pytest.mark.parametrize("resource", [ICON1, RCDATA101, VERSION])
def test_icon_file_needs_a_group_icon_resource(load_fixture, resource):
    with pytest.raises(UnsupportedError):
        resources.icon_file(load_fixture("resdemo.exe"), resource)


def test_icon_group_entry_without_its_image_is_left_out():
    # The first group entry's icon ID (0xD38 + 6 + 12) points at ICON #9.
    b = binspect.load_bytes(patched({0xD4A: u16(9)}))
    ico = resources.icon_file(b, GROUP)
    assert ico[:6] == bytes.fromhex("0000 0100 0100")
    assert struct.unpack_from("<BBBBHHII", ico, 6) == (32, 32, 2, 0, 1, 1, 304, 22)
    assert hashlib.sha256(ico[22:]).hexdigest() == \
        "db95a54e2aa380701a9f9e80612001f3319dd162f1b0f8a89b46e94076ed3710"


def test_icon_group_without_any_image_is_a_parse_error():
    b = binspect.load_bytes(patched({0xD4A: u16(9), 0xD58: u16(8)}))
    with pytest.raises(ParseError):
        resources.icon_file(b, GROUP)


def test_icon_directory_uses_the_real_size_of_each_image():
    # The group claims 0x99999 bytes for the first image; the ICON resource has 296.
    b = binspect.load_bytes(patched({0xD38 + 6 + 8: u32(0x99999)}))
    assert resources.icon_file(b, GROUP) == (SRC / "resdemo.ico").read_bytes()


@pytest.mark.parametrize("edits", [
    {0xD3C: u16(0xFFFF)},               # 65535 images claimed, data for two
    {0xD3C: u16(0)},                    # no images
    {0xD3A: u16(2)},                    # a cursor group, not an icon group
    {0xA84: u32(3)},                    # group truncated inside its header
    {0xA84: u32(0)},
    {0xA84: u32(19)},                   # truncated inside the first entry
])
def test_corrupt_icon_group_gives_an_ico_or_a_binspect_error(edits):
    b = binspect.load_bytes(patched(edits))
    group = next(r for r in resources.list_resources(b) if r.type == "GROUP_ICON")
    with time_limit(10):
        try:
            ico = resources.icon_file(b, group)
        except BinspectError:
            return
    count = struct.unpack_from("<H", ico, 4)[0]
    assert 1 <= count <= 2 and ico[:4] == b"\0\0\1\0"


# --- hostile resource directories -------------------------------------------

def test_subdirectory_pointing_back_at_the_root_is_a_cycle_not_a_loop():
    # 0x81C: where the ICON entry of the root says its subdirectory is.
    b = binspect.load_bytes(patched({0x81C: u32(0x80000000)}))
    with time_limit(10):
        found = resources.list_resources(b)
    assert found == without(ICON1, ICON2)
    assert any("cycle" in w for w in b.warnings)


def test_directory_that_contains_itself_is_skipped():
    # 0x874: subdirectory of ICON #1, pointed at the ICON type directory (0x60).
    with time_limit(10):
        assert listing(patched({0x874: u32(0x80000060)})) == without(ICON1)
    # 0x934: the language entry of ICON #1, pointed at its own directory (0x120).
    with time_limit(10):
        assert listing(patched({0x934: u32(0x80000120)})) == without(ICON1)


def test_tree_deeper_than_three_levels_is_not_followed():
    # The language entry of ICON #1 claims a fourth level (the STRING type directory).
    assert listing(patched({0x934: u32(0x80000080)})) == without(ICON1)


def test_data_entry_above_the_language_level_is_skipped():
    # The ICON type entry (level 1) and the ICON #1 name entry (level 2) point
    # straight at a data entry instead of a subdirectory.
    assert listing(patched({0x81C: u32(0x210)})) == without(ICON1, ICON2)
    assert listing(patched({0x874: u32(0x210)})) == without(ICON1)


@pytest.mark.parametrize("edits, dropped", [
    ({0x81C: u32(0xFFFFFFF0)}, (ICON1, ICON2)),     # subdirectory far outside the file
    ({0x81C: u32(0x80000BF8)}, (ICON1, ICON2)),     # subdirectory cut by the section end
    ({0x81C: u32(0x80000C00)}, (ICON1, ICON2)),     # subdirectory in the next section
    ({0x934: u32(0x7FFFFFF0)}, (ICON1,)),           # data entry far outside the file
    ({0x934: u32(0xBF8)}, (ICON1,)),                # data entry cut by the section end
    ({0xA10: u32(0x7FFF0000)}, (ICON1,)),           # data RVA outside the image
    ({0xA14: u32(0x7FFFFFFF)}, (ICON1,)),           # data larger than the file
    ({0xA14: u32(0x921)}, (ICON1,)),                # data one byte past the section
    ({0x810: u32(0xFFFFFFF0)}, (LEVELDATA,)),       # type name string outside the file
    ({0xAC2: u16(0xFFFF)}, (LEVELDATA,)),           # type name longer than the section
])
def test_out_of_range_offsets_cost_only_the_entries_they_break(edits, dropped):
    b = binspect.load_bytes(patched(edits))
    assert resources.list_resources(b) == without(*dropped)
    assert any("resource" in w for w in b.warnings)


def test_data_in_the_headers_is_file_backed_and_listed():
    # RVA 0 is the DOS header, which the loader maps like any other page.
    found = listing(patched({0xA10: u32(0)}))
    assert found == [Resource("ICON", "#1", 1033, 0, 296, 0) if r == ICON1 else r
                     for r in ALL]


def test_data_ending_exactly_at_the_section_end_is_accepted():
    # ICON #1 data starts at 0xAE0; the section's file data ends at 0x1400.
    found = listing(patched({0xA14: u32(0x920)}))
    assert found[1] == Resource("ICON", "#1", 1033, 0xAE0, 0x920, 0)


def test_named_entries_read_their_utf16_names():
    # Rename SETTINGS (length-prefixed UTF-16 at 0xAB0) to "SET".
    found = listing(patched({0xAB0: u16(3)}))
    assert found[6] == Resource("RCDATA", "SET", 1033, 0xD90, 24, 0)


def test_absurd_entry_count_stops_at_the_end_of_the_data():
    for edits in ({0x80E: u16(0xFFFF)}, {0x80C: u16(0xFFFF), 0x80E: u16(0xFFFF)}):
        b = binspect.load_bytes(patched(edits))
        with time_limit(10):
            found = resources.list_resources(b)
        assert found[:11] == ALL                    # the genuine entries come first
        assert len(found) < 100
        for r in found:
            assert len(resources.read_resource(b, r)) == r.size


def test_absurd_count_in_a_language_directory():
    # ICON #1 language directory (0x920): 65535 ID entries.
    b = binspect.load_bytes(patched({0x92E: u16(0xFFFF)}))
    with time_limit(10):
        found = resources.list_resources(b)
    assert [r for r in found if r in ALL] == ALL
    for r in found:
        assert len(resources.read_resource(b, r)) == r.size


@pytest.mark.parametrize("entry", [
    u32(0x7FFF0000, 0xB80), u32(0x5000, 0xB80), u32(0xFFFFFFFF, 0xFFFFFFFF),
    u32(0x3FFC, 0xB80),         # in the section's memory range but not in the file
    u32(0x3BF8, 0xB80),         # 8 bytes before the end: no room for a directory
])
def test_resource_directory_outside_the_image_gives_an_empty_list(entry):
    b = binspect.load_bytes(patched({RESOURCE_DIR: entry}))
    assert resources.list_resources(b) == []
    assert any("resource" in w for w in b.warnings)
    assert resources.version_info(b) == {}


def test_warnings_are_not_duplicated_by_listing_twice():
    b = binspect.load_bytes(patched({0x81C: u32(0xFFFFFFF0)}))
    resources.list_resources(b)
    first = list(b.warnings)
    resources.list_resources(b)
    resources.version_info(b)
    assert b.warnings == first and len(first) >= 1


def fan_out_image() -> bytes:
    """A hostile image whose resource tree is three directories of 65535
    entries each, every entry pointing at the same next directory: 65535**3
    (2.8e14) paths to a single data entry."""
    count = 0xFFFF
    table = 16 + 8 * count

    def directory(target):
        return bytes(14) + u16(count) + u32(1, target) * count

    blob = (directory(0x80000000 | table) + directory(0x80000000 | 2 * table)
            + directory(3 * table)
            + u32(0x3000 + 3 * table + 16, 4, 0, 0) + b"DATA")
    blob += bytes(-len(blob) % 0x200)
    # Move .rsrc to the end of the file: VirtualSize, (RVA), raw size, raw pointer.
    return patched({
        RSRC_HEADER + 8: u32(len(blob)), RSRC_HEADER + 16: u32(len(blob), 0x1800),
        RESOURCE_DIR: u32(0x3000, len(blob)),
    }) + blob


def test_exponential_fan_out_is_cut_off():
    b = binspect.load_bytes(fan_out_image())
    with time_limit(30):
        found = resources.list_resources(b)
    assert 1 <= len(found) <= 65536
    assert found[0] == Resource("CURSOR", "#1", 1, 0x1800 + 3 * (16 + 8 * 0xFFFF) + 16, 4, 0)
    assert resources.read_resource(b, found[0]) == b"DATA"
    assert any("resource" in w for w in b.warnings)
    with time_limit(30):
        assert resources.version_info(b) == {}


def test_any_single_corrupt_byte_in_the_directory_is_survived():
    original = fixture_bytes("resdemo.exe")
    with time_limit(120):
        for offset in range(0x800, 0xAE0):
            for value in (0x00, 0x80, 0xFF):
                data = bytearray(original)
                if data[offset] == value:
                    continue
                data[offset] = value
                b = binspect.load_bytes(bytes(data))
                found = resources.list_resources(b)     # must not raise
                assert len(found) <= 5000
                for r in found:
                    assert 0 <= r.offset and r.offset + r.size <= len(data)
                resources.version_info(b)


def test_truncated_files_are_survived():
    original = fixture_bytes("resdemo.exe")
    with time_limit(60):
        for size in list(range(0x400, 0x1800, 0x37)) + [0x800, 0x810, 0xA00, 0xA08, 0xAE0]:
            b = binspect.load_bytes(original[:size])
            found = resources.list_resources(b)
            assert all(r in ALL for r in found)
            for r in found:
                assert r.offset + r.size <= size
            assert isinstance(resources.version_info(b), dict)
    # The German string table ends at 0x137C; everything else ends before 0x1318.
    assert listing(original[:0x1370]) == without(STRING_DE)


# --- replace_resource: rewriting in place ------------------------------------

def test_smaller_data_is_rewritten_in_place(exe, tmp_path):
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(exe, out, RCDATA101, b"patched!")
    assert updated == Resource("RCDATA", "#101", 1033, 0xD60, 8, 0)

    expected = bytearray(fixture_bytes("resdemo.exe"))
    expected[0xD60:0xD60 + 43] = b"patched!" + bytes(35)        # slack is zeroed
    expected[ENTRY_RCDATA101 + 4:ENTRY_RCDATA101 + 8] = u32(8)  # Size of the data entry
    assert out.read_bytes() == bytes(expected)

    b = binspect.load(out)
    assert b.warnings == []
    found = resources.list_resources(b)
    assert found == [updated if r == RCDATA101 else r for r in ALL]
    assert resources.read_resource(b, updated) == b"patched!"
    assert exe.read_bytes() == fixture_bytes("resdemo.exe")     # source untouched
    assert only_entries(tmp_path) == ["out.exe", "resdemo.exe"]


def test_data_of_the_same_size_changes_nothing_else(exe, tmp_path):
    out = tmp_path / "out.exe"
    new = b"VOLUME=9\r\nFULLSCREEN=1\r\n"
    updated = resources.replace_resource(exe, out, SETTINGS, new)
    assert updated == SETTINGS
    expected = bytearray(fixture_bytes("resdemo.exe"))
    expected[0xD90:0xD90 + 24] = new
    assert out.read_bytes() == bytes(expected)


def test_resource_can_be_emptied(exe, tmp_path):
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(exe, out, SETTINGS, b"")
    assert updated == Resource("RCDATA", "SETTINGS", 1033, 0xD90, 0, 0)
    b = binspect.load(out)
    assert resources.read_resource(b, resources.list_resources(b)[6]) == b""
    assert out.read_bytes()[0xD90:0xD90 + 24] == bytes(24)


def test_version_info_can_be_edited_in_place(exe, tmp_path):
    out = tmp_path / "out.exe"
    data = bytearray(resources.read_resource(binspect.load(exe), VERSION))
    old = "Binspect Fixtures".encode("utf-16-le")
    assert data.count(old) == 1
    data = bytes(data).replace(old, "Modded by a user!".encode("utf-16-le"))
    resources.replace_resource(exe, out, VERSION, data)
    info = resources.version_info(binspect.load(out))
    assert info["CompanyName"] == "Modded by a user!"
    assert info["ProductName"] == "Binspect Resource Demo"


def test_stale_offsets_in_the_resource_argument_do_not_matter(exe, tmp_path):
    out = tmp_path / "out.exe"
    stale = Resource("RCDATA", "#101", 1033, 0x9999, 7, 0)
    updated = resources.replace_resource(exe, out, stale, b"patched!")
    assert updated == Resource("RCDATA", "#101", 1033, 0xD60, 8, 0)


def test_one_language_of_a_resource_is_replaced_without_touching_the_other(exe, tmp_path):
    out = tmp_path / "out.exe"
    new = b"\0\0\2\0H\0i\0" + bytes(28)
    resources.replace_resource(exe, out, STRING_DE, new)
    b = binspect.load(out)
    found = resources.list_resources(b)
    assert found[3] == Resource("STRING", "#1", 1031, 0x1318, 36, 0)
    assert found[4] == STRING_EN
    assert hashlib.sha256(resources.read_resource(b, found[4])).hexdigest() == \
        "902558fca24cf0fb1aefbb4754827933f006e8cb75b84e5a149688e5a066fa33"


# --- replace_resource: relocating into the section's padding ------------------

def test_larger_data_moves_into_the_padding_of_the_resource_section(exe, tmp_path):
    out = tmp_path / "out.exe"
    new = bytes(range(100))
    updated = resources.replace_resource(exe, out, SETTINGS, new)
    # .rsrc: file offset 0x800, RVA 0x3000, 0xB80 bytes used of 0xC00.
    assert updated == Resource("RCDATA", "SETTINGS", 1033, 0x1380, 100, 0)

    expected = bytearray(fixture_bytes("resdemo.exe"))
    expected[0x1380:0x1380 + 100] = new
    expected[ENTRY_SETTINGS:ENTRY_SETTINGS + 8] = u32(0x3B80, 100)      # RVA, Size
    expected[0xD90:0xD90 + 24] = bytes(24)                              # old copy erased
    expected[RSRC_HEADER + 8:RSRC_HEADER + 12] = u32(0xBE4)             # VirtualSize
    expected[RESOURCE_DIR + 4:RESOURCE_DIR + 8] = u32(0xBE4)            # directory size
    assert out.read_bytes() == bytes(expected)

    b = binspect.load(out)
    assert b.warnings == []
    assert [(s.name, s.vaddr, s.vsize, s.offset, s.size) for s in b.sections] == [
        (".text", 0x140001000, 0x16, 0x400, 0x200),
        (".rdata", 0x140002000, 0x93, 0x600, 0x200),
        (".rsrc", 0x140003000, 0xBE4, 0x800, 0xC00),
        (".reloc", 0x140004000, 0xC, 0x1400, 0x200),
    ]
    found = resources.list_resources(b)
    assert found == [updated if r == SETTINGS else r for r in ALL]
    assert resources.read_resource(b, updated) == new


def test_padding_is_used_up_to_its_last_byte(exe, tmp_path):
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(exe, out, SETTINGS, b"\x5A" * 128)
    assert (updated.offset, updated.size) == (0x1380, 128)
    data = out.read_bytes()
    assert len(data) == 0x1800
    assert data[NUM_SECTIONS:NUM_SECTIONS + 2] == u16(4)
    assert data[RSRC_HEADER + 8:RSRC_HEADER + 12] == u32(0xC00)
    assert binspect.load(out).warnings == []


def test_second_relocation_goes_after_the_first_one(exe, tmp_path):
    out = tmp_path / "out.exe"
    resources.replace_resource(exe, out, SETTINGS, b"\x11" * 50)
    # 0xB80 + 50 = 0xBB2, rounded up to 8 -> 0xBB8.
    updated = resources.replace_resource(out, out, LEVELDATA, b"\x22" * 60)
    assert (updated.offset, updated.size) == (0x800 + 0xBB8, 60)
    data = out.read_bytes()
    assert data[0x1380:0x1380 + 50] == b"\x11" * 50
    assert data[0x13B8:0x13B8 + 60] == b"\x22" * 60
    assert data[RSRC_HEADER + 8:RSRC_HEADER + 12] == u32(0xBB8 + 60)
    b = binspect.load(out)
    found = resources.list_resources(b)
    assert resources.read_resource(b, found[6]) == b"\x11" * 50
    assert resources.read_resource(b, found[0]) == b"\x22" * 60


def test_padding_that_is_not_empty_is_not_reused(tmp_path):
    # Something already lives in the slack space after the resources.
    src = tmp_path / "in.exe"
    src.write_bytes(patched({0x13F0: b"hidden"}))
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(src, out, SETTINGS, bytes(100))
    data = out.read_bytes()
    assert data[0x13F0:0x13F6] == b"hidden"
    assert updated.offset == 0x1600                     # went to a new section instead
    assert data[NUM_SECTIONS:NUM_SECTIONS + 2] == u16(5)


def test_resource_sharing_its_bytes_with_another_is_not_rewritten_in_place(tmp_path):
    # RCDATA #101 now points at the same bytes as RCDATA SETTINGS.
    src = tmp_path / "in.exe"
    src.write_bytes(patched({ENTRY_RCDATA101: u32(0x3590, 24)}))
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(src, out, SETTINGS, b"x")
    assert (updated.offset, updated.size) == (0x1380, 1)
    b = binspect.load(out)
    found = resources.list_resources(b)
    assert found[7] == Resource("RCDATA", "#101", 1033, 0xD90, 24, 0)
    assert resources.read_resource(b, found[7]) == SETTINGS_DATA    # still intact
    assert resources.read_resource(b, found[6]) == b"x"


def test_emptying_a_resource_that_shares_its_bytes_leaves_the_bytes_alone(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes(patched({ENTRY_RCDATA101: u32(0x3590, 24)}))
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(src, out, SETTINGS, b"")
    assert (updated.offset, updated.size) == (0xD90, 0)
    data = out.read_bytes()
    assert data[0xD90:0xD90 + 24] == SETTINGS_DATA
    assert data[ENTRY_RCDATA101:ENTRY_RCDATA101 + 8] == u32(0x3590, 24)
    assert len(data) == 0x1800 and data[RSRC_HEADER + 8:RSRC_HEADER + 12] == u32(0xB80)


# --- replace_resource: relocating into a new section --------------------------

NEW_MANIFEST = b"<assembly>" + bytes(range(256)) * 7 + b"</assembly>" + b"\n" * 187
assert len(NEW_MANIFEST) == 2000


def test_data_too_large_for_the_padding_goes_into_a_new_section(exe, tmp_path):
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(exe, out, MANIFEST, NEW_MANIFEST)
    # The image ended at RVA 0x5000 and its sections at file offset 0x1600.
    assert updated == Resource("MANIFEST", "#1", 1033, 0x1600, 2000, 0)

    original = fixture_bytes("resdemo.exe")
    expected = bytearray(original)
    expected[NUM_SECTIONS:NUM_SECTIONS + 2] = u16(5)
    expected[SYMTAB_PTR:SYMTAB_PTR + 4] = u32(0x1E00)       # symbol table moved by 0x800
    expected[SIZE_OF_INIT_DATA:SIZE_OF_INIT_DATA + 4] = u32(0x1000 + 0x800)
    expected[SIZE_OF_IMAGE:SIZE_OF_IMAGE + 4] = u32(0x6000)
    expected[FREE_HEADER_SLOT:FREE_HEADER_SLOT + 40] = (
        b".rsrc2\0\0"                 # VirtualSize, RVA, raw size, raw pointer, ...
        + u32(2000, 0x5000, 0x800, 0x1600, 0, 0, 0, 0x40000040))   # data, readable
    expected[ENTRY_MANIFEST:ENTRY_MANIFEST + 8] = u32(0x5000, 2000)
    expected[0x1088:0x1088 + 456] = bytes(456)              # old copy erased
    expected[0x1600:0x1600] = NEW_MANIFEST + bytes(48)      # raw data, file-aligned
    assert len(expected) == 0x2000
    assert out.read_bytes() == bytes(expected)
    assert out.read_bytes()[0x1E00:] == original[0x1600:]   # trailing data kept, moved


def test_image_with_a_new_section_still_loads_cleanly(exe, tmp_path):
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(exe, out, MANIFEST, NEW_MANIFEST)
    b = binspect.load(out)
    assert b.warnings == []
    assert [(s.name, s.vaddr, s.vsize, s.offset, s.size, s.perms) for s in b.sections] == [
        (".text", 0x140001000, 0x16, 0x400, 0x200, "r-x"),
        (".rdata", 0x140002000, 0x93, 0x600, 0x200, "r--"),
        (".rsrc", 0x140003000, 0xB80, 0x800, 0xC00, "r--"),
        (".reloc", 0x140004000, 0xC, 0x1400, 0x200, "r--"),
        (".rsrc2", 0x140005000, 2000, 0x1600, 0x800, "r--"),
    ]
    assert b.read(0x140005000, 2000) == NEW_MANIFEST
    found = resources.list_resources(b)
    assert found == [updated if r == MANIFEST else r for r in ALL]
    assert resources.read_resource(b, updated) == NEW_MANIFEST
    # The COFF symbols (llvm-readobj --symbols) are still found after the move.
    by_name = {s.name: s.address for s in b.symbols}
    assert by_name["entry"] == 0x140001000
    assert by_name["resdemo_table"] == 0x140002020
    assert len(b.symbols) == len(binspect.load(exe).symbols) > 0
    assert "overlay" not in b.metadata
    assert resources.version_info(b)["ProductName"] == "Binspect Resource Demo"


def test_one_byte_more_than_the_padding_needs_a_new_section(exe, tmp_path):
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(exe, out, SETTINGS, b"\x5A" * 129)
    assert (updated.offset, updated.size) == (0x1600, 129)
    data = out.read_bytes()
    assert len(data) == 0x1800 + 0x200
    assert data[NUM_SECTIONS:NUM_SECTIONS + 2] == u16(5)
    assert data[SIZE_OF_IMAGE:SIZE_OF_IMAGE + 4] == u32(0x6000)


def test_image_size_follows_the_section_alignment(exe, tmp_path):
    out = tmp_path / "out.exe"
    resources.replace_resource(exe, out, MANIFEST, bytes(0x1001))
    data = out.read_bytes()
    assert data[SIZE_OF_IMAGE:SIZE_OF_IMAGE + 4] == u32(0x7000)     # 0x5000 + 2 pages
    assert data[FREE_HEADER_SLOT + 8:FREE_HEADER_SLOT + 24] == \
        u32(0x1001, 0x5000, 0x1200, 0x1600)
    assert len(data) == 0x1800 + 0x1200
    assert binspect.load(out).warnings == []


def test_later_relocations_reuse_the_section_added_before(exe, tmp_path):
    out = tmp_path / "out.exe"
    resources.replace_resource(exe, out, MANIFEST, NEW_MANIFEST)
    new_version = bytes([7]) * 1500
    updated = resources.replace_resource(out, out, VERSION, new_version)
    # .rsrc2 held 2000 bytes; the new data follows at 0x5000 + 2000.
    assert updated == Resource("VERSION", "#1", 1033, 0x1600 + 2000, 1500, 0)
    data = out.read_bytes()
    assert data[NUM_SECTIONS:NUM_SECTIONS + 2] == u16(5)            # no sixth section
    assert data[FREE_HEADER_SLOT:FREE_HEADER_SLOT + 24] == \
        b".rsrc2\0\0" + u32(3500, 0x5000, 0xE00, 0x1600)
    assert data[FREE_HEADER_SLOT + 40:FREE_HEADER_SLOT + 80] == bytes(40)
    assert data[ENTRY_VERSION:ENTRY_VERSION + 8] == u32(0x57D0, 1500)
    assert data[SIZE_OF_IMAGE:SIZE_OF_IMAGE + 4] == u32(0x6000)
    assert data[SYMTAB_PTR:SYMTAB_PTR + 4] == u32(0x1600 + 0xE00)
    assert data[SIZE_OF_INIT_DATA:SIZE_OF_INIT_DATA + 4] == u32(0x1000 + 0xE00)
    assert len(data) == 0x1800 + 0xE00
    assert data[0x2400:] == fixture_bytes("resdemo.exe")[0x1600:]

    b = binspect.load(out)
    assert b.warnings == []
    found = resources.list_resources(b)
    assert resources.read_resource(b, found[9]) == new_version
    assert resources.read_resource(b, found[10]) == NEW_MANIFEST
    assert {s.name: s.address for s in b.symbols}["entry"] == 0x140001000


def test_image_without_trailing_data_just_grows(tmp_path):
    # Drop the COFF symbol table: the file then ends where its sections end.
    src = tmp_path / "in.exe"
    src.write_bytes(patched({SYMTAB_PTR: u32(0, 0)})[:0x1600])
    out = tmp_path / "out.exe"
    updated = resources.replace_resource(src, out, MANIFEST, NEW_MANIFEST)
    assert updated.offset == 0x1600
    data = out.read_bytes()
    assert len(data) == 0x1600 + 0x800
    assert data[SYMTAB_PTR:SYMTAB_PTR + 8] == u32(0, 0)
    assert data[0x1600:0x1600 + 2000] == NEW_MANIFEST
    assert binspect.load(out).warnings == []


def test_debug_data_behind_the_sections_is_still_found_after_it_moved(tmp_path):
    # A debug directory (data directory 6, at 0x130) with two entries in the slack
    # of .rdata (file 0x700 = RVA 0x2100). The first points at a CodeView record
    # in the trailing data (0x1740), the second into .rdata itself (0x680).
    codeview = b"RSDS" + bytes(range(16)) + u32(1) + b"C:\\mods\\resdemo.pdb\0"
    src = tmp_path / "in.exe"
    src.write_bytes(patched({
        0x130: u32(0x2100, 56),
        0x700: u32(0, 0, 0, 2, len(codeview), 0, 0x1740),
        0x71C: u32(0, 0, 0, 0, 16, 0x2080, 0x680),
        0x1740: codeview,
    }))
    assert binspect.load(src).metadata["pdb_path"] == "C:\\mods\\resdemo.pdb"
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, MANIFEST, NEW_MANIFEST)
    data = out.read_bytes()
    assert data[0x700 + 24:0x700 + 28] == u32(0x1740 + 0x800)      # moved with the data
    assert data[0x71C + 24:0x71C + 28] == u32(0x680)               # inside a section: stays
    assert data[0x1F40:0x1F40 + len(codeview)] == codeview
    b = binspect.load(out)
    assert b.warnings == []
    assert b.metadata["pdb_path"] == "C:\\mods\\resdemo.pdb"


def test_appended_payload_stays_at_the_end_of_the_file(tmp_path):
    # Installers and self-extracting archives keep a payload after the image.
    payload = b"PK-OVERLAY-PAYLOAD" * 40
    src = tmp_path / "in.exe"
    src.write_bytes(fixture_bytes("resdemo.exe") + payload)
    assert binspect.load(src).metadata["overlay"] == {"offset": 0x1800, "size": 720}
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, MANIFEST, NEW_MANIFEST)
    data = out.read_bytes()
    assert data.endswith(payload) and len(data) == 0x2000 + 720
    b = binspect.load(out)
    assert b.warnings == []
    assert b.metadata["overlay"] == {"offset": 0x2000, "size": 720}


@pytest.mark.parametrize("edits", [
    {FREE_HEADER_SLOT: b"\x01" * 40},           # the slot after the table is in use
    {FREE_HEADER_SLOT + 39: b"\x01"},
    {SIZE_OF_HEADERS: u32(0x220)},              # headers end right after the table
    {SIZE_OF_HEADERS: u32(0x247)},              # one byte short of a section header
])
def test_no_room_for_another_section_header_is_unsupported(tmp_path, edits):
    src = tmp_path / "in.exe"
    src.write_bytes(patched(edits))
    out = tmp_path / "out.exe"
    with pytest.raises(UnsupportedError):
        resources.replace_resource(src, out, MANIFEST, NEW_MANIFEST)
    assert not out.exists()
    assert only_entries(tmp_path) == ["in.exe"]
    # Data that fits where it is can still be replaced.
    resources.replace_resource(src, out, MANIFEST, b"<assembly/>")
    assert resources.read_resource(binspect.load(out), Resource(
        "MANIFEST", "#1", 1033, 0x1088, 11, 0)) == b"<assembly/>"


def test_header_slot_that_exactly_fits_is_used(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes(patched({SIZE_OF_HEADERS: u32(0x248)}))
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, MANIFEST, NEW_MANIFEST)
    assert out.read_bytes()[NUM_SECTIONS:NUM_SECTIONS + 2] == u16(5)


# --- replace_resource: signatures and checksums --------------------------------

# WIN_CERTIFICATE: dwLength 24, revision 2.0, PKCS#7 type, 16 bytes of payload.
FAKE_CERTIFICATE = u32(24) + u16(0x0200) + u16(0x0002) + b"SIGNATURE-BYTES!"


def signed_fixture() -> bytes:
    # The certificate directory holds a file offset (not an RVA) and a size.
    return patched({SECURITY_DIR: u32(0x1800, 24)}) + FAKE_CERTIFICATE


def test_fixture_with_a_certificate_counts_as_signed():
    assert binspect.load_bytes(signed_fixture()).security["signed"] is True


def test_signature_is_stripped_when_rewriting_in_place(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes(signed_fixture())
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, RCDATA101, b"patched!")

    expected = bytearray(fixture_bytes("resdemo.exe"))      # no certificate, no directory
    expected[0xD60:0xD60 + 43] = b"patched!" + bytes(35)
    expected[ENTRY_RCDATA101 + 4:ENTRY_RCDATA101 + 8] = u32(8)
    assert out.read_bytes() == bytes(expected)
    b = binspect.load(out)
    assert b.security["signed"] is False
    assert b.warnings == [] and "overlay" not in b.metadata


def test_signature_is_stripped_when_adding_a_section(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes(signed_fixture())
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, MANIFEST, NEW_MANIFEST)
    data = out.read_bytes()
    assert data[SECURITY_DIR:SECURITY_DIR + 8] == bytes(8)
    assert b"SIGNATURE-BYTES!" not in data
    assert len(data) == 0x2000
    b = binspect.load(out)
    assert b.security["signed"] is False and b.warnings == []


def test_signature_is_stripped_when_using_the_padding(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes(signed_fixture())
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, SETTINGS, bytes(100))
    data = out.read_bytes()
    assert data[SECURITY_DIR:SECURITY_DIR + 8] == bytes(8)
    assert len(data) == 0x1800


def test_certificate_followed_by_other_data_is_unlinked_but_not_cut_out(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes(signed_fixture() + b"MORE-PAYLOAD")
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, RCDATA101, b"patched!")
    data = out.read_bytes()
    assert data[SECURITY_DIR:SECURITY_DIR + 8] == bytes(8)
    assert data[0x1800:] == FAKE_CERTIFICATE + b"MORE-PAYLOAD"     # nothing moved
    assert binspect.load(out).security["signed"] is False


def test_certificate_directory_pointing_into_the_image_never_truncates_it(tmp_path):
    # A bogus certificate "table" in the middle of .text must not cost any bytes.
    src = tmp_path / "in.exe"
    src.write_bytes(patched({SECURITY_DIR: u32(0x400, 0x1400)}))
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, RCDATA101, b"patched!")
    data = out.read_bytes()
    assert len(data) == 0x1800
    assert data[0x400:0x600] == fixture_bytes("resdemo.exe")[0x400:0x600]
    assert data[SECURITY_DIR:SECURITY_DIR + 8] == bytes(8)


def test_zero_checksum_stays_zero(exe, tmp_path):
    out = tmp_path / "out.exe"
    resources.replace_resource(exe, out, RCDATA101, b"patched!")
    assert out.read_bytes()[CHECKSUM:CHECKSUM + 4] == u32(0)


def test_nonzero_checksum_is_recomputed(tmp_path):
    # pefile.generate_checksum(): 0x6601 for the fixture, 0x9E1B for the expected
    # output of this in-place replacement (built by hand, not by binspect).
    src = tmp_path / "in.exe"
    src.write_bytes(patched({CHECKSUM: u32(0x6601)}))
    out = tmp_path / "out.exe"
    resources.replace_resource(src, out, RCDATA101, b"patched!")
    assert out.read_bytes()[CHECKSUM:CHECKSUM + 4] == u32(0x9E1B)


# --- replace_resource: refusals, backups, atomic writes ------------------------

def test_unknown_resource_is_a_location_error_and_writes_nothing(exe, tmp_path):
    out = tmp_path / "out.exe"
    for missing in (Resource("RCDATA", "#102", 1033, 0xD60, 43, 0),
                    Resource("RCDATA", "#101", 1031, 0xD60, 43, 0),
                    Resource("BITMAP", "#101", 1033, 0xD60, 43, 0),
                    Resource("RCDATA", "settings", 1033, 0xD90, 24, 0)):
        with pytest.raises(LocationError):
            resources.replace_resource(exe, out, missing, b"x")
    assert only_entries(tmp_path) == ["resdemo.exe"]


def test_files_without_resources_are_refused(tmp_path):
    out = tmp_path / "out"
    with pytest.raises(UnsupportedError):
        resources.replace_resource(fixture_path("hello_elf64"), out, RCDATA101, b"x")
    with pytest.raises(LocationError):
        resources.replace_resource(fixture_path("hello_pe64.exe"), out, RCDATA101, b"x")
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not an executable")
    with pytest.raises(BinspectError):
        resources.replace_resource(junk, out, RCDATA101, b"x")
    assert only_entries(tmp_path) == ["junk.bin"]


def test_replacement_that_would_wreck_the_image_is_refused(tmp_path):
    # ICON #1 claims the DOS and PE headers (RVA 0) as its data.
    src = tmp_path / "in.exe"
    src.write_bytes(patched({0xA10: u32(0)}))
    out = tmp_path / "out.exe"
    in_headers = Resource("ICON", "#1", 1033, 0, 296, 0)
    assert in_headers in resources.list_resources(binspect.load(src))
    with pytest.raises(ParseError):
        resources.replace_resource(src, out, in_headers, b"\xCC" * 296)
    assert only_entries(tmp_path) == ["in.exe"]


def test_replacing_in_the_same_file_keeps_the_original_as_bak(exe, tmp_path):
    resources.replace_resource(exe, exe, RCDATA101, b"patched!")
    resources.replace_resource(exe, exe, MANIFEST, NEW_MANIFEST)
    assert (tmp_path / "resdemo.exe.bak").read_bytes() == fixture_bytes("resdemo.exe")
    assert only_entries(tmp_path) == ["resdemo.exe", "resdemo.exe.bak"]
    b = binspect.load(exe)
    found = resources.list_resources(b)
    assert resources.read_resource(b, found[7]) == b"patched!"
    assert resources.read_resource(b, found[10]) == NEW_MANIFEST


def test_crash_while_writing_leaves_the_destination_untouched(exe, tmp_path, monkeypatch):
    out = tmp_path / "out.exe"
    out.write_bytes(b"previous content")

    def boom(src, dst, *args, **kwargs):
        raise OSError("simulated crash")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="simulated crash"):
        resources.replace_resource(exe, out, MANIFEST, NEW_MANIFEST)
    assert out.read_bytes() == b"previous content"
    assert only_entries(tmp_path) == ["out.exe", "resdemo.exe"]


def test_new_data_may_be_a_bytearray(exe, tmp_path):
    out = tmp_path / "out.exe"
    resources.replace_resource(str(exe), str(out), RCDATA101, bytearray(b"patched!"))
    assert out.read_bytes()[0xD60:0xD68] == b"patched!"


def test_replaced_icon_image_shows_up_in_the_rebuilt_ico(exe, tmp_path):
    out = tmp_path / "out.exe"
    b = binspect.load(exe)
    image = bytearray(resources.read_resource(b, ICON1))
    image[0x68:0x70] = b"\xFF" * 8              # repaint the bottom row of pixels
    resources.replace_resource(exe, out, ICON1, bytes(image))
    ico = resources.icon_file(binspect.load(out), GROUP)
    assert ico[38:334] == bytes(image)
    assert ico[:38] == (SRC / "resdemo.ico").read_bytes()[:38]
    assert ico[334:] == (SRC / "resdemo.ico").read_bytes()[334:]
