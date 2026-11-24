"""The practice file for `vex split`: examples/split_sample/bundle_pe64.exe.

The bundle is the hello_pe64.exe fixture with a PNG, a WAV and a ZIP appended
back to back. The offsets and sizes below are literals worked out from the
layout the generator documents; each attached file is then checked with a
reader that has nothing to do with vex (a chunk walk with zlib for the PNG,
the standard library's wave and zipfile for the other two).
"""
import io
import runpy
import struct
import wave
import zipfile
import zlib
from pathlib import Path

import pytest

import vex
from conftest import fixture_bytes

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SCRIPT = EXAMPLES / "make_split_sample.py"
SAMPLE = EXAMPLES / "split_sample"
BUNDLE = SAMPLE / "bundle_pe64.exe"

STUB_SIZE = 3072                        # tests/fixtures/bin/hello_pe64.exe

# 32x32 RGB picture, pixel data stored uncompressed:
#   signature 8 + IHDR (12 + 13) + IDAT (12 + 3115) + IEND 12 = 3172
#   IDAT data = zlib header 2 + stored-block header 5 + 32 * (1 + 96) + adler 4
PNG_OFFSET, PNG_SIZE = 3072, 3172
PNG_RAW_SIZE = 32 * (1 + 32 * 3)        # one filter byte per row, 3 bytes per pixel

# 2000 frames of 8-bit mono at 8000 Hz: 44-byte header + 2000 bytes of sound
WAV_OFFSET, WAV_SIZE = 6244, 2044
WAV_FRAMES, WAV_RATE = 2000, 8000

# one stored 141-byte text file called readme.txt (10-byte name):
#   local header 30 + 10, data 141, central entry 46 + 10, end record 22 = 259
ZIP_OFFSET, ZIP_SIZE = 8288, 259

BUNDLE_SIZE = 8547                      # 3072 + 3172 + 2044 + 259


@pytest.fixture(scope="module")
def bundle() -> bytes:
    return BUNDLE.read_bytes()


def piece(data: bytes, offset: int, size: int) -> bytes:
    assert offset + size <= len(data)
    return data[offset:offset + size]


# --- the committed file ------------------------------------------------------

def test_regenerating_reproduces_the_committed_files(tmp_path):
    build = runpy.run_path(str(SCRIPT))["build"]
    build(tmp_path / "first")
    build(tmp_path / "second")
    for name in ("bundle_pe64.exe", "README.txt"):
        first = (tmp_path / "first" / name).read_bytes()
        assert first == (tmp_path / "second" / name).read_bytes()
        assert first == (SAMPLE / name).read_bytes()
    assert sorted(p.name for p in (tmp_path / "first").iterdir()) == [
        "README.txt", "bundle_pe64.exe"]


def test_bundle_starts_with_the_unmodified_fixture(bundle):
    stub = fixture_bytes("hello_pe64.exe")
    assert len(stub) == STUB_SIZE
    assert bundle[:STUB_SIZE] == stub


def test_attached_files_are_back_to_back_and_fill_the_rest(bundle):
    assert len(bundle) == BUNDLE_SIZE
    assert PNG_OFFSET == STUB_SIZE
    assert WAV_OFFSET == PNG_OFFSET + PNG_SIZE
    assert ZIP_OFFSET == WAV_OFFSET + WAV_SIZE
    assert BUNDLE_SIZE == ZIP_OFFSET + ZIP_SIZE


def test_readme_is_plain_ascii_text():
    text = (SAMPLE / "README.txt").read_bytes()
    assert all(byte == 0x0A or 0x20 <= byte < 0x7F for byte in text)   # no \r, no tabs
    assert text.endswith(b"\n")
    assert b"vex split bundle_pe64.exe" in text


# --- the three attached files, each checked without vex ------------------------

def test_png_is_valid(bundle):
    data = piece(bundle, PNG_OFFSET, PNG_SIZE)
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    chunks = []
    pos = 8
    while pos < len(data):
        length, kind = struct.unpack_from(">I4s", data, pos)
        body = data[pos + 8:pos + 8 + length]
        assert len(body) == length
        (crc,) = struct.unpack_from(">I", data, pos + 8 + length)
        assert crc == zlib.crc32(kind + body), kind
        chunks.append((kind, body))
        pos += 12 + length
    assert pos == PNG_SIZE                                  # IEND ends exactly at the WAV
    assert [kind for kind, _ in chunks] == [b"IHDR", b"IDAT", b"IEND"]
    # 32x32, 8 bits per channel, colour type 2 (RGB), no interlace
    assert chunks[0][1] == struct.pack(">IIBBBBB", 32, 32, 8, 2, 0, 0, 0)
    assert chunks[2][1] == b""
    raw = zlib.decompress(chunks[1][1])
    assert len(raw) == PNG_RAW_SIZE
    assert all(raw[row * 97] == 0 for row in range(32))     # filter type 0 on every row
    assert len(set(raw[1 + row * 97:(row + 1) * 97] for row in range(32))) == 2   # a pattern


def test_wav_is_valid(bundle):
    data = piece(bundle, WAV_OFFSET, WAV_SIZE)
    assert data[:4] == b"RIFF" and data[8:12] == b"WAVE"
    assert struct.unpack_from("<I", data, 4)[0] == WAV_SIZE - 8
    with wave.open(io.BytesIO(data), "rb") as sound:
        assert sound.getnchannels() == 1
        assert sound.getsampwidth() == 1
        assert sound.getframerate() == WAV_RATE
        assert sound.getnframes() == WAV_FRAMES
        assert sound.getcomptype() == "NONE"
        frames = sound.readframes(WAV_FRAMES)
    assert len(frames) == WAV_FRAMES
    assert min(frames) < 128 < max(frames)                  # an audible tone, not silence
    assert frames[:20] * (WAV_FRAMES // 20) == frames       # 20-frame period = 400 Hz


def test_zip_is_valid(bundle):
    data = piece(bundle, ZIP_OFFSET, ZIP_SIZE)
    assert data[:4] == b"PK\x03\x04"
    with zipfile.ZipFile(io.BytesIO(data)) as pack:
        assert pack.testzip() is None
        (info,) = pack.infolist()
        assert info.filename == "readme.txt"
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.date_time == (2024, 1, 1, 0, 0, 0)
        assert info.header_offset == 0                      # offsets are relative to the zip
        text = pack.read("readme.txt")
    assert len(text) == 141
    assert text.startswith(b"This text file sits inside a ZIP archive")
    # stored, so the text is readable in place: after the 30-byte header and 10-byte name
    assert piece(bundle, ZIP_OFFSET + 40, 141) == text
    # the end record is the last 22 bytes of the bundle and has no comment
    assert data[-22:-18] == b"PK\x05\x06" and data[-2:] == b"\x00\x00"


def test_no_other_file_signatures_in_the_bundle(bundle):
    """Each signature shows up exactly where a file was put, so a scan finds three files."""
    def places(signature):
        found, at = [], bundle.find(signature)
        while at >= 0:
            found.append(at)
            at = bundle.find(signature, at + 1)
        return found

    assert places(b"\x89PNG\r\n\x1a\n") == [PNG_OFFSET]
    assert places(b"RIFF") == [WAV_OFFSET]
    assert places(b"PK\x03\x04") == [ZIP_OFFSET]
    assert places(b"PK\x05\x06") == [BUNDLE_SIZE - 22]
    assert places(b"MZ") == [0]
    assert places(b"GIF8") == [] and places(b"\x7fELF") == []


# --- vex -----------------------------------------------------------------------

def test_vex_still_loads_the_bundle_as_a_64_bit_windows_program():
    b = vex.load(BUNDLE)
    original = vex.load_bytes(fixture_bytes("hello_pe64.exe"))
    assert (b.format, b.arch, b.bits, b.endian) == ("PE", "x86_64", 64, "little")
    assert b.kind == "executable"
    assert b.entry == 0x140001060
    assert b.image_base == 0x140000000
    assert [s.name for s in b.sections] == [s.name for s in original.sections]


def test_split_finds_exactly_the_three_attached_files(tmp_path):
    split = pytest.importorskip("vex.split")
    import vex
    result = split.split(vex.load(str(BUNDLE)), str(tmp_path / "out"))
    found = [(p["path"].rsplit(".", 1)[1], p["offset"], p["size"])
             for p in result["pieces"] if p["kind"] == "embedded"]
    assert found == [("png", 3072, 3172), ("wav", 6244, 2044), ("zip", 8288, 259)]
    data = BUNDLE.read_bytes()
    for p in result["pieces"]:
        if p["kind"] == "embedded":
            assert (tmp_path / "out" / p["path"]).read_bytes() == data[p["offset"]:p["offset"] + p["size"]]
