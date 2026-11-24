"""`vex split`: saving the parts of a program as separate files.

Expected values are derived here, independently of vex.split: from the
fixture bytes, from small files built with the standard library, and from a
deliberately naive reference carver written straight from the specification.
"""
import hashlib
import io
import json
import os
import random
import struct
import time
import wave
import zipfile
import zlib
from urllib.parse import quote

import pytest

import vex
from vex import split
from vex.cli import main
from conftest import FIXTURES, fixture_bytes, fixture_path
from test_server import client  # noqa: F401  (pytest fixture)

ALL_FIXTURES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())
PIECE_KEYS = {"path", "kind", "name", "offset", "size", "address", "note"}
REFUSAL = "{} is not empty; choose a new or empty folder"


# --- small valid files, built without vex -----------------------------------

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def png_chunk(kind: bytes, body: bytes = b"") -> bytes:
    return struct.pack(">I", len(body)) + kind + body + \
        struct.pack(">I", zlib.crc32(kind + body))


PNG_HEAD = PNG_SIG + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))


def make_png() -> bytes:
    return PNG_HEAD + png_chunk(b"tEXt", b"Comment\0planted") + \
        png_chunk(b"IDAT", zlib.compress(b"\0\x7f")) + png_chunk(b"IEND")


def make_gif(local_table: bool = False) -> bytes:
    out = b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x80, 0, 0) + b"\0\0\0\xff\xff\xff"
    out += b"\x21\xf9\x04\x00\x00\x00\x00\x00"                  # graphic control
    out += b"\x21\xfe\x05hello\x03abc\x00"                      # comment, two sub-blocks
    out += b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0x81 if local_table else 0)
    out += b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0" if local_table else b""
    return out + b"\x02\x02\x4c\x01\x00" + b"\x3b"


def make_wav() -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        w.writeframes(b"\x01\x02" * 40)
    return buf.getvalue()


def make_riff(form: bytes) -> bytes:
    body = form + b"LIST" + struct.pack("<I", 4) + b"abcd"
    return b"RIFF" + struct.pack("<I", len(body)) + body


def make_zip(comment: bytes = b"", extra: dict = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("readme.txt", "hello " * 30)
        z.writestr("data/level.bin", bytes(range(64)))
        for name, data in (extra or {}).items():
            z.writestr(zipfile.ZipInfo(name), data, zipfile.ZIP_STORED)
        z.comment = comment
    return buf.getvalue()


BLOBS = {
    "png": make_png(), "gif": make_gif(), "wav": make_wav(),
    "avi": make_riff(b"AVI "), "webp": make_riff(b"WEBP"),
    "zip": make_zip(), "exe": fixture_bytes("hello_pe32.exe"),
    "dll": fixture_bytes("sample.dll"), "elf": fixture_bytes("bare_elf32"),
}
HOST = fixture_bytes("hello_pe32.exe")          # sections end where the file ends


def appended(blob: bytes, host: bytes = HOST, gap: int = 7):
    """host + junk + blob + junk, and the offset the blob landed at."""
    return host + b"\xaa" * gap + blob + b"\x55" * 9, len(host) + gap


def pieces_of(data: bytes, name: str = "test.bin"):
    return split.plan(vex.load_bytes(data, name))


def embedded(data: bytes):
    return [(p["offset"], p["size"], p["path"]) for p in pieces_of(data)
            if p["kind"] == "embedded"]


def files_under(folder) -> dict:
    out = {}
    for root, _dirs, names in os.walk(folder):
        for name in names:
            full = os.path.join(root, name)
            with open(full, "rb") as f:
                out[os.path.relpath(full, folder).replace(os.sep, "/")] = f.read()
    return out


# --- parts -------------------------------------------------------------------

@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_parts_concatenate_back_to_the_original_file(name, tmp_path):
    data = fixture_bytes(name)
    dest = tmp_path / "out"
    result = split.split(vex.load(fixture_path(name)), str(dest))
    rebuilt = b""
    for p in result["pieces"]:
        if p["kind"] in ("embedded", "resource"):
            continue
        assert p["offset"] == len(rebuilt)
        if p["path"] is None:
            assert p["kind"] == "padding"
            rebuilt += bytes(p["size"])
        else:
            chunk = (dest / p["path"]).read_bytes()
            assert len(chunk) == p["size"]
            rebuilt += chunk
    assert rebuilt == data
    assert fixture_bytes(name) == data          # the original is untouched


def test_all_four_format_flavours_are_covered_by_the_fixtures():
    kinds = {(b.format, b.bits) for b in map(vex.load, map(fixture_path, ALL_FIXTURES))}
    assert kinds == {("ELF", 32), ("ELF", 64), ("PE", 32), ("PE", 64)}


def test_part_names_offsets_and_addresses():
    pieces = pieces_of(fixture_bytes("hello_pe64.exe"))
    assert [(p["path"], p["kind"], p["name"], p["offset"], p["size"]) for p in pieces] == [
        ("parts/00_headers.bin", "headers", "headers", 0, 1024),
        ("parts/01_.text.bin", "code", ".text", 1024, 512),
        ("parts/02_.rdata.bin", "data", ".rdata", 1536, 512),
        ("parts/03_.pdata.bin", "data", ".pdata", 2048, 512),
        ("parts/04_symbol_table.bin", "meta", "symbol table", 2560, 243),
        (None, "padding", "padding", 2803, 269),
    ]
    assert pieces[1]["address"] == "0x140001000"
    assert pieces[4]["address"] is None
    assert all(set(p) - {"data"} == PIECE_KEYS for p in pieces)
    assert [p["note"] for p in pieces] == [""] * 5 + ["zero padding, not saved"]
    data = fixture_bytes("hello_pe64.exe")
    assert bytes(pieces[2]["data"]) == data[1536:2048]
    assert pieces[5]["data"] is None


def test_numbering_counts_padding_regions_too():
    data = fixture_bytes("bare_elf32")
    paths = [p["path"] for p in pieces_of(data)]
    # headers, .rodata, 1 zero byte, .text, 2 zero bytes, .comment, ...
    assert paths[:6] == ["parts/00_headers.bin", "parts/01_.rodata.bin", None,
                         "parts/03_.text.bin", None, "parts/05_.comment.bin"]
    assert paths[-1] == "parts/11_section_headers.bin"


def test_zero_padding_is_not_saved_but_other_padding_is(tmp_path):
    data = bytearray(fixture_bytes("hello_pe64.exe"))
    assert not any(data[2803:])                 # the fixture's tail is all zero
    data[2900] = 0x41
    result = split.split(vex.load_bytes(bytes(data), "x.exe"), str(tmp_path / "out"))
    last = result["pieces"][5]
    assert (last["path"], last["kind"], last["note"]) == \
        ("parts/05_padding.bin", "padding", "")
    assert (tmp_path / "out" / "parts" / "05_padding.bin").read_bytes() == bytes(data[2803:])


def test_overlay_is_saved(tmp_path):
    payload = b"OVERLAY-PAYLOAD-" * 5
    result = split.split(vex.load_bytes(HOST + payload, "x.exe"), str(tmp_path / "out"))
    last = result["pieces"][-1]
    assert (last["path"], last["kind"], last["offset"], last["size"]) == \
        ("parts/03_overlay.bin", "overlay", len(HOST), len(payload))
    assert (tmp_path / "out" / last["path"]).read_bytes() == payload


@pytest.mark.parametrize("patched", [b"../x\0\0\0\0", b"/../../x", b"a\\..\\b\0\0", b"..\0\0\0\0\0\0",
                                     b"C:\\x\0\0\0\0", b"a b\tc\n\0\0"])
def test_hostile_pe_section_names_stay_inside_the_folder(patched, tmp_path):
    data = fixture_bytes("hello_pe64.exe")
    assert data.count(b".rdata\0\0") == 1
    data = data.replace(b".rdata\0\0", patched)
    binary = vex.load_bytes(data, "x.exe")
    assert binary.sections[1].name == patched.rstrip(b"\0").decode()
    dest = tmp_path / "deep" / "out"
    result = split.split(binary, str(dest))
    path = result["pieces"][2]["path"]
    assert path.startswith("parts/02_") and path.endswith(".bin")
    assert set(path[len("parts/"):]) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
    assert (dest / "parts" / path[len("parts/"):]).read_bytes() == data[1536:2048]
    # nothing was created anywhere but in the destination folder
    assert sorted(os.listdir(tmp_path)) == ["deep"]
    assert sorted(os.listdir(tmp_path / "deep")) == ["out"]
    assert sorted(os.listdir(dest)) == ["index.txt", "parts"]
    assert len(os.listdir(dest / "parts")) == 5


def test_hostile_elf_section_name_stays_inside_the_folder(tmp_path):
    data = fixture_bytes("hello_elf64")
    assert data.count(b"\0.comment\0") == 1
    binary = vex.load_bytes(data.replace(b"\0.comment\0", b"\0../../zz\0"), "x")
    assert "../../zz" in [s.name for s in binary.sections]
    dest = tmp_path / "a" / "b" / "out"
    result = split.split(binary, str(dest))
    piece = next(p for p in result["pieces"] if p["name"] == "../../zz")
    assert piece["path"].endswith("_.._.._zz.bin") and piece["path"].count("/") == 1
    assert sorted(os.listdir(tmp_path)) == ["a"] and os.listdir(tmp_path / "a") == ["b"]
    assert os.listdir(tmp_path / "a" / "b") == ["out"]


def test_very_long_section_names_still_give_usable_file_names(tmp_path):
    # ELF section names can be longer than a file name may be.
    data = bytearray(fixture_bytes("hello_elf64"))
    start = data.index(b"\0.symtab\0") + 1          # start of .shstrtab's names
    room = 13960 + 282 - start - 1
    data[start:start + room] = b"n" * room          # one name of ~280 characters
    binary = vex.load_bytes(bytes(data), "x")
    assert max(len(s.name) for s in binary.sections) > 250
    result = split.split(binary, str(tmp_path / "out"))
    for p in result["pieces"]:
        if p["path"]:
            assert len(p["path"].split("/")[1]) <= 80
            assert (tmp_path / "out" / p["path"]).is_file()


# --- embedded files ------------------------------------------------------------

@pytest.mark.parametrize("ext", sorted(BLOBS))
def test_each_format_is_found_when_appended(ext, tmp_path):
    blob = BLOBS[ext]
    data, offset = appended(blob)
    assert embedded(data) == [(offset, len(blob), f"embedded/000_0x{offset:08x}.{ext}")]
    result = split.split(vex.load_bytes(data, "x.exe"), str(tmp_path / "out"))
    piece = next(p for p in result["pieces"] if p["kind"] == "embedded")
    assert piece == {"path": f"embedded/000_0x{offset:08x}.{ext}", "kind": "embedded",
                     "name": f"{ext} file", "offset": offset, "size": len(blob),
                     "address": None, "note": "found inside overlay"}
    assert (tmp_path / "out" / piece["path"]).read_bytes() == blob


def test_gif87_with_a_local_colour_table_is_measured_exactly():
    blob = make_gif(local_table=True).replace(b"GIF89a", b"GIF87a")
    data, offset = appended(blob)
    assert embedded(data) == [(offset, len(blob), f"embedded/000_0x{offset:08x}.gif")]


def test_zip_length_includes_the_archive_comment():
    blob = make_zip(comment=b"the end of the archive")
    data, offset = appended(blob)
    assert embedded(data) == [(offset, len(blob), f"embedded/000_0x{offset:08x}.zip")]


def test_pe_length_is_the_end_of_its_last_section_not_of_its_symbol_table():
    blob = fixture_bytes("hello_pe64.exe")      # 512-byte sections up to 2560, then symbols
    data, offset = appended(blob)
    assert embedded(data) == [(offset, 2560, f"embedded/000_0x{offset:08x}.exe")]


def test_elf64_is_measured_to_the_end_of_its_section_header_table():
    blob = fixture_bytes("hello_elf64")         # its last 1984 bytes are section headers
    data, offset = appended(blob, host=fixture_bytes("libsample.so"))
    assert embedded(data) == [(offset, len(blob), f"embedded/000_0x{offset:08x}.elf")]


def test_files_planted_inside_a_program_are_found_with_their_address_and_region():
    data = bytearray(fixture_bytes("hello_pe64.exe"))
    png, gif = BLOBS["png"], BLOBS["gif"]
    assert not any(data[1850:2048]) and len(png) + len(gif) < 180
    data[1860:1860 + len(png)] = png            # zero tail of .rdata (RVA 0x2000)
    data[1960:1960 + len(gif)] = gif
    found = [p for p in pieces_of(bytes(data)) if p["kind"] == "embedded"]
    assert [(p["path"], p["offset"], p["size"], p["address"], p["note"]) for p in found] == [
        ("embedded/000_0x00000744.png", 1860, len(png), hex(0x140002000 + 1860 - 1536),
         "found inside .rdata"),
        ("embedded/001_0x000007a8.gif", 1960, len(gif), hex(0x140002000 + 1960 - 1536),
         "found inside .rdata"),
    ]
    assert bytes(found[0]["data"]) == png and bytes(found[1]["data"]) == gif


def test_a_file_planted_in_padding_makes_that_padding_worth_saving():
    data = bytearray(fixture_bytes("hello_elf64"))
    wav = BLOBS["wav"]
    assert not any(data[1880:4096])
    data[2000:2000 + len(wav)] = wav
    pieces = pieces_of(bytes(data))
    hit = [p for p in pieces if p["kind"] == "embedded"]
    assert [(p["offset"], p["size"], p["note"]) for p in hit] == \
        [(2000, len(wav), "found inside padding")]
    pad = next(p for p in pieces if p["offset"] == 1880)
    assert pad["path"] == "parts/17_padding.bin" and pad["size"] == 2216


def test_several_files_are_numbered_in_file_order():
    order = ["zip", "png", "elf", "gif", "exe", "wav"]
    data, expected = HOST + b"\xaa" * 3, []
    for i, ext in enumerate(order):
        expected.append((len(data), len(BLOBS[ext]),
                         f"embedded/{i:03d}_0x{len(data):08x}.{ext}"))
        data += BLOBS[ext] + b"\xaa" * (i + 1)
    assert embedded(data) == expected


def test_the_program_itself_is_not_reported_as_embedded():
    for name in ALL_FIXTURES:
        assert embedded(fixture_bytes(name)) == [], name
    assert split.carve(BLOBS["png"]) == []      # offset 0 is never a hit
    assert split.carve(b"\0" + BLOBS["png"]) == [(1, len(BLOBS["png"]), "png")]


def test_hits_never_overlap_files_inside_files_are_left_inside():
    inner_zip, png = BLOBS["zip"], BLOBS["png"]
    outer = make_zip(extra={"inner.zip": inner_zip, "picture.png": png, "tool.exe": HOST})
    assert inner_zip in outer and png in outer and HOST in outer
    data, offset = appended(outer + png)
    assert embedded(data) == [
        (offset, len(outer), f"embedded/000_0x{offset:08x}.zip"),
        (offset + len(outer), len(png), f"embedded/001_0x{offset + len(outer):08x}.png")]


def bad_png_crc() -> bytes:
    blob = bytearray(BLOBS["png"])
    blob[8 + 8 + 13] ^= 0x01                    # first byte of the IHDR checksum
    return bytes(blob)


def zip_with(cd_offset_delta: int, cd_size_delta: int) -> bytes:
    blob = bytearray(BLOBS["zip"])
    eocd = blob.rindex(b"PK\x05\x06")
    size, offset = struct.unpack_from("<II", blob, eocd + 12)
    struct.pack_into("<II", blob, eocd + 12, size + cd_size_delta, offset + cd_offset_delta)
    return bytes(blob)


def patched(blob: bytes, at: int, new: bytes) -> bytes:
    return blob[:at] + new + blob[at + len(new):]


PE32 = BLOBS["exe"]
PE32_HEADER = struct.unpack_from("<I", PE32, 0x3c)[0]
NEAR_MISSES = {
    "png: wrong IHDR checksum": bad_png_crc(),
    "png: IHDR of length 14": PNG_SIG + png_chunk(b"IHDR", bytes(14)) + png_chunk(b"IEND"),
    "png: first chunk is not IHDR": PNG_SIG + png_chunk(b"IDAT", bytes(13)) + png_chunk(b"IEND"),
    "png: no IEND": BLOBS["png"][:-12],
    "png: chunk longer than the file": PNG_HEAD + struct.pack(">I", 5000) + b"IDAT" + bytes(40),
    "gif: no image": make_gif()[:19] + b"\x21\xfe\x02hi\x00\x3b",
    "gif: unknown block": make_gif()[:19] + b"\x99" + make_gif()[19:],
    "gif: no trailer": make_gif()[:-1],
    "riff: size past the end": patched(BLOBS["wav"], 4, struct.pack("<I", len(BLOBS["wav"]) + 40)),
    "riff: size below 4": b"RIFF" + struct.pack("<I", 3) + b"WAVE" + bytes(20),
    "riff: unknown form": make_riff(b"JUNK"),
    "zip: central directory offset is off": zip_with(1, 0),
    "zip: directory does not start at PK 01 02": zip_with(1, -1),
    "zip: end record missing": BLOBS["zip"][:BLOBS["zip"].rindex(b"PK\x05\x06")],
    "zip: comment runs past the end": patched(
        BLOBS["zip"], len(BLOBS["zip"]) - 2, struct.pack("<H", 100)),
    "pe: no PE signature": patched(PE32, PE32_HEADER, b"PE\0\1"),
    "pe: no sections": patched(PE32, PE32_HEADER + 6, b"\0\0"),
    "pe: 97 sections": patched(PE32, PE32_HEADER + 6, struct.pack("<H", 97)),
    "pe: header offset outside the file": patched(PE32, 0x3c, struct.pack("<I", 1 << 20)),
    "elf: class 3": patched(BLOBS["elf"], 4, b"\x03"),
    "elf: data encoding 0": patched(BLOBS["elf"], 5, b"\x00"),
    "elf: version 2": patched(BLOBS["elf"], 6, b"\x02"),
}


@pytest.mark.parametrize("label", sorted(NEAR_MISSES))
def test_near_misses_are_not_reported(label):
    data, _offset = appended(NEAR_MISSES[label])
    assert embedded(data) == []


@pytest.mark.parametrize("ext", sorted(BLOBS))
def test_truncated_files_are_not_reported(ext):
    blob = BLOBS[ext]
    for cut in (1, 2, 13, len(blob) // 2):
        data = HOST + b"\xaa" * 5 + blob[:-cut]     # the file ends inside the blob
        assert embedded(data) == [], cut


def test_pe_shorter_than_512_bytes_is_not_reported():
    # A structurally fine PE whose sections all end before byte 512.
    blob = bytearray(PE32)
    table = PE32_HEADER + 24 + struct.unpack_from("<H", blob, PE32_HEADER + 20)[0]
    for i in range(struct.unpack_from("<H", blob, PE32_HEADER + 6)[0]):
        struct.pack_into("<II", blob, table + 40 * i + 16, 16, 300)   # raw size, pointer
    struct.pack_into("<I", blob, PE32_HEADER + 24 + 60, 400)          # SizeOfHeaders
    assert embedded(appended(bytes(blob))[0]) == []
    struct.pack_into("<I", blob, PE32_HEADER + 24 + 60, 512)
    data, offset = appended(bytes(blob))
    assert embedded(data) == [(offset, 512, f"embedded/000_0x{offset:08x}.exe")]


def test_elf_shorter_than_84_bytes_is_not_reported():
    def tiny(phoff, phnum):                     # ELF32 header only, no sections
        return b"\x7fELF\x01\x01\x01" + bytes(9) + struct.pack(
            "<HHIIIIIHHHHHH", 2, 3, 1, 0, phoff, 0, 0, 52, 32, phnum, 40, 0, 0)
    filler = bytes([1, 0, 0, 0]) + bytes(60)    # one empty PT_LOAD and slack
    assert embedded(appended(tiny(51, 1) + filler)[0]) == []          # ends at 83
    data, offset = appended(tiny(52, 1) + filler)
    assert embedded(data) == [(offset, 84, f"embedded/000_0x{offset:08x}.elf")]


# --- resources ---------------------------------------------------------------

def test_resources_are_saved_like_vex_resources_extract(tmp_path, capsys):
    exe = str(fixture_path("resdemo.exe"))
    assert main(["resources", "extract", exe, str(tmp_path / "ref")]) == 0
    capsys.readouterr()
    reference = files_under(tmp_path / "ref")
    assert len(reference) == 11 and "GROUP_ICON_1_1033.ico" in reference
    result = split.split(vex.load(exe), str(tmp_path / "out"))
    assert files_under(tmp_path / "out" / "resources") == reference
    rows = [p for p in result["pieces"] if p["kind"] == "resource"]
    assert result["pieces"][-len(rows):] == rows            # resources come last
    assert sorted(p["path"] for p in rows) == sorted("resources/" + n for n in reference)
    assert all(p["size"] == len(reference[p["path"][len("resources/"):]]) for p in rows)
    settings = next(p for p in rows if p["path"] == "resources/RCDATA_SETTINGS_1033.bin")
    assert (settings["offset"], settings["size"], settings["name"]) == \
        (3472, 24, "RCDATA SETTINGS")
    assert settings["address"] == hex(0x140003000 + 3472 - 2048)


def test_broken_resources_are_skipped_and_the_rest_is_still_saved(tmp_path):
    data = bytearray(fixture_bytes("resdemo.exe"))
    assert struct.unpack_from("<HHH", data, 3384) == (0, 1, 2)     # the icon group
    data[3386] = 9                                                  # no longer an icon group
    result = split.split(vex.load_bytes(bytes(data), "r.exe"), str(tmp_path / "out"))
    assert [p for p in result["pieces"] if p["kind"] == "resource"] == []
    assert sorted(os.listdir(tmp_path / "out")) == ["index.txt", "parts"]
    assert result["count"] == 6


def test_elf_files_have_no_resource_group():
    assert {p["kind"] for p in pieces_of(fixture_bytes("hello_elf64"))} == \
        {"headers", "code", "data", "meta", "padding"}


# --- destination folder, result and index -----------------------------------

def test_result_counts_files_and_bytes_and_gives_the_absolute_folder(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    data, _offset = appended(BLOBS["png"])
    result = split.split(vex.load_bytes(data, "x.exe"), "new/out")
    assert set(result) == {"dest", "count", "bytes", "index", "pieces"}
    assert result["dest"] == str(tmp_path / "new" / "out") and result["index"] == "index.txt"
    written = files_under(tmp_path / "new" / "out")
    index = written.pop("index.txt")
    assert result["count"] == len(written) == 5         # 4 parts and the picture
    assert result["bytes"] == sum(map(len, written.values())) == len(data) + len(BLOBS["png"])
    assert sorted(written) == sorted(p["path"] for p in result["pieces"])
    assert all(set(p) == PIECE_KEYS for p in result["pieces"])
    json.dumps(result)                                  # plain data only
    assert index.count(b"\n") == 1 + len(result["pieces"])


def test_an_existing_empty_folder_is_accepted(tmp_path):
    (tmp_path / "out").mkdir()
    assert split.split(vex.load_bytes(HOST, "x.exe"), str(tmp_path / "out"))["count"] == 3


@pytest.mark.parametrize("occupant", ["file", "folder", "hidden file"])
def test_a_folder_that_is_not_empty_is_refused_and_left_alone(occupant, tmp_path):
    dest = tmp_path / "out"
    dest.mkdir()
    if occupant == "folder":
        (dest / "sub").mkdir()
    else:
        (dest / (".keep" if occupant == "hidden file" else "notes.txt")).write_text("mine")
    before = files_under(tmp_path), sorted(os.listdir(dest))
    with pytest.raises(vex.VexError) as err:
        split.split(vex.load_bytes(HOST, "x.exe"), str(dest))
    assert str(err.value) == REFUSAL.format(dest)
    assert (files_under(tmp_path), sorted(os.listdir(dest))) == before


def test_a_destination_that_is_a_file_is_refused(tmp_path):
    dest = tmp_path / "out.txt"
    dest.write_text("mine")
    with pytest.raises(vex.VexError) as err:
        split.split(vex.load_bytes(HOST, "x.exe"), str(dest))
    assert str(err.value) == REFUSAL.format(dest)
    assert dest.read_text() == "mine"


def test_index_lists_every_piece_in_aligned_rows(tmp_path):
    name = "hello_pe64.exe"
    data = fixture_bytes(name)
    split.split(vex.load(fixture_path(name)), str(tmp_path / "out"))
    assert (tmp_path / "out" / "index.txt").read_bytes().decode("ascii") == (
        f"hello_pe64.exe: 3072 bytes, SHA-256 {hashlib.sha256(data).hexdigest()}\n"
        "0x00000000  1024  headers  parts/00_headers.bin       headers\n"
        "0x00000400   512  code     parts/01_.text.bin         .text\n"
        "0x00000600   512  data     parts/02_.rdata.bin        .rdata\n"
        "0x00000800   512  data     parts/03_.pdata.bin        .pdata\n"
        "0x00000a00   243  meta     parts/04_symbol_table.bin  symbol table\n"
        "0x00000af3   269  padding  -                          padding"
        "       zero padding, not saved\n")


def test_index_aligns_each_group_on_its_own(tmp_path):
    # The rows of the parts must not depend on which other groups exist, so
    # that an edition without resources writes the same bytes for them.
    plain = tmp_path / "plain"
    split.split(vex.load_bytes(HOST, "x.exe"), str(plain))
    data, offset = appended(BLOBS["wav"])
    split.split(vex.load_bytes(data, "x.exe"), str(tmp_path / "more"))
    rows = (tmp_path / "more" / "index.txt").read_text().splitlines()
    assert rows[1:4] == (plain / "index.txt").read_text().splitlines()[1:]
    assert rows[5] == (f"0x{offset:08x}  {len(BLOBS['wav'])}  embedded  "
                       f"embedded/000_0x{offset:08x}.wav  wav file  found inside overlay")
    with_resources = tmp_path / "res"
    split.split(vex.load(fixture_path("resdemo.exe")), str(with_resources))
    rows = (with_resources / "index.txt").read_text().splitlines()
    assert rows[1] == "0x00000000  1024  headers  parts/00_headers.bin       headers"
    assert "0x00000d90    24  resource  resources/RCDATA_SETTINGS_1033.bin  " \
           "RCDATA SETTINGS  language 1033" in rows


def test_index_stays_one_row_per_piece_whatever_the_names_contain(tmp_path):
    data = fixture_bytes("hello_pe64.exe").replace(b".rdata\0\0", b"a\nb\x1b[1m\0\0")
    split.split(vex.load_bytes(data, "x.exe"), str(tmp_path / "out"))
    text = (tmp_path / "out" / "index.txt").read_bytes()
    assert text.count(b"\n") == 7 and b"\x1b" not in text
    assert b"parts/02_a_b__1m.bin        a?b?[1m\n" in text


# --- command line ----------------------------------------------------------------

def test_cli_prints_the_piece_table_and_a_summary(tmp_path, capsys):
    dest = tmp_path / "out"
    assert main(["split", str(fixture_path("hello_pe64.exe")), str(dest)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split() == ["Offset", "Size", "Kind", "File", "Name", "Note"]
    assert out[2].split() == ["0x0", "1024", "headers", "parts/00_headers.bin", "headers"]
    assert out[7].split(None, 5) == ["0xaf3", "269", "padding", "-", "padding",
                                     "zero padding, not saved"]
    assert out[-1] == f"Saved 5 files to {dest}" and len(out) == 9
    assert len(files_under(dest)) == 6


def test_cli_json_is_the_result_object(tmp_path, capsys):
    dest = tmp_path / "out"
    data, offset = appended(BLOBS["zip"])
    (tmp_path / "prog.exe").write_bytes(data)
    assert main(["--json", "split", str(tmp_path / "prog.exe"), str(dest)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert set(result) == {"dest", "count", "bytes", "index", "pieces"}
    assert (result["dest"], result["count"], result["index"]) == (str(dest), 5, "index.txt")
    assert result["bytes"] == len(data) + len(BLOBS["zip"])
    assert result["pieces"][-1] == {
        "path": f"embedded/000_0x{offset:08x}.zip", "kind": "embedded", "name": "zip file",
        "offset": offset, "size": len(BLOBS["zip"]), "address": None,
        "note": "found inside overlay"}
    assert (tmp_path / "prog.exe").read_bytes() == data


def test_cli_refuses_a_folder_that_is_not_empty(tmp_path, capsys):
    (tmp_path / "keep.txt").write_text("mine")
    code = main(["split", str(fixture_path("hello_pe64.exe")), str(tmp_path)])
    captured = capsys.readouterr()
    assert code == 1 and captured.out == ""
    assert captured.err == "vex: error: " + REFUSAL.format(tmp_path) + "\n"
    assert os.listdir(tmp_path) == ["keep.txt"]


def test_cli_reports_a_file_that_is_not_a_program(tmp_path, capsys):
    (tmp_path / "notes.txt").write_text("hello")
    assert main(["split", str(tmp_path / "notes.txt"), str(tmp_path / "out")]) == 1
    assert "not an ELF or PE file" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


# --- HTTP API -------------------------------------------------------------------

def test_api_preview_describes_the_split_without_touching_the_disk(client, tmp_path):  # noqa: F811
    data, offset = appended(BLOBS["gif"])
    (tmp_path / "prog.exe").write_bytes(data)
    before = files_under(tmp_path)
    preview = client.api("split", path=tmp_path / "prog.exe")
    assert files_under(tmp_path) == before and os.listdir(tmp_path) == ["prog.exe"]
    assert preview["dest"] is None and preview["index"] == "index.txt"
    assert (preview["count"], preview["bytes"]) == (5, len(data) + len(BLOBS["gif"]))
    assert preview["pieces"][-1]["path"] == f"embedded/000_0x{offset:08x}.gif"
    assert all(set(p) == PIECE_KEYS for p in preview["pieces"])


def post(client, **params):  # noqa: F811
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
    status, _ctype, body = client.request("POST", f"/api/split?{query}")
    return status, json.loads(body)


def test_api_post_performs_the_split(client, tmp_path):  # noqa: F811
    exe = fixture_path("resdemo.exe")
    preview = client.api("split", path=exe)
    status, result = post(client, path=exe, dest=tmp_path / "out")
    assert status == 200
    assert result == dict(preview, dest=str(tmp_path / "out"))
    written = files_under(tmp_path / "out")
    assert written.pop("index.txt").startswith(b"resdemo.exe: 6144 bytes, SHA-256 ")
    assert (len(written), sum(map(len, written.values()))) == (result["count"], result["bytes"])
    assert "resources/GROUP_ICON_1_1033.ico" in written


def test_api_refuses_a_folder_that_is_not_empty(client, tmp_path):  # noqa: F811
    (tmp_path / "keep.txt").write_text("mine")
    status, body = post(client, path=fixture_path("hello_elf64"), dest=tmp_path)
    assert status == 400 and body == {"error": REFUSAL.format(tmp_path)}
    assert os.listdir(tmp_path) == ["keep.txt"]


def test_api_reports_missing_parameters_and_files(client, tmp_path):  # noqa: F811
    status, body = post(client, path=fixture_path("hello_elf64"))
    assert status == 400 and "dest" in body["error"]
    status, body = post(client, path=tmp_path / "nope.exe", dest=tmp_path / "out")
    assert status == 404 and not (tmp_path / "out").exists()
    status, body = client.get("/api/split?path=" + quote(str(tmp_path / "nope.exe"), safe=""))
    assert status == 404


# --- the carver on hostile input -------------------------------------------------
#
# reference_carve() is the specification transcribed as plainly as possible:
# no caches, no shortcuts, quadratic where the specification is.

def _u(data, at, size, order="little"):
    return int.from_bytes(data[at:at + size], order) if at + size <= len(data) else None


def _ref_png(d, o):
    if d[o:o + 16] != PNG_SIG + b"\0\0\0\rIHDR" or o + 33 > len(d):
        return None
    if zlib.crc32(d[o + 12:o + 29]) != _u(d, o + 29, 4, "big"):
        return None
    at = o + 33
    while at + 12 <= len(d):
        end = at + 12 + _u(d, at, 4, "big")
        if end > len(d):
            return None
        if d[at + 4:at + 8] == b"IEND":
            return "png", end - o
        at = end
    return None


def _ref_sub_blocks(d, at):
    while at < len(d):
        if d[at] == 0:
            return at + 1
        at += 1 + d[at]
    return None


def _ref_gif(d, o):
    if d[o:o + 6] not in (b"GIF87a", b"GIF89a") or o + 13 > len(d):
        return None
    at = o + 13 + (3 * 2 ** ((d[o + 10] & 7) + 1) if d[o + 10] & 0x80 else 0)
    images = 0
    while at is not None and at < len(d):
        if d[at] == 0x3b:
            return ("gif", at + 1 - o) if images else None
        if d[at] == 0x2c:
            if at + 10 > len(d):
                return None
            flags = d[at + 9]
            images += 1
            at = _ref_sub_blocks(d, at + 10 + (3 * 2 ** ((flags & 7) + 1)
                                               if flags & 0x80 else 0) + 1)
        elif d[at] == 0x21:
            at = _ref_sub_blocks(d, at + 2)
        else:
            return None
    return None


def _ref_riff(d, o):
    forms = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}
    size = _u(d, o + 4, 4)
    if d[o:o + 4] != b"RIFF" or d[o + 8:o + 12] not in forms or size < 4:
        return None
    return forms[d[o + 8:o + 12]], size + 8


def _ref_zip(d, o):
    if d[o:o + 4] != b"PK\x03\x04":
        return None
    at = d.find(b"PK\x05\x06", o + 1)
    while at != -1:
        if at + 22 <= len(d) and at + 22 + _u(d, at + 20, 2) <= len(d):
            size, offset = _u(d, at + 12, 4), _u(d, at + 16, 4)
            if o + offset + size == at and d[o + offset:o + offset + 4] == b"PK\x01\x02":
                return "zip", at + 22 + _u(d, at + 20, 2) - o
        at = d.find(b"PK\x05\x06", at + 1)
    return None


def _ref_pe(d, o):
    if d[o:o + 2] != b"MZ" or o + 0x40 > len(d):
        return None
    pe = o + _u(d, o + 0x3c, 4)
    if pe + 88 > len(d) or d[pe:pe + 4] != b"PE\0\0":
        return None
    count, table = _u(d, pe + 6, 2), pe + 24 + _u(d, pe + 20, 2)
    if not 1 <= count <= 96 or table + 40 * count > len(d):
        return None
    length = _u(d, pe + 24 + 60, 4)
    for i in range(count):
        length = max(length, _u(d, table + 40 * i + 16, 4) + _u(d, table + 40 * i + 20, 4))
    if length < 512:
        return None
    return ("dll" if _u(d, pe + 22, 2) & 0x2000 else "exe"), length


def _ref_elf(d, o):
    if d[o:o + 4] != b"\x7fELF" or o + 7 > len(d):
        return None
    if d[o + 4] not in (1, 2) or d[o + 5] not in (1, 2) or d[o + 6] != 1:
        return None
    wide, order = d[o + 4] == 2, "little" if d[o + 5] == 1 else "big"
    if o + (64 if wide else 52) > len(d):
        return None
    word = 8 if wide else 4
    phoff, shoff = _u(d, o + 28 + (4 if wide else 0), word, order), \
        _u(d, o + 28 + (4 if wide else 0) + word, word, order)
    phentsize, phnum, shentsize, shnum = (
        _u(d, o + (54 if wide else 42) + 2 * i, 2, order) for i in range(4))
    if (phnum and phentsize != (56 if wide else 32)) or \
            (shnum and shentsize != (64 if wide else 40)):
        return None
    length = max(phoff + phnum * phentsize, shoff + shnum * shentsize)
    if o + length > len(d):
        return None
    for i in range(phnum):
        at = o + phoff + i * phentsize
        length = max(length, _u(d, at + (8 if wide else 4), word, order) +
                     _u(d, at + (32 if wide else 16), word, order))
    for i in range(shnum):
        at = o + shoff + i * shentsize
        if _u(d, at + 4, 4, order) != 8:
            length = max(length, _u(d, at + (24 if wide else 16), word, order) +
                         _u(d, at + (32 if wide else 20), word, order))
    return ("elf", length) if length >= 84 else None


def reference_carve(d: bytes) -> list:
    hits, at = [], 1
    while at < len(d):
        for probe in (_ref_png, _ref_gif, _ref_riff, _ref_zip, _ref_pe, _ref_elf):
            found = probe(d, at)
            if found and at + found[1] <= len(d):
                hits.append((at, found[1], found[0]))
                at += found[1] - 1
                break
        at += 1
    return hits


def check_carve(data: bytes) -> list:
    hits = split.carve(data)
    end = 1
    for offset, size, ext in hits:
        assert offset >= end and size > 0 and offset + size <= len(data)
        assert ext in ("png", "gif", "wav", "avi", "webp", "zip", "exe", "dll", "elf")
        end = offset + size
    return hits


def test_reference_carver_agrees_on_the_plain_cases():
    for ext, blob in BLOBS.items():
        data, offset = appended(blob)
        assert reference_carve(data) == split.carve(data) == [(offset, len(blob), ext)]


def test_carver_copes_with_empty_and_tiny_input():
    for data in (b"", b"M", b"MZ", b"\0MZ", b"\0PK\x03\x04", b"\0GIF89a", b"\0RIFF",
                 b"\0\x7fELF", b"\0" + PNG_SIG, b"\0" + PNG_HEAD, b"\0GIF89a" + bytes(7)):
        assert check_carve(data) == []


def test_carver_survives_every_truncation_of_every_format():
    for ext, blob in BLOBS.items():
        step = max(1, len(blob) // 400)
        for cut in list(range(0, len(blob), step)) + list(range(len(blob) - 40, len(blob))):
            data = b"\xaa" + blob[:max(cut, 0)]
            assert check_carve(data) == reference_carve(data) == [], (ext, cut)


def test_carver_agrees_with_the_reference_on_damaged_files():
    rng = random.Random(1234)
    for round_ in range(400):
        ext = rng.choice(sorted(BLOBS))
        blob = bytearray(BLOBS[ext])
        for _ in range(rng.randint(1, 4)):
            at = rng.randrange(min(len(blob), 600))
            blob[at] = rng.choice((0, 1, 0xff, blob[at] ^ (1 << rng.randrange(8)),
                                   rng.randrange(256)))
        data = b"\xaa" * rng.randint(1, 3) + bytes(blob) + BLOBS[rng.choice(sorted(BLOBS))]
        assert check_carve(data) == reference_carve(data), (round_, ext)


# Building blocks that make walks from different starting points run into each
# other: where a cache could give a wrong answer, and where a carver without
# one would take quadratic time.

def png_trap(count: int, finish: bool) -> bytes:
    """A PNG whose every chunk holds the start of another PNG that, when read
    on its own, joins the outer chunk chain."""
    link = struct.pack(">I", 41) + b"juNK" + PNG_HEAD + struct.pack(">I", 0) + b"miNI" + bytes(4)
    return PNG_HEAD + link * count + (png_chunk(b"IEND") if finish else b"")


def gif_trap(count: int, images: bool, trailer: bool, first_image: bool = False) -> bytes:
    """A GIF of comment blocks, each holding the start of another GIF that
    joins the outer block chain (after an image block of its own if `images`)."""
    head = b"GIF89a" + bytes(7)
    image = b"\x2c" + bytes(9) + b"\x02"
    inner = head + (image if images else b"\x21\xfe") + b"\x01\x00"
    link = b"\x21\xfe" + bytes([len(inner)]) + inner + b"\x00"
    return head + (image + b"\x01\x00\x00" if first_image else b"") + \
        link * count + (b"\x3b" if trailer else b"")


def zip_trap(count: int) -> bytes:
    """Local headers and end records that never belong together."""
    end = b"PK\x05\x06" + bytes(8) + struct.pack("<IIH", 7, 0x7fffffff, 0)
    return (b"PK\x03\x04" + end) * count


def pe_trap(count: int, sections: int = 96) -> bytes:
    """Many MZ headers that all point at one PE header whose last section
    reaches past the end of the file."""
    stubs = count * 64
    out = bytearray()
    for i in range(count):
        out += b"MZ" + bytes(58) + struct.pack("<I", stubs - i * 64)
    out += b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, sections, 0, 0, 0, 0, 0)
    out += bytes(64)
    table = bytearray(40 * sections)
    for i in range(sections):
        struct.pack_into("<II", table, 40 * i + 16, 512, 512)
    struct.pack_into("<II", table, 40 * (sections - 1) + 16, 0x100000, 0x7f000000)
    return bytes(out + table)


def elf_trap(count: int, entries: int, wide: bool = True, order: str = "<") -> bytes:
    """Many ELF headers sharing one section header table; each uses a
    different window of it and all windows hold one section that reaches past
    the end of the file."""
    head, entry = (64, 64) if wide else (52, 40)
    out = bytearray()
    for i in range(count):
        ident = b"\x7fELF" + bytes([2 if wide else 1, 1 if order == "<" else 2, 1]) + bytes(9)
        shoff = (count - i) * head + (i % entries) * entry
        shnum = entries - i % entries
        if wide:
            fields = struct.pack(order + "HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 56, 0,
                                 64, shnum, 0)
        else:
            fields = struct.pack(order + "HHIIIIIHHHHHH", 2, 3, 1, 0, 0, shoff, 0, 52, 32, 0,
                                 40, shnum, 0)
        out += ident + fields
    table = bytearray(entry * entries)
    for i in range(entries):
        kind, offset, size = (8, 0x7fff0000, 0x7fff0000) if i % 7 == 3 else (1, 64, 100 + i % 50)
        if i == entries - 1:
            kind, offset, size = 1, 0x7f000000, 16          # past the end of any test file
        struct.pack_into(order + "I", table, entry * i + 4, kind)
        struct.pack_into(order + ("QQ" if wide else "II"), table,
                         entry * i + (24 if wide else 16), offset, size)
    return bytes(out + table)


TRAPS = {
    "png chain, never finished": lambda n: png_trap(n, False),
    "png chain, finished": lambda n: png_trap(n, True),
    "gif chain, cut off": lambda n: gif_trap(n, False, False),
    "gif chain, no image": lambda n: gif_trap(n, False, True),
    "gif chain, images only inside": lambda n: gif_trap(n, True, True),
    "gif chain, images inside, cut off": lambda n: gif_trap(n, True, False),
    "gif chain, image first, cut off": lambda n: gif_trap(n, False, False, first_image=True),
    "zip records that do not match": zip_trap,
    "one pe header, many stubs": pe_trap,
    "one elf64 table, many headers": lambda n: elf_trap(n, 7 * n + 3),
    "one elf32 table, many headers": lambda n: elf_trap(n, 7 * n + 3, wide=False),
    "one big-endian elf table": lambda n: elf_trap(n, 7 * n + 3, wide=False, order=">"),
}


@pytest.mark.parametrize("label", sorted(TRAPS))
def test_carver_agrees_with_the_reference_on_entangled_structures(label):
    for count in (1, 2, 5, 40, 100):
        for lead in (b"\xaa", b"\xaa" * 37):
            data = lead + TRAPS[label](count)
            assert check_carve(data) == reference_carve(data), count
            data += b"\x3b" + png_chunk(b"IEND") + bytes(50)   # endings that arrive late
            assert check_carve(data) == reference_carve(data), count


def test_entangled_structures_give_the_expected_hits():
    # Hand-checked: what the traps above must produce.
    assert check_carve(b"\xaa" + png_trap(5, False)) == []
    data = b"\xaa" + png_trap(5, True)
    assert check_carve(data) == [(1, len(data) - 1, "png")]
    assert check_carve(b"\xaa" + gif_trap(5, False, True)) == []
    data = b"\xaa" + gif_trap(5, True, True)        # the first inner GIF has an image
    assert check_carve(data) == [(1 + 13 + 3, len(data) - 17, "gif")]


def test_carver_agrees_with_the_reference_on_random_mixtures():
    rng = random.Random(99)
    parts = list(BLOBS.values()) + list(NEAR_MISSES.values()) + [
        PNG_HEAD, png_chunk(b"IEND"), png_chunk(b"abCD", b"xyz"), b"GIF89a" + bytes(7),
        b"\x21\xfe\x03abc\x00", b"\x2c" + bytes(9) + b"\x02\x01\x00\x00", b"\x3b",
        b"PK\x03\x04", b"PK\x05\x06" + bytes(18), b"MZ", b"\x7fELF\x02\x01\x01", b"RIFF",
        png_trap(3, False), gif_trap(3, True, False), gif_trap(2, False, True),
        zip_trap(2), pe_trap(2, 3), elf_trap(3, 9), elf_trap(2, 300, wide=False)]
    for round_ in range(150):
        data = b"\xaa"
        for _ in range(rng.randint(1, 12)):
            part = rng.choice(parts)
            if rng.random() < 0.3:
                part = part[:rng.randrange(len(part) + 1)]
            data += part + bytes(rng.randrange(256) for _ in range(rng.choice((0, 0, 1, 5))))
        assert check_carve(data) == reference_carve(data), round_


def test_carver_agrees_with_the_reference_on_random_bytes():
    rng = random.Random(7)
    alphabet = [b"PK", b"\x03\x04", b"\x05\x06", b"\x01\x02", b"MZ", b"PE\0\0", b"\x7fELF",
                b"GIF89a", b"RIFF", b"WAVE", b"\0", b"\0\0\0", b"\x01", b"\x02", b"\x21",
                b"\x2c", b"\x3b", b"IEND", b"IHDR", PNG_SIG, b"\xff", b"\x40", b"\x08"]
    for round_ in range(300):
        data = b"\0" + b"".join(rng.choice(alphabet) for _ in range(rng.randint(1, 120)))
        assert check_carve(data) == reference_carve(data), round_


LIMIT = 20.0        # seconds; each case takes well under one, a quadratic carver minutes

BIG = {
    "4 MB of zip local headers": lambda: b"PK\x03\x04" * (1 << 20),
    "4 MB of MZ": lambda: b"MZ" * (2 << 20),
    "4 MB of every signature": lambda: (
        b"MZ\x7fELFRIFFPK\x03\x04GIF89a" + PNG_SIG + b"PK\x05\x06PE\0\0") * (4 << 20 // 36),
    "4 MB of zip records that do not match": lambda: zip_trap((4 << 20) // 26),
    "2 MB png chain": lambda: png_trap((2 << 20) // 53, False),
    "2 MB gif chain": lambda: gif_trap((2 << 20) // 20, False, False),
    "2 MB gif chain with images": lambda: gif_trap((2 << 20) // 29, True, False),
    "2 MB of sub-blocks": lambda: (b"GIF89a" + bytes(7) + b"\x21\xfe" + b"\x01" * 51) * (2 << 14),
    "pe header shared by 32768 stubs": lambda: pe_trap(1 << 15),
    "elf table shared by 16384 headers": lambda: elf_trap(1 << 14, 60000),
}


@pytest.mark.parametrize("label", sorted(BIG))
def test_carver_stays_fast_on_large_hostile_input(label):
    data = b"\xaa" + BIG[label]()
    assert len(data) > 1 << 20
    started = time.perf_counter()
    hits = check_carve(data)
    assert time.perf_counter() - started < LIMIT
    assert hits == []


def test_split_of_a_program_with_a_large_hostile_overlay(tmp_path):
    junk = (b"PK\x03\x04MZ" + b"GIF89a" + PNG_SIG) * 150000 + b"\x55"     # 3 MB
    binary = vex.load_bytes(HOST + junk + BLOBS["png"], "x.exe")
    started = time.perf_counter()
    result = split.split(binary, str(tmp_path / "out"))
    assert time.perf_counter() - started < LIMIT
    found = [p for p in result["pieces"] if p["kind"] == "embedded"]
    assert [(p["offset"], p["size"]) for p in found] == \
        [(len(HOST) + len(junk), len(BLOBS["png"]))]
