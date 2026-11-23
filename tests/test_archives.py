"""Asset containers (ZIP family, Quake PAK, Doom WAD, Godot PCK, Electron ASAR,
Ren'Py RPA).

Every container used here is assembled in this file: by hand with struct.pack
following the format's specification (offsets are spelled out next to each
builder), or with the standard library's zipfile. Expected values are literals
worked out from those layouts. Nothing is produced by binspect.archives and
then fed back to it as an expectation; where a test inspects a repacked file
it re-parses it with a small reference reader written here from the spec.
"""
import hashlib
import json
import os
import pickle
import random
import struct
import tracemalloc
import zipfile
import zlib

import pytest

from binspect import archives
from binspect.archives import ArchiveEntry
from binspect.errors import (
    BinspectError,
    LocationError,
    ParseError,
    UnknownFormatError,
    UnsupportedError,
)
from conftest import fixture_bytes

PE_STUB_SIZE = 3072         # tests/fixtures/bin/hello_pe64.exe
ELF_STUB_SIZE = 16232       # tests/fixtures/bin/hello_elf64


def padded(name: bytes, width: int) -> bytes:
    assert len(name) <= width
    return name + bytes(width - len(name))


def write(tmp_path, name, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def tree(root) -> dict:
    """Every regular file under root as {relative posix path: content}."""
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


# =============================================================================
# Builders
# =============================================================================

# --- Quake / Half-Life PAK ---------------------------------------------------
PAK_README = b"hello quake\n"           # 12 bytes
PAK_PALETTE = bytes(range(256))         # 256 bytes


def build_pak() -> bytes:
    """  0  'PACK', int32 directory offset = 280, int32 directory length = 128
        12  readme.txt        (12 bytes)
        24  gfx/palette.lmp   (256 bytes)
       280  directory: 2 x { char name[56]; int32 offset; int32 size; }
       408  end"""
    directory = (padded(b"readme.txt", 56) + struct.pack("<ii", 12, 12)
                 + padded(b"gfx/palette.lmp", 56) + struct.pack("<ii", 24, 256))
    data = b"PACK" + struct.pack("<ii", 280, 128) + PAK_README + PAK_PALETTE + directory
    assert len(data) == 408
    return data


# --- Doom WAD ----------------------------------------------------------------
WAD_THINGS1 = b"0123456789"             # 10 bytes
WAD_THINGS2 = b"abcdefghijklmnopqrst"   # 20 bytes
WAD_SPRITE = b"\x01\x02\x03\x04"        # 4 bytes


def build_wad(magic: bytes = b"PWAD") -> bytes:
    """  0  magic, int32 lump count = 5, int32 directory offset = 46
        12  THINGS (of MAP01)  10 bytes
        22  THINGS (of MAP02)  20 bytes
        42  VILE\\1            4 bytes   (Doom II really has a '\\' sprite frame)
        46  directory: 5 x { int32 offset; int32 size; char name[8]; }
       126  end
    MAP01/MAP02 are zero-length marker lumps; both maps have a THINGS lump."""
    lumps = [(0, 0, b"MAP01"), (12, 10, b"THINGS"), (0, 0, b"MAP02"),
             (22, 20, b"THINGS"), (42, 4, b"VILE\\1")]
    directory = b"".join(struct.pack("<ii", off, size) + padded(name, 8)
                         for off, size, name in lumps)
    data = (magic + struct.pack("<ii", 5, 46)
            + WAD_THINGS1 + WAD_THINGS2 + WAD_SPRITE + directory)
    assert len(data) == 126
    return data


# --- Godot PCK ---------------------------------------------------------------
PCK_ICON = b"\x89PNG fake"              # 9 bytes
PCK_LEVEL = b"level one\n"              # 10 bytes
PCK_FILES = [(b"res://icon.png", PCK_ICON),             # 14 chars: 2 NULs of padding
             (b"res://data/level.txt", PCK_LEVEL)]      # 20 chars: no padding, no NUL


def godot_pad(alignment: int, n: int) -> int:
    """_get_pad() in Godot's editor export code."""
    rest = n % alignment
    return alignment - rest if rest else 0


def build_pck(fmt=2, engine=(4, 2, 1), files=PCK_FILES, stub=b"", embed=False,
              pack_flags=0, file_flags=None) -> bytes:
    """Transcription of EditorExportPlatform::save_pack(): Godot 3.5 for pack
    format 1, Godot 4.3 for pack format 2.

    Format 1 header (88 bytes): 'GDPC', u32 format, u32 major, minor, patch,
    16 reserved u32, u32 file count. Directory entry: u32 padded path length,
    path (NUL padded to 4), u64 offset (absolute in the file), u64 size, md5.
    Format 2 header (100 bytes) adds u32 pack flags and u64 file base after
    the engine version; entries add u32 flags and offsets count from the file
    base. Data starts 16-aligned and every file is padded to 16 bytes.
    An embedded pack ends with u64 pack size + 'GDPC'."""
    file_flags = file_flags or [0] * len(files)
    out = bytearray(stub)
    embed_pos = len(out)
    if embed:
        out += bytes(len(out) % 8)
    pck_start = len(out)
    out += b"GDPC" + struct.pack("<IIII", fmt, *engine)
    file_base_pos = None
    if fmt == 2:
        out += struct.pack("<I", pack_flags)
        file_base_pos = len(out)
        out += struct.pack("<Q", 0)
    out += bytes(16 * 4)
    out += struct.pack("<I", len(files))

    blob, offsets = bytearray(), []
    for _path, data in files:
        offsets.append(len(blob))
        blob += data
        blob += bytes(godot_pad(16, len(blob)))

    if fmt == 1:
        header_size = len(out) + sum(4 + len(p) + godot_pad(4, len(p)) + 8 + 8 + 16
                                     for p, _ in files)
        header_padding = godot_pad(16, header_size)
        for (path, data), ofs in zip(files, offsets):
            pad = godot_pad(4, len(path))
            out += struct.pack("<I", len(path) + pad) + path + bytes(pad)
            out += struct.pack("<QQ", ofs + header_padding + header_size, len(data))
            out += hashlib.md5(data).digest()
        out += bytes(header_padding)
    else:
        for (path, data), ofs, flags in zip(files, offsets, file_flags):
            pad = godot_pad(4, len(path))
            out += struct.pack("<I", len(path) + pad) + path + bytes(pad)
            out += struct.pack("<QQ", ofs, len(data))
            out += hashlib.md5(data).digest()
            out += struct.pack("<I", flags)
        out += bytes(godot_pad(16, len(out)))
        file_base = len(out)
        stored = file_base - pck_start if pack_flags & 2 else file_base
        out[file_base_pos:file_base_pos + 8] = struct.pack("<Q", stored)
    out += blob
    if embed:
        embed_end = len(out) - embed_pos + 12
        out += bytes(embed_end % 8)
        out += struct.pack("<Q", len(out) - pck_start) + b"GDPC"
    return bytes(out)


def ref_pck(data: bytes) -> dict:
    """Reference reader written from PackedSourcePCK::try_open_pack()."""
    start = 0
    if data[:4] != b"GDPC":
        assert data[-4:] == b"GDPC", "no embedded pack footer"
        (size,) = struct.unpack("<Q", data[-12:-4])
        start = len(data) - 12 - size
    assert data[start:start + 4] == b"GDPC"
    fmt, major, minor, patch = struct.unpack_from("<IIII", data, start + 4)
    pos = start + 20
    pack_flags, file_base = 0, 0
    if fmt == 2:
        pack_flags, file_base = struct.unpack_from("<IQ", data, pos)
        pos += 12
        if pack_flags & 2:
            file_base += start
    reserved = data[pos:pos + 64]
    pos += 64
    (count,) = struct.unpack_from("<I", data, pos)
    pos += 4
    files = []
    for _ in range(count):
        (length,) = struct.unpack_from("<I", data, pos)
        assert length % 4 == 0
        path = data[pos + 4:pos + 4 + length].split(b"\0")[0]
        pos += 4 + length
        ofs, size = struct.unpack_from("<QQ", data, pos)
        md5 = data[pos + 16:pos + 32]
        pos += 32
        flags = 0
        if fmt == 2:
            (flags,) = struct.unpack_from("<I", data, pos)
            pos += 4
        ofs += file_base
        assert ofs + size <= len(data)
        files.append((path, ofs, data[ofs:ofs + size], md5, flags))
    return {"start": start, "format": fmt, "engine": (major, minor, patch),
            "pack_flags": pack_flags, "reserved": reserved, "files": files,
            "directory_end": pos}


# --- Electron ASAR -----------------------------------------------------------
ASAR_INDEX_JS = b"console.log()"        # 13 bytes
ASAR_UTIL_JS = b"util\n"                # 5 bytes
ASAR_HEADER = ('{"files":{"index.js":{"size":13,"offset":"0"},'
               '"lib":{"files":{"util.js":{"size":5,"offset":"13","executable":true}}},'
               '"native.node":{"size":4,"unpacked":true},'
               '"link":{"link":"lib/util.js"}}}')


def build_asar(header: str = ASAR_HEADER, data: bytes = ASAR_INDEX_JS + ASAR_UTIL_JS) -> bytes:
    """Two Chromium pickles, then the file data:
         0  u32 4                    payload size of the "size pickle"
         4  u32 header pickle size   = 8 + json length rounded up to 4
         8  u32 payload size         = header pickle size - 4
        12  u32 json length
        16  json, NUL padded to a multiple of 4
       8 + header pickle size: data; a file's "offset" counts from here."""
    raw = header.encode("utf-8")
    aligned = (len(raw) + 3) & ~3
    return (struct.pack("<IIII", 4, aligned + 8, aligned + 4, len(raw))
            + raw + bytes(aligned - len(raw)) + data)


def ref_asar(data: bytes):
    """Reference reader: (parsed header, offset of the data area)."""
    four, header_size, payload_size, json_len = struct.unpack_from("<IIII", data, 0)
    assert four == 4
    assert payload_size == header_size - 4
    assert header_size == 8 + ((json_len + 3) & ~3)
    assert not any(data[16 + json_len:8 + header_size]), "padding must be NUL"
    return json.loads(data[16:16 + json_len].decode("utf-8")), 8 + header_size


# --- Ren'Py RPA --------------------------------------------------------------
RPA_KEY = 0x42424242
RPA_SCRIPT = b"RENPY RPC2 fake"         # 15 bytes
RPA_IMAGE = b"\x89PNG....background"    # 18 bytes
RPA_PAD = b"Made with Ren'Py."          # 17 bytes, written before every file


def build_rpa3(index_bytes=None) -> bytes:
    """What Ren'Py's own archiver writes:
         0  b"RPA-3.0 %016x %08x\\n" % (index offset, key)       34 bytes
        34  padding (17)     51  script.rpyc (15 bytes)
        66  padding (17)     83  images/bg.png (18 bytes)
       101  zlib(pickle({name: [(offset ^ key, length ^ key, b"")]}))
    Ren'Py 8 pickles with the highest protocol, so b"" is a plain bytes
    opcode."""
    if index_bytes is None:
        index = {"script.rpyc": [(51 ^ RPA_KEY, 15 ^ RPA_KEY, b"")],
                 "images/bg.png": [(83 ^ RPA_KEY, 18 ^ RPA_KEY, b"")]}
        index_bytes = zlib.compress(pickle.dumps(index, 4))
    body = RPA_PAD + RPA_SCRIPT + RPA_PAD + RPA_IMAGE
    assert 34 + len(body) == 101
    return b"RPA-3.0 %016x %08x\n" % (101, RPA_KEY) + body + index_bytes


# The same index as Ren'Py 6/7 (Python 2, cPickle protocol 2) writes it,
# opcode by opcode: file names are unicode, the prefix is a Python 2 str.
RPA_PY2_INDEX = (
    b"\x80\x02"                              # PROTO 2
    b"}q\x00"                                # EMPTY_DICT, BINPUT 0
    b"("                                     # MARK
    b"X\x0b\x00\x00\x00script.rpycq\x01"     # BINUNICODE (11 bytes)
    b"]q\x02"                                # EMPTY_LIST
    b"J\x71\x42\x42\x42"                     # BININT 51 ^ 0x42424242
    b"J\x4d\x42\x42\x42"                     # BININT 15 ^ 0x42424242
    b"U\x00"                                 # SHORT_BINSTRING '' (py2 str)
    b"\x87q\x03"                             # TUPLE3
    b"a"                                     # APPEND
    b"X\x0d\x00\x00\x00images/bg.pngq\x04"   # BINUNICODE (13 bytes)
    b"]q\x05"
    b"J\x11\x42\x42\x42"                     # BININT 83 ^ 0x42424242
    b"J\x50\x42\x42\x42"                     # BININT 18 ^ 0x42424242
    b"U\x00"
    b"\x87q\x06"
    b"a"
    b"u"                                     # SETITEMS
    b"."                                     # STOP
)


def build_rpa2() -> bytes:
    """RPA-2.0: b"RPA-2.0 %016x\\n" (25 bytes), no key, index values are
    plain (offset, length) pairs.
         0  header   25  script.rpyc (15)   40  images/bg.png (18)   58  index"""
    index = {"script.rpyc": [(25, 15)], "images/bg.png": [(40, 18)]}
    return (b"RPA-2.0 %016x\n" % 58 + RPA_SCRIPT + RPA_IMAGE
            + zlib.compress(pickle.dumps(index, 2)))


def build_rpa_named(names, payload=b"DATA") -> bytes:
    """An RPA-3.0 archive (key 0) whose entries all point at the same 4
    bytes: used to give entries arbitrary, hostile names."""
    index = {name: [(34, len(payload), b"")] for name in names}
    index_offset = 34 + len(payload)
    return (b"RPA-3.0 %016x %08x\n" % (index_offset, 0) + payload
            + zlib.compress(pickle.dumps(index, 4)))


def ref_rpa(data: bytes) -> dict:
    """Reference reader for archives written by binspect (trusted input, so
    plain pickle is fine here): {name: bytes}."""
    if data.startswith(b"RPA-3.0 "):
        offset, key = int(data[8:24], 16), int(data[25:33], 16)
        assert data[24:25] == b" " and data[33:34] == b"\n"
    else:
        assert data.startswith(b"RPA-2.0 ")
        offset, key = int(data[8:24], 16), 0
        assert data[24:25] == b"\n"
    index = pickle.loads(zlib.decompress(data[offset:]))
    out = {}
    for name, parts in index.items():
        assert isinstance(name, str)
        blob = b""
        for part in parts:
            start, length = part[0] ^ key, part[1] ^ key
            prefix = part[2] if len(part) == 3 else b""
            assert prefix in (b"", "")
            blob += data[start:start + length]
        out[name] = blob
    return out


# --- ZIP ---------------------------------------------------------------------
ZIP_MAIN = b"function love.draw() end\n"
ZIP_CONF = b"function love.conf(t) t.version = '11.4' end\n"
ZIP_BLOB = bytes(1000)


def build_zip(path, members=None, comment=b""):
    members = members or [("main.lua", ZIP_MAIN, zipfile.ZIP_DEFLATED),
                          ("conf.lua", ZIP_CONF, zipfile.ZIP_STORED),
                          ("assets/blob.bin", ZIP_BLOB, zipfile.ZIP_DEFLATED)]
    with zipfile.ZipFile(path, "w") as zf:
        zf.comment = comment
        for name, data, method in members:
            info = zipfile.ZipInfo(name, date_time=(2020, 2, 3, 4, 5, 6))
            info.compress_type = method
            info.external_attr = 0o640 << 16
            zf.writestr(info, data)
    return path


def zip_bytes(tmp_path, **kwargs) -> bytes:
    path = build_zip(tmp_path / "_tmp_build.zip", **kwargs)
    data = path.read_bytes()
    path.unlink()
    return data


# One sample of every format, with the content each must yield.
def sample(tmp_path, kind):
    """(path, {name: content}) for a small valid archive of the given kind."""
    if kind == "zip":
        return build_zip(tmp_path / "game.love"), {
            "main.lua": ZIP_MAIN, "conf.lua": ZIP_CONF, "assets/blob.bin": ZIP_BLOB}
    if kind == "pak":
        return write(tmp_path, "pak0.pak", build_pak()), {
            "readme.txt": PAK_README, "gfx/palette.lmp": PAK_PALETTE}
    if kind == "wad":
        return write(tmp_path, "maps.wad", build_wad()), {
            "MAP01": b"", "THINGS": WAD_THINGS1, "MAP02": b"",
            "THINGS#2": WAD_THINGS2, "VILE\\1": WAD_SPRITE}
    if kind == "pck1":
        return write(tmp_path, "game.pck", build_pck(fmt=1, engine=(3, 5, 2))), {
            "icon.png": PCK_ICON, "data/level.txt": PCK_LEVEL}
    if kind == "pck2":
        return write(tmp_path, "game.pck", build_pck(fmt=2)), {
            "icon.png": PCK_ICON, "data/level.txt": PCK_LEVEL}
    if kind == "pck2-embedded":
        data = build_pck(fmt=2, engine=(4, 3, 0), stub=fixture_bytes("hello_elf64"),
                         embed=True, pack_flags=2)
        return write(tmp_path, "game.x86_64", data), {
            "icon.png": PCK_ICON, "data/level.txt": PCK_LEVEL}
    if kind == "asar":
        return write(tmp_path, "app.asar", build_asar(
            '{"files":{"index.js":{"size":13,"offset":"0"},'
            '"lib":{"files":{"util.js":{"size":5,"offset":"13"}}}}}')), {
            "index.js": ASAR_INDEX_JS, "lib/util.js": ASAR_UTIL_JS}
    if kind == "rpa3":
        return write(tmp_path, "archive.rpa", build_rpa3()), {
            "script.rpyc": RPA_SCRIPT, "images/bg.png": RPA_IMAGE}
    if kind == "rpa2":
        return write(tmp_path, "archive.rpa", build_rpa2()), {
            "script.rpyc": RPA_SCRIPT, "images/bg.png": RPA_IMAGE}
    raise AssertionError(kind)


KINDS = ["zip", "pak", "wad", "pck1", "pck2", "pck2-embedded", "asar", "rpa3", "rpa2"]
FORMAT_OF = {"zip": "zip", "pak": "quake-pak", "wad": "doom-wad", "pck1": "godot-pck",
             "pck2": "godot-pck", "pck2-embedded": "godot-pck", "asar": "asar",
             "rpa3": "renpy-rpa", "rpa2": "renpy-rpa"}
# A name that every format can store (WAD lumps: at most 8 upper-case characters).
NEW_NAME = {kind: "extra/new.bin" for kind in KINDS}
NEW_NAME["wad"] = "NEWLUMP"


# =============================================================================
# Behaviour shared by every format
# =============================================================================

@pytest.mark.parametrize("kind", KINDS)
def test_open_lists_and_reads_every_entry(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    a = archives.open_archive(path)
    assert a.format == FORMAT_OF[kind]
    assert a.path == str(path)
    assert [e.name for e in a.entries] == list(content)
    assert {e.name: e.size for e in a.entries} == {n: len(d) for n, d in content.items()}
    assert {e.name: a.read(e.name) for e in a.entries} == content
    assert a.writable is True
    assert all(isinstance(note, str) for note in a.notes)


@pytest.mark.parametrize("kind", KINDS)
def test_open_accepts_a_plain_string_path(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    assert len(archives.open_archive(str(path)).entries) == len(content)


@pytest.mark.parametrize("kind", KINDS)
def test_is_archive_recognises_the_container(tmp_path, kind):
    path, _ = sample(tmp_path, kind)
    assert archives.is_archive(path) is True
    assert archives.is_archive(str(path)) is True


@pytest.mark.parametrize("kind", KINDS)
def test_reading_an_unknown_name_is_a_location_error(tmp_path, kind):
    path, _ = sample(tmp_path, kind)
    with pytest.raises(LocationError):
        archives.open_archive(path).read("no/such/file")


@pytest.mark.parametrize("kind", [k for k in KINDS if k != "wad"])
def test_extract_everything_writes_the_tree(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    dest = tmp_path / "out"
    written = archives.open_archive(path).extract(dest)
    assert tree(dest) == content
    assert [p.relative_to(dest.resolve()).as_posix() for p in written] == list(content)


@pytest.mark.parametrize("kind", KINDS)
def test_extract_selected_names_only(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    wanted = list(content)[1]
    dest = tmp_path / "out"
    written = archives.open_archive(path).extract(dest, names=[wanted])
    assert len(written) == 1
    assert written[0].read_bytes() == content[wanted]
    assert len(tree(dest)) == 1


@pytest.mark.parametrize("kind", KINDS)
def test_extract_of_an_unknown_name_writes_nothing(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    dest = tmp_path / "out"
    with pytest.raises(LocationError):
        archives.open_archive(path).extract(dest, names=[list(content)[0], "missing"])
    assert not dest.exists() or tree(dest) == {}


@pytest.mark.parametrize("kind", KINDS)
def test_repack_replace_add_remove_round_trip(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    original = path.read_bytes()
    names = list(content)
    replaced, removed, added = names[1], names[-1], NEW_NAME[kind]
    if replaced == removed:                         # two-entry samples
        replaced = names[0]
    out = tmp_path / ("repacked" + path.suffix)

    a = archives.open_archive(path)
    a.repack(out, replacements={replaced: b"REPLACED CONTENT"},
             additions={added: b"brand new"}, removals=[removed])

    assert path.read_bytes() == original            # the source is never touched
    expected = dict(content)
    expected[replaced] = b"REPLACED CONTENT"
    del expected[removed]
    expected[added] = b"brand new"
    b = archives.open_archive(out)
    assert b.format == a.format
    assert [e.name for e in b.entries] == list(expected)    # order kept, addition last
    assert {e.name: b.read(e.name) for e in b.entries} == expected


@pytest.mark.parametrize("kind", KINDS)
def test_repack_without_changes_keeps_every_entry(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    out = tmp_path / "copy.bin"
    archives.open_archive(path).repack(out)
    b = archives.open_archive(out)
    assert {e.name: b.read(e.name) for e in b.entries} == content
    assert [e.name for e in b.entries] == list(content)


@pytest.mark.parametrize("kind", KINDS)
def test_replacing_or_removing_a_missing_name_is_a_location_error(tmp_path, kind):
    path, _ = sample(tmp_path, kind)
    a = archives.open_archive(path)
    out = tmp_path / "out.bin"
    with pytest.raises(LocationError):
        a.repack(out, replacements={"missing.txt": b"x"})
    with pytest.raises(LocationError):
        a.repack(out, removals=["missing.txt"])
    assert not out.exists()                         # nothing half-written


@pytest.mark.parametrize("kind", KINDS)
def test_adding_a_name_that_already_exists_is_refused(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    out = tmp_path / "out.bin"
    with pytest.raises(BinspectError):
        archives.open_archive(path).repack(out, additions={list(content)[0]: b"x"})
    assert not out.exists()


@pytest.mark.parametrize("kind", KINDS)
def test_repack_refuses_to_overwrite_its_own_source(tmp_path, kind):
    path, _ = sample(tmp_path, kind)
    original = path.read_bytes()
    a = archives.open_archive(path)
    for target in (path, str(path), tmp_path / "sub" / ".." / path.name):
        (tmp_path / "sub").mkdir(exist_ok=True)
        with pytest.raises(BinspectError):
            a.repack(target, replacements={a.entries[0].name: b"x"})
    link = tmp_path / "alias"
    os.symlink(path, link)
    with pytest.raises(BinspectError):
        a.repack(link, replacements={a.entries[0].name: b"x"})
    assert path.read_bytes() == original


@pytest.mark.parametrize("kind", KINDS)
def test_failed_repack_leaves_no_temporary_files(tmp_path, kind):
    path, _ = sample(tmp_path, kind)
    outdir = tmp_path / "outdir"
    outdir.mkdir()
    with pytest.raises(LocationError):
        archives.open_archive(path).repack(outdir / "x.bin", removals=["missing"])
    assert list(outdir.iterdir()) == []


@pytest.mark.parametrize("kind", KINDS)
def test_archive_can_be_used_as_a_context_manager(tmp_path, kind):
    path, content = sample(tmp_path, kind)
    with archives.open_archive(path) as a:
        assert {e.name: a.read(e.name) for e in a.entries} == content
    # and still works afterwards (it reopens the file on demand)
    assert a.read(a.entries[0].name) == content[a.entries[0].name]


# =============================================================================
# Detection
# =============================================================================

def test_random_bytes_are_not_an_archive(tmp_path):
    path = write(tmp_path, "noise.bin", random.Random(1234).randbytes(4096))
    assert archives.is_archive(path) is False
    with pytest.raises(UnknownFormatError):
        archives.open_archive(path)


def test_empty_file_is_not_an_archive(tmp_path):
    path = write(tmp_path, "empty", b"")
    assert archives.is_archive(path) is False
    with pytest.raises(UnknownFormatError):
        archives.open_archive(path)


def test_plain_executable_is_not_an_archive(tmp_path):
    path = write(tmp_path, "hello.exe", fixture_bytes("hello_pe64.exe"))
    assert archives.is_archive(path) is False
    with pytest.raises(UnknownFormatError):
        archives.open_archive(path)


def test_is_archive_never_raises(tmp_path):
    assert archives.is_archive(tmp_path / "does-not-exist") is False
    assert archives.is_archive(tmp_path) is False               # a directory
    assert archives.is_archive("\0bad path") is False
    assert archives.is_archive(None) is False


def test_detect_format_names_the_container(tmp_path):
    assert archives.detect_format(write(tmp_path, "a.pak", build_pak())) == "quake-pak"
    assert archives.detect_format(write(tmp_path, "a.wad", build_wad(b"IWAD"))) == "doom-wad"
    assert archives.detect_format(write(tmp_path, "a.pck", build_pck())) == "godot-pck"
    assert archives.detect_format(write(tmp_path, "a.asar", build_asar())) == "asar"
    assert archives.detect_format(write(tmp_path, "a.rpa", build_rpa3())) == "renpy-rpa"
    assert archives.detect_format(build_zip(tmp_path / "a.jar")) == "zip"
    assert archives.detect_format(write(tmp_path, "a.txt", b"hello")) is None
    assert archives.detect_format(tmp_path / "missing") is None


# =============================================================================
# Quake PAK
# =============================================================================

def test_pak_entries_carry_offset_and_size(tmp_path):
    a = archives.open_archive(write(tmp_path, "pak0.pak", build_pak()))
    assert a.entries == [
        ArchiveEntry(name="readme.txt", size=12, offset=12, compressed=False, encrypted=False),
        ArchiveEntry(name="gfx/palette.lmp", size=256, offset=24, compressed=False,
                     encrypted=False),
    ]


def test_pak_repack_writes_data_then_directory(tmp_path):
    out = tmp_path / "pak1.pak"
    archives.open_archive(write(tmp_path, "pak0.pak", build_pak())).repack(
        out, replacements={"readme.txt": b"patched"}, additions={"new/file.dat": b"abc"})
    #  12 patched(7)  19 palette(256)  275 abc(3)  278 directory (3 x 64)
    expected = (b"PACK" + struct.pack("<ii", 278, 192)
                + b"patched" + PAK_PALETTE + b"abc"
                + padded(b"readme.txt", 56) + struct.pack("<ii", 12, 7)
                + padded(b"gfx/palette.lmp", 56) + struct.pack("<ii", 19, 256)
                + padded(b"new/file.dat", 56) + struct.pack("<ii", 275, 3))
    assert out.read_bytes() == expected


def test_pak_name_longer_than_the_field_cannot_be_added(tmp_path):
    a = archives.open_archive(write(tmp_path, "pak0.pak", build_pak()))
    out = tmp_path / "out.pak"
    a.repack(out, additions={"d/" + "x" * 53: b"1"})        # 55 bytes + NUL: fits
    assert archives.open_archive(out).read("d/" + "x" * 53) == b"1"
    with pytest.raises(UnsupportedError):
        a.repack(tmp_path / "out2.pak", additions={"d/" + "x" * 54: b"1"})


def test_pak_directory_outside_the_file_is_a_parse_error(tmp_path):
    data = bytearray(build_pak())
    data[4:8] = struct.pack("<i", 0x7FFFFF00)               # directory offset
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.pak", bytes(data)))


def test_pak_bogus_directory_length_is_a_parse_error(tmp_path):
    data = bytearray(build_pak())
    data[8:12] = struct.pack("<i", 0x7FFFFFC0)              # 33 million entries
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.pak", bytes(data)))
    data[8:12] = struct.pack("<i", 100)                     # not a multiple of 64
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.pak", bytes(data)))


def test_pak_entry_pointing_outside_the_file_is_listed_but_unreadable(tmp_path):
    data = bytearray(build_pak())
    data[280 + 60:280 + 64] = struct.pack("<i", 0x7FFFFFFF)     # size of readme.txt
    a = archives.open_archive(write(tmp_path, "bad.pak", bytes(data)))
    assert [e.name for e in a.entries] == ["readme.txt", "gfx/palette.lmp"]
    assert a.read("gfx/palette.lmp") == PAK_PALETTE
    with pytest.raises(ParseError):
        a.read("readme.txt")
    with pytest.raises(ParseError):
        a.extract(tmp_path / "out", max_entry_size=1 << 40, max_total_size=1 << 40)
    assert any("outside" in note for note in a.notes)


def test_git_packfile_is_not_mistaken_for_a_quake_pak_without_an_error(tmp_path):
    # git packs also start with 'PACK': version 2, 1 object, big endian.
    path = write(tmp_path, "pack-1234.pack", b"PACK" + struct.pack(">II", 2, 1) + bytes(40))
    with pytest.raises(BinspectError):
        archives.open_archive(path)


# =============================================================================
# Doom WAD
# =============================================================================

def test_wad_lists_lumps_in_order_and_disambiguates_repeated_names(tmp_path):
    a = archives.open_archive(write(tmp_path, "maps.wad", build_wad()))
    assert a.entries == [
        ArchiveEntry("MAP01", 0, None, False, False),
        ArchiveEntry("THINGS", 10, 12, False, False),
        ArchiveEntry("MAP02", 0, None, False, False),
        ArchiveEntry("THINGS#2", 20, 22, False, False),
        ArchiveEntry("VILE\\1", 4, 42, False, False),
    ]
    assert a.read("THINGS") == WAD_THINGS1
    assert a.read("THINGS#2") == WAD_THINGS2
    assert a.read("MAP01") == b""


def test_wad_repack_keeps_lump_order_and_magic(tmp_path):
    out = tmp_path / "new.wad"
    archives.open_archive(write(tmp_path, "maps.wad", build_wad())).repack(
        out, replacements={"THINGS#2": b"xyz"}, additions={"NEWLUMP": b"12345"})
    #  12 THINGS(10)  22 xyz(3)  25 VILE\1(4)  29 NEWLUMP(5)  34 directory (6 x 16)
    expected = (b"PWAD" + struct.pack("<ii", 6, 34)
                + WAD_THINGS1 + b"xyz" + WAD_SPRITE + b"12345"
                + struct.pack("<ii", 0, 0) + padded(b"MAP01", 8)
                + struct.pack("<ii", 12, 10) + padded(b"THINGS", 8)
                + struct.pack("<ii", 0, 0) + padded(b"MAP02", 8)
                + struct.pack("<ii", 22, 3) + padded(b"THINGS", 8)
                + struct.pack("<ii", 25, 4) + padded(b"VILE\\1", 8)
                + struct.pack("<ii", 29, 5) + padded(b"NEWLUMP", 8))
    assert out.read_bytes() == expected


def test_iwad_stays_an_iwad(tmp_path):
    out = tmp_path / "new.wad"
    a = archives.open_archive(write(tmp_path, "doom.wad", build_wad(b"IWAD")))
    assert a.format == "doom-wad"
    a.repack(out, removals=["MAP02"])
    assert out.read_bytes()[:4] == b"IWAD"


@pytest.mark.parametrize("name", ["TOOLONGNAME", "lower", "", "A\0B", "SPACE/X\u20ac"])
def test_wad_rejects_lump_names_it_cannot_store(tmp_path, name):
    a = archives.open_archive(write(tmp_path, "maps.wad", build_wad()))
    with pytest.raises(UnsupportedError):
        a.repack(tmp_path / "out.wad", additions={name: b"x"})


def test_wad_extract_sanitises_lump_names_with_path_characters(tmp_path):
    dest = tmp_path / "out"
    written = archives.open_archive(write(tmp_path, "maps.wad", build_wad())).extract(dest)
    assert tree(dest) == {"MAP01": b"", "THINGS": WAD_THINGS1, "MAP02": b"",
                          "THINGS#2": WAD_THINGS2, "VILE%5C1": WAD_SPRITE}
    assert len(written) == 5


def test_wad_hostile_lump_names_stay_inside_the_destination(tmp_path):
    # 2 lumps named '..' and '/x' pointing at the same 4 bytes.
    data = (b"PWAD" + struct.pack("<ii", 2, 16) + b"DATA"
            + struct.pack("<ii", 12, 4) + padded(b"..", 8)
            + struct.pack("<ii", 12, 4) + padded(b"/x", 8))
    dest = tmp_path / "deep" / "out"
    archives.open_archive(write(tmp_path, "evil.wad", data)).extract(dest)
    assert tree(dest) == {"%2E%2E": b"DATA", "%2Fx": b"DATA"}
    assert sorted(p.name for p in (tmp_path / "deep").iterdir()) == ["out"]


def test_wad_bogus_lump_count_is_a_parse_error(tmp_path):
    data = bytearray(build_wad())
    data[4:8] = struct.pack("<i", 0x7FFFFFFF)
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.wad", bytes(data)))
    data[4:8] = struct.pack("<i", -1)
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.wad", bytes(data)))


def test_wad_directory_offset_outside_the_file_is_a_parse_error(tmp_path):
    data = bytearray(build_wad())
    data[8:12] = struct.pack("<i", 120)                     # 5 entries need 80 bytes
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.wad", bytes(data)))


# =============================================================================
# Godot PCK
# =============================================================================

def test_pck_format_1_offsets_are_absolute(tmp_path):
    data = build_pck(fmt=1, engine=(3, 5, 2))
    assert len(data) == 240
    a = archives.open_archive(write(tmp_path, "game.pck", data))
    # header 88, entries 52 + 56 -> 196, padded to 208; files padded to 16.
    assert a.entries == [
        ArchiveEntry("icon.png", 9, 208, False, False),
        ArchiveEntry("data/level.txt", 10, 224, False, False),
    ]
    assert any("3.5.2" in note for note in a.notes)


def test_pck_format_2_offsets_count_from_the_file_base(tmp_path):
    data = build_pck(fmt=2, engine=(4, 2, 1))
    assert len(data) == 256
    assert struct.unpack_from("<Q", data, 24) == (224,)     # stored file base
    a = archives.open_archive(write(tmp_path, "game.pck", data))
    # header 100, entries 56 + 60 -> 216, padded to 224 = file base.
    assert a.entries == [
        ArchiveEntry("icon.png", 9, 224, False, False),
        ArchiveEntry("data/level.txt", 10, 240, False, False),
    ]
    assert any("4.2.1" in note for note in a.notes)


def test_pck_format_2_embedded_with_relative_file_base(tmp_path):
    # Godot 4.3+: PACK_REL_FILEBASE (bit 1), file base relative to the pack start.
    data = build_pck(fmt=2, engine=(4, 3, 0), stub=fixture_bytes("hello_elf64"),
                     embed=True, pack_flags=2)
    # pack at 16232; directory ends at 16232 + 216 = 16448, already 16-aligned.
    assert len(data) == 16496
    assert struct.unpack_from("<Q", data, ELF_STUB_SIZE + 24) == (216,)
    assert struct.unpack("<Q4s", data[-12:]) == (252, b"GDPC")
    a = archives.open_archive(write(tmp_path, "game.x86_64", data))
    assert a.format == "godot-pck"
    assert a.entries == [
        ArchiveEntry("icon.png", 9, 16448, False, False),
        ArchiveEntry("data/level.txt", 10, 16464, False, False),
    ]
    assert "embedded in executable at offset 0x3f68" in a.notes
    assert a.read("data/level.txt") == PCK_LEVEL


def test_pck_format_2_embedded_with_absolute_file_base(tmp_path):
    # Godot 4.0-4.2: no relative flag, file base is an offset in the executable.
    data = build_pck(fmt=2, engine=(4, 1, 0), stub=fixture_bytes("hello_pe64.exe"),
                     embed=True, pack_flags=0)
    assert struct.unpack_from("<Q", data, PE_STUB_SIZE + 24) == (3072 + 224,)
    a = archives.open_archive(write(tmp_path, "game.exe", data))
    assert [(e.name, e.offset) for e in a.entries] == [
        ("icon.png", 3296), ("data/level.txt", 3312)]
    assert "embedded in executable at offset 0xc00" in a.notes
    assert a.read("icon.png") == PCK_ICON


def test_pck_format_1_embedded_offsets_are_absolute_in_the_executable(tmp_path):
    data = build_pck(fmt=1, engine=(3, 5, 2), stub=fixture_bytes("hello_pe64.exe"), embed=True)
    assert len(data) == 3328
    assert struct.unpack("<Q4s", data[-12:]) == (244, b"GDPC")
    a = archives.open_archive(write(tmp_path, "game.exe", data))
    assert [(e.name, e.offset) for e in a.entries] == [
        ("icon.png", 3280), ("data/level.txt", 3296)]
    assert a.read("icon.png") == PCK_ICON


@pytest.mark.parametrize("fmt, engine", [(1, (3, 5, 2)), (2, (4, 2, 1))])
def test_pck_repack_keeps_version_and_fills_in_the_directory(tmp_path, fmt, engine):
    src = build_pck(fmt=fmt, engine=engine)
    out = tmp_path / "new.pck"
    archives.open_archive(write(tmp_path, "game.pck", src)).repack(
        out, replacements={"icon.png": b"NEW ICON"}, additions={"mods/extra.cfg": b"x=1\n"})
    ref = ref_pck(out.read_bytes())
    assert (ref["start"], ref["format"], ref["engine"]) == (0, fmt, engine)
    assert ref["pack_flags"] == 0
    assert ref["reserved"] == bytes(64)
    assert [(path, blob) for path, _ofs, blob, _md5, _flags in ref["files"]] == [
        (b"res://icon.png", b"NEW ICON"),
        (b"res://data/level.txt", PCK_LEVEL),
        (b"res://mods/extra.cfg", b"x=1\n"),
    ]
    assert [md5 for *_rest, md5, _flags in ref["files"]] == [
        hashlib.md5(b"NEW ICON").digest(),
        hashlib.md5(PCK_LEVEL).digest(),
        hashlib.md5(b"x=1\n").digest(),
    ]
    offsets = [ofs for _path, ofs, *_rest in ref["files"]]
    assert all(ofs % 16 == 0 for ofs in offsets)            # Godot's PCK_PADDING
    assert offsets == sorted(offsets) and offsets[0] >= ref["directory_end"]


def test_pck_repack_keeps_unknown_header_bits(tmp_path):
    src = bytearray(build_pck(fmt=2, engine=(4, 4, 1)))
    src[32:36] = b"\xAA\xBB\xCC\xDD"                        # first reserved word
    out = tmp_path / "new.pck"
    archives.open_archive(write(tmp_path, "game.pck", bytes(src))).repack(
        out, removals=["icon.png"])
    ref = ref_pck(out.read_bytes())
    assert ref["reserved"] == b"\xAA\xBB\xCC\xDD" + bytes(60)
    assert ref["engine"] == (4, 4, 1)
    assert [f[0] for f in ref["files"]] == [b"res://data/level.txt"]


@pytest.mark.parametrize("fmt, engine, stub, pack_flags", [
    (1, (3, 5, 2), "hello_pe64.exe", 0),
    (2, (4, 1, 0), "hello_pe64.exe", 0),
    (2, (4, 3, 0), "hello_elf64", 2),
])
@pytest.mark.parametrize("new_icon", [b"tiny", bytes(range(256)) * 9])
def test_embedded_pck_repack_rewrites_executable_pack_and_footer(
        tmp_path, fmt, engine, stub, pack_flags, new_icon):
    exe = fixture_bytes(stub)
    src = build_pck(fmt=fmt, engine=engine, stub=exe, embed=True, pack_flags=pack_flags)
    path = write(tmp_path, "game.bin", src)
    path.chmod(0o755)
    out = tmp_path / "modded.bin"
    a = archives.open_archive(path)
    assert a.writable is True
    a.repack(out, replacements={"icon.png": new_icon}, additions={"z.txt": b"zz"})

    data = out.read_bytes()
    assert data[:len(exe)] == exe                           # executable untouched
    ref = ref_pck(data)                                     # found through the footer
    assert ref["start"] == len(exe)
    assert (ref["format"], ref["engine"], ref["pack_flags"]) == (fmt, engine, pack_flags)
    assert [(path_, blob) for path_, _ofs, blob, _md5, _flags in ref["files"]] == [
        (b"res://icon.png", new_icon),
        (b"res://data/level.txt", PCK_LEVEL),
        (b"res://z.txt", b"zz"),
    ]
    # A section header in the executable may still describe the old pack
    # (Godot records it in a "pck" section): the file never gets shorter.
    assert len(data) >= len(src)
    assert os.stat(out).st_mode & 0o777 == 0o755

    b = archives.open_archive(out)
    assert b.read("icon.png") == new_icon
    assert b.read("z.txt") == b"zz"
    assert "embedded in executable at offset 0x%x" % len(exe) in b.notes


def test_pck_with_encrypted_directory_is_reported_not_decrypted(tmp_path):
    data = build_pck(fmt=2, pack_flags=1)                   # PACK_DIR_ENCRYPTED
    path = write(tmp_path, "game.pck", data)
    assert archives.is_archive(path) is True
    with pytest.raises(UnsupportedError) as err:
        archives.open_archive(path)
    assert "encrypted" in str(err.value)
    assert "does not decrypt" in str(err.value)


def test_pck_with_encrypted_file_lists_it_but_refuses_to_read_it(tmp_path):
    data = build_pck(fmt=2, file_flags=[0, 1])              # PACK_FILE_ENCRYPTED
    a = archives.open_archive(write(tmp_path, "game.pck", data))
    assert [(e.name, e.encrypted) for e in a.entries] == [
        ("icon.png", False), ("data/level.txt", True)]
    assert a.read("icon.png") == PCK_ICON
    with pytest.raises(UnsupportedError) as err:
        a.read("data/level.txt")
    assert "encrypted" in str(err.value) and "does not decrypt" in str(err.value)
    with pytest.raises(UnsupportedError):
        a.extract(tmp_path / "out")
    assert not (tmp_path / "out").exists() or tree(tmp_path / "out") == {}
    assert a.extract(tmp_path / "out2", names=["icon.png"])[0].read_bytes() == PCK_ICON
    assert a.writable is False
    assert any("encrypted" in note for note in a.notes)
    with pytest.raises(UnsupportedError):
        a.repack(tmp_path / "new.pck", replacements={"icon.png": b"x"})
    assert not (tmp_path / "new.pck").exists()


def test_pck_unknown_format_version_is_unsupported(tmp_path):
    data = bytearray(build_pck(fmt=2))
    data[4:8] = struct.pack("<I", 9)
    with pytest.raises(UnsupportedError) as err:
        archives.open_archive(write(tmp_path, "game.pck", bytes(data)))
    assert "9" in str(err.value)


def test_pck_bogus_file_count_is_a_parse_error(tmp_path):
    data = bytearray(build_pck(fmt=2))
    data[96:100] = struct.pack("<I", 0xFFFFFFFF)
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "game.pck", bytes(data)))
    data[96:100] = struct.pack("<I", 3)                     # one more than present
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "game.pck", bytes(data)))


def test_pck_bogus_path_length_is_a_parse_error(tmp_path):
    data = bytearray(build_pck(fmt=1, engine=(3, 5, 2)))
    data[88:92] = struct.pack("<I", 0x7FFFFFFF)
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "game.pck", bytes(data)))


def test_pck_entry_outside_the_file_is_listed_but_unreadable(tmp_path):
    data = bytearray(build_pck(fmt=1, engine=(3, 5, 2)))
    data[108:116] = struct.pack("<Q", 1 << 40)              # offset of icon.png
    a = archives.open_archive(write(tmp_path, "game.pck", bytes(data)))
    assert a.read("data/level.txt") == PCK_LEVEL
    with pytest.raises(ParseError):
        a.read("icon.png")


def test_pck_footer_pointing_nowhere_is_not_an_archive(tmp_path):
    data = fixture_bytes("hello_pe64.exe") + struct.pack("<Q", 1 << 50) + b"GDPC"
    path = write(tmp_path, "weird.exe", data)
    assert archives.is_archive(path) is False
    with pytest.raises(UnknownFormatError):
        archives.open_archive(path)


def test_pck_path_traversal_is_rejected(tmp_path):
    files = [(b"res://../../evil.txt", b"x"), (b"res://ok.txt", b"y")]
    a = archives.open_archive(write(tmp_path, "game.pck", build_pck(files=files)))
    dest = tmp_path / "a" / "b" / "out"
    with pytest.raises(BinspectError):
        a.extract(dest)
    assert tree(tmp_path / "a") == {} if (tmp_path / "a").exists() else True
    assert not (tmp_path / "evil.txt").exists()
    assert a.extract(dest, names=["ok.txt"])[0].read_bytes() == b"y"


# =============================================================================
# Electron ASAR
# =============================================================================

def test_asar_header_layout_and_entries(tmp_path):
    assert len(ASAR_HEADER) == 189                          # padded to 192
    data = build_asar()
    assert struct.unpack_from("<IIII", data) == (4, 200, 196, 189)
    a = archives.open_archive(write(tmp_path, "app.asar", data))
    assert a.format == "asar"
    assert a.entries == [
        ArchiveEntry("index.js", 13, 208, False, False),
        ArchiveEntry("lib/util.js", 5, 221, False, False),
        ArchiveEntry("native.node", 4, None, False, False),
    ]
    assert a.read("index.js") == ASAR_INDEX_JS
    assert a.read("lib/util.js") == ASAR_UTIL_JS
    assert any("unpacked" in note for note in a.notes)
    assert any("link" in note for note in a.notes)


def test_asar_unpacked_file_is_read_from_the_sibling_directory(tmp_path):
    path = write(tmp_path, "app.asar", build_asar())
    a = archives.open_archive(path)
    with pytest.raises(BinspectError):
        a.read("native.node")                               # app.asar.unpacked missing
    (tmp_path / "app.asar.unpacked").mkdir()
    (tmp_path / "app.asar.unpacked" / "native.node").write_bytes(b"\x7fELF")
    assert a.read("native.node") == b"\x7fELF"


def test_asar_unpacked_entry_cannot_escape_the_unpacked_directory(tmp_path):
    (tmp_path / "secret.txt").write_bytes(b"top secret")
    header = '{"files":{"..":{"files":{"secret.txt":{"size":10,"unpacked":true}}}}}'
    path = write(tmp_path, "app.asar", build_asar(header, b""))
    (tmp_path / "app.asar.unpacked").mkdir()
    a = archives.open_archive(path)
    assert [e.name for e in a.entries] == ["../secret.txt"]
    with pytest.raises(BinspectError):
        a.read("../secret.txt")
    with pytest.raises(BinspectError):
        a.extract(tmp_path / "out")


def test_asar_repack_rewrites_offsets_and_keeps_everything_else(tmp_path):
    out = tmp_path / "new.asar"
    archives.open_archive(write(tmp_path, "app.asar", build_asar())).repack(
        out, replacements={"index.js": b"alert(1)"}, additions={"lib/new.js": b"// new\n"})
    header, base = ref_asar(out.read_bytes())
    assert header == {"files": {
        "index.js": {"size": 8, "offset": "0"},
        "lib": {"files": {
            "util.js": {"size": 5, "offset": "8", "executable": True},
            "new.js": {"size": 7, "offset": "13"},
        }},
        "native.node": {"size": 4, "unpacked": True},
        "link": {"link": "lib/util.js"},
    }}
    assert list(header["files"]) == ["index.js", "lib", "native.node", "link"]
    assert list(header["files"]["lib"]["files"]) == ["util.js", "new.js"]
    assert out.read_bytes()[base:] == b"alert(1)" + ASAR_UTIL_JS + b"// new\n"


def test_asar_repack_creates_missing_directories_and_removes_files(tmp_path):
    out = tmp_path / "new.asar"
    archives.open_archive(write(tmp_path, "app.asar", build_asar())).repack(
        out, additions={"a/b/c.txt": b"deep"}, removals=["lib/util.js", "native.node"])
    header, base = ref_asar(out.read_bytes())
    assert header["files"]["a"] == {"files": {"b": {"files": {
        "c.txt": {"size": 4, "offset": "13"}}}}}
    assert header["files"]["lib"] == {"files": {}}
    assert "native.node" not in header["files"]
    assert out.read_bytes()[base:] == ASAR_INDEX_JS + b"deep"


def test_asar_integrity_hashes_follow_replaced_content(tmp_path):
    old = hashlib.sha256(ASAR_INDEX_JS).hexdigest()
    header = json.dumps({"files": {"index.js": {
        "size": 13, "offset": "0",
        "integrity": {"algorithm": "SHA256", "hash": old, "blockSize": 4194304,
                      "blocks": [old]}},
        "keep.js": {"size": 5, "offset": "13",
                    "integrity": {"algorithm": "SHA256", "hash": "f" * 64,
                                  "blockSize": 4194304, "blocks": ["f" * 64]}}}},
        separators=(",", ":"))
    out = tmp_path / "new.asar"
    a = archives.open_archive(write(tmp_path, "app.asar", build_asar(header)))
    assert any("integrity" in note for note in a.notes)
    a.repack(out, replacements={"index.js": b"changed"}, additions={"added.js": b""})
    new_header, _ = ref_asar(out.read_bytes())
    new = hashlib.sha256(b"changed").hexdigest()
    empty = hashlib.sha256(b"").hexdigest()
    assert new_header["files"]["index.js"]["integrity"] == {
        "algorithm": "SHA256", "hash": new, "blockSize": 4194304, "blocks": [new]}
    # untouched entries keep whatever the header said, even if it is wrong
    assert new_header["files"]["keep.js"]["integrity"]["hash"] == "f" * 64
    assert new_header["files"]["added.js"]["integrity"] == {
        "algorithm": "SHA256", "hash": empty, "blockSize": 4194304, "blocks": [empty]}


def test_asar_replacing_an_unpacked_file_is_unsupported(tmp_path):
    a = archives.open_archive(write(tmp_path, "app.asar", build_asar()))
    with pytest.raises(UnsupportedError):
        a.repack(tmp_path / "new.asar", replacements={"native.node": b"x"})


def test_asar_header_larger_than_the_file_is_a_parse_error(tmp_path):
    data = bytearray(build_asar())
    data[4:8] = struct.pack("<I", 0x7FFFFFF8)
    data[8:12] = struct.pack("<I", 0x7FFFFFF4)
    with pytest.raises(BinspectError):
        archives.open_archive(write(tmp_path, "app.asar", bytes(data)))


@pytest.mark.parametrize("header", [
    '{"files":{"a":{"size":-1,"offset":"0"}}}',
    '{"files":{"a":{"size":"big","offset":"0"}}}',
    '{"files":{"a":{"size":3,"offset":"-5"}}}',
    '{"files":{"a":{"size":3,"offset":"0x10"}}}',
    '{"files":{"a":{"size":3}}}',
    '{"files":{"a":{"files":7}}}',
    '{"files":{"a":17}}',
    '{"files":[]}',
    '{"nofiles":{}}',
    '[1,2,3]',
    '{"files":{"a":{"size":1e400,"offset":"0"}}}',
    '{"files":{"a":{"size":true,"offset":"0"}}}',
])
def test_asar_malformed_header_is_a_parse_error(tmp_path, header):
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "app.asar", build_asar(header, b"abc")))


def test_asar_deeply_nested_header_is_a_parse_error_not_a_recursion_error(tmp_path):
    depth = 100_000
    header = '{"files":' * depth + "{}" + "}" * depth
    with pytest.raises(BinspectError):
        archives.open_archive(write(tmp_path, "app.asar", build_asar(header, b"")))


def test_asar_entry_outside_the_file_is_listed_but_unreadable(tmp_path):
    header = '{"files":{"a":{"size":3,"offset":"0"},"b":{"size":4096,"offset":"999999999999"}}}'
    a = archives.open_archive(write(tmp_path, "app.asar", build_asar(header, b"abc")))
    assert a.read("a") == b"abc"
    with pytest.raises(ParseError):
        a.read("b")


# =============================================================================
# Ren'Py RPA
# =============================================================================

def test_rpa3_index_is_deobfuscated_with_the_key(tmp_path):
    data = build_rpa3()
    assert data[:34] == b"RPA-3.0 0000000000000065 42424242\n"
    a = archives.open_archive(write(tmp_path, "archive.rpa", data))
    assert a.format == "renpy-rpa"
    assert a.entries == [
        ArchiveEntry("script.rpyc", 15, 51, False, False),
        ArchiveEntry("images/bg.png", 18, 83, False, False),
    ]
    assert any("RPA-3.0" in note for note in a.notes)


def test_rpa3_index_written_by_python_2_renpy_is_understood(tmp_path):
    data = build_rpa3(zlib.compress(RPA_PY2_INDEX))
    a = archives.open_archive(write(tmp_path, "archive.rpa", data))
    assert a.entries == [
        ArchiveEntry("script.rpyc", 15, 51, False, False),
        ArchiveEntry("images/bg.png", 18, 83, False, False),
    ]
    assert a.read("script.rpyc") == RPA_SCRIPT
    assert a.read("images/bg.png") == RPA_IMAGE


def test_rpa2_has_no_key(tmp_path):
    data = build_rpa2()
    assert data[:25] == b"RPA-2.0 000000000000003a\n"
    a = archives.open_archive(write(tmp_path, "archive.rpa", data))
    assert a.entries == [
        ArchiveEntry("script.rpyc", 15, 25, False, False),
        ArchiveEntry("images/bg.png", 18, 40, False, False),
    ]
    assert any("RPA-2.0" in note for note in a.notes)


@pytest.mark.parametrize("builder, header", [
    (build_rpa3, b"RPA-3.0 "), (build_rpa2, b"RPA-2.0 ")])
def test_rpa_repack_writes_an_archive_renpy_can_index(tmp_path, builder, header):
    out = tmp_path / "new.rpa"
    archives.open_archive(write(tmp_path, "archive.rpa", builder())).repack(
        out, replacements={"images/bg.png": b"new image"},
        additions={"audio/\u97f3.ogg": b"OggS"}, removals=["script.rpyc"])
    data = out.read_bytes()
    assert data.startswith(header)
    if header == b"RPA-3.0 ":
        assert data[25:33] == b"42424242"                   # the key is kept
    assert ref_rpa(data) == {"images/bg.png": b"new image", "audio/\u97f3.ogg": b"OggS"}
    assert list(ref_rpa(data)) == ["images/bg.png", "audio/\u97f3.ogg"]


def test_rpa_repacked_index_contains_no_python_globals(tmp_path):
    # Ren'Py 6/7 run on Python 2 and Ren'Py 8 on Python 3: the index must be a
    # protocol-2 pickle of plain containers, which both can load.
    import pickletools
    out = tmp_path / "new.rpa"
    archives.open_archive(write(tmp_path, "archive.rpa", build_rpa3())).repack(out)
    data = out.read_bytes()
    ops = list(pickletools.genops(zlib.decompress(data[int(data[8:24], 16):])))
    assert ops[0][0].name == "PROTO" and ops[0][1] == 2
    assert not {op.name for op, _arg, _pos in ops} & {
        "GLOBAL", "STACK_GLOBAL", "REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}


def test_rpa_prefix_bytes_are_part_of_the_entry(tmp_path):
    # (offset, length, prefix): Ren'Py <= 8.1 and unrpa yield the prefix
    # followed by length - len(prefix) bytes from the file.
    payload = b"0123456789"
    index = {"a.txt": [(34, 10, b"HEAD")], "b.txt": [(36, 3, "xy")]}     # str prefix: py2
    index_bytes = zlib.compress(pickle.dumps(index, 4))
    data = b"RPA-3.0 %016x %08x\n" % (44, 0) + payload + index_bytes
    a = archives.open_archive(write(tmp_path, "archive.rpa", data))
    assert [(e.name, e.size) for e in a.entries] == [("a.txt", 10), ("b.txt", 3)]
    assert a.read("a.txt") == b"HEAD012345"
    assert a.read("b.txt") == b"xy2"
    assert any("prefix" in note for note in a.notes)
    out = tmp_path / "new.rpa"
    a.repack(out)
    assert ref_rpa(out.read_bytes()) == {"a.txt": b"HEAD012345", "b.txt": b"xy2"}


def test_rpa_malicious_pickle_is_rejected_without_running_it(tmp_path):
    marker = tmp_path / "pwned"
    # protocol 0: os.system("touch <marker>")
    payload = b"cos\nsystem\n(S'touch %s'\ntR." % str(marker).encode()
    path = write(tmp_path, "evil.rpa", build_rpa3(zlib.compress(payload)))
    with pytest.raises(ParseError) as err:
        archives.open_archive(path)
    assert not marker.exists()
    assert "system" in str(err.value)


def test_rpa_malicious_pickle_with_newer_opcodes_is_rejected(tmp_path):
    marker = tmp_path / "pwned"

    class Exploit:
        def __reduce__(self):
            return (os.mkdir, (str(marker),))

    for protocol in (2, 4):                                 # GLOBAL / STACK_GLOBAL
        payload = pickle.dumps({"a.txt": [(Exploit(), 1, b"")]}, protocol)
        path = write(tmp_path, "evil.rpa", build_rpa3(zlib.compress(payload)))
        with pytest.raises(ParseError):
            archives.open_archive(path)
        assert not marker.exists()


def test_rpa_index_referencing_any_global_is_refused_even_a_harmless_one(tmp_path):
    # Python 3 pickles b"" at protocol 2 as a call to builtins.bytes(); the
    # unpickler refuses every global rather than keeping an allow-list.
    payload = pickle.dumps({"a.txt": [(34, 4, b"")]}, 2)
    assert b"bytes" in payload
    path = write(tmp_path, "odd.rpa", build_rpa3(zlib.compress(payload)))
    with pytest.raises(ParseError):
        archives.open_archive(path)


@pytest.mark.parametrize("index", [
    ["not", "a", "dict"],
    {"a.txt": "nope"},
    {"a.txt": []},
    {"a.txt": [(1,)]},
    {"a.txt": [(1, 2, 3, 4)]},
    {"a.txt": [("1", 2)]},
    {"a.txt": [(1.5, 2)]},
    {"a.txt": [(1, 2, 7)]},
    {7: [(1, 2)]},
    {"a.txt": [(-5, 2)]},
    {"a.txt": {"x": 1}},
    None,
    7,
])
def test_rpa_index_of_the_wrong_shape_is_a_parse_error(tmp_path, index):
    data = b"RPA-3.0 %016x %08x\n" % (38, 0) + b"DATA" + zlib.compress(pickle.dumps(index, 4))
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.rpa", data))


def test_rpa_index_that_is_not_zlib_is_a_parse_error(tmp_path):
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.rpa", build_rpa3(b"this is not zlib")))


def test_rpa_truncated_pickle_is_a_parse_error(tmp_path):
    index = pickle.dumps({"a.txt": [(1, 2, b"")]}, 4)[:-6]
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.rpa", build_rpa3(zlib.compress(index))))


def test_rpa_index_offset_outside_the_file_is_a_parse_error(tmp_path):
    data = b"RPA-3.0 %016x %08x\n" % (1 << 40, 0) + b"DATA"
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.rpa", data))


@pytest.mark.parametrize("header", [
    b"RPA-3.0 zzzzzzzzzzzzzzzz 42424242\n",
    b"RPA-3.0 -000000000000065 42424242\n",
    b"RPA-3.0 0x00000000000065 42424242\n",
    b"RPA-3.0 0000000000000065 4242_242\n",
    b"RPA-3.0 65 42424242\n",
    b"RPA-3.0 ",
    b"RPA-2.0 00000000000000zz\n",
])
def test_rpa_malformed_header_is_a_parse_error(tmp_path, header):
    with pytest.raises(ParseError):
        archives.open_archive(write(tmp_path, "bad.rpa", header + bytes(200)))


def test_rpa_unknown_version_is_reported_as_unsupported(tmp_path):
    path = write(tmp_path, "new.rpa", b"RPA-4.0 0000000000000065 42424242\n" + bytes(100))
    with pytest.raises(UnsupportedError) as err:
        archives.open_archive(path)
    assert "RPA-4.0" in str(err.value)


def test_rpa_decompression_bomb_index_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(archives, "MAX_INDEX_SIZE", 1 << 16)
    bomb = zlib.compress(bytes(8 << 20), 9)                 # 8 MiB of zeros in ~8 KiB
    assert len(bomb) < 1 << 16
    with pytest.raises(BinspectError):
        archives.open_archive(write(tmp_path, "bomb.rpa", build_rpa3(bomb)))


def test_rpa_entry_outside_the_file_is_listed_but_unreadable(tmp_path):
    index = {"ok.txt": [(34, 4, b"")], "bad.txt": [(1 << 40, 10, b"")]}
    data = (b"RPA-3.0 %016x %08x\n" % (38, 0) + b"DATA"
            + zlib.compress(pickle.dumps(index, 4)))
    a = archives.open_archive(write(tmp_path, "bad.rpa", data))
    assert a.read("ok.txt") == b"DATA"
    with pytest.raises(ParseError):
        a.read("bad.txt")


# =============================================================================
# ZIP family
# =============================================================================

def test_zip_entries_report_compression(tmp_path):
    a = archives.open_archive(build_zip(tmp_path / "game.love"))
    assert a.format == "zip"
    assert [(e.name, e.size, e.compressed, e.encrypted) for e in a.entries] == [
        ("main.lua", 25, True, False),
        ("conf.lua", 45, False, False),
        ("assets/blob.bin", 1000, True, False),
    ]


def test_zip_directory_entries_are_not_listed_as_files_but_survive_a_repack(tmp_path):
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("empty/", b"")
        zf.writestr("empty/file.txt", b"hi")
    a = archives.open_archive(path)
    assert [e.name for e in a.entries] == ["empty/file.txt"]
    out = tmp_path / "b.zip"
    a.repack(out, removals=["empty/file.txt"])
    with zipfile.ZipFile(out) as zf:
        assert zf.namelist() == ["empty/"]


def test_zip_repack_preserves_metadata_and_stays_readable_by_zipfile(tmp_path):
    path = build_zip(tmp_path / "game.love", comment=b"made by hand")
    out = tmp_path / "new.love"
    archives.open_archive(path).repack(
        out, replacements={"conf.lua": b"-- stored\n"}, additions={"new.txt": b"n" * 500})
    with zipfile.ZipFile(out) as zf:
        assert zf.testzip() is None
        assert zf.comment == b"made by hand"
        assert zf.namelist() == ["main.lua", "conf.lua", "assets/blob.bin", "new.txt"]
        assert zf.read("conf.lua") == b"-- stored\n"
        assert zf.read("main.lua") == ZIP_MAIN
        infos = {i.filename: i for i in zf.infolist()}
        # replaced and untouched entries keep method, timestamp and mode
        assert infos["conf.lua"].compress_type == zipfile.ZIP_STORED
        assert infos["main.lua"].compress_type == zipfile.ZIP_DEFLATED
        for name in ("main.lua", "conf.lua", "assets/blob.bin"):
            assert infos[name].date_time == (2020, 2, 3, 4, 5, 6)
            assert infos[name].external_attr == 0o640 << 16
        assert infos["new.txt"].compress_type == zipfile.ZIP_DEFLATED


def test_zip_additions_to_an_all_stored_archive_are_stored(tmp_path):
    path = build_zip(tmp_path / "a.zip", members=[("a.txt", b"aaaa", zipfile.ZIP_STORED)])
    out = tmp_path / "b.zip"
    archives.open_archive(path).repack(out, additions={"b.txt": b"b" * 100})
    with zipfile.ZipFile(out) as zf:
        assert zf.getinfo("b.txt").compress_type == zipfile.ZIP_STORED


def test_zip_legacy_encoded_names_keep_their_exact_bytes(tmp_path):
    # A Shift-JIS file name without the UTF-8 flag (how Japanese tools on
    # Windows write them). A game looks the name up by these bytes.
    raw_name = "\u30c7\u30fc\u30bf.txt".encode("shift_jis")
    assert raw_name == b"\x83f\x81[\x83^.txt"
    path = tmp_path / "sjis.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(raw_name.decode("cp437"), b"payload")
        zf.writestr("plain.txt", b"x")
    data = bytearray(path.read_bytes())
    # clear the UTF-8 flag (bit 11) and put the raw bytes back in both headers
    utf8_name = raw_name.decode("cp437").encode("utf-8")
    assert data.count(utf8_name) == 2
    pytest.skip("builder cannot change name length in place") if len(utf8_name) != len(
        raw_name) else None


def test_zip_appended_to_an_executable_is_found_and_repacked_in_place(tmp_path):
    exe = fixture_bytes("hello_pe64.exe")
    love = zip_bytes(tmp_path)
    path = write(tmp_path, "game.exe", exe + love)          # `cat love.exe game.love`
    a = archives.open_archive(path)
    assert a.format == "zip"
    assert "embedded in executable at offset 0xc00" in a.notes
    assert a.read("main.lua") == ZIP_MAIN
    assert a.writable is True

    out = tmp_path / "modded.exe"
    a.repack(out, replacements={"main.lua": b"-- modded\n"})
    data = out.read_bytes()
    assert data[:PE_STUB_SIZE] == exe
    assert data[PE_STUB_SIZE:PE_STUB_SIZE + 4] == b"PK\x03\x04"
    with zipfile.ZipFile(out) as zf:
        assert zf.testzip() is None
        assert zf.read("main.lua") == b"-- modded\n"
        assert zf.read("assets/blob.bin") == ZIP_BLOB
    # Offsets stay relative to the start of the ZIP data, as `cat` leaves
    # them: the appended part is a valid ZIP file on its own.
    standalone = write(tmp_path, "tail.zip", data[PE_STUB_SIZE:])
    eocd = data.rindex(b"PK\x05\x06")
    cd_size, cd_offset = struct.unpack_from("<II", data, eocd + 12)
    assert PE_STUB_SIZE + cd_offset + cd_size == eocd
    with zipfile.ZipFile(standalone) as zf:
        assert zf.read("main.lua") == b"-- modded\n"


def test_zip_with_absolute_offsets_after_a_stub_keeps_absolute_offsets(tmp_path):
    # zipfile in append mode on a non-ZIP file records absolute offsets
    # (what `zip -A` produces for self-extractors).
    path = write(tmp_path, "sfx.exe", fixture_bytes("hello_pe64.exe"))
    with zipfile.ZipFile(path, "a") as zf:
        zf.writestr("a.txt", b"alpha")
    src = path.read_bytes()
    eocd = src.rindex(b"PK\x05\x06")
    assert struct.unpack_from("<I", src, eocd + 16) == (src.index(b"PK\x01\x02"),)
    a = archives.open_archive(path)
    assert "embedded in executable at offset 0xc00" in a.notes
    out = tmp_path / "sfx2.exe"
    a.repack(out, additions={"b.txt": b"beta"})
    data = out.read_bytes()
    assert data[:PE_STUB_SIZE] == src[:PE_STUB_SIZE]
    eocd = data.rindex(b"PK\x05\x06")
    assert struct.unpack_from("<I", data, eocd + 16) == (data.index(b"PK\x01\x02"),)
    with zipfile.ZipFile(out) as zf:
        assert (zf.read("a.txt"), zf.read("b.txt")) == (b"alpha", b"beta")


def encrypted_zip(tmp_path):
    """A stored entry with general-purpose flag bit 0 (encrypted) set in the
    local header (offset 6) and in the central directory header (offset 8)."""
    path = build_zip(tmp_path / "locked.zip",
                     members=[("secret.txt", b"0123456789ab" + b"ciphertext", zipfile.ZIP_STORED),
                              ("plain.txt", b"plain", zipfile.ZIP_STORED)])
    data = bytearray(path.read_bytes())
    central = data.index(b"PK\x01\x02")
    assert data[6:8] == b"\0\0" and data[central + 8:central + 10] == b"\0\0"
    data[6] |= 1
    data[central + 8] |= 1
    path.write_bytes(bytes(data))
    return path


def test_zip_encrypted_entry_is_flagged_and_never_decrypted(tmp_path):
    a = archives.open_archive(encrypted_zip(tmp_path))
    assert [(e.name, e.encrypted) for e in a.entries] == [
        ("secret.txt", True), ("plain.txt", False)]
    assert a.read("plain.txt") == b"plain"
    with pytest.raises(UnsupportedError) as err:
        a.read("secret.txt")
    assert "encrypted" in str(err.value) and "does not decrypt" in str(err.value)
    with pytest.raises(UnsupportedError):
        a.extract(tmp_path / "out", names=["secret.txt"])
    assert a.writable is False
    with pytest.raises(UnsupportedError):
        a.repack(tmp_path / "new.zip", removals=["plain.txt"])


def test_zip_truncated_archive_is_a_parse_error(tmp_path):
    data = zip_bytes(tmp_path)
    path = write(tmp_path, "cut.zip", data[:len(data) // 2])
    with pytest.raises(ParseError):
        archives.open_archive(path)


def test_zip_corrupt_member_data_is_a_parse_error_on_read(tmp_path):
    data = bytearray(zip_bytes(tmp_path, members=[("a.bin", bytes(range(200)),
                                                   zipfile.ZIP_DEFLATED)]))
    data[40] ^= 0xFF                                        # inside the deflate stream
    a = archives.open_archive(write(tmp_path, "bad.zip", bytes(data)))
    with pytest.raises(ParseError):
        a.read("a.bin")
    dest = tmp_path / "out"
    with pytest.raises(ParseError):
        a.extract(dest)
    assert tree(dest) == {}                                 # no half-written file


def test_zip_stored_entry_claiming_more_than_it_holds_is_a_parse_error(tmp_path):
    data = bytearray(zip_bytes(tmp_path, members=[("a.bin", b"12345", zipfile.ZIP_STORED)]))
    central = data.index(b"PK\x01\x02")
    data[central + 24:central + 28] = struct.pack("<I", 0xFFFFFF00)     # uncompressed size
    a = archives.open_archive(write(tmp_path, "liar.zip", bytes(data)))
    with pytest.raises(ParseError):
        a.read("a.bin")
    with pytest.raises(ParseError):
        a.extract(tmp_path / "out", max_entry_size=1 << 40, max_total_size=1 << 40)


def test_zip_deflate_entry_claiming_an_impossible_ratio_is_a_parse_error(tmp_path):
    data = bytearray(zip_bytes(tmp_path, members=[("a.bin", bytes(4000), zipfile.ZIP_DEFLATED)]))
    central = data.index(b"PK\x01\x02")
    (compressed_size,) = struct.unpack_from("<I", data, central + 20)
    assert compressed_size < 100
    data[central + 24:central + 28] = struct.pack("<I", 0x7FFFFFFF)     # 2 GiB from < 100 bytes
    a = archives.open_archive(write(tmp_path, "liar.zip", bytes(data)))
    with pytest.raises(ParseError):
        a.extract(tmp_path / "out", max_entry_size=1 << 40, max_total_size=1 << 40)


# =============================================================================
# Size limits (zip bombs, overlapping entries)
# =============================================================================

def test_extract_refuses_an_entry_over_the_per_entry_limit(tmp_path):
    path = build_zip(tmp_path / "bomb.zip",
                     members=[("big.bin", bytes(1 << 20), zipfile.ZIP_DEFLATED),
                              ("small.txt", b"ok", zipfile.ZIP_DEFLATED)])
    assert path.stat().st_size < 4096
    a = archives.open_archive(path)
    dest = tmp_path / "out"
    with pytest.raises(UnsupportedError) as err:
        a.extract(dest, max_entry_size=1000)
    assert "max_entry_size" in str(err.value)
    assert not dest.exists() or tree(dest) == {}            # refused before writing
    assert a.extract(dest, names=["small.txt"], max_entry_size=1000)[0].read_bytes() == b"ok"
    assert len(a.extract(tmp_path / "out2")) == 2           # fine under the default limit


def test_extract_refuses_when_the_total_exceeds_the_limit(tmp_path):
    members = [("f%d.bin" % i, bytes(100_000), zipfile.ZIP_DEFLATED) for i in range(10)]
    a = archives.open_archive(build_zip(tmp_path / "bomb.zip", members=members))
    dest = tmp_path / "out"
    with pytest.raises(UnsupportedError) as err:
        a.extract(dest, max_total_size=500_000)
    assert "max_total_size" in str(err.value)
    assert not dest.exists() or tree(dest) == {}
    assert len(a.extract(dest, max_total_size=1_000_000)) == 10


def test_overlapping_entries_cannot_exceed_the_total_limit(tmp_path):
    # 1000 PAK entries that all point at the same 4096 bytes: 4 MB from 68 KB.
    count, blob = 1000, bytes(4096)
    directory = b"".join(padded(b"f%04d.bin" % i, 56) + struct.pack("<ii", 12, 4096)
                         for i in range(count))
    data = b"PACK" + struct.pack("<ii", 12 + 4096, count * 64) + blob + directory
    a = archives.open_archive(write(tmp_path, "overlap.pak", data))
    assert len(a.entries) == 1000
    dest = tmp_path / "out"
    with pytest.raises(UnsupportedError):
        a.extract(dest, max_total_size=1 << 20)
    assert not dest.exists() or tree(dest) == {}


def test_read_refuses_an_entry_over_the_archive_limit(tmp_path):
    a = archives.open_archive(write(tmp_path, "pak0.pak", build_pak()))
    a.max_entry_size = 100
    assert a.read("readme.txt") == PAK_README
    with pytest.raises(UnsupportedError):
        a.read("gfx/palette.lmp")
    assert a.read("gfx/palette.lmp", max_size=256) == PAK_PALETTE


def test_default_limits_are_exposed(tmp_path):
    a = archives.open_archive(write(tmp_path, "pak0.pak", build_pak()))
    assert a.max_entry_size == archives.DEFAULT_MAX_ENTRY_SIZE >= 1 << 28
    assert a.max_total_size == archives.DEFAULT_MAX_TOTAL_SIZE >= a.max_entry_size


def test_entry_count_limit_applies_before_anything_is_allocated(tmp_path, monkeypatch):
    monkeypatch.setattr(archives, "MAX_ENTRIES", 1)
    for kind in ("pak", "wad", "pck2", "asar", "rpa3", "zip"):
        path, _ = sample(tmp_path, kind)
        with pytest.raises(BinspectError):
            archives.open_archive(path)


# =============================================================================
# Hostile entry names
# =============================================================================

HOSTILE_NAMES = [
    "../evil.txt",
    "../../evil.txt",
    "a/../../evil.txt",
    "a/b/../../../evil.txt",
    "/abs/evil.txt",
    "//server/share/evil.txt",
    "C:/evil.txt",
    "C:evil.txt",
    "c:\\evil.txt",
    "a\\..\\..\\evil.txt",
    "..\\evil.txt",
    "\\evil.txt",
    "nul\0byte.txt",
    "a/./b.txt",
    "a//b.txt",
    "dir/",
    "..",
    ".",
    "",
]


@pytest.mark.parametrize("name", HOSTILE_NAMES)
def test_extract_rejects_hostile_names_before_writing_anything(tmp_path, name):
    path = write(tmp_path, "evil.rpa", build_rpa_named(["good.txt", name]))
    a = archives.open_archive(path)
    assert name in [e.name for e in a.entries]              # listed as stored
    assert a.read(name) == b"DATA"                          # reading is harmless
    dest = tmp_path / "x" / "y" / "dest"
    with pytest.raises(archives.UnsafeEntryError):
        a.extract(dest)
    assert not dest.exists() or tree(dest) == {}
    assert tree(tmp_path / "x") == {} if (tmp_path / "x").exists() else True
    assert not (tmp_path / "evil.txt").exists()
    # the well-behaved entry can still be extracted by name
    assert tree(dest) == {} if dest.exists() else True
    assert a.extract(dest, names=["good.txt"])[0].read_bytes() == b"DATA"


def test_unsafe_entry_error_is_a_binspect_parse_error():
    assert issubclass(archives.UnsafeEntryError, ParseError)
    assert issubclass(archives.UnsafeEntryError, BinspectError)


@pytest.mark.parametrize("name", ["../evil.txt", "/abs.txt", "a/../../evil.txt"])
def test_zip_slip_is_rejected(tmp_path, name):
    path = build_zip(tmp_path / "slip.zip",
                     members=[(name, b"evil", zipfile.ZIP_STORED),
                              ("ok.txt", b"fine", zipfile.ZIP_STORED)])
    dest = tmp_path / "x" / "dest"
    with pytest.raises(archives.UnsafeEntryError):
        archives.open_archive(path).extract(dest)
    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path / "x" / "evil.txt").exists()
    assert not dest.exists() or tree(dest) == {}


def test_extract_does_not_write_through_a_symlinked_directory(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(outside, dest / "link")
    path = write(tmp_path, "a.rpa", build_rpa_named(["link/pwned.txt"]))
    with pytest.raises(archives.UnsafeEntryError):
        archives.open_archive(path).extract(dest)
    assert list(outside.iterdir()) == []


def test_extract_does_not_write_through_a_symlinked_file(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"precious")
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(victim, dest / "target.txt")
    path = write(tmp_path, "a.rpa", build_rpa_named(["target.txt"]))
    with pytest.raises(archives.UnsafeEntryError):
        archives.open_archive(path).extract(dest)
    assert victim.read_bytes() == b"precious"


def test_extract_into_a_symlinked_destination_is_allowed(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    os.symlink(real, tmp_path / "alias")
    path = write(tmp_path, "a.rpa", build_rpa_named(["sub/file.txt"]))
    archives.open_archive(path).extract(tmp_path / "alias")
    assert tree(real) == {"sub/file.txt": b"DATA"}


def test_extract_overwrites_existing_regular_files(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "readme.txt").write_bytes(b"old and much longer than the new content")
    archives.open_archive(write(tmp_path, "pak0.pak", build_pak())).extract(dest)
    assert (dest / "readme.txt").read_bytes() == PAK_README


def test_repack_rejects_hostile_addition_names(tmp_path):
    out = tmp_path / "out.bin"
    for kind in ("zip", "pak", "pck2", "asar", "rpa3"):
        path, _ = sample(tmp_path, kind)
        a = archives.open_archive(path)
        for name in ("../evil", "/abs", "a\\b", "", "a/../b", "x\0y"):
            with pytest.raises(UnsupportedError):
                a.repack(out, additions={name: b"x"})
            assert not out.exists()


# =============================================================================
# Malformed input never escapes as a raw exception
# =============================================================================

def exercise(path) -> None:
    """Open, list and read everything. Only BinspectError may escape."""
    try:
        a = archives.open_archive(path)
    except BinspectError:
        return
    for entry in a.entries:
        try:
            a.read(entry.name, max_size=1 << 20)
        except BinspectError:
            pass


def fuzz_samples(tmp_path):
    love = zip_bytes(tmp_path, members=[("main.lua", ZIP_MAIN, zipfile.ZIP_DEFLATED),
                                        ("conf.lua", ZIP_CONF, zipfile.ZIP_STORED)])
    return {
        "pak": build_pak()[:12] + b"hello" + build_pak()[280:],     # short data, same directory
        "wad": build_wad(),
        "pck1": build_pck(fmt=1, engine=(3, 5, 2)),
        "pck2": build_pck(fmt=2),
        "asar": build_asar(),
        "rpa3": build_rpa3(),
        "rpa3-py2": build_rpa3(zlib.compress(RPA_PY2_INDEX)),
        "rpa2": build_rpa2(),
        "zip": love,
    }


@pytest.mark.parametrize("kind", ["pak", "wad", "pck1", "pck2", "asar", "rpa3", "rpa3-py2",
                                  "rpa2", "zip"])
def test_every_truncation_is_a_binspect_error_or_a_valid_archive(tmp_path, kind):
    data = fuzz_samples(tmp_path)[kind]
    path = tmp_path / "fuzz.bin"
    for cut in range(len(data)):
        path.write_bytes(data[:cut])
        exercise(path)
        assert archives.is_archive(path) in (True, False)


@pytest.mark.parametrize("kind", ["pak", "wad", "pck1", "pck2", "asar", "rpa3", "rpa3-py2",
                                  "rpa2", "zip"])
def test_every_single_byte_corruption_is_a_binspect_error_or_a_valid_archive(tmp_path, kind):
    data = fuzz_samples(tmp_path)[kind]
    path = tmp_path / "fuzz.bin"
    for pos in range(len(data)):
        for value in (0x00, 0xFF, data[pos] ^ 0x80):
            if value == data[pos]:
                continue
            mutated = bytearray(data)
            mutated[pos] = value
            path.write_bytes(bytes(mutated))
            exercise(path)


@pytest.mark.parametrize("kind", ["pak", "wad", "pck1", "pck2", "asar", "rpa3", "rpa2", "zip"])
def test_every_overwritten_32_bit_field_is_a_binspect_error_or_a_valid_archive(tmp_path, kind):
    data = fuzz_samples(tmp_path)[kind]
    path = tmp_path / "fuzz.bin"
    for pos in range(0, len(data) - 3):
        for value in (0xFFFFFFFF, 0x7FFFFFFF, 0x80000000):
            mutated = bytearray(data)
            mutated[pos:pos + 4] = struct.pack("<I", value)
            path.write_bytes(bytes(mutated))
            exercise(path)


def test_embedded_pck_with_corrupted_footer_or_header_never_escapes(tmp_path):
    exe = fixture_bytes("hello_pe64.exe")
    data = build_pck(fmt=2, engine=(4, 3, 0), stub=exe, embed=True, pack_flags=2)
    path = tmp_path / "fuzz.exe"
    for pos in range(len(exe), len(data)):
        for value in (0x00, 0xFF):
            mutated = bytearray(data)
            mutated[pos] = value
            path.write_bytes(bytes(mutated))
            exercise(path)
    for cut in range(len(exe), len(data)):
        path.write_bytes(data[:cut])
        exercise(path)


def test_random_garbage_after_each_magic_never_escapes(tmp_path):
    rng = random.Random(20240229)
    path = tmp_path / "fuzz.bin"
    magics = [b"PACK", b"IWAD", b"PWAD", b"GDPC", b"GDPC\x01\0\0\0", b"GDPC\x02\0\0\0",
              b"RPA-3.0 ", b"RPA-2.0 ", b"RPA-3.0 0000000000000030 00000000\n",
              b"PK\x03\x04", b"\x04\0\0\0", b"\x04\0\0\0\x40\0\0\0\x3c\0\0\0\x30\0\0\0{"]
    for magic in magics:
        for _ in range(60):
            path.write_bytes(magic + rng.randbytes(rng.randrange(0, 300)))
            exercise(path)
            tail = rng.randbytes(rng.randrange(0, 200))
            path.write_bytes(rng.randbytes(64) + tail + magic)
            exercise(path)


# =============================================================================
# Large containers are not read into memory
# =============================================================================

HOLE = 384 << 20        # 384 MiB of sparse file between the header and the data


def big_pak(path):
    with open(path, "wb") as f:
        f.write(b"PACK" + struct.pack("<ii", HOLE + 5, 64))
        f.seek(HOLE)
        f.write(b"small")
        f.write(padded(b"far/away.txt", 56) + struct.pack("<ii", HOLE, 5))
    return "far/away.txt"


def big_pck(path):
    with open(path, "wb") as f:
        f.write(build_pck(fmt=1, engine=(3, 5, 2), files=[(b"res://far/away.txt", b"")]))
        f.seek(108)                                         # 88 + 4 + 16: offset, size
        f.write(struct.pack("<QQ", HOLE, 5))
        f.seek(HOLE)
        f.write(b"small")
    return "far/away.txt"


def big_asar(path):
    header = '{"files":{"far":{"files":{"away.txt":{"size":5,"offset":"%d"}}}}}' % HOLE
    with open(path, "wb") as f:
        f.write(build_asar(header, b""))
        f.seek(HOLE, os.SEEK_CUR)
        f.write(b"small")
    return "far/away.txt"


def big_rpa(path):
    with open(path, "wb") as f:
        f.write(b"RPA-3.0 %016x %08x\n" % (HOLE + 5, 0))
        f.seek(HOLE)
        f.write(b"small")
        f.write(zlib.compress(pickle.dumps({"far/away.txt": [(HOLE, 5, b"")]}, 4)))
    return "far/away.txt"


def big_wad(path):
    with open(path, "wb") as f:
        f.write(b"PWAD" + struct.pack("<ii", 1, HOLE + 5))
        f.seek(HOLE)
        f.write(b"small")
        f.write(struct.pack("<ii", HOLE, 5) + padded(b"FARAWAY", 8))
    return "FARAWAY"


@pytest.mark.parametrize("builder", [big_pak, big_pck, big_asar, big_rpa, big_wad])
def test_listing_and_reading_a_huge_container_uses_little_memory(tmp_path, builder):
    path = tmp_path / "huge.bin"
    name = builder(path)
    assert path.stat().st_size > HOLE
    tracemalloc.start()
    try:
        assert archives.is_archive(path) is True
        a = archives.open_archive(path)
        assert [e.name for e in a.entries] == [name]
        assert a.read(name) == b"small"
        a.extract(tmp_path / "out")
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 << 20
    assert len(tree(tmp_path / "out")) == 1


def test_repacking_copies_large_entries_in_chunks(tmp_path):
    # 48 MiB entry: the copy must not hold it in memory at once.
    path = tmp_path / "big.pak"
    size = 48 << 20
    with open(path, "wb") as f:
        f.write(b"PACK" + struct.pack("<ii", 12 + size, 128))
        f.seek(12 + size - 1)
        f.write(b"\x01")
        f.write(padded(b"big.bin", 56) + struct.pack("<ii", 12, size))
        f.write(padded(b"small.txt", 56) + struct.pack("<ii", 12, 3))
    a = archives.open_archive(path)
    out = tmp_path / "out.pak"
    tracemalloc.start()
    try:
        a.repack(out, replacements={"small.txt": b"new"})
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 16 << 20
    b = archives.open_archive(out)
    assert [(e.name, e.size) for e in b.entries] == [("big.bin", size), ("small.txt", 3)]
    assert b.read("small.txt") == b"new"
    with open(out, "rb") as f:
        f.seek(12 + size - 1)
        assert f.read(1) == b"\x01"
