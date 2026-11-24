"""The native C `split` command against the Python implementation.

Both editions are run on the same inputs: every fixture, inputs with files
planted inside them (PNG, GIF, WAV/AVI/WebP, ZIP, PE, ELF) together with
near-misses of each, programs damaged at random, and inputs built to make a
naive carver slow. The JSON results, the written folders (byte for byte,
index.txt included), the text output, the error messages and the HTTP API
must agree.

The C edition has no PE resource support, so pieces of kind `resource`, the
`resources/` folder and their rows of index.txt are left out of the
comparison (and out of `count` and `bytes`).

The hostile inputs are also fed to the AddressSanitizer/UBSan build.
"""
import contextlib
import http.client
import io
import json
import os
import random
import re
import shutil
import struct
import subprocess
import threading
import time
import zipfile
import zlib
from pathlib import Path
from urllib.parse import quote

import pytest

from vex import server
from vex.cli import main as python_main
from conftest import FIXTURES, fixture_bytes, fixture_path

C_DIR = Path(__file__).resolve().parent.parent / "c"
MAKE = shutil.which("make")
COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")

pytestmark = pytest.mark.skipif(
    not (MAKE and COMPILER and C_DIR.is_dir()),
    reason="the C port needs make and a C compiler")

FIXTURE_NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())
NOT_EMPTY = "is not empty; choose a new or empty folder"


# --- the two implementations --------------------------------------------------

def _make(target):
    proc = subprocess.run([MAKE, "-C", str(C_DIR), target], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


@pytest.fixture(scope="session")
def c_binary():
    _make("all")
    return C_DIR / "build" / "vex"


@pytest.fixture(scope="session")
def asan_binary():
    _make("asan")
    return C_DIR / "build" / "vex-asan"


def run_c(binary, *args, timeout=120, env=None):
    proc = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                          timeout=timeout, env=env)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


def run_python(*args):
    """The Python CLI in-process: (exit status, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = python_main([str(a) for a in args])
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


# --- comparing ----------------------------------------------------------------

def without_resources(result):
    """The result as the C edition reports it: no `resource` pieces, and
    `count`/`bytes` without them. `dest` differs by construction."""
    result = dict(result)
    resources = [p for p in result["pieces"] if p["kind"] == "resource"]
    result["pieces"] = [p for p in result["pieces"] if p["kind"] != "resource"]
    result["count"] -= sum(1 for p in resources if p["path"])
    result["bytes"] -= sum(p["size"] for p in resources if p["path"])
    result.pop("dest", None)
    return result


def tree(root):
    """Every file under root except resources/: {relative path: bytes}."""
    root = Path(root)
    files = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if rel == "resources" or rel.startswith("resources/"):
            continue
        assert not path.is_symlink(), rel
        if path.is_file():
            files[rel] = path.read_bytes()
    return files


def without_resource_rows(index, result):
    """index.txt without the rows of `resource` pieces."""
    paths = {p["path"] for p in result["pieces"] if p["kind"] == "resource" and p["path"]}
    return [line for line in index.decode("utf-8").split("\n")
            if not any(f" {path} " in line + " " for path in paths)]


def split_both(c_binary, tmp_path, source, tag="x"):
    """Splits `source` with both editions; returns their (status, result,
    folder) and has checked that they agree."""
    c_dest, py_dest = tmp_path / f"c-{tag}", tmp_path / f"py-{tag}"
    c_code, c_out, c_err = run_c(c_binary, "--json", "split", source, c_dest)
    py_code, py_out, py_err = run_python("--json", "split", source, py_dest)
    assert c_code == py_code, (c_err, py_err)
    if py_code != 0:
        assert c_err == py_err
        assert not c_dest.exists() and not py_dest.exists()
        return c_code, None, None
    c_result, py_result = json.loads(c_out), json.loads(py_out)
    assert c_result["dest"] == str(c_dest)
    assert without_resources(c_result) == without_resources(py_result)
    c_tree, py_tree = tree(c_dest), tree(py_dest)
    has_resources = any(p["kind"] == "resource" for p in py_result["pieces"])
    if has_resources:
        c_index, py_index = c_tree.pop("index.txt"), py_tree.pop("index.txt")
        assert (without_resource_rows(c_index, py_result)
                == without_resource_rows(py_index, py_result))
    assert c_tree == py_tree
    # What the result promises is what is on disk.
    saved = [p for p in c_result["pieces"] if p["path"]]
    assert sorted(p["path"] for p in saved) == sorted(set(c_tree) - {"index.txt"})
    assert c_result["count"] == len(saved)
    assert c_result["bytes"] == sum(len(c_tree[p["path"]]) for p in saved)
    return c_code, c_result, c_dest


def rebuilt(result, folder):
    """The parts put back together, zero bytes for unsaved padding."""
    out = b""
    for piece in result["pieces"]:
        if piece["kind"] in ("embedded", "resource"):
            continue
        if piece["path"]:
            out += (Path(folder) / piece["path"]).read_bytes()
        else:
            out += b"\x00" * piece["size"]
    return out


# --- files to plant -----------------------------------------------------------

def _chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_START = PNG_SIGNATURE + _chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))


def make_png(width=1, height=1, text=b""):
    raw = b"".join(b"\x00" + b"\x7f" * width for _ in range(height))
    out = PNG_SIGNATURE + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
    if text:
        out += _chunk(b"tEXt", text)
    return out + _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b"")


GIF_START = b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0, 0, 0)
GIF_IMAGE = b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + b"\x02\x02\x44\x01\x00"


def make_gif(version=b"GIF89a", global_table=True, extensions=True, images=1,
             local_table=False):
    out = version + struct.pack("<HHBBB", 1, 1, 0x80 if global_table else 0, 0, 0)
    if global_table:
        out += b"\x00\x00\x00\xff\xff\xff"
    if extensions:
        out += b"\x21\xf9\x04\x00\x00\x00\x00\x00" + b"\x21\xfe\x05hello\x03abc\x00"
    for _ in range(images):
        out += b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0x81 if local_table else 0)
        if local_table:
            out += bytes(range(12))
        out += b"\x02\x02\x44\x01\x00"
    return out + b"\x3b"


def make_riff(form=b"WAVE", payload=None):
    if payload is None:
        payload = (b"fmt \x10\x00\x00\x00" + struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
                   + b"data\x04\x00\x00\x00abcd")
    return b"RIFF" + struct.pack("<I", 4 + len(payload)) + form + payload


def make_zip(files=(("a.txt", b"hello"), ("dir/b.bin", b"\x00" * 50)), comment=b"",
             method=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        for name, data in files:
            archive.writestr(name, data)
        archive.comment = comment
    return buffer.getvalue()


def planted_files():
    """Complete files of every recognised kind: {label: bytes}."""
    return {
        "png": make_png(),
        "png-text": make_png(3, 2, b"key\x00value"),
        "gif89": make_gif(),
        "gif87": make_gif(b"GIF87a", False, False, 2, True),
        "wav": make_riff(),
        "avi": make_riff(b"AVI ", b"LIST" + struct.pack("<I", 4) + b"hdrl"),
        "webp": make_riff(b"WEBP", b"VP8 " + struct.pack("<I", 2) + b"\x00\x00"),
        "riff-min": make_riff(b"WAVE", b""),
        "zip": make_zip(),
        "zip-comment": make_zip(comment=b"a comment"),
        "zip-stored": make_zip((("x", b"PK\x03\x04 inside"),), method=zipfile.ZIP_STORED),
        "exe": fixture_bytes("hello_pe64.exe"),
        "exe32": fixture_bytes("hello_pe32.exe"),
        "dll": fixture_bytes("sample.dll"),
        "elf32": fixture_bytes("bare_elf32"),
        "elf64": fixture_bytes("hello_elf64_stripped"),
        "so": fixture_bytes("libsample.so"),
        "arm64": fixture_bytes("bare_arm64"),
    }


def _patched(data, offset, replacement):
    return data[:offset] + replacement + data[offset + len(replacement):]


def near_misses():
    """Things that look like the start of a file but are not a complete one."""
    png, gif, wav, zipped = make_png(), make_gif(), make_riff(), make_zip()
    pe, elf = fixture_bytes("hello_pe64.exe"), fixture_bytes("bare_elf32")
    lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    eocd = zipped.rindex(b"PK\x05\x06")
    return {
        "png-signature-only": PNG_SIGNATURE,
        "png-bad-ihdr-crc": _patched(png, 29, b"\x00\x00\x00\x00"),
        "png-ihdr-length-12": _patched(png, 8, struct.pack(">I", 12)),
        "png-first-chunk-not-ihdr": _patched(png, 12, b"IDAT"),
        "png-no-iend": png[:-12],
        "png-truncated-iend": png[:-1],
        "png-chunk-past-end": _patched(png, 33, struct.pack(">I", 0x7FFFFFFF)),
        "png-chunk-huge": _patched(png, 33, struct.pack(">I", 0xFFFFFFFF)),
        "gif-header-only": gif[:13],
        "gif-no-image": make_gif(images=0),
        "gif-no-trailer": gif[:-1],
        "gif-bad-block": _patched(gif, len(gif) - 1, b"\x00"),
        "gif-bad-version": b"GIF88a" + gif[6:],
        "gif-truncated-table": gif[:16],
        "gif-truncated-image": gif[:-6],
        "riff-size-3": b"RIFF" + struct.pack("<I", 3) + b"WAVE",
        "riff-past-end": b"RIFF" + struct.pack("<I", 1 << 20) + b"WAVEdata",
        "riff-huge": b"RIFF" + struct.pack("<I", 0xFFFFFFFF) + b"WAVEdata",
        "riff-unknown-form": make_riff(b"ACON"),
        "riff-truncated": wav[:10],
        "zip-local-header-only": zipped[:eocd],
        "zip-wrong-cd-offset": _patched(zipped, eocd + 16, struct.pack(
            "<I", struct.unpack_from("<I", zipped, eocd + 16)[0] + 1)),
        "zip-wrong-cd-size": _patched(zipped, eocd + 12, struct.pack(
            "<I", struct.unpack_from("<I", zipped, eocd + 12)[0] + 1)),
        "zip-cd-signature-gone": zipped.replace(b"PK\x01\x02", b"PK\x01\x03"),
        "zip-comment-past-end": _patched(zipped, eocd + 20, b"\xff\xff"),
        "zip-truncated-eocd": zipped[:-1],
        "pe-mz-only": b"MZ" + b"\x00" * 62,
        "pe-lfanew-past-end": _patched(pe, 0x3C, struct.pack("<I", 0x7FFFFFFF)),
        "pe-lfanew-huge": _patched(pe, 0x3C, struct.pack("<I", 0xFFFFFFFF)),
        "pe-bad-signature": _patched(pe, lfanew, b"PE\x00\x01"),
        "pe-no-sections": _patched(pe, lfanew + 6, struct.pack("<H", 0)),
        "pe-97-sections": _patched(pe, lfanew + 6, struct.pack("<H", 97)),
        "pe-truncated": pe[:len(pe) // 2],
        "pe-headers-only": pe[:0x200],
        "elf-magic-only": b"\x7fELF",
        "elf-bad-class": _patched(elf, 4, b"\x03"),
        "elf-bad-data": _patched(elf, 5, b"\x00"),
        "elf-bad-version": _patched(elf, 6, b"\x02"),
        "elf-truncated": elf[:len(elf) // 2],
        "elf-header-only": elf[:52],
    }


def build_input(host, blobs, filler=b"-filler-"):
    data = host
    for blob in blobs:
        data += filler + blob
    return data + filler


# --- every fixture ------------------------------------------------------------

@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_matches_python(c_binary, tmp_path, name):
    code, result, folder = split_both(c_binary, tmp_path, fixture_path(name))
    assert code == 0
    assert rebuilt(result, folder) == fixture_bytes(name)
    assert fixture_bytes(name) == fixture_path(name).read_bytes()      # untouched


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_text_output_matches_python(c_binary, tmp_path, name):
    c_dest, py_dest = tmp_path / "c", tmp_path / "py"
    c_code, c_out, c_err = run_c(c_binary, "split", fixture_path(name), c_dest)
    py_code, py_out, py_err = run_python("split", fixture_path(name), py_dest)
    assert (c_code, c_err) == (py_code, py_err) == (0, "")
    py_json = json.loads(run_python("--json", "split", fixture_path(name), tmp_path / "j")[1])
    resources = [p for p in py_json["pieces"] if p["kind"] == "resource"]
    if not resources:
        assert c_out.replace(str(c_dest), "DEST") == py_out.replace(str(py_dest), "DEST")
    else:
        # The table's column widths depend on the resource rows; compare the cells.
        def cells(text):
            return [line.split() for line in text.replace(str(c_dest), "DEST")
                    .replace(str(py_dest), "DEST").splitlines()]
        paths = {p["path"] for p in resources}
        py_rows = [row for row in cells(py_out) if not paths & set(row)]
        c_rows = cells(c_out)
        assert c_rows[2:-1] == py_rows[2:-1]
        assert c_rows[0] == py_rows[0]
        assert c_rows[-1][0] == py_rows[-1][0] == "Saved"


# --- planted files and near-misses ----------------------------------------------

@pytest.mark.parametrize("host", ["hello_elf64", "hello_pe64.exe", "resdemo.exe"])
def test_planted_files_are_found_like_python(c_binary, tmp_path, host):
    blobs = planted_files()
    source = tmp_path / "planted.bin"
    source.write_bytes(build_input(fixture_bytes(host), blobs.values()))
    code, result, folder = split_both(c_binary, tmp_path, source)
    assert code == 0
    embedded = [p for p in result["pieces"] if p["kind"] == "embedded"]
    data = source.read_bytes()
    for piece in embedded:
        saved = (folder / piece["path"]).read_bytes()
        assert saved == data[piece["offset"]:piece["offset"] + piece["size"]]
    # Each planted file comes back whole, except hello_pe64.exe: its COFF symbol
    # table lies after the last section, which is where a PE's length ends.
    found = {(folder / p["path"]).read_bytes() for p in embedded}
    for label, blob in blobs.items():
        if label not in ("exe", "exe32"):
            assert blob in found, label
    assert rebuilt(result, folder) == data


@pytest.mark.parametrize("label", sorted(near_misses()))
def test_near_miss_matches_python(c_binary, tmp_path, label):
    miss = near_misses()[label]
    source = tmp_path / "miss.bin"
    # Once followed by other data, once at the very end of the file.
    source.write_bytes(build_input(fixture_bytes("hello_elf64"), [miss, make_png(), miss])
                       [:-len(b"-filler-")])
    code, result, folder = split_both(c_binary, tmp_path, source)
    assert code == 0
    assert rebuilt(result, folder) == source.read_bytes()


def test_files_inside_files_match_python(c_binary, tmp_path):
    """A hit swallows what is inside it; the scan resumes after it."""
    inner = make_png()
    outer_zip = make_zip((("picture.png", inner), ("sound.wav", make_riff())),
                         method=zipfile.ZIP_STORED)
    wav_with_gif = make_riff(b"WAVE", b"data" + struct.pack("<I", 100) + make_gif().ljust(100))
    source = tmp_path / "nested.bin"
    source.write_bytes(build_input(fixture_bytes("hello_pe64.exe"),
                                   [outer_zip, wav_with_gif, inner + inner, b"MZ" + inner]))
    code, result, folder = split_both(c_binary, tmp_path, source)
    assert code == 0
    kinds = [p["name"] for p in result["pieces"] if p["kind"] == "embedded"]
    assert kinds == ["zip file", "wav file", "png file", "png file", "png file"]


def test_two_zips_and_shared_end_records_match_python(c_binary, tmp_path):
    """Several local headers and end records: each archive is closed by the
    first end record that fits it."""
    first, second = make_zip((("one", b"1"),)), make_zip((("two", b"22"),), comment=b"note")
    eocd = first.rindex(b"PK\x05\x06")
    source = tmp_path / "zips.bin"
    source.write_bytes(build_input(fixture_bytes("hello_elf64"), [
        first, second, first + first[eocd:], first[:eocd] + second, b"PK\x03\x04" * 50,
        b"PK\x05\x06" * 50, first[eocd:] * 3]))
    code, result, _ = split_both(c_binary, tmp_path, source)
    assert code == 0
    assert sum(p["name"] == "zip file" for p in result["pieces"]) >= 3


def test_embedded_at_the_edges_matches_python(c_binary, tmp_path):
    """Offset 0 is the program itself and is never reported; a file may end
    exactly at the end of the input."""
    host = fixture_bytes("hello_pe64.exe")
    for tag, data in (("end", host + make_gif()), ("one", host + b"\x00" + make_png()),
                      ("elf-in-elf", fixture_bytes("bare_elf32") + fixture_bytes("bare_elf32"))):
        source = tmp_path / f"{tag}.bin"
        source.write_bytes(data)
        code, result, _ = split_both(c_binary, tmp_path, source, tag)
        assert code == 0
        embedded = [p for p in result["pieces"] if p["kind"] == "embedded"]
        assert len(embedded) == 1 and embedded[0]["offset"] > 0
        assert embedded[0]["offset"] + embedded[0]["size"] == len(data)


# --- names, folders, errors -------------------------------------------------------

def test_hostile_section_names_stay_inside_the_folder(c_binary, tmp_path):
    """Section names are attacker-controlled; no name leaves the folder."""
    pe = bytearray(fixture_bytes("hello_pe64.exe"))
    lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    sections = struct.unpack_from("<H", pe, lfanew + 6)[0]
    table = lfanew + 24 + struct.unpack_from("<H", pe, lfanew + 20)[0]
    names = [b"../../x\x00", b"..\\..\\y\x00", b"/abs\x00\x00\x00\x00", b"\xc3\xa9t\xc3\xa9\x00\x00\x00",
             b"a b\tc\x00\x00\x00", b"CON\x00\x00\x00\x00\x00", b"\xff\xfe\x00\x00\x00\x00\x00\x00"]
    for i in range(sections):
        pe[table + 40 * i:table + 40 * i + 8] = names[i % len(names)]
    elf = bytearray(fixture_bytes("hello_elf64"))
    at = elf.index(b".comment\x00")
    elf[at:at + 8] = b"../../ev"
    at = elf.index(b".eh_frame\x00")
    elf[at:at + 9] = b"/tmp/own\x00"
    for tag, data in (("pe", bytes(pe)), ("elf", bytes(elf))):
        work = tmp_path / tag
        work.mkdir()
        source = work / "hostile.bin"
        source.write_bytes(data)
        code, result, folder = split_both(c_binary, work, source)
        assert code == 0
        for piece in result["pieces"]:
            if piece["path"]:
                assert re.fullmatch(r"(parts|embedded)/[A-Za-z0-9._-]+", piece["path"])
                assert ".." not in piece["path"].split("/")
        assert sorted(p.name for p in work.iterdir()) == ["c-x", "hostile.bin", "py-x"]
        assert rebuilt(result, folder) == data


def test_folder_is_created_with_its_parents(c_binary, tmp_path):
    for edition, run in (("c", lambda *a: run_c(c_binary, *a)), ("py", run_python)):
        dest = tmp_path / edition / "a" / "b" / "c"
        code, out, err = run("--json", "split", fixture_path("hello_elf64"), dest)
        assert code == 0, err
        assert json.loads(out)["dest"] == str(dest)
        assert (dest / "index.txt").is_file() and (dest / "parts").is_dir()
    assert tree(tmp_path / "c" / "a" / "b" / "c") == tree(tmp_path / "py" / "a" / "b" / "c")


def test_empty_existing_folder_is_accepted(c_binary, tmp_path):
    for edition, run in (("c", lambda *a: run_c(c_binary, *a)), ("py", run_python)):
        dest = tmp_path / edition
        dest.mkdir()
        code, _, err = run("split", fixture_path("sample.dll"), dest)
        assert code == 0, err
    assert tree(tmp_path / "c") == tree(tmp_path / "py")


@pytest.mark.parametrize("json_flag", [[], ["--json"]])
def test_non_empty_folder_is_refused_like_python(c_binary, tmp_path, json_flag):
    dest = tmp_path / "taken"
    dest.mkdir()
    (dest / "keep.txt").write_text("mine")
    source = fixture_path("hello_elf64")
    c = run_c(c_binary, *json_flag, "split", source, dest)
    py = run_python(*json_flag, "split", source, dest)
    assert c == py
    assert c == (1, "", f"vex: error: {dest} {NOT_EMPTY}\n")
    assert sorted(p.name for p in dest.iterdir()) == ["keep.txt"]
    assert (dest / "keep.txt").read_text() == "mine"
    # The message names the folder as it was given.
    c = run_c(c_binary, "split", source, os.path.relpath(dest))
    py = run_python("split", source, os.path.relpath(dest))
    assert c == py and c[2] == f"vex: error: {os.path.relpath(dest)} {NOT_EMPTY}\n"


def test_folder_holding_only_a_hidden_file_or_a_folder_is_not_empty(c_binary, tmp_path):
    for name, make in ((".hidden", lambda p: p.write_text("")), ("sub", lambda p: p.mkdir())):
        dest = tmp_path / name
        dest.mkdir()
        make(dest / name)
        c = run_c(c_binary, "split", fixture_path("hello_elf64"), dest)
        py = run_python("split", fixture_path("hello_elf64"), dest)
        assert c == py and c[0] == 1 and NOT_EMPTY in c[2]
        assert sorted(p.name for p in dest.iterdir()) == [name]


def test_errors_match_python(c_binary, tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("not a program at all, just some text\n" * 4)
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    a_file = tmp_path / "a_file"
    a_file.write_text("x")
    for args in (["split", text, tmp_path / "o1"], ["split", empty, tmp_path / "o2"],
                 ["split", tmp_path / "missing", tmp_path / "o3"],
                 ["--json", "split", text, tmp_path / "o4"],
                 ["split", fixture_path("hello_elf64"), a_file]):
        c, py = run_c(c_binary, *args), run_python(*args)
        assert c == py, args
        assert c[0] == 1 and c[1] == ""
    assert sorted(p.name for p in tmp_path.iterdir()) == ["a_file", "empty", "notes.txt"]
    assert a_file.read_text() == "x"


def test_usage_errors(c_binary, tmp_path):
    for args in (["split"], ["split", fixture_path("hello_elf64")],
                 ["split", fixture_path("hello_elf64"), tmp_path / "o", "extra"]):
        c, py = run_c(c_binary, *args), run_python(*args)
        assert c[0] == py[0] == 2 and c[1] == py[1] == ""
    assert not (tmp_path / "o").exists()
    assert "split FILE FOLDER" in run_c(c_binary, "--help")[1]


# --- damaged programs -------------------------------------------------------------

def _damaged(rng, blobs):
    data = bytearray(fixture_bytes(rng.choice(FIXTURE_NAMES)))
    for _ in range(rng.randrange(1, 3)):
        choice = rng.randrange(6)
        if choice == 0:
            del data[rng.randrange(len(data) + 1):]
        elif choice == 1:
            for _ in range(rng.randrange(1, 30)):
                if data:
                    data[rng.randrange(len(data))] = rng.randrange(256)
        elif choice == 2:
            for _ in range(rng.randrange(1, 6)):
                at = rng.randrange(len(data) + 1)
                data[at:at] = rng.choice(blobs)
        elif choice == 3:
            for _ in range(rng.randrange(1, 6)):
                blob = bytearray(rng.choice(blobs))
                for _ in range(rng.randrange(0, 4)):
                    blob[rng.randrange(len(blob))] = rng.randrange(256)
                if rng.random() < 0.3:
                    del blob[rng.randrange(len(blob) + 1):]
                at = rng.randrange(len(data) + 1)
                data[at:at] = blob
        elif choice == 4:
            for _ in range(rng.randrange(1, 8)):
                if len(data) > 8:
                    at = rng.randrange(len(data) - 8)
                    data[at:at + 4] = rng.choice([b"\xff\xff\xff\xff", b"\x00\x00\x00\x00",
                                                  b"\xff\xff\xff\x7f", b"\x00\x00\x00\x80"])
        else:
            at = rng.randrange(len(data) + 1)
            data[at:at] = rng.choice([b"PK\x03\x04", b"PK\x05\x06", b"MZ", b"\x7fELF\x02\x01\x01",
                                      b"GIF89a", b"RIFF", PNG_SIGNATURE]) * rng.randrange(1, 200)
    return bytes(data)


def _fuzz_blobs():
    return list(planted_files().values()) + list(near_misses().values())


@pytest.mark.parametrize("seed", range(6))
def test_damaged_programs_match_python(c_binary, tmp_path, seed):
    rng = random.Random(4000 + seed)
    blobs = _fuzz_blobs()
    source = tmp_path / "damaged.bin"
    split = 0
    for round_number in range(40):
        data = _damaged(rng, blobs)
        source.write_bytes(data)
        code, result, folder = split_both(c_binary, tmp_path, source, str(round_number))
        if code == 0:
            split += 1
            for piece in result["pieces"]:
                if piece["path"]:
                    assert re.fullmatch(r"(parts|embedded)/[A-Za-z0-9._-]+", piece["path"])
            shutil.rmtree(folder)
            shutil.rmtree(tmp_path / f"py-{round_number}")
    assert split >= 10
    assert sorted(p.name for p in tmp_path.iterdir()) == ["damaged.bin"]


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_truncated_fixtures_match_python(c_binary, tmp_path, name):
    data = fixture_bytes(name)
    source = tmp_path / "cut.bin"
    for i, cut in enumerate(sorted({1, 4, 16, 52, 64, 100, len(data) // 3, len(data) // 2,
                                    len(data) * 3 // 4, len(data) - 1})):
        source.write_bytes(data[:cut])
        split_both(c_binary, tmp_path, source, str(i))


def test_hostile_input_is_safe_under_asan(asan_binary, tmp_path):
    """Damaged programs under AddressSanitizer/UBSan: exit status 0 or 1, no
    sanitizer report, nothing written outside the destination."""
    rng = random.Random(99)
    blobs = _fuzz_blobs()
    env = dict(os.environ, ASAN_OPTIONS="abort_on_error=1:detect_leaks=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    source, dest = tmp_path / "fuzz.bin", tmp_path / "dest"

    def exercise(data):
        source.write_bytes(data)
        for args in (["--json", "split", source, dest], ["split", source, dest]):
            shutil.rmtree(dest, ignore_errors=True)
            code, _, err = run_c(asan_binary, *args, env=env)
            assert code in (0, 1), (code, err[-400:])
            for bad in ("AddressSanitizer", "runtime error", "LeakSanitizer", "ERROR:"):
                assert bad not in err, err[-600:]
            if code == 0:
                for path in dest.rglob("*"):
                    assert not path.is_symlink()

    for name in FIXTURE_NAMES:
        data = fixture_bytes(name)
        exercise(data)
        for cut in range(0, len(data), max(1, len(data) // 10)):
            exercise(data[:cut])
    for _ in range(150):
        exercise(_damaged(rng, blobs))
    for payload in adversarial_inputs(scale=1).values():
        exercise(fixture_bytes("hello_elf64") + payload)
    shutil.rmtree(dest, ignore_errors=True)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fuzz.bin"]


# --- inputs made to be slow -------------------------------------------------------

def png_chain(starts, links, closed):
    """`starts` PNG beginnings, each skipping over the following ones into one
    shared chain of `links` empty chunks."""
    out = bytearray()
    for i in range(starts):
        out += PNG_START + struct.pack(">I", (starts - i - 1) * 41) + b"skip"
    out += b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00abcd\x00\x00\x00\x00" * links
    if closed:
        out += _chunk(b"IEND", b"")
    return bytes(out)


def gif_block_chain(starts, links, closed, image_at=None):
    """`starts` GIF beginnings whose comment data hops over the following
    ones into one shared chain of `links` extension blocks."""
    out = bytearray()
    for _ in range(starts):
        out += GIF_START + b"\x21\xfe" + bytes([15])
    out += b"\x00"
    for i in range(links):
        if i == image_at:
            out += GIF_IMAGE
        out += b"\x21\xfe\x01x\x00"
    if closed:
        out += b"\x3b"
    return bytes(out)


def gif_data_chain(starts, links, closed):
    """`starts` GIF beginnings, each with an image whose data runs into one
    shared chain of `links` one-byte sub-blocks."""
    out = bytearray()
    for _ in range(starts):
        out += GIF_START + b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + b"\x02" + bytes([24])
    out += b"\x01\x01" * links
    if closed:
        out += b"\x00\x3b"
    return bytes(out)


def elf_tables(starts, sections):
    """`starts` ELF headers that all point at one large section header table."""
    out = bytearray()
    for i in range(starts):
        out += (b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + struct.pack(
            "<HHIIIIIHHHHHH", 2, 3, 1, 0, 0, (starts - i) * 52, 0, 52, 32, 0, 40, sections, 0))
    table = bytearray(40 * sections)
    struct.pack_into("<II", table, 40 * (sections - 1) + 16, 0x7FFFFFF0, 0x100)   # past the end
    return bytes(out + table)


def pe_headers(starts):
    """`starts` MZ stubs (8 bytes apart) that share one PE header with 96 sections."""
    stubs = bytearray(8 * starts + 64)
    target = len(stubs)
    for i in range(starts):
        stubs[8 * i:8 * i + 2] = b"MZ"
    for i in range(starts):
        struct.pack_into("<I", stubs, 8 * i + 0x3C, target - 8 * i)
    header = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x8664, 96, 0, 0, 0, 240, 0x22)
    optional = bytearray(240)
    struct.pack_into("<I", optional, 60, 0x400)
    table = bytearray(40 * 96)
    struct.pack_into("<II", table, 40 * 95 + 16, 0x100, 0x7FFFFFF0)
    return bytes(stubs) + header + bytes(optional) + bytes(table)


def adversarial_inputs(scale):
    """Payloads that cost a naive carver time quadratic in their size.
    scale=1 is small enough for the Python edition and the sanitizer build."""
    return {
        "zip-local-headers": b"PK\x03\x04" * (2000 * scale),
        "zip-end-records": b"PK\x05\x06" * (2000 * scale),
        "zip-everything": (b"PK\x03\x04" + b"PK\x05\x06" + b"PK\x01\x02") * (700 * scale),
        "zip-ends-pointing-back": (b"PK\x03\x04" * (300 * scale) + b"".join(
            b"PK\x05\x06" + bytes(8) + struct.pack("<IIH", 4, 22 * i, 0)
            for i in range(300 * scale))),
        "mz": b"MZ" * (4000 * scale),
        "pe-headers": pe_headers(100 * scale),
        "elf-magic": b"\x7fELF\x02\x01\x01\x00" * (1000 * scale),
        "elf-tables": elf_tables(40 * scale, min(65535, 300 * scale)),
        "gif-magic": b"GIF89a" * (1300 * scale),
        "png-magic": PNG_SIGNATURE * (1000 * scale),
        "riff-magic": b"RIFF" * (2000 * scale),
        "png-chain-open": png_chain(60 * scale, 300 * scale, False),
        "png-chain-closed": png_chain(60 * scale, 300 * scale, True),
        "gif-blocks-open": gif_block_chain(60 * scale, 300 * scale, False, 250 * scale),
        "gif-blocks-closed": gif_block_chain(60 * scale, 300 * scale, True, 250 * scale),
        "gif-blocks-no-image": gif_block_chain(60 * scale, 300 * scale, True),
        "gif-blocks-early-image": gif_block_chain(60 * scale, 300 * scale, True, 10),
        "gif-data-open": gif_data_chain(60 * scale, 600 * scale, False),
        "gif-data-closed": gif_data_chain(60 * scale, 600 * scale, True),
    }


@pytest.mark.parametrize("label", sorted(adversarial_inputs(1)))
def test_adversarial_input_matches_python(c_binary, tmp_path, label):
    """Small versions of the slow-by-design inputs: the shortcuts the C
    edition takes on them must not change a single result."""
    source = tmp_path / "adversarial.bin"
    source.write_bytes(fixture_bytes("hello_elf64") + adversarial_inputs(1)[label])
    code, _, _ = split_both(c_binary, tmp_path, source)
    assert code == 0


def test_adversarial_input_stays_fast(c_binary, tmp_path):
    """Megabytes of signatures and shared chains finish in seconds."""
    source = tmp_path / "big.bin"
    host = fixture_bytes("hello_elf64")
    payloads = adversarial_inputs(600)
    payloads["zip-local-headers-8mb"] = b"PK\x03\x04" * (2 << 20)
    payloads["mz-8mb"] = b"MZ" * (4 << 20)
    payloads["png-chain-4mb"] = png_chain(40000, 200000, False)
    payloads["gif-blocks-4mb"] = gif_block_chain(100000, 500000, False)
    payloads["gif-data-4mb"] = gif_data_chain(100000, 1000000, False)
    for label, payload in payloads.items():
        source.write_bytes(host + payload)
        dest = tmp_path / "out"
        started = time.monotonic()
        code, out, err = run_c(c_binary, "--json", "split", source, dest, timeout=300)
        elapsed = time.monotonic() - started
        assert code == 0, (label, err)
        assert elapsed < 20, (label, len(payload), elapsed)
        shutil.rmtree(dest)


# --- the HTTP API -----------------------------------------------------------------

class Client:
    def __init__(self, port, token):
        self.port, self.token = port, token

    def call(self, method, name, **params):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        conn.request(method, f"/api/{name}?{query}", headers={"X-Vex-Token": self.token})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, json.loads(data)


@pytest.fixture(scope="module")
def c_client(c_binary):
    proc = subprocess.Popen([str(c_binary), "gui", "--no-browser", "--port", "0"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    found = None
    deadline = time.time() + 30
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        found = re.search(r"http://127\.0\.0\.1:(\d+)/#token=(\S+)", line)
        if found:
            break
    if not found:
        proc.kill()
        pytest.fail("the C server did not print its address")
    yield Client(int(found.group(1)), found.group(2))
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def py_client():
    httpd, workspace = server.create_server(port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield Client(httpd.server_address[1], workspace.token)
    httpd.shutdown()
    httpd.server_close()
    workspace.close()


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_api_preview_matches_python(c_client, py_client, name):
    before = sorted(p.name for p in FIXTURES.iterdir())
    c_status, c_data = c_client.call("GET", "split", path=fixture_path(name))
    py_status, py_data = py_client.call("GET", "split", path=fixture_path(name))
    assert c_status == py_status == 200
    assert c_data["dest"] is None and py_data["dest"] is None
    assert without_resources(c_data) == without_resources(py_data)
    assert c_data["index"] == "index.txt"
    assert sorted(p.name for p in FIXTURES.iterdir()) == before       # nothing written


def test_api_preview_equals_what_split_writes(c_client, tmp_path):
    source = tmp_path / "planted.bin"
    source.write_bytes(build_input(fixture_bytes("hello_pe64.exe"), planted_files().values()))
    _, preview = c_client.call("GET", "split", path=source)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["planted.bin"]
    status, done = c_client.call("POST", "split", path=source, dest=tmp_path / "out")
    assert status == 200 and done["dest"] == str(tmp_path / "out")
    assert dict(done, dest=None) == preview
    saved = tree(tmp_path / "out")
    assert preview["count"] == len(saved) - 1
    assert preview["bytes"] == sum(len(v) for k, v in saved.items() if k != "index.txt")


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_api_split_matches_python(c_client, py_client, tmp_path, name):
    c_dest, py_dest = tmp_path / "c" / "new", tmp_path / "py" / "new"
    c_status, c_data = c_client.call("POST", "split", path=fixture_path(name), dest=c_dest)
    py_status, py_data = py_client.call("POST", "split", path=fixture_path(name), dest=py_dest)
    assert c_status == py_status == 200
    assert (c_data["dest"], py_data["dest"]) == (str(c_dest), str(py_dest))
    assert without_resources(c_data) == without_resources(py_data)
    c_tree, py_tree = tree(c_dest), tree(py_dest)
    if any(p["kind"] == "resource" for p in py_data["pieces"]):
        c_index, py_index = c_tree.pop("index.txt"), py_tree.pop("index.txt")
        assert (without_resource_rows(c_index, py_data)
                == without_resource_rows(py_index, py_data))
    assert c_tree == py_tree
    # A second time into the same folder is refused, by both, the same way.
    c_again = c_client.call("POST", "split", path=fixture_path(name), dest=c_dest)
    py_again = py_client.call("POST", "split", path=fixture_path(name), dest=py_dest)
    assert c_again == (400, {"error": f"{c_dest} {NOT_EMPTY}"})
    assert py_again == (400, {"error": f"{py_dest} {NOT_EMPTY}"})
    assert tree(c_dest) == c_tree | ({"index.txt": c_index} if "index.txt" not in c_tree else {})


def test_api_errors_match_python(c_client, py_client, tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("plain text, not a program\n" * 3)
    elf = fixture_path("hello_elf64")
    for method, params in (
            ("GET", {}), ("GET", {"path": tmp_path / "missing"}), ("GET", {"path": text}),
            ("POST", {}), ("POST", {"path": elf}), ("POST", {"dest": tmp_path / "o"}),
            ("POST", {"path": tmp_path / "missing", "dest": tmp_path / "o"}),
            ("POST", {"path": text, "dest": tmp_path / "o"}),
            ("POST", {"path": elf, "dest": text})):
        c, py = c_client.call(method, "split", **params), py_client.call(method, "split", **params)
        assert c == py, (method, params)
        assert c[0] in (400, 404) and "error" in c[1]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["notes.txt"]
