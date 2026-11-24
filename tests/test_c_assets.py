"""Differential tests for the native C edition's asset-pack and engine support.

The C program (c/binspect) is built and then checked, command by command,
against the Python edition that is this repository's oracle: the same packs
(assembled by the builders in test_archives.py / test_engines.py) are fed to
both and their --json output, exit codes, extracted bytes and repacked files
are required to agree. The Python reader (and `unzip -t` for ZIP) also reads
back everything the C program writes.

The whole module skips cleanly when there is no C compiler.
"""
import json
import os
import pathlib
import random
import shutil
import struct
import subprocess
import sys
import zipfile

import pytest

import test_archives as TA
import test_engines as TE
from conftest import fixture_bytes

REPO = pathlib.Path(__file__).resolve().parent.parent
CDIR = REPO / "c"
BIN = CDIR / "build" / "binspect"
ASAN = CDIR / "build" / "binspect-asan"


def _have(cmd):
    return shutil.which(cmd) is not None


pytestmark = pytest.mark.skipif(
    not (_have("cc") or _have("gcc")) or not _have("make"),
    reason="no C compiler / make available",
)


@pytest.fixture(scope="session")
def native():
    r = subprocess.run(["make", "-C", str(CDIR)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("make -C c failed:\n" + r.stdout + r.stderr)
    assert BIN.exists()
    return BIN


@pytest.fixture(scope="session")
def asan():
    r = subprocess.run(["make", "-C", str(CDIR), "asan"], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail("make -C c asan failed:\n" + r.stdout + r.stderr)
    assert ASAN.exists()
    return ASAN


def run_c(binary, args):
    return subprocess.run([str(binary)] + args, capture_output=True)


def run_py(args):
    return subprocess.run([sys.executable, "-m", "binspect"] + args,
                          capture_output=True, cwd=str(REPO))


def both(binary, args):
    return run_c(binary, args), run_py(args)


# formats the C edition implements (ASAR / RPA are Python-only there)
C_KINDS = ["zip", "pak", "wad", "pck1", "pck2", "pck2-embedded"]


def tree(root):
    root = pathlib.Path(root)
    return {str(p.relative_to(root)): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


# =============================================================================
# assets list: --json output and exit code match the Python CLI
# =============================================================================

@pytest.mark.parametrize("kind", C_KINDS)
def test_list_json_matches_python(native, tmp_path, kind):
    sub = tmp_path / kind
    sub.mkdir()
    path, _ = TA.sample(sub, kind)
    c, py = both(native, ["--json", "assets", "list", str(path)])
    assert c.returncode == py.returncode == 0, (c.stderr, py.stderr)
    assert c.stdout == py.stdout


def test_list_json_matches_for_zip_variants(native, tmp_path):
    cases = {
        "stored_and_deflated.zip": TA.build_zip(tmp_path / "a.zip"),
        "all_stored.zip": TA.build_zip(
            tmp_path / "b.zip", members=[("a.txt", b"aaaa", zipfile.ZIP_STORED)]),
        "legacy_name.zip": TA.write(tmp_path, "sjis.zip", TA.raw_zip(
            [("データ.txt".encode("shift_jis"), b"payload"), (b"plain.txt", b"x")])),
        "comment.zip": TA.build_zip(tmp_path / "c.zip", comment=b"made by hand"),
    }
    for _name, path in cases.items():
        c, py = both(native, ["--json", "assets", "list", str(path)])
        assert c.returncode == py.returncode == 0, (c.stderr, py.stderr)
        assert c.stdout == py.stdout, _name


def test_list_zip_appended_to_executable(native, tmp_path):
    exe = fixture_bytes("hello_pe64.exe")
    path = TA.write(tmp_path, "game.exe", exe + TA.zip_bytes(tmp_path))
    c, py = both(native, ["--json", "assets", "list", str(path)])
    assert c.returncode == py.returncode == 0, (c.stderr, py.stderr)
    assert c.stdout == py.stdout


def test_list_encrypted_zip_is_flagged(native, tmp_path):
    path = TA.encrypted_zip(tmp_path)
    c, py = both(native, ["--json", "assets", "list", str(path)])
    assert c.returncode == py.returncode == 0
    assert c.stdout == py.stdout
    assert b'"encrypted": true' in c.stdout


def test_list_grep_filters_by_substring(native, tmp_path):
    path, _ = TA.sample(tmp_path, "zip")
    # a plain-substring pattern: Python's regex search and C's substring agree
    c = run_c(native, ["--json", "assets", "list", str(path), "--grep", "conf"])
    py = run_py(["--json", "assets", "list", str(path), "--grep", "conf"])
    assert c.returncode == py.returncode == 0
    assert c.stdout == py.stdout
    assert json.loads(c.stdout)["items"][0]["name"] == "conf.lua"


# =============================================================================
# assets extract: every entry comes out byte-identical to archive.read()
# =============================================================================

@pytest.mark.parametrize("kind", C_KINDS)
def test_extract_everything_is_byte_identical(native, tmp_path, kind):
    sub = tmp_path / kind
    sub.mkdir()
    path, _ = TA.sample(sub, kind)
    cdest = sub / "c_out"
    r = run_c(native, ["assets", "extract", str(path), str(cdest)])
    assert r.returncode == 0, r.stderr
    pydest = sub / "py_out"
    TA.archives.open_archive(str(path)).extract(pydest)
    assert tree(cdest) == tree(pydest)


@pytest.mark.parametrize("kind", C_KINDS)
def test_extract_selected_names(native, tmp_path, kind):
    sub = tmp_path / kind
    sub.mkdir()
    path, content = TA.sample(sub, kind)
    name = list(content)[1]
    cdest = sub / "c_out"
    r = run_c(native, ["assets", "extract", str(path), str(cdest), name])
    assert r.returncode == 0, r.stderr
    got = tree(cdest)
    assert len(got) == 1
    expected = TA.archives.open_archive(str(path)).read(name)
    assert list(got.values())[0] == expected


def test_extract_unknown_name_matches_error(native, tmp_path):
    path, content = TA.sample(tmp_path, "zip")
    c, py = both(native, ["assets", "extract", str(path), str(tmp_path / "o"),
                          list(content)[0], "nope"])
    assert c.returncode == py.returncode == 1
    # equivalent message (LocationError text)
    assert b"no such entry" in c.stderr


# =============================================================================
# assets replace / add: the Python reader reads back a correct result and the
# untouched entries are unchanged; unzip -t accepts a repacked ZIP.
# =============================================================================

_REPACK = {
    "zip": ("conf.lua", "extra/new.bin"),
    "pak": ("readme.txt", "new/file.dat"),
    "wad": ("THINGS", "NEWLUMP"),
    "pck1": ("icon.png", "mods/x.cfg"),
    "pck2": ("icon.png", "mods/x.cfg"),
    "pck2-embedded": ("icon.png", "mods/x.cfg"),
}


@pytest.mark.parametrize("kind", C_KINDS)
def test_replace_round_trip(native, tmp_path, kind):
    sub = tmp_path / kind
    sub.mkdir()
    path, content = TA.sample(sub, kind)
    original = pathlib.Path(path).read_bytes()
    rep = _REPACK[kind][0]
    newfile = sub / "new.bin"
    newfile.write_bytes(b"REPLACED CONTENT")
    out = sub / ("rep" + pathlib.Path(path).suffix)
    r = run_c(native, ["assets", "replace", str(path), rep, str(newfile), "-o", str(out)])
    assert r.returncode == 0, r.stderr
    assert pathlib.Path(path).read_bytes() == original       # source untouched
    b = TA.archives.open_archive(str(out))
    got = {e.name: b.read(e.name) for e in b.entries}
    expected = dict(content)
    expected[rep] = b"REPLACED CONTENT"
    assert got == expected
    assert [e.name for e in b.entries] == list(content)      # order preserved


@pytest.mark.parametrize("kind", C_KINDS)
def test_add_round_trip(native, tmp_path, kind):
    sub = tmp_path / kind
    sub.mkdir()
    path, content = TA.sample(sub, kind)
    add = _REPACK[kind][1]
    newfile = sub / "add.bin"
    newfile.write_bytes(b"brand new")
    out = sub / ("add" + pathlib.Path(path).suffix)
    r = run_c(native, ["assets", "add", str(path), add, str(newfile), "-o", str(out)])
    assert r.returncode == 0, r.stderr
    b = TA.archives.open_archive(str(out))
    got = {e.name: b.read(e.name) for e in b.entries}
    expected = dict(content)
    expected[add] = b"brand new"
    assert got == expected
    assert [e.name for e in b.entries] == list(content) + [add]      # addition last


@pytest.mark.skipif(not _have("unzip"), reason="needs the unzip tool")
def test_repacked_zip_passes_unzip_t(native, tmp_path):
    path = TA.build_zip(tmp_path / "g.zip", comment=b"hand")
    newfile = tmp_path / "n"
    newfile.write_bytes(b"-- stored\n")
    out = tmp_path / "out.zip"
    r = run_c(native, ["assets", "replace", str(path), "conf.lua", str(newfile), "-o", str(out)])
    assert r.returncode == 0, r.stderr
    t = subprocess.run(["unzip", "-t", str(out)], capture_output=True)
    assert t.returncode == 0, t.stdout + t.stderr
    with zipfile.ZipFile(out) as zf:
        assert zf.testzip() is None
        assert zf.read("conf.lua") == b"-- stored\n"
        assert zf.read("main.lua") == TA.ZIP_MAIN
        assert zf.namelist() == ["main.lua", "conf.lua", "assets/blob.bin"]


def test_pck3_is_read_only(native, tmp_path):
    path = TA.write(tmp_path, "game.pck", TA.build_pck3())
    newfile = tmp_path / "n"
    newfile.write_bytes(b"x")
    out = tmp_path / "o.pck"
    c, py = both(native, ["assets", "replace", str(path), "icon.png", str(newfile), "-o", str(out)])
    assert c.returncode == py.returncode == 1
    assert c.stderr == py.stderr
    assert not out.exists()


def test_asar_and_rpa_are_python_only(native, tmp_path):
    for kind in ("asar", "rpa3"):
        sub = tmp_path / kind
        sub.mkdir()
        path, _ = TA.sample(sub, kind)
        c = run_c(native, ["--json", "assets", "list", str(path)])
        assert c.returncode == 1
        assert b"available in the Python edition" in c.stderr


# =============================================================================
# Inflate: C output is byte-for-byte identical to Python zlib across the deflate
# block kinds, and corrupt streams fail cleanly (never a crash).
# =============================================================================

def test_inflate_matches_python_zlib(native, tmp_path):
    rng = random.Random(7)
    payloads = {
        "empty": b"",
        "tiny": b"x",
        "stored_short": b"abcdef",
        "long_run": b"A" * 200000,
        "incompressible": rng.randbytes(90000),
        "text": (b"the quick brown fox jumps over the lazy dog\n" * 4000),
        "over64k": bytes(range(256)) * 400,
    }
    members = [(name, data, zipfile.ZIP_DEFLATED) for name, data in payloads.items()]
    path = TA.build_zip(tmp_path / "varied.zip", members=members)
    a = TA.archives.open_archive(str(path))
    cdest = tmp_path / "c_out"
    r = run_c(native, ["assets", "extract", str(path), str(cdest)])
    assert r.returncode == 0, r.stderr
    got = tree(cdest)
    for name, data in payloads.items():
        assert a.read(name) == data        # sanity on the oracle
        assert got[name] == data           # C inflate is byte-exact


def test_corrupt_deflate_fails_cleanly(native, tmp_path):
    data = bytearray(TA.zip_bytes(tmp_path, members=[("a.bin", bytes(range(200)),
                                                      zipfile.ZIP_DEFLATED)]))
    data[40] ^= 0xFF
    path = TA.write(tmp_path, "bad.zip", bytes(data))
    r = run_c(native, ["assets", "extract", str(path), str(tmp_path / "o")])
    assert r.returncode == 1
    assert tree(tmp_path / "o") == {}      # nothing half-written


# =============================================================================
# engine: --json output equals Python for the test_engines layouts (ASAR / RPA
# advice aside, which the C edition cannot produce without those readers).
# =============================================================================

def _engine_trees(tmp_path):
    out = {}
    d = tmp_path / "unity_mono"
    TE.unity_tree(d, il2cpp=False)
    out["unity-mono"] = d / "Space Game.exe"
    d = tmp_path / "unity_il2cpp"
    TE.unity_tree(d, il2cpp=True)
    out["unity-il2cpp"] = d
    d = tmp_path / "unreal"
    shipping = TE.unreal_tree(d)
    out["unreal-dir"] = d
    out["unreal-shipping"] = shipping
    d = tmp_path / "godot"
    g = TE.exe(d, "platformer.exe")
    TE.put(d, "platformer.pck", TE.minimal_pck(2, (4, 2, 1)))
    out["godot"] = g
    d = tmp_path / "godot_embed"
    pck = TE.minimal_pck(2, (4, 3, 0), flags=2)
    TE.exe(d, "single.exe", pck + struct.pack("<Q", len(pck)) + b"GDPC")
    out["godot-embed"] = d / "single.exe"
    d = tmp_path / "gamemaker"
    TE.exe(d, "runner.exe")
    TE.put(d, "data.win", b"FORM" + struct.pack("<I", 16) + b"GEN8" + struct.pack("<I", 8)
           + b"\x00\x11\x00\x00" + bytes(4))
    TE.put(d, "audiogroup1.dat", b"FORM" + bytes(12))
    out["gamemaker"] = d
    d = tmp_path / "rpgmaker"
    TE.exe(d, "Game.exe")
    TE.put(d, "www/js/rpg_core.js", b"// MV\n")
    TE.put(d, "www/data/System.json", b'{"hasEncryptedImages":true}')
    TE.put(d, "www/img/system/Window.rpgmvp", b"RPGMV\0\0\0" + bytes(24))
    out["rpgmaker"] = d
    d = tmp_path / "love"
    love = TE.make_zip(d / "tmp.love", TE.LOVE_FILES).read_bytes()
    (d / "tmp.love").unlink()
    out["love"] = TE.exe(d, "game.exe", love)
    d = tmp_path / "source"
    TE.exe(d, "hl2.exe")
    TE.put(d, "hl2/gameinfo.txt", b'"GameInfo"\n')
    TE.put(d, "hl2/hl2_misc_dir.vpk", struct.pack("<III", 0x55AA1234, 2, 0) + bytes(16))
    out["source"] = d
    d = tmp_path / "goldsrc"
    TE.exe(d, "hl.exe")
    TE.put(d, "valve/liblist.gam", b'game "Half-Life"\n')
    TE.put(d, "valve/pak0.pak", b"PACK" + struct.pack("<ii", 12, 0))
    TE.put(d, "valve/halflife.wad", b"WAD3" + struct.pack("<ii", 0, 12))
    out["goldsrc"] = d
    d = tmp_path / "idtech"
    TE.put(d, "DOOM2.WAD", b"IWAD" + struct.pack("<ii", 0, 12))
    TE.exe(d, "gzdoom.exe")
    TE.make_zip(d / "gzdoom.pk3", {"zscript.txt": b""})
    out["idtech"] = d
    d = tmp_path / "java"
    jar = TE.make_zip(d / "app.jar", {"META-INF/MANIFEST.MF": TE.MANIFEST})
    out["java"] = jar
    d = tmp_path / "monogame"
    TE.exe(d, "Farm.exe")
    TE.put(d, "MonoGame.Framework.dll", b"MZ")
    TE.put(d, "Content/Title.xnb", b"XNBw\x05\x00" + bytes(8))
    out["monogame"] = d
    d = tmp_path / "marker"
    out["marker"] = TE.exe(d, "mystery.exe", bytes(64) + "/Script/Engine".encode("utf-16-le"))
    d = tmp_path / "nothing"
    TE.put(d, "notes.txt", b"hi")
    out["nothing"] = d
    return out


def test_engine_json_matches_python(native, tmp_path):
    trees = _engine_trees(tmp_path)
    for name, target in trees.items():
        c, py = both(native, ["--json", "engine", str(target)])
        assert c.returncode == py.returncode == 0, (name, c.stderr, py.stderr)
        assert c.stdout == py.stdout, name


def test_engine_electron_matches_except_asar_advice(native, tmp_path):
    # ASAR / RPA are not opened by the C edition, so the one advice line that
    # describes opening the archive legitimately differs; everything else must
    # agree (evidence, details, asset_files, packs, root).
    d = tmp_path / "electron"
    TE.exe(d, "App.exe")
    TE.put(d, "resources/app.asar", TE.asar_bytes())
    TE.put(d, "version", b"28.2.1")
    for extra in ("chrome_100_percent.pak", "icudtl.dat"):
        TE.put(d, extra, bytes(8))
    c, py = both(native, ["--json", "engine", str(d / "App.exe")])
    assert c.returncode == py.returncode == 0
    cj, pj = json.loads(c.stdout), json.loads(py.stdout)
    assert cj["root"] == pj["root"]
    assert cj["packs"] == pj["packs"]
    assert len(cj["matches"]) == len(pj["matches"])
    for mc, mp in zip(cj["matches"], pj["matches"]):
        assert mc["engine"] == mp["engine"]
        assert mc["confidence"] == mp["confidence"]
        assert mc["details"] == mp["details"]
        assert mc["evidence"] == mp["evidence"]
        assert mc["asset_files"] == mp["asset_files"]
    # the C advice reports the archive as Python-only rather than openable
    assert any("available in the Python edition" in a for a in cj["matches"][0]["advice"])


def test_engine_missing_path(native, tmp_path):
    c, py = both(native, ["--json", "engine", str(tmp_path / "nope")])
    assert c.returncode == py.returncode == 1
    assert c.stderr == py.stderr


# =============================================================================
# Hostile input under AddressSanitizer: mutated / truncated packs must exit 0
# or 1 only, with no sanitizer report and nothing written outside the dest.
# =============================================================================

def test_hostile_input_is_safe_under_asan(asan, tmp_path):
    rng = random.Random(1234)
    samples = {
        "pak": TA.build_pak(),
        "wad": TA.build_wad(),
        "pck1": TA.build_pck(fmt=1, engine=(3, 5, 2)),
        "pck2": TA.build_pck(fmt=2),
        "pck3": TA.build_pck3(),
        "zip": TA.zip_bytes(tmp_path, members=[
            ("main.lua", TA.ZIP_MAIN, zipfile.ZIP_DEFLATED),
            ("conf.lua", TA.ZIP_CONF, zipfile.ZIP_STORED)]),
        "pck-embed": TA.build_pck(fmt=2, engine=(4, 3, 0),
                                  stub=fixture_bytes("hello_elf64"), embed=True, pack_flags=2),
    }
    env = dict(os.environ, ASAN_OPTIONS="abort_on_error=1:detect_leaks=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    fuzz = tmp_path / "fuzz.bin"
    dest = tmp_path / "dest"
    before = sorted(p.name for p in tmp_path.iterdir())

    def exercise(data):
        fuzz.write_bytes(data)
        for args in (["--json", "assets", "list", str(fuzz)],
                     ["assets", "list", str(fuzz)],
                     ["assets", "extract", str(fuzz), str(dest)]):
            r = subprocess.run([str(asan)] + args, capture_output=True, env=env, timeout=30)
            assert r.returncode in (0, 1), (args, r.returncode, r.stderr[-300:])
            for bad in (b"AddressSanitizer", b"runtime error", b"LeakSanitizer", b"ERROR:"):
                assert bad not in r.stderr, (args, r.stderr[-400:])
        shutil.rmtree(dest, ignore_errors=True)

    for _name, data in samples.items():
        for cut in range(0, len(data), max(1, len(data) // 12)):
            exercise(data[:cut])
        for _ in range(40):
            m = bytearray(data)
            pos = rng.randrange(len(data))
            if rng.random() < 0.5:
                m[pos] = rng.randrange(256)
            elif pos + 4 <= len(m):
                m[pos:pos + 4] = struct.pack("<I", rng.choice(
                    [0xFFFFFFFF, 0x7FFFFFFF, 0x80000000]))
            exercise(bytes(m))
        for _ in range(10):
            exercise(data[:8] + rng.randbytes(rng.randrange(0, 200)))

    # nothing was created in tmp_path outside the destination directory
    after = sorted(p.name for p in tmp_path.iterdir())
    assert set(after) - set(before) <= {"dest"}


# =============================================================================
# The MinGW (Windows) build still succeeds.
# =============================================================================

@pytest.mark.skipif(not _have("x86_64-w64-mingw32-gcc"), reason="no MinGW-w64 toolchain")
def test_windows_build_succeeds():
    r = subprocess.run(["make", "-C", str(CDIR), "windows"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (CDIR / "build" / "binspect.exe").exists()
