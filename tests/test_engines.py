"""Engine detection from a game directory or an executable. Game trees are
built in tmp_path from the file names and signatures each engine is known to
ship; expected values are literals."""
import os
import pickle
import struct
import zipfile
import zlib

import pytest

from binspect import engines
from binspect.engines import EngineMatch, detect_engines
from conftest import fixture_bytes


def put(root, relative, data: bytes = b""):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def exe(root, relative="Game.exe", extra: bytes = b""):
    return put(root, relative, fixture_bytes("hello_pe64.exe") + extra)


def names(matches):
    return [m.engine for m in matches]


def advice_text(match) -> str:
    return "\n".join(match.advice)


def minimal_pck(fmt=2, engine=(4, 2, 1), flags=0) -> bytes:
    """A Godot pack with no files: 'GDPC', format, engine version, then
    (format 2) pack flags and file base, 16 reserved words, file count 0."""
    out = b"GDPC" + struct.pack("<IIII", fmt, *engine)
    if fmt >= 2:
        out += struct.pack("<IQ", flags, 112)
    out += bytes(64) + struct.pack("<I", 0)
    return out + bytes(-len(out) % 16)


def make_zip(path, members):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


# --- result shape ------------------------------------------------------------------

def test_nothing_recognised_gives_an_empty_list(tmp_path):
    put(tmp_path, "notes.txt", b"hello")
    put(tmp_path, "sub/data.bin", bytes(100))
    assert detect_engines(tmp_path) == []
    assert detect_engines(exe(tmp_path, "tool.exe")) == []


def test_match_has_the_documented_fields(tmp_path):
    put(tmp_path, "data.win", b"FORM" + struct.pack("<I", 16) + b"GEN8" + struct.pack("<I", 8)
        + b"\x00\x11\x00\x00" + bytes(4))
    (match,) = detect_engines(tmp_path)
    assert isinstance(match, EngineMatch)
    assert isinstance(match.engine, str)
    assert match.confidence in ("high", "medium", "low")
    assert all(isinstance(x, str) for x in match.evidence) and match.evidence
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in match.details.items())
    assert all(isinstance(x, str) for x in match.asset_files)
    assert all(isinstance(x, str) for x in match.advice) and match.advice


def test_accepts_str_and_path_and_file_or_directory(tmp_path):
    put(tmp_path, "data.win", b"FORM" + bytes(60))
    game = exe(tmp_path)
    for target in (tmp_path, str(tmp_path), game, str(game)):
        assert names(detect_engines(target)) == ["GameMaker"]


# --- Unity -------------------------------------------------------------------------

def unity_tree(root, il2cpp: bool):
    exe(root, "Space Game.exe")
    put(root, "UnityPlayer.dll", b"MZ")
    put(root, "UnityCrashHandler64.exe", b"MZ")
    # SerializedFile header (format 22): the engine version string follows it.
    put(root, "Space Game_Data/globalgamemanagers",
        bytes(8) + struct.pack(">I", 22) + bytes(36) + b"2021.3.16f1\x00" + bytes(20))
    put(root, "Space Game_Data/resources.assets", bytes(64))
    put(root, "Space Game_Data/sharedassets0.assets", bytes(64))
    put(root, "Space Game_Data/level0", bytes(64))
    if il2cpp:
        put(root, "GameAssembly.dll", b"MZ")
        put(root, "Space Game_Data/il2cpp_data/Metadata/global-metadata.dat",
            b"\xaf\x1b\xb1\xfa" + bytes(60))
    else:
        put(root, "Space Game_Data/Managed/Assembly-CSharp.dll", b"MZ")
        put(root, "MonoBleedingEdge/etc/config", b"")


def test_unity_mono_game(tmp_path):
    unity_tree(tmp_path, il2cpp=False)
    match = detect_engines(tmp_path / "Space Game.exe")[0]
    assert (match.engine, match.confidence) == ("Unity", "high")
    assert match.details == {"scripting": "Mono", "version": "2021.3.16f1"}
    assert "UnityPlayer.dll next to the executable" in match.evidence
    assert any("Space Game_Data" in e for e in match.evidence)
    assert "Space Game_Data/resources.assets" in match.asset_files
    assert "Space Game_Data/globalgamemanagers" in match.asset_files
    text = advice_text(match)
    assert "cannot open" in text
    assert "AssetStudio" in text and "UABEA" in text
    assert "ILSpy" in text and "dnSpy" in text
    assert "Il2CppDumper" not in text


def test_unity_il2cpp_game(tmp_path):
    unity_tree(tmp_path, il2cpp=True)
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("Unity", "high")
    assert match.details["scripting"] == "IL2CPP"
    assert any("GameAssembly.dll" in e for e in match.evidence)
    text = advice_text(match)
    assert "Il2CppDumper" in text and "global-metadata.dat" in text
    assert "AssetStudio" in text
    assert "ILSpy" not in text


def test_unity_scrambled_il2cpp_metadata_is_reported_not_decrypted(tmp_path):
    unity_tree(tmp_path, il2cpp=True)
    put(tmp_path, "Space Game_Data/il2cpp_data/Metadata/global-metadata.dat", b"\x13\x37" * 32)
    text = advice_text(detect_engines(tmp_path)[0])
    assert "does not decrypt" in text


def test_unity_is_matched_case_insensitively(tmp_path):
    exe(tmp_path, "game.exe")
    put(tmp_path, "unityplayer.dll", b"MZ")
    put(tmp_path, "game_data/globalgamemanagers", bytes(64))
    assert detect_engines(tmp_path)[0].engine == "Unity"


# --- Unreal ------------------------------------------------------------------------

def unreal_tree(root, footer: bytes = b""):
    put(root, "Engine/Binaries/ThirdParty/readme.txt", b"")
    put(root, "Shooter/Content/Paks/Shooter-WindowsNoEditor.pak", bytes(300) + footer)
    exe(root, "Shooter.exe")
    return exe(root, "Shooter/Binaries/Win64/Shooter-Win64-Shipping.exe")


def test_unreal_game_directory(tmp_path):
    unreal_tree(tmp_path)
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("Unreal Engine", "high")
    assert match.asset_files == ["Shooter/Content/Paks/Shooter-WindowsNoEditor.pak"]
    text = advice_text(match)
    assert "cannot open" in text
    assert "FModel" in text and "UE Viewer" in text


def test_unreal_shipping_executable_deep_in_the_tree(tmp_path):
    shipping = unreal_tree(tmp_path)
    match = detect_engines(shipping)[0]
    assert (match.engine, match.confidence) == ("Unreal Engine", "high")
    # asset paths are relative to the directory of the executable given
    assert match.asset_files == ["../../Content/Paks/Shooter-WindowsNoEditor.pak"]
    for relative in match.asset_files:
        assert (shipping.parent / relative).is_file()


def test_unreal_iostore_and_encrypted_index_are_reported(tmp_path):
    # FPakInfo, version 8+: key GUID (16), encrypted-index flag (1), magic
    # 0x5A6F12E1, version, index offset, index size, SHA-1, compression names.
    footer = (bytes(16) + b"\x01" + struct.pack("<IIqq", 0x5A6F12E1, 11, 0, 0)
              + bytes(20) + bytes(5 * 32))
    unreal_tree(tmp_path, footer)
    put(tmp_path, "Shooter/Content/Paks/global.utoc", bytes(16))
    put(tmp_path, "Shooter/Content/Paks/global.ucas", bytes(16))
    match = detect_engines(tmp_path)[0]
    assert match.details["pak_version"] == "11"
    assert match.details["pak_index_encrypted"] == "yes"
    assert "IoStore" in match.details["packaging"]
    assert "Shooter/Content/Paks/global.utoc" in match.asset_files
    text = advice_text(match)
    assert "encrypted" in text and "key" in text
    assert "does not" in text


# --- Godot -------------------------------------------------------------------------

def test_godot_pack_next_to_the_executable(tmp_path):
    game = exe(tmp_path, "platformer.exe")
    put(tmp_path, "platformer.pck", minimal_pck(fmt=2, engine=(4, 2, 1)))
    match = detect_engines(game)[0]
    assert (match.engine, match.confidence) == ("Godot", "high")
    assert match.details == {"version": "4.2.1", "pack_format": "2"}
    assert match.asset_files == ["platformer.pck"]
    assert any("platformer.pck" in e for e in match.evidence)
    text = advice_text(match)
    assert "binspect can list, extract and repack" in text
    assert "gdsdecomp" in text


def test_godot_3_pack_reports_its_version(tmp_path):
    put(tmp_path, "game.pck", minimal_pck(fmt=1, engine=(3, 5, 2)))
    match = detect_engines(tmp_path)[0]
    assert match.engine == "Godot"
    assert match.details == {"version": "3.5.2", "pack_format": "1"}


def test_godot_pack_embedded_in_the_executable(tmp_path):
    pck = minimal_pck(fmt=2, engine=(4, 3, 0), flags=2)
    game = exe(tmp_path, "single.exe", pck + struct.pack("<Q", len(pck)) + b"GDPC")
    match = detect_engines(game)[0]
    assert (match.engine, match.confidence) == ("Godot", "high")
    assert match.details["version"] == "4.3.0"
    assert match.asset_files == ["single.exe"]
    assert any("embedded" in e for e in match.evidence)


def test_godot_encrypted_pack_is_reported_not_decrypted(tmp_path):
    exe(tmp_path, "game.exe")
    put(tmp_path, "game.pck", minimal_pck(fmt=2, engine=(4, 2, 1), flags=1))
    match = detect_engines(tmp_path)[0]
    assert match.engine == "Godot"
    assert match.details["encrypted"] == "yes"
    text = advice_text(match)
    assert "encrypted" in text and "does not decrypt" in text
    assert "binspect can list" not in text


# --- GameMaker ---------------------------------------------------------------------

def test_gamemaker_data_file(tmp_path):
    exe(tmp_path, "runner.exe")
    put(tmp_path, "data.win", b"FORM" + struct.pack("<I", 16) + b"GEN8" + struct.pack("<I", 8)
        + b"\x00\x11\x00\x00" + bytes(4))
    put(tmp_path, "options.ini", b"[Windows]\n")
    put(tmp_path, "audiogroup1.dat", b"FORM" + bytes(12))
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("GameMaker", "high")
    assert match.details == {"bytecode_version": "17"}
    assert match.asset_files == ["audiogroup1.dat", "data.win"]
    text = advice_text(match)
    assert "UndertaleModTool" in text and "cannot open" in text


def test_a_file_named_data_win_without_the_signature_is_weak_evidence(tmp_path):
    put(tmp_path, "data.win", b"just some text")
    matches = detect_engines(tmp_path)
    assert names(matches) == ["GameMaker"]
    assert matches[0].confidence == "low"


# --- Ren'Py ------------------------------------------------------------------------

def test_renpy_game(tmp_path):
    exe(tmp_path, "novel.exe")
    put(tmp_path, "renpy/__init__.py", b"")
    put(tmp_path, "renpy/vc_version.py",
        b"vc_version = 23091805\nofficial = True\nnightly = False\nversion = '8.1.3.23091805'\n")
    put(tmp_path, "game/script.rpyc", b"RENPY RPC2")
    # header (34 bytes), then the zlib-compressed pickle of an empty index
    put(tmp_path, "game/archive.rpa",
        b"RPA-3.0 0000000000000022 42424242\n" + zlib.compress(pickle.dumps({}, 2)))
    put(tmp_path, "lib/py3-windows-x86_64/python.exe", b"MZ")
    match = detect_engines(tmp_path / "novel.exe")[0]
    assert (match.engine, match.confidence) == ("Ren'Py", "high")
    assert match.details["version"] == "8.1.3.23091805"
    assert match.asset_files == ["game/archive.rpa"]
    text = advice_text(match)
    assert "binspect can list, extract and repack" in text and "RPA" in text
    assert "unrpyc" in text


def test_renpy_archive_with_a_foreign_header_is_not_claimed(tmp_path):
    put(tmp_path, "renpy/__init__.py", b"")
    put(tmp_path, "game/archive.rpa", b"ZiX-12B 0000000000000022\n" + bytes(40))
    match = detect_engines(tmp_path)[0]
    assert match.engine == "Ren'Py"
    text = advice_text(match)
    assert "not supported" in text or "cannot open" in text


# --- RPG Maker ---------------------------------------------------------------------

def test_rpg_maker_mv(tmp_path):
    exe(tmp_path, "Game.exe")
    put(tmp_path, "www/js/rpg_core.js", b"// RPG Maker MV core\n")
    put(tmp_path, "www/data/System.json", b'{"gameTitle":"x","hasEncryptedImages":true}')
    put(tmp_path, "www/img/system/Window.rpgmvp", b"RPGMV\0\0\0" + bytes(24))
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("RPG Maker", "high")
    assert match.details["version"] == "MV"
    assert match.details["encrypted_assets"] == "yes"
    text = advice_text(match)
    assert "does not decrypt" in text


def test_rpg_maker_mz_without_encryption(tmp_path):
    put(tmp_path, "js/rmmz_core.js", b"// core\n")
    put(tmp_path, "data/System.json", b'{"hasEncryptedImages":false,"hasEncryptedAudio":false}')
    put(tmp_path, "img/system/Window.png", b"\x89PNG")
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.details["version"]) == ("RPG Maker", "MZ")
    assert "encrypted_assets" not in match.details
    assert "plain" in advice_text(match)


@pytest.mark.parametrize("archive, version", [
    ("Game.rgss3a", "VX Ace"), ("Game.rgss2a", "VX"), ("Game.rgssad", "XP")])
def test_rpg_maker_rgss_archive(tmp_path, archive, version):
    exe(tmp_path, "Game.exe")
    put(tmp_path, archive, b"RGSSAD\0\x03" + bytes(16))
    put(tmp_path, "Game.ini", b"[Game]\nLibrary=System\\RGSS301.dll\n")
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("RPG Maker", "high")
    assert match.details["version"] == version
    assert match.asset_files == [archive]
    text = advice_text(match)
    assert "encrypted" in text and "does not" in text


# --- Electron ----------------------------------------------------------------------

ASAR_HEADER = b'{"files":{"main.js":{"size":3,"offset":"0"}}}'      # 45 bytes -> 48


def asar_bytes() -> bytes:
    return (struct.pack("<IIII", 4, 56, 52, 45) + ASAR_HEADER + bytes(3) + b"1;\n")


def test_electron_app(tmp_path):
    exe(tmp_path, "App.exe")
    put(tmp_path, "resources/app.asar", asar_bytes())
    put(tmp_path, "version", b"28.2.1")
    put(tmp_path, "chrome_100_percent.pak", bytes(8))
    put(tmp_path, "icudtl.dat", bytes(8))
    match = detect_engines(tmp_path / "App.exe")[0]
    assert (match.engine, match.confidence) == ("Electron", "high")
    assert match.details == {"version": "28.2.1"}
    assert match.asset_files == ["resources/app.asar"]
    assert "resources/app.asar" in " ".join(match.evidence)
    text = advice_text(match)
    assert "binspect can list, extract and repack" in text
    assert "integrity" in text


# --- LÖVE --------------------------------------------------------------------------

LOVE_FILES = {"main.lua": b"function love.draw() end\n",
              "conf.lua": b'function love.conf(t)\n  t.version = "11.4"\nend\n'}


def test_love_game_fused_to_its_executable(tmp_path):
    love = make_zip(tmp_path / "tmp.love", LOVE_FILES).read_bytes()
    (tmp_path / "tmp.love").unlink()
    game = exe(tmp_path, "game.exe", love)
    put(tmp_path, "love.dll", b"MZ")
    put(tmp_path, "lua51.dll", b"MZ")
    match = detect_engines(game)[0]
    assert (match.engine, match.confidence) == ("LÖVE", "high")
    assert match.details == {"version": "11.4"}
    assert match.asset_files == ["game.exe"]
    assert any("main.lua" in e for e in match.evidence)
    text = advice_text(match)
    assert "binspect can list, extract and repack" in text


def test_love_file_next_to_the_runtime(tmp_path):
    make_zip(tmp_path / "game.love", LOVE_FILES)
    exe(tmp_path, "love.exe")
    match = detect_engines(tmp_path)[0]
    assert match.engine == "LÖVE"
    assert match.asset_files == ["game.love"]


# --- Source / GoldSrc --------------------------------------------------------------

def test_source_game(tmp_path):
    exe(tmp_path, "hl2.exe")
    put(tmp_path, "bin/engine.dll", b"MZ")
    put(tmp_path, "hl2/gameinfo.txt", b'"GameInfo"\n{\n}\n')
    put(tmp_path, "hl2/hl2_misc_dir.vpk", struct.pack("<III", 0x55AA1234, 2, 0) + bytes(16))
    put(tmp_path, "hl2/hl2_misc_000.vpk", bytes(32))
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("Source", "high")
    assert match.details["vpk_version"] == "2"
    assert match.asset_files == ["hl2/hl2_misc_000.vpk", "hl2/hl2_misc_dir.vpk"]
    text = advice_text(match)
    assert "cannot open" in text and "VPK" in text
    assert "GCFScape" in text or "VPKEdit" in text


def test_goldsrc_game_distinguishes_quake_paks_from_texture_wads(tmp_path):
    exe(tmp_path, "hl.exe")
    put(tmp_path, "valve/liblist.gam", b'game "Half-Life"\n')
    put(tmp_path, "valve/pak0.pak", b"PACK" + struct.pack("<ii", 12, 0))
    put(tmp_path, "valve/halflife.wad", b"WAD3" + struct.pack("<ii", 0, 12))
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("GoldSrc", "high")
    assert match.asset_files == ["valve/halflife.wad", "valve/pak0.pak"]
    text = advice_text(match)
    assert "binspect can list, extract and repack" in text and "PAK" in text
    assert "WAD3" in text and "cannot open" in text


# --- id Tech -----------------------------------------------------------------------

def test_quake_directory(tmp_path):
    exe(tmp_path, "quake.exe")
    put(tmp_path, "id1/pak0.pak", b"PACK" + struct.pack("<ii", 12, 0))
    put(tmp_path, "id1/pak1.pak", b"PACK" + struct.pack("<ii", 12, 0))
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("id Tech", "high")
    assert match.asset_files == ["id1/pak0.pak", "id1/pak1.pak"]
    text = advice_text(match)
    assert "binspect can list, extract and repack" in text


def test_doom_iwad(tmp_path):
    put(tmp_path, "DOOM2.WAD", b"IWAD" + struct.pack("<ii", 0, 12))
    exe(tmp_path, "gzdoom.exe")
    make_zip(tmp_path / "gzdoom.pk3", {"zscript.txt": b""})
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("id Tech", "high")
    assert match.asset_files == ["DOOM2.WAD", "gzdoom.pk3"]
    assert "SLADE" in advice_text(match)


def test_unreal_pak_is_not_mistaken_for_a_quake_pak(tmp_path):
    put(tmp_path, "Game/Content/Paks/Game.pak", bytes(400))
    assert "id Tech" not in names(detect_engines(tmp_path))


# --- Java --------------------------------------------------------------------------

MANIFEST = b"Manifest-Version: 1.0\r\nMain-Class: com.example.Game\r\n\r\n"


def test_java_game_with_a_jar_and_a_bundled_runtime(tmp_path):
    exe(tmp_path, "launcher.exe")
    make_zip(tmp_path / "game.jar", {"META-INF/MANIFEST.MF": MANIFEST,
                                     "com/example/Game.class": b"\xca\xfe\xba\xbe"})
    put(tmp_path, "jre/bin/java.exe", b"MZ")
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("Java", "high")
    assert match.details == {"main_class": "com.example.Game"}
    assert match.asset_files == ["game.jar"]
    text = advice_text(match)
    assert "binspect can list, extract and repack" in text and "JAR" in text
    assert "decompile" in text


def test_jar_file_given_directly(tmp_path):
    jar = make_zip(tmp_path / "app.jar", {"META-INF/MANIFEST.MF": MANIFEST})
    match = detect_engines(jar)[0]
    assert (match.engine, match.confidence) == ("Java", "high")
    assert match.asset_files == ["app.jar"]


# --- MonoGame / XNA ----------------------------------------------------------------

def test_monogame_game(tmp_path):
    exe(tmp_path, "Farm.exe")
    put(tmp_path, "MonoGame.Framework.dll", b"MZ")
    put(tmp_path, "Content/Fonts/Small.xnb", b"XNBw\x05\x80" + bytes(8))
    put(tmp_path, "Content/Title.xnb", b"XNBw\x05\x00" + bytes(8))
    match = detect_engines(tmp_path)[0]
    assert (match.engine, match.confidence) == ("MonoGame/XNA", "high")
    assert match.details == {"framework": "MonoGame"}
    assert match.asset_files == ["Content/Fonts/Small.xnb", "Content/Title.xnb"]
    text = advice_text(match)
    assert "cannot open" in text and "ILSpy" in text


def test_xna_and_fna_frameworks_are_told_apart(tmp_path):
    put(tmp_path, "a/Microsoft.Xna.Framework.dll", b"MZ")
    put(tmp_path, "a/Content/x.xnb", b"XNBw\x05\x00")
    put(tmp_path, "b/FNA.dll", b"MZ")
    put(tmp_path, "b/Content/x.xnb", b"XNBw\x05\x00")
    assert detect_engines(tmp_path / "a")[0].details == {"framework": "XNA"}
    assert detect_engines(tmp_path / "b")[0].details == {"framework": "FNA"}


# --- marker strings in the executable ----------------------------------------------

def test_marker_strings_in_the_executable_are_evidence(tmp_path):
    game = exe(tmp_path, "mystery.exe", bytes(5000) + b"ELECTRON_RUN_AS_NODE\0" + bytes(100))
    matches = detect_engines(game)
    assert names(matches) == ["Electron"]
    assert matches[0].confidence in ("low", "medium")
    assert any("ELECTRON_RUN_AS_NODE" in e for e in matches[0].evidence)


def test_utf16_marker_strings_are_found(tmp_path):
    game = exe(tmp_path, "mystery.exe", bytes(64) + "/Script/Engine".encode("utf-16-le"))
    assert names(detect_engines(game)) == ["Unreal Engine"]


def test_executable_scan_is_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(engines, "MAX_EXE_SCAN", 4096)
    game = exe(tmp_path, "mystery.exe", bytes(8192) + b"ELECTRON_RUN_AS_NODE\0")
    assert detect_engines(game) == []


# --- ordering ----------------------------------------------------------------------

def test_best_match_comes_first(tmp_path):
    unity_tree(tmp_path, il2cpp=False)
    make_zip(tmp_path / "tools/helper.jar", {"META-INF/MANIFEST.MF": MANIFEST})
    matches = detect_engines(tmp_path)
    assert matches[0].engine == "Unity"
    order = {"high": 0, "medium": 1, "low": 2}
    ranks = [order[m.confidence] for m in matches]
    assert ranks == sorted(ranks)


# --- robustness --------------------------------------------------------------------

def test_missing_path_gives_an_empty_list(tmp_path):
    assert detect_engines(tmp_path / "nope") == []
    assert detect_engines(tmp_path / "nope" / "game.exe") == []
    assert detect_engines("\0bad") == []


def test_unreadable_and_odd_files_are_skipped(tmp_path):
    os.symlink(tmp_path / "missing-target", tmp_path / "UnityPlayer.dll")   # dangling
    (tmp_path / "data.win").mkdir()                                         # a directory
    os.symlink(tmp_path, tmp_path / "loop")                                 # cycle
    put(tmp_path, "game/archive.rpa", b"")                                  # empty
    put(tmp_path, "x.pck", b"GD")                                           # truncated
    put(tmp_path, "y.jar", b"PK\x03\x04 not really a zip")
    put(tmp_path, "resources/app.asar", b"\x04\0\0\0\xff\xff\xff\x7f")
    for match in detect_engines(tmp_path):
        assert match.confidence in ("high", "medium", "low")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_named_pipes_are_never_opened(tmp_path):
    os.mkfifo(tmp_path / "data.win")
    os.mkfifo(tmp_path / "game.pck")
    os.mkfifo(tmp_path / "Game.exe")
    assert detect_engines(tmp_path) == []           # would block forever if opened


def test_permission_errors_are_swallowed(tmp_path, monkeypatch):
    put(tmp_path, "data.win", b"FORM" + bytes(60))
    put(tmp_path, "game.pck", minimal_pck())
    real_open = open

    def deny(file, *args, **kwargs):
        if str(file).startswith(str(tmp_path)):
            raise PermissionError(13, "Permission denied", str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", deny)
    matches = detect_engines(tmp_path)              # must not raise
    assert all(m.confidence == "low" for m in matches)


def test_unlistable_directory_is_skipped(tmp_path, monkeypatch):
    put(tmp_path, "data.win", b"FORM" + bytes(60))
    put(tmp_path, "locked/secret.pck", minimal_pck())
    real_scandir = os.scandir

    def scandir(path="."):
        if os.path.basename(str(path)) == "locked":
            raise PermissionError(13, "Permission denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    assert names(detect_engines(tmp_path)) == ["GameMaker"]


def test_tree_walk_is_depth_limited(tmp_path):
    put(tmp_path, "a/b/c/d/e/f/data.win", b"FORM" + bytes(60))
    assert detect_engines(tmp_path) == []
    assert names(detect_engines(tmp_path / "a/b/c/d/e/f")) == ["GameMaker"]


def test_tree_walk_inspects_a_bounded_number_of_entries(tmp_path, monkeypatch):
    for i in range(300):
        put(tmp_path, "junk/%03d.bin" % i)
    monkeypatch.setattr(engines, "MAX_SCAN_ENTRIES", 50)
    seen = []
    real_scandir = os.scandir

    class Counting:
        def __init__(self, path):
            self._it = real_scandir(path)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._it.close()

        def __iter__(self):
            for entry in self._it:
                seen.append(entry.name)
                yield entry

        def close(self):
            self._it.close()

    monkeypatch.setattr(os, "scandir", Counting)
    detect_engines(tmp_path)
    assert len(seen) <= 60
