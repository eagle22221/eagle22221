"""Which engine or runtime a game or program was built with, and what that
means for getting at its assets.

    for match in detect_engines("C:/Games/Example/Example.exe"):
        print(match.engine, match.confidence, match.evidence, match.advice)

Detection uses cheap evidence only: the names of neighbouring files and
folders, the signature of asset containers found there, and a capped scan of
the executable for marker strings. Nothing is executed and no file is read
in full. The advice says what binspect itself can do with the assets (see
binspect.archives) and names the established community tool for everything
it cannot; binspect never decrypts anything, so encrypted assets are only
reported.
"""
from __future__ import annotations

import os
import re
import stat
import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import archives

MAX_DEPTH = 3                   # directory levels listed below the game directory
MAX_SCAN_ENTRIES = 5000         # directory entries looked at, in total
MAX_EXE_SCAN = 64 << 20         # bytes of executables scanned for marker strings
MAX_ASSET_FILES = 200           # asset files reported per engine

_HIGH, _MEDIUM = 5, 3           # score needed for "high" / "medium" confidence
_STRONG, _GOOD, _WEAK = 5, 3, 1


@dataclass
class EngineMatch:
    engine: str                 # "Unity", "Unreal Engine", "Godot", ...
    confidence: str             # "high" | "medium" | "low"
    evidence: List[str] = field(default_factory=list)       # concrete reasons
    details: Dict[str, str] = field(default_factory=dict)   # e.g. {"scripting": "IL2CPP"}
    asset_files: List[str] = field(default_factory=list)    # relative to the game directory
    advice: List[str] = field(default_factory=list)         # honest next steps


# -- reading without surprises -----------------------------------------------------

def _read(path: str, size: int, offset: int = 0) -> bytes:
    """Up to `size` bytes of a regular file (from the end when offset < 0).
    b"" for anything unreadable: detection must never raise or block, so
    pipes, devices and directories are not opened at all."""
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode):
            return b""
        with open(path, "rb") as fh:
            if offset < 0:
                fh.seek(max(0, info.st_size + offset))
            elif offset:
                fh.seek(offset)
            return fh.read(size)
    except (OSError, ValueError):
        return b""


def _glob_regex(pattern: str) -> "re.Pattern[str]":
    """Shell-style pattern over '/'-separated lower-case paths; '*' and '?'
    do not cross a '/'."""
    out = ""
    for char in pattern.lower():
        out += "[^/]*" if char == "*" else "[^/]" if char == "?" else re.escape(char)
    return re.compile(out + r"\Z")


class _Tree:
    """A bounded listing of the game directory plus cached peeks into it.
    Paths are matched case-insensitively (Windows games are sloppy)."""

    def __init__(self, root: str, base: str, given: Optional[str]):
        self.root = root            # directory that is listed
        self.base = base            # directory asset paths are reported relative to
        self.given = given          # the file the caller pointed at, if any
        self.files: Dict[str, str] = {}     # lower-case relative path -> path as on disk
        self.dirs: Dict[str, str] = {}
        self._heads: Dict[str, bytes] = {}
        self._archives: Dict[str, object] = {}
        self._markers: Optional[Dict[str, List[str]]] = None
        self._walk()
        self.given_rel: Optional[str] = None
        if given:
            try:
                self.given_rel = os.path.relpath(given, root).replace(os.sep, "/")
            except ValueError:
                self.given_rel = None
            if self.given_rel and not self.given_rel.startswith("../"):
                self.files.setdefault(self.given_rel.lower(), self.given_rel)

    def _walk(self) -> None:
        budget = MAX_SCAN_ENTRIES
        queue: List[Tuple[str, int]] = [("", 0)]
        while queue and budget > 0:
            relative, depth = queue.pop(0)
            found = []
            try:
                with os.scandir(os.path.join(self.root, relative) if relative
                                else self.root) as entries:
                    for entry in entries:
                        budget -= 1
                        found.append(entry)
                        if budget <= 0:
                            break
            except OSError:
                continue
            for entry in sorted(found, key=lambda e: e.name):
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    is_file = not is_dir and entry.is_file()
                except OSError:
                    continue
                child = f"{relative}/{entry.name}" if relative else entry.name
                if is_dir:
                    self.dirs[child.lower()] = child
                    if depth < MAX_DEPTH:
                        queue.append((child, depth + 1))
                elif is_file:
                    self.files[child.lower()] = child

    # lookups ---------------------------------------------------------------------

    def file(self, *candidates: str) -> Optional[str]:
        for candidate in candidates:
            hit = self.files.get(candidate.lower())
            if hit:
                return hit
        return None

    def dir(self, *candidates: str) -> Optional[str]:
        for candidate in candidates:
            hit = self.dirs.get(candidate.lower())
            if hit:
                return hit
        return None

    def glob(self, *patterns: str, dirs: bool = False) -> List[str]:
        table = self.dirs if dirs else self.files
        regexes = [_glob_regex(p) for p in patterns]
        return sorted(actual for lower, actual in table.items()
                      if any(r.match(lower) for r in regexes))

    def named(self, *basenames: str) -> List[str]:
        """Files with one of these names, at any listed depth."""
        wanted = {b.lower() for b in basenames}
        return sorted(actual for lower, actual in self.files.items()
                      if lower.rsplit("/", 1)[-1] in wanted)

    def with_suffix(self, *suffixes: str) -> List[str]:
        return sorted(actual for lower, actual in self.files.items()
                      if lower.endswith(tuple(s.lower() for s in suffixes)))

    def path(self, relative: str) -> str:
        return os.path.normpath(os.path.join(self.root, relative))

    def report(self, relative: str) -> str:
        """A listed path as the caller should see it: relative to the game
        directory (the directory given, or the one holding the file given)."""
        try:
            return os.path.relpath(self.path(relative), self.base).replace(os.sep, "/")
        except ValueError:
            return relative

    def reports(self, relatives: Iterable[str]) -> List[str]:
        return sorted({self.report(r) for r in relatives})[:MAX_ASSET_FILES]

    # peeks -----------------------------------------------------------------------

    def head(self, relative: str, size: int = 4096) -> bytes:
        key = f"{relative}:{size}"
        if key not in self._heads:
            self._heads[key] = _read(self.path(relative), size)
        return self._heads[key]

    def tail(self, relative: str, size: int) -> bytes:
        return _read(self.path(relative), size, -size)

    def archive(self, relative: str):
        """(Archive or None, reason it could not be opened)."""
        if relative not in self._archives:
            try:
                self._archives[relative] = (archives.open_archive(self.path(relative)), "")
            except Exception as exc:        # unreadable or unsupported: report, never raise
                self._archives[relative] = (None, str(exc) or type(exc).__name__)
        return self._archives[relative]

    def member(self, relative: str, name: str, limit: int = 65536) -> bytes:
        """A small member of an archive, or b""."""
        archive, _reason = self.archive(relative)
        if archive is None:
            return b""
        try:
            return archive.read(name, max_size=limit)
        except Exception:
            return b""

    def member_names(self, relative: str) -> List[str]:
        archive, _reason = self.archive(relative)
        return [e.name for e in archive.entries] if archive is not None else []

    # executables -----------------------------------------------------------------

    def executables(self) -> List[str]:
        """The file given by the caller, or the likely executables at the top
        of the game directory (at most three)."""
        if self.given_rel:
            return [self.given_rel]
        out = []
        for lower, actual in sorted(self.files.items()):
            if "/" in lower:
                continue
            if lower.endswith((".exe", ".x86_64", ".x86")):
                out.append(actual)
            elif "." not in lower and self.head(actual, 4) == b"\x7fELF":
                out.append(actual)
            if len(out) == 3:
                break
        return out

    def markers(self) -> Dict[str, List[str]]:
        """Marker strings found in the executables: {engine: [marker, ...]}.
        ASCII and UTF-16LE spellings are searched; at most MAX_EXE_SCAN bytes
        are read in total."""
        if self._markers is not None:
            return self._markers
        needles = [(engine, text, text.encode("ascii"), text.encode("utf-16-le"))
                   for engine, texts in _MARKERS.items() for text in texts]
        overlap = max(len(n[3]) for n in needles)
        found: Dict[str, List[str]] = {}
        budget = MAX_EXE_SCAN
        for relative in self.executables():
            path = self.path(relative)
            try:
                if not stat.S_ISREG(os.stat(path).st_mode):
                    continue
                with open(path, "rb") as fh:
                    carry = b""
                    while budget > 0 and needles:
                        chunk = fh.read(min(1 << 20, budget))
                        if not chunk:
                            break
                        budget -= len(chunk)
                        window = carry + chunk
                        for needle in list(needles):
                            if needle[2] in window or needle[3] in window:
                                found.setdefault(needle[0], []).append(needle[1])
                                needles.remove(needle)
                        carry = window[-overlap:]
            except (OSError, ValueError):
                continue
        self._markers = found
        return found


# Strings that the engine's own runtime carries in its executable.
_MARKERS: Dict[str, List[str]] = {
    "Unity": ["UnityPlayer.dll", "UnityMain"],
    "Unreal Engine": ["/Script/Engine", "/Script/CoreUObject", "UnrealEngine"],
    "Godot": ["Godot Engine"],
    "GameMaker": ["YoYo Games", "GameMaker"],
    "Electron": ["ELECTRON_RUN_AS_NODE"],
    "Java": ["launch4j", "JNI_CreateJavaVM"],
    "MonoGame/XNA": ["Microsoft.Xna.Framework", "MonoGame.Framework"],
    "RPG Maker": ["RGSSGameMain"],
    "LÖVE": ["love.boot"],
}


class _Case:
    """Evidence being collected for one engine."""

    def __init__(self, engine: str, tree: _Tree):
        self.engine = engine
        self.tree = tree
        self.score = 0
        self.evidence: List[str] = []
        self.details: Dict[str, str] = {}
        self.assets: List[str] = []
        self.advice: List[str] = []

    def add(self, weight: int, text: str) -> None:
        self.score += weight
        self.evidence.append(text)

    def add_markers(self) -> None:
        hits = self.tree.markers().get(self.engine)
        if hits:
            quoted = ", ".join(f"'{h}'" for h in hits)
            self.add(_GOOD, f"marker string {quoted} in the executable")

    def result(self) -> Optional[Tuple[int, EngineMatch]]:
        if self.score <= 0:
            return None
        confidence = "high" if self.score >= _HIGH else "medium" if self.score >= _MEDIUM \
            else "low"
        return self.score, EngineMatch(
            engine=self.engine, confidence=confidence, evidence=self.evidence,
            details=self.details, asset_files=self.tree.reports(self.assets),
            advice=self.advice)


def _archive_advice(tree: _Tree, relative: str, what: str) -> Tuple[bool, str]:
    """(binspect can open it, advice saying exactly what it can do). The
    text is shown to end users as is, so it speaks of the Assets view and the
    command line, and it is only ever claimed after the container was
    actually opened."""
    shown = tree.report(relative)
    archive, reason = tree.archive(relative)
    if archive is None:
        return False, f"binspect cannot open {shown}: {reason.rstrip('.')}."
    if archive.writable:
        return True, (
            f"binspect can browse, extract and repack {what} ({shown}): open it in the "
            "Assets view, or run `binspect assets list PACK`, `binspect assets extract "
            "PACK FOLDER`, `binspect assets replace PACK NAME NEWFILE -o NEWPACK`. "
            "Repacking always writes a new file, so keep the original as a backup.")
    why = "; ".join(n for n in archive.notes if "repack" in n or "encrypted" in n)
    return True, (
        f"binspect can browse and extract {what} ({shown}) in the Assets view or with "
        "`binspect assets list PACK` and `binspect assets extract PACK FOLDER`, but "
        f"cannot repack it: {why.rstrip('.') or 'not supported for this pack'}.")


# -- detectors ---------------------------------------------------------------------

def _unity(tree: _Tree) -> _Case:
    case = _Case("Unity", tree)
    player = tree.file("UnityPlayer.dll", "UnityPlayer.so", "UnityPlayer.dylib")
    if player:
        case.add(_STRONG, f"{player} next to the executable")
    data_dir = None
    for folder in tree.glob("*_data", dirs=True):
        contents = [name for name in ("globalgamemanagers", "mainData", "data.unity3d",
                                      "resources.assets")
                    if tree.file(f"{folder}/{name}")]
        contents += [name + "/" for name in ("Managed", "il2cpp_data")
                     if tree.dir(f"{folder}/{name}")]
        if contents:
            data_dir = folder
            case.add(_STRONG, f"{folder}/ folder with Unity player data ({', '.join(contents)})")
            break
    il2cpp = tree.file("GameAssembly.dll", "GameAssembly.so", "GameAssembly.dylib")
    managed = tree.glob("*_data/managed/assembly-csharp.dll")
    if il2cpp:
        case.add(_GOOD, f"{il2cpp} (IL2CPP-compiled game code)")
        case.details["scripting"] = "IL2CPP"
    elif managed:
        case.add(_GOOD, f"{managed[0]} (Mono game code)")
        case.details["scripting"] = "Mono"
    crash = tree.file("UnityCrashHandler64.exe", "UnityCrashHandler32.exe")
    if crash:
        case.add(_GOOD, crash)
    if tree.dir("MonoBleedingEdge"):
        case.add(_WEAK, "MonoBleedingEdge/ folder")
    case.add_markers()
    if not case.score:
        return case

    if data_dir:
        for name in ("globalgamemanagers", "data.unity3d", "mainData", "level0"):
            found = tree.file(f"{data_dir}/{name}")
            version = found and re.search(
                rb"(?<![\d.])(\d{1,4}\.\d{1,2}\.\d{1,3}[abcfpx]\d{1,3})", tree.head(found, 256))
            if version:
                case.details["version"] = version.group(1).decode("ascii")
                break
    case.assets = tree.glob(
        "*_data/*.assets", "*_data/data.unity3d", "*_data/globalgamemanagers",
        "*_data/maindata", "*_data/level*", "*_data/*.bundle", "*_data/*.unity3d",
        "*_data/streamingassets/*.bundle", "*_data/streamingassets/*/*.bundle",
        "*_data/streamingassets/*.unity3d")
    case.advice.append(
        "binspect cannot open Unity's serialized files (.assets, level*, "
        "globalgamemanagers) or asset bundles / UnityFS (data.unity3d, *.bundle). Use "
        "AssetStudio or AssetRipper to browse and export assets, and UABEA to edit or "
        "replace them.")
    if case.details.get("scripting") == "IL2CPP":
        case.advice.append(
            "Game code is compiled to native code (IL2CPP) in GameAssembly: binspect can "
            "disassemble it like any native binary, but recovering class and method names "
            "needs Il2CppDumper or Cpp2IL together with il2cpp_data/Metadata/"
            "global-metadata.dat.")
        metadata = tree.glob("*_data/il2cpp_data/metadata/global-metadata.dat")
        if metadata and tree.head(metadata[0], 4) not in (b"", b"\xaf\x1b\xb1\xfa"):
            case.advice.append(
                f"{tree.report(metadata[0])} does not start with the IL2CPP metadata "
                "signature: it is probably encrypted or obfuscated. binspect does not "
                "decrypt it.")
    elif case.details.get("scripting") == "Mono":
        case.advice.append(
            f"Game code is .NET IL in {tree.report(managed[0])}: decompile and edit it "
            "with ILSpy or dnSpy (dnSpyEx). binspect only reads the PE headers of .NET "
            "assemblies; it does not decompile IL.")
    return case


def _unreal(tree: _Tree) -> _Case:
    case = _Case("Unreal Engine", tree)
    if tree.dir("Engine/Binaries"):
        case.add(_STRONG, "Engine/Binaries folder")
    elif tree.dir("Engine/Content"):
        case.add(_GOOD, "Engine/Content folder")
    paks = tree.glob("*/content/paks/*.pak", "content/paks/*.pak",
                     "*/content/paks/*/*.pak")
    if paks:
        case.add(_STRONG, f"{tree.report(paks[0])} (Content/Paks/*.pak)")
    iostore = tree.glob("*/content/paks/*.utoc", "*/content/paks/*.ucas",
                        "content/paks/*.utoc", "content/paks/*.ucas")
    packages = tree.glob("*/cookedpc/*.upk", "*/cookedpcconsole/*.upk", "*/content/*.upk")
    if packages:
        case.add(_GOOD, f"{tree.report(packages[0])} (Unreal Engine 3 package)")
    shipping = [e for e in tree.executables()
                if re.search(r"-(win64|win32|linux|wingdk)-shipping", e.lower())]
    if shipping:
        case.add(_GOOD, f"{shipping[0]} (Unreal shipping executable name)")
    if tree.glob("manifest_nonufsfiles_*.txt", "manifest_ufsfiles_*.txt"):
        case.add(_GOOD, "Manifest_NonUFSFiles_*.txt (Unreal packaging manifest)")
    case.add_markers()
    if not case.score:
        return case

    case.assets = paks + iostore + packages
    if iostore:
        case.details["packaging"] = "IoStore (.utoc/.ucas) with .pak"
    elif paks:
        case.details["packaging"] = ".pak"
    encrypted = False
    for pak in paks[:4]:
        # FPakInfo sits at the very end: [key GUID] [encrypted-index flag]
        # magic 0x5A6F12E1, version, index offset, index size, hash, ...
        tail = tree.tail(pak, 512)
        at = tail.rfind(b"\xe1\x12\x6f\x5a")
        if at < 1 or at + 8 > len(tail):
            continue
        (version,) = struct.unpack_from("<I", tail, at + 4)
        if not 1 <= version <= 32:
            continue
        case.details["pak_version"] = str(version)
        if version >= 4 and tail[at - 1] == 1:
            encrypted = True
            case.details["pak_index_encrypted"] = "yes"
        break
    case.advice.append(
        "binspect cannot open Unreal .pak or IoStore (.utoc/.ucas) containers, nor the "
        ".uasset/.umap packages inside. Use FModel or UE Viewer (umodel) to browse and "
        "export assets, and UnrealPak or repak to build paks.")
    case.advice.append(
        "Mods are normally shipped as an additional patch pak (a name ending in _P) in "
        "Content/Paks, often in a ~mods subfolder, rather than by rewriting the game's "
        "own pak.")
    if encrypted:
        case.advice.append(
            "The pak index is encrypted (AES): those tools need the game's key. binspect "
            "does not decrypt paks and does not recover keys.")
    return case


def _godot_header(data: bytes) -> Optional[Tuple[int, str, int]]:
    """(pack format, engine version, pack flags) from the start of a pack."""
    if len(data) < 20 or data[:4] != b"GDPC":
        return None
    fmt, major, minor, patch = struct.unpack_from("<IIII", data, 4)
    flags = struct.unpack_from("<I", data, 20)[0] if fmt >= 2 and len(data) >= 24 else 0
    return fmt, f"{major}.{minor}.{patch}", flags


def _godot(tree: _Tree) -> _Case:
    case = _Case("Godot", tree)
    header = None
    packs: List[str] = []
    for pck in tree.with_suffix(".pck")[:8]:
        head = tree.head(pck, 32)
        found = _godot_header(head)
        if found:
            packs.append(pck)
            header = header or found
            case.add(_STRONG, f"{tree.report(pck)} is a Godot pack ('GDPC' signature, pack "
                              f"format {found[0]}, engine {found[1]})")
        elif not head:
            case.add(_WEAK, f"{tree.report(pck)} (.pck file; its signature could not be read)")
    for executable in tree.executables():
        tail = tree.tail(executable, 12)
        if len(tail) == 12 and tail[8:] == b"GDPC":
            (size,) = struct.unpack_from("<Q", tail)
            try:
                start = os.path.getsize(tree.path(executable)) - 12 - size
            except OSError:
                continue
            found = _godot_header(_read(tree.path(executable), 32, start)) if start > 0 else None
            if found:
                packs.append(executable)
                header = header or found
                case.add(_STRONG, f"Godot pack embedded in {tree.report(executable)} at offset "
                                  f"{start:#x} (pack format {found[0]}, engine {found[1]})")
    case.add_markers()
    if not case.score:
        return case

    case.assets = packs
    encrypted = False
    if header:
        case.details["version"] = header[1]
        case.details["pack_format"] = str(header[0])
        if header[0] >= 2 and header[2] & 1:
            encrypted = True
            case.details["encrypted"] = "yes"
    if tree.glob("data_*/godotsharp.dll", "data_*/*/godotsharp.dll"):
        case.details["scripting"] = "C# (.NET) and GDScript"
    for pack in packs[:2]:
        case.advice.append(_archive_advice(tree, pack, "this Godot pack")[1])
    if encrypted:
        case.advice.append(
            "The pack's index is encrypted with a key compiled into the game. binspect "
            "reports this but does not decrypt the pack or recover the key.")
    if packs:
        case.advice.append(
            "Files inside a pack are in Godot's imported formats (.ctex/.stex textures, "
            ".sample/.oggvorbisstr audio, binary .scn/.res, compiled .gdc scripts): use "
            "gdsdecomp (GDRE Tools) to convert them back or to decompile scripts.")
    if "scripting" in case.details:
        case.advice.append(
            "C# game code is in .NET assemblies under the data_* folder: decompile them "
            "with ILSpy or dnSpy.")
    return case


def _gamemaker(tree: _Tree) -> _Case:
    case = _Case("GameMaker", tree)
    data_files = tree.named("data.win", "game.unx", "game.ios", "game.droid")
    confirmed = None
    for data in data_files:
        head = tree.head(data, 32)
        if head[:4] == b"FORM":
            confirmed = confirmed or data
            case.add(_STRONG, f"{tree.report(data)} starts with GameMaker's 'FORM' signature")
            if head[8:12] == b"GEN8" and len(head) >= 18:
                case.details.setdefault("bytecode_version", str(head[17]))
        else:
            case.add(_WEAK, f"a file named {tree.report(data)} (GameMaker's data file name, "
                            "signature not confirmed)")
    if confirmed and tree.file("options.ini"):
        case.add(_WEAK, "options.ini next to the data file")
    case.add_markers()
    if not case.score:
        return case
    case.assets = data_files + tree.glob("audiogroup*.dat", "*/audiogroup*.dat")
    case.advice.append(
        "binspect cannot open data.win / game.unx (GameMaker's IFF-style 'FORM' data "
        "file holding sprites, sounds, rooms and code). Use UndertaleModTool to browse "
        "and edit it.")
    case.advice.append(
        "Games built with the YYC compiler have their code compiled into the executable "
        "instead of bytecode in the data file; binspect can disassemble that as native "
        "code but cannot recover GML.")
    return case


def _renpy(tree: _Tree) -> _Case:
    case = _Case("Ren'Py", tree)
    if tree.dir("renpy"):
        case.add(_GOOD, "renpy/ folder (the engine's Python package)")
        if tree.file("renpy/__init__.py", "renpy/__init__.pyo", "renpy/__init__.pyc") \
                or tree.dir("renpy/common"):
            case.add(_GOOD, "renpy/ contains the engine modules")
    archives_found = tree.with_suffix(".rpa")
    if tree.glob("game/*.rpa"):
        case.add(_GOOD, f"{tree.glob('game/*.rpa')[0]} (Ren'Py archive in game/)")
    scripts = tree.glob("game/*.rpyc", "game/*.rpy", "game/*/*.rpyc", "game/*/*.rpy")
    if scripts:
        case.add(_GOOD, f"{scripts[0]} (Ren'Py script)")
    if tree.glob("lib/py*", "lib/windows-*", "lib/linux-*", dirs=True):
        case.add(_WEAK, "lib/ folder with a bundled Python runtime")
    if not case.score:
        return case

    version = re.search(rb"""(?m)^version\s*=\s*u?['"]([0-9][0-9.]*)['"]""",
                        tree.head("renpy/vc_version.py", 4096)
                        if tree.file("renpy/vc_version.py") else b"")
    if version:
        case.details["version"] = version.group(1).decode("ascii")
    case.assets = archives_found
    if archives_found:
        ok, sentence = _archive_advice(tree, archives_found[0], "Ren'Py RPA archives")
        case.advice.append(sentence)
        if not ok:
            case.advice.append(
                "Only the standard RPA-2.0 and RPA-3.0 archive layouts are supported; a "
                "different header means the developer changed the format, which is not "
                "supported.")
    case.advice.append(
        "Ren'Py looks for a file in the game/ folder before it looks in the archives, so "
        "a changed image, sound or script can simply be placed in game/ under the same "
        "path; repacking is rarely necessary.")
    case.advice.append(
        ".rpyc files are compiled scripts: binspect does not decompile them; use unrpyc "
        "to get .rpy sources back.")
    return case


_RPG_ENCRYPTED = (".rpgmvp", ".rpgmvo", ".rpgmvm", ".png_", ".ogg_", ".m4a_")


def _rpg_maker(tree: _Tree) -> _Case:
    case = _Case("RPG Maker", tree)
    mv = tree.file("www/js/rpg_core.js", "js/rpg_core.js")
    mz = tree.file("js/rmmz_core.js", "www/js/rmmz_core.js")
    rgss = tree.glob("*.rgss3a", "*.rgss2a", "*.rgssad")
    if mz:
        case.add(_STRONG, f"{mz} (RPG Maker MZ core script)")
        case.details["version"] = "MZ"
    elif mv:
        case.add(_STRONG, f"{mv} (RPG Maker MV core script)")
        case.details["version"] = "MV"
    if rgss:
        suffix = rgss[0].lower().rsplit(".", 1)[-1]
        case.details.setdefault(
            "version", {"rgss3a": "VX Ace", "rgss2a": "VX", "rgssad": "XP"}[suffix])
        case.add(_STRONG, f"{rgss[0]} (RGSS encrypted archive)")
    libraries = tree.glob("rgss*.dll", "system/rgss*.dll")
    if libraries:
        case.add(_GOOD, f"{libraries[0]} (RGSS runtime library)")
    if tree.file("RPG_RT.exe") and tree.file("RPG_RT.ldb", "RPG_RT.lmt"):
        case.add(_STRONG, "RPG_RT.exe with RPG_RT.ldb (RPG Maker 2000/2003)")
        case.details.setdefault("version", "2000/2003")
    case.add_markers()
    if not case.score:
        return case

    case.assets = list(rgss)
    if mv or mz:
        system = tree.file("www/data/System.json", "data/System.json")
        flagged = bool(system and re.search(
            rb'"hasEncrypted(Images|Audio)"\s*:\s*true', tree.head(system, 1 << 20)))
        scrambled = tree.with_suffix(*_RPG_ENCRYPTED)
        if flagged or scrambled:
            case.details["encrypted_assets"] = "yes"
            case.assets += scrambled
            case.advice.append(
                "Images and/or audio were deployed with RPG Maker's built-in asset "
                "encryption (.rpgmvp/.rpgmvo/.rpgmvm, or .png_/.ogg_/.m4a_ in MZ). binspect "
                "reports this but does not decrypt them.")
        else:
            case.advice.append(
                "Images (img/) and audio (audio/) are plain .png/.ogg/.m4a files: replace "
                "them directly, no container is involved.")
        case.advice.append(
            "Game data (data/*.json), scripts (js/) and plugins are plain text files "
            "that can be edited directly.")
    if rgss:
        case.advice.append(
            f"{rgss[0]} is an RGSS archive, which is always encrypted: binspect cannot "
            "open it and does not decrypt it.")
    if case.details.get("version") == "2000/2003":
        case.advice.append(
            "RPG Maker 2000/2003 keeps assets as loose files in folders next to "
            "RPG_RT.exe (some in the proprietary XYZ image format); binspect has no "
            "special support for its .ldb/.lmu databases. EasyRPG's tools can read them.")
    return case


def _electron(tree: _Tree) -> _Case:
    case = _Case("Electron", tree)
    app = tree.file("resources/app.asar")
    if app:
        case.add(_STRONG, f"{app} (Electron application archive)")
    elif tree.file("resources/app/package.json"):
        case.add(_GOOD, "resources/app/package.json (unpacked Electron application)")
    other = tree.file("resources/electron.asar", "resources/default_app.asar")
    if other:
        case.add(_GOOD, other)
    is_nw = tree.file("nw.pak", "nw.dll", "package.nw", "nw_100_percent.pak")
    runtime = [name for name in ("icudtl.dat", "v8_context_snapshot.bin", "snapshot_blob.bin",
                                 "chrome_100_percent.pak", "resources.pak")
               if tree.file(name)]
    if case.score and len(runtime) >= 2 and not is_nw:
        case.add(_WEAK, f"Chromium runtime files ({', '.join(runtime)})")
    case.add_markers()
    if not case.score:
        return case

    version = re.match(rb"v?(\d+\.\d+\.\d+)\s*\Z", tree.head("version", 64)
                       if tree.file("version") else b"")
    if version:
        case.details["version"] = version.group(1).decode("ascii")
    case.assets = tree.glob("resources/*.asar")
    if app:
        case.advice.append(_archive_advice(tree, app, "the application archive")[1])
        case.advice.append(
            "The archive holds the app's JavaScript, HTML and CSS as plain files. Files "
            "its header marks as unpacked live in resources/app.asar.unpacked/ instead.")
        case.advice.append(
            "If the app enables Electron's ASAR integrity validation, a modified "
            "app.asar is rejected unless the hash stored in the executable is updated "
            "as well; binspect does not do that.")
    elif tree.file("resources/app/package.json"):
        case.advice.append(
            "The application is not packed: its JavaScript, HTML and CSS are plain "
            "files under resources/app/ and can be edited directly.")
    else:
        case.advice.append(
            "No resources/app.asar was found next to this executable; if it exists "
            "elsewhere, binspect.archives.open_archive can list, extract and repack it.")
    return case


def _love(tree: _Tree) -> _Case:
    case = _Case("LÖVE", tree)
    containers: List[str] = []
    for executable in tree.executables():
        if executable.lower().endswith(".love"):
            continue
        if archives.detect_format(tree.path(executable)) == "zip" \
                and "main.lua" in tree.member_names(executable):
            containers.append(executable)
            case.add(_STRONG, f"{tree.report(executable)} has a ZIP appended that contains "
                              "main.lua (a LÖVE game fused to its executable)")
    for love in tree.glob("*.love"):
        if "main.lua" in tree.member_names(love):
            containers.append(love)
            case.add(_STRONG, f"{tree.report(love)} is a ZIP containing main.lua")
        else:
            case.add(_GOOD, f"{tree.report(love)} (.love file)")
            containers.append(love)
    runtime = tree.file("love.dll", "love.exe", "liblove.so") or \
        (tree.glob("liblove*.so*", "lib/liblove*.so*") or [None])[0]
    if runtime:
        case.add(_GOOD, f"{runtime} (LÖVE runtime)")
    if tree.file("main.lua") and b"love." in tree.head("main.lua", 65536) + (
            tree.head("conf.lua", 65536) if tree.file("conf.lua") else b""):
        case.add(_GOOD, "main.lua using the love.* API (unpacked LÖVE game)")
    if case.score:
        case.add_markers()
    if not case.score:
        return case

    conf = b""
    for container in containers:
        conf = conf or tree.member(container, "conf.lua")
    if not conf and tree.file("conf.lua"):
        conf = tree.head("conf.lua", 65536)
    version = re.search(rb"""\.version\s*=\s*["']([0-9][0-9.]*)["']""", conf)
    if version:
        case.details["version"] = version.group(1).decode("ascii")
    case.assets = containers
    if containers:
        case.advice.append(_archive_advice(
            tree, containers[0], "the game archive (a plain ZIP)")[1])
    case.advice.append(
        "A LÖVE game is Lua source plus loose images and sounds. Scripts are normally "
        "plain text; if they were precompiled to LuaJIT bytecode, binspect does not "
        "decompile them.")
    return case


def _source(tree: _Tree) -> _Case:
    case = _Case("Source", tree)
    gameinfo = tree.glob("*/gameinfo.txt")
    if gameinfo:
        case.add(_STRONG, f"{gameinfo[0]} (Source game definition)")
    source2 = tree.glob("game/*/gameinfo.gi") or tree.glob("game/bin/*/engine2.dll")
    if source2:
        case.add(_STRONG, f"{source2[0]} (Source 2)")
        case.details["generation"] = "Source 2"
    vpks = tree.with_suffix(".vpk")
    version = None
    for vpk in [v for v in vpks if v.lower().endswith("_dir.vpk")] + vpks:
        head = tree.head(vpk, 12)
        if len(head) >= 8 and head[:4] == b"\x34\x12\xaa\x55":
            (version,) = struct.unpack_from("<I", head, 4)
            case.add(_STRONG, f"{vpk} is a Valve pack file (VPK signature, version {version})")
            if version in (1, 2):
                case.details["vpk_version"] = str(version)
            break
    if vpks and version is None:
        case.add(_WEAK, f"{vpks[0]} (.vpk file)")
    launcher = tree.file("hl2.exe", "hl2_linux", "hl2.sh", "hl2_osx")
    if launcher:
        case.add(_GOOD, f"{launcher} (Source launcher)")
    engine = tree.file("bin/engine.dll", "bin/engine.so", "bin/engine_srv.so",
                       "bin/win64/engine.dll", "bin/x64/engine.dll")
    if engine:
        case.add(_GOOD, engine)
    if not case.score:
        return case
    case.assets = vpks
    case.advice.append(
        "binspect cannot open Valve VPK pack files. Use VPKEdit or GCFScape to browse "
        "and extract them, and Valve's vpk tool (shipped in the game's bin folder) to "
        "build new ones.")
    case.advice.append(
        "Many Source games load loose files or extra VPKs from a custom/ or addons/ "
        "folder inside the game folder, which avoids rewriting the original packs.")
    return case


def _goldsrc(tree: _Tree) -> _Case:
    case = _Case("GoldSrc", tree)
    liblist = tree.glob("*/liblist.gam")
    if liblist:
        case.add(_STRONG, f"{liblist[0]} (GoldSrc game definition)")
    launcher = tree.file("hl.exe", "hl_linux", "hl.sh")
    if launcher and (liblist or tree.dir("valve")):
        case.add(_GOOD, f"{launcher} (Half-Life launcher)")
    if not liblist:
        case.score = 0
        return case
    paks = [p for p in tree.glob("*/*.pak") if tree.head(p, 4) == b"PACK"]
    wads = tree.glob("*/*.wad")
    case.assets = paks + wads
    if paks:
        case.advice.append(_archive_advice(tree, paks[0], "the Quake-format PAK files")[1])
    texture_wads = [w for w in wads if tree.head(w, 4) in (b"WAD3", b"WAD2")]
    if texture_wads:
        case.advice.append(
            f"{tree.report(texture_wads[0])} and the other .wad files are Half-Life "
            "texture WADs (WAD3), a different format from Doom's IWAD/PWAD: binspect "
            "cannot open them. Use a WAD3 editor such as Wally.")
    case.advice.append(
        "GoldSrc loads loose files from the game folder (and its _addon/_hd variants) "
        "before pak files, so replacement assets can usually be placed there directly.")
    return case


_QUAKE_DIRS = ("id1", "hipnotic", "rogue", "baseq2", "baseq3", "base", "missionpack",
               "xatrix", "main", "data")


def _id_tech(tree: _Tree) -> _Case:
    case = _Case("id Tech", tree)
    if tree.glob("*/liblist.gam"):
        return case                      # GoldSrc: reported as its own engine
    paks = [p for p in tree.with_suffix(".pak")[:40] if tree.head(p, 4) == b"PACK"]
    if paks:
        folder = paks[0].lower().split("/")[0] if "/" in paks[0] else ""
        weight = _STRONG if folder in _QUAKE_DIRS else _GOOD
        case.add(weight, f"{paks[0]} is a Quake PAK ('PACK' signature)")
    iwads, pwads = [], []
    for wad in tree.with_suffix(".wad")[:40]:
        magic = tree.head(wad, 4)
        if magic == b"IWAD":
            iwads.append(wad)
        elif magic == b"PWAD":
            pwads.append(wad)
    if iwads:
        case.add(_STRONG, f"{iwads[0]} is a Doom IWAD (the game's main data file)")
    elif pwads:
        case.add(_GOOD, f"{pwads[0]} is a Doom PWAD")
    zips = [z for z in tree.with_suffix(".pk3", ".pk4", ".kpf")[:40]
            if tree.head(z, 4) == b"PK\x03\x04"]
    if zips:
        case.add(_GOOD, f"{zips[0]} (id Tech 3/4 style ZIP pack)")
    if not case.score:
        return case
    case.assets = paks + iwads + pwads + zips
    seen = set()
    for container, what in ([(p, "Quake PAK files") for p in paks[:1]]
                            + [(w, "Doom WAD files") for w in (iwads + pwads)[:1]]
                            + [(z, "pk3/pk4/kpf packs (plain ZIP)") for z in zips[:1]]):
        if what not in seen:
            seen.add(what)
            case.advice.append(_archive_advice(tree, container, what)[1])
    case.advice.append(
        "These engines let later packs override earlier ones (pak1 over pak0, a PWAD "
        "loaded with -file over the IWAD): ship changes as an additional pack instead "
        "of rewriting the original.")
    if iwads or pwads:
        case.advice.append(
            "WAD lumps are in Doom's own formats (patches, flats, maps, DMX sounds): "
            "binspect extracts and replaces the raw lumps; use SLADE to view, convert "
            "and edit them.")
    return case


def _java(tree: _Tree) -> _Case:
    case = _Case("Java", tree)
    main_jar = None
    for executable in tree.executables():
        if archives.detect_format(tree.path(executable)) == "zip" \
                and "META-INF/MANIFEST.MF" in tree.member_names(executable):
            main_jar = main_jar or executable
            kind = "is a JAR" if executable.lower().endswith(".jar") \
                else "has a JAR appended (wrapped Java application)"
            case.add(_STRONG, f"{tree.report(executable)} {kind}: ZIP with "
                              "META-INF/MANIFEST.MF")
    top = [j for j in tree.glob("*.jar") if j != main_jar]
    nested = tree.glob("*/*.jar", "*/*/*.jar")
    if top:
        case.add(_GOOD, f"{top[0]} next to the executable")
    elif nested and not main_jar:
        case.add(_WEAK, f"{nested[0]} (.jar file in a subfolder)")
    runtime = tree.file(*[f"{d}/bin/{n}" for d in ("jre", "runtime", "jdk", "java")
                          for n in ("java.exe", "javaw.exe", "java")])
    if runtime and case.score:
        case.add(_GOOD, f"bundled Java runtime ({runtime})")
    case.add_markers()
    if not case.score:
        return case

    jars = ([main_jar] if main_jar else []) + top + nested
    case.assets = jars
    stem = os.path.splitext(os.path.basename(tree.given or ""))[0].lower()
    preferred = main_jar or next(
        (j for j in top if os.path.splitext(j)[0].lower() == stem), None) or \
        (top[0] if top else None)
    if preferred:
        main_class = re.search(rb"(?mi)^Main-Class:[ \t]*([\w.$]+)",
                               tree.member(preferred, "META-INF/MANIFEST.MF"))
        if main_class:
            case.details["main_class"] = main_class.group(1).decode("ascii", "replace")
    if jars:
        case.advice.append(_archive_advice(
            tree, preferred or jars[0], "JAR files (they are ZIP archives)")[1])
        case.advice.append(
            "Images, sounds and data inside a JAR are ordinary files. .class files are "
            "JVM bytecode, which binspect does not decompile: use a Java decompiler "
            "such as CFR, Vineflower or JD-GUI, or Recaf to edit classes.")
        case.advice.append(
            "A signed JAR (META-INF/*.SF) fails verification once changed: remove the "
            "signature files or re-sign it.")
    else:
        case.advice.append(
            "The executable looks like a Java launcher but no JAR was found next to "
            "it; JAR files are ZIP archives that binspect can list, extract and repack.")
    return case


def _monogame(tree: _Tree) -> _Case:
    case = _Case("MonoGame/XNA", tree)
    monogame = tree.file("MonoGame.Framework.dll") or \
        (tree.glob("*/monogame.framework.dll") or [None])[0]
    fna = tree.file("FNA.dll")
    xna = (tree.glob("microsoft.xna.framework*.dll") or [None])[0]
    for library, name in ((monogame, "MonoGame"), (fna, "FNA"), (xna, "XNA")):
        if library:
            case.add(_STRONG, f"{library} ({name} framework assembly)")
            case.details.setdefault("framework", name)
    content = tree.glob("content/*.xnb", "content/*/*.xnb", "content/*/*/*.xnb")
    if content:
        if tree.head(content[0], 3) == b"XNB":
            case.add(_STRONG if not case.score else _GOOD,
                     f"{content[0]} (compiled XNA content, 'XNB' signature)")
        else:
            case.add(_WEAK, f"{content[0]} (.xnb file)")
    case.add_markers()
    if not case.score:
        return case
    case.assets = content
    case.advice.append(
        "binspect cannot open .xnb files (XNA's compiled content, usually LZX or LZ4 "
        "compressed). Use an XNB tool such as xnbcli to unpack and repack them.")
    case.advice.append(
        "The game code is .NET: decompile and edit the game's .exe and .dll assemblies "
        "with ILSpy or dnSpy. binspect only reads their PE headers.")
    return case


_DETECTORS: Sequence[Callable[[_Tree], _Case]] = (
    _unity, _unreal, _godot, _gamemaker, _renpy, _rpg_maker, _electron, _love,
    _source, _goldsrc, _id_tech, _java, _monogame,
)


def _tree_for(path) -> Optional[_Tree]:
    target = os.path.abspath(os.fspath(path))
    mode = os.stat(target).st_mode
    if stat.S_ISDIR(mode):
        return _Tree(target, target, None)
    if not stat.S_ISREG(mode):
        return None
    base = os.path.dirname(target)
    root = base
    # <root>/<Project>/Binaries/<Platform>/<Project>-Win64-Shipping.exe: the
    # game directory proper is three levels up.
    if os.path.basename(os.path.dirname(base)).lower() == "binaries":
        candidate = os.path.dirname(os.path.dirname(os.path.dirname(base)))
        if os.path.isdir(candidate):
            root = candidate
    return _Tree(root, base, target)


def detect_engines(path) -> List[EngineMatch]:
    """Engines/runtimes recognised for an executable or a game directory,
    best match first; [] if nothing is recognised or the path is unusable.
    Never raises on unreadable files or directories: they are skipped."""
    try:
        tree = _tree_for(path)
    except Exception:           # missing, unreadable or nonsensical path
        return []
    if tree is None:
        return []
    scored: List[Tuple[int, EngineMatch]] = []
    for detector in _DETECTORS:
        try:
            result = detector(tree).result()
        except Exception:       # one detector tripping must not hide the others
            continue
        if result:
            scored.append(result)
    scored.sort(key=lambda item: -item[0])
    return [match for _score, match in scored]
