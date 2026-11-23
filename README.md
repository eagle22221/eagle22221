# binspect

A reverse-engineering toolkit for **Linux (ELF)** and **Windows (PE: `.exe`, `.dll`)** programs
that runs on both systems. It takes a compiled program apart without ever running it, and it can
open game asset packs and save modified copies.

A step-by-step beginner's guide with screenshots is in
[`docs/binspect-guide.pdf`](docs/binspect-guide.pdf).

## What it does

| Area | What you get |
|---|---|
| Identity | Format, CPU, entry point, hashes, build details, compiler, debug-file path |
| Protections | NX/DEP, PIE/ASLR, RELRO, stack canaries, Control Flow Guard, signatures |
| Layout | Sections and segments with permissions and entropy; data appended after the program |
| Imports and exports | Which system functions a program uses, and where it calls them |
| Strings | ASCII and UTF-16 text, with URLs, IP addresses, e-mails, paths and registry keys flagged |
| Code | Disassembly (x86, x86-64, ARM64; ARM, MIPS, PowerPC best-effort) with names, strings and imports annotated |
| Functions | Found from symbols, exports, the Windows exception table and call targets; `main` recovered in stripped Linux programs |
| Cross-references | Every instruction that calls, jumps to or mentions an address, function, import or string |
| Game engines | Recognises Unity, Unreal, Godot, GameMaker, Ren'Py, RPG Maker, Electron and others, and says where the assets are |
| Asset packs | Browse, extract, replace and repack ZIP-family packs, Quake PAK, Doom WAD, Godot PCK, Electron ASAR, Ren'Py RPA |
| Windows resources | List, extract and replace icons, version info, manifests and embedded data |
| Patching | Overwrite bytes, blank out instructions, or replace text, always into a copy or with a backup |

## Install

Python 3.9 or newer, on Linux or Windows.

```
pip install .
```

This installs the `binspect` command and its one dependency, the Capstone disassembler.
Without installing, `python -m binspect ...` works from this folder once Capstone is present
(`pip install capstone`).

## The graphical interface

```
binspect gui                # then choose a file in the browser
binspect gui path/to/game   # or open something straight away
```

This starts a small server on your own computer and opens it in your browser. Nothing is sent
anywhere. Drop a file on the page or use **Open file or folder**.

- **Overview** — what the file is, how it is protected, what it needs.
- **Code** — functions on the left, instructions in the middle, "used by" on the right. Click a call to follow it.
- **Strings** — search the text in the file; **Find uses** jumps to the code that reads it.
- **Imports**, **Sections**, **Bytes** — the supporting tables and a hex view.
- **Assets** — the game engine, its asset packs, and resources inside Windows programs.
- **Modify** — save a patched copy.

The strip across the top is the file drawn to scale: click any part to see its bytes.

## The command line

```
binspect info FILE                     identity, hashes, protections
binspect report FILE                   everything at a glance
binspect sections FILE                 section table with entropy
binspect imports FILE                  imported functions, grouped by library
binspect exports FILE                  exported functions
binspect symbols FILE [--grep REGEX]
binspect strings FILE [-n MIN] [-e ascii|utf16] [--grep REGEX] [--tagged]
binspect functions FILE [--grep REGEX]
binspect disasm FILE [LOCATION] [-n COUNT]
binspect xrefs FILE TARGET             who uses this function, import or address
binspect xrefs FILE --string TEXT      who uses strings containing TEXT
binspect hexdump FILE [LOCATION] [--offset N] [-n BYTES]
```

`LOCATION` and `TARGET` accept a function, symbol or import name (`main`, `puts`,
`kernel32.dll!WriteFile`), a `0x` address, or `entry`. Add `--json` before the command for
machine-readable output, for example `binspect --json info FILE`.

A typical first look at an unknown program:

```
binspect info suspicious.exe
binspect strings suspicious.exe --tagged
binspect xrefs suspicious.exe --string "http"
binspect disasm suspicious.exe sub_401230
```

## Games and modding

```
binspect engine GAME_FOLDER                         which engine, where the assets are
binspect assets list data.pck
binspect assets extract data.pck out_folder
binspect assets replace data.pck sprites/hero.png my_hero.png -o data.modded.pck
binspect assets add data.pck mods/extra.txt extra.txt -o data.modded.pck

binspect resources list game.exe
binspect resources extract game.exe out_folder
binspect resources replace game.exe RCDATA 101 new.bin -o game.modded.exe

binspect patch nop game.exe 0x401234 5 -o game.patched.exe
binspect patch bytes game.exe 0x401234 "eb 05" -o game.patched.exe
binspect patch string game.exe "Old text" "New" -o game.patched.exe
```

To try these without a real game, `examples/demo_game` is a pretend game with one asset pack
(`python examples/make_demo_game.py` rebuilds it).

Rules the modding features follow:

- **The original is never changed unless you ask.** Packs and resources are always written to a
  new file. `patch` needs `-o OUT`, or `--in-place`, which first keeps the original as `FILE.bak`.
- **Patches overwrite, they do not insert.** The file size never changes, and replacement text
  cannot be longer than the text it replaces.
- **No circumvention.** Encrypted packs and protected content are detected and reported, not
  decrypted. There is nothing here for removing DRM, licence checks or anti-cheat.
- **Signed programs.** Changing a signed Windows program invalidates its signature.
- For formats binspect does not rebuild (Unity bundles, Unreal `.pak`, .NET and IL2CPP code),
  `binspect engine` names the community tool that does.

Only modify software you are allowed to modify, and keep to single-player or offline use where a
game's rules require it.

## Safety

- Files are parsed, never executed, so it is safe to point binspect at untrusted programs.
- The parsers are written for hostile input: every offset and count read from a file is
  bounds-checked, and a corrupt table costs a warning rather than a crash.
- Extraction refuses paths that would land outside the destination folder.
- The web interface listens on `127.0.0.1` only. Each session has a random key carried in the link;
  requests without it, or addressed to another host name, are refused.

## Development

```
pip install -e ".[dev]"
python -m pytest
```

The tests run against small programs in `tests/fixtures/bin`, built from the sources in
`tests/fixtures/src` by `tests/fixtures/build.sh` (needs gcc, clang and lld; the built files are
committed, so running the tests needs no compiler). Expected values in the tests were read from
those files with independent tools (`readelf`, `objdump`, `llvm-readobj`, `pefile`), not produced
by binspect.

```
binspect/
  elf.py, pe.py        format parsers -> one Binary model (model.py)
  strings.py           string extraction and tagging
  disasm.py            Capstone wrapper with annotations
  analysis.py          functions, name resolution, cross-references
  archives/            asset pack formats (ZIP family, PAK, WAD, PCK, ASAR, RPA)
  engines.py           game engine detection
  resources.py         Windows resources
  patch.py             byte, instruction and text patches
  views.py             JSON-ready views shared by the CLI and the web UI
  cli.py               command line
  server.py, web/      local web interface
```

## Limits

- Static analysis only: no debugger, no emulation, no decompiler to C.
- Function discovery is a linear sweep. It is fast and works well on compiler output, but data
  placed inside code sections can be misread as instructions.
- Mach-O (macOS) files are not supported.
- Bundled fonts (Barlow, IBM Plex Mono) are under the SIL Open Font License; see `binspect/web/fonts`.
