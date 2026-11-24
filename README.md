# vex

A reverse-engineering toolkit for **Linux (ELF)** and **Windows (PE: `.exe`, `.dll`)** programs
that runs on both systems. It takes a compiled program apart without ever running it, and it can
open game asset packs and save modified copies.

Developed by SS.

A step-by-step beginner's guide with screenshots is in
[`docs/vex-guide.pdf`](docs/vex-guide.pdf).

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
| Techniques | Flags protection and evasion techniques — packing/protectors, anti-debugging, VM/sandbox checks, process injection, API hooking, kernel drivers — with evidence and a plain explanation (useful for dissecting cheats and anti-cheat). Identifies only; never defeats them |
| Game engines | Recognises Unity, Unreal, Godot, GameMaker, Ren'Py, RPG Maker, Electron and others, and says where the assets are |
| Asset packs | Browse, extract, replace and repack ZIP-family packs, Quake PAK, Doom WAD, Godot PCK, Electron ASAR, Ren'Py RPA |
| Windows resources | List, extract and replace icons, version info, manifests and embedded data |
| Splitting | Save a program's parts (headers, code, data, appended data) as separate files in a folder, together with any complete files found inside it — pictures, sounds, ZIP archives, other programs — and an index of every piece |
| Patching | Overwrite bytes, blank out instructions, or replace text, always into a copy or with a backup |

## Install

Python 3.9 or newer, on Linux or Windows.

```
pip install .
```

This installs the `vex` command and its one dependency, the Capstone disassembler.
Without installing, `python -m vex ...` works from this folder once Capstone is present
(`pip install capstone`).

## The graphical interface

```
vex gui                # then choose a file in the browser
vex gui path/to/game   # or open something straight away
```

This starts a small server on your own computer and opens it in your browser. Nothing is sent
anywhere. Drop a file on the page or use **Open file or folder**.

- **Overview** — what the file is, how it is protected, what it needs.
- **Techniques** — protection and evasion techniques (anti-debug, VM checks, injection, hooking, packing, drivers) with their evidence; "Find uses" jumps to the code that uses each API.
- **Code** — functions on the left, instructions in the middle, "used by" on the right. Click a call to follow it.
- **Strings** — search the text in the file; **Find uses** jumps to the code that reads it.
- **Imports**, **Sections**, **Bytes** — the supporting tables and a hex view.
- **Assets** — the game engine, its asset packs, and resources inside Windows programs.
- **Split** — lists the parts of the program and the complete files found inside it, and saves them as separate files in a folder you choose.
- **Modify** — save a patched copy.

The strip across the top is the file drawn to scale: click any part to see its bytes.

## The command line

```
vex info FILE                     identity, hashes, protections
vex report FILE                   everything at a glance
vex sections FILE                 section table with entropy
vex imports FILE                  imported functions, grouped by library
vex exports FILE                  exported functions
vex symbols FILE [--grep REGEX]
vex strings FILE [-n MIN] [-e ascii|utf16] [--grep REGEX] [--tagged]
vex functions FILE [--grep REGEX]
vex disasm FILE [LOCATION] [-n COUNT]
vex xrefs FILE TARGET             who uses this function, import or address
vex xrefs FILE --string TEXT      who uses strings containing TEXT
vex hexdump FILE [LOCATION] [--offset N] [-n BYTES]
vex techniques FILE               protection and evasion techniques in a program
vex split FILE FOLDER             save the parts of a program as separate files
```

`LOCATION` and `TARGET` accept a function, symbol or import name (`main`, `puts`,
`kernel32.dll!WriteFile`), a `0x` address, or `entry`. Add `--json` before the command for
machine-readable output, for example `vex --json info FILE`.

A typical first look at an unknown program:

```
vex info suspicious.exe
vex strings suspicious.exe --tagged
vex xrefs suspicious.exe --string "http"
vex disasm suspicious.exe sub_401230
```

## Splitting a program into its parts

```
vex split FILE FOLDER
```

`split` saves the parts of a Linux or Windows program as separate files, so that each one can be
looked at on its own or opened with another tool. `FOLDER` is created if it does not exist. A
folder that already exists must be empty; otherwise vex stops with a message and writes nothing.

```
vex split game.exe game_parts
```

The command prints a table of the pieces and ends with `Saved N files to game_parts`. The folder
then looks like this (the names depend on the program):

```
game_parts/
  index.txt                      a list of every piece
  parts/
    00_headers.bin               the program cut into its parts, in file order
    01_.text.bin
    ...
  embedded/
    000_0x00000e00.png           complete files found inside the program
    ...
  resources/                     Windows resources (Windows programs only)
```

- **`parts/`** — the file cut along the same lines as the file map: headers, code, data, tables,
  and any data appended after the program. The number at the start of each name gives the order.
- **`embedded/`** — complete files that sit inside the program: PNG and GIF pictures, WAV, AVI and
  WebP files, ZIP archives, and other Windows or Linux programs. Each name carries the offset the
  file was found at. These are extra copies: the same bytes are also in the part that contains
  them.
- **`resources/`** — for Windows programs, every resource (icons, version info, manifests), named
  the same way as by `vex resources extract`.
- **`index.txt`** — the source file's name, size and SHA-256, then one line per piece: offset,
  size, kind, the file it was saved as, its name and a note.

What to expect:

- **The original is not changed, and nothing is run.** `split` only reads the file.
- **The parts add up to the original.** Joining the files in `parts/` in order gives back the
  original file exactly. Only padding that is all zero bytes is left out: `index.txt` lists each
  such stretch with its size and the note `zero padding, not saved`, so put that many zero bytes
  in its place when joining.
- **It copies, it does not convert.** Nothing is unpacked, decrypted or decompressed. Packed or
  encrypted content comes out exactly as it is stored, and a ZIP archive is saved as one `.zip`
  file.
- **It does not recover source code.** A program cannot be turned back into its source files; the
  code part holds the same machine instructions that `vex disasm` shows.

## Games and modding

```
vex engine GAME_FOLDER                         which engine, where the assets are
vex assets list data.pck
vex assets extract data.pck out_folder
vex assets replace data.pck sprites/hero.png my_hero.png -o data.modded.pck
vex assets add data.pck mods/extra.txt extra.txt -o data.modded.pck

vex resources list game.exe
vex resources extract game.exe out_folder
vex resources replace game.exe RCDATA 101 new.bin -o game.modded.exe

vex patch nop game.exe 0x401234 5 -o game.patched.exe
vex patch bytes game.exe 0x401234 "eb 05" -o game.patched.exe
vex patch string game.exe "Old text" "New" -o game.patched.exe
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
- **Pack format limits.** Godot packs from Godot 4.5 and later (pack format 3) can be read and
  extracted but not rebuilt. Godot pack support was written from the engine's source and has not
  been tried against a running game; ZIP, PAK, WAD, ASAR and RPA were checked against other tools.
  Engine detection has not been tried on commercial games.
- For formats vex does not rebuild (Unity bundles, Unreal `.pak`, .NET and IL2CPP code),
  `vex engine` names the community tool that does.

Only modify software you are allowed to modify, and keep to single-player or offline use where a
game's rules require it.

## Dissecting cheats and anti-cheat

```
vex techniques FILE
vex report FILE          # includes the techniques section
```

`techniques` statically flags the protection and evasion techniques a program uses, each with the
evidence it was found from and a plain explanation:

- **Packing / protectors** — compressed or protected code (UPX, VMProtect, Themida, …), spotted
  from packer section names or executable high-entropy code.
- **Anti-debugging** — checks for a debugger (`IsDebuggerPresent`, `NtQueryInformationProcess`,
  `ptrace`, …).
- **VM / sandbox checks** — looks for VirtualBox, VMware, QEMU, Sandboxie and similar artifacts.
- **Process injection** — writing into and running code in another process
  (`VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`, …).
- **API / input hooking** — `SetWindowsHookEx` and friends.
- **Kernel driver** — a native-subsystem driver, driver-only imports, or `DeviceIoControl`.

These techniques appear in anti-cheat, DRM, cheats and malware alike, so this is a research view
on both sides: what a cheat does to your machine, and what techniques an anti-cheat uses. It is
tuned to stay quiet on ordinary software. **vex only identifies these techniques — it never
disables, bypasses or defeats them, and there is nothing here for evading anti-cheat or building
cheats.**

## Safety

- Files are parsed, never executed, so it is safe to point vex at untrusted programs.
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
by vex.

```
vex/
  elf.py, pe.py        format parsers -> one Binary model (model.py)
  strings.py           string extraction and tagging
  disasm.py            Capstone wrapper with annotations
  analysis.py          functions, name resolution, cross-references
  archives/            asset pack formats (ZIP family, PAK, WAD, PCK, ASAR, RPA)
  engines.py           game engine detection
  resources.py         Windows resources
  split.py             saving a program's parts as separate files
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
- Bundled fonts (Barlow, IBM Plex Mono) are under the SIL Open Font License; see `vex/web/fonts`.
