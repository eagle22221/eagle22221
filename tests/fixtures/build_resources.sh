#!/bin/sh
# Rebuilds tests/fixtures/bin/resdemo.exe, the PE fixture that carries Windows
# resources (icon group, version info, string tables, manifest, raw data).
# Kept apart from build.sh so rebuilding it never touches the other fixtures.
# Needs python3, clang, lld-link, llvm-rc and llvm-dlltool; no Windows SDK.
# The built binary is committed; the literal values in tests/test_resources.py
# were read from it with `llvm-readobj --coff-resources` and pefile.
set -eu
cd "$(dirname "$0")"
SRC=src
OUT=bin
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"

# The icon is generated, then committed so the tests can compare against it.
python3 "$SRC/make_resdemo_icon.py" "$SRC/resdemo.ico"

llvm-rc /no-preprocess /FO "$TMP/resdemo.res" "$SRC/resdemo.rc"
llvm-dlltool -m i386:x86-64 -d "$SRC/kernel32_x64.def" -l "$TMP/kernel32_x64.lib"
clang --target=x86_64-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector \
    -funwind-tables -c "$SRC/resdemo.c" -o "$TMP/resdemo.obj"
lld-link /nologo /entry:entry /subsystem:windows /nodefaultlib \
    /dynamicbase /nxcompat /highentropyva /timestamp:1700000000 \
    /debug:symtab /out:"$OUT/resdemo.exe" \
    "$TMP/resdemo.obj" "$TMP/resdemo.res" "$TMP/kernel32_x64.lib"

ls -l "$OUT/resdemo.exe"
