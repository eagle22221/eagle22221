#!/bin/sh
# Packs the native Windows build into dist/vex-windows.rar.
# Needs: c/build/vex.exe (make -C c windows) and the `rar` archiver.
#
#   make_windows_rar.sh                 build dist/vex-windows.rar
#   make_windows_rar.sh --stage DIR     only lay the folder out in DIR (no archive)
set -eu
cd "$(dirname "$0")/.."
EXE=c/build/vex.exe
[ -f "$EXE" ] || { echo "missing $EXE: run 'make -C c windows' first" >&2; exit 1; }

STAGE_ONLY=
if [ "${1:-}" = "--stage" ]; then
    STAGE_ONLY=1
    ROOT=${2:?--stage needs a folder}
    rm -rf "$ROOT"
else
    STAGE=$(mktemp -d)
    trap 'rm -rf "$STAGE"' EXIT
    ROOT="$STAGE/vex"
fi

mkdir -p "$ROOT/practice" "$ROOT/licences"
cp "$EXE" "$ROOT/vex.exe"
# The windowed program, and the loader it needs for a window of its own.
if [ -f c/build/vex-app.exe ]; then
    cp c/build/vex-app.exe "$ROOT/vex-app.exe"
fi
if [ -f c/build/WebView2Loader.dll ]; then
    cp c/build/WebView2Loader.dll "$ROOT/WebView2Loader.dll"
    cp c/third_party/webview2/LICENSE.txt "$ROOT/licences/webview2-LICENSE.txt"
fi
# Windows Notepad wants CRLF line endings
sed 's/$/\r/' "packaging/START HERE.txt" > "$ROOT/START HERE.txt"
cp tests/fixtures/bin/hello_pe64.exe tests/fixtures/bin/sample.dll \
   tests/fixtures/bin/libsample.so tests/fixtures/bin/evasion_pe64.exe "$ROOT/practice/"
# a pretend game so the Assets view and the engine/assets commands have something to open
python3 examples/make_demo_game.py >/dev/null 2>&1 || true
mkdir -p "$ROOT/practice/demo_game"
cp examples/demo_game/game.exe examples/demo_game/assets.pk3 "$ROOT/practice/demo_game/"
# a program with a picture, a sound and a zip attached, for trying the split command
python3 examples/make_split_sample.py >/dev/null 2>&1 || true
cp examples/split_sample/bundle_pe64.exe "$ROOT/practice/"
# a handful of encode/cipher puzzles for trying the decode command
python3 examples/make_decode_sample.py >/dev/null 2>&1 || true
cp examples/decode_sample/secrets.txt "$ROOT/practice/"
for f in c/third_party/capstone*/LICENSE.TXT c/third_party/*/LICENSE.TXT; do
    [ -f "$f" ] && cp "$f" "$ROOT/licences/capstone-LICENSE.TXT" && break
done

[ -n "$STAGE_ONLY" ] && { echo "staged in $ROOT"; exit 0; }

mkdir -p dist
rm -f dist/vex-windows.rar
(cd "$STAGE" && rar a -r -m5 -idq "$OLDPWD/dist/vex-windows.rar" vex)
rar l dist/vex-windows.rar
