#!/bin/sh
# Packs the native Windows build into dist/vex-windows.rar.
# Needs: c/build/vex.exe (make -C c windows) and the `rar` archiver.
set -eu
cd "$(dirname "$0")/.."
EXE=c/build/vex.exe
[ -f "$EXE" ] || { echo "missing $EXE: run 'make -C c windows' first" >&2; exit 1; }
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/vex"
mkdir -p "$ROOT/practice" "$ROOT/licences" dist
cp "$EXE" "$ROOT/vex.exe"
# Windows Notepad wants CRLF line endings
sed 's/$/\r/' "packaging/START HERE.txt" > "$ROOT/START HERE.txt"
cp tests/fixtures/bin/hello_pe64.exe tests/fixtures/bin/sample.dll \
   tests/fixtures/bin/libsample.so tests/fixtures/bin/evasion_pe64.exe "$ROOT/practice/"
# a pretend game so the Assets view and the engine/assets commands have something to open
python3 examples/make_demo_game.py >/dev/null 2>&1 || true
mkdir -p "$ROOT/practice/demo_game"
cp examples/demo_game/game.exe examples/demo_game/assets.pk3 "$ROOT/practice/demo_game/"
for f in c/third_party/capstone*/LICENSE.TXT c/third_party/*/LICENSE.TXT; do
    [ -f "$f" ] && cp "$f" "$ROOT/licences/capstone-LICENSE.TXT" && break
done
rm -f dist/vex-windows.rar
(cd "$STAGE" && rar a -r -m5 -idq "$OLDPWD/dist/vex-windows.rar" vex)
rar l dist/vex-windows.rar
