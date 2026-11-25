#!/bin/sh
# Fetch the Microsoft Edge WebView2 SDK into third_party/webview2/.
#
# The windowed Windows build (vex-app.exe) shows the interface in a window of
# its own through WebView2, the web engine that ships with Windows. Building
# it needs two files from Microsoft's SDK (BSD-style licence, see LICENSE.txt
# in the package):
#
#   WebView2.h          the interface definitions, used at compile time
#   WebView2Loader.dll  the small loader that goes next to vex-app.exe
#
# They come from the official NuGet package, whose checksum is verified before
# anything is unpacked. Without them `make windows` still builds vex.exe, and
# vex-app.exe falls back to an app-mode browser window.
#
#   ./fetch_webview2.sh && make windows
set -eu

VERSION=1.0.4370.26
SHA256=1c0dacac84b70109b3fd42f90c53a0ba942abc3a87590d7a4e0ccd86e4a06cf4
ARCHIVE=microsoft.web.webview2.$VERSION.nupkg
URL=https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$VERSION/$ARCHIVE

cd "$(dirname "$0")"
mkdir -p third_party
cd third_party

if [ ! -f "$ARCHIVE" ]; then
    curl -fsSL -o "$ARCHIVE.part" "$URL"
    mv "$ARCHIVE.part" "$ARCHIVE"
fi

if command -v sha256sum >/dev/null 2>&1; then
    echo "$SHA256  $ARCHIVE" | sha256sum -c -
else
    echo "$SHA256  $ARCHIVE" | shasum -a 256 -c -
fi

rm -rf webview2
mkdir webview2
# A .nupkg is a zip file. Only the three files needed are taken out of it.
python3 -I - "$ARCHIVE" webview2 <<'PY'
import os, sys, zipfile
archive, dest = sys.argv[1], sys.argv[2]
wanted = {"build/native/include/WebView2.h": "WebView2.h",
          "build/native/x64/WebView2Loader.dll": "WebView2Loader.dll",
          "LICENSE.txt": "LICENSE.txt"}
with zipfile.ZipFile(archive) as z:
    for member, name in wanted.items():
        with open(os.path.join(dest, name), "wb") as out:
            out.write(z.read(member))
PY
# The header asks for "EventToken.h"; MinGW names it in lower case.
printf '#include <eventtoken.h>\n' > webview2/EventToken.h
test -s webview2/WebView2.h && test -s webview2/WebView2Loader.dll
echo "WebView2 SDK $VERSION is ready in c/third_party/webview2"
