#!/bin/sh
# Fetch the source of the Capstone disassembly engine into third_party/.
#
# vex's disasm/functions/xrefs commands are built on Capstone
# (https://www.capstone-engine.org, BSD 3-clause licence). The version is
# pinned to the one the Python reference implementation was tested with, so
# both print identical instruction text. The source comes from the PyPI
# source distribution of the `capstone` package, which bundles the C code
# under src/; its checksum is verified before unpacking.
#
#   ./fetch_capstone.sh && make
set -eu

VERSION=5.0.9
SHA256=0429af292ddc604d3c9344696807e281d5e728db029f00e6a4ea9e3bff1aac9e
ARCHIVE=capstone-$VERSION.tar.gz
URL=https://files.pythonhosted.org/packages/source/c/capstone/$ARCHIVE

cd "$(dirname "$0")"
mkdir -p third_party
cd third_party

if [ ! -f "$ARCHIVE" ]; then
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$ARCHIVE.part" "$URL"
        mv "$ARCHIVE.part" "$ARCHIVE"
    else
        python3 -m pip download "capstone==$VERSION" --no-binary :all: --no-deps -d .
    fi
fi

if command -v sha256sum >/dev/null 2>&1; then
    echo "$SHA256  $ARCHIVE" | sha256sum -c -
else
    echo "$SHA256  $ARCHIVE" | shasum -a 256 -c -
fi

rm -rf "capstone-$VERSION"
tar xzf "$ARCHIVE"
test -f "capstone-$VERSION/src/cs.c" && test -d "capstone-$VERSION/src/arch/X86"
echo "Capstone $VERSION is in third_party/capstone-$VERSION (licence: src/LICENSE.TXT)"
