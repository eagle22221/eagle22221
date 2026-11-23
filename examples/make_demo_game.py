"""Builds examples/demo_game: a tiny pretend game used by lesson 6 of the guide.

It contains game.exe (the Windows practice program from the test fixtures)
and assets.pk3, a ZIP-based asset pack with two pictures, a settings file
and a text file. Run from anywhere: python examples/make_demo_game.py
"""
import json
import shutil
import struct
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GAME = ROOT / "demo_game"
PRACTICE_EXE = ROOT.parent / "tests" / "fixtures" / "bin" / "hello_pe64.exe"


def png(width, height, pixel):
    """A minimal 8-bit RGB PNG; pixel(x, y) returns an (r, g, b) tuple."""
    rows = b"".join(
        b"\x00" + b"".join(bytes(pixel(x, y)) for x in range(width)) for y in range(height))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + \
            struct.pack(">I", zlib.crc32(kind + data))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


def main():
    GAME.mkdir(exist_ok=True)
    shutil.copyfile(PRACTICE_EXE, GAME / "game.exe")
    logo = png(96, 96, lambda x, y: (15, 86, 217) if (x // 12 + y // 12) % 2 == 0
               else (233, 238, 243))
    hero = png(64, 64, lambda x, y: (212, 72, 11) if abs(x - 32) + abs(y - 32) < 26
               else (19, 34, 56))
    files = [
        ("textures/logo.png", logo),
        ("textures/hero.png", hero),
        ("scripts/config.json", json.dumps(
            {"title": "Demo Game", "difficulty": "normal", "lives": 3}, indent=2).encode()),
        ("readme.txt", b"Demo asset pack for the binspect guide.\n"),
    ]
    with zipfile.ZipFile(GAME / "assets.pk3", "w", zipfile.ZIP_DEFLATED) as pack:
        for name, data in files:
            # fixed timestamp so rebuilding gives the same file
            pack.writestr(zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0)), data,
                          zipfile.ZIP_DEFLATED)
    print(f"wrote {GAME}")


if __name__ == "__main__":
    main()
