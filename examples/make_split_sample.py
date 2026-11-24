"""Builds examples/split_sample: a practice file for the `vex split` command.

bundle_pe64.exe is the Windows practice program from the test fixtures with
three small, harmless files attached to its end, back to back: a picture
(PNG), a sound (WAV) and a ZIP archive holding a short text file. `vex split`
should find all three. Run from anywhere: python examples/make_split_sample.py

The output is the same on every run and on every machine: nothing here depends
on the clock, on the platform or on which zlib build Python was linked against.
"""
import io
import struct
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "split_sample"
PRACTICE_EXE = ROOT.parent / "tests" / "fixtures" / "bin" / "hello_pe64.exe"

BUNDLE_NAME = "bundle_pe64.exe"
README_NAME = "README.txt"

README = (
    b"bundle_pe64.exe is a harmless hello-world program for Windows with three\n"
    b"small files attached to its end: a picture (PNG), a short sound (WAV) and\n"
    b"a ZIP archive that holds one text file. It is here so you can try the\n"
    b"split command: `vex split bundle_pe64.exe out` saves the parts of the\n"
    b"program and the three attached files into the folder `out`.\n"
)

ZIP_README = (
    b"This text file sits inside a ZIP archive that is attached to the end of\n"
    b"bundle_pe64.exe. If you are reading it, vex split found the archive.\n"
)


def stored_zlib(data):
    """A zlib stream holding data uncompressed (one stored block, max 65535 bytes).

    Written out by hand so the bytes do not depend on the zlib version.
    """
    assert len(data) <= 0xFFFF
    return (b"\x78\x01"                                    # zlib header, no preset dictionary
            + b"\x01"                                      # final block, type 0 = stored
            + struct.pack("<HH", len(data), len(data) ^ 0xFFFF)
            + data
            + struct.pack(">I", zlib.adler32(data)))


def png(width, height, pixel):
    """A minimal 8-bit RGB PNG; pixel(x, y) returns an (r, g, b) tuple."""
    rows = b"".join(
        b"\x00" + b"".join(bytes(pixel(x, y)) for x in range(width)) for y in range(height))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + \
            struct.pack(">I", zlib.crc32(kind + data))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", stored_zlib(rows)) + chunk(b"IEND", b""))


def wav(samples, rate):
    """An 8-bit mono PCM WAV; samples is a bytes object of unsigned values."""
    assert len(samples) % 2 == 0                           # odd data would need a pad byte
    fmt = struct.pack("<HHIIHH", 1, 1, rate, rate, 1, 8)   # PCM, mono, 1 byte per frame
    body = (b"WAVE"
            + b"fmt " + struct.pack("<I", len(fmt)) + fmt
            + b"data" + struct.pack("<I", len(samples)) + samples)
    return b"RIFF" + struct.pack("<I", len(body)) + body


def tone(rate=8000, period=20, count=2000):
    """A quarter of a second of a 400 Hz triangle wave, whole numbers only."""
    half = period // 2
    return bytes(68 + 12 * (half - abs(i % period - half)) for i in range(count))


def readme_zip():
    """A ZIP archive with one stored text file and a fixed timestamp."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as pack:
        info = zipfile.ZipInfo("readme.txt", (2024, 1, 1, 0, 0, 0))
        # zipfile fills these in from the platform; pin them so every machine agrees
        info.create_system = 3
        info.external_attr = 0o644 << 16
        pack.writestr(info, ZIP_README, zipfile.ZIP_STORED)
    return buffer.getvalue()


def attachments():
    """The three attached files in the order they are appended: (ext, bytes)."""
    picture = png(32, 32, lambda x, y: (15, 86, 217) if (x // 8 + y // 8) % 2 == 0
                  else (233, 238, 243))
    return [("png", picture), ("wav", wav(tone(), 8000)), ("zip", readme_zip())]


def build(dest=SAMPLE):
    """Write bundle_pe64.exe and README.txt into dest; returns the bundle's path."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    bundle = dest / BUNDLE_NAME
    bundle.write_bytes(PRACTICE_EXE.read_bytes() + b"".join(data for _, data in attachments()))
    (dest / README_NAME).write_bytes(README)
    return bundle


def main():
    build()
    print(f"wrote {SAMPLE}")


if __name__ == "__main__":
    main()
