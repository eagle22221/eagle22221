#!/usr/bin/env python3
"""Writes resdemo.ico: a two-image icon (16x16 with 16 colours, 32x32 in
black and white) small enough to commit. Run by build_resources.sh; the
output is deterministic.

    python3 make_resdemo_icon.py OUTPUT.ico
"""
import struct
import sys


def dib(width, height, bits, palette, pixel):
    """One icon image in the classic (non-PNG) form: BITMAPINFOHEADER with
    doubled height, palette, colour bitmap, then the 1-bit transparency mask.
    Rows are stored bottom-up and padded to 32 bits."""
    def rows(bits_per_pixel, value):
        out = b""
        for y in reversed(range(height)):
            acc = nbits = 0
            row = bytearray()
            for x in range(width):
                acc = (acc << bits_per_pixel) | value(x, y)
                nbits += bits_per_pixel
                while nbits >= 8:
                    nbits -= 8
                    row.append((acc >> nbits) & 0xFF)
            if nbits:
                row.append((acc << (8 - nbits)) & 0xFF)
            row += bytes(-len(row) % 4)
            out += bytes(row)
        return out

    header = struct.pack("<IiiHHIIiiII", 40, width, height * 2, 1, bits, 0, 0, 0, 0, 0, 0)
    colours = b"".join(struct.pack("<BBBB", b, g, r, 0) for r, g, b in palette)
    return header + colours + rows(bits, pixel) + rows(1, lambda x, y: 0)


def main(path):
    vga = [(0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0), (0, 0, 128),
           (128, 0, 128), (0, 128, 128), (192, 192, 192), (128, 128, 128),
           (255, 0, 0), (0, 255, 0), (255, 255, 0), (0, 0, 255), (255, 0, 255),
           (0, 255, 255), (255, 255, 255)]
    images = [
        # (width, height, colour count, bits per pixel, image bytes)
        (16, 16, 16, 4, dib(16, 16, 4, vga, lambda x, y: (x + y) % 16)),
        (32, 32, 2, 1, dib(32, 32, 1, [(0, 0, 0), (255, 255, 255)],
                           lambda x, y: (x // 4 + y // 4) % 2)),
    ]
    out = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    for width, height, colours, bits, data in images:
        out += struct.pack("<BBBBHHII", width, height, colours, 0, 1, bits,
                           len(data), offset)
        offset += len(data)
    out += b"".join(image[4] for image in images)
    with open(path, "wb") as f:
        f.write(out)


if __name__ == "__main__":
    main(sys.argv[1])
