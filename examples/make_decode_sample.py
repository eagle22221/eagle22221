"""Builds examples/decode_sample: practice puzzles for the `vex decode` command.

secrets.txt holds five short, friendly, made-up messages, each encoded or
enciphered a different way, with a one-line hint naming the recipe that undoes
it. Between them they exercise an encoding, a two-step encoding, a classic
cipher, a repeating-key XOR and a supplied-key stream cipher, so a learner can
reproduce every one in the Decode view or with `vex decode`.

Run from anywhere: python examples/make_decode_sample.py

The output is the same on every run and on every machine: the gzip stream is
built by hand with mtime pinned to 0 and one uncompressed block, so it does not
depend on the clock, the platform or which zlib build Python was linked
against, and every cipher key and nonce is a fixed literal.

Nothing here is a real secret. The keys and nonce are throwaway demo values
for the puzzles, not credentials or keys to any system.
"""
import base64
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLE = ROOT / "decode_sample"

SECRETS_NAME = "secrets.txt"
README_NAME = "README.txt"

# --- the five plaintexts the puzzles reveal (all wholesome, all pinned) -------

GREETING = b"Hello from the vex decode workbench -- happy decoding!"
CHANGELOG = b"vex changelog: the decode workbench now chains operations into recipes."
WELL_DONE = b"Well done -- you turned every letter back the right way round."
XOR_TIP = b"Tip: chain small steps and a repeating-key XOR comes right undone."
CHEER = b"Congratulations -- you solved the last puzzle with the key and the nonce!"

# --- fixed cipher parameters (demo data, printed in the hints) ----------------

XOR_KEY = b"puzzle"                                 # repeating-key XOR key, as text
CHACHA_KEY = bytes(range(32))                        # 00 01 02 ... 1f
CHACHA_NONCE = bytes.fromhex("000000000000004a00000000")
CHACHA_COUNTER = 1                                   # the operation's default


# --- encoders, each the inverse of the recipe named in the hint ---------------

def gzip_stored(data):
    """A gzip stream (RFC 1952) wrapping one uncompressed DEFLATE block.

    Written out by hand so the bytes never depend on the zlib version or the
    platform: the modification time is pinned to 0 and the OS byte to 255
    (unknown). `gunzip` reads it back the same everywhere.
    """
    assert len(data) <= 0xFFFF                       # one stored block holds up to 65535 bytes
    header = b"\x1f\x8b\x08\x00" + b"\x00\x00\x00\x00" + b"\x00\xff"  # magic, deflate, flags, mtime=0, xfl=0, os=unknown
    block = b"\x01" + struct.pack("<HH", len(data), len(data) ^ 0xFFFF) + data  # final stored block
    trailer = struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return header + block + trailer


def rot13(data):
    """ROT13 on ASCII letters; every other byte is left alone (self-inverse)."""
    out = bytearray(data)
    for i, b in enumerate(out):
        if 65 <= b <= 90:
            out[i] = (b - 65 + 13) % 26 + 65
        elif 97 <= b <= 122:
            out[i] = (b - 97 + 13) % 26 + 97
    return bytes(out)


def xor_repeat(data, key):
    """Repeating-key XOR (self-inverse)."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _chacha_quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha_block(key, counter, nonce):
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state += list(struct.unpack("<8I", key))
    state.append(counter & 0xFFFFFFFF)
    state += list(struct.unpack("<3I", nonce))
    work = state[:]
    for _ in range(10):                              # 20 rounds = 10 column/diagonal double rounds
        _chacha_quarter(work, 0, 4, 8, 12)
        _chacha_quarter(work, 1, 5, 9, 13)
        _chacha_quarter(work, 2, 6, 10, 14)
        _chacha_quarter(work, 3, 7, 11, 15)
        _chacha_quarter(work, 0, 5, 10, 15)
        _chacha_quarter(work, 1, 6, 11, 12)
        _chacha_quarter(work, 2, 7, 8, 13)
        _chacha_quarter(work, 3, 4, 9, 14)
    return struct.pack("<16I", *[(work[i] + state[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20(data, key, nonce, counter=1):
    """RFC 8439 ChaCha20 (self-inverse): encrypt == decrypt."""
    assert len(key) == 32 and len(nonce) == 12
    out = bytearray()
    for i in range(0, len(data), 64):
        keystream = _chacha_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], keystream))
    return bytes(out)


# --- the document -------------------------------------------------------------

def puzzles():
    """The five puzzles as (title, encoded_line, hint_lines)."""
    return [
        ("A hidden greeting -- Base64",
         base64.b64encode(GREETING).decode("ascii"),
         ["plain Base64, nothing more.",
          'recipe:  from-base64']),
        ("A changelog note, packed twice -- Base64 then gzip",
         base64.b64encode(gzip_stored(CHANGELOG)).decode("ascii"),
         ["Base64 on the outside, a gzip stream on the inside, so it takes two",
          "steps to unwrap.",
          'recipe:  from-base64 | gunzip']),
        ("A pat on the back -- ROT13",
         rot13(WELL_DONE).decode("ascii"),
         ["every letter is rotated by 13 places; ROT13 is its own undo.",
          'recipe:  rot13']),
        ("A tip, hidden with a repeating-key XOR -- hex",
         xor_repeat(XOR_TIP, XOR_KEY).hex(),
         ["hex bytes XORed with a short key that repeats.",
          'key as text:  "%s"' % XOR_KEY.decode("ascii"),
          "key as hex:   %s" % XOR_KEY.hex(),
          'recipe:  from-hex | xor:key_text=%s' % XOR_KEY.decode("ascii"),
          "(or xor:key=%s -- same key, written in hex)" % XOR_KEY.hex()]),
        ("A final cheer -- ChaCha20 (RFC 8439)",
         chacha20(CHEER, CHACHA_KEY, CHACHA_NONCE, CHACHA_COUNTER).hex(),
         ["a ChaCha20 stream cipher. The key and nonce below are throwaway",
          "demo values for this puzzle, not a secret. Block counter is 1 (the",
          "operation's default), so you need only the key and the nonce.",
          "key   (hex): %s" % CHACHA_KEY.hex(),
          "nonce (hex): %s" % CHACHA_NONCE.hex(),
          'recipe:  from-hex | chacha20:key=%s,nonce=%s'
          % (CHACHA_KEY.hex(), CHACHA_NONCE.hex())]),
    ]


def secrets_text():
    lines = [
        "vex decode -- practice puzzles",
        "==============================",
        "",
        "Five short, made-up messages for the `vex decode` workbench. Each one has",
        "been encoded or enciphered a different way; the hint under it names the",
        "recipe that puts it back. Try one in the Decode view, or on the command",
        "line, for example:",
        "",
        '    vex decode --text "<the encoded line>" --recipe "from-base64"',
        "",
        "Everything here is friendly practice data -- there are no real secrets,",
        "passwords or keys to anything.",
        "",
    ]
    for number, (title, encoded, hint_lines) in enumerate(puzzles(), start=1):
        lines.append("")
        lines.append("%d. %s" % (number, title))
        lines.append("   encoded: %s" % encoded)
        lines.append("   hint:    %s" % hint_lines[0])
        for extra in hint_lines[1:]:
            lines.append("            %s" % extra)
    lines.append("")
    return ("\n".join(lines) + "\n").encode("ascii")


README = (
    b"This folder is practice material for the `vex decode` command.\n"
    b"\n"
    b"secrets.txt holds five short, made-up messages that have each been encoded\n"
    b"or enciphered a different way, with a hint naming the recipe that undoes it.\n"
    b"Work through them in the Decode view or with `vex decode` to get a feel for\n"
    b"encodings, classic ciphers and supplied-key decryption. Nothing here is a\n"
    b"real secret.\n"
)


def build(dest=SAMPLE):
    """Write secrets.txt and README.txt into dest; returns the secrets path."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    secrets = dest / SECRETS_NAME
    secrets.write_bytes(secrets_text())
    (dest / README_NAME).write_bytes(README)
    return secrets


def main():
    build()
    print(f"wrote {SAMPLE}")


if __name__ == "__main__":
    main()
