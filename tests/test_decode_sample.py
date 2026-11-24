"""The practice puzzles for `vex decode`: examples/decode_sample/secrets.txt.

secrets.txt carries five short messages, each encoded or enciphered a different
way, with a hint naming the recipe that undoes it. These tests check that the
committed file is reproduced byte for byte by its generator, and that every
puzzle really is solvable: each plaintext is recovered here by an independent
implementation (stdlib base64 and gzip for those two; ROT13, repeating-XOR and
ChaCha20 spelled out inline from their definitions) that never touches vex, and
the recovered text is pinned to the friendly message it is meant to reveal.
"""
import base64
import gzip
import re
import runpy
import struct
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SCRIPT = EXAMPLES / "make_decode_sample.py"
SAMPLE = EXAMPLES / "decode_sample"
SECRETS = SAMPLE / "secrets.txt"
README = SAMPLE / "README.txt"

# The plaintext each puzzle reveals, pinned so the content cannot drift.
PLAINTEXTS = [
    b"Hello from the vex decode workbench -- happy decoding!",
    b"vex changelog: the decode workbench now chains operations into recipes.",
    b"Well done -- you turned every letter back the right way round.",
    b"Tip: chain small steps and a repeating-key XOR comes right undone.",
    b"Congratulations -- you solved the last puzzle with the key and the nonce!",
]

XOR_KEY = b"puzzle"
CHACHA_KEY = bytes(range(32))
CHACHA_NONCE = bytes.fromhex("000000000000004a00000000")


def encoded_lines():
    """The five `encoded:` lines from the committed secrets.txt, in order."""
    text = SECRETS.read_text("ascii")
    found = re.findall(r"^   encoded: (.+)$", text, re.MULTILINE)
    assert len(found) == 5, "expected five puzzles, found %d" % len(found)
    return found


# --- independent recovery implementations (no vex) ----------------------------

def rot13(data: bytes) -> bytes:
    out = bytearray(data)
    for i, b in enumerate(out):
        if 65 <= b <= 90:
            out[i] = (b - 65 + 13) % 26 + 65
        elif 97 <= b <= 122:
            out[i] = (b - 97 + 13) % 26 + 97
    return bytes(out)


def xor_repeat(data: bytes, key: bytes) -> bytes:
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
    for _ in range(10):
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
    assert len(key) == 32 and len(nonce) == 12
    out = bytearray()
    for i in range(0, len(data), 64):
        keystream = _chacha_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], keystream))
    return bytes(out)


# --- the committed files ------------------------------------------------------

def test_regenerating_reproduces_the_committed_files(tmp_path):
    build = runpy.run_path(str(SCRIPT))["build"]
    build(tmp_path / "first")
    build(tmp_path / "second")
    for name in ("secrets.txt", "README.txt"):
        first = (tmp_path / "first" / name).read_bytes()
        assert first == (tmp_path / "second" / name).read_bytes()     # same on every run
        assert first == (SAMPLE / name).read_bytes()                  # and matches the commit
    assert sorted(p.name for p in (tmp_path / "first").iterdir()) == [
        "README.txt", "secrets.txt"]


def test_files_are_plain_ascii_text():
    for path in (SECRETS, README):
        data = path.read_bytes()
        assert all(byte == 0x0A or 0x20 <= byte < 0x7F for byte in data)   # no \r, no tabs
        assert data.endswith(b"\n")
    assert b"vex decode" in README.read_bytes()
    assert b"no real secrets" in SECRETS.read_bytes()


# --- every puzzle solved by an independent implementation ---------------------

def test_puzzle_1_base64():
    assert base64.b64decode(encoded_lines()[0]) == PLAINTEXTS[0]


def test_puzzle_2_base64_then_gzip():
    # two steps: undo base64, then gunzip
    assert gzip.decompress(base64.b64decode(encoded_lines()[1])) == PLAINTEXTS[1]


def test_puzzle_3_rot13():
    assert rot13(encoded_lines()[2].encode("ascii")) == PLAINTEXTS[2]


def test_puzzle_4_repeating_key_xor():
    cipher = bytes.fromhex(encoded_lines()[3])
    assert xor_repeat(cipher, XOR_KEY) == PLAINTEXTS[3]
    # the hint also prints the key in hex; it must be the same key
    assert bytes.fromhex("70757a7a6c65") == XOR_KEY


def test_puzzle_5_chacha20():
    cipher = bytes.fromhex(encoded_lines()[4])
    assert chacha20(cipher, CHACHA_KEY, CHACHA_NONCE, counter=1) == PLAINTEXTS[4]


def test_every_puzzle_is_listed_with_its_recipe():
    text = SECRETS.read_text("ascii")
    for recipe in ("from-base64", "from-base64 | gunzip", "rot13",
                   "from-hex | xor:key_text=puzzle",
                   "from-hex | chacha20:key="):
        assert recipe in text
