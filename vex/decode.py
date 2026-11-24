"""decode & cipher workbench: reversible transforms and supplied-key
decryptions chained into a recipe, like a local CyberChef.

An **operation** maps ``bytes -> bytes`` (``fn(data, **params)``) and raises
:class:`DecodeError` on bad input or params. A **recipe** is an ordered list
``[(op_name, params), ...]`` applied left to right from the source bytes. A
**source** (text / hex / base64 / a byte range of a file) produces the start.

Everything operates on data the user supplies or selects. Strong crypto is
decrypted only with a key the user gives; nothing here recovers an unknown key
or defeats protection, and no analysed file is ever executed. Every operation
and the whole pipeline cap output at 64 MiB; decompression is incremental so a
bomb is refused rather than expanded.

Standard library only. The symmetric operations call :mod:`vex.crypto`.
"""
from __future__ import annotations

import base64
import binascii
import bz2
import hashlib
import lzma
import quopri
import re
import urllib.parse
import zlib
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from .errors import DecodeError, VexError

try:                                    # crypto.py is written concurrently
    from . import crypto                # and may not have landed yet
except ImportError:                     # pragma: no cover - depends on build
    crypto = None                       # type: ignore


class RecipeError(DecodeError):
    """The recipe string names an unknown operation or parameter, or is
    malformed. The command line reports this as a usage error (exit 2)."""


# 64 MiB cap on every operation's output and on the whole pipeline.
CAP = 64 << 20
# Decompressors emit at most this many bytes per step, so the cap is hit long
# before a bomb is expanded.
_CHUNK = 1 << 20
# Solvers analyse (and return) at most this much of the input, so searching a
# large blob stays fast and bounded.
_SOLVE_CAP = 1 << 16


# --- helpers ---------------------------------------------------------------

def _as_int(value, name: str) -> int:
    if isinstance(value, bool):         # bool is an int subclass; reject it
        raise DecodeError(f"{name} must be a number")
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except (ValueError, TypeError):
        raise DecodeError(f"{name} must be a number, not {value!r}") from None


def _as_bytes(value) -> bytes:
    """A parameter value as raw bytes (str is UTF-8 encoded)."""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def _parse_hex(value) -> bytes:
    """Lenient hex: spaces, newlines, ``0x``, ``,`` and ``:`` are ignored."""
    text = value.decode("latin-1") if isinstance(value, (bytes, bytearray)) else str(value)
    text = re.sub(r"0x", "", text, flags=re.IGNORECASE)
    text = re.sub(r"[\s,:]", "", text)
    if len(text) % 2:
        raise DecodeError("hex needs an even number of digits")
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise DecodeError("not valid hex") from None


def _key_bytes(params: dict, op_name: str) -> bytes:
    """A ``key`` (hex) or ``key_text`` parameter, as raw bytes."""
    if params.get("key") not in (None, ""):
        return _parse_hex(params["key"])
    if params.get("key_text") not in (None, ""):
        return _as_bytes(params["key_text"])
    raise DecodeError(f"{op_name} needs a key (key=HEX or key_text=TEXT)")


def _b64_prep(value) -> bytes:
    data = value if isinstance(value, (bytes, bytearray)) else str(value).encode("latin-1")
    data = bytes(c for c in data if c not in b" \t\r\n\f\v")
    return data + b"=" * ((-len(data)) % 4)


# --- encodings -------------------------------------------------------------

def _from_base64(data: bytes, alphabet: str = "std") -> bytes:
    if alphabet not in ("std", "url"):
        raise DecodeError("alphabet must be std or url")
    alt = b"-_" if alphabet == "url" else None
    try:
        return base64.b64decode(_b64_prep(data), altchars=alt, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"invalid base64: {exc}") from None


def _to_base64(data: bytes, alphabet: str = "std") -> bytes:
    if alphabet not in ("std", "url"):
        raise DecodeError("alphabet must be std or url")
    return base64.urlsafe_b64encode(data) if alphabet == "url" else base64.b64encode(data)


def _from_base32(data: bytes) -> bytes:
    try:
        return base64.b32decode(_b64_prep_b32(data), casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise DecodeError(f"invalid base32: {exc}") from None


def _b64_prep_b32(value) -> bytes:
    data = value if isinstance(value, (bytes, bytearray)) else str(value).encode("latin-1")
    data = bytes(c for c in data if c not in b" \t\r\n\f\v")
    return data + b"=" * ((-len(data)) % 8)


def _to_base32(data: bytes) -> bytes:
    return base64.b32encode(data)


def _from_base85(data: bytes, variant: str = "ascii85") -> bytes:
    try:
        if variant == "ascii85":
            return base64.a85decode(data)
        if variant == "z85":
            raw = data if isinstance(data, (bytes, bytearray)) else str(data).encode("latin-1")
            return base64.z85decode(bytes(c for c in raw if c not in b" \t\r\n\f\v"))
    except (ValueError, binascii.Error) as exc:
        raise DecodeError(f"invalid base85: {exc}") from None
    raise DecodeError("variant must be ascii85 or z85")


def _to_base85(data: bytes, variant: str = "ascii85") -> bytes:
    if variant == "ascii85":
        return base64.a85encode(data)
    if variant == "z85":
        if len(data) % 4:
            raise DecodeError("z85 needs a length that is a multiple of 4 bytes")
        return base64.z85encode(data)
    raise DecodeError("variant must be ascii85 or z85")


def _from_hex(data: bytes) -> bytes:
    return _parse_hex(data)


def _to_hex(data: bytes) -> bytes:
    return binascii.hexlify(data)


def _url_decode(data: bytes) -> bytes:
    return urllib.parse.unquote_to_bytes(bytes(data))


def _url_encode(data: bytes) -> bytes:
    return urllib.parse.quote_from_bytes(bytes(data), safe=b"").encode("ascii")


def _qp_decode(data: bytes) -> bytes:
    return quopri.decodestring(bytes(data))


def _rot13(data: bytes) -> bytes:
    out = bytearray(data)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = (c - 65 + 13) % 26 + 65
        elif 97 <= c <= 122:
            out[i] = (c - 97 + 13) % 26 + 97
    return bytes(out)


def _reverse(data: bytes) -> bytes:
    return data[::-1]


_CHARSETS = {"utf-8": "utf-8", "utf-16le": "utf-16-le", "utf-16be": "utf-16-be",
             "latin-1": "latin-1"}


def _charset_decode(data: bytes, **params) -> bytes:
    name = params.get("from", "utf-8")
    codec = _CHARSETS.get(name)
    if codec is None:
        raise DecodeError("from must be utf-8, utf-16le, utf-16be or latin-1")
    try:
        return bytes(data).decode(codec).encode("utf-8")
    except UnicodeDecodeError as exc:
        raise DecodeError(f"cannot read bytes as {name}: {exc}") from None


# --- decompress (incremental, bomb-guarded) --------------------------------

def _inflate(data: bytes, wbits: int) -> bytes:
    d = zlib.decompressobj(wbits)
    out = bytearray()
    buf = bytes(data)
    try:
        while True:
            part = d.decompress(buf, _CHUNK)
            if not part:
                break
            out.extend(part)
            if len(out) > CAP:
                raise DecodeError("output too large")
            buf = d.unconsumed_tail
        out.extend(d.flush())
    except zlib.error as exc:
        raise DecodeError(f"not valid compressed data: {exc}") from None
    if len(out) > CAP:
        raise DecodeError("output too large")
    return bytes(out)


def _zlib_inflate(data: bytes) -> bytes:
    return _inflate(data, 15)


def _raw_inflate(data: bytes) -> bytes:
    return _inflate(data, -15)


def _gunzip(data: bytes) -> bytes:
    return _inflate(data, 15 + 16)


def _stream_decompress(data: bytes, new_decompressor: Callable, label: str) -> bytes:
    dec = new_decompressor()
    out = bytearray()
    buf = bytes(data)
    fed = False
    try:
        while True:
            part = dec.decompress(b"" if fed else buf, _CHUNK)
            fed = True
            out.extend(part)
            if len(out) > CAP:
                raise DecodeError("output too large")
            if dec.eof:
                break
            if not part and dec.needs_input:   # all input consumed, stream unfinished
                break
    except (OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        raise DecodeError(f"not valid {label} data: {exc}") from None
    return bytes(out)


def _bunzip2(data: bytes) -> bytes:
    return _stream_decompress(data, bz2.BZ2Decompressor, "bzip2")


def _unxz(data: bytes) -> bytes:
    return _stream_decompress(
        data, lambda: lzma.LZMADecompressor(format=lzma.FORMAT_XZ), "xz")


# --- classic ciphers -------------------------------------------------------

def _rot_n(data: bytes, n=13) -> bytes:
    n = _as_int(n, "n")
    if not 0 <= n <= 25:
        raise DecodeError("n must be between 0 and 25")
    out = bytearray(data)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = (c - 65 + n) % 26 + 65
        elif 97 <= c <= 122:
            out[i] = (c - 97 + n) % 26 + 97
    return bytes(out)


def _atbash(data: bytes) -> bytes:
    out = bytearray(data)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = 90 - (c - 65)
        elif 97 <= c <= 122:
            out[i] = 122 - (c - 97)
    return bytes(out)


def _vigenere(data: bytes, key="", mode="decrypt") -> bytes:
    if mode not in ("decrypt", "encrypt"):
        raise DecodeError("mode must be decrypt or encrypt")
    shifts = [(ord(ch.upper()) - 65) for ch in str(key) if ch.isalpha()]
    if not shifts:
        raise DecodeError("vigenere needs a key of letters")
    sign = 1 if mode == "encrypt" else -1
    out = bytearray(data)
    j = 0
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = (c - 65 + sign * shifts[j % len(shifts)]) % 26 + 65
            j += 1
        elif 97 <= c <= 122:
            out[i] = (c - 97 + sign * shifts[j % len(shifts)]) % 26 + 97
            j += 1
    return bytes(out)


def _xor_with(data: bytes, key: bytes) -> bytes:
    if not key:
        raise DecodeError("xor needs a non-empty key")
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def _xor(data: bytes, **params) -> bytes:
    return _xor_with(data, _key_bytes(params, "xor"))


def _railfence(data: bytes, rails=2, mode="decrypt") -> bytes:
    rails = _as_int(rails, "rails")
    if rails < 2:
        raise DecodeError("rails must be at least 2")
    if mode not in ("decrypt", "encrypt"):
        raise DecodeError("mode must be decrypt or encrypt")
    n = len(data)
    if n == 0:
        return b""
    # The zig-zag row index for each of the n positions.
    rows, r, step = [], 0, 1
    for _ in range(n):
        rows.append(r)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    if mode == "encrypt":
        out = bytearray()
        for target in range(rails):
            for i, row in enumerate(rows):
                if row == target:
                    out.append(data[i])
        return bytes(out)
    # decrypt: fill the rails from the ciphertext, then read along the zig-zag.
    counts = [rows.count(target) for target in range(rails)]
    pos, rail_data = 0, []
    for c in counts:
        rail_data.append(bytearray(data[pos:pos + c]))
        pos += c
    out = bytearray(n)
    idx = [0] * rails
    for i, row in enumerate(rows):
        out[i] = rail_data[row][idx[row]]
        idx[row] += 1
    return bytes(out)


def _substitution(data: bytes, map="") -> bytes:
    mapping = str(map)
    letters = [ch for ch in mapping if ch.isalpha()]
    if len(letters) != 26 or len({ch.upper() for ch in letters}) != 26:
        raise DecodeError("map must be a 26-letter permutation of the alphabet")
    cipher = [ch.upper() for ch in letters]     # plain 'A'+i is enciphered as cipher[i]
    inverse = {cipher[i]: i for i in range(26)}  # cipher letter -> plain index
    out = bytearray(data)
    for i, c in enumerate(out):
        upper = 65 <= c <= 90
        lower = 97 <= c <= 122
        if upper or lower:
            plain = inverse[chr(c).upper()]
            out[i] = plain + (65 if upper else 97)
    return bytes(out)


# --- hash ------------------------------------------------------------------

def _hash(data: bytes, algo="sha256") -> bytes:
    if algo == "crc32":
        return format(zlib.crc32(bytes(data)) & 0xFFFFFFFF, "08x").encode("ascii")
    if algo in ("md5", "sha1", "sha256"):
        return hashlib.new(algo, bytes(data)).hexdigest().encode("ascii")
    raise DecodeError("algo must be md5, sha1, sha256 or crc32")


# --- symmetric (via vex.crypto) --------------------------------------------

def _crypto_has(name: str) -> bool:
    return crypto is not None and name in getattr(crypto, "AVAILABLE", set())


def _need(name: str) -> None:
    if not _crypto_has(name):
        raise DecodeError(f"{name} is not available in this build")


def _aes(data: bytes, key="", mode="cbc", iv="", nonce="", tag="",
         op="decrypt", unpad="pkcs7") -> bytes:
    _need("aes")
    if mode == "gcm":
        _need("aes-gcm")
    if mode not in ("ecb", "cbc", "ctr", "gcm"):
        raise DecodeError("mode must be ecb, cbc, ctr or gcm")
    if op not in ("decrypt", "encrypt"):
        raise DecodeError("op must be decrypt or encrypt")
    if unpad not in ("pkcs7", "none"):
        raise DecodeError("unpad must be pkcs7 or none")
    try:
        return crypto.aes(bytes(data), _parse_hex(key), mode, iv=_parse_hex(iv),
                          nonce=_parse_hex(nonce), op=op, unpad=unpad, tag=_parse_hex(tag))
    except VexError:
        raise
    except Exception as exc:
        raise DecodeError(f"aes failed: {exc}") from None


def _chacha20(data: bytes, key="", nonce="", counter=1) -> bytes:
    _need("chacha20")
    try:
        return crypto.chacha20(bytes(data), _parse_hex(key), _parse_hex(nonce),
                               counter=_as_int(counter, "counter"))
    except VexError:
        raise
    except Exception as exc:
        raise DecodeError(f"chacha20 failed: {exc}") from None


def _rc4(data: bytes, **params) -> bytes:
    _need("rc4")
    try:
        return crypto.rc4(bytes(data), _key_bytes(params, "rc4"))
    except VexError:
        raise
    except Exception as exc:
        raise DecodeError(f"rc4 failed: {exc}") from None


def _des(data: bytes, key="", mode="ecb", iv="", op="decrypt") -> bytes:
    _need("des")
    try:
        return crypto.des(bytes(data), _parse_hex(key), mode=mode,
                          iv=_parse_hex(iv), op=op)
    except VexError:
        raise
    except Exception as exc:
        raise DecodeError(f"des failed: {exc}") from None


def _triple_des(data: bytes, key="", mode="ecb", iv="", op="decrypt") -> bytes:
    _need("3des")
    try:
        return crypto.triple_des(bytes(data), _parse_hex(key), mode=mode,
                                 iv=_parse_hex(iv), op=op)
    except VexError:
        raise
    except Exception as exc:
        raise DecodeError(f"3des failed: {exc}") from None


# --- the operation registry ------------------------------------------------

@dataclass
class Op:
    name: str
    group: str
    summary: str
    params: List[dict]
    fn: Callable[..., bytes]
    requires: Optional[str] = None      # crypto primitive this op needs

    def available(self) -> bool:
        return self.requires is None or _crypto_has(self.requires)


def _p(name: str, type: str, required: bool = False,
       choices: Optional[Tuple[str, ...]] = None, default=None) -> dict:
    d: dict = {"name": name, "required": required, "type": type}
    if choices is not None:
        d["choices"] = list(choices)
    if default is not None:
        d["default"] = default
    return d


_ALPHABET = (_p("alphabet", "choice", choices=("std", "url"), default="std"),)
_VARIANT = (_p("variant", "choice", choices=("ascii85", "z85"), default="ascii85"),)

_OP_LIST: List[Op] = [
    # Encoding
    Op("from-base64", "Encoding", "decode base64", list(_ALPHABET), _from_base64),
    Op("to-base64", "Encoding", "encode base64", list(_ALPHABET), _to_base64),
    Op("from-base32", "Encoding", "decode base32", [], _from_base32),
    Op("to-base32", "Encoding", "encode base32", [], _to_base32),
    Op("from-hex", "Encoding", "decode hex (lenient whitespace)", [], _from_hex),
    Op("to-hex", "Encoding", "encode hex", [], _to_hex),
    Op("from-base85", "Encoding", "decode ascii85 or z85", list(_VARIANT), _from_base85),
    Op("to-base85", "Encoding", "encode ascii85 or z85", list(_VARIANT), _to_base85),
    Op("url-decode", "Encoding", "decode percent-encoding", [], _url_decode),
    Op("url-encode", "Encoding", "encode percent-encoding", [], _url_encode),
    Op("qp-decode", "Encoding", "decode quoted-printable", [], _qp_decode),
    Op("rot13", "Encoding", "ROT13 on letters (self-inverse)", [], _rot13),
    Op("reverse", "Encoding", "reverse the bytes", [], _reverse),
    Op("charset-decode", "Encoding", "reinterpret text and re-emit UTF-8",
       [_p("from", "choice", choices=("utf-8", "utf-16le", "utf-16be", "latin-1"),
           default="utf-8")], _charset_decode),
    # Decompress
    Op("zlib-inflate", "Decompress", "inflate a zlib stream", [], _zlib_inflate),
    Op("raw-inflate", "Decompress", "inflate a headerless DEFLATE stream", [], _raw_inflate),
    Op("gunzip", "Decompress", "decompress a gzip stream", [], _gunzip),
    Op("bunzip2", "Decompress", "decompress a bzip2 stream", [], _bunzip2),
    Op("unxz", "Decompress", "decompress an xz stream", [], _unxz),
    # Classic cipher
    Op("rot-n", "Classic cipher", "Caesar shift on letters",
       [_p("n", "int", default=13)], _rot_n),
    Op("atbash", "Classic cipher", "Atbash (self-inverse)", [], _atbash),
    Op("vigenere", "Classic cipher", "Vigenere cipher",
       [_p("key", "string", required=True),
        _p("mode", "choice", choices=("decrypt", "encrypt"), default="decrypt")], _vigenere),
    Op("xor", "Classic cipher", "repeating-key XOR (self-inverse)",
       [_p("key", "hex"), _p("key_text", "string")], _xor),
    Op("railfence", "Classic cipher", "rail-fence transposition",
       [_p("rails", "int", required=True),
        _p("mode", "choice", choices=("decrypt", "encrypt"), default="decrypt")], _railfence),
    Op("substitution", "Classic cipher", "monoalphabetic substitution",
       [_p("map", "string", required=True)], _substitution),
    # Symmetric
    Op("aes", "Symmetric", "AES (needs a supplied key)",
       [_p("key", "hex", required=True),
        _p("mode", "choice", choices=("ecb", "cbc", "ctr", "gcm"), required=True),
        _p("iv", "hex"), _p("nonce", "hex"), _p("tag", "hex"),
        _p("op", "choice", choices=("decrypt", "encrypt"), default="decrypt"),
        _p("unpad", "choice", choices=("pkcs7", "none"), default="pkcs7")],
       _aes, requires="aes"),
    Op("chacha20", "Symmetric", "ChaCha20 (RFC 8439, self-inverse)",
       [_p("key", "hex", required=True), _p("nonce", "hex", required=True),
        _p("counter", "int", default=1)], _chacha20, requires="chacha20"),
    Op("rc4", "Symmetric", "RC4 (self-inverse)",
       [_p("key", "hex"), _p("key_text", "string")], _rc4, requires="rc4"),
    Op("des", "Symmetric", "DES (needs a supplied key)",
       [_p("key", "hex", required=True),
        _p("mode", "choice", choices=("ecb", "cbc"), default="ecb"),
        _p("iv", "hex"), _p("op", "choice", choices=("decrypt", "encrypt"), default="decrypt")],
       _des, requires="des"),
    Op("3des", "Symmetric", "Triple DES (needs a supplied key)",
       [_p("key", "hex", required=True),
        _p("mode", "choice", choices=("ecb", "cbc"), default="ecb"),
        _p("iv", "hex"), _p("op", "choice", choices=("decrypt", "encrypt"), default="decrypt")],
       _triple_des, requires="3des"),
    # Hash
    Op("hash", "Hash", "replace data with its digest as hex",
       [_p("algo", "choice", choices=("md5", "sha1", "sha256", "crc32"), default="sha256")],
       _hash),
]

REGISTRY: Dict[str, Op] = {op.name: op for op in _OP_LIST}
_GROUP_ORDER = ["Encoding", "Decompress", "Classic cipher", "Symmetric", "Hash"]


# --- applying operations ---------------------------------------------------

def apply_op(name: str, params: dict, data: bytes) -> bytes:
    """Run one operation, validating its name, parameters and the output cap."""
    op = REGISTRY.get(name)
    if op is None:
        raise DecodeError(f"unknown operation: {name!r}")
    if not op.available():
        raise DecodeError(f"{name} is not available in this build")
    allowed = {p["name"] for p in op.params}
    for key in params:
        if key not in allowed:
            raise DecodeError(f"unknown parameter {key!r} for {name}")
    for p in op.params:
        if p.get("required") and params.get(p["name"]) in (None, ""):
            raise DecodeError(f"{name} needs parameter {p['name']}")
    out = op.fn(bytes(data), **{k: v for k, v in params.items()})
    if not isinstance(out, (bytes, bytearray)):
        raise DecodeError(f"{name} did not produce bytes")
    if len(out) > CAP:
        raise DecodeError("output too large")
    return bytes(out)


# --- the pipeline engine ---------------------------------------------------

@dataclass
class ExecResult:
    ok: bool
    data: bytes                         # final bytes, or the last good bytes on failure
    steps: List[dict]                   # completed steps: [{op, size}, ...]
    error: Optional[str]


def execute(get_source: Callable[[], bytes],
            recipe: List[Tuple[str, dict]]) -> ExecResult:
    """Resolve the source and apply the recipe left to right. A failed step (or
    bad source) stops the pipeline and is reported; it never raises."""
    try:
        data = bytes(get_source())
        if len(data) > CAP:
            raise DecodeError("output too large")
    except DecodeError as exc:
        return ExecResult(False, b"", [], str(exc))
    steps: List[dict] = []
    for name, params in recipe:
        try:
            new = apply_op(name, params or {}, data)
        except DecodeError as exc:
            return ExecResult(False, data, steps, str(exc))
        data = new
        steps.append({"op": name, "size": len(data)})
    return ExecResult(True, data, steps, None)


def result_object(er: ExecResult) -> dict:
    return {"ok": er.ok, "size": len(er.data), "hex": er.data.hex(),
            "text": er.data.decode("utf-8", "replace"),
            "looks_like": looks_like(er.data), "steps": er.steps, "error": er.error}


def run(get_source: Callable[[], bytes], recipe: List[Tuple[str, dict]]) -> dict:
    """Execute a recipe and return the result object the API and CLI share."""
    return result_object(execute(get_source, recipe))


# --- sources ---------------------------------------------------------------

def source_bytes(kind: str, value: str = "", data: bytes = b"",
                 offset=0, length=None) -> bytes:
    """The starting bytes for a source. ``file`` slices ``data`` (already read
    from the open program or a path), bounded to what the file holds."""
    if kind == "text":
        return str(value).encode("utf-8")
    if kind == "hex":
        return _parse_hex(value)
    if kind == "base64":
        return _from_base64(value if isinstance(value, (bytes, bytearray))
                            else str(value).encode("latin-1"))
    if kind == "file":
        off = _as_int(offset, "offset") if offset not in (None, "") else 0
        if off < 0:
            raise DecodeError("offset must not be negative")
        if length in (None, ""):
            end = len(data)
        else:
            n = _as_int(length, "length")
            if n < 0:
                raise DecodeError("length must not be negative")
            end = off + n
        return bytes(data)[off:end]
    raise DecodeError(f"unknown source kind: {kind!r}")


# --- the recipe grammar ----------------------------------------------------

def parse_recipe(text: str) -> List[Tuple[str, dict]]:
    """Parse ``op[:k=v,...][|op...]``. An unknown operation or parameter, or a
    malformed ``k=v``, raises :class:`RecipeError` (a usage error)."""
    recipe: List[Tuple[str, dict]] = []
    if text is None or not text.strip():
        return recipe
    for piece in text.split("|"):
        name, sep, rest = piece.partition(":")
        name = name.strip()
        if not name:
            raise RecipeError("empty operation in recipe")
        op = REGISTRY.get(name)
        if op is None:
            raise RecipeError(f"unknown operation: {name!r}")
        allowed = {p["name"] for p in op.params}
        params: dict = {}
        if sep:
            for pair in rest.split(","):
                if not pair.strip():
                    continue
                key, eq, val = pair.partition("=")
                key = key.strip()
                if not eq:
                    raise RecipeError(f"expected key=value, got {pair.strip()!r} for {name}")
                if key not in allowed:
                    raise RecipeError(f"unknown parameter {key!r} for {name}")
                params[key] = val.strip()
        recipe.append((name, params))
    return recipe


# --- the operation catalogue -----------------------------------------------

def ops() -> dict:
    """The catalogue ``GET /api/decode/ops`` serves and ``--list`` prints."""
    groups = []
    for group_name in _GROUP_ORDER:
        entries = []
        for op in _OP_LIST:
            if op.group != group_name:
                continue
            entries.append({"name": op.name, "summary": op.summary,
                            "available": op.available(),
                            "params": [dict(p) for p in op.params]})
        groups.append({"name": group_name, "ops": entries})
    solvers = [{"name": name, "summary": summary} for name, summary in _SOLVERS_INFO]
    return {"groups": groups, "solvers": solvers}


# --- scoring ---------------------------------------------------------------

_ENGLISH_FREQ = {
    "a": .08167, "b": .01492, "c": .02782, "d": .04253, "e": .12702, "f": .02228,
    "g": .02015, "h": .06094, "i": .06966, "j": .00153, "k": .00772, "l": .04025,
    "m": .02406, "n": .06749, "o": .07507, "p": .01929, "q": .00095, "r": .05987,
    "s": .06327, "t": .09056, "u": .02758, "v": .00978, "w": .02360, "x": .00150,
    "y": .01974, "z": .00074,
}
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for c in data if c in _PRINTABLE) / len(data)


# The commonest English letter pairs, per 10,000 pairs. They separate real words
# from letter soup on inputs too short for single-letter counts to settle.
_PAIRS = ("th 356 he 307 in 243 er 205 an 199 re 185 on 176 at 149 en 145 nd 135 "
          "ti 134 es 134 or 128 te 120 of 117 ed 117 is 113 it 112 al 109 ar 107 "
          "st 105 to 104 nt 104 ng 95 se 93 ha 93 as 87 ou 87 io 83 le 83 ve 83 "
          "co 79 me 79 de 76 hi 76 ri 73 ro 73 ic 70 ne 69 ea 69 ra 69 ce 65 li 62 "
          "ch 60 ll 58 be 58 ma 57 si 55 om 55 ur 54").split()
_PAIR_FREQ = {_PAIRS[i].encode(): int(_PAIRS[i + 1]) / 10000 for i in range(0, len(_PAIRS), 2)}
_SPACE_WEIGHT = 0.19                # a space is the commonest character in English
_WEIGHT_FULL = 0.085                # mean character weight of ordinary English
_PAIR_FULL = 0.0075                 # mean pair weight of ordinary English


def _english_fitness(data: bytes) -> float:
    """How English the bytes read, 0..1: 0.7 * characters + 0.3 * letter pairs.

    Characters: the mean of a per-byte weight (a letter's English frequency,
    0.19 for a space, 0 for other printable bytes, -0.5 for anything else),
    divided by 0.085 and clamped to 0..1. Pairs: the mean frequency of each
    adjacent pair of bytes among the commonest English letter pairs, divided by
    0.0075 and capped at 1. Unlike a chi-square on letters alone this rewards
    spaces, so a near-miss key that turns them into punctuation ranks lower."""
    if not data:
        return 0.0
    total = 0.0
    for c in data:
        if c == 0x20:
            total += _SPACE_WEIGHT
        elif 65 <= c <= 90:
            total += _ENGLISH_FREQ[chr(c + 32)]
        elif 97 <= c <= 122:
            total += _ENGLISH_FREQ[chr(c)]
        elif c not in _PRINTABLE:
            total -= 0.5
    chars = min(1.0, max(0.0, total / len(data) / _WEIGHT_FULL))
    pairs = 0.0
    if len(data) > 1:
        low = data.lower()
        hits = 0.0
        for i in range(len(low) - 1):
            hits += _PAIR_FREQ.get(low[i:i + 2], 0.0)
        pairs = min(1.0, hits / (len(low) - 1) / _PAIR_FULL)
    return 0.7 * chars + 0.3 * pairs


def _score(data: bytes) -> float:
    return 0.6 * _printable_ratio(data) + 0.4 * _english_fitness(data)


def _candidate(params: dict, data: bytes) -> dict:
    return {"params": params, "size": len(data), "hex": data.hex(),
            "text": data.decode("utf-8", "replace"), "score": round(_score(data), 6)}


# --- solvers ---------------------------------------------------------------

def _solve_caesar(data: bytes) -> List[dict]:
    out = [_candidate({"n": n}, _rot_n(data, n=n)) for n in range(26)]
    out.sort(key=lambda c: c["score"], reverse=True)
    return out


def _solve_xor_single(data: bytes) -> List[dict]:
    out = []
    for b in range(256):
        dec = bytes(c ^ b for c in data)
        out.append(_candidate({"key": format(b, "02x")}, dec))
    out.sort(key=lambda c: c["score"], reverse=True)
    return out[:20]


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# Space-aware English weights for single-byte key recovery. The plain chi-square
# in _score ignores spaces (the commonest character in English), which is too
# weak on the short, space-heavy columns a repeating key splits text into.
_RECOVERY_WEIGHT = dict(_ENGLISH_FREQ)
_RECOVERY_WEIGHT[" "] = 0.19


def _recovery_score(data: bytes) -> float:
    total = 0.0
    for c in data:
        if c == 0x20:
            total += 0.19
        elif 65 <= c <= 90:
            total += _ENGLISH_FREQ[chr(c + 32)]
        elif 97 <= c <= 122:
            total += _ENGLISH_FREQ[chr(c)]
        elif c in (0x09, 0x0A, 0x0D) or 0x21 <= c <= 0x7E:
            total += 0.0
        else:
            total -= 0.5                # control / non-printable: unlikely in text
    return total


def _best_single_byte(column: bytes) -> int:
    best_b, best_score = 0, float("-inf")
    for b in range(256):
        s = _recovery_score(bytes(c ^ b for c in column))
        if s > best_score:
            best_score, best_b = s, b
    return best_b


def _minimal_period(key: bytes) -> bytes:
    """Collapse a key that is a whole-number repeat of a shorter one."""
    n = len(key)
    for p in range(1, n):
        if n % p == 0 and key == key[:p] * (n // p):
            return key[:p]
    return key


def _solve_xor_keylen(data: bytes) -> List[dict]:
    n = len(data)
    if n < 2:
        return _solve_xor_single(data)
    max_len = min(40, n // 2)
    scored = []
    for L in range(1, max_len + 1):
        blocks = [data[i * L:(i + 1) * L] for i in range(n // L)]
        pairs = min(len(blocks) - 1, 12)
        if pairs < 1:
            continue
        dist = sum(_hamming(blocks[i], blocks[i + 1]) for i in range(pairs)) / (pairs * L)
        scored.append((dist, L))
    scored.sort()
    lengths = [L for _, L in scored[:4]] or [1]
    out, seen = [], set()
    for L in lengths:
        key = _minimal_period(bytes(_best_single_byte(data[col::L]) for col in range(L)))
        if key in seen:
            continue
        seen.add(key)
        dec = _xor_with(data, key) if key else data
        out.append(_candidate({"key": key.hex(), "keylen": len(key)}, dec))
    # Best decode first; on a tie, the shorter key is the canonical answer.
    out.sort(key=lambda c: (-c["score"], c["params"]["keylen"]))
    return out[:20]


_ENGLISH_ORDER = "etaoinshrdlcumwfgypbvkjxqz"


def _solve_substitution(data: bytes) -> List[dict]:
    counts = [0] * 26
    for c in data:
        if 65 <= c <= 90:
            counts[c - 65] += 1
        elif 97 <= c <= 122:
            counts[c - 97] += 1
    # cipher letters, most frequent first
    cipher_by_freq = [chr(65 + i) for i in sorted(range(26), key=lambda i: -counts[i])]
    # guess: i-th most common cipher letter is the i-th most common English letter
    plain_to_cipher: Dict[str, str] = {}
    used = set()
    for cipher_letter, plain_letter in zip(cipher_by_freq, _ENGLISH_ORDER.upper()):
        plain_to_cipher[plain_letter] = cipher_letter
        used.add(cipher_letter)
    # fill any plain letters left (when ties collapsed) with unused cipher letters
    spare = [chr(65 + i) for i in range(26) if chr(65 + i) not in used]
    for plain_letter in (chr(65 + i) for i in range(26)):
        if plain_letter not in plain_to_cipher:
            plain_to_cipher[plain_letter] = spare.pop()
    mapping = "".join(plain_to_cipher[chr(65 + i)] for i in range(26))
    return [_candidate({"map": mapping}, _substitution(data, map=mapping))]


_SOLVERS: Dict[str, Callable[[bytes], List[dict]]] = {
    "caesar": _solve_caesar,
    "xor-single": _solve_xor_single,
    "xor-keylen": _solve_xor_keylen,
    "substitution": _solve_substitution,
}
_SOLVERS_INFO = [
    ("caesar", "try all 26 Caesar shifts"),
    ("xor-single", "try all 256 single-byte XOR keys"),
    ("xor-keylen", "guess a repeating-XOR key of length 1..40"),
    ("substitution", "frequency-match a monoalphabetic substitution"),
]


def solve(name: str, get_source: Callable[[], bytes]) -> dict:
    """Run a solver over the source bytes, returning ``{ok, candidates, error}``.
    Solvers never raise on arbitrary bytes; a bad source is reported, not raised."""
    solver = _SOLVERS.get(name)
    if solver is None:
        return {"ok": False, "candidates": [], "error": f"unknown solver: {name!r}"}
    try:
        data = bytes(get_source())
    except DecodeError as exc:
        return {"ok": False, "candidates": [], "error": str(exc)}
    data = data[:_SOLVE_CAP]
    try:
        candidates = solver(data)
    except Exception as exc:            # a solver must never take the caller down
        return {"ok": False, "candidates": [], "error": f"solver failed: {exc}"}
    return {"ok": True, "candidates": candidates[:20], "error": None}


# --- looks_like magic guess ------------------------------------------------

_SIGNATURES: List[Tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"PK\x03\x04", "zip archive"),
    (b"PK\x05\x06", "zip archive"),
    (b"\x7fELF", "ELF program"),
    (b"%PDF-", "PDF document"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"\x25\x21", "PostScript"),
]


def looks_like(data: bytes) -> str:
    """A short magic guess: a file type, "printable text", "binary" or "empty"."""
    if not data:
        return "empty"
    for sig, name in _SIGNATURES:
        if data.startswith(sig):
            return name
    if data[:2] == b"MZ":
        if len(data) >= 0x40:
            e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
            if 0 <= e_lfanew <= len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                return "PE program"
        return "DOS executable"
    if _printable_ratio(data) >= 0.95:
        return "printable text"
    return "binary"
