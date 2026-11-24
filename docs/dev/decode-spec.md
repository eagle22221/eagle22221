# `vex decode` — decode & cipher workbench — specification

Purpose: apply reversible transforms and supplied-key decryptions to data the
user already has — typed text, a hex/base64 blob, a byte range of the open
program, or a string from it — and chain operations into a recipe, like a local
CyberChef built into vex. It never recovers an unknown key and never defeats DRM,
licence checks or anti-cheat: strong crypto is decrypted only with the key the
user supplies. Everything operates on data the user provides or selects.

## Data model

- An **operation** maps `bytes -> bytes`. Python signature `fn(data: bytes, **params) -> bytes`;
  raises `DecodeError(message)` on bad input or params.
- A **recipe** is an ordered list `[(op_name, params), ...]`, applied left to right
  starting from the source bytes.
- A **source** produces the starting bytes:
  - `text`: UTF-8 encoding of a string.
  - `hex`: parse hex, ignoring spaces, newlines, `0x`, `,`, `:`; error on odd length or non-hex.
  - `base64`: standard alphabet, padding optional; error on invalid.
  - `file`: offset + length within the open program (server) or a path (CLI).
- The output bytes are rendered as `text` (UTF-8, U+FFFD for invalid), `hex`,
  `size`, and a short `looks_like` magic guess (e.g. "PNG image", "gzip", "PE
  program", "printable text", "binary").

## Output cap

Every operation and the whole pipeline cap output at **64 MiB**; exceeding it
raises `DecodeError("output too large")`. Decompression operations must enforce
this incrementally — never allocate unbounded — so a decompression bomb is
refused, not expanded.

## Operations (name — params — meaning)

Encoding (reversible):
- `from-base64` — alphabet=std|url (std) — decode base64; `to-base64` encodes.
- `from-base32` / `to-base32`
- `from-hex` (lenient whitespace) / `to-hex`
- `from-base85` — variant=ascii85|z85 (ascii85) / `to-base85`
- `url-decode` / `url-encode` (percent-encoding)
- `qp-decode` (quoted-printable)
- `rot13` (self-inverse)
- `reverse` (reverse the bytes)
- `charset-decode` — from=utf-8|utf-16le|utf-16be|latin-1 — reinterpret bytes as text, re-emit UTF-8

Decompress:
- `zlib-inflate` (zlib header), `raw-inflate` (no header), `gunzip`, `bunzip2`, `unxz`

Classic cipher:
- `rot-n` — n=0..25 — Caesar shift on letters
- `atbash`
- `vigenere` — key=TEXT, mode=decrypt|encrypt (decrypt)
- `xor` — key=HEX or key_text=TEXT — repeating-key XOR (self-inverse)
- `railfence` — rails=N, mode=decrypt
- `substitution` — map=26-letter mapping — decrypt

Symmetric (needs a user-supplied key; from `vex/crypto.py`):
- `aes` — key=HEX(16/24/32), mode=ecb|cbc|ctr|gcm, iv=HEX(16) for cbc,
  nonce=HEX for ctr/gcm, tag=HEX(16) for gcm, op=decrypt|encrypt, unpad=pkcs7|none.
  ECB/CBC/CTR are required; GCM is optional (mark unavailable if not built).
- `chacha20` — key=HEX(32), nonce=HEX(12), counter=INT(1) — RFC 8439 (self-inverse)
- `rc4` — key=HEX or key_text — RC4 (self-inverse)
- `des`, `3des` — optional; key=HEX, mode=ecb|cbc, iv=HEX(8). May be Python-only.

Hash (not reversible; convenience):
- `hash` — algo=md5|sha1|sha256|crc32 — replace data with its digest as hex bytes

## Solvers (search; a separate entry point, never in a plain recipe)

Each returns a ranked list `[{params, size, hex, text, score}]`, best first, at most
20 candidates. `score` in 0..1 = 0.6 * printable_ratio + 0.4 * english_fitness,
where english_fitness maps an English letter-frequency chi-square to 0..1 (1 = very
English-like). Solvers never raise on arbitrary bytes.
- `caesar` — all 26 shifts
- `xor-single` — all 256 single-byte keys
- `xor-keylen` — guess a repeating-XOR key of length 1..40 (Hamming-distance
  method), recover it, return the best few
- `substitution` — frequency-match monoalphabetic substitution (best-effort)

## crypto API (`vex/crypto.py`, consumed by `vex/decode.py`)

Pure Python, standard library only. Correct against public test vectors (NIST
AES, RFC 8439 ChaCha20, standard RC4). Interface:

    crypto.AVAILABLE: set[str]        # subset of {"aes","aes-gcm","chacha20","rc4","des","3des"}
    crypto.aes(data, key, mode, iv=b"", nonce=b"", op="decrypt", unpad="pkcs7", tag=b"") -> bytes
    crypto.chacha20(data, key, nonce, counter=1) -> bytes
    crypto.rc4(data, key) -> bytes
    crypto.des(data, key, mode="ecb", iv=b"", op="decrypt") -> bytes      # if "des" in AVAILABLE
    crypto.triple_des(...) -> bytes                                        # if "3des" in AVAILABLE

`decode.py` consults `crypto.AVAILABLE`; a symmetric op whose primitive is not
available raises `DecodeError("aes is not available in this build")`.

## CLI

    vex decode SOURCE [--recipe "op[:k=v,...][|op...]"] [--out FILE] [--json]
    vex decode SOURCE --solve NAME [--json]
    vex decode --list

SOURCE: `--text S` | `--hex S` | `--base64 S` | `--file PATH [--offset O] [--length N]`,
or a bare positional treated as `--text`.
Recipe grammar: operations separated by `|`; each is `name` optionally `:` then
comma-separated `k=v` pairs (a `,` inside a value is not supported — give the value
as hex). Unknown operation or parameter: exit 2 with a clear message.
Default (no recipe, no solve): show the source bytes (hexdump + text).
`--out FILE` writes the raw output bytes; it refuses to overwrite (`FILE exists`)
and prints a one-line confirmation.
Human output: the final `text`, then a hexdump, then `N bytes · looks like X`.
`--json`: the result object below. `--list`: available operations and params.

## HTTP API

- `GET /api/decode/ops` -> the operation catalogue the UI renders:
  `{groups:[{name, ops:[{name, params:[{name, required, type, choices?, default?}], summary, available:bool}]}], solvers:[{name, summary}]}`.
  `available` is false for operations this edition does not implement; the shared
  UI reads this catalogue and must not hard-code the operation list.
- `POST /api/decode` body `{source:{kind, value?, path?, offset?, length?}, recipe:[{op, params}]}`
  -> `{ok, size, hex, text, looks_like, steps:[{op, size}], error?}`. Never writes
  to disk. A bad operation/param/key is `ok:false` with `error` and the `steps`
  completed so far, HTTP 200. A malformed body is 400.
- `POST /api/decode/solve` body `{source, name}` -> `{ok, candidates:[...], error?}`.
A `file` source resolves against the open workspace program the same way other
POST routes do, bounded to the file.

## Result object (CLI `--json`, used by tests)

    {"ok": bool, "size": int, "hex": str, "text": str, "looks_like": str,
     "steps": [{"op": str, "size": int}], "error": str|null}

## Editions

- Python (`vex/decode.py` + `vex/crypto.py`): everything above.
- C (`c/`): match Python byte-for-byte for what it implements — all encodings,
  `raw-inflate`/`zlib-inflate`/`gunzip` (reuse `c/src/inflate.c`), every classic
  cipher, `xor`, `rc4`, `chacha20`, and the solvers. `aes` (and `gcm`), `bunzip2`,
  `unxz`, `des`/`3des` may be Python-only for now; the C `ops` catalogue reports
  `available:false` for those, so the shared UI greys them out when the C edition
  serves it.
- Safety: operate only on supplied or selected data; decryptions require a
  user-supplied key; no search that targets protection; enforce the 64 MiB cap and
  decompression-bomb guards everywhere; never execute anything.
