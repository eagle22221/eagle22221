"""Pure-Python symmetric crypto primitives for vex's decode workbench.

Standard library only -- no third-party crypto. Consumed by ``vex/decode.py``,
which maps these onto recipe operations (see ``docs/dev/decode-spec.md``). Every
primitive is verified against public test vectors (NIST FIPS-197 / SP 800-38A /
SP 800-38D for AES, RFC 8439 for ChaCha20, standard RC4 and FIPS-46 DES vectors)
in ``tests/test_crypto.py``.

Nothing here searches for an unknown key: callers supply the key. Functions
raise ``ValueError`` with a clear message on bad input (wrong key/iv/nonce
length, bad padding, a GCM tag that does not verify).

Interface (as the spec fixes it)::

    AVAILABLE: set[str]
    aes(data, key, mode, iv=b"", nonce=b"", op="decrypt", unpad="pkcs7", tag=b"") -> bytes
    chacha20(data, key, nonce, counter=1) -> bytes
    rc4(data, key) -> bytes
    des(data, key, mode="ecb", iv=b"", op="decrypt") -> bytes
    triple_des(data, key, mode="ecb", iv=b"", op="decrypt") -> bytes
"""

import hmac
import struct

__all__ = ["AVAILABLE", "aes", "chacha20", "rc4", "des", "triple_des"]


# --------------------------------------------------------------------------- #
# GF(2^8) arithmetic and the AES lookup tables (built once at import time).
# --------------------------------------------------------------------------- #

def _gmul(a, b):
    """Multiply two bytes in GF(2^8) with the AES reduction polynomial 0x11b."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _build_sbox():
    # Multiplicative inverse via exp/log tables over the generator 0x03.
    exp = [0] * 256
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _gmul(x, 3)

    def inv(a):
        return 0 if a == 0 else exp[(255 - log[a]) % 255]

    sbox = [0] * 256
    for a in range(256):
        i = inv(a)
        s = i ^ _rotl8(i, 1) ^ _rotl8(i, 2) ^ _rotl8(i, 3) ^ _rotl8(i, 4) ^ 0x63
        sbox[a] = s & 0xFF
    inv_sbox = [0] * 256
    for a in range(256):
        inv_sbox[sbox[a]] = a
    return sbox, inv_sbox


_SBOX, _INV_SBOX = _build_sbox()


def _build_tables():
    te0 = [0] * 256
    td0 = [0] * 256
    for x in range(256):
        s = _SBOX[x]
        te0[x] = ((_gmul(s, 2) << 24) ^ (s << 16) ^ (s << 8) ^ _gmul(s, 3)) & 0xFFFFFFFF
        si = _INV_SBOX[x]
        td0[x] = (
            (_gmul(si, 0x0E) << 24)
            ^ (_gmul(si, 0x09) << 16)
            ^ (_gmul(si, 0x0D) << 8)
            ^ _gmul(si, 0x0B)
        ) & 0xFFFFFFFF
    te1 = [_rotr32(v, 8) for v in te0]
    te2 = [_rotr32(v, 16) for v in te0]
    te3 = [_rotr32(v, 24) for v in te0]
    td1 = [_rotr32(v, 8) for v in td0]
    td2 = [_rotr32(v, 16) for v in td0]
    td3 = [_rotr32(v, 24) for v in td0]
    return (te0, te1, te2, te3), (td0, td1, td2, td3)


_TE, _TD = _build_tables()
_TE0, _TE1, _TE2, _TE3 = _TE
_TD0, _TD1, _TD2, _TD3 = _TD

# Round constants (rc[i] = x^(i-1) in GF(2^8)), as high-byte words.
_RCON = [0]
_rc = 1
for _ in range(14):
    _RCON.append(_rc << 24)
    _rc = _gmul(_rc, 2)


# --------------------------------------------------------------------------- #
# AES core: key schedule, single-block encrypt/decrypt (T-table based).
# --------------------------------------------------------------------------- #

def _aes_key_schedule(key):
    """Return (enc_words, dec_words, Nr) for a 16/24/32-byte key."""
    nk = len(key) // 4
    nr = nk + 6
    w = list(struct.unpack(">%dI" % nk, key))
    total = 4 * (nr + 1)
    sbox = _SBOX
    for i in range(nk, total):
        temp = w[i - 1]
        if i % nk == 0:
            # SubWord(RotWord(temp)) xor Rcon
            rot = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF
            temp = (
                (sbox[(rot >> 24) & 0xFF] << 24)
                | (sbox[(rot >> 16) & 0xFF] << 16)
                | (sbox[(rot >> 8) & 0xFF] << 8)
                | sbox[rot & 0xFF]
            ) ^ _RCON[i // nk]
        elif nk > 6 and i % nk == 4:
            temp = (
                (sbox[(temp >> 24) & 0xFF] << 24)
                | (sbox[(temp >> 16) & 0xFF] << 16)
                | (sbox[(temp >> 8) & 0xFF] << 8)
                | sbox[temp & 0xFF]
            )
        w.append(w[i - nk] ^ temp)

    # Decryption round keys (equivalent inverse cipher): reverse the round
    # order, then InvMixColumns every key but the first and last.
    dw = [0] * total
    for r in range(nr + 1):
        src = nr - r
        for c in range(4):
            word = w[4 * src + c]
            if 0 < r < nr:
                word = _inv_mix_column(word)
            dw[4 * r + c] = word
    return w, dw, nr


def _inv_mix_column(word):
    b0 = (word >> 24) & 0xFF
    b1 = (word >> 16) & 0xFF
    b2 = (word >> 8) & 0xFF
    b3 = word & 0xFF
    o0 = _gmul(b0, 0x0E) ^ _gmul(b1, 0x0B) ^ _gmul(b2, 0x0D) ^ _gmul(b3, 0x09)
    o1 = _gmul(b0, 0x09) ^ _gmul(b1, 0x0E) ^ _gmul(b2, 0x0B) ^ _gmul(b3, 0x0D)
    o2 = _gmul(b0, 0x0D) ^ _gmul(b1, 0x09) ^ _gmul(b2, 0x0E) ^ _gmul(b3, 0x0B)
    o3 = _gmul(b0, 0x0B) ^ _gmul(b1, 0x0D) ^ _gmul(b2, 0x09) ^ _gmul(b3, 0x0E)
    return (o0 << 24) | (o1 << 16) | (o2 << 8) | o3


def _encrypt_block(block, w, nr):
    te0, te1, te2, te3 = _TE0, _TE1, _TE2, _TE3
    sbox = _SBOX
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= w[0]
    s1 ^= w[1]
    s2 ^= w[2]
    s3 ^= w[3]
    for r in range(1, nr):
        k = 4 * r
        t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xFF] ^ te2[(s2 >> 8) & 0xFF] ^ te3[s3 & 0xFF] ^ w[k]
        t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xFF] ^ te2[(s3 >> 8) & 0xFF] ^ te3[s0 & 0xFF] ^ w[k + 1]
        t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xFF] ^ te2[(s0 >> 8) & 0xFF] ^ te3[s1 & 0xFF] ^ w[k + 2]
        t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xFF] ^ te2[(s1 >> 8) & 0xFF] ^ te3[s2 & 0xFF] ^ w[k + 3]
        s0, s1, s2, s3 = t0, t1, t2, t3
    k = 4 * nr
    o0 = ((sbox[s0 >> 24] << 24) | (sbox[(s1 >> 16) & 0xFF] << 16) | (sbox[(s2 >> 8) & 0xFF] << 8) | sbox[s3 & 0xFF]) ^ w[k]
    o1 = ((sbox[s1 >> 24] << 24) | (sbox[(s2 >> 16) & 0xFF] << 16) | (sbox[(s3 >> 8) & 0xFF] << 8) | sbox[s0 & 0xFF]) ^ w[k + 1]
    o2 = ((sbox[s2 >> 24] << 24) | (sbox[(s3 >> 16) & 0xFF] << 16) | (sbox[(s0 >> 8) & 0xFF] << 8) | sbox[s1 & 0xFF]) ^ w[k + 2]
    o3 = ((sbox[s3 >> 24] << 24) | (sbox[(s0 >> 16) & 0xFF] << 16) | (sbox[(s1 >> 8) & 0xFF] << 8) | sbox[s2 & 0xFF]) ^ w[k + 3]
    return struct.pack(">4I", o0, o1, o2, o3)


def _decrypt_block(block, dw, nr):
    td0, td1, td2, td3 = _TD0, _TD1, _TD2, _TD3
    isbox = _INV_SBOX
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= dw[0]
    s1 ^= dw[1]
    s2 ^= dw[2]
    s3 ^= dw[3]
    for r in range(1, nr):
        k = 4 * r
        t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xFF] ^ td2[(s2 >> 8) & 0xFF] ^ td3[s1 & 0xFF] ^ dw[k]
        t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xFF] ^ td2[(s3 >> 8) & 0xFF] ^ td3[s2 & 0xFF] ^ dw[k + 1]
        t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xFF] ^ td2[(s0 >> 8) & 0xFF] ^ td3[s3 & 0xFF] ^ dw[k + 2]
        t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xFF] ^ td2[(s1 >> 8) & 0xFF] ^ td3[s0 & 0xFF] ^ dw[k + 3]
        s0, s1, s2, s3 = t0, t1, t2, t3
    k = 4 * nr
    o0 = ((isbox[s0 >> 24] << 24) | (isbox[(s3 >> 16) & 0xFF] << 16) | (isbox[(s2 >> 8) & 0xFF] << 8) | isbox[s1 & 0xFF]) ^ dw[k]
    o1 = ((isbox[s1 >> 24] << 24) | (isbox[(s0 >> 16) & 0xFF] << 16) | (isbox[(s3 >> 8) & 0xFF] << 8) | isbox[s2 & 0xFF]) ^ dw[k + 1]
    o2 = ((isbox[s2 >> 24] << 24) | (isbox[(s1 >> 16) & 0xFF] << 16) | (isbox[(s0 >> 8) & 0xFF] << 8) | isbox[s3 & 0xFF]) ^ dw[k + 2]
    o3 = ((isbox[s3 >> 24] << 24) | (isbox[(s2 >> 16) & 0xFF] << 16) | (isbox[(s1 >> 8) & 0xFF] << 8) | isbox[s0 & 0xFF]) ^ dw[k + 3]
    return struct.pack(">4I", o0, o1, o2, o3)


# --------------------------------------------------------------------------- #
# PKCS#7 padding.
# --------------------------------------------------------------------------- #

def _pkcs7_pad(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def _pkcs7_unpad(data, block=16):
    if not data or len(data) % block != 0:
        raise ValueError("invalid PKCS#7 padding: length not a block multiple")
    n = data[-1]
    if n < 1 or n > block:
        raise ValueError("invalid PKCS#7 padding: bad pad byte")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding: inconsistent pad bytes")
    return data[:-n]


# --------------------------------------------------------------------------- #
# AES block modes.
# --------------------------------------------------------------------------- #

def _xor_bytes(a, b):
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")


def _aes_ecb(data, w, dw, nr, op, unpad):
    if op == "encrypt":
        if unpad == "pkcs7":
            data = _pkcs7_pad(data)
        elif len(data) % 16 != 0:
            raise ValueError("AES-ECB encrypt with unpad=none needs a multiple of 16 bytes")
        out = bytearray()
        for i in range(0, len(data), 16):
            out += _encrypt_block(data[i:i + 16], w, nr)
        return bytes(out)
    if len(data) % 16 != 0:
        raise ValueError("AES-ECB decrypt needs a multiple of 16 bytes")
    out = bytearray()
    for i in range(0, len(data), 16):
        out += _decrypt_block(data[i:i + 16], dw, nr)
    result = bytes(out)
    return _pkcs7_unpad(result) if unpad == "pkcs7" else result


def _aes_cbc(data, w, dw, nr, iv, op, unpad):
    if len(iv) != 16:
        raise ValueError("AES-CBC needs a 16-byte iv")
    if op == "encrypt":
        if unpad == "pkcs7":
            data = _pkcs7_pad(data)
        elif len(data) % 16 != 0:
            raise ValueError("AES-CBC encrypt with unpad=none needs a multiple of 16 bytes")
        out = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            prev = _encrypt_block(_xor_bytes(data[i:i + 16], prev), w, nr)
            out += prev
        return bytes(out)
    if len(data) % 16 != 0:
        raise ValueError("AES-CBC decrypt needs a multiple of 16 bytes")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        out += _xor_bytes(_decrypt_block(block, dw, nr), prev)
        prev = block
    result = bytes(out)
    return _pkcs7_unpad(result) if unpad == "pkcs7" else result


def _aes_ctr(data, w, nr, nonce):
    # The 16-byte counter block is `nonce` right-padded with zeros; it is
    # incremented as a 128-bit big-endian integer (matches NIST SP 800-38A,
    # whose vectors give the full 16-byte initial counter block).
    if len(nonce) > 16 or len(nonce) == 0:
        raise ValueError("AES-CTR needs a 1..16 byte nonce (16 for NIST vectors)")
    counter = int.from_bytes(nonce + b"\x00" * (16 - len(nonce)), "big")
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = _encrypt_block(counter.to_bytes(16, "big"), w, nr)
        chunk = data[i:i + 16]
        out += _xor_bytes(chunk, ks[:len(chunk)])
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


# ---- AES-GCM --------------------------------------------------------------- #

def _gf_mult(x, y):
    """Multiply two elements of GF(2^128) under the GCM reduction polynomial."""
    r = 0xE1 << 120
    z = 0
    v = x
    for bit in range(128):
        if (y >> (127 - bit)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ r
        else:
            v >>= 1
    return z


def _ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        y = _gf_mult(y ^ int.from_bytes(block, "big"), h)
    return y


def _gcm_j0(h, nonce):
    if len(nonce) == 12:
        return nonce + b"\x00\x00\x00\x01"
    # General case: GHASH(nonce padded || 0^64 || [len(nonce)*8]_64).
    padded = bytes(nonce)
    if len(padded) % 16 != 0:
        padded += b"\x00" * (16 - len(padded) % 16)
    padded += struct.pack(">QQ", 0, len(nonce) * 8)
    return _ghash(h, padded).to_bytes(16, "big")


def _gcm_ctr(data, w, nr, j0):
    # GCM counter: only the low 32 bits increment, starting at inc32(J0).
    base = int.from_bytes(j0, "big")
    out = bytearray()
    for i in range(0, len(data), 16):
        counter = (base & ~0xFFFFFFFF) | (((base & 0xFFFFFFFF) + 1 + (i // 16)) & 0xFFFFFFFF)
        ks = _encrypt_block(counter.to_bytes(16, "big"), w, nr)
        chunk = data[i:i + 16]
        out += _xor_bytes(chunk, ks[:len(chunk)])
    return bytes(out)


def _aes_gcm(data, w, nr, nonce, op, tag):
    if len(nonce) == 0:
        raise ValueError("AES-GCM needs a nonce (12 bytes recommended)")
    h = int.from_bytes(_encrypt_block(b"\x00" * 16, w, nr), "big")
    j0 = _gcm_j0(h, nonce)
    e_j0 = _encrypt_block(j0, w, nr)

    def compute_tag(ciphertext):
        lenc = len(ciphertext)
        padded = bytes(ciphertext)
        if lenc % 16 != 0:
            padded += b"\x00" * (16 - lenc % 16)
        padded += struct.pack(">QQ", 0, lenc * 8)  # AAD length 0, ciphertext bit length
        s = _ghash(h, padded)
        return _xor_bytes(s.to_bytes(16, "big"), e_j0)

    if op == "encrypt":
        ciphertext = _gcm_ctr(data, w, nr, j0)
        return ciphertext + compute_tag(ciphertext)

    # decrypt: tag supplied separately, or appended to the data.
    if tag:
        if len(tag) != 16:
            raise ValueError("AES-GCM tag must be 16 bytes")
        ciphertext = data
        want = tag
    else:
        if len(data) < 16:
            raise ValueError("AES-GCM decrypt needs ciphertext followed by a 16-byte tag")
        ciphertext = data[:-16]
        want = data[-16:]
    expected = compute_tag(ciphertext)
    if not hmac.compare_digest(expected, want):
        raise ValueError("AES-GCM authentication failed: tag mismatch")
    return _gcm_ctr(ciphertext, w, nr, j0)


# --------------------------------------------------------------------------- #
# Public AES entry point.
# --------------------------------------------------------------------------- #

def aes(data, key, mode, iv=b"", nonce=b"", op="decrypt", unpad="pkcs7", tag=b""):
    """AES-128/192/256 in ECB, CBC, CTR, or GCM.

    key must be 16/24/32 bytes. mode is ecb|cbc|ctr|gcm. op is decrypt|encrypt.
    unpad is pkcs7|none and applies to ECB/CBC only. CBC needs a 16-byte iv;
    CTR/GCM need a nonce (GCM: 12 bytes recommended). For GCM decrypt the 16-byte
    tag is verified (supplied via ``tag`` or appended to ``data``); GCM encrypt
    returns ciphertext || tag. Raises ValueError on bad input.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("data must be bytes")
    data = bytes(data)
    key = bytes(key)
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes, got %d" % len(key))
    mode = mode.lower()
    if op not in ("encrypt", "decrypt"):
        raise ValueError("op must be 'encrypt' or 'decrypt'")
    if unpad not in ("pkcs7", "none"):
        raise ValueError("unpad must be 'pkcs7' or 'none'")

    if mode in ("ecb", "cbc"):
        w, dw, nr = _aes_key_schedule(key)
        if mode == "ecb":
            return _aes_ecb(data, w, dw, nr, op, unpad)
        return _aes_cbc(data, w, dw, nr, bytes(iv), op, unpad)
    if mode == "ctr":
        w, _dw, nr = _aes_key_schedule(key)
        return _aes_ctr(data, w, nr, bytes(nonce))
    if mode == "gcm":
        if "aes-gcm" not in AVAILABLE:
            raise ValueError("AES-GCM is not available in this build")
        w, _dw, nr = _aes_key_schedule(key)
        return _aes_gcm(data, w, nr, bytes(nonce), op, bytes(tag))
    raise ValueError("unknown AES mode %r (use ecb|cbc|ctr|gcm)" % mode)


# --------------------------------------------------------------------------- #
# ChaCha20 (RFC 8439).
# --------------------------------------------------------------------------- #

_CHACHA_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _chacha_block(key_words, counter, nonce_words):
    s = [
        _CHACHA_CONST[0], _CHACHA_CONST[1], _CHACHA_CONST[2], _CHACHA_CONST[3],
        key_words[0], key_words[1], key_words[2], key_words[3],
        key_words[4], key_words[5], key_words[6], key_words[7],
        counter & 0xFFFFFFFF, nonce_words[0], nonce_words[1], nonce_words[2],
    ]
    x = s[:]

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl32(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl32(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl32(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl32(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    out = [(x[i] + s[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20(data, key, nonce, counter=1):
    """RFC 8439 ChaCha20 keystream XOR (encrypt and decrypt are identical).

    key is 32 bytes, nonce is 12 bytes, counter is the 32-bit initial block
    counter (RFC 8439 §2.4.2 uses 1). Raises ValueError on a bad length.
    """
    data = bytes(data)
    key = bytes(key)
    nonce = bytes(nonce)
    if len(key) != 32:
        raise ValueError("ChaCha20 key must be 32 bytes, got %d" % len(key))
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonce must be 12 bytes, got %d" % len(nonce))
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)
    out = bytearray()
    ctr = counter & 0xFFFFFFFF
    for i in range(0, len(data), 64):
        ks = _chacha_block(key_words, ctr, nonce_words)
        chunk = data[i:i + 64]
        out += _xor_bytes(chunk, ks[:len(chunk)])
        ctr = (ctr + 1) & 0xFFFFFFFF
    return bytes(out)


# --------------------------------------------------------------------------- #
# RC4.
# --------------------------------------------------------------------------- #

def rc4(data, key):
    """Standard RC4 (encrypt and decrypt are identical). key: 1..256 bytes."""
    data = bytes(data)
    key = bytes(key)
    if not 1 <= len(key) <= 256:
        raise ValueError("RC4 key must be 1..256 bytes, got %d" % len(key))
    s = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + s[i] + key[i % klen]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


# --------------------------------------------------------------------------- #
# DES and 3DES (FIPS-46). Pure Python, used for legacy blobs.
# --------------------------------------------------------------------------- #

_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_SBOXES = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _permute(bits, table):
    return [bits[i - 1] for i in table]


def _bytes_to_bits(b):
    out = []
    for byte in b:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def _bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def _des_subkeys(key):
    bits = _bytes_to_bits(key)
    key56 = _permute(bits, _PC1)
    c, d = key56[:28], key56[28:]
    subkeys = []
    for shift in _SHIFTS:
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        subkeys.append(_permute(c + d, _PC2))
    return subkeys


def _des_feistel(right, subkey):
    expanded = _permute(right, _E)
    xored = [a ^ b for a, b in zip(expanded, subkey)]
    out = []
    for i in range(8):
        chunk = xored[i * 6:i * 6 + 6]
        row = (chunk[0] << 1) | chunk[5]
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        val = _SBOXES[i][row * 16 + col]
        out.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
    return _permute(out, _P)


def _des_block(block8, subkeys):
    bits = _permute(_bytes_to_bits(block8), _IP)
    left, right = bits[:32], bits[32:]
    for sk in subkeys:
        new_right = [a ^ b for a, b in zip(left, _des_feistel(right, sk))]
        left, right = right, new_right
    return _bits_to_bytes(_permute(right + left, _FP))


def _des_run(data, subkeys, mode, iv, op):
    if len(data) % 8 != 0:
        raise ValueError("DES data must be a multiple of 8 bytes")
    mode = mode.lower()
    if mode == "ecb":
        out = bytearray()
        for i in range(0, len(data), 8):
            out += _des_block(data[i:i + 8], subkeys)
        return bytes(out)
    if mode == "cbc":
        if len(iv) != 8:
            raise ValueError("DES-CBC needs an 8-byte iv")
        out = bytearray()
        if op == "encrypt":
            prev = iv
            for i in range(0, len(data), 8):
                prev = _des_block(_xor_bytes(data[i:i + 8], prev), subkeys)
                out += prev
        else:
            prev = iv
            for i in range(0, len(data), 8):
                block = data[i:i + 8]
                out += _xor_bytes(_des_block(block, subkeys), prev)
                prev = block
        return bytes(out)
    raise ValueError("unknown DES mode %r (use ecb|cbc)" % mode)


def des(data, key, mode="ecb", iv=b"", op="decrypt"):
    """Single DES in ECB or CBC (no padding; data must be a multiple of 8).

    key is 8 bytes (the low bit of each byte is an ignored parity bit). op is
    decrypt|encrypt; CBC needs an 8-byte iv. Raises ValueError on bad input.
    """
    data = bytes(data)
    key = bytes(key)
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes, got %d" % len(key))
    if op not in ("encrypt", "decrypt"):
        raise ValueError("op must be 'encrypt' or 'decrypt'")
    subkeys = _des_subkeys(key)
    if op == "decrypt":
        subkeys = subkeys[::-1]
    return _des_run(data, subkeys, mode, bytes(iv), op)


def triple_des(data, key, mode="ecb", iv=b"", op="decrypt"):
    """Triple DES (EDE) in ECB or CBC. key is 16 bytes (K1K2, K3=K1) or 24
    bytes (K1K2K3). op is decrypt|encrypt; CBC needs an 8-byte iv.

    Encryption is E_K3(D_K2(E_K1(x))); decryption reverses it. CBC chains over
    the whole 3DES block, matching OpenSSL / common toolchains.
    """
    data = bytes(data)
    key = bytes(key)
    if len(key) == 16:
        k1, k2, k3 = key[:8], key[8:16], key[:8]
    elif len(key) == 24:
        k1, k2, k3 = key[:8], key[8:16], key[16:24]
    else:
        raise ValueError("3DES key must be 16 or 24 bytes, got %d" % len(key))
    if op not in ("encrypt", "decrypt"):
        raise ValueError("op must be 'encrypt' or 'decrypt'")
    if len(data) % 8 != 0:
        raise ValueError("3DES data must be a multiple of 8 bytes")

    sk1 = _des_subkeys(k1)
    sk2 = _des_subkeys(k2)
    sk3 = _des_subkeys(k3)
    sk1r, sk2r, sk3r = sk1[::-1], sk2[::-1], sk3[::-1]

    if op == "encrypt":
        def transform(block):
            return _des_block(_des_block(_des_block(block, sk1), sk2r), sk3)
    else:
        def transform(block):
            return _des_block(_des_block(_des_block(block, sk3r), sk2), sk1r)

    mode = mode.lower()
    if mode == "ecb":
        out = bytearray()
        for i in range(0, len(data), 8):
            out += transform(data[i:i + 8])
        return bytes(out)
    if mode == "cbc":
        if len(iv) != 8:
            raise ValueError("3DES-CBC needs an 8-byte iv")
        out = bytearray()
        if op == "encrypt":
            prev = iv
            for i in range(0, len(data), 8):
                prev = transform(_xor_bytes(data[i:i + 8], prev))
                out += prev
        else:
            prev = iv
            for i in range(0, len(data), 8):
                block = data[i:i + 8]
                out += _xor_bytes(transform(block), prev)
                prev = block
        return bytes(out)
    raise ValueError("unknown 3DES mode %r (use ecb|cbc)" % mode)


# --------------------------------------------------------------------------- #
# What this build provides. Verified against public vectors in tests.
# --------------------------------------------------------------------------- #

AVAILABLE = {"aes", "aes-gcm", "chacha20", "rc4", "des", "3des"}
