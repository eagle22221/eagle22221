"""Correctness tests for vex.crypto, anchored to public test vectors.

Vectors used (each named in its test):
  - NIST FIPS-197 Appendix B/C: AES-128/192/256 single-block examples.
  - NIST SP 800-38A Appendix F: AES-128 and AES-256 ECB / CBC / CTR vectors.
  - NIST SP 800-38D / McGrew-Viega: AES-GCM Test Cases 1, 2, 3, 14 (+ tag).
  - RFC 8439 §2.3.2 and §2.4.2: ChaCha20 keystream block and the sunscreen text.
  - Standard RC4 vectors (Wikipedia Key/Plaintext, Wiki/pedia, Secret/Attack)
    and RFC 6229 (key 0102030405).
  - FIPS-46 DES worked example and the all-zero DES known answer; 3DES is
    anchored to the NIST-verified DES primitive (EDE with equal keys == DES).

These assert against the published constants, never against the module's own
output, except the explicit encrypt/decrypt round-trip tests.
"""

import os

import pytest

from vex import crypto


def hx(s):
    return bytes.fromhex(s)


# --------------------------------------------------------------------------- #
# AVAILABLE
# --------------------------------------------------------------------------- #

def test_available_is_subset_of_spec():
    allowed = {"aes", "aes-gcm", "chacha20", "rc4", "des", "3des"}
    assert crypto.AVAILABLE <= allowed
    # Core primitives this build commits to.
    assert {"aes", "chacha20", "rc4"} <= crypto.AVAILABLE


# --------------------------------------------------------------------------- #
# AES single-block (FIPS-197)
# --------------------------------------------------------------------------- #

FIPS197_PT = hx("00112233445566778899aabbccddeeff")


@pytest.mark.parametrize("key, ct", [
    # FIPS-197 Appendix B / C.1, C.2, C.3
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
])
def test_aes_fips197_block(key, ct):
    # Exercise through the public ECB interface (one block, no padding).
    assert crypto.aes(FIPS197_PT, hx(key), "ecb", op="encrypt", unpad="none") == hx(ct)
    assert crypto.aes(hx(ct), hx(key), "ecb", op="decrypt", unpad="none") == FIPS197_PT


# --------------------------------------------------------------------------- #
# AES mode vectors (NIST SP 800-38A Appendix F)
# --------------------------------------------------------------------------- #

SP38A_PT = hx(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
K128 = hx("2b7e151628aed2a6abf7158809cf4f3c")
K256 = hx("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
CBC_IV = hx("000102030405060708090a0b0c0d0e0f")
CTR_IV = hx("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")


def test_aes128_ecb_vector():
    ct = hx(
        "3ad77bb40d7a3660a89ecaf32466ef97"
        "f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed030688"
        "7b0c785e27e8ad3f8223207104725dd4"
    )
    assert crypto.aes(SP38A_PT, K128, "ecb", op="encrypt", unpad="none") == ct
    assert crypto.aes(ct, K128, "ecb", op="decrypt", unpad="none") == SP38A_PT


def test_aes256_ecb_vector():
    ct = hx(
        "f3eed1bdb5d2a03c064b5a7e3db181f8"
        "591ccb10d410ed26dc5ba74a31362870"
        "b6ed21b99ca6f4f9f153e7b1beafed1d"
        "23304b7a39f9f3ff067d8d8f9e24ecc7"
    )
    assert crypto.aes(SP38A_PT, K256, "ecb", op="encrypt", unpad="none") == ct
    assert crypto.aes(ct, K256, "ecb", op="decrypt", unpad="none") == SP38A_PT


def test_aes128_cbc_vector():
    ct = hx(
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"
    )
    assert crypto.aes(SP38A_PT, K128, "cbc", iv=CBC_IV, op="encrypt", unpad="none") == ct
    assert crypto.aes(ct, K128, "cbc", iv=CBC_IV, op="decrypt", unpad="none") == SP38A_PT


def test_aes256_cbc_vector():
    ct = hx(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
        "9cfc4e967edb808d679f777bc6702c7d"
        "39f23369a9d9bacfa530e26304231461"
        "b2eb05e2c39be9fcda6c19078c6a9d1b"
    )
    assert crypto.aes(SP38A_PT, K256, "cbc", iv=CBC_IV, op="encrypt", unpad="none") == ct
    assert crypto.aes(ct, K256, "cbc", iv=CBC_IV, op="decrypt", unpad="none") == SP38A_PT


def test_aes128_ctr_vector():
    ct = hx(
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"
    )
    assert crypto.aes(SP38A_PT, K128, "ctr", nonce=CTR_IV, op="encrypt") == ct
    # CTR is symmetric: decrypt recovers the plaintext.
    assert crypto.aes(ct, K128, "ctr", nonce=CTR_IV, op="decrypt") == SP38A_PT


def test_aes256_ctr_vector():
    ct = hx(
        "601ec313775789a5b7a7f504bbf3d228"
        "f443e3ca4d62b59aca84e990cacaf5c5"
        "2b0930daa23de94ce87017ba2d84988d"
        "dfc9c58db67aada613c2dd08457941a6"
    )
    assert crypto.aes(SP38A_PT, K256, "ctr", nonce=CTR_IV, op="encrypt") == ct
    assert crypto.aes(ct, K256, "ctr", nonce=CTR_IV, op="decrypt") == SP38A_PT


# --------------------------------------------------------------------------- #
# AES-GCM (NIST SP 800-38D / McGrew-Viega test cases), only if available
# --------------------------------------------------------------------------- #

gcm_only = pytest.mark.skipif("aes-gcm" not in crypto.AVAILABLE, reason="GCM not built")


@gcm_only
def test_gcm_case1_empty():
    # Test Case 1: zero key, zero IV, empty plaintext -> tag only.
    out = crypto.aes(b"", bytes(16), "gcm", nonce=bytes(12), op="encrypt")
    assert out == hx("58e2fccefa7e3061367f1d57a4e7455a")


@gcm_only
def test_gcm_case2_one_block():
    # Test Case 2: zero key, zero IV, 16 zero bytes.
    out = crypto.aes(bytes(16), bytes(16), "gcm", nonce=bytes(12), op="encrypt")
    assert out[:16] == hx("0388dace60b6a392f328c2b971b2fe78")
    assert out[16:] == hx("ab6e47d42cec13bdf53a67b21257bddf")


@gcm_only
def test_gcm_case3_aes128_tag_and_roundtrip():
    key = hx("feffe9928665731c6d6a8f9467308308")
    iv = hx("cafebabefacedbaddecaf888")
    pt = hx(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
    )
    ct = hx(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
    )
    tag = hx("4d5c2af327cd64a62cf35abd2ba6fab4")
    out = crypto.aes(pt, key, "gcm", nonce=iv, op="encrypt")
    assert out[:64] == ct
    assert out[64:] == tag
    # Decrypt with the tag supplied separately...
    assert crypto.aes(ct, key, "gcm", nonce=iv, op="decrypt", tag=tag) == pt
    # ...or appended to the ciphertext.
    assert crypto.aes(ct + tag, key, "gcm", nonce=iv, op="decrypt") == pt


@gcm_only
def test_gcm_case14_aes256():
    out = crypto.aes(bytes(16), bytes(32), "gcm", nonce=bytes(12), op="encrypt")
    assert out[:16] == hx("cea7403d4d606b6e074ec5d3baf39d18")
    assert out[16:] == hx("d0d1c8a799996bf0265b98b5d48ab919")


@gcm_only
def test_gcm_tag_mismatch_raises():
    key = hx("feffe9928665731c6d6a8f9467308308")
    iv = hx("cafebabefacedbaddecaf888")
    ct = hx("42831ec2217774244b7221b784d0d49c")
    with pytest.raises(ValueError, match="tag"):
        crypto.aes(ct, key, "gcm", nonce=iv, op="decrypt", tag=bytes(16))
    # A single flipped ciphertext bit must also fail authentication.
    pt = hx("00000000000000000000000000000000")
    good = crypto.aes(pt, key, "gcm", nonce=iv, op="encrypt")
    tampered = bytearray(good)
    tampered[0] ^= 1
    with pytest.raises(ValueError, match="tag"):
        crypto.aes(bytes(tampered), key, "gcm", nonce=iv, op="decrypt")


# --------------------------------------------------------------------------- #
# PKCS#7 padding behaviour
# --------------------------------------------------------------------------- #

def test_pkcs7_adds_and_strips_ecb():
    key = bytes(16)
    for n in range(0, 40):
        data = bytes(range(n % 256 if n else 1))[:n]
        enc = crypto.aes(data, key, "ecb", op="encrypt", unpad="pkcs7")
        assert len(enc) % 16 == 0
        assert len(enc) > len(data)  # padding always adds at least one byte
        assert crypto.aes(enc, key, "ecb", op="decrypt", unpad="pkcs7") == data


def test_pkcs7_full_block_added_when_aligned():
    key = bytes(16)
    data = bytes(16)
    enc = crypto.aes(data, key, "ecb", op="encrypt", unpad="pkcs7")
    assert len(enc) == 32  # a whole extra block of padding
    assert crypto.aes(enc, key, "ecb", op="decrypt", unpad="pkcs7") == data


def test_pkcs7_bad_padding_raises():
    key = bytes(16)
    # Decrypt a block that, once decrypted, has invalid trailing padding.
    garbage = crypto.aes(bytes(16), key, "ecb", op="encrypt", unpad="none")
    with pytest.raises(ValueError, match="padding"):
        crypto.aes(garbage, key, "ecb", op="decrypt", unpad="pkcs7")


def test_unpad_none_requires_block_multiple_on_encrypt():
    with pytest.raises(ValueError):
        crypto.aes(b"short", bytes(16), "ecb", op="encrypt", unpad="none")


# --------------------------------------------------------------------------- #
# AES round-trips on random data for every mode
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("keylen", [16, 24, 32])
@pytest.mark.parametrize("mode,kwargs", [
    ("ecb", {}),
    ("cbc", {"iv": os.urandom(16)}),
    ("ctr", {"nonce": os.urandom(16)}),
])
def test_aes_roundtrip_random(keylen, mode, kwargs):
    key = os.urandom(keylen)
    data = os.urandom(200)  # not a block multiple, exercises padding for ecb/cbc
    enc = crypto.aes(data, key, mode, op="encrypt", **kwargs)
    dec = crypto.aes(enc, key, mode, op="decrypt", **kwargs)
    assert dec == data


@gcm_only
@pytest.mark.parametrize("keylen", [16, 24, 32])
def test_aes_gcm_roundtrip_random(keylen):
    key = os.urandom(keylen)
    nonce = os.urandom(12)
    data = os.urandom(173)
    enc = crypto.aes(data, key, "gcm", nonce=nonce, op="encrypt")
    assert crypto.aes(enc, key, "gcm", nonce=nonce, op="decrypt") == data


# --------------------------------------------------------------------------- #
# AES input validation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("keylen", [0, 8, 15, 17, 20, 31, 33, 64])
def test_aes_bad_key_length_raises(keylen):
    with pytest.raises(ValueError, match="key"):
        crypto.aes(bytes(16), bytes(keylen), "ecb", op="encrypt", unpad="none")


@pytest.mark.parametrize("ivlen", [0, 8, 15, 17, 32])
def test_aes_cbc_bad_iv_raises(ivlen):
    with pytest.raises(ValueError, match="iv"):
        crypto.aes(bytes(16), bytes(16), "cbc", iv=bytes(ivlen), op="encrypt", unpad="none")


def test_aes_unknown_mode_raises():
    with pytest.raises(ValueError, match="mode"):
        crypto.aes(bytes(16), bytes(16), "ofb", op="encrypt")


def test_aes_bad_op_raises():
    with pytest.raises(ValueError, match="op"):
        crypto.aes(bytes(16), bytes(16), "ecb", op="sign")


def test_aes_ecb_decrypt_non_block_multiple_raises():
    with pytest.raises(ValueError, match="multiple of 16"):
        crypto.aes(bytes(20), bytes(16), "ecb", op="decrypt", unpad="none")


# --------------------------------------------------------------------------- #
# ChaCha20 (RFC 8439)
# --------------------------------------------------------------------------- #

def test_chacha20_rfc8439_2_4_2():
    key = bytes(range(32))
    nonce = hx("000000000000004a00000000")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    ct = hx(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d"
    )
    assert crypto.chacha20(pt, key, nonce, counter=1) == ct
    # Self-inverse: running the ciphertext back through yields the plaintext.
    assert crypto.chacha20(ct, key, nonce, counter=1) == pt


def test_chacha20_roundtrip_random():
    key = os.urandom(32)
    nonce = os.urandom(12)
    data = os.urandom(1000)
    assert crypto.chacha20(crypto.chacha20(data, key, nonce), key, nonce) == data


def test_chacha20_bad_key_length_raises():
    with pytest.raises(ValueError, match="key"):
        crypto.chacha20(b"x", bytes(16), bytes(12))


def test_chacha20_bad_nonce_length_raises():
    with pytest.raises(ValueError, match="nonce"):
        crypto.chacha20(b"x", bytes(32), bytes(8))


# --------------------------------------------------------------------------- #
# RC4
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("key, pt, ct", [
    (b"Key", b"Plaintext", "bbf316e8d940af0ad3"),
    (b"Wiki", b"pedia", "1021bf0420"),
    (b"Secret", b"Attack at dawn", "45a01f645fc35b383552544b9bf5"),
])
def test_rc4_known_vectors(key, pt, ct):
    assert crypto.rc4(pt, key) == hx(ct)
    assert crypto.rc4(hx(ct), key) == pt  # self-inverse


def test_rc4_rfc6229_keystream():
    # RFC 6229, key 0102030405: first 16 keystream bytes = RC4 of 16 zero bytes.
    ks = crypto.rc4(bytes(16), hx("0102030405"))
    assert ks == hx("b2396305f03dc027ccc3524a0a1118a8")


def test_rc4_bad_key_length_raises():
    with pytest.raises(ValueError, match="key"):
        crypto.rc4(b"data", b"")


# --------------------------------------------------------------------------- #
# DES / 3DES (optional; only if built)
# --------------------------------------------------------------------------- #

des_only = pytest.mark.skipif("des" not in crypto.AVAILABLE, reason="DES not built")
des3_only = pytest.mark.skipif("3des" not in crypto.AVAILABLE, reason="3DES not built")


@des_only
def test_des_fips46_worked_example():
    # The classic FIPS-46 worked example.
    key = hx("133457799bbcdff1")
    pt = hx("0123456789abcdef")
    ct = hx("85e813540f0ab405")
    assert crypto.des(pt, key, op="encrypt") == ct
    assert crypto.des(ct, key, op="decrypt") == pt


@des_only
def test_des_all_zero_known_answer():
    # Well-known: DES(key=0, plaintext=0) = 8ca64de9c1b123a7.
    assert crypto.des(bytes(8), bytes(8), op="encrypt") == hx("8ca64de9c1b123a7")


@des_only
def test_des_cbc_roundtrip():
    key = os.urandom(8)
    iv = os.urandom(8)
    data = os.urandom(64)
    enc = crypto.des(data, key, mode="cbc", iv=iv, op="encrypt")
    assert crypto.des(enc, key, mode="cbc", iv=iv, op="decrypt") == data


@des_only
def test_des_bad_key_length_raises():
    with pytest.raises(ValueError, match="key"):
        crypto.des(bytes(8), bytes(7), op="encrypt")


@des_only
def test_des_non_block_multiple_raises():
    with pytest.raises(ValueError, match="multiple of 8"):
        crypto.des(bytes(5), bytes(8), op="encrypt")


@des3_only
def test_3des_equal_keys_matches_single_des():
    # EDE with K1=K2=K3 reduces to single DES; anchors 3DES to the NIST-verified
    # DES primitive above.
    key8 = hx("133457799bbcdff1")
    pt = hx("0123456789abcdef")
    assert crypto.triple_des(pt, key8 * 3, op="encrypt") == crypto.des(pt, key8, op="encrypt")


@des3_only
@pytest.mark.parametrize("keylen", [16, 24])
@pytest.mark.parametrize("mode,kwargs", [("ecb", {}), ("cbc", {"iv": os.urandom(8)})])
def test_3des_roundtrip(keylen, mode, kwargs):
    key = os.urandom(keylen)
    data = os.urandom(64)
    enc = crypto.triple_des(data, key, mode=mode, op="encrypt", **kwargs)
    assert crypto.triple_des(enc, key, mode=mode, op="decrypt", **kwargs) == data


@des3_only
def test_3des_bad_key_length_raises():
    with pytest.raises(ValueError, match="key"):
        crypto.triple_des(bytes(8), bytes(8), op="encrypt")
