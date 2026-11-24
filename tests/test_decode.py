"""The decode & cipher workbench: operations, the pipeline engine, solvers,
the output cap and bomb guards, the CLI `decode` subcommand and the HTTP API.

Expected values are derived with Python's own stdlib (base64/zlib/...), never
with the code under test, so the tests pin behaviour independently.
"""
import base64
import binascii
import bz2
import gzip
import json
import lzma
import os
import quopri
import urllib.parse
import zlib
from urllib.parse import quote

import pytest

from vex import decode
from vex.cli import main
from vex.errors import DecodeError
from conftest import fixture_bytes, fixture_path

try:
    from vex import crypto as _crypto
except ImportError:
    _crypto = None


def _has(name: str) -> bool:
    return _crypto is not None and name in getattr(_crypto, "AVAILABLE", set())


def op(name, data, **params):
    return decode.apply_op(name, params, data)


def run(data, recipe):
    return decode.run(lambda: data, recipe)


# --- encodings round-trip against the stdlib --------------------------------

def test_from_base64_matches_stdlib():
    raw = b"the quick brown fox\x00\x01\x02"
    assert op("from-base64", base64.b64encode(raw)) == raw
    # padding is optional
    assert op("from-base64", base64.b64encode(raw).rstrip(b"=")) == raw


def test_to_base64_matches_stdlib():
    raw = b"\x00\xff\x10hello"
    assert op("to-base64", raw) == base64.b64encode(raw)
    assert op("to-base64", raw, alphabet="url") == base64.urlsafe_b64encode(raw)
    assert op("from-base64", base64.urlsafe_b64encode(raw), alphabet="url") == raw


def test_invalid_base64_is_a_decode_error():
    with pytest.raises(DecodeError):
        op("from-base64", b"not valid base64 !!!!@@@@")


def test_base32_round_trips_against_stdlib():
    raw = b"base32 sample \x80\x81"
    assert op("to-base32", raw) == base64.b32encode(raw)
    assert op("from-base32", base64.b32encode(raw)) == raw


def test_hex_round_trips_and_is_lenient():
    raw = bytes(range(10))
    assert op("to-hex", raw) == binascii.hexlify(raw)
    assert op("from-hex", b"00 01 02 03\n04:05,06 0x07 08 09") == raw
    with pytest.raises(DecodeError):
        op("from-hex", b"abc")          # odd length
    with pytest.raises(DecodeError):
        op("from-hex", b"zz")           # non-hex


def test_base85_round_trips_against_stdlib():
    raw = b"base85 sample data 1234"
    assert op("to-base85", raw) == base64.a85encode(raw)
    assert op("from-base85", base64.a85encode(raw)) == raw
    z = base64.z85encode(raw)           # length already a multiple of 4
    assert op("to-base85", raw, variant="z85") == z
    assert op("from-base85", z, variant="z85") == raw


def test_url_and_quoted_printable_match_stdlib():
    raw = b"a b+c/d?e=\xe2\x98\x83"
    assert op("url-encode", raw) == urllib.parse.quote_from_bytes(raw, safe="").encode()
    assert op("url-decode", urllib.parse.quote_from_bytes(raw, safe="").encode()) == raw
    qp = quopri.encodestring(raw)
    assert op("qp-decode", qp) == raw


def test_rot13_reverse_and_charset():
    assert op("rot13", b"Hello, World!") == b"Uryyb, Jbeyq!"
    assert op("rot13", op("rot13", b"abc")) == b"abc"       # self-inverse
    assert op("reverse", b"abcd") == b"dcba"
    utf16 = "héllo".encode("utf-16le")
    assert op("charset-decode", utf16, **{"from": "utf-16le"}) == "héllo".encode("utf-8")


# --- decompress on real stdlib blobs + the bomb guard -----------------------

def test_zlib_and_raw_inflate():
    raw = b"inflate me " * 1000
    assert op("zlib-inflate", zlib.compress(raw)) == raw
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    rawdeflate = co.compress(raw) + co.flush()
    assert op("raw-inflate", rawdeflate) == raw


def test_gunzip_bunzip2_unxz():
    raw = b"compress me please " * 500
    assert op("gunzip", gzip.compress(raw)) == raw
    assert op("bunzip2", bz2.compress(raw)) == raw
    assert op("unxz", lzma.compress(raw, format=lzma.FORMAT_XZ)) == raw


def _zero_bomb(make):
    """A tiny compressed blob that would inflate past the 64 MiB cap, built a
    megabyte at a time so the test never holds the expanded form in memory."""
    return make()


def test_decompression_bomb_is_refused_quickly():
    # ~70 MiB of zeros, compressed one MiB at a time (never materialised whole).
    co = zlib.compressobj()
    parts = []
    for _ in range(70):
        parts.append(co.compress(b"\x00" * (1 << 20)))
    parts.append(co.flush())
    bomb = b"".join(parts)
    assert len(bomb) < (1 << 20)        # the compressed form really is tiny
    with pytest.raises(DecodeError) as exc:
        op("zlib-inflate", bomb)
    assert "too large" in str(exc.value)

    # gzip, bz2 and xz bombs are guarded the same way.
    gz = gzip.compress(b"\x00" * (70 << 20))
    with pytest.raises(DecodeError):
        op("gunzip", gz)


# --- classic ciphers against known vectors ----------------------------------

def test_rot_n_and_atbash():
    assert op("rot-n", b"Hello", n=13) == b"Uryyb"
    assert op("rot-n", b"abc", n=1) == b"bcd"
    assert op("atbash", b"abc") == b"zyx"
    assert op("atbash", op("atbash", b"Attack")) == b"Attack"
    with pytest.raises(DecodeError):
        op("rot-n", b"x", n=99)


def test_vigenere_known_vector():
    # Classic ATTACKATDAWN / LEMON example.
    assert op("vigenere", b"ATTACKATDAWN", key="LEMON", mode="encrypt") == b"LXFOPVEFRNHR"
    assert op("vigenere", b"LXFOPVEFRNHR", key="LEMON", mode="decrypt") == b"ATTACKATDAWN"


def test_repeating_xor_known_vector():
    # cryptopals set 1 challenge 5.
    plain = (b"Burning 'em, if you ain't quick and nimble\n"
             b"I go crazy when I hear a cymbal")
    expected = bytes.fromhex(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324"
        "272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165"
        "286326302e27282f")
    assert op("xor", plain, key="494345") == expected          # "ICE"
    assert op("xor", plain, key_text="ICE") == expected
    assert op("xor", expected, key_text="ICE") == plain        # self-inverse
    with pytest.raises(DecodeError):
        op("xor", plain)                                       # no key given


def test_railfence_known_vector():
    plain = b"WEAREDISCOVEREDFLEEATONCE"
    cipher = b"WECRLTEERDSOEEFEAOCAIVDEN"
    assert op("railfence", plain, rails=3, mode="encrypt") == cipher
    assert op("railfence", cipher, rails=3, mode="decrypt") == plain


def test_substitution_decrypts_with_a_map():
    import string
    # map plain A..Z -> a Caesar-by-3 cipher alphabet, encipher, then decrypt.
    cipher_alpha = (string.ascii_uppercase[3:] + string.ascii_uppercase[:3])
    table = {p: c for p, c in zip(string.ascii_uppercase, cipher_alpha)}
    plain = b"THEQUICKBROWNFOX"
    enc = bytes(ord(table[chr(b)]) for b in plain)
    assert op("substitution", enc, map=cipher_alpha) == plain


def test_hash_op():
    import hashlib
    raw = b"hash me"
    assert op("hash", raw, algo="md5") == hashlib.md5(raw).hexdigest().encode()
    assert op("hash", raw, algo="sha256") == hashlib.sha256(raw).hexdigest().encode()
    assert op("hash", raw, algo="crc32") == format(zlib.crc32(raw), "08x").encode()


# --- solvers ----------------------------------------------------------------

ENGLISH = (b"the quick brown fox jumps over the lazy dog while the sun is "
           b"shining and the birds are singing in the trees near the river")


def test_caesar_solver_ranks_the_true_shift_first():
    shift = 7
    cipher = op("rot-n", ENGLISH, n=shift)
    res = decode.solve("caesar", lambda: cipher)
    assert res["ok"]
    best = res["candidates"][0]
    # recovering means applying rot-n with n = (26 - shift) % 26
    assert best["params"]["n"] == (26 - shift) % 26
    assert best["text"] == ENGLISH.decode()
    assert 0.0 <= best["score"] <= 1.0


def test_xor_single_solver_ranks_the_true_key_first():
    key = 0x5a
    cipher = bytes(b ^ key for b in ENGLISH)
    res = decode.solve("xor-single", lambda: cipher)
    assert res["candidates"][0]["params"]["key"] == format(key, "02x")
    assert res["candidates"][0]["text"] == ENGLISH.decode()
    assert len(res["candidates"]) <= 20


def test_xor_keylen_solver_recovers_a_multibyte_key():
    base = ENGLISH * 4
    key = b"SECRET"
    cipher = bytes(c ^ key[i % len(key)] for i, c in enumerate(base))
    res = decode.solve("xor-keylen", lambda: cipher)
    assert res["candidates"][0]["params"]["key"] == key.hex()
    assert res["candidates"][0]["text"].startswith(ENGLISH.decode()[:20])


def test_substitution_solver_is_best_effort_and_safe():
    res = decode.solve("substitution", lambda: ENGLISH * 6)
    assert res["ok"] and res["candidates"]
    assert "map" in res["candidates"][0]["params"]


def test_solvers_never_raise_on_random_bytes():
    blob = os.urandom(512)
    for name in ("caesar", "xor-single", "xor-keylen", "substitution"):
        res = decode.solve(name, lambda: blob)
        assert res["ok"] and isinstance(res["candidates"], list)
    # empty and tiny inputs are safe too
    for name in ("caesar", "xor-single", "xor-keylen", "substitution"):
        assert decode.solve(name, lambda: b"")["ok"]
        assert decode.solve(name, lambda: b"a")["ok"]


def test_solve_reports_a_bad_source_without_raising():
    res = decode.solve("caesar", lambda: (_ for _ in ()).throw(DecodeError("bad")))
    assert res["ok"] is False and res["candidates"] == [] and res["error"]


def test_unknown_solver_errors():
    res = decode.solve("nope", lambda: b"x")
    assert res["ok"] is False and "nope" in res["error"]


# --- looks_like magic guess -------------------------------------------------

def test_looks_like():
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    assert decode.looks_like(png) == "PNG image"
    assert decode.looks_like(gzip.compress(b"x")) == "gzip"
    assert decode.looks_like(fixture_bytes("hello_pe64.exe")) == "PE program"
    assert decode.looks_like(b"just some plain readable text\n") == "printable text"
    assert decode.looks_like(bytes([0, 1, 2, 3, 255, 254, 7, 8])) == "binary"
    assert decode.looks_like(fixture_bytes("hello_elf64")) == "ELF program"


# --- the pipeline engine ----------------------------------------------------

def test_recipe_chains_left_to_right():
    plain = b"secret payload inside a gzip inside base64" * 10
    key = b"KEY!"
    xored = bytes(c ^ key[i % len(key)] for i, c in enumerate(plain))
    blob = base64.b64encode(gzip.compress(xored))
    result = run(blob, [("from-base64", {}), ("gunzip", {}),
                        ("xor", {"key_text": "KEY!"})])
    assert result["ok"] is True
    assert result["text"] == plain.decode()
    assert [s["op"] for s in result["steps"]] == ["from-base64", "gunzip", "xor"]
    assert result["steps"][-1]["size"] == len(plain)


def test_failed_step_returns_ok_false_with_completed_steps():
    blob = base64.b64encode(b"this is not gzip data")
    result = run(blob, [("from-base64", {}), ("gunzip", {}),
                        ("to-hex", {})])
    assert result["ok"] is False
    assert [s["op"] for s in result["steps"]] == ["from-base64"]   # only the first ran
    assert result["error"]
    # the reported bytes are those of the last good step
    assert result["text"] == "this is not gzip data"


def test_result_object_shape():
    result = run(b"hi", [])
    assert set(result) == {"ok", "size", "hex", "text", "looks_like", "steps", "error"}
    assert result == {"ok": True, "size": 2, "hex": "6869", "text": "hi",
                      "looks_like": "printable text", "steps": [], "error": None}
    for step in run(b"x", [("to-hex", {})])["steps"]:
        assert set(step) == {"op", "size"}


def test_invalid_utf8_output_uses_replacement_character():
    result = run(b"\xff\xfe", [])
    assert result["text"] == "��" and result["hex"] == "fffe"


def test_output_cap_refuses_oversized_output():
    big = b"\x00" * (33 << 20)            # to-hex doubles it, past 64 MiB
    result = run(big, [("to-hex", {})])
    assert result["ok"] is False and "too large" in result["error"]


def test_source_bytes_bounded_to_file():
    data = bytes(range(256))
    assert decode.source_bytes("file", data=data, offset=10, length=4) == bytes(range(10, 14))
    # length past the end is clamped to the file
    assert decode.source_bytes("file", data=data, offset=250, length=999) == bytes(range(250, 256))
    assert decode.source_bytes("file", data=data, offset=1000) == b""


def test_source_bytes_kinds():
    assert decode.source_bytes("text", "hi") == b"hi"
    assert decode.source_bytes("hex", "48 69") == b"Hi"
    assert decode.source_bytes("base64", base64.b64encode(b"Hi").decode()) == b"Hi"


# --- recipe grammar ---------------------------------------------------------

def test_parse_recipe_grammar():
    assert decode.parse_recipe("") == []
    assert decode.parse_recipe("from-base64|gunzip") == [
        ("from-base64", {}), ("gunzip", {})]
    assert decode.parse_recipe("xor:key=ff | rot-n:n=3") == [
        ("xor", {"key": "ff"}), ("rot-n", {"n": "3"})]
    assert decode.parse_recipe("from-base64:alphabet=url") == [
        ("from-base64", {"alphabet": "url"})]


def test_parse_recipe_rejects_unknown_op_and_param():
    with pytest.raises(decode.RecipeError) as e:
        decode.parse_recipe("definitely-not-an-op")
    assert "definitely-not-an-op" in str(e.value)
    with pytest.raises(decode.RecipeError) as e:
        decode.parse_recipe("rot-n:bogus=1")
    assert "bogus" in str(e.value)
    with pytest.raises(decode.RecipeError):
        decode.parse_recipe("rot-n:n")        # malformed k=v


# --- the operation catalogue ------------------------------------------------

def test_ops_catalogue_shape():
    cat = decode.ops()
    assert set(cat) == {"groups", "solvers"}
    names = set()
    group_names = []
    for group in cat["groups"]:
        assert set(group) == {"name", "ops"}
        group_names.append(group["name"])
        for o in group["ops"]:
            assert set(o) >= {"name", "params", "summary", "available"}
            assert isinstance(o["available"], bool)
            for p in o["params"]:
                assert set(p) >= {"name", "required", "type"}
            names.add(o["name"])
    assert {"Encoding", "Decompress", "Classic cipher", "Symmetric", "Hash"} <= set(group_names)
    assert {"from-base64", "gunzip", "rot13", "xor", "aes", "hash"} <= names
    solver_names = {s["name"] for s in cat["solvers"]}
    assert solver_names == {"caesar", "xor-single", "xor-keylen", "substitution"}


def test_catalogue_marks_symmetric_availability_from_crypto():
    by_name = {o["name"]: o for g in decode.ops()["groups"] for o in g["ops"]}
    assert by_name["rc4"]["available"] == _has("rc4")
    assert by_name["aes"]["available"] == _has("aes")
    # non-symmetric ops are always available
    assert by_name["rot13"]["available"] is True


# --- symmetric ops (skip when crypto has not landed) ------------------------

def test_rc4_matches_crypto_or_reports_unavailable():
    data, key = b"attack at dawn", bytes.fromhex("0102030405")
    if _has("rc4"):
        expect = _crypto.rc4(data, key)
        assert op("rc4", data, key="0102030405") == expect
        assert op("rc4", expect, key="0102030405") == data
    else:
        with pytest.raises(DecodeError) as e:
            op("rc4", data, key="0102030405")
        assert "not available in this build" in str(e.value)


def test_chacha20_matches_crypto_or_reports_unavailable():
    data = b"nineteen byte message!!"
    key = bytes(range(32)).hex()
    nonce = bytes(range(12)).hex()
    if _has("chacha20"):
        expect = _crypto.chacha20(data, bytes.fromhex(key), bytes.fromhex(nonce), 1)
        assert op("chacha20", data, key=key, nonce=nonce) == expect
    else:
        with pytest.raises(DecodeError) as e:
            op("chacha20", data, key=key, nonce=nonce)
        assert "not available in this build" in str(e.value)


def test_aes_matches_crypto_or_reports_unavailable():
    key = (b"\x00" * 16).hex()
    block = b"\x11" * 16
    if _has("aes"):
        ct = _crypto.aes(block, bytes.fromhex(key), "ecb", op="encrypt", unpad="none")
        got = op("aes", ct, key=key, mode="ecb", op="decrypt", unpad="none")
        assert got == block
    else:
        with pytest.raises(DecodeError) as e:
            op("aes", block, key=key, mode="ecb", op="decrypt", unpad="none")
        assert "not available in this build" in str(e.value)


# --- CLI --------------------------------------------------------------------

def cli(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def cli_json(capsys, *args):
    code, out, err = cli(capsys, "--json", *args)
    assert code == 0, err
    return json.loads(out)


def test_cli_hex_source_default_view(capsys):
    code, out, _ = cli(capsys, "decode", "--hex", "48656c6c6f")
    assert code == 0
    assert "Hello" in out and "looks like" in out


def test_cli_positional_is_text(capsys):
    result = cli_json(capsys, "decode", "aGVsbG8=", "--recipe", "from-base64")
    assert result["text"] == "hello"


def test_cli_recipe_chain(capsys):
    blob = base64.b64encode(gzip.compress(b"chained!")).decode()
    result = cli_json(capsys, "decode", "--text", blob, "--recipe", "from-base64|gunzip")
    assert result["ok"] and result["text"] == "chained!"


def test_cli_unknown_op_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["decode", "--text", "x", "--recipe", "no-such-op"])
    assert exc.value.code == 2
    assert "no-such-op" in capsys.readouterr().err


def test_cli_unknown_param_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["decode", "--text", "x", "--recipe", "rot13:bad=1"])
    assert exc.value.code == 2


def test_cli_solve(capsys):
    cipher = op("xor", ENGLISH, key="2a").decode("latin-1")
    # pass as hex source so the raw bytes survive
    result = cli_json(capsys, "decode", "--hex", op("xor", ENGLISH, key="2a").hex(),
                      "--solve", "xor-single")
    assert result["ok"]
    assert result["candidates"][0]["params"]["key"] == "2a"


def test_cli_list(capsys):
    cat = cli_json(capsys, "decode", "--list")
    assert "groups" in cat and "solvers" in cat


def test_cli_out_writes_bytes_and_refuses_overwrite(capsys, tmp_path):
    dest = tmp_path / "out.bin"
    code, out, _ = cli(capsys, "decode", "--hex", "deadbeef", "--out", str(dest))
    assert code == 0 and dest.read_bytes() == bytes.fromhex("deadbeef")
    assert str(dest) in out
    # second time: refuse to overwrite
    code, _, err = cli(capsys, "decode", "--hex", "deadbeef", "--out", str(dest))
    assert code == 1 and "exists" in err


def test_cli_file_source_bounded(capsys, tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(bytes(range(64)))
    result = cli_json(capsys, "decode", "--file", str(f), "--offset", "8", "--length", "4")
    assert result["hex"] == bytes(range(8, 12)).hex()


# --- HTTP API (uses the shared client fixture from test_server) -------------

from test_server import client     # noqa: E402  (pytest fixture)


def _post(client, name, payload):
    status, ctype, data = client.request(
        "POST", f"/api/{name}", body=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    return status, (json.loads(data) if "json" in ctype else data)


def test_api_ops_catalogue(client):
    status, data = client.get(f"/api/decode/ops")
    assert status == 200
    assert "groups" in data and "solvers" in data
    names = {o["name"] for g in data["groups"] for o in g["ops"]}
    assert {"from-base64", "gunzip", "xor", "aes"} <= names


def test_api_decode_pipeline(client):
    blob = base64.b64encode(gzip.compress(b"api pipeline")).decode()
    status, data = _post(client, "decode", {
        "source": {"kind": "text", "value": blob},
        "recipe": [{"op": "from-base64", "params": {}}, {"op": "gunzip", "params": {}}]})
    assert status == 200 and data["ok"] and data["text"] == "api pipeline"
    assert [s["op"] for s in data["steps"]] == ["from-base64", "gunzip"]


def test_api_decode_bad_step_is_ok_false_http_200(client):
    status, data = _post(client, "decode", {
        "source": {"kind": "text", "value": "not base64 valid !!!!"},
        "recipe": [{"op": "from-base64", "params": {}}]})
    assert status == 200 and data["ok"] is False and data["error"]
    assert data["steps"] == []


def test_api_decode_unknown_op_is_ok_false(client):
    status, data = _post(client, "decode", {
        "source": {"kind": "text", "value": "x"},
        "recipe": [{"op": "made-up", "params": {}}]})
    assert status == 200 and data["ok"] is False and "made-up" in data["error"]


def test_api_decode_malformed_body_is_400(client):
    status, ctype, body = client.request(
        "POST", "/api/decode", body=b"{not json",
        headers={"Content-Type": "application/json"})
    assert status == 400


def test_api_decode_file_source_bounded(client):
    elf = str(fixture_path("hello_elf64"))
    raw = fixture_bytes("hello_elf64")
    status, data = _post(client, "decode", {
        "source": {"kind": "file", "path": elf, "offset": 0, "length": 4},
        "recipe": [{"op": "to-hex", "params": {}}]})
    assert status == 200 and data["ok"]
    assert data["text"] == raw[:4].hex()


def test_api_solve(client):
    cipher = op("xor", ENGLISH, key="2a")
    status, data = _post(client, "decode/solve", {
        "source": {"kind": "hex", "value": cipher.hex()}, "name": "xor-single"})
    assert status == 200 and data["ok"]
    assert data["candidates"][0]["params"]["key"] == "2a"
