"""The native C `decode` workbench against the Python implementation.

Both editions get the same requests and must give the same answers: the
result object of every operation on plain, empty, non-ASCII and long input,
multi-step recipes, every way a step can fail (with the same message and the
same completed steps), the catalogue, the solvers (same candidates, order,
params and scores), the command line (text, `--json`, exit status and
stderr), `--out`, byte ranges of a file, the practice puzzles, and the HTTP
routes with well-formed and malformed bodies. A randomized run with a fixed
seed sends thousands of random recipes over random and damaged input to both.

What the C edition does not have (`aes` in GCM mode, `des`, `3des`,
`bunzip2`, `unxz`) must be in its catalogue as unavailable and fail with
"<name> is not available in this build".

Inputs that once stopped the Python edition (a traceback on the command
line, HTTP 500, or hours of work) are compared like any others: the two
editions must fail them alike, with the same message (`ONCE_STOPPED_PYTHON`).

`VEX_TEST_SANITIZED=1` runs everything with the AddressSanitizer/UBSan build;
`test_hostile_input_is_safe_under_asan` always does. `VEX_TEST_C_BUILD=DIR`
builds into (and tests) another build folder than `c/build`.
"""
import base64
import bz2
import contextlib
import gzip
import http.client
import io
import json
import lzma
import os
import quopri
import random
import re
import resource
import shutil
import signal
import struct
import subprocess
import threading
import time
import urllib.parse
import zlib
from pathlib import Path

import pytest

from vex import crypto, decode, server
from vex.cli import main as python_main
from conftest import fixture_bytes, fixture_path

REPO = Path(__file__).resolve().parent.parent
C_DIR = REPO / "c"
MAKE = shutil.which("make")
COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
BUILD_DIR = os.environ.get("VEX_TEST_C_BUILD")

pytestmark = pytest.mark.skipif(
    not (MAKE and COMPILER and C_DIR.is_dir()),
    reason="the C port needs make and a C compiler")

# What the C edition leaves to the Python edition. `aes` is there, without GCM.
C_UNAVAILABLE = {"bunzip2", "unxz", "des", "3des"}
GCM_MISSING = "aes-gcm is not available in this build"
ALL_OPS = [op.name for op in decode._OP_LIST]
C_OPS = [name for name in ALL_OPS if name not in C_UNAVAILABLE]
SOLVERS = ["caesar", "xor-single", "xor-keylen", "substitution"]


# --- the two implementations --------------------------------------------------

def _make(target):
    command = [MAKE, "-C", str(C_DIR), target]
    if BUILD_DIR:
        command.append(f"BUILD={BUILD_DIR}")
    proc = subprocess.run(command, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")
    return Path(BUILD_DIR) if BUILD_DIR else C_DIR / "build"


@pytest.fixture(scope="session")
def c_binary():
    """The native build; with VEX_TEST_SANITIZED=1 the AddressSanitizer/UBSan
    build, so that a memory error anywhere fails the test that reaches it."""
    if os.environ.get("VEX_TEST_SANITIZED"):
        return _make("asan") / "vex-asan"
    return _make("all") / "vex"


@pytest.fixture(scope="session")
def asan_binary():
    return _make("asan") / "vex-asan"


SANITIZER_ENV = dict(os.environ, ASAN_OPTIONS="abort_on_error=1:detect_leaks=1",
                     UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
SANITIZER_WORDS = ("AddressSanitizer", "runtime error", "LeakSanitizer", "ERROR:")


def run_c(binary, *args, timeout=300, preexec_fn=None):
    proc = subprocess.run([str(binary), *map(os.fsencode, map(_text_arg, args))],
                          capture_output=True, timeout=timeout, env=SANITIZER_ENV,
                          preexec_fn=preexec_fn)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


def run_c_to_file(binary, folder, *args, preexec_fn=None, timeout=600):
    """For output too large to hold in the test: the exit status, the first
    and the last few hundred characters of stdout, its size and stderr."""
    path = Path(folder) / "captured-stdout"
    with open(path, "wb") as out:
        proc = subprocess.run([str(binary), *map(os.fsencode, map(_text_arg, args))],
                              stdout=out, stderr=subprocess.PIPE, timeout=timeout,
                              env=SANITIZER_ENV, preexec_fn=preexec_fn)
    size = path.stat().st_size
    with open(path, "rb") as f:
        head = f.read(600)
        f.seek(max(0, size - 600))
        tail = f.read()
    path.unlink()
    return (proc.returncode, head.decode("utf-8", "replace"), tail.decode("utf-8", "replace"),
            size, proc.stderr.decode("utf-8", "replace"))


def _text_arg(value):
    return value if isinstance(value, (str, bytes)) else str(value)


def run_python(*args):
    """The Python CLI in-process: (exit status, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = python_main([_text_arg(a) for a in args])
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def same_cli(c_binary, *args):
    """Runs both command lines; they must print the same and exit the same."""
    c, py = run_c(c_binary, *args), run_python(*args)
    assert c == py, args
    return c


class Client:
    def __init__(self, port, token):
        self.port, self.token = port, token

    def request(self, method, name, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=300)
        conn.request(method, f"/api/{name}", body=body, headers={"X-Vex-Token": self.token})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, json.loads(data)

    def post(self, name, payload):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        return self.request("POST", name, body)


@pytest.fixture(scope="module")
def c_client(c_binary):
    proc = subprocess.Popen([str(c_binary), "gui", "--no-browser", "--port", "0"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=SANITIZER_ENV)
    found = None
    deadline = time.time() + 30
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        found = re.search(r"http://127\.0\.0\.1:(\d+)/#token=(\S+)", line)
        if found:
            break
    if not found:
        proc.kill()
        pytest.fail("the C server did not print its address")
    yield Client(int(found.group(1)), found.group(2))
    # Stopped the way Ctrl+C stops it, so that a sanitizer build reports what
    # it has to report (leaks included) on the way out.
    still_running = proc.poll() is None
    proc.send_signal(signal.SIGINT)
    try:
        _, err = proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
    assert still_running, f"the C server died:\n{err[-3000:]}"
    assert proc.returncode == 0, err[-3000:]
    for word in SANITIZER_WORDS:
        assert word not in err, err[-3000:]


@pytest.fixture(scope="module")
def py_client():
    httpd, workspace = server.create_server(port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield Client(httpd.server_address[1], workspace.token)
    httpd.shutdown()
    httpd.server_close()
    workspace.close()


@pytest.fixture(scope="module")
def both(c_client, py_client):
    """Sends one request to both servers and returns the answer they agree
    on: (status, JSON)."""
    def ask(name, payload, method="POST"):
        body = None
        if method == "POST":
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        c, py = c_client.request(method, name, body), py_client.request(method, name, body)
        assert c == py, (name, payload if not isinstance(payload, bytes) else payload[:200])
        return c
    return ask


def hex_source(data):
    return {"kind": "hex", "value": bytes(data).hex()}


def run_both(both, data, recipe):
    """A recipe over `data` in both editions; the result they agree on. The
    recipe is a list of (op, params)."""
    status, result = both("decode", {
        "source": hex_source(data),
        "recipe": [{"op": name, "params": params} for name, params in recipe]})
    assert status == 200
    return result


def expect(both, data, recipe, output):
    result = run_both(both, data, recipe)
    assert result["ok"], result["error"]
    assert bytes.fromhex(result["hex"]) == output
    return result


def refused(both, data, recipe, message):
    result = run_both(both, data, recipe)
    assert result["ok"] is False and message in result["error"], result["error"]
    return result


# --- inputs -------------------------------------------------------------------

ENGLISH = (b"the quick brown fox jumps over the lazy dog while the sun is "
           b"shining and the birds are singing in the trees near the river")
UNICODE_TEXT = "h\u00e9llo w\u00f6rld \u2603 \U0001f600 \u65e5\u672c\u8a9e".encode("utf-8")


def plain_inputs():
    rng = random.Random(7)
    return {
        "empty": b"",
        "nul": b"\x00",
        "letter": b"A",
        "high": b"\xff",
        "text": ENGLISH,
        "mixed-case": b"Hello, World! The Quick Brown Fox; 0123456789 ~!@#$%^&*()_+",
        "non-ascii": UNICODE_TEXT,
        "latin": bytes(range(0x80, 0x100)),
        "every-byte": bytes(range(256)),
        "random": bytes(rng.randrange(256) for _ in range(1000)),
        "zeros": b"\x00" * 4099,
        "long": (ENGLISH + b"\n") * 600,
        "long-random": bytes(rng.randrange(256) for _ in range(70001)),
    }


PLAIN = plain_inputs()
# What each operation is given besides the inputs above: parameters that work.
WORKING_PARAMS = {
    "vigenere": {"key": "LEMON"}, "railfence": {"rails": "3"},
    "substitution": {"map": "QWERTYUIOPASDFGHJKLZXCVBNM"},
    "xor": {"key_text": "k3y"}, "rc4": {"key": "0102030405"},
    "chacha20": {"key": "00" * 31 + "01", "nonce": "00" * 11 + "02"},
    "aes": {"key": "000102030405060708090a0b0c0d0e0f", "mode": "ctr", "nonce": "00" * 16},
}


# --- every operation on plain inputs ------------------------------------------

@pytest.mark.parametrize("name", C_OPS)
def test_operation_matches_python_on_plain_inputs(both, name):
    succeeded = 0
    for label, data in PLAIN.items():
        if len(data) > 5000 and name in ("vigenere", "substitution", "rc4",
                                         "chacha20", "aes", "from-base85"):
            data = data[:5000]          # slow in pure Python; the fuzz goes further
        result = run_both(both, data, [(name, WORKING_PARAMS.get(name, {}))])
        succeeded += result["ok"]
        if result["ok"]:
            assert result["steps"] == [{"op": name, "size": result["size"]}]
        else:
            assert result["steps"] == [] and result["hex"] == data.hex()
    assert succeeded >= 1, name


def test_encodings_decode_what_the_standard_library_encodes(both):
    for data in PLAIN.values():
        data = data[:3000]
        expect(both, base64.b64encode(data), [("from-base64", {})], data)
        expect(both, base64.b64encode(data).rstrip(b"="), [("from-base64", {})], data)
        expect(both, base64.encodebytes(data), [("from-base64", {})], data)
        expect(both, base64.urlsafe_b64encode(data), [("from-base64", {"alphabet": "url"})], data)
        expect(both, base64.b32encode(data), [("from-base32", {})], data)
        expect(both, base64.b32encode(data).lower().rstrip(b"="), [("from-base32", {})], data)
        expect(both, data.hex(" ", 4).encode(), [("from-hex", {})], data)
        expect(both, base64.a85encode(data), [("from-base85", {})], data)
        expect(both, base64.a85encode(data, wrapcol=40), [("from-base85", {})], data)
        padded = data + b"\x00" * (-len(data) % 4)
        expect(both, base64.z85encode(padded), [("from-base85", {"variant": "z85"})], padded)
        expect(both, urllib.parse.quote_from_bytes(data, safe="").encode(), [("url-decode", {})],
               data)
        expect(both, quopri.encodestring(data), [("qp-decode", {})], data)
        expect(both, zlib.compress(data), [("zlib-inflate", {})], data)
        expect(both, gzip.compress(data), [("gunzip", {})], data)
        raw = zlib.compressobj(9, zlib.DEFLATED, -15)
        expect(both, raw.compress(data) + raw.flush(), [("raw-inflate", {})], data)
        expect(both, data, [("to-base64", {})], base64.b64encode(data))
        expect(both, data, [("to-base64", {"alphabet": "url"})], base64.urlsafe_b64encode(data))
        expect(both, data, [("to-base32", {})], base64.b32encode(data))
        expect(both, data, [("to-hex", {})], data.hex().encode())
        expect(both, data, [("to-base85", {})], base64.a85encode(data))
        expect(both, padded, [("to-base85", {"variant": "z85"})], base64.z85encode(padded))
        expect(both, data, [("url-encode", {})],
               urllib.parse.quote_from_bytes(data, safe="").encode())
        expect(both, data, [("reverse", {})], data[::-1])


def test_charset_decode(both):
    text = "caf\u00e9 \u2603 \U0001f600 plain"
    for name, codec in (("utf-8", "utf-8"), ("utf-16le", "utf-16-le"), ("utf-16be", "utf-16-be")):
        expect(both, text.encode(codec), [("charset-decode", {"from": name})], text.encode())
    expect(both, bytes(range(256)), [("charset-decode", {"from": "latin-1"})],
           bytes(range(256)).decode("latin-1").encode())
    expect(both, text.encode(), [("charset-decode", {})], text.encode())
    # Every way the bytes can fail to be the text they are said to be.
    bad_utf8 = [b"\xff", b"abc\x80", b"\xc0\xaf", b"\xc2", b"\xc2A", b"\xe0\x80\x80", b"\xe0\xa0",
                b"\xe0\xa0A", b"\xe1", b"\xe1\x80", b"\xe1A\x80", b"\xed\xa0\x80", b"\xed\xa0",
                b"\xed\xbf\xbf", b"\xf0\x80\x80\x80", b"\xf0\x90", b"\xf0\x90\x80",
                b"\xf0\x90\x80A", b"\xf0\x90A", b"\xf0A", b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80",
                b"ok \xe2\x98 no", b"\xf8\x88\x80\x80\x80", b"A\xf0", b"long " * 50 + b"\xfe",
                b"\xe2\x82", b"\xf1\x80\x80", b"\xc3\xa9\xe9"]
    for data in bad_utf8:
        refused(both, data, [("charset-decode", {})], "cannot read bytes as utf-8: 'utf-8' codec")
        refused(both, data, [("charset-decode", {"from": "utf-8"})], "codec can't decode")
    bad_utf16 = [b"A", b"A\x00B", b"\x00\xdc", b"\x00\xdcA\x00", b"\x00\xd8", b"\x00\xd8A",
                 b"\x00\xd8A\x00", b"\x00\xd8\x00\xd8", b"A\x00\x00\xd8", b"A\x00\x00\xd8B",
                 b"\x3d\xd8\x00\xde\x00", b"\xd8\x00", b"\xdc\x00\x00A", b"\xd8\x00\x00A",
                 b"\xd8\x3d\xde", b"\xd8\x3d\xde\x00\xff"]
    for data in bad_utf16:
        for name in ("utf-16le", "utf-16be"):
            run_both(both, data, [("charset-decode", {"from": name})])
    refused(both, b"A", [("charset-decode", {"from": "utf-16le"})], "truncated data")
    refused(both, b"\x00\xdc", [("charset-decode", {"from": "utf-16le"})], "illegal encoding")
    refused(both, b"\x00\xd8", [("charset-decode", {"from": "utf-16le"})],
            "unexpected end of data")
    refused(both, b"\x00\xd8A\x00", [("charset-decode", {"from": "utf-16le"})],
            "illegal UTF-16 surrogate")
    for value in ("ascii", "UTF-8", "", None, 5, True):
        refused(both, b"x", [("charset-decode", {"from": value})],
                "from must be utf-8, utf-16le, utf-16be or latin-1")


def test_classic_ciphers_known_vectors(both):
    expect(both, b"Hello, World!", [("rot13", {})], b"Uryyb, Jbeyq!")
    expect(both, b"Hello", [("rot-n", {})], b"Uryyb")
    expect(both, b"abcXYZ", [("rot-n", {"n": "1"})], b"bcdYZA")
    expect(both, b"abcXYZ", [("rot-n", {"n": 25})], b"zabWXY")
    expect(both, b"abc XYZ", [("atbash", {})], b"zyx CBA")
    expect(both, b"ATTACKATDAWN", [("vigenere", {"key": "LEMON", "mode": "encrypt"})],
           b"LXFOPVEFRNHR")
    expect(both, b"LXFOPVEFRNHR", [("vigenere", {"key": "LEMON"})], b"ATTACKATDAWN")
    expect(both, b"Attack at Dawn!", [("vigenere", {"key": "l-e m.o,n9", "mode": "encrypt"})],
           b"Lxfopv ef Rnhr!")
    ice = bytes.fromhex(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324"
        "272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165"
        "286326302e27282f")
    plain = (b"Burning 'em, if you ain't quick and nimble\n"
             b"I go crazy when I hear a cymbal")
    expect(both, plain, [("xor", {"key": "494345"})], ice)
    expect(both, ice, [("xor", {"key_text": "ICE"})], plain)
    expect(both, ice, [("xor", {"key": "0x49, 0x43:45"})], plain)
    expect(both, b"WEAREDISCOVEREDFLEEATONCE", [("railfence", {"rails": "3", "mode": "encrypt"})],
           b"WECRLTEERDSOEEFEAOCAIVDEN")
    expect(both, b"WECRLTEERDSOEEFEAOCAIVDEN", [("railfence", {"rails": 3})],
           b"WEAREDISCOVEREDFLEEATONCE")
    expect(both, b"Wkh Txlfn Eurzq Ira", [("substitution", {"map": "DEFGHIJKLMNOPQRSTUVWXYZABC"})],
           b"The Quick Brown Fox")


def test_railfence_every_shape(both):
    text = bytes(range(33, 33 + 60))
    for size in (0, 1, 2, 3, 4, 5, 7, 12, 13, 59, 60):
        for rails in (2, 3, 4, 5, 7, 12, 13, 58, 59, 60, 61, 1000):
            data = text[:size]
            sealed = run_both(both, data, [("railfence", {"rails": rails, "mode": "encrypt"})])
            opened = run_both(both, bytes.fromhex(sealed["hex"]), [("railfence", {"rails": rails})])
            assert sealed["ok"] and bytes.fromhex(opened["hex"]) == data
    result = run_both(both, b"", [("railfence", {"rails": 10 ** 30})])
    assert result["ok"] and result["size"] == 0


def test_railfence_with_more_rails_than_bytes(both):
    """Past the length of the data more rails change nothing, and cost
    nothing: the text comes out as it went in, in no time. (The Python
    edition once went through every rail, one by one, for hours.)"""
    data = bytes(range(33, 33 + 90))
    start = time.monotonic()
    for rails in (90, 91, 5000, 10 ** 9, 2 ** 64, 10 ** 40, "0x" + "f" * 60, "9" * 4300):
        for mode in ("encrypt", "decrypt"):
            expect(both, data, [("railfence", {"rails": rails, "mode": mode})], data)
    assert time.monotonic() - start < 60
    for size in (1, 2, 3, 89, 90):
        for rails in (size - 1, size, size + 1):
            if rails >= 2:
                sealed = run_both(both, data[:size], [("railfence", {"rails": rails,
                                                                     "mode": "encrypt"})])
                expect(both, bytes.fromhex(sealed["hex"]), [("railfence", {"rails": rails})],
                       data[:size])
    assert run_both(both, data, [("railfence", {"rails": 89, "mode": "encrypt"})])["hex"] != \
        data.hex()


def test_hash(both):
    import hashlib
    for data in (b"", b"abc", PLAIN["every-byte"], PLAIN["long"]):
        expect(both, data, [("hash", {})], hashlib.sha256(data).hexdigest().encode())
        for algo in ("md5", "sha1", "sha256"):
            expect(both, data, [("hash", {"algo": algo})],
                   hashlib.new(algo, data).hexdigest().encode())
        expect(both, data, [("hash", {"algo": "crc32"})], b"%08x" % zlib.crc32(data))
    for algo in ("sha512", "MD5", "", None, 1, ["md5"]):
        refused(both, b"x", [("hash", {"algo": algo})], "algo must be md5, sha1, sha256 or crc32")


# --- symmetric ciphers against public vectors ----------------------------------

def test_rc4_and_chacha20_public_vectors(both):
    sealed = expect(both, b"Plaintext", [("rc4", {"key_text": "Key"})],
                    bytes.fromhex("bbf316e8d940af0ad3"))
    expect(both, bytes.fromhex(sealed["hex"]), [("rc4", {"key": "4b6579"})], b"Plaintext")
    expect(both, b"pedia", [("rc4", {"key_text": "Wiki"})], bytes.fromhex("1021bf0420"))
    expect(both, b"Attack at dawn", [("rc4", {"key_text": "Secret"})],
           bytes.fromhex("45a01f645fc35b383552544b9bf5"))
    # RFC 8439, section 2.4.2
    key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    nonce = "000000000000004a00000000"
    plain = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
             b"only one tip for the future, sunscreen would be it.")
    sealed = bytes.fromhex(
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d")
    expect(both, plain, [("chacha20", {"key": key, "nonce": nonce})], sealed)
    expect(both, sealed, [("chacha20", {"key": key, "nonce": nonce, "counter": "1"})], plain)
    # The block counter: any integer, taken modulo 2**32, and it wraps.
    data = PLAIN["random"][:200]
    for counter in (0, 1, 2, "0x10", 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 5, -1, -2 ** 40, 10 ** 30,
                    "0b101", " 7 ", "1_000"):
        want = crypto.chacha20(data, bytes.fromhex(key), bytes.fromhex(nonce),
                               counter if isinstance(counter, int) else int(counter, 0))
        expect(both, data, [("chacha20", {"key": key, "nonce": nonce, "counter": counter})], want)
    for size in (0, 1, 63, 64, 65, 127, 128, 129, 1000):
        data = PLAIN["long-random"][:size]
        expect(both, data, [("chacha20", {"key": key, "nonce": nonce})],
               crypto.chacha20(data, bytes.fromhex(key), bytes.fromhex(nonce)))
        expect(both, data, [("rc4", {"key": "0102030405"})],
               crypto.rc4(data, bytes.fromhex("0102030405")))
    for length in (1, 2, 16, 255, 256):
        key_hex = PLAIN["long-random"][:length].hex()
        expect(both, ENGLISH, [("rc4", {"key": key_hex})],
               crypto.rc4(ENGLISH, bytes.fromhex(key_hex)))


def test_symmetric_error_paths(both):
    key, nonce = "00" * 32, "00" * 12
    refused(both, b"x", [("chacha20", {"key": "00" * 31, "nonce": nonce})],
            "chacha20 failed: ChaCha20 key must be 32 bytes, got 31")
    refused(both, b"x", [("chacha20", {"key": key, "nonce": "00" * 8})],
            "chacha20 failed: ChaCha20 nonce must be 12 bytes, got 8")
    refused(both, b"x", [("chacha20", {"key": key})], "chacha20 needs parameter nonce")
    refused(both, b"x", [("chacha20", {"nonce": nonce})], "chacha20 needs parameter key")
    refused(both, b"x", [("chacha20", {"key": "0", "nonce": "zz"})],
            "hex needs an even number of digits")
    refused(both, b"x", [("chacha20", {"key": key, "nonce": "zz", "counter": "x"})],
            "not valid hex")
    refused(both, b"x", [("chacha20", {"key": key, "nonce": nonce, "counter": "x"})],
            "counter must be a number, not 'x'")
    refused(both, b"x", [("chacha20", {"key": key, "nonce": nonce, "counter": None})],
            "counter must be a number, not None")
    refused(both, b"x", [("chacha20", {"key": key, "nonce": nonce, "counter": True})],
            "counter must be a number")
    refused(both, b"x", [("rc4", {})], "rc4 needs a key (key=HEX or key_text=TEXT)")
    refused(both, b"x", [("rc4", {"key": "", "key_text": ""})], "rc4 needs a key")
    refused(both, b"x", [("rc4", {"key": "0x"})], "rc4 failed: RC4 key must be 1..256 bytes, got 0")
    refused(both, b"x", [("rc4", {"key": "00" * 257})],
            "rc4 failed: RC4 key must be 1..256 bytes, got 257")
    refused(both, b"x", [("rc4", {"key": "abc"})], "hex needs an even number of digits")
    refused(both, b"x", [("rc4", {"key_text": "\ud800x"})],
            "rc4 failed: 'utf-8' codec can't encode character '\\ud800' in position 0: "
            "surrogates not allowed")
    refused(both, b"x", [("rc4", {"key_text": "ab" + chr(0xDC00) + chr(0xDC01) + chr(0xD800) + "c"})],
            "rc4 failed: 'utf-8' codec can't encode characters in position 2-4")


# --- AES: ECB, CBC and CTR ------------------------------------------------------

NIST_BLOCKS = bytes.fromhex(         # SP 800-38A, appendix F: the four plaintext blocks
    "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
NIST_KEYS = {
    128: "2b7e151628aed2a6abf7158809cf4f3c",
    192: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    256: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
}
NIST_IV = "000102030405060708090a0b0c0d0e0f"
NIST_COUNTER = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
NIST_SP800_38A = {                   # (mode, key bits): the ciphertext
    ("ecb", 128): "3ad77bb40d7a3660a89ecaf32466ef97" "f5d3d58503b9699de785895a96fdbaaf"
                  "43b1cd7f598ece23881b00e3ed030688" "7b0c785e27e8ad3f8223207104725dd4",
    ("ecb", 192): "bd334f1d6e45f25ff712a214571fa5cc" "974104846d0ad3ad7734ecb3ecee4eef"
                  "ef7afd2270e2e60adce0ba2face6444e" "9a4b41ba738d6c72fb16691603c18e0e",
    ("ecb", 256): "f3eed1bdb5d2a03c064b5a7e3db181f8" "591ccb10d410ed26dc5ba74a31362870"
                  "b6ed21b99ca6f4f9f153e7b1beafed1d" "23304b7a39f9f3ff067d8d8f9e24ecc7",
    ("cbc", 128): "7649abac8119b246cee98e9b12e9197d" "5086cb9b507219ee95db113a917678b2"
                  "73bed6b8e3c1743b7116e69e22229516" "3ff1caa1681fac09120eca307586e1a7",
    ("cbc", 192): "4f021db243bc633d7178183a9fa071e8" "b4d9ada9ad7dedf4e5e738763f69145a"
                  "571b242012fb7ae07fa9baac3df102e0" "08b0e27988598881d920a9e64f5615cd",
    ("cbc", 256): "f58c4c04d6e5f1ba779eabfb5f7bfbd6" "9cfc4e967edb808d679f777bc6702c7d"
                  "39f23369a9d9bacfa530e26304231461" "b2eb05e2c39be9fcda6c19078c6a9d1b",
    ("ctr", 128): "874d6191b620e3261bef6864990db6ce" "9806f66b7970fdff8617187bb9fffdff"
                  "5ae4df3edbd5d35e5b4f09020db03eab" "1e031dda2fbe03d1792170a0f3009cee",
    ("ctr", 192): "1abc932417521ca24f2b0459fe7e6e0b" "090339ec0aa6faefd5ccc2c6f4ce8e94"
                  "1e36b26bd1ebc670d1bd1d665620abf7" "4f78a7f6d29809585a97daec58c6b050",
    ("ctr", 256): "601ec313775789a5b7a7f504bbf3d228" "f443e3ca4d62b59aca84e990cacaf5c5"
                  "2b0930daa23de94ce87017ba2d84988d" "dfc9c58db67aada613c2dd08457941a6",
}
FIPS_197 = {                         # appendix C: key -> ciphertext of 00112233...eeff
    "000102030405060708090a0b0c0d0e0f": "69c4e0d86a7b0430d8cdb78070b4c55a",
    "000102030405060708090a0b0c0d0e0f1011121314151617": "dda97ca4864cdfe06eaf70a0ec0d7191",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f":
        "8ea2b7ca516745bfeafc49904b496089",
}


def test_aes_nist_vectors(both):
    """FIPS-197 appendix C and SP 800-38A appendix F, both directions: the C
    edition, the Python edition and the published ciphertexts agree."""
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    for key, sealed in FIPS_197.items():
        params = {"key": key, "mode": "ecb", "unpad": "none"}
        expect(both, block, [("aes", dict(params, op="encrypt"))], bytes.fromhex(sealed))
        expect(both, bytes.fromhex(sealed), [("aes", params)], block)
        expect(both, bytes.fromhex(sealed), [("aes", dict(params, op="decrypt"))], block)
    for (mode, bits), sealed in NIST_SP800_38A.items():
        sealed = bytes.fromhex(sealed)
        params = {"key": NIST_KEYS[bits], "mode": mode, "unpad": "none"}
        if mode == "cbc":
            params["iv"] = NIST_IV
        if mode == "ctr":
            params["nonce"] = NIST_COUNTER
        expect(both, NIST_BLOCKS, [("aes", dict(params, op="encrypt"))], sealed)
        expect(both, sealed, [("aes", dict(params, op="decrypt"))], NIST_BLOCKS)
        expect(both, sealed, [("aes", params)], NIST_BLOCKS)
        # block by block, and with the padding a whole message gets
        expect(both, NIST_BLOCKS[:16], [("aes", dict(params, op="encrypt"))], sealed[:16])
        padded = run_both(both, NIST_BLOCKS, [("aes", dict(params, op="encrypt", unpad="pkcs7"))])
        assert padded["ok"] and padded["hex"].startswith(sealed.hex())
        assert padded["size"] == (64 if mode == "ctr" else 80)
        expect(both, bytes.fromhex(padded["hex"]), [("aes", dict(params, unpad="pkcs7"))],
               NIST_BLOCKS)


def test_aes_matches_python_for_every_mode_and_size(both):
    rng = random.Random(197)
    data = bytes(rng.randrange(256) for _ in range(400))
    checked = 0
    for bits in (128, 192, 256):
        key = bytes(rng.randrange(256) for _ in range(bits // 8)).hex()
        for size in (0, 1, 15, 16, 17, 31, 32, 33, 48, 100, 256, 399):
            plain = data[:size]
            for mode in ("ecb", "cbc", "ctr"):
                extra = {"iv": data[100:116].hex()} if mode == "cbc" else \
                    {"nonce": data[200:200 + rng.choice((1, 8, 12, 15, 16))].hex()} \
                    if mode == "ctr" else {}
                for unpad in ("pkcs7", "none", None):
                    params = dict({"key": key, "mode": mode}, **extra)
                    if unpad:
                        params["unpad"] = unpad
                    sealed = run_both(both, plain, [("aes", dict(params, op="encrypt"))])
                    opened = run_both(both, plain, [("aes", params)])
                    checked += 2
                    if sealed["ok"]:
                        back = run_both(both, bytes.fromhex(sealed["hex"]), [("aes", params)])
                        assert back["ok"] and bytes.fromhex(back["hex"]) == plain
                        want = crypto.aes(plain, bytes.fromhex(key), mode,
                                          iv=bytes.fromhex(extra.get("iv", "")),
                                          nonce=bytes.fromhex(extra.get("nonce", "")),
                                          op="encrypt", unpad=unpad or "pkcs7")
                        assert bytes.fromhex(sealed["hex"]) == want
                    else:
                        assert unpad == "none" and size % 16 and mode != "ctr"
                    assert opened["ok"] or mode != "ctr"
    assert checked > 600
    # the counter is one number of 128 bits: it carries, and it wraps
    for nonce in ("ff" * 16, "00" * 15 + "ff", "fe" + "ff" * 15, "ffffffff", "01"):
        params = {"key": NIST_KEYS[128], "mode": "ctr", "nonce": nonce}
        expect(both, data[:100], [("aes", params)],
               crypto.aes(data[:100], bytes.fromhex(NIST_KEYS[128]), "ctr",
                          nonce=bytes.fromhex(nonce)))
    # a longer message, in a recipe
    long = PLAIN["long-random"][:20000]
    params = {"key": NIST_KEYS[256], "mode": "cbc", "iv": NIST_IV}
    expect(both, long, [("aes", dict(params, op="encrypt")), ("to-base64", {}),
                        ("from-base64", {}), ("aes", params)], long)


def test_aes_error_paths(both, c_client, py_client):
    key, iv = NIST_KEYS[128], NIST_IV
    block = b"sixteen byte msg"
    refused(both, block, [("aes", {})], "aes needs parameter key")
    refused(both, block, [("aes", {"key": key})], "aes needs parameter mode")
    refused(both, block, [("aes", {"mode": "ecb"})], "aes needs parameter key")
    refused(both, block, [("aes", {"key": key, "mode": ""})], "aes needs parameter mode")
    for mode in ("ofb", "ECB", "cfb", 1, True, ["ecb"]):
        refused(both, block, [("aes", {"key": key, "mode": mode, "op": "x", "unpad": "x"})],
                "mode must be ecb, cbc, ctr or gcm")
    refused(both, block, [("aes", {"key": key, "mode": "ecb", "op": "seal", "unpad": "x"})],
            "op must be decrypt or encrypt")
    refused(both, block, [("aes", {"key": key, "mode": "ecb", "op": None})],
            "op must be decrypt or encrypt")
    refused(both, block, [("aes", {"key": "zz", "mode": "ecb", "unpad": "zero"})],
            "unpad must be pkcs7 or none")
    refused(both, block, [("aes", {"key": key, "mode": "ecb", "unpad": None})],
            "unpad must be pkcs7 or none")
    refused(both, block, [("aes", {"key": "zz", "mode": "ecb"})], "not valid hex")
    refused(both, block, [("aes", {"key": "abc", "mode": "ecb", "iv": "zz"})],
            "hex needs an even number of digits")
    # every hex parameter is read, whether the mode uses it or not
    refused(both, block, [("aes", {"key": key, "mode": "ecb", "iv": "zz", "nonce": "0"})],
            "not valid hex")
    refused(both, block, [("aes", {"key": key, "mode": "ecb", "nonce": "0", "tag": "zz"})],
            "hex needs an even number of digits")
    refused(both, block, [("aes", {"key": key, "mode": "ecb", "tag": "zz"})], "not valid hex")
    refused(both, block, [("aes", {"key": key, "mode": "ecb", "iv": None})], "not valid hex")
    for length in (0, 1, 15, 17, 23, 25, 31, 33, 64):
        refused(both, block, [("aes", {"key": "00" * length if length else "0x", "mode": "ecb"})],
                f"aes failed: AES key must be 16, 24, or 32 bytes, got {length}")
    refused(both, block[:15], [("aes", {"key": key, "mode": "ecb"})],
            "aes failed: AES-ECB decrypt needs a multiple of 16 bytes")
    refused(both, block[:15], [("aes", {"key": key, "mode": "cbc", "iv": iv})],
            "aes failed: AES-CBC decrypt needs a multiple of 16 bytes")
    refused(both, block[:15], [("aes", {"key": key, "mode": "ecb", "op": "encrypt",
                                        "unpad": "none"})],
            "aes failed: AES-ECB encrypt with unpad=none needs a multiple of 16 bytes")
    refused(both, block[:15], [("aes", {"key": key, "mode": "cbc", "iv": iv, "op": "encrypt",
                                        "unpad": "none"})],
            "aes failed: AES-CBC encrypt with unpad=none needs a multiple of 16 bytes")
    for bad_iv in ("", "00" * 15, "00" * 17, None):
        params = {"key": key, "mode": "cbc"}
        if bad_iv is not None:
            params["iv"] = bad_iv
        refused(both, block[:15], [("aes", params)], "aes failed: AES-CBC needs a 16-byte iv")
    for bad_nonce in ("", "00" * 17, None):
        params = {"key": key, "mode": "ctr"}
        if bad_nonce is not None:
            params["nonce"] = bad_nonce
        refused(both, block, [("aes", params)],
                "aes failed: AES-CTR needs a 1..16 byte nonce (16 for NIST vectors)")
    refused(both, b"", [("aes", {"key": key, "mode": "ecb"})],
            "aes failed: invalid PKCS#7 padding: length not a block multiple")
    # decrypted to something that does not end in padding
    sealed = crypto.aes(block, bytes.fromhex(key), "ecb", op="encrypt", unpad="none")
    refused(both, sealed, [("aes", {"key": key, "mode": "ecb"})],
            "aes failed: invalid PKCS#7 padding: bad pad byte")
    for tail, message in ((b"\x00", "bad pad byte"), (b"\x11", "bad pad byte"),
                          (b"\x02\x03", "inconsistent pad bytes"),
                          (b"\x01\x02\x03\x03", "inconsistent pad bytes")):
        plain = (b"A" * 16)[:16 - len(tail)] + tail
        sealed = crypto.aes(plain, bytes.fromhex(key), "cbc", iv=bytes.fromhex(iv),
                            op="encrypt", unpad="none")
        refused(both, sealed, [("aes", {"key": key, "mode": "cbc", "iv": iv})],
                f"aes failed: invalid PKCS#7 padding: {message}")
        expect(both, sealed, [("aes", {"key": key, "mode": "cbc", "iv": iv, "unpad": "none"})],
               plain)
    expect(both, crypto.aes(b"A" * 15 + b"\x01", bytes.fromhex(key), "ecb", op="encrypt",
                            unpad="none"), [("aes", {"key": key, "mode": "ecb"})], b"A" * 15)
    expect(both, crypto.aes(b"\x10" * 16, bytes.fromhex(key), "ecb", op="encrypt",
                            unpad="none"), [("aes", {"key": key, "mode": "ecb"})], b"")
    # GCM is the Python edition's alone: the C edition says so, in the words
    # Python uses for a build without it, whatever else is wrong with the step
    for params in ({"key": key, "mode": "gcm", "nonce": "00" * 12},
                   {"key": "zz", "mode": "gcm", "op": "x", "unpad": "x", "tag": "0"}):
        payload = {"source": hex_source(block), "recipe": [{"op": "to-hex", "params": {}},
                                                           {"op": "aes", "params": params}]}
        status, result = c_client.post("decode", payload)
        assert status == 200 and result["ok"] is False and result["error"] == GCM_MISSING
        assert result["steps"] == [{"op": "to-hex", "size": 32}]
    saved = decode.crypto
    decode.crypto = type("NoGcm", (), {"AVAILABLE": {"aes"}})
    try:
        assert decode.run(lambda: block, [("aes", {"key": key, "mode": "gcm"})])["error"] == \
            GCM_MISSING
    finally:
        decode.crypto = saved
    # but a missing or unknown parameter comes first, as in Python
    refused(both, block, [("aes", {"mode": "gcm"})], "aes needs parameter key")
    refused(both, block, [("aes", {"key": key, "mode": "gcm", "aad": "00"})],
            "unknown parameter 'aad' for aes")


# --- what the C edition does not have -------------------------------------------

def test_catalogue_matches_python_except_for_what_is_missing(c_client, py_client):
    c_status, c_ops = c_client.request("GET", "decode/ops")
    py_status, py_ops = py_client.request("GET", "decode/ops")
    assert c_status == py_status == 200
    missing = set()
    for group in c_ops["groups"]:
        for op in group["ops"]:
            if not op["available"]:
                missing.add(op["name"])
                op["available"] = True
    assert missing == C_UNAVAILABLE
    assert all(op["available"] for group in py_ops["groups"] for op in group["ops"])
    assert c_ops == py_ops
    # the same catalogue, key order included, on the command line
    assert json.dumps(c_ops) == json.dumps(py_ops)


@pytest.mark.parametrize("name", sorted(C_UNAVAILABLE))
def test_missing_operation_says_so(c_client, c_binary, name):
    message = f"{name} is not available in this build"
    status, result = c_client.post("decode", {
        "source": {"kind": "text", "value": "abc"},
        "recipe": [{"op": "to-hex", "params": {}},
                   {"op": name, "params": {"no-such-parameter": 1}}]})
    assert status == 200
    assert result == {"ok": False, "size": 6, "hex": b"616263".hex(), "text": "616263",
                      "looks_like": "printable text", "steps": [{"op": "to-hex", "size": 6}],
                      "error": message}
    # The wording is the Python edition's for a primitive its build lacks.
    saved = decode.crypto
    decode.crypto = type("NoCrypto", (), {"AVAILABLE": set()})
    try:
        if name in ("des", "3des"):
            assert decode.run(lambda: b"abc", [("to-hex", {}), (name, {})]) == result
    finally:
        decode.crypto = saved
    code, out, err = run_c(c_binary, "decode", "abc", "--recipe", name)
    assert code == 1 and f"error: {message}" in out and err == ""
    # an unknown parameter is still a usage error, as the recipe is read first
    code, out, err = run_c(c_binary, "decode", "abc", "--recipe", f"{name}:bogus=1")
    assert code == 2 and out == "" and "unknown parameter 'bogus'" in err


# --- recipes --------------------------------------------------------------------

def test_recipes_chain_left_to_right(both):
    plain = b"secret payload inside a gzip inside base64 " * 20
    key = b"KEY!"
    xored = bytes(c ^ key[i % len(key)] for i, c in enumerate(plain))
    blob = base64.b64encode(gzip.compress(xored))
    result = expect(both, blob, [("from-base64", {}), ("gunzip", {}), ("xor", {"key_text": "KEY!"})],
                    plain)
    assert [s["op"] for s in result["steps"]] == ["from-base64", "gunzip", "xor"]
    assert result["steps"][1]["size"] == len(plain)
    layered = base64.b32encode(base64.a85encode(zlib.compress(plain[::-1].hex().encode())))
    expect(both, layered, [("from-base32", {}), ("from-base85", {}), ("zlib-inflate", {}),
                           ("from-hex", {}), ("reverse", {})], plain)
    expect(both, plain, [("to-base64", {}), ("rot13", {}), ("rot13", {}), ("from-base64", {}),
                         ("hash", {"algo": "md5"}), ("to-hex", {}), ("from-hex", {})],
           __import__("hashlib").md5(plain).hexdigest().encode())
    expect(both, b"", [], b"")
    expect(both, b"\xff\xfe", [], b"\xff\xfe")


def test_failed_step_keeps_the_completed_ones(both):
    blob = base64.b64encode(b"this is not gzip data")
    result = refused(both, blob, [("from-base64", {}), ("gunzip", {}), ("to-hex", {})],
                     "incorrect header check")
    assert result["steps"] == [{"op": "from-base64", "size": 21}]
    assert result["text"] == "this is not gzip data"
    result = refused(both, b"abc", [("to-hex", {}), ("no-such-op", {}), ("to-hex", {})],
                     "unknown operation: 'no-such-op'")
    assert result["steps"] == [{"op": "to-hex", "size": 6}]
    result = refused(both, b"abc", [("rot13", {"n": 1})], "unknown parameter 'n' for rot13")
    assert result["steps"] == []
    refused(both, b"abc", [("vigenere", {})], "vigenere needs parameter key")
    refused(both, b"abc", [("vigenere", {"key": ""})], "vigenere needs parameter key")
    refused(both, b"abc", [("vigenere", {"key": None})], "vigenere needs parameter key")
    refused(both, b"abc", [("railfence", {"mode": "encrypt"})], "railfence needs parameter rails")
    refused(both, b"abc", [("substitution", {"map": ""})], "substitution needs parameter map")
    # the first unknown parameter, in the order they were given
    refused(both, b"abc", [("xor", {"key": "00", "zeta": 1, "alpha": 2})],
            "unknown parameter 'zeta' for xor")
    refused(both, b"abc", [("xor", {"": 1})], "unknown parameter '' for xor")


# Parameter values of every JSON type, and text values that are nearly right.
ODD_VALUES = [None, True, False, 0, 1, -1, 13, 25, 26, 2, 3, 1.0, 2.5, -0.0, 1e100, 1e-7, 1e16,
              123456789.125, 0.1, "", " ", "0", "13", " 5 ", "0x1f", "0b11", "0o17", "1_0", "+3",
              "-3", "1e3", "abc", "0x", "\u0663", "\uff11\uff12", "std", "url", "encrypt",
              "decrypt", "z85", "ascii85", "ecb", "none", "utf-16le", "md5", [], [1], ["a", "b"],
              {}, {"a": 1}, {"k": [1, {"z": None}]}, "caf\u00e9", "\u00e9", "\u0391\u03b2\u03b3",
              "a'b", 'a"b', "a'b\"c", "tab\tnew\nline\\", "\x00", "\x7f\x80\xa0\xad",
              "\u200b\u2028\ufeff", "\U0001f600", "\ud800", "x\udfffy", 10 ** 20, -10 ** 20,
              2 ** 64, 12345678901234567890123456789012345678901234567890, "1" * 50, "ff" * 40,
              "0x41 0x42", "41:42,43", "4 1", "4142434", "zz", "dead beef", "DEADBEEF"]


@pytest.mark.parametrize("name", C_OPS)
def test_parameter_values_of_every_kind(both, name):
    """Each parameter of each operation is given every odd value in turn: the
    two editions must take it, or refuse it, alike."""
    spec = decode.REGISTRY[name]
    data = b"Hello, World! 0123 \xff\x00 the end"
    base = WORKING_PARAMS.get(name, {})
    run_both(both, data, [(name, base)])
    for p in spec.params:
        for value in ODD_VALUES:
            run_both(both, data, [(name, dict(base, **{p["name"]: value}))])
        without = {k: v for k, v in base.items() if k != p["name"]}
        run_both(both, data, [(name, without)])
    run_both(both, data, [(name, dict(base, bogus=1))])
    run_both(both, data, [(name, {"bogus": 1})])


def test_parameters_that_are_not_an_object(both):
    data = b"abc"
    for params in ("", [], {}, None, 0, False):
        expect(both, data, [("rot13", params)], b"nop")
    refused(both, data, [("rot13", "xyz")], "unknown parameter 'x' for rot13")
    refused(both, data, [("rot13", ["zz", "n"])], "unknown parameter 'zz' for rot13")
    refused(both, data, [("rot-n", ["n", 5])], "unknown parameter 5 for rot-n")
    refused(both, data, [("rot-n", [None])], "unknown parameter None for rot-n")
    refused(both, data, [("rot-n", [True, "n"])], "unknown parameter True for rot-n")
    refused(both, data, [("rot-n", [1.5])], "unknown parameter 1.5 for rot-n")
    refused(both, data, [("rot-n", "n=1")], "unknown parameter '=' for rot-n")
    refused(both, data, [("nothing", [1, 2])], "unknown operation: 'nothing'")
    # Where every name is a parameter (or a list holds a list or an object),
    # what is not an object fails the step. (Python once stopped here with an
    # internal error.)
    for params in ("n", "nn", ["n"], [["n"]], [{"n": 1}], ["n", ["x"], "zz"], ["n", {"x": 1}],
                   5, -1, True, 1.5):
        result = refused(both, data, [("to-hex", {}), ("rot-n", params)],
                         "params must be an object")
        assert result["error"] == "params must be an object"
        assert result["steps"] == [{"op": "to-hex", "size": 6}]
    refused(both, data, [("xor", ["key", "key_text"])], "params must be an object")
    status, result = both("decode", b'{"source": {"kind": "text", "value": "x"}, '
                                    b'"recipe": [{"op": "rot-n", "params": NaN}]}')
    assert status == 200 and result["error"] == "params must be an object"


# --- sources --------------------------------------------------------------------

SOURCE_VALUES = ["", "plain", "caf\u00e9 \u2603 \U0001f600", "  spaced  ", "\x00\x01", "line\nline",
                 None, 0, 5, -7, 1.5, True, False, [], {}, [1, "two", None, 3.25, [True]],
                 {"a": "b", "c": [1, 2.0]}, 10 ** 25, 1e22, 1e-5, 123456.789, float(2 ** 53),
                 "48656c6c6f", "48 65 6c\n6c:6f", "0x48,0x65", "4", "xyz", "48 6", "0X410x42",
                 "\uff14\uff11", "41\u00a042\u200343\u300044", "0x", "0 x41", "00x41",
                 "aGVsbG8=", "aGVsbG8", "aGVs bG8=\n", "aGVsbG8==", "=aGVsbG8", "aGV=sbG8",
                 "aGVsbG8=x", "a", "ab", "abc", "abcd", "abcde", "ab==", "ab=", "ab===", "a===",
                 "ab==cd", "ab=c", "a b c d", "ab\tcd\r\nef==", "a-b_", "a+b/", "!!!!", "caf\u00e9",
                 "YQ==YQ==", "YQ=\n=", "YWI=", "YWI", "YWJj", "====", "=",
                 # not UTF-8 (a lone surrogate), not Latin-1 (for base64)
                 "a\ud800b", "\udcff", "\ud800\ud800\ud800x\udc00", "aGk\u20ac", "\u0100",
                 ["\u20ac"], ["\udc80"], {"\udc80": 1}]


def test_sources_of_every_kind(both):
    for kind in ("text", "hex", "base64"):
        for value in SOURCE_VALUES:
            both("decode", {"source": {"kind": kind, "value": value}, "recipe": []})
            both("decode/solve", {"source": {"kind": kind, "value": value}, "name": "caesar"})
        both("decode", {"source": {"kind": kind}})
        both("decode", {"source": {"kind": kind, "value": "6869", "extra": 1},
                        "recipe": [{"op": "to-hex"}]})
    status, result = both("decode", {"source": {"kind": "text", "value": "h\u00e9"},
                                     "recipe": [{"op": "to-hex", "params": None}]})
    assert result["text"] == "68c3a9"
    status, result = both("decode", {"source": {"kind": "hex", "value": "zz"},
                                     "recipe": [{"op": "to-hex"}]})
    assert status == 200 and result == {
        "ok": False, "size": 0, "hex": "", "text": "", "looks_like": "empty", "steps": [],
        "error": "not valid hex"}
    status, result = both("decode", {"source": {"kind": "base64", "value": "a"}})
    assert result["error"] == ("invalid base64: Invalid base64-encoded string: number of data "
                               "characters (1) cannot be 1 more than a multiple of 4")
    # text that cannot be UTF-8, base64 that cannot be Latin-1: a failed source
    status, result = both("decode", {"source": {"kind": "text", "value": "a\ud800b"}})
    assert status == 200 and result["ok"] is False and result["error"] == (
        "'utf-8' codec can't encode character '\\ud800' in position 1: surrogates not allowed")
    status, result = both("decode/solve", {"source": {"kind": "base64", "value": "aGk\u20ac"},
                                           "name": "caesar"})
    assert status == 200 and result == {"ok": False, "candidates": [], "error": (
        "'latin-1' codec can't encode character '\\u20ac' in position 3: ordinal not in "
        "range(256)")}


def test_file_source_ranges(both):
    elf = str(fixture_path("hello_elf64"))
    size = len(fixture_bytes("hello_elf64"))
    ranges = [(None, None), (0, 4), (0, 0), (1, 3), (size - 4, 4), (size - 4, 400), (size, 1),
              (size + 10, 5), (10 ** 30, 1), (0, 10 ** 30), (0, size), (0, size + 1), (-1, 4),
              (4, -1), (-5, -5), ("0x10", "0x10"), (" 16 ", "0b100"), ("1_6", 2), ("x", 1),
              (1, "y"), (1.5, 2), (1, 2.5), (True, 1), (1, True), (False, 1), (1, False),
              ("", ""), (None, ""), ("", None), (0, None), ([], 1), ([1], 1), (1, [2]), ({}, 1),
              (0.0, 3), (1, 0.0), ("\u0661\u0660", 2), (2, "+3"), ("-0", 2), ("0", "-0"),
              (5, 1e3), (2 ** 64, 2 ** 64), (-2 ** 70, 1)]
    for offset, length in ranges:
        source = {"kind": "file", "path": elf}
        if offset is not None:
            source["offset"] = offset
        if length is not None:
            source["length"] = length
        status, result = both("decode", {"source": source, "recipe": [{"op": "to-hex"}]})
        assert status == 200
    status, result = both("decode", {"source": {"kind": "file", "path": elf, "offset": 1,
                                                "length": 3}})
    assert result["text"] == "ELF" and result["looks_like"] == "printable text"
    status, result = both("decode", {"source": {"kind": "file", "path": elf}})
    assert result["size"] == size and result["looks_like"] == "ELF program"
    status, result = both("decode", {"source": {"kind": "file", "path": elf, "offset": -1}})
    assert result["ok"] is False and result["error"] == "offset must not be negative"
    status, result = both("decode", {"source": {"kind": "file", "path": elf, "length": -1}})
    assert result["error"] == "length must not be negative"
    status, result = both("decode", {"source": {"kind": "file", "path": elf, "offset": "q"}})
    assert result["error"] == "offset must be a number, not 'q'"
    for name in ("hello_pe64.exe", "hello_elf64"):
        both("decode/solve", {"source": {"kind": "file", "path": str(fixture_path(name)),
                                         "offset": 64, "length": 300}, "name": "xor-single"})


def test_file_source_errors_match_python(both, tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("plain text, not a program\n" * 3)
    for source in ({"kind": "file"}, {"kind": "file", "path": ""}, {"kind": "file", "path": None},
                   {"kind": "file", "path": 0}, {"kind": "file", "path": []},
                   # not text, or text no file can be named with
                   {"kind": "file", "path": 5}, {"kind": "file", "path": ["a"]},
                   {"kind": "file", "path": {"a": 1}}, {"kind": "file", "path": True},
                   {"kind": "file", "path": 1.5}, {"kind": "file", "path": "a\x00b"},
                   {"kind": "file", "path": "\x00"}, {"kind": "file", "path": "\ud800"},
                   {"kind": "file", "path": str(tmp_path / "x\udfffy")},
                   {"kind": "file", "path": str(tmp_path / "missing")},
                   {"kind": "file", "path": str(notes)},
                   {"kind": "file", "path": str(tmp_path / "missing"), "offset": "bad"}):
        for route, extra in (("decode", {"recipe": [{"op": "nothing"}]}),
                             ("decode/solve", {"name": "nothing"})):
            status, result = both(route, dict(extra, source=source))
            assert status in (400, 404) and set(result) == {"error"}, source


# --- the 64 MiB cap and decompression bombs --------------------------------------

def zero_bomb(megabytes, wbits=15):
    """A stream that inflates to `megabytes` MiB of zeros, made a megabyte at
    a time so that the test never holds the expanded form."""
    co = zlib.compressobj(9, zlib.DEFLATED, wbits)
    parts = [co.compress(b"\x00" * (1 << 20)) for _ in range(megabytes)]
    return b"".join(parts) + co.flush()


def limit_memory(megabytes):
    def apply():
        resource.setrlimit(resource.RLIMIT_AS, (megabytes << 20, megabytes << 20))
    return apply


def test_decompression_bomb_is_refused_not_expanded(c_binary, tmp_path):
    """Half a megabyte that would inflate to half a gigabyte: refused, and
    (with the plain build, whose memory can be capped) in a process that may
    not have more than 300 MiB."""
    sanitized = "asan" in c_binary.name
    for op, wbits in (("zlib-inflate", 15), ("gunzip", 31), ("raw-inflate", -15)):
        bomb = tmp_path / f"bomb-{op}"
        bomb.write_bytes(zero_bomb(512, wbits))
        assert bomb.stat().st_size < (1 << 20)
        start = time.time()
        code, out, err = run_c(c_binary, "--json", "decode", "--file", bomb, "--recipe", op,
                               preexec_fn=None if sanitized else limit_memory(300))
        assert code == 1 and err == "", err[-2000:]
        result = json.loads(out)
        assert result["ok"] is False and result["error"] == "output too large"
        assert result["steps"] == [] and result["size"] == bomb.stat().st_size
        assert time.time() - start < (120 if sanitized else 20)


def test_cap_is_the_same_in_both_editions(both):
    # Just over the cap is refused by both, whatever came before it.
    over = zero_bomb(65)
    refused(both, over, [("zlib-inflate", {})], "output too large")
    result = refused(both, over, [("to-hex", {}), ("from-hex", {}), ("zlib-inflate", {}),
                                  ("to-hex", {})], "output too large")
    assert [step["op"] for step in result["steps"]] == ["to-hex", "from-hex"]
    refused(both, zero_bomb(70, 31), [("gunzip", {})], "output too large")
    refused(both, zero_bomb(66, -15), [("raw-inflate", {})], "output too large")
    # damage that comes before the cap is reached is reported as damage
    co = zlib.compressobj(9)
    stream = co.compress(b"\x00" * (10 << 20)) + co.flush()
    refused(both, stream[:-3] + b"\x00\x00\x00", [("zlib-inflate", {})], "incorrect data check")
    # ... and so is damage in the megabyte that would have crossed it
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = b"".join(co.compress(b"\x00" * (1 << 20)) for _ in range(64)) \
        + co.compress(b"\x00" * 5000) + co.flush(zlib.Z_SYNC_FLUSH)
    refused(both, stream + b"\x07", [("raw-inflate", {})], "invalid block type")
    refused(both, stream + b"\x01\x00\x00\xff\xff", [("raw-inflate", {})], "output too large")


def test_results_at_the_cap(c_binary, tmp_path):
    """Exactly 64 MiB passes, one byte more does not: for a source, for an
    encoder and for a decompressor."""
    cap = 64 << 20
    exact = tmp_path / "exact"
    exact.write_bytes(zero_bomb(64))
    result = json.loads(run_c(c_binary, "--json", "decode", "--file", exact, "--recipe",
                              "zlib-inflate|hash:algo=crc32")[1])
    assert result["ok"] and result["steps"][0] == {"op": "zlib-inflate", "size": cap}
    assert result["text"] == "%08x" % zlib.crc32(b"\x00" * cap)
    co = zlib.compressobj(9)
    one_more = tmp_path / "one-more"
    one_more.write_bytes(b"".join(co.compress(b"\x00" * (1 << 20)) for _ in range(64))
                         + co.compress(b"\x00") + co.flush())
    result = json.loads(run_c(c_binary, "--json", "decode", "--file", one_more, "--recipe",
                              "zlib-inflate")[1])
    assert result["ok"] is False and result["error"] == "output too large"
    big = tmp_path / "big"
    with open(big, "wb") as f:
        f.truncate(cap + 1)
    code, out, err = run_c(c_binary, "--json", "decode", "--file", big)
    assert code == 1 and json.loads(out) == {
        "ok": False, "size": 0, "hex": "", "text": "", "looks_like": "empty", "steps": [],
        "error": "output too large"}
    code, head, tail, size, err = run_c_to_file(
        c_binary, tmp_path, "decode", "--file", big, "--length", cap // 2 + 1, "--recipe", "to-hex")
    assert code == 1 and err == "" and head.startswith("error: output too large\n\x00\x00")
    assert tail.endswith(f"\n{cap // 2 + 1} bytes \xb7 looks like binary\n")
    code, out, err = run_c(c_binary, "decode", "--file", big, "--length", cap // 2, "--recipe",
                           "to-hex|hash:algo=md5")
    assert code == 0 and out.startswith("steps: to-hex -> hash\n")
    for recipe in ("to-base64", "to-base32", "to-base85", "to-hex", "url-encode",
                   "charset-decode:from=latin-1"):
        # 64 MiB of 0xFF: every encoding of it is larger than the cap
        code, head, tail, size, err = run_c_to_file(
            c_binary, tmp_path, "decode", "--file", big, "--offset", 1, "--recipe",
            f"xor:key=ff|{recipe}")
        assert code == 1 and err == "", recipe
        assert head.startswith("steps: xor\nerror: output too large\n\ufffd\ufffd"), recipe
        assert tail.endswith(f"\n{cap} bytes \xb7 looks like binary\n"), recipe
    # a solver looks at the first 64 KiB, however large the source is
    code, out, err = run_c(c_binary, "--json", "decode", "--file", big, "--solve", "substitution")
    assert code == 0 and json.loads(out)["candidates"][0]["size"] == 1 << 16


# --- damaged streams and encodings -------------------------------------------------

def deflate_streams():
    rng = random.Random(11)
    noise = bytes(rng.randrange(256) for _ in range(300))
    payloads = [b"", b"a", b"hello hello hello hello", ENGLISH * 3, noise, b"\x00" * 5000,
                ENGLISH + noise + ENGLISH[::-1]]
    streams = []
    for payload in payloads:
        for level in (0, 1, 6, 9):
            for strategy in (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED, zlib.Z_HUFFMAN_ONLY):
                co = zlib.compressobj(level, zlib.DEFLATED, -15, 8, strategy)
                streams.append(co.compress(payload) + co.flush())
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    streams.append(co.compress(ENGLISH) + co.flush(zlib.Z_SYNC_FLUSH) + co.compress(noise)
                   + co.flush(zlib.Z_FULL_FLUSH) + co.compress(ENGLISH) + co.flush())
    return streams


def gzip_with_header(payload, extra=None, name=None, comment=None, header_crc=False, flags=0):
    raw = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = raw.compress(payload) + raw.flush()
    flags |= (4 if extra is not None else 0) | (8 if name is not None else 0) \
        | (16 if comment is not None else 0) | (2 if header_crc else 0)
    head = b"\x1f\x8b\x08" + bytes([flags]) + b"\x00\x00\x00\x00\x02\xff"
    if extra is not None:
        head += struct.pack("<H", len(extra)) + extra
    if name is not None:
        head += name + b"\x00"
    if comment is not None:
        head += comment + b"\x00"
    if header_crc:
        head += struct.pack("<H", zlib.crc32(head) & 0xFFFF)
    return head + body + struct.pack("<II", zlib.crc32(payload), len(payload) & 0xFFFFFFFF)


def test_truncated_and_damaged_streams_match_python(both):
    """Every stream cut at every length, and damaged at every byte: zlib's
    answer (what came out so far, or its error message) must be reproduced."""
    rng = random.Random(5)
    checked = 0
    for stream in deflate_streams()[::3]:
        cuts = range(len(stream) + 1) if len(stream) < 80 else \
            sorted(rng.sample(range(len(stream)), 40))
        for cut in cuts:
            run_both(both, stream[:cut], [("raw-inflate", {})])
            checked += 1
        for _ in range(25):
            damaged = bytearray(stream)
            if not damaged:
                break
            for _ in range(rng.choice((1, 1, 2, 5))):
                at = rng.randrange(len(damaged))
                damaged[at] = rng.choice((damaged[at] ^ (1 << rng.randrange(8)),
                                          rng.randrange(256)))
            run_both(both, damaged, [("raw-inflate", {})])
            checked += 1
    assert checked > 1000


def test_zlib_and_gzip_wrappers_match_python(both):
    rng = random.Random(6)
    payload = ENGLISH * 2
    wrapped = [zlib.compress(payload), zlib.compress(b""), zlib.compress(payload, 0),
               zlib.compress(payload, wbits=9), zlib.compress(payload, wbits=12),
               gzip.compress(payload), gzip.compress(b""), gzip.compress(payload, mtime=1),
               gzip_with_header(payload, extra=b"extra field"),
               gzip_with_header(payload, name=b"file.txt"),
               gzip_with_header(payload, comment=b"a comment"),
               gzip_with_header(payload, header_crc=True),
               gzip_with_header(payload, extra=b"\x01\x02", name=b"n", comment=b"c",
                                header_crc=True),
               gzip_with_header(payload, extra=b""), gzip_with_header(payload, name=b""),
               gzip_with_header(payload, flags=1), gzip_with_header(payload, flags=0x20),
               gzip_with_header(payload, flags=0x80),
               gzip.compress(payload) + gzip.compress(b"second member"),
               zlib.compress(payload) + b"trailing bytes", gzip.compress(payload) + b"\x00" * 9,
               b"\x78\x9c", b"\x78", b"\x1f", b"\x1f\x8b", b"\x1f\x8b\x08", b"\x1f\x8b\x09\x00",
               b"\x78\xbb" + zlib.compress(payload)[2:], b"\x78\xbb\x00\x00",
               b"\x78\xbb\x00\x00\x00\x00", b"\x78\xbb\x00\x00\x00\x00\x4b",
               b"\x88\x1c" + zlib.compress(payload)[2:], b"\x79\x9c", b"\x08\x1d", b"\x00\x00",
               b"\x77\x9d", b"\x0f\x01", b"hello world", b"\x00", b"\xff" * 20]
    co = zlib.compressobj(9, zlib.DEFLATED, 15, zdict=b"the quick brown fox")
    wrapped.append(co.compress(payload) + co.flush())
    for stream in wrapped:
        for op in ("zlib-inflate", "gunzip", "raw-inflate"):
            run_both(both, stream, [(op, {})])
        for cut in range(len(stream)):
            for op in ("zlib-inflate", "gunzip"):
                run_both(both, stream[:cut], [(op, {})])
        for _ in range(60):
            damaged = bytearray(stream)
            at = rng.randrange(len(damaged))
            damaged[at] ^= 1 << rng.randrange(8)
            for op in ("zlib-inflate", "gunzip"):
                run_both(both, damaged, [(op, {})])
    refused(both, zlib.compress(payload)[:-1] + b"\x00", [("zlib-inflate", {})],
            "Error -3 while decompressing data: incorrect data check")
    refused(both, gzip.compress(payload)[:-1] + b"\x7f", [("gunzip", {})],
            "incorrect length check")
    refused(both, gzip.compress(payload)[:-5] + b"\x7f\x00\x00\x00\x00", [("gunzip", {})],
            "incorrect data check")
    refused(both, gzip_with_header(payload, header_crc=True).replace(b"\x02\xff", b"\x02\xfe", 1),
            [("gunzip", {})], "header crc mismatch")
    refused(both, wrapped[-1], [("zlib-inflate", {})], "Error 2 while decompressing data")
    refused(both, b"\x00\x00\x00\x00\x00", [("raw-inflate", {})],
            "invalid stored block lengths")
    refused(both, b"\x07", [("raw-inflate", {})], "invalid block type")
    # cut short is not an error: what there is comes out
    result = expect(both, zlib.compress(payload)[:-4], [("zlib-inflate", {})], payload)
    result = run_both(both, gzip.compress(PLAIN["long"])[:200], [("gunzip", {})])
    assert result["ok"] and 0 < result["size"] < len(PLAIN["long"])
    expect(both, b"", [("gunzip", {})], b"")
    expect(both, b"", [("raw-inflate", {})], b"")


def mutations(rng, data, count, alphabet=None):
    """`data` and `count` damaged copies of it: a byte changed, dropped,
    doubled or inserted, the end cut off."""
    yield bytes(data)
    alphabet = alphabet or bytes(range(256))
    for _ in range(count):
        out = bytearray(data)
        for _ in range(rng.choice((1, 1, 1, 2, 3))):
            kind = rng.randrange(5)
            at = rng.randrange(len(out) + 1)
            if kind == 0 and out:
                out[at % len(out)] = rng.choice(alphabet)
            elif kind == 1 and out:
                del out[at % len(out)]
            elif kind == 2:
                out.insert(at, rng.choice(alphabet))
            elif kind == 3:
                out.insert(at, rng.randrange(256))
            else:
                del out[at:]
        yield bytes(out)


def test_damaged_encodings_match_python(both):
    """Text encodings with characters changed, dropped and added: the same
    bytes, or the same complaint, from both editions."""
    rng = random.Random(3)
    samples = [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar", b"\x00\x00\x00\x00",
               b"\x00" * 9, b"\xff" * 7, b"    ", ENGLISH[:37], UNICODE_TEXT,
               bytes(rng.randrange(256) for _ in range(61))]
    b64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_= \n\t\r\x0b\x0c"
    checked = 0
    for raw in samples:
        padded = raw + b"\x00" * (-len(raw) % 4)
        cases = [
            (base64.b64encode(raw), "from-base64", {}, b64),
            (base64.b64encode(raw), "from-base64", {"alphabet": "url"}, b64),
            (base64.urlsafe_b64encode(raw), "from-base64", {"alphabet": "url"}, b64),
            (base64.b32encode(raw), "from-base32", {},
             b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcxyz234567=018 9\n\x0c"),
            (raw.hex().encode(), "from-hex", {}, b"0123456789abcdefABCDEFxX,: \n\t\x0b\x1c\x85\xa0g"),
            (base64.a85encode(raw), "from-base85", {}, bytes(range(33, 118)) + b"zzyvw{~ \n\t\r\x0b\x0c"),
            (base64.a85encode(raw), "from-base85", {"variant": "ascii85"}, b"!u5stz \x00"),
            (base64.z85encode(padded), "from-base85", {"variant": "z85"},
             decode.base64._z85alphabet + b";_`|~\"', \n\x0c\x00\xff"),
            (urllib.parse.quote_from_bytes(raw).encode(), "url-decode", {}, b"%0123456789abcdefABCDEFg+ "),
            (quopri.encodestring(raw * 4), "qp-decode", {}, b"=0123456789ABCDEFabcdefg\r\n _"),
            (raw.decode("latin-1").encode("utf-16-le"), "charset-decode", {"from": "utf-16le"},
             b"\x00\xd8\xdc\xdf\xdbA"),
            (raw.decode("latin-1").encode("utf-8"), "charset-decode", {},
             b"\x80\xbf\xc2\xe0\xed\xf0\xf4\xa0\x90A"),
        ]
        for encoded, op, params, alphabet in cases:
            for damaged in mutations(rng, encoded, 60, alphabet):
                run_both(both, damaged, [(op, params)])
                checked += 1
    assert checked > 5000
    # the complaints, word for word
    refused(both, b"=abc", [("from-base64", {})], "invalid base64: Leading padding not allowed")
    refused(both, b"ab==cd", [("from-base64", {})], "invalid base64: Excess data after padding")
    refused(both, b"a!bc", [("from-base64", {})], "invalid base64: Only base64 data is allowed")
    refused(both, b"ab=c", [("from-base64", {})],
            "invalid base64: Discontinuous padding not allowed")
    refused(both, b"abcde", [("from-base64", {})],
            "number of data characters (5) cannot be 1 more than a multiple of 4")
    refused(both, b"a-b_", [("from-base64", {})], "Only base64 data is allowed")
    refused(both, b"MZXW6Y==", [("from-base32", {})], "invalid base32: Incorrect padding")
    refused(both, b"MZXW1YQ=", [("from-base32", {})], "invalid base32: Non-base32 digit found")
    refused(both, b"abc", [("from-hex", {})], "hex needs an even number of digits")
    refused(both, b"zz", [("from-hex", {})], "not valid hex")
    refused(both, b"ab\x00cd", [("from-base85", {})],
            "invalid base85: Non-Ascii85 digit found: \x00")
    refused(both, b"ab\xe9cd", [("from-base85", {})],
            "invalid base85: Non-Ascii85 digit found: \u00e9")
    refused(both, b"abz", [("from-base85", {})], "invalid base85: z inside Ascii85 5-tuple")
    refused(both, b"uuuuu", [("from-base85", {})], "invalid base85: Ascii85 overflow")
    refused(both, b"ab~cd", [("from-base85", {"variant": "z85"})],
            "invalid base85: bad z85 character at position 2")
    refused(both, b"#####", [("from-base85", {"variant": "z85"})],
            "invalid base85: z85 overflow in hunk starting at byte 0")
    refused(both, b"abc", [("to-base85", {"variant": "z85"})],
            "z85 needs a length that is a multiple of 4 bytes")
    refused(both, b"abc", [("to-base85", {"variant": "b85"})], "variant must be ascii85 or z85")
    refused(both, b"abc", [("from-base85", {"variant": "b85"})], "variant must be ascii85 or z85")
    refused(both, b"abc", [("to-base64", {"alphabet": "URL"})], "alphabet must be std or url")
    refused(both, b"abc", [("rot-n", {"n": "26"})], "n must be between 0 and 25")
    refused(both, b"abc", [("rot-n", {"n": "-1"})], "n must be between 0 and 25")
    refused(both, b"abc", [("rot-n", {"n": "1.0"})], "n must be a number, not '1.0'")
    refused(both, b"abc", [("rot-n", {"n": "9" * 4301})], "n must be a number, not '999")
    refused(both, b"abc", [("rot-n", {"n": "9" * 4300})], "n must be between 0 and 25")
    refused(both, b"abc", [("vigenere", {"key": "123 !?"})], "vigenere needs a key of letters")
    refused(both, b"abc", [("vigenere", {"key": "k", "mode": "both"})],
            "mode must be decrypt or encrypt")
    refused(both, b"abc", [("xor", {})], "xor needs a key (key=HEX or key_text=TEXT)")
    refused(both, b"abc", [("xor", {"key": "0x"})], "xor needs a non-empty key")
    refused(both, b"abc", [("xor", {"key": "0x4"})], "hex needs an even number of digits")
    refused(both, b"abc", [("xor", {"key": "gg"})], "not valid hex")
    refused(both, b"abc", [("railfence", {"rails": "1"})], "rails must be at least 2")
    refused(both, b"abc", [("railfence", {"rails": "-4", "mode": "x"})],
            "rails must be at least 2")
    refused(both, b"abc", [("railfence", {"rails": "2", "mode": "x"})],
            "mode must be decrypt or encrypt")
    refused(both, b"abc", [("railfence", {"rails": "two"})], "rails must be a number, not 'two'")
    for bad_map in ("ABC", "ABCDEFGHIJKLMNOPQRSTUVWXYA", "ABCDEFGHIJKLMNOPQRSTUVWXYZA",
                    "abcdefghijklmnopqrstuvwxyZ" + "z"):
        refused(both, b"abc", [("substitution", {"map": bad_map})],
                "map must be a 26-letter permutation of the alphabet")
    expect(both, b"Abc xyz", [("substitution", {"map": "z y x w v u t s r q p o n m l k j i h g "
                                                       "f e d c b a 123 !"})], b"Zyx cba")


def test_letters_of_any_script_in_keys_and_maps(both):
    """Python takes every Unicode letter for a Vigenere key and a substitution
    map; so does the C edition."""
    data = b"Attack at dawn, said Zo\xc3\xab."
    for key in ("cl\u00e9", "\u00e9", "\u0391\u03b2\u03b3", "\u65e5\u672c", "k\u0131z", "\u01c5",
                "\u217b", "a\u0300b", "\U0001d400\U0001d41a", "\u00aa\u00ba", "x\u00b5y",
                "\u1e9e", "\u017f", "\u0149n"[1:], "\ua7b5"):
        for mode in ("encrypt", "decrypt"):
            run_both(both, data, [("vigenere", {"key": key, "mode": mode})])
    # U+017F (long s) is a letter whose upper case is "S"
    long_s = "abcdefghijklmnopqr\u017ftuvwxyz"
    expect(both, b"Stressed", [("substitution", {"map": long_s})], b"Stressed")
    refused(both, b"abc", [("substitution", {"map": long_s + "s"})], "map must be a 26-letter")
    refused(both, b"abc", [("substitution", {"map": "abcdefghijklmnopqrs\u017ftuvwxyz"[:26]})],
            "map must be a 26-letter")
    # 26 letters that are not A to Z: fine while no letter needs them
    greek = "\u03b1\u03b2\u03b3\u03b4\u03b5\u03b6\u03b7\u03b8\u03b9\u03ba\u03bb\u03bc\u03bd" \
            "\u03be\u03bf\u03c0\u03c1\u03c3\u03c4\u03c5\u03c6\u03c7\u03c8\u03c9\u03ac\u03ad"
    expect(both, b"1234 !?", [("substitution", {"map": greek})], b"1234 !?")
    half = "abcdefghijklm" + greek[:13]
    expect(both, b"Abc 123 mlk", [("substitution", {"map": half})], b"Abc 123 mlk")
    # ... and a failed step at the first letter that needs them (Python once
    # stopped there with a KeyError)
    for data in (b"Hello nop", b"abc", b"xyz", b"Abc 123 mlk z"):
        for mapping in (greek, half):
            if mapping is greek or any(ch in data.lower() for ch in b"nopqrstuvwxyz"):
                refused(both, data, [("to-hex", {}), ("from-hex", {}),
                                     ("substitution", {"map": mapping})],
                        "map must be a 26-letter permutation of the alphabet")
    # a key letter whose upper case is two letters (or three) is no key letter
    # (Python once stopped there with a TypeError)
    for key in ("stra\u00dfe", "\u00df", "\ufb01", "\u0390", "key\ufb01", ["\u00df"]):
        for mode in ("encrypt", "decrypt"):
            result = refused(both, b"Hello nop", [("vigenere", {"key": key, "mode": mode})],
                             "vigenere needs a key of letters")
            assert result["error"] == "vigenere needs a key of letters"
    refused(both, b"Hello", [("vigenere", {"key": "\u00df", "mode": "x"})],
            "mode must be decrypt or encrypt")


# --- solvers --------------------------------------------------------------------

def solve_both(both, data, name):
    status, result = both("decode/solve", {"source": hex_source(data), "name": name})
    assert status == 200
    return result


def solver_inputs():
    rng = random.Random(21)
    key = b"SECRET"
    texts = {
        "english": ENGLISH,
        "caesar-7": decode.apply_op("rot-n", {"n": 7}, ENGLISH),
        "xor-5a": bytes(c ^ 0x5A for c in ENGLISH),
        "xor-secret": bytes(c ^ key[i % 6] for i, c in enumerate(ENGLISH * 4)),
        "xor-two": bytes(c ^ b"\x13\x37"[i % 2] for i, c in enumerate(ENGLISH)),
        "substituted": decode.apply_op("substitution", {"map": "QWERTYUIOPASDFGHJKLZXCVBNM"},
                                       ENGLISH * 3).translate(bytes.maketrans(b"QW", b"WQ")),
        "pangram": b"The quick brown fox jumps over the lazy dog and keeps running",
        "mixed": b"Hello, World! 123 \x00\xff\x80 tab\there\r\nnew line",
        "empty": b"", "one": b"a", "two": b"ab", "three": b"abc", "nul": b"\x00",
        "spaces": b" " * 40, "zz": b"zz", "the": b"the", "same": b"\xaa" * 100,
        "non-ascii": UNICODE_TEXT, "every-byte": bytes(range(256)),
        "random": bytes(rng.randrange(256) for _ in range(512)),
        "random-short": bytes(rng.randrange(256) for _ in range(9)),
        "random-letters": bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz ") for _ in range(300)),
        "ties": b"ab" * 30 + b"ba" * 30,
        "periodic": bytes(c ^ b"ABAB"[i % 4] for i, c in enumerate(ENGLISH * 2)),
        "odd-80": (ENGLISH * 2)[:81], "exact-80": (ENGLISH * 2)[:80],
    }
    return texts


@pytest.mark.parametrize("name", SOLVERS)
def test_solver_matches_python(both, name):
    for label, data in solver_inputs().items():
        result = solve_both(both, data, name)
        assert result["ok"] and result["error"] is None, label
        assert len(result["candidates"]) <= 20
        for found in result["candidates"]:
            assert 0.0 <= found["score"] <= 1.0
            assert found["size"] == len(data) and found["hex"] == \
                bytes.fromhex(found["hex"]).hex()


def test_solvers_find_what_was_hidden(both):
    inputs = solver_inputs()
    best = solve_both(both, inputs["caesar-7"], "caesar")["candidates"][0]
    assert best["params"] == {"n": 19} and best["text"] == ENGLISH.decode()
    best = solve_both(both, inputs["xor-5a"], "xor-single")["candidates"][0]
    assert best["params"] == {"key": "5a"} and best["text"] == ENGLISH.decode()
    best = solve_both(both, inputs["xor-secret"], "xor-keylen")["candidates"][0]
    assert best["params"] == {"key": b"SECRET".hex(), "keylen": 6}
    best = solve_both(both, inputs["xor-two"], "xor-keylen")["candidates"][0]
    assert best["params"] == {"key": "1337", "keylen": 2}
    found = solve_both(both, inputs["substituted"], "substitution")["candidates"]
    assert len(found) == 1 and sorted(found[0]["params"]["map"]) == list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def test_solver_scores_are_the_same_floats(c_client, py_client):
    """Not just equal after parsing: the same digits in the JSON, so the
    score is the same double, rounded and written the same way."""
    seen = set()
    for label, data in solver_inputs().items():
        for name in SOLVERS:
            body = json.dumps({"source": hex_source(data), "name": name}).encode()
            raw = []
            for client in (c_client, py_client):
                conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=300)
                conn.request("POST", "/api/decode/solve", body=body,
                             headers={"X-Vex-Token": client.token})
                raw.append(conn.getresponse().read().decode())
                conn.close()
            scores = [re.findall(r'"score": ?([^,}\s]+)', text) for text in raw]
            assert scores[0] == scores[1], (label, name)
            assert [c["params"] for c in json.loads(raw[0])["candidates"]] == \
                [c["params"] for c in json.loads(raw[1])["candidates"]]
            seen.update(scores[0])
    assert len(seen) > 100 and "0.0" in seen


def test_solver_scores_small_enough_for_an_exponent(c_client, py_client):
    """repr() writes a float below 0.0001 as 1.2e-05: one printable byte
    among thousands that are not gives such scores."""
    tokens = []
    for size in (5000, 6001, 7000, 20000, 30000, 40000, 50000, 60000, 65536):
        data = b"!" + b"\x80" * (size - 1)
        body = json.dumps({"source": hex_source(data), "name": "substitution"}).encode()
        raw = []
        for client in (c_client, py_client):
            conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=300)
            conn.request("POST", "/api/decode/solve", body=body,
                         headers={"X-Vex-Token": client.token})
            raw.append(re.findall(r'"score": ?([^,}\s]+)', conn.getresponse().read().decode()))
            conn.close()
        assert raw[0] == raw[1] and len(raw[0]) == 1
        tokens.append(raw[0][0])
    assert tokens == ["0.00012", "0.0001", "8.6e-05", "3e-05", "2e-05", "1.5e-05", "1.2e-05",
                      "1e-05", "9e-06"]


def test_solvers_on_random_bytes(both):
    rng = random.Random(1234)
    for round_ in range(60):
        size = rng.choice((0, 1, 2, 3, 5, 8, 40, 79, 80, 81, 200, 700))
        kind = rng.randrange(4)
        if kind == 0:
            data = bytes(rng.randrange(256) for _ in range(size))
        elif kind == 1:
            data = bytes(rng.choice(b"etaoin shrdlu ETAOIN.,\n") for _ in range(size))
        elif kind == 2:
            key = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9)))
            text = (ENGLISH * 6)[:size]
            data = bytes(c ^ key[i % len(key)] for i, c in enumerate(text))
        else:
            data = bytes(rng.choice((0x20, 0x41, 0x7A, 0x00, 0xFF)) for _ in range(size))
        for name in SOLVERS:
            assert solve_both(both, data, name)["ok"]


def test_solver_errors(both):
    for name in ("nope", "", "Caesar", None, 5, 1.5, True, ["caesar"], {"a": 1}, "caf\u00e9",
                 "it's", "\x00"):
        status, result = both("decode/solve", {"source": hex_source(b"abc"), "name": name})
        assert status == 200 and result["ok"] is False and result["candidates"] == []
        assert result["error"].startswith("unknown solver: ")
    status, result = both("decode/solve", {"source": hex_source(b"abc")})
    assert result["error"] == "unknown solver: 'None'"
    # the solver is looked up before the source is read
    status, result = both("decode/solve", {"source": {"kind": "hex", "value": "zz"},
                                           "name": "nope"})
    assert result["error"] == "unknown solver: 'nope'"
    status, result = both("decode/solve", {"source": {"kind": "hex", "value": "zz"},
                                           "name": "caesar"})
    assert result == {"ok": False, "candidates": [], "error": "not valid hex"}
    status, result = both("decode/solve", {"source": {"kind": "base64", "value": "!"},
                                           "name": "xor-keylen"})
    assert result["ok"] is False and result["error"].startswith("invalid base64: ")


def test_solver_looks_at_the_first_64_kib(both):
    data = (ENGLISH * 700)[:70000]
    for name in ("caesar", "substitution"):
        found = solve_both(both, data, name)["candidates"]
        assert found[0]["size"] == 1 << 16


# --- looks_like -------------------------------------------------------------------

def test_looks_like_matches_python(both):
    pe = fixture_bytes("hello_pe64.exe")
    samples = [b"", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, b"\x89PNG\r\n\x1a", gzip.compress(b"x"),
               b"\x1f\x8b", b"\x1f", b"BZh91AY", b"BZ", b"\xfd7zXZ\x00\x00", b"\xfd7zXZ",
               b"PK\x03\x04rest", b"PK\x05\x06", b"PK\x07\x08", b"\x7fELF\x02", b"\x7fEL",
               b"%PDF-1.7", b"%PDF", b"\xff\xd8\xff\xe0", b"\xff\xd8", b"GIF87a", b"GIF89a",
               b"GIF88a", b"%!PS-Adobe", b"%!", b"%", pe, pe[:0x40], pe[:0x3f], pe[:0x100],
               b"MZ", b"M", b"MZ" + b"\x00" * 62, b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00PE\x00\x00",
               b"MZ" + b"\x00" * 58 + b"\x3d\x00\x00\x00PE\x00\x00",
               b"MZ" + b"\x00" * 58 + b"\x41\x00\x00\x00PE\x00\x00",
               b"MZ" + b"\x00" * 58 + b"\xff\xff\xff\xffPE\x00\x00",
               b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00PE\x00",
               b"just some plain readable text\n", b"\t\r\n", b"\x0b", b"a" * 19 + b"\x00",
               b"a" * 18 + b"\x00", b"a" * 20 + b"\x00", b"a" * 95 + b"\x7f" * 5,
               b"a" * 94 + b"\x7f" * 6, bytes([0, 1, 2, 3, 255, 254, 7, 8]), UNICODE_TEXT, b" "]
    seen = set()
    for data in samples:
        seen.add(run_both(both, data, [])["looks_like"])
    assert seen == {"empty", "PNG image", "gzip", "bzip2", "xz", "zip archive", "ELF program",
                    "PDF document", "JPEG image", "GIF image", "PostScript", "PE program",
                    "DOS executable", "printable text", "binary"}


# --- the command line ---------------------------------------------------------------

def test_cli_text_output_matches_python(c_binary, tmp_path):
    blob = base64.b64encode(gzip.compress(b"chained!")).decode()
    binary = tmp_path / "blob.bin"
    binary.write_bytes(bytes(range(256)) * 3)
    for args in (
            ["decode", "aGVsbG8=", "--recipe", "from-base64"],
            ["decode", "--text", blob, "--recipe", "from-base64|gunzip"],
            ["decode", "--hex", "48656c6c6f"],
            ["decode", "--hex", "48 65:6c,0x6c 6f", "--recipe", " to-hex | rot13 "],
            ["decode", "--base64", "aGVsbG8"],
            ["decode", "--base64", "aGVs\nbG8=", "--recipe", "to-base32"],
            ["decode", ""], ["decode", "--text", ""], ["decode", "--hex", ""],
            ["decode", "\n\nleading line breaks go"], ["decode", "\n"], ["decode", "\n\n\n"],
            ["decode", "x\n"], ["decode", "--hex", "0a0a41"], ["decode", "--hex", "0a"],
            ["decode", "caf\u00e9 \u2603 \U0001f600"], ["decode", "--hex", "fffe00410d0a1b5b"],
            ["decode", "tab\there"], ["decode", "--file", binary],
            ["decode", "--file", binary, "--offset", "250", "--length", "20"],
            ["decode", "--file", binary, "--offset", "0x100", "--length", "0x101"],
            ["decode", "--file", binary, "--length", "256"],
            ["decode", "--file", binary, "--length", "257"],
            ["decode", "--file", binary, "--offset", "9999"],
            ["decode", "--file", binary, "--offset", "-1"],
            ["decode", "--file", binary, "--length", "-1"],
            ["decode", "--file", binary, "--offset", "9" * 40, "--length", "9" * 40],
            ["decode", "--file", binary, "--recipe", "hash"],
            ["decode", "--file", fixture_path("hello_pe64.exe"), "--length", "1024"],
            ["decode", "--file", fixture_path("hello_elf64"), "--recipe", "hash:algo=sha1"],
            ["decode", "abc", "--offset", "5", "--length", "1"],
            ["decode", "--text", "one", "two"],
            ["decode", "--text", "plain", "--recipe", "to-hex|gunzip"],
            ["decode", "--text", "plain", "--recipe", "gunzip|to-hex"],
            ["decode", "--hex", "zz", "--recipe", "to-hex"],
            ["decode", "--hex", "abc"], ["decode", "--base64", "a"],
            ["decode", "--base64", "=x"], ["decode", "plain", "--recipe", ""],
            ["decode", "plain", "--recipe", "   "],
            ["decode", "Uryyb", "--recipe", "rot-n:n=13"],
            ["decode", "Uryyb", "--recipe", "rot-n:n= 13 ,,"],
            ["decode", "Uryyb", "--recipe", "rot-n: n = 0xd "],
            ["decode", "Uryyb", "--recipe", "rot-n:n=13,n=1"],
            ["decode", "Uryyb", "--recipe", "rot-n:n=99"],
            ["decode", "Uryyb", "--recipe", "rot-n:n="],
            ["decode", "Uryyb", "--recipe", "rot-n:n=x=y"],
            ["decode", "Uryyb", "--recipe", "rot-n:"],
            ["decode", "Uryyb", "--recipe", "rot-n:,"],
            ["decode", "abc", "--recipe", "xor:key="],
            ["decode", "abc", "--recipe", "xor:key=,key_text=k"],
            ["decode", "abc", "--recipe", "xor:key_text=a=b"],
            ["decode", "abc", "--recipe", "vigenere:key=cl\u00e9,mode=encrypt"],
            ["decode", "abc", "--recipe", "vigenere:mode=encrypt"],
            ["decode", "abc", "--recipe", "railfence:rails=\u0663,mode=encrypt"],
            ["decode", "%41%zz", "--recipe", "url-decode|url-encode|to-base85"],
            ["decode", "abc", "--recipe", "from-base85:variant=z85"],
            ["decode", "ab\x01cd", "--recipe", "from-base85"],
            ["decode", "ab\u00e9", "--recipe", "charset-decode:from=latin-1"],
            ["decode", "--hex", "e9", "--recipe", "charset-decode"],
            ["decode", "abc", "--recipe", "hash:algo=crc32|to-hex|from-hex"],
            ["decode", "abc", "--recipe", "chacha20:key=" + "00" * 32 + ",nonce=" + "00" * 12],
            ["decode", "abc", "--recipe", "rc4:key_text= pass word "],
            ["decode", "--text", "x" * 300, "--recipe", "to-hex"],
            ["decode", "--solve", "caesar", "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"],
            ["decode", "--hex", bytes(c ^ 0x2A for c in ENGLISH).hex(), "--solve", "xor-single"],
            ["decode", "--hex", bytes(c ^ b"KEY"[i % 3] for i, c in enumerate(ENGLISH * 3)).hex(),
             "--solve", "xor-keylen"],
            ["decode", "--solve", "substitution", "Gsv jfrxp yildm ulc qfnkh levi gsv ozab wlt"],
            ["decode", "--solve", "caesar", "line one\nline two\r\nand a third line that is "
                                            "long enough to be cut off at sixty characters"],
            ["decode", "--solve", "xor-single", "\u65e5\u672c\u8a9e" * 30],
            ["decode", "--solve", "xor-single", ""], ["decode", "--solve", "xor-keylen", "a"],
            ["decode", "--solve", "nope", "abc"], ["decode", "--solve", "caesar", "--hex", "zz"],
            ["decode", "--solve", "", "abc", "--recipe", "to-hex"],
            ["decode", "--solve", "caesar", "abc", "--recipe", "no-such-op", "--out", "/"],
            ["decode", "--list"], ["decode", "--list", "ignored", "--recipe", "nope"]):
        for prefix in ([], ["--json"], ["--color", "always"]):
            if "--list" in args:
                c, py = run_c(c_binary, *prefix, *args), run_python(*prefix, *args)
                assert c[0] == py[0] == 0 and c[2] == py[2] == ""
                assert _available_everywhere(c[1], prefix) == py[1], prefix
                continue
            code, out, err = same_cli(c_binary, *prefix, *args)
            assert code in (0, 1) and err == ""
            if prefix == ["--json"]:
                assert code == (0 if json.loads(out)["ok"] else 1)


def _available_everywhere(text, prefix):
    """The C edition's --list as the Python edition prints it: nothing
    marked unavailable."""
    if prefix == ["--json"]:
        catalogue = json.loads(text)
        marked = 0
        for group in catalogue["groups"]:
            for op in group["ops"]:
                marked += not op["available"]
                op["available"] = True
        assert marked == len(C_UNAVAILABLE)
        return json.dumps(catalogue, indent=2) + "\n"
    tag = "  (unavailable in this build)"
    if prefix:
        tag = f"\x1b[2m{tag}\x1b[0m"
    assert text.count(tag) == len(C_UNAVAILABLE)
    return text.replace(tag, "")


def test_cli_errors_match_python(c_binary, tmp_path):
    taken = tmp_path / "taken.bin"
    taken.write_bytes(b"keep me")
    for args, status in (
            (["decode"], 1), (["decode", "--recipe", "to-hex"], 1),
            (["decode", "--file", tmp_path / "missing"], 1),
            (["decode", "--file", tmp_path], 1),
            (["decode", "--file", tmp_path / "missing", "--recipe", "nope"], 1),
            (["decode", "abc", "--out", taken], 1),
            (["decode", "abc", "--out", tmp_path], 1),
            (["decode", "abc", "--out", taken, "--recipe", "gunzip"], 1),
            (["decode", "abc", "--recipe", "no-such-op"], 2),
            (["decode", "abc", "--recipe", "to-hex|"], 2),
            (["decode", "abc", "--recipe", "|"], 2),
            (["decode", "abc", "--recipe", "to-hex||rot13"], 2),
            (["decode", "abc", "--recipe", ":n=1"], 2),
            (["decode", "abc", "--recipe", "rot-n:bogus=1"], 2),
            (["decode", "abc", "--recipe", "rot-n:n"], 2),
            (["decode", "abc", "--recipe", "rot-n:n=1, x "], 2),
            (["decode", "abc", "--recipe", "rot-n:=1"], 2),
            (["decode", "abc", "--recipe", "rot-n:N=1"], 2),
            (["decode", "abc", "--recipe", "ROT13"], 2),
            (["decode", "abc", "--recipe", "rot13:n=1"], 2),
            (["decode", "abc", "--recipe", "to-hex | it's"], 2),
            (["decode", "abc", "--recipe", 'say "hi"'], 2),
            (["decode", "abc", "--recipe", "it's \"both\""], 2),
            (["decode", "abc", "--recipe", "caf\u00e9"], 2),
            (["decode", "abc", "--recipe", "tab\there\\"], 2),
            (["decode", "abc", "--recipe", "\u200bzero\u00a0width\x7f"], 2),
            (["decode", "abc", "--recipe", "xor:k\u00e9y=1"], 2),
            (["decode", "abc", "--recipe", "xor: key text =1"], 2),
            (["decode", "abc", "--recipe", "aes:bogus=1"], 2),
            (["decode", "abc", "--recipe", "des:key=00,nope=1"], 2),
            (["decode", "abc", "--recipe", "nope", "--out", taken], 2),
            (["decode", "--hex", "zz", "--recipe", "nope"], 2)):
        c, py = run_c(c_binary, *args), run_python(*args)
        assert c == py, args
        assert c[0] == status and c[1] == "" and c[2].startswith("vex: error: "), args
    assert taken.read_bytes() == b"keep me"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["taken.bin"]


def test_cli_usage_errors(c_binary, tmp_path):
    for args, message in (
            (["decode", "--text", "a", "--hex", "00"],
             "argument --hex: not allowed with argument --text"),
            (["decode", "--file", "x", "--base64", "YQ==", "--text", "a"],
             "argument --base64: not allowed with argument --file"),
            (["decode", "--hex", "00", "--text", "a", "--list"],
             "argument --text: not allowed with argument --hex"),
            (["decode", "abc", "--offset", "x"], "argument --offset: invalid _int value: 'x'"),
            (["decode", "abc", "--length", "1.5"], "argument --length: invalid _int value: '1.5'"),
            (["decode", "abc", "--length", ""], "argument --length: invalid _int value: ''"),
            (["decode", "abc", "--offset", "08"], "argument --offset: invalid _int value: '08'"),
            (["decode", "--list", "--offset", "it's"],
             "argument --offset: invalid _int value: \"it's\""),
            (["decode", "one", "two"], "unrecognized arguments: two"),
            (["decode", "abc", "--bogus"], None), (["decode", "abc", "--recipe"], None),
            (["decode", "abc", "--list=1"], None), (["decode", "--solve"], None),
            (["decode", "abc", "--o", "x"], None)):
        c, py = run_c(c_binary, *args), run_python(*args)
        assert c[0] == py[0] == 2 and c[1] == py[1] == "", args
        if message:
            assert c[2].endswith(f"error: {message}\n"), c[2]
            assert py[2].endswith(f"error: {message}\n"), py[2]
    assert list(tmp_path.iterdir()) == []
    help_text = run_c(c_binary, "--help")[1]
    assert "decode SOURCE [--recipe SPEC] [--out FILE]" in help_text
    assert "decode --list" in help_text


def test_cli_accepts_what_argparse_accepts(c_binary):
    for args in (["decode", "--rec", "to-hex", "abc"], ["decode", "--recipe=to-hex", "abc"],
                 ["decode", "--te", "abc", "--re=to-hex"], ["decode", "--", "--text"],
                 ["decode", "--text=--hex"], ["decode", "-5"], ["decode", "--text", "-5"],
                 ["decode", "--hex", "41", "--hex", "42"], ["decode", "--li"],
                 ["decode", "abc", "--recipe", "to-hex", "--recipe", "rot13"],
                 ["decode", "--offset", "0x_1", "--length", " 2 ", "abc"],
                 ["decode", "abc", "--offset", "\u0663", "--length", "0_0"]):
        if "--li" in args:
            assert run_c(c_binary, *args)[0] == run_python(*args)[0] == 0
            continue
        same_cli(c_binary, *args)


def test_cli_out_writes_the_bytes_and_never_overwrites(c_binary, tmp_path):
    for label, (run, folder) in {"c": (lambda *a: run_c(c_binary, *a), tmp_path / "c"),
                                 "py": (run_python, tmp_path / "py")}.items():
        folder.mkdir()
        dest = folder / "out.bin"
        code, out, err = run("decode", "--hex", "deadbeef00ff", "--recipe", "reverse", "--out", dest)
        assert (code, out, err) == (0, f"wrote 6 bytes to {dest}\n", "")
        assert dest.read_bytes() == bytes.fromhex("ff00efbeadde")
        code, out, err = run("decode", "--hex", "00", "--out", dest)
        assert (code, out, err) == (1, "", f"vex: error: {dest} exists\n")
        assert dest.read_bytes() == bytes.fromhex("ff00efbeadde")
        # nothing is written when the recipe fails, and the result is shown
        failed = folder / "failed.bin"
        code, out, err = run("decode", "abc", "--recipe", "to-hex|gunzip", "--out", failed)
        assert code == 1 and "error: not valid compressed data" in out and "616263" in out
        assert not failed.exists()
        # --json still prints the result object; the file is written all the same
        quiet = folder / "quiet.bin"
        code, out, err = run("--json", "decode", "", "--out", quiet)
        assert code == 0 and json.loads(out)["size"] == 0 and quiet.read_bytes() == b""
        relative = run("decode", "abc", "--out", os.path.relpath(folder / "rel.bin"))
        assert relative == (0, f"wrote 3 bytes to {folder / 'rel.bin'}\n", "")
        # an empty name is no name; --solve and --list do not write
        assert run("decode", "abc", "--out", "")[0] == 0
        assert run("decode", "abc", "--solve", "caesar", "--out", folder / "solve.bin")[0] == 0
        assert run("decode", "--list", "--out", folder / "list.bin")[0] == 0
        if os.name != "nt":
            # os.path.exists() follows links: one that leads nowhere is not "there"
            (folder / "dangling").symlink_to(folder / "target.bin")
            assert run("decode", "xyz", "--out", folder / "dangling")[0] == 0
            assert (folder / "target.bin").read_bytes() == b"xyz"
            (folder / "link").symlink_to(dest)
            assert run("decode", "xyz", "--out", folder / "link")[0] == 1
        assert sorted(p.name for p in folder.iterdir()) == sorted(
            ["out.bin", "quiet.bin", "rel.bin"] + (["dangling", "link", "target.bin"]
                                                   if os.name != "nt" else []))
    # Where the file cannot be written: the same one line and exit 1 from both.
    target = tmp_path / "no-such-folder" / "out.bin"
    assert same_cli(c_binary, "decode", "abc", "--out", target) == (
        1, "", f"vex: error: cannot write {target}: No such file or directory\n")
    blocker = tmp_path / "a-file"
    blocker.write_bytes(b"")
    assert same_cli(c_binary, "--json", "decode", "abc", "--out", blocker / "out.bin") == (
        1, "", f"vex: error: cannot write {blocker / 'out.bin'}: Not a directory\n")


def test_practice_puzzles(c_binary, both):
    text = (REPO / "examples" / "decode_sample" / "secrets.txt").read_text()
    puzzles, encoded = [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("encoded:"):
            encoded = line[len("encoded:"):].strip()
        elif line.startswith("recipe:") and encoded is not None:
            puzzles.append((encoded, line[len("recipe:"):].strip()))
            encoded = None
    plaintexts = [
        "Hello from the vex decode workbench -- happy decoding!",
        "vex changelog: the decode workbench now chains operations into recipes.",
        "Well done -- you turned every letter back the right way round.",
        "Tip: chain small steps and a repeating-key XOR comes right undone.",
        "Congratulations -- you solved the last puzzle with the key and the nonce!",
    ]
    assert len(puzzles) == 5
    for (encoded, recipe), plain in zip(puzzles, plaintexts):
        code, out, err = same_cli(c_binary, "--json", "decode", "--text", encoded,
                                  "--recipe", recipe)
        assert code == 0 and json.loads(out)["text"] == plain
        code, out, err = same_cli(c_binary, "decode", encoded, "--recipe", recipe)
        assert out.split("\n")[1] == plain
    # every solver over every puzzle: the same candidates from both editions
    for encoded, _ in puzzles:
        for name in SOLVERS:
            assert solve_both(both, encoded.encode(), name)["ok"]
    sample = REPO / "examples" / "decode_sample" / "secrets.txt"
    same_cli(c_binary, "decode", "--file", sample, "--recipe", "hash:algo=md5")
    same_cli(c_binary, "--json", "decode", "--file", sample, "--offset", "100", "--length", "64")


# --- the HTTP API: bodies ------------------------------------------------------------

GOOD = '{"source": {"kind": "text", "value": "abc"}, "recipe": [{"op": "to-hex"}]}'


def json_bodies():
    """Request bodies that are, nearly are, or are not at all JSON."""
    value = lambda text: ('{"source": {"kind": "text", "value": %s}}' % text).encode()   # noqa
    bodies = [
        b"", b" ", b"{}", b"[]", b"null", b"true", b"1", b'"text"', b"{", b"}", b"{not json",
        b'{"source"}', b'{"source":}', b'{"source": {"kind": "text"},}', b'{"a": 1,, "b": 2}',
        b"{'source': 1}", b'{"source": {"kind": "text"}} extra', b'{"source": {"kind": "text"}}{}',
        b'\n\t\r {"source": {"kind": "text", "value": "ws"}}\n\t\r ',
        b'\x0c{"source": {"kind": "text"}}', b'\xa0{"source": {"kind": "text"}}',
        b'{"source": {"kind": "text"}}\x00', b'{"source" : {"kind" :"text" , "value":"x"} }',
        b'{"source": {"kind": "text", "value": "a"}, "source": {"kind": "hex", "value": "41"}}',
        b'{"source": {"kind": "hex", "kind": "text", "value": "4a", "value": "4b"}}',
        b'{"so\\u0075rce": {"kind": "te\\u0078t", "value": "escaped key"}}',
        b'{"source\\u0000": {"kind": "text"}}', b'{"source": {"kind": "text\\u0000"}}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{"op": "to-hex", "op": "rot13"}]}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": null}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": {"op": "to-hex"}}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": "to-hex"}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [1, "a", null, [], {"op": "to-hex"}]}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{}]}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{"op": null}]}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{"op": 5}]}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{"op": ["rot13"]}]}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{"op": "rot13", "params": 0}]}',
        b'{"source": null}', b'{"source": []}', b'{"source": "text"}', b'{"source": 5}',
        b'{"source": {}}', b'{"source": {"kind": null}}', b'{"source": {"kind": "TEXT"}}',
        b'{"source": {"kind": ["text"]}}', b'{"source": {"kind": "url"}}',
        b'{"source": {"kind": 1}}', b'{"Source": {"kind": "text"}}',
        value("NaN"), value("Infinity"), value("-Infinity"), value("-NaN"), value("+1"),
        value("nan"), value("Inf"), value("-"), value("--1"), value("01"), value("-01"),
        value("1."), value(".5"), value("1.e5"), value("1e"), value("1e+"), value("1E5"),
        value("1e-5"), value("-0"), value("-0.0"), value("0e0"), value("-0e-0"), value("1.50"),
        value("100"), value("1e2"), value("1e15"), value("1e16"), value("1e17"), value("1.5e300"),
        value("1e400"), value("-1e400"), value("1e-400"), value("0.0001"), value("0.00001"),
        value("123456789012345678"), value("1234567890123456789012"), value("0.1"),
        value("0.30000000000000004"), value("5e-324"), value("2.2250738585072014e-308"),
        value("1.7976931348623157e308"), value("9007199254740993"), value("9007199254740993.0"),
        value("4.35"), value("0.1e1"), value("1" * 4300), value("1" * 4301), value("-" + "1" * 4300),
        value("-" + "1" * 4301), value("1" * 5000 + ".5"), value("1" * 400 + "e-380"),
        value("0x10"), value("1_000"), value("1 2"), value("tru"), value("True"), value("nul"),
        value("truefalse"), value("[1,]"), value("[,1]"), value("[1 2]"), value("[1,2"),
        value('{"a" 1}'), value('{"a":1,}'), value('{1: 2}'), value("{a: 1}"), value('["\\q"]'),
        value('"\\u12"'), value('"\\u12g4"'), value('"\\U00000041"'), value('"\\x41"'),
        value('"tab\there"'), value('"line\nbreak"'), value('"\x7f del is fine"'),
        value('"\\/\\b\\f\\n\\r\\t\\"\\\\"'), value('"unterminated'), value('"ends with \\"'),
        value('"\\ud83d\\ude00"'), value('"\\ud83d\\ude00\\ud83d"'), value('"\\uD83D\\uDE00"'),
        value('"\\ud83dx\\ude00"'), value('"\\ud83d\\u0041"'), value('"\\ud83d\\ud83d\\ude00"'),
        value('"\\ud83d\\uzzzz"'), value('"\\ud83d\\u00"'), value('"\\ud83d\\"'),
        value('"\\u0000\\u001f\\u007f\\u0080\\u00ff\\u0100\\uffff"'),
        value('"caf\u00e9 \u2603 \U0001f600"'.encode().decode("latin-1")),
        value("[]"), value("{}"), value("[[]]"), value("[{}]"), value('[1, "a", null, true]'),
        value('[1.0, -2.5e-3, 1e100, NaN, -Infinity]'), value('{"k": "v", "k2": [1, {"z": []}]}'),
        value('{"a": 1, "b": 2, "a": 3}'), value('{"it\'s": "it\'s", "q\\"": "\\"", "n": "\\n"}'),
        value('["\\ud800", "x\\udfff", "\\u00e9", "\\u200b", "\\u0378", "\\ue000", "\\ufffe"]'),
        value('{"\\u0000": "\\u0000"}'), value("[" * 100 + "]" * 100),
        value("[" * 510 + "]" * 510), value('{"a":' * 300 + "1" + "}" * 300),
        # nested deeper than 512 levels (2 + 511), however that is spelt
        value("[" * 511 + "]" * 511), value('{"a":' * 511 + "1" + "}" * 511),
        value("[" * 600 + "]" * 599), value("[" * 600 + "]" * 600),
        value('"' + "[{" * 2000 + '\\"[{"'), b"[" * 512 + b"]" * 512, b"[" * 513 + b"]" * 513,
        b'"' + b"[{" * 3000 + b'"', b'["' + b"]" * 3000 + b'"]',
        b'{"source": {"kind": "text", "value": ' + b"[" * 600 + b"]" * 600 +
        b', "value": "the earlier value counts"}}',
        ('{"source": {"kind": "text", "value": %s}}' % ("[" * 511 + "]" * 511)).encode("utf-16"),
        # a recipe, parameters or a path of the wrong JSON type
        b'{"source": {"kind": "text", "value": "x"}, "recipe": 5}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": true}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": -0.5}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": NaN}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": 1e400}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{"op": "rot-n", "params": 5}]}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{"op": "rot-n", "params": "n"}]}',
        b'{"source": {"kind": "text", "value": "x"}, "recipe": [{"op": "rot-n", "params": [["n"]]}]}',
        b'{"source": {"kind": "file", "path": 5}}', b'{"source": {"kind": "file", "path": ["a"]}}',
        b'{"source": {"kind": "file", "path": "a\\u0000b"}}',
        b'{"source": {"kind": "file", "path": "\\ud800"}}',
        b'{"source": {"kind": "text", "value": "\xff"}}', b'{"source": {"kind": "text", "value": "\xc3"}}',
        b'{"source": {"kind": "text", "value": "\xed\xa0\x80"}}',
        b'{"source": {"kind": "text", "value": "\xed\xa0"}}',
        b'{"source": {"kind": "text", "value": "\xc0\xaf"}}',
        b'{"source": {"kind": "text", "value": "\xf4\x90\x80\x80"}}',
        b'{"source": {"kind": "text", "value": "\xe2\x98\x83 \xf0\x9f\x98\x80"}}',
        b"\xef\xbb\xbf" + GOOD.encode(), b"\xef\xbb\xbf\xef\xbb\xbf" + GOOD.encode(),
        b"\xef\xbb\xbf", b"\xef\xbb", b"\xff\xfe", b"\xfe\xff", b"\xff\xfe\x00\x00",
        GOOD.encode("utf-16"), GOOD.encode("utf-16-le"), GOOD.encode("utf-16-be"),
        b"\xfe\xff" + GOOD.encode("utf-16-be"), GOOD.encode("utf-32"), GOOD.encode("utf-32-le"),
        GOOD.encode("utf-32-be"), b"\x00\x00\xfe\xff" + GOOD.encode("utf-32-be"),
        GOOD.encode("utf-16-le") + b"\x00", GOOD.encode("utf-32-le") + b"\x00\x00",
        GOOD.encode("utf-16-le")[:-1], GOOD.encode("utf-32-be")[:-3],
        '{"source": {"kind": "text", "value": "\U0001f600 \u00e9"}}'.encode("utf-16-le"),
        '{"source": {"kind": "text", "value": "\U0001f600 \u00e9"}}'.encode("utf-16-be"),
        '{"source": {"kind": "text", "value": "\U0001f600 \u00e9"}}'.encode("utf-32-le"),
        b'{\x00"\x00a\x00"\x00:\x00"\x00\x3d\xd8"\x00}\x00', b'{\x00"\x00a\x00"\x00:\x00"\x00\x00\xdc"\x00}\x00',
        b'[\x00\x00\x00\x00\xd8\x00\x00]\x00\x00\x00', b'[\x00\x00\x00\x00\x00\x11\x00]\x00\x00\x00',
        b"1\x00", b"\x001", b"1\x00\x00\x00", b"\x00\x00\x001", b"12", b"[]\x00\x00", b"{\x00}\x00",
        b"\x00{\x00}", b"{}\x00", b" {}", b"{} ",
    ]
    return bodies


def agree(c, py, case):
    """The two servers' answers to one request: the same, and never an
    internal error."""
    assert c == py, case
    assert py[0] in (200, 400, 404), (case, py)


@pytest.mark.parametrize("route", ["decode", "decode/solve"])
def test_request_bodies_match_python(c_client, py_client, route):
    bodies = json_bodies()
    for body in bodies:
        c, py = c_client.request("POST", route, body), py_client.request("POST", route, body)
        agree(c, py, body[:120])
    assert len(bodies) > 200


def test_json_values_read_like_python(both):
    """Every JSON value as the text source's value: the text is Python's
    str() of it, so a number, a string or a nesting read differently shows."""
    rng = random.Random(8)
    floats = [0.0, -0.0, 1.0, -1.0, 0.1, 0.5, 1 / 3, 2 / 3, 1e-4, 9.999e-5, 1e-5, 1.5e-7,
              123456789012345.6, 1e15, 9999999999999998.0, 1e16, 1.2e16, 1e21, 1e22, 1e23,
              5e-324, 2.2250738585072014e-308, 1.7976931348623157e308, 4.35, 0.285, 2.675,
              1.0000000000000002, 0.30000000000000004, 100.0, 1e100, 123.456e-7, 2.5e-10]
    floats += [2.0 ** k for k in range(-1074, 1024)]       # where the shortest form is hardest
    floats += [struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0] for _ in range(3000)]
    floats = [f for f in floats if f == f and abs(f) != float("inf")]
    for start in range(0, len(floats), 500):
        chunk = floats[start:start + 500]
        status, result = both("decode", {"source": {"kind": "text", "value": chunk}})
        assert status == 200 and result["text"] == str(chunk)
    ints = [0, 1, -1, 2 ** 31, 2 ** 53 + 1, -2 ** 63, 2 ** 64, 10 ** 30, -10 ** 300, 7 * 10 ** 4299]
    status, result = both("decode", {"source": {"kind": "text", "value": ints}})
    assert result["text"] == str(ints)
    strings = ["", "plain", "it's", 'say "hi"', "both ' and \"", "back\\slash", "\t\n\r\x00\x1f",
               "\x7f\x80\x9f\xa0\xad\xff", "caf\u00e9", "\u0378\u0379 unassigned", "\u200b\u200e",
               "\u2028\u2029", "\ue000 private", "\ufeff\ufffd\ufffe\uffff", "\U0001f600",
               "\U000e0001 tag", "\U0010ffff", "\u3000\u00a0 spaces", "\u0300 combining",
               "".join(chr(rng.randrange(0x20, 0x3000)) for _ in range(200)),
               "".join(chr(rng.choice((rng.randrange(0xE000), rng.randrange(0xE000, 0x110000))))
                       .replace("\ud800", "x") for _ in range(300))]
    strings = ["".join(ch for ch in s if not 0xD800 <= ord(ch) <= 0xDFFF) for s in strings]
    nested = {"list": strings, "dict": {s: i for i, s in enumerate(strings)},
              "mixed": [None, True, False, 1, 1.5, "s", [], {}, [[]], {"a": {"b": [1, 2]}}]}
    for ensure_ascii in (True, False):
        body = json.dumps({"source": {"kind": "text", "value": nested}},
                          ensure_ascii=ensure_ascii).encode()
        status, result = both("decode", body)
        assert status == 200 and result["text"] == str(nested)
    # the same str() wherever a value is taken as text
    for value in strings + [nested, 1.5, 10 ** 22, None, True]:
        both("decode", {"source": hex_source(b"Hello"),
                        "recipe": [{"op": "xor", "params": {"key_text": value}}]})
        both("decode", {"source": hex_source(b"Hello"),
                        "recipe": [{"op": "vigenere", "params": {"key": value}}]})
        both("decode", {"source": hex_source(b"Hello"),
                        "recipe": [{"op": value, "params": {"n": value}}]})
        both("decode/solve", {"source": hex_source(b"Hello"), "name": value})
        both("decode", {"source": hex_source(b"Hello"),
                        "recipe": [{"op": "rot-n", "params": {"n": value}}]})
        if isinstance(value, str):
            both("decode", {"source": hex_source(b"Hello"),
                            "recipe": [{"op": "xor", "params": {value: 1}}]})


def test_damaged_json_matches_python(c_client, py_client):
    """Requests with bytes changed at random: the same status and the same
    answer, whatever became of the JSON."""
    rng = random.Random(77)
    seeds = [GOOD.encode(),
             json.dumps({"source": {"kind": "hex", "value": "48 65 6c 6c 6f"},
                         "recipe": [{"op": "xor", "params": {"key": "2a", "key_text": None}},
                                    {"op": "rot-n", "params": {"n": 3}},
                                    {"op": "to-base64", "params": {"alphabet": "url"}}],
                         "name": "caesar"}).encode(),
             json.dumps({"source": {"kind": "base64", "value": "aGVsbG8gd29ybGQ="},
                         "recipe": [{"op": "vigenere", "params": {"key": "cl\u00e9"}},
                                    {"op": "hash", "params": {"algo": "md5"}}],
                         "name": "xor-single"}, ensure_ascii=False).encode(),
             json.dumps({"source": {"kind": "text", "value": [1.5, -2e-7, True, None, "\u2603"]},
                         "recipe": [{"op": "railfence", "params": {"rails": 2.0, "mode": []}}],
                         "name": "substitution"}).encode()]
    alphabet = b'{}[]":,\\ \n0123456789.eE+-truefalsnNIaiyu\x00\x1f\x7f\x80\xc3\xa9\xed\xa0\xff'
    compared = 0
    for seed in seeds:
        for body in mutations(rng, seed, 450, alphabet):
            for route in ("decode", "decode/solve"):
                c, py = c_client.request("POST", route, body), py_client.request("POST", route, body)
                agree(c, py, body)
                compared += 1
    assert compared > 3000


def test_api_wrong_method_token_and_route(c_client, py_client):
    for client in (c_client, py_client):
        assert client.request("GET", "decode")[0] == 404
        assert client.request("POST", "decode/ops", b"{}")[0] == 404
        assert client.request("GET", "decode/solve")[0] == 404
        conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=30)
        conn.request("POST", "/api/decode", body=GOOD.encode())
        response = conn.getresponse()
        assert response.status == 403 and b"token" in response.read()
        conn.close()
    assert c_client.request("POST", "decode", GOOD.encode()) == \
        py_client.request("POST", "decode", GOOD.encode())


GREEK_MAP = ("\u03b1\u03b2\u03b3\u03b4\u03b5\u03b6\u03b7\u03b8\u03b9\u03ba\u03bb\u03bc\u03bd"
             "\u03be\u03bf\u03c0\u03c1\u03c3\u03c4\u03c5\u03c6\u03c7\u03c8\u03c9\u03ac\u03ad")
NOT_UTF8 = "'utf-8' codec can't encode character '\\{}' in position {}: surrogates not allowed"
NOT_LATIN1 = ("'latin-1' codec can't encode character '\\{}' in position {}: ordinal not in "
              "range(256)")
TEXT_X = {"kind": "text", "value": "x"}

# Requests the Python edition once answered with an internal error (HTTP 500),
# and the answer both editions now give: (route, body, status, error).
ONCE_STOPPED_PYTHON = [
    # a lone surrogate cannot be written as UTF-8 (text source, xor key_text)
    ("decode", {"source": {"kind": "text", "value": "a\ud800b"}}, 200, NOT_UTF8.format("ud800", 1)),
    ("decode/solve", {"source": {"kind": "text", "value": "a\ud800b"}, "name": "caesar"}, 200,
     NOT_UTF8.format("ud800", 1)),
    ("decode", {"source": TEXT_X, "recipe": [{"op": "xor", "params": {"key_text": "\udc80"}}]},
     200, NOT_UTF8.format("udc80", 0)),
    # a base64 source with a character above U+00FF cannot be written as Latin-1
    ("decode", {"source": {"kind": "base64", "value": "aGk\u20ac"}}, 200,
     NOT_LATIN1.format("u20ac", 3)),
    ("decode/solve", {"source": {"kind": "base64", "value": "\u0100"}, "name": "caesar"}, 200,
     NOT_LATIN1.format("u0100", 0)),
    # a list or an object where a name is looked up
    ("decode", {"source": TEXT_X, "recipe": [{"op": "charset-decode", "params": {"from": ["utf-8"]}}]},
     200, "from must be utf-8, utf-16le, utf-16be or latin-1"),
    ("decode", {"source": TEXT_X, "recipe": [{"op": "charset-decode", "params": {"from": {"a": 1}}}]},
     200, "from must be utf-8, utf-16le, utf-16be or latin-1"),
    # parameters, a recipe or a path of the wrong JSON type
    ("decode", {"source": TEXT_X, "recipe": [{"op": "rot-n", "params": 5}]}, 200,
     "params must be an object"),
    ("decode", {"source": TEXT_X, "recipe": [{"op": "rot-n", "params": ["n"]}]}, 200,
     "params must be an object"),
    ("decode", {"source": TEXT_X, "recipe": 5}, 400, "recipe must be a list of steps"),
    ("decode", {"source": TEXT_X, "recipe": True}, 400, "recipe must be a list of steps"),
    ("decode", {"source": TEXT_X, "recipe": 1.5}, 400, "recipe must be a list of steps"),
    ("decode", {"source": {"kind": "file", "path": 5}}, 400, "a file source needs a path"),
    ("decode", {"source": {"kind": "file", "path": ["a"]}}, 400, "a file source needs a path"),
    ("decode", {"source": {"kind": "file", "path": "a\x00b"}}, 400, "a file source needs a path"),
    ("decode/solve", {"source": {"kind": "file", "path": "a\x00b"}, "name": "caesar"}, 400,
     "a file source needs a path"),
    # letters whose upper case is not one letter, and maps of other letters
    ("decode", {"source": {"kind": "text", "value": "abc"},
                "recipe": [{"op": "vigenere", "params": {"key": "stra\u00dfe"}}]}, 200,
     "vigenere needs a key of letters"),
    ("decode", {"source": {"kind": "text", "value": "abc"},
                "recipe": [{"op": "vigenere", "params": {"key": "\ufb01"}}]}, 200,
     "vigenere needs a key of letters"),
    ("decode", {"source": {"kind": "text", "value": "abc"},
                "recipe": [{"op": "substitution", "params": {"map": GREEK_MAP}}]}, 200,
     "map must be a 26-letter permutation of the alphabet"),
]


def test_what_once_stopped_python_fails_alike(both):
    for route, payload, status, error in ONCE_STOPPED_PYTHON:
        got_status, result = both(route, payload)
        assert got_status == status and result["error"] == error, (payload, result)
        if status == 200:
            assert result["ok"] is False
        else:
            assert set(result) == {"error"}


def test_json_nested_deeper_than_512_levels(both):
    """The C reader goes 512 levels deep; Python used to read on (to a depth
    of some thousands, then stop with a RecursionError). Now both refuse."""
    def nested(levels):              # the body, the source and `levels` lists: 2 + levels
        return (b'{"name": "caesar", "source": {"kind": "text", "value": ' + b"[" * levels +
                b"]" * levels + b"}}")
    for route in ("decode", "decode/solve"):
        status, result = both(route, nested(510))
        assert status == 200 and result["ok"]
        for levels in (511, 600, 5000, 200000):
            assert both(route, nested(levels)) == (400, {"error": "request body must be JSON"})


def test_cli_arguments_that_are_not_utf8(c_binary):
    """Arguments that are not UTF-8, or not Latin-1 for --base64: a failed
    source, shown like any other, exit status 1, from both. (Python once
    stopped with a traceback.)"""
    for args in (["decode", b"caf\xe9"], ["decode", "--text", b"\xff"],
                 ["decode", "--base64", "aGk\u20ac"], ["--json", "decode", "--text", b"\xff"],
                 ["decode", "--text", b"\xed\xa0\x80", "--solve", "caesar"],
                 ["decode", "abc", "--recipe", b"xor:key_text=\xff"]):
        c, py = run_c(c_binary, *args), run_python(*[os.fsdecode(a) for a in args])
        assert c == py, args
        assert c[0] == 1 and c[2] == "" and "codec can't encode" in c[1]
    # in a recipe such bytes are shown the way Python shows them
    args = ["decode", "abc", "--recipe", b"caf\xe9\xff"]
    c, py = run_c(c_binary, *args), run_python(*[os.fsdecode(a) for a in args])
    assert c == py == (2, "", "vex: error: unknown operation: 'caf\\udce9\\udcff'\n")


# --- randomized differential run -------------------------------------------------------

def random_value(rng, good):
    """A parameter value: mostly one that works, sometimes an odd one."""
    roll = rng.random()
    if roll < 0.75:
        return rng.choice(good)
    if roll < 0.9:
        return rng.choice(ODD_VALUES)
    return "".join(rng.choice("0123456789abcdefxyzXA _-,:=|\u00e9\u0663\n") for _ in
                   range(rng.randrange(0, 12)))


def random_params(rng, name):
    hexkey = lambda n: bytes(rng.randrange(256) for _ in range(n)).hex()     # noqa
    good = {
        "alphabet": ["std", "url"], "variant": ["ascii85", "z85"],
        "from": ["utf-8", "utf-16le", "utf-16be", "latin-1"],
        "n": [0, 1, 13, 25, "7", " 0x10 "], "mode": ["decrypt", "encrypt"],
        "rails": [2, 3, 4, "5", 7, 50, 1000, 10 ** 9, "0x" + "f" * 40], "algo": ["md5", "sha1", "sha256", "crc32"],
        "map": ["QWERTYUIOPASDFGHJKLZXCVBNM", "zyxwvutsrqponmlkjihgfedcba", "a-z? " +
                "bcdefghijklmnopqrstuvwxyz", GREEK_MAP],
        "key_text": ["k", "KEY!", "p\u00e4ss w\u00f6rd", "\u2603", "\udc80"], "counter": [0, 1, 7, 2 ** 32 - 1, "0x10"],
        "nonce": [hexkey(12), hexkey(12), hexkey(16), hexkey(8)], "iv": [hexkey(16), hexkey(16), hexkey(8)],
        "tag": ["", hexkey(16)], "op": ["decrypt", "encrypt"], "unpad": ["pkcs7", "none"],
    }
    if name == "vigenere":
        good["key"] = ["LEMON", "k", "The Key", "cl\u00e9 \u0391", "stra\u00dfe"]
    elif name == "chacha20":
        good["key"] = [hexkey(32), hexkey(32), hexkey(31)]
    elif name == "aes":
        good["key"] = [hexkey(16), hexkey(24), hexkey(32), hexkey(15)]
        good["mode"] = ["ecb", "cbc", "ctr", "ctr", "gcm"]
    else:
        good["key"] = [hexkey(1), hexkey(5), "0x41 0x42", hexkey(40)]
    spec = decode.REGISTRY[name]
    params = {}
    for p in spec.params:
        if p["required"] or rng.random() < 0.5:
            if rng.random() < 0.97:
                params[p["name"]] = random_value(rng, good[p["name"]])
    if rng.random() < 0.02:
        params[rng.choice(["bogus", "", "KEY", "n "])] = 1
    return params


# Operations that undo each other, for input that survives several steps.
def wrap(rng, data):
    """`data` wrapped in a few layers, and the recipe that unwraps them."""
    recipe = []
    for _ in range(rng.randrange(0, 4)):
        kind = rng.randrange(12)
        if kind == 0:
            data, step = base64.b64encode(data), ("from-base64", {})
        elif kind == 1:
            data, step = base64.urlsafe_b64encode(data), ("from-base64", {"alphabet": "url"})
        elif kind == 2:
            data, step = base64.b32encode(data), ("from-base32", {})
        elif kind == 3:
            data, step = data.hex().encode(), ("from-hex", {})
        elif kind == 4:
            data, step = base64.a85encode(data), ("from-base85", {})
        elif kind == 5:
            data, step = zlib.compress(data), ("zlib-inflate", {})
        elif kind == 6:
            data, step = gzip.compress(data), ("gunzip", {})
        elif kind == 7:
            co = zlib.compressobj(rng.randrange(10), zlib.DEFLATED, -15)
            data, step = co.compress(data) + co.flush(), ("raw-inflate", {})
        elif kind == 8:
            key = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 6)))
            data = bytes(c ^ key[i % len(key)] for i, c in enumerate(data))
            step = ("xor", {"key": key.hex()})
        elif kind == 9:
            data, step = urllib.parse.quote_from_bytes(data).encode(), ("url-decode", {})
        elif kind == 10:
            data, step = quopri.encodestring(data), ("qp-decode", {})
        else:
            data, step = data[::-1], ("reverse", {})
        recipe.insert(0, step)
    return data, recipe


def random_case(rng):
    size = rng.choice((0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 600))
    kind = rng.randrange(5)
    if kind == 0:
        data = bytes(rng.randrange(256) for _ in range(size))
    elif kind == 1:
        data = (ENGLISH * 5)[:size]
    elif kind == 2:
        data = bytes(rng.choice(b"ABCDEFabcdef0123456789+/=-_ \n%zu!") for _ in range(size))
    elif kind == 3:
        data = ("\u00e9\u2603\U0001f600 text " * 40).encode()[:size]
    else:
        data = bytes(rng.choice((0, 0x41, 0xFF, 0x20, 0x80)) for _ in range(size))
    data, recipe = wrap(rng, data)
    if rng.random() < 0.3 and data:
        data = next(iter(list(mutations(rng, data, 1))[1:]))
    for _ in range(rng.choice((0, 0, 1, 1, 1, 2, 3))):
        name = rng.choice(C_OPS)
        recipe.insert(rng.randrange(len(recipe) + 1), (name, random_params(rng, name)))
    if rng.random() < 0.03:
        recipe.insert(rng.randrange(len(recipe) + 1),
                      (rng.choice(sorted(C_UNAVAILABLE) + ["nope", "", "ROT13"]), {}))
    return data, recipe


@pytest.mark.parametrize("seed", range(8))
def test_random_recipes_match_python(c_client, py_client, seed):
    """Random recipes over random, wrapped and damaged bytes, fixed seeds."""
    rng = random.Random(1000 + seed)
    succeeded = failed = 0
    for _ in range(500):
        data, recipe = random_case(rng)
        payload = {"source": hex_source(data),
                   "recipe": [{"op": name, "params": params} for name, params in recipe]}
        c, py = c_client.post("decode", payload), py_client.post("decode", payload)
        if c[0] == 200 and c[1]["ok"] is False and \
                c[1]["error"].endswith(" is not available in this build"):
            # the Python edition has the operation (bunzip2, AES-GCM, ...): only
            # the steps before it compare
            done = len(c[1]["steps"])
            name, params = recipe[done]
            assert name in C_UNAVAILABLE or (name == "aes" and params.get("mode") == "gcm")
            assert c[1]["steps"] == py[1]["steps"][:done] and py[0] == 200
            continue
        assert c == py, (seed, data.hex(), recipe)
        if c[1]["ok"]:
            succeeded += 1
        else:
            failed += 1
    assert succeeded > 100 and failed > 100


def test_random_recipes_on_the_command_line(c_binary, tmp_path):
    """The same kind of random run through the command line: the recipe
    grammar, a file source and the text output."""
    rng = random.Random(4242)
    source = tmp_path / "input.bin"

    def text_of(value):
        return value if isinstance(value, str) else str(value)

    ran = 0
    while ran < 120:
        data, recipe = random_case(rng)
        parts = []
        usable = True
        for name, params in recipe:
            if name == "" or name in C_UNAVAILABLE:
                usable = False
            pairs = []
            for key, value in params.items():
                value = text_of(value)
                if any(ch in value for ch in ",|") or not isinstance(key, str) or \
                        any(0xD800 <= ord(ch) <= 0xDFFF for ch in value + key) or "\x00" in value:
                    usable = False
                pairs.append(f"{key}={value}")
            parts.append(name + (":" + ",".join(pairs) if pairs else ""))
        if not usable:
            continue
        ran += 1
        source.write_bytes(data)
        args = ["decode", "--file", source, "--recipe", "|".join(parts)]
        if rng.random() < 0.5:
            args = ["--json"] + args
        c, py = run_c(c_binary, *args), run_python(*args)
        if GCM_MISSING in c[1]:
            continue
        assert c == py, (data.hex(), parts)
        assert c[0] in (0, 1, 2)


# --- robustness ------------------------------------------------------------------------

def test_hostile_input_is_safe_under_asan(asan_binary, tmp_path):
    """Damaged streams, odd recipes and broken arguments through the
    AddressSanitizer/UBSan build: an ordinary exit, no sanitizer report."""
    rng = random.Random(99)
    source = tmp_path / "fuzz.bin"

    def exercise(*args, statuses=(0, 1, 2)):
        code, out, err = run_c(asan_binary, *args)
        assert code in statuses, (args, code, err[-600:])
        for word in SANITIZER_WORDS:
            assert word not in err, (args, err[-900:])
        return code, out

    streams = deflate_streams()
    payload = ENGLISH * 3
    wrapped = [zlib.compress(payload), gzip.compress(payload), gzip_with_header(
        payload, extra=b"ab", name=b"n", comment=b"c", header_crc=True)]
    for index in range(260):
        stream = rng.choice(streams + wrapped * 4)
        data = bytearray(stream)
        for _ in range(rng.randrange(0, 4)):
            if data:
                data[rng.randrange(len(data))] = rng.randrange(256)
        if rng.random() < 0.3:
            del data[rng.randrange(len(data) + 1):]
        source.write_bytes(data)
        op = rng.choice(("raw-inflate", "zlib-inflate", "gunzip"))
        exercise("--json" if index % 2 else "--color=always", "decode", "--file", source,
                 "--recipe", f"{op}|to-base85|from-base85|to-base32|from-base32")
    for _ in range(150):
        data, recipe = random_case(rng)
        source.write_bytes(data)
        text = "|".join(name + ":" + ",".join(f"{k}={v}" for k, v in params.items())
                        for name, params in recipe)
        exercise("decode", "--file", source, "--recipe", text.replace("\x00", ""))
        exercise("--json", "decode", "--file", source, "--solve", rng.choice(SOLVERS + ["x"]),
                 "--offset", rng.choice(("0", "3", "0x40", "-1", "99999999999999999999")),
                 "--length", rng.choice(("0", "1", "2", "70000", "-5", "0b1")))
    garbage = [b"\xff\xfe\xfd", b"\xed\xa0\x80", b"\xf0\x9f", "\U0001f600" * 50, "a" * 100000,
               "|" * 500, ":" * 500, "," * 500, "=" * 500, "rot-n:" + "n=1," * 5000,
               "xor:key=" + "41" * 60000, "rot-n:n=" + "9" * 9000, "0x" * 4000, "%" * 3000]
    for text in garbage:
        exercise("decode", text, "--recipe", "url-decode|qp-decode|from-hex")
        exercise("decode", "abc", "--recipe", text)
        exercise("decode", "--hex", text)
        exercise("decode", "--base64", text)
        exercise("decode", "abc", "--solve", text)
        exercise("decode", "abc", "--offset", text, statuses=(0, 2))
        exercise("decode", "abc", "--out", tmp_path / "never" / "written", "--recipe", text)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["fuzz.bin"]
