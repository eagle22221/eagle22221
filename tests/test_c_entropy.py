"""The native C `entropy` command and GET /api/entropy against the Python ones.

Both editions are run on the same inputs: every fixture, files built to
sizes around the block rules (0, 1, 255, 256, 257, 256*64, 256*64+1, 3 MB),
the points 1, 8, 64, 1024 and values out of range or not numbers at all, and
a fuzz of random sizes and points with a fixed seed. The command line must
agree byte for byte (text, --json, exit status, standard error); the API must
give the same status and the same JSON.

With VEX_TEST_SANITIZED=1 everything runs against the AddressSanitizer/UBSan
build; a few inputs always do.
"""
import contextlib
import http.client
import io
import json
import os
import random
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import quote

import pytest

from vex import server
from vex.cli import main as python_main
from conftest import FIXTURES, fixture_path

C_DIR = Path(__file__).resolve().parent.parent / "c"
MAKE = shutil.which("make")
COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")

pytestmark = pytest.mark.skipif(
    not (MAKE and COMPILER and C_DIR.is_dir()),
    reason="the C port needs make and a C compiler")

FIXTURE_NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())
ELF_HEADER = b"\x7fELF\x02\x01\x01" + bytes(57)      # the smallest file vex loads
SIZES = [0, 1, 63, 64, 255, 256, 257, 256 * 64, 256 * 64 + 1, 3 * 1024 * 1024]
# --points as given on the command line (None: not given)
CLI_POINTS = [None, "1", "8", "64", "1024", "0", "-7", "1025", "100000", "0x10", "1_0",
              str(10 ** 40)]
# ?points= as given to the API (None: not given)
API_POINTS = [None, 1, 8, 64, 1024, 0, -1, 1025, 5000, "", "0x10", " 12 ", "1_0", "0o17",
              str(10 ** 30), str(-10 ** 30)]


# --- the two implementations --------------------------------------------------

def _make(target):
    proc = subprocess.run([MAKE, "-C", str(C_DIR), target], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


@pytest.fixture(scope="session")
def c_binary():
    """The native build; with VEX_TEST_SANITIZED=1 the AddressSanitizer/UBSan
    build, so that a memory error anywhere fails the test that reaches it."""
    if os.environ.get("VEX_TEST_SANITIZED"):
        _make("asan")
        return C_DIR / "build" / "vex-asan"
    _make("all")
    return C_DIR / "build" / "vex"


@pytest.fixture(scope="session")
def asan_binary():
    _make("asan")
    return C_DIR / "build" / "vex-asan"


SANITIZER_ENV = dict(os.environ, ASAN_OPTIONS="abort_on_error=1:detect_leaks=1",
                     UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")


def run_c(binary, *args):
    proc = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=120,
                          env=SANITIZER_ENV)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


def run_python(*args):
    """The Python CLI in-process: (exit status, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = python_main([str(a) for a in args])
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


def assert_cli_same(c_binary, *args):
    """Both editions print the same, byte for byte, and exit the same way."""
    c, py = run_c(c_binary, *args), run_python(*args)
    assert c == py, args
    return c


def assert_usage_error_same(c_binary, *args):
    """A usage error: status 2 and nothing on stdout from both, and the same
    error. The usage line above it is each edition's own, and so is the name
    before "error:" (argparse names the sub-command: "vex entropy: error:")."""
    c, py = run_c(c_binary, *args), run_python(*args)
    assert c[0] == py[0] == 2 and c[1] == py[1] == "", (args, c, py)
    c_line, py_line = c[2].splitlines()[-1], py[2].splitlines()[-1]
    assert c_line.startswith("vex: error: ") and py_line.startswith("vex")
    assert c_line == "vex: " + py_line[py_line.index("error: "):], args
    return c_line


def points_args(points):
    return [] if points is None else ["--points", points]


def body(size, seed=0):
    """`size` bytes that are not all alike: random stretches, runs of one
    byte, text."""
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        kind, n = rng.randrange(3), rng.randrange(1, 5000)
        if kind == 0:
            out += rng.randbytes(n)
        elif kind == 1:
            out += bytes([rng.randrange(256)]) * n
        else:
            out += (b"the quick brown fox jumps over the lazy dog " * (n // 44 + 1))[:n]
    return bytes(out[:size])


def constructed(size, seed=0):
    """`size` bytes: from 64 on, a file vex loads (an ELF header first);
    below that, as many bytes of one (not loadable)."""
    if size >= len(ELF_HEADER):
        return ELF_HEADER + body(size - len(ELF_HEADER), seed)
    return (ELF_HEADER + bytes(64))[:size]


@pytest.fixture(scope="module")
def inputs(tmp_path_factory):
    """The constructed files, written once: {size: path}."""
    folder = tmp_path_factory.mktemp("entropy-inputs")
    paths = {}
    for size in SIZES:
        paths[size] = folder / f"size{size}"
        paths[size].write_bytes(constructed(size, seed=size))
    return paths


# --- the command line ---------------------------------------------------------

@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_fixture_cli_matches_python(c_binary, name):
    path = fixture_path(name)
    for points in CLI_POINTS:
        code, out, err = assert_cli_same(c_binary, "--json", "entropy", path,
                                         *points_args(points))
        assert (code, err) == (0, "") and json.loads(out)["size"] == path.stat().st_size
        code, out, _ = assert_cli_same(c_binary, "entropy", path, *points_args(points))
        assert code == 0 and out.startswith("Size ")
    assert_cli_same(c_binary, "--color", "always", "entropy", path)
    assert_cli_same(c_binary, "entropy", f"--points={8}", path)
    assert_cli_same(c_binary, "entropy", "--poi", "8", path)     # a prefix, as argparse allows


@pytest.mark.parametrize("size", SIZES)
def test_constructed_cli_matches_python(c_binary, inputs, size):
    for points in CLI_POINTS[:8]:
        for json_flag in (["--json"], []):
            code, out, err = assert_cli_same(c_binary, *json_flag, "entropy", inputs[size],
                                             *points_args(points))
            if size < len(ELF_HEADER):
                assert code == 1 and out == "" and err.startswith("vex: error: ")
            else:
                assert code == 0 and err == ""


def test_cli_errors_match_python(c_binary, tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("not a program at all, just some text\n" * 4)
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    dos = tmp_path / "dos.exe"
    dos.write_bytes(b"MZ" + bytes(300))
    for args in (["entropy", text], ["entropy", empty], ["entropy", tmp_path / "missing"],
                 ["entropy", tmp_path], ["entropy", dos], ["--json", "entropy", text],
                 ["--json", "entropy", tmp_path / "missing", "--points", "8"]):
        code, out, err = assert_cli_same(c_binary, *args)
        assert code == 1 and out == "" and err.startswith("vex: error: ")


def test_cli_usage_errors_match_python(c_binary):
    elf = fixture_path("hello_elf64")
    for bad in ("abc", "", "1.5", "0x", "010", "8 8", "--json"):
        line = assert_usage_error_same(c_binary, "entropy", elf, "--points", bad)
        if bad != "--json":
            assert line == f"vex: error: argument --points: invalid _int value: {bad!r}"
    assert assert_usage_error_same(c_binary, "entropy", elf, "--points") == \
        "vex: error: argument --points: expected one argument"
    assert assert_usage_error_same(c_binary, "entropy") == \
        "vex: error: the following arguments are required: FILE"
    assert assert_usage_error_same(c_binary, "entropy", elf, "extra") == \
        "vex: error: unrecognized arguments: extra"
    assert_usage_error_same(c_binary, "entropy", elf, "--points=x")
    assert_usage_error_same(c_binary, "entropy", elf, "--length")


def test_help_lists_the_command(c_binary):
    code, out, _ = run_c(c_binary, "--help")
    assert code == 0 and "  entropy FILE [--points N]" in out
    code, out, _ = run_python("--help")
    assert code == 0 and re.search(r"^\s+entropy\s+\S", out, re.M)
    assert run_c(c_binary, "entropy", "--help")[0] == 0


# --- the HTTP API -----------------------------------------------------------------

class Client:
    def __init__(self, port, token):
        self.port, self.token = port, token

    def get(self, **params):
        return self.call("entropy", **params)

    def call(self, name, **params):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items()
                         if v is not None)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        conn.request("GET", f"/api/{name}?{query}", headers={"X-Vex-Token": self.token})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        assert response.getheader("Content-Type") == "application/json"
        return response.status, json.loads(data)


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
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def py_client():
    httpd, workspace = server.create_server(port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield Client(httpd.server_address[1], workspace.token)
    httpd.shutdown()
    httpd.server_close()
    workspace.close()


def assert_api_same(c_client, py_client, **params):
    c, py = c_client.get(**params), py_client.get(**params)
    assert c == py, params
    return c


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_api_fixtures_match_python(c_client, py_client, name):
    path = fixture_path(name)
    for points in API_POINTS:
        status, data = assert_api_same(c_client, py_client, path=path, points=points)
        assert status == 200 and data["size"] == path.stat().st_size


@pytest.mark.parametrize("size", SIZES)
def test_api_constructed_match_python(c_client, py_client, inputs, size):
    for points in API_POINTS[:9]:
        status, data = assert_api_same(c_client, py_client, path=inputs[size], points=points)
        assert status == (400 if size < len(ELF_HEADER) else 200)


def test_api_errors_match_python(c_client, py_client, tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("plain text, not a program\n" * 3)
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    elf = fixture_path("hello_elf64")
    for params in ({}, {"path": ""}, {"path": tmp_path / "missing"}, {"path": text},
                   {"path": empty}, {"path": elf, "points": "abc"},
                   {"path": elf, "points": "1.5"}, {"path": elf, "points": "0x"},
                   {"path": elf, "points": "010"}, {"path": elf, "points": "--1"},
                   {"points": "abc"}, {"path": tmp_path / "missing", "points": "abc"},
                   {"path": tmp_path / "missing", "points": "8"}):
        status, data = assert_api_same(c_client, py_client, **params)
        assert status in (400, 404) and "error" in data, params
    # A folder is refused like every other per-file route refuses it; the two
    # editions word that differently (for `info` as much as here).
    for client in (c_client, py_client):
        status, data = client.get(path=tmp_path)
        assert status == 400 and (status, data) == client.call("info", path=tmp_path)


def test_api_and_cli_agree(c_binary, c_client):
    path = fixture_path("netprobe.exe")
    for points in (1, 8, 64, 1024):
        _, out, _ = run_c(c_binary, "--json", "entropy", path, "--points", points)
        assert c_client.get(path=path, points=points) == (200, json.loads(out))


# --- a fuzz of sizes and points ------------------------------------------------

def fuzz_cases(count=60, seed=20261125):
    rng = random.Random(seed)
    for i in range(count):
        size = rng.choice([rng.randint(64, 600), rng.randint(600, 20000),
                           rng.randint(20000, 300000), rng.randint(0, 63)])
        if i % 15 == 0:
            size = rng.randint(1 << 20, 3 << 20)
        points = rng.choice([rng.randint(1, 64), rng.randint(-10, 1100), rng.randint(1, 1024),
                             None, str(rng.randint(0, 2000)), hex(rng.randint(0, 2000))])
        yield i, size, points, rng.randrange(1 << 30)


def test_fuzz_matches_python(c_binary, c_client, py_client, tmp_path):
    for i, size, points, seed in fuzz_cases():
        path = tmp_path / f"fuzz{i}"
        path.write_bytes(constructed(size, seed))
        wanted = None if points is None else str(points)
        code, out, err = assert_cli_same(c_binary, "--json", "entropy", path,
                                         *points_args(wanted))
        assert code == (0 if size >= len(ELF_HEADER) else 1), (i, err)
        if i % 4 == 0:
            assert_cli_same(c_binary, "entropy", path, *points_args(wanted))
        status, data = assert_api_same(c_client, py_client, path=path, points=points)
        if code == 0:
            assert (status, data) == (200, json.loads(out))


# --- memory safety ---------------------------------------------------------------

def test_inputs_are_safe_under_asan(asan_binary, inputs):
    paths = list(inputs.values()) + [fixture_path(n) for n in FIXTURE_NAMES]
    for path in paths:
        for args in (["--json", "entropy", path, "--points", "1"],
                     ["--json", "entropy", path, "--points", "1024"],
                     ["--json", "entropy", path, "--points", "-1"],
                     ["entropy", path]):
            code, _, err = run_c(asan_binary, *args)
            assert code in (0, 1), (args, err)
            assert "Sanitizer" not in err and "runtime error" not in err, err
