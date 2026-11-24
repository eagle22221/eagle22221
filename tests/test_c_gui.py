"""The native C web server (vex gui) against the Python one (server.py).

The Python package is the reference. For every implemented endpoint the C
server must return the same status and the same decoded JSON on the same
input. The rest covers the access-control rules, static-file serving, hostile
requests under AddressSanitizer/UBSan, and the Windows build.

The C server is started as a subprocess (`vex gui --no-browser --port 0`);
the Python server runs in-process (vex.server.create_server). Both are
spoken to over HTTP with http.client.
"""
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import quote

import pytest

import vex
from vex import server
from conftest import FIXTURES, fixture_bytes, fixture_path

C_DIR = Path(__file__).resolve().parent.parent / "c"
WEB_DIR = Path(vex.__file__).resolve().parent / "web"
MAKE = shutil.which("make")
COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
MINGW = shutil.which("x86_64-w64-mingw32-gcc")

pytestmark = pytest.mark.skipif(
    not (MAKE and COMPILER and C_DIR.is_dir()),
    reason="the C port needs make and a C compiler")

FIXTURE_NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())
ELF_FIXTURES = [n for n in FIXTURE_NAMES if fixture_bytes(n)[:4] == b"\x7fELF"]
PE_FIXTURES = [n for n in FIXTURE_NAMES if fixture_bytes(n)[:2] == b"MZ"]

NO_DISASSEMBLER = "this build has no disassembler"


# --- building ------------------------------------------------------------------

def _make(target):
    if not list(C_DIR.glob("third_party/capstone-*/src/cs.c")):
        subprocess.run(["sh", str(C_DIR / "fetch_capstone.sh")], capture_output=True,
                       timeout=300, check=False)
    proc = subprocess.run([MAKE, "-C", str(C_DIR), target], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


# --- talking to a server --------------------------------------------------------

class Client:
    def __init__(self, port, token):
        self.port = port
        self.token = token

    def request(self, method, url, body=None, token=True, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        if token:
            h["X-Vex-Token"] = self.token if token is True else token
        conn.request(method, url, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        ctype = resp.getheader("Content-Type", "")
        conn.close()
        return resp.status, ctype, data

    def call(self, method, name, params=None, body=None):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in (params or {}).items())
        status, ctype, data = self.request(method, f"/api/{name}?{query}", body=body)
        return status, (json.loads(data) if "json" in ctype else data)

    def get(self, name, **params):
        return self.call("GET", name, params)


def _start_c_server(binary):
    proc = subprocess.Popen([str(binary), "gui", "--no-browser", "--port", "0"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    port = token = None
    deadline = time.time() + 30
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        m = re.search(r"http://127\.0\.0\.1:(\d+)/#token=(\S+)", line)
        if m:
            port, token = int(m.group(1)), m.group(2)
            break
    if port is None:
        proc.kill()
        pytest.fail("the C server did not print its address")
    return proc, Client(port, token)


@pytest.fixture(scope="module")
def c_client():
    _make("all")
    proc, client = _start_c_server(C_DIR / "build" / "vex")
    yield client
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


@pytest.fixture(scope="module")
def have_disassembler(c_client):
    status, data = c_client.get("functions", path=str(fixture_path("hello_elf64")))
    if status != 200 and isinstance(data, dict) and NO_DISASSEMBLER in data.get("error", ""):
        return False
    return True


# --- helpers --------------------------------------------------------------------

def _strip(name, data):
    """Drop fields that legitimately differ (path formatting of the argument)."""
    if isinstance(data, dict) and name in ("info", "open"):
        return {k: v for k, v in data.items() if k not in ("path", "name")}
    return data


def _same(c_client, py_client, method, name, params=None, body=None):
    cs, cj = c_client.call(method, name, params, body)
    ps, pj = py_client.call(method, name, params, body)
    assert cs == ps, (name, params, "status", cs, ps, cj, pj)
    assert _strip(name, cj) == _strip(name, pj), (name, params, cj, pj)
    return cj


# --- differential: analysis endpoints over every fixture ------------------------

@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_plain_tables_match_python(c_client, py_client, fixture):
    path = str(fixture_path(fixture))
    for name in ("info", "layout", "sections", "segments", "imports", "exports"):
        _same(c_client, py_client, "GET", name, {"path": path})


@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_symbols_and_strings_match_python(c_client, py_client, fixture):
    path = str(fixture_path(fixture))
    _same(c_client, py_client, "GET", "symbols", {"path": path})
    _same(c_client, py_client, "GET", "symbols", {"path": path, "q": "a"})
    _same(c_client, py_client, "GET", "strings", {"path": path})
    _same(c_client, py_client, "GET", "strings", {"path": path, "tagged": 1, "limit": 5})
    _same(c_client, py_client, "GET", "strings",
          {"path": path, "min": 6, "encoding": "ascii", "limit": 10, "offset": 1})
    _same(c_client, py_client, "GET", "strings", {"path": path, "encoding": "utf16"})


@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_techniques_match_python(c_client, py_client, fixture):
    _same(c_client, py_client, "GET", "techniques", {"path": str(fixture_path(fixture))})


@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_hexdump_matches_python(c_client, py_client, fixture):
    path = str(fixture_path(fixture))
    _same(c_client, py_client, "GET", "hexdump", {"path": path, "length": 48})
    _same(c_client, py_client, "GET", "hexdump", {"path": path, "offset": 0, "length": 32})


@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_code_endpoints_match_python(c_client, py_client, fixture, have_disassembler):
    if not have_disassembler:
        pytest.skip("the C program was built without Capstone")
    path = str(fixture_path(fixture))
    _same(c_client, py_client, "GET", "functions", {"path": path})
    _same(c_client, py_client, "GET", "functions", {"path": path, "q": "a"})
    info = c_client.get("info", path=path)[1]
    _same(c_client, py_client, "GET", "disasm", {"path": path, "count": 8})
    entry = info.get("entry")
    if entry:
        _same(c_client, py_client, "GET", "disasm", {"path": path, "at": entry, "count": 8})
        _same(c_client, py_client, "GET", "xrefs", {"path": path, "target": entry})


@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_open_and_engine_match_python(c_client, py_client, fixture):
    path = str(fixture_path(fixture))
    _same(c_client, py_client, "GET", "open", {"path": path})
    _same(c_client, py_client, "GET", "engine", {"path": path})


def test_browse_matches_python(c_client, py_client):
    _same(c_client, py_client, "GET", "browse", {"dir": str(FIXTURES)})
    _same(c_client, py_client, "GET", "browse", {"dir": str(FIXTURES.parent)})


@pytest.mark.parametrize("fixture", FIXTURE_NAMES)
def test_resources_report_as_empty(c_client, py_client, fixture):
    """Resources are not ported to C: it always returns an empty set. Where the
    Python edition also has none (every ELF, PE files without resources) the two
    agree; a PE with resources is the one sanctioned difference."""
    path = str(fixture_path(fixture))
    status, data = c_client.get("resources", path=path)
    assert status == 200 and data == {"items": [], "version": {}}
    py_status, py_data = py_client.get("resources", path=path)
    if py_data == {"items": [], "version": {}}:
        assert (status, data) == (py_status, py_data)


def test_resource_detail_endpoints_are_python_only(c_client):
    pe = str(fixture_path("resdemo.exe"))
    for method, name, params in (("GET", "resource/data", {"path": pe, "index": 0}),
                                 ("GET", "resource/icon", {"path": pe, "index": 8}),
                                 ("POST", "resource/replace", {"path": pe, "index": 0, "out": "/tmp/x"})):
        status, data = c_client.call(method, name, params)
        assert status == 400
        assert data["error"] == "resources are available in the Python edition"


def test_archive_endpoints_reject_non_archives_like_python(c_client, py_client):
    """A non-pack is rejected with the same status as the Python server. The
    real C archive reader (when linked) returns the same message too; the stub
    fallback returns its own message, so only the status is compared here."""
    path = str(fixture_path("hello_elf64"))
    for name in ("archive/list", "archive/file"):
        params = {"path": path} if name == "archive/list" else {"path": path, "name": "x"}
        cs, _ = c_client.call("GET", name, params)
        ps, _ = py_client.call("GET", name, params)
        assert cs == ps and cs >= 400


# --- differential: error behaviour ----------------------------------------------

def test_errors_match_python(c_client, py_client):
    elf = str(fixture_path("hello_elf64"))
    _same(c_client, py_client, "GET", "info", {"path": "/no/such/file/here"})     # 404
    _same(c_client, py_client, "GET", "info", {})                                 # missing param
    _same(c_client, py_client, "GET", "nope", {})                                 # unknown endpoint
    _same(c_client, py_client, "GET", "hexdump", {"path": elf, "length": "abc"})  # bad number
    _same(c_client, py_client, "GET", "strings", {"path": elf, "encoding": "x"})  # bad choice


def test_non_binary_is_a_json_error(c_client, py_client, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    _same(c_client, py_client, "GET", "info", {"path": str(f)})


# --- differential: POST (upload, patch) -----------------------------------------

def test_upload_matches_python(c_client, py_client):
    data = fixture_bytes("bare_elf32")
    c_status, _, c_body = c_client.request(
        "POST", "/api/upload?name=..%2F..%2Fevil.bin", body=data)
    p_status, _, p_body = py_client.request(
        "POST", "/api/upload?name=..%2F..%2Fevil.bin", body=data)
    assert c_status == p_status == 200
    c_saved, p_saved = json.loads(c_body), json.loads(p_body)
    assert c_saved["name"] == p_saved["name"] == "evil.bin"
    for saved in (c_saved, p_saved):
        assert ".." not in saved["path"] and saved["path"].endswith("evil.bin")
        assert Path(saved["path"]).read_bytes() == data
    # the uploaded file is then analysed the same way by both
    assert c_client.get("info", path=c_saved["path"])[1]["arch"] == "x86"
    assert py_client.get("info", path=p_saved["path"])[1]["arch"] == "x86"


def _patch(c_client, py_client, tmp_path, name, base_params, tag):
    """Run the same patch on both servers (to distinct outputs) and compare the
    response (minus the output path) and the resulting file bytes."""
    c_out = tmp_path / f"{tag}.c.bin"
    p_out = tmp_path / f"{tag}.py.bin"
    cs, cj = c_client.call("POST", name, dict(base_params, out=str(c_out)))
    ps, pj = py_client.call("POST", name, dict(base_params, out=str(p_out)))
    assert cs == ps == 200, (name, cs, ps, cj, pj)

    def scrub(d):
        d = {k: v for k, v in d.items() if k != "out"}
        for entry in d.get("patches", []):
            entry.pop("out", None)
        return d

    assert scrub(cj) == scrub(pj), (name, cj, pj)
    assert c_out.read_bytes() == p_out.read_bytes()


def test_patch_bytes_matches_python(c_client, py_client, tmp_path):
    elf = str(fixture_path("hello_elf64"))
    _patch(c_client, py_client, tmp_path, "patch/bytes",
           {"path": elf, "offset": 0, "hex": "90 90 90 90"}, "bytes_off")
    pe = str(fixture_path("hello_pe64.exe"))
    _patch(c_client, py_client, tmp_path, "patch/bytes",
           {"path": pe, "offset": 0, "hex": "cc"}, "bytes_pe")


def test_patch_bytes_by_address_matches_python(c_client, py_client, tmp_path, have_disassembler):
    elf = str(fixture_path("hello_elf64"))
    entry = c_client.get("info", path=elf)[1]["entry"]
    _patch(c_client, py_client, tmp_path, "patch/bytes",
           {"path": elf, "address": entry, "hex": "90 90"}, "bytes_addr")


def test_patch_nop_matches_python(c_client, py_client, tmp_path):
    elf = str(fixture_path("hello_elf64"))
    entry = c_client.get("info", path=elf)[1]["entry"]
    _patch(c_client, py_client, tmp_path, "patch/nop",
           {"path": elf, "address": entry, "length": 4}, "nop")


def test_patch_string_matches_python(c_client, py_client, tmp_path):
    elf = str(fixture_path("hello_elf64"))
    _patch(c_client, py_client, tmp_path, "patch/string",
           {"path": elf, "old": "Hello", "new": "Byeee"}, "str")


def test_patch_errors_match_python(c_client, py_client, tmp_path):
    elf = str(fixture_path("hello_elf64"))
    good_out = str(tmp_path / "out.bin")
    # output to a folder, and output into a missing folder
    _same(c_client, py_client, "POST", "patch/bytes",
          {"path": elf, "offset": 0, "hex": "90", "out": str(tmp_path)})
    _same(c_client, py_client, "POST", "patch/bytes",
          {"path": elf, "offset": 0, "hex": "90", "out": "/no/such/dir/out.bin"})
    # bad hex, and no bytes
    _same(c_client, py_client, "POST", "patch/bytes",
          {"path": elf, "offset": 0, "hex": "zz", "out": good_out})
    # new text longer than old
    _same(c_client, py_client, "POST", "patch/string",
          {"path": elf, "old": "Hi", "new": "Hello", "out": good_out})


# --- access control (mirrors tests/test_server.py) ------------------------------

def test_api_requires_the_session_token(c_client):
    elf = quote(str(fixture_path("hello_elf64")))
    assert c_client.request("GET", f"/api/info?path={elf}", token=False)[0] == 403
    assert c_client.request("GET", f"/api/info?path={elf}", token="wrong")[0] == 403


def test_requests_for_another_host_name_are_refused(c_client):
    elf = quote(str(fixture_path("hello_elf64")))
    status, _, _ = c_client.request(
        "GET", f"/api/info?path={elf}", headers={"Host": "evil.example"})
    assert status == 403


def test_responses_do_not_grant_cross_origin_access(c_client):
    elf = quote(str(fixture_path("hello_elf64")))
    conn = http.client.HTTPConnection("127.0.0.1", c_client.port, timeout=10)
    conn.request("GET", f"/api/info?path={elf}",
                 headers={"X-Vex-Token": c_client.token, "Origin": "http://evil.example"})
    resp = conn.getresponse()
    resp.read()
    assert resp.getheader("Access-Control-Allow-Origin") is None
    conn.close()


def test_security_headers_are_present(c_client):
    conn = http.client.HTTPConnection("127.0.0.1", c_client.port, timeout=10)
    conn.request("GET", "/", headers={"Host": f"127.0.0.1:{c_client.port}"})
    resp = conn.getresponse()
    resp.read()
    assert resp.getheader("X-Content-Type-Options") == "nosniff"
    assert resp.getheader("Referrer-Policy") == "no-referrer"
    assert resp.getheader("Cache-Control") == "no-store"
    assert resp.getheader("Content-Security-Policy") == server.CSP
    conn.close()


# --- static files ---------------------------------------------------------------

def test_index_page_is_served(c_client):
    status, _, body = c_client.request("GET", "/", token=False)
    assert status == 200 and b"<title>vex" in body
    assert c_client.request("GET", "/index.html", token=False)[0] == 200


def test_fonts_are_served_from_the_package(c_client):
    rel = "fonts/ibm-plex-mono-latin-400-normal.woff2"
    status, ctype, body = c_client.request("GET", f"/static/{rel}", token=False)
    assert (status, ctype) == (200, "font/woff2")
    assert body[:4] == b"wOF2"
    assert body == (WEB_DIR / rel).read_bytes()


def test_javascript_and_css_content_types(c_client):
    _, js_ctype, _ = c_client.request("GET", "/static/app.js", token=False)
    _, css_ctype, _ = c_client.request("GET", "/static/app.css", token=False)
    assert js_ctype == "text/javascript; charset=utf-8"
    assert css_ctype == "text/css; charset=utf-8"


def test_static_path_cannot_escape_the_web_directory(c_client):
    for url in ("/static/../server.py", "/static/..%2fserver.py", "/static/%2e%2e/cli.py",
                "/static/does-not-exist", "/nope"):
        assert c_client.request("GET", url, token=False)[0] == 404


# --- hostile requests under AddressSanitizer/UBSan ------------------------------

def test_survives_hostile_requests(tmp_path):
    _make("asan")
    proc, client = _start_c_server(C_DIR / "build" / "vex-asan")
    port = client.port
    host = f"127.0.0.1:{port}".encode()
    token = client.token.encode()

    def raw(data):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            s.sendall(data)
            s.settimeout(5)
            try:
                return s.recv(4096)
            except socket.timeout:
                return b""
        except OSError:
            return b""
        finally:
            s.close()

    hostiles = [
        b"X" * 70000,                                                    # oversized garbage
        b"GET / HTTP/1.1\r\nHost: " + host,                             # no terminating CRLF
        b"POST /api/upload?name=x HTTP/1.1\r\nHost: " + host +
        b"\r\nX-Vex-Token: " + token +
        b"\r\nContent-Length: 999999999\r\n\r\nshort",                  # lying length, truncated
        b"POST /api/upload?name=x HTTP/1.1\r\nHost: " + host +
        b"\r\nContent-Length: not-a-number\r\n\r\n",                    # bad Content-Length
        b"GET /api/info?path=%ZZ%2%2f%%% HTTP/1.1\r\nHost: " + host +
        b"\r\nX-Vex-Token: " + token + b"\r\n\r\n",                # malformed escapes
        bytes(range(256)) * 8,                                          # binary garbage
        b"GET /static/../../../../etc/passwd HTTP/1.1\r\nHost: " + host + b"\r\n\r\n",
        b"\r\n\r\n\r\n",
        b"GET",
        b"GET " + b"/" * 50000 + b" HTTP/1.1\r\nHost: " + host + b"\r\n\r\n",
        b"POST /api/patch/bytes?path=/etc/hostname&offset=0&hex=zz&out=/tmp/z HTTP/1.1\r\n"
        b"Host: " + host + b"\r\nX-Vex-Token: " + token + b"\r\n\r\n",
    ]
    try:
        for data in hostiles:
            raw(data)                               # must not crash or hang the server
        # the server is still up and answering
        status, _, body = client.request("GET", "/", token=False)
        assert status == 200 and b"<title>vex" in body
        # and a token-authenticated API call still works
        status, data = client.get("info", path=str(fixture_path("hello_elf64")))
        assert status == 200 and data["format"] == "ELF"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        err = proc.stderr.read() or ""
    for marker in ("AddressSanitizer", "runtime error:", "LeakSanitizer", "SUMMARY:"):
        assert marker not in err, err[-3000:]


# --- the Windows build ----------------------------------------------------------

@pytest.mark.skipif(not MINGW, reason="the Windows build needs x86_64-w64-mingw32-gcc")
def test_windows_build_is_a_console_exe():
    _make("windows")
    exe = C_DIR / "build" / "vex.exe"
    assert exe.is_file()
    info = vex.views.info(vex.load(str(exe)))
    assert info["format"] == "PE"
    assert info["bits"] == 64
    assert info["kind"] == "executable"
    assert info["metadata"].get("subsystem") == "console"
