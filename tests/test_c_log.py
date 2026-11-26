"""The run's log of the C edition (window_trace, c/src/window.c) and what the
server writes to it (c/src/server.c).

On Windows the programs that show the interface log to vex-log.txt next to
the .exe by default; that cannot be run here. What can: the log itself on
POSIX, where $VEX_WINDOW_LOG names the file (rotation, the size cap, many
threads, the session token kept out), the path helpers the Windows log is
built with (c/tests/log_check.c, which includes window.c whole), and the
server's lines: one per request, socket trouble, and the page's own notes of
requests that never got an answer (POST /api/log, which server.py accepts
and drops with the same checks).
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

from vex import server
from conftest import fixture_path

C_DIR = Path(__file__).resolve().parent.parent / "c"
MAKE = shutil.which("make")
COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
ELF = str(fixture_path("hello_elf64"))
LINE = re.compile(r"^\[ *\d+ ms\] \S")

pytestmark = pytest.mark.skipif(
    not (MAKE and COMPILER and C_DIR.is_dir() and os.name != "nt"),
    reason="needs make and a C compiler (POSIX)")


def _make(target):
    proc = subprocess.run([MAKE, "-C", str(C_DIR), target], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


# --- the unit checks (c/tests/log_check.c) ------------------------------------------

SANITIZERS = {
    "plain": ["-O2"],
    "address": ["-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"],
    "thread": ["-O1", "-g", "-fsanitize=thread"],
}


@pytest.fixture(scope="module", params=sorted(SANITIZERS))
def log_check(request, tmp_path_factory):
    out = tmp_path_factory.mktemp("log-check") / f"log-check-{request.param}"
    proc = subprocess.run([COMPILER, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                           *SANITIZERS[request.param], "-o", str(out),
                           str(C_DIR / "tests" / "log_check.c")],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        if request.param != "plain":
            pytest.skip(f"no {request.param} sanitizer here: {proc.stderr[-300:]}")
        pytest.fail(proc.stderr[-3000:])
    probe = subprocess.run([str(out), "paths"], capture_output=True, text=True)
    if request.param == "thread" and "FATAL: ThreadSanitizer" in probe.stderr:
        pytest.skip("ThreadSanitizer cannot run here")
    return out


def _check(binary, *args, env=None, cwd=None):
    proc = subprocess.run([str(binary), *args], capture_output=True, text=True, env=env, cwd=cwd,
                          timeout=120)
    assert proc.returncode == 0 and proc.stdout == "ok\n", proc.stdout + proc.stderr
    for marker in ("AddressSanitizer", "runtime error:", "ThreadSanitizer", "LeakSanitizer"):
        assert marker not in proc.stderr, proc.stderr[-3000:]


def test_path_helpers_of_the_windows_log(log_check):
    # vex-log.txt beside the .exe, %LOCALAPPDATA%\vex\vex-log.txt, the
    # .previous name, "off", the token hidden even where a line is cut.
    _check(log_check, "paths")


def test_log_keeps_the_run_before_caps_its_size_and_takes_many_threads(log_check, tmp_path):
    (tmp_path / "vex-log.txt").write_text("the run before\n")
    _check(log_check, "run", str(tmp_path))
    assert (tmp_path / "vex-log.previous.txt").read_text() == "the run before\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["vex-log.previous.txt", "vex-log.txt"]


@pytest.mark.parametrize("setting", [None, "", "off", "OFF", "0"])
def test_log_can_be_off(log_check, tmp_path, setting):
    env = {k: v for k, v in os.environ.items() if k != "VEX_WINDOW_LOG"}
    if setting is not None:
        env["VEX_WINDOW_LOG"] = setting
    _check(log_check, "quiet", env=env, cwd=tmp_path)
    assert list(tmp_path.iterdir()) == []


# --- the server's lines -------------------------------------------------------------

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

    def log(self, events, **kw):
        return self.call("POST", "log", body=json.dumps({"events": events}), **kw)


class Run:
    """`vex gui --no-browser` with its log in `log`."""

    def __init__(self, binary, log, *args):
        env = dict(os.environ, VEX_WINDOW_LOG=str(log))
        self.log_path = log
        self.proc = subprocess.Popen([str(binary), "gui", "--no-browser", "--port", "0", *args],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env=env)
        deadline = time.time() + 30
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            m = re.search(r"http://127\.0\.0\.1:(\d+)/#token=([^&\s]+)", line)
            if m:
                self.client = Client(int(m.group(1)), m.group(2))
                return
            if not line:
                break
        self.proc.kill()
        pytest.fail("the C server did not print its address")

    def raw(self, data, wait=0.3):
        with socket.create_connection(("127.0.0.1", self.client.port), timeout=5) as s:
            if data:
                s.sendall(data)
            time.sleep(wait)

    def stop(self):
        self.proc.terminate()
        try:
            assert self.proc.wait(timeout=15) == 0
        finally:
            if self.proc.poll() is None:
                self.proc.kill()
            self.stderr = self.proc.stderr.read()
            self.proc.stdout.close()
            self.proc.stderr.close()
        return self.log_path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def vex_binary():
    _make("all")
    return C_DIR / "build" / "vex"


FAILED_FETCH = {"kind": "network", "method": "GET", "api": "info",
                "error": "TypeError: Failed to fetch", "ms": 3, "count": 2,
                "time": "2026-11-26T10:00:00.000Z"}


def _line(text, start):
    lines = [line for line in text.splitlines() if start in line]
    assert lines, (start, text)
    return lines[0]


def test_each_request_is_a_line_and_the_token_never_appears(vex_binary, tmp_path):
    log = tmp_path / "vex-log.txt"
    run = Run(vex_binary, log, ELF)
    c = run.client
    assert c.request("GET", "/", token=False)[0] == 200
    assert c.call("GET", "info", {"path": ELF})[0] == 200
    assert c.call("GET", "nope", {"path": ELF})[0] == 404
    assert c.call("GET", "info", {"path": ELF + ".missing"})[0] == 404
    assert c.request("GET", f"/api/info?path={quote(ELF)}", token="wrong")[0] == 403
    assert c.request("GET", f"/api/{c.token}?token={c.token}")[0] == 404   # odd, but no leak
    assert c.log([FAILED_FETCH]) == (204, b"")
    run.raw(b"")                                     # a browser's spare connection
    run.raw(b"GET / HTTP/1.1\r\nHo")                 # a head cut short
    run.raw(b"X" * 70000)                            # a head too large
    run.raw(b"POST /api/log HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Vex-Token: %s\r\n"
            b"Content-Length: 500\r\n\r\n{\"ev" % (c.port, c.token.encode()))  # a body cut short
    text = run.stop()

    assert c.token not in text and "#token=" not in text
    assert all(LINE.match(line) for line in text.splitlines()), text
    # the first lines of the run
    first = text.splitlines()[:4]
    assert re.match(r"\[ *\d+ ms\] vex \d+\.\d+\.\d+: the log of this run, started "
                    r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \(UTC[+-]\d{4}\)$", first[0]), first
    assert first[1].endswith(f"] log: {log}, named by $VEX_WINDOW_LOG; there was no log before")
    assert f"] program: {vex_binary.resolve()} (process {run.proc.pid})" in first[2]
    assert "] system: " in first[3]
    assert f"gui: the file to open: {ELF}" in text
    assert "http: the server thread is serving on port" in text
    assert re.search(r"http: the server thread ends \(told to stop by a signal\) after \d+ "
                     r"requests", text)
    # one line per request: method, path without its query, status, bytes, time
    assert re.search(r"\] http: GET / 200 \d+ B \d+ ms$", text, re.M)
    info = _line(text, "http: GET /api/info 200")
    assert re.search(r"\] http: GET /api/info 200 \d+ B \d+ ms$", info), info
    assert "?" not in info and "path=" not in text
    assert _line(text, "http: GET /api/nope 404").endswith(": unknown API endpoint: nope")
    assert _line(text, "http: GET /api/info 404").endswith(f": no such file or folder: {ELF}.missing")
    assert _line(text, "http: GET /api/info 403").endswith(": missing or wrong session token")
    assert "http: GET /api/[hidden] 404" in text
    # the page's note, and the request that carried it
    assert _line(text, "page: ").endswith(
        "] page: network GET info: TypeError: Failed to fetch "
        "(after 3 ms, 2 times, at 2026-11-26T10:00:00.000Z)")
    assert re.search(r"\] http: POST /api/log 204 0 B \d+ ms$", text, re.M)
    # trouble on the connections
    assert "] http: a connection closed with no request" in text
    assert "] http: a request was cut short after 18 bytes of its head: the client closed " \
           "the connection" in text
    assert "] http: refused a request head of more than 65536 bytes" in text
    assert "; the request body was cut short: 4 of 500 bytes arrived: the client closed the " \
           "connection" in text


def test_a_new_run_keeps_the_log_of_the_run_before(vex_binary, tmp_path):
    log = tmp_path / "vex-log.txt"
    first = Run(vex_binary, log)
    first.client.request("GET", "/api/first-run")
    first_text = first.stop()
    second = Run(vex_binary, log)
    second_text = second.stop()
    assert (tmp_path / "vex-log.previous.txt").read_text() == first_text
    assert "first-run" in first_text and "first-run" not in second_text
    assert "the run before is in vex-log.previous.txt" in second_text


def test_plain_commands_never_create_or_touch_the_log(vex_binary, tmp_path):
    log = tmp_path / "vex-log.txt"
    env = dict(os.environ, VEX_WINDOW_LOG=str(log))
    for args in (["info", ELF], ["info", ELF + ".missing"], ["--version"], ["gui", "--help"]):
        subprocess.run([str(vex_binary), *args], capture_output=True, env=env, timeout=60)
    assert list(tmp_path.iterdir()) == []
    log.write_text("kept\n")
    subprocess.run([str(vex_binary), "info", "/no/such/file"], capture_output=True, env=env,
                   timeout=60)
    assert log.read_text() == "kept\n" and list(tmp_path.iterdir()) == [log]


def test_logging_survives_hostile_requests_under_sanitizers(tmp_path):
    _make("asan")
    log = tmp_path / "vex-log.txt"
    run = Run(C_DIR / "build" / "vex-asan", log)
    c = run.client
    head = b"POST /api/log HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Vex-Token: %s\r\n" % (
        c.port, c.token.encode())
    for body in (b"[" * 100000, b"{\"events\": [" + b"{}," * 5000 + b"{}]}",
                 b"{\"events\": [{\"error\": \"\\u0000\\ud800\xff\xfe\"}]}", bytes(range(256)),
                 json.dumps({"events": [{"error": "x" * 500, "k%d" % i: i} for i in range(20)]}).encode()):
        run.raw(head + b"Content-Length: %d\r\n\r\n" % len(body) + body, wait=0.05)
    run.raw(b"GET /" + b"%41" * 20000 + b" HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % c.port, wait=0.05)
    assert c.call("GET", "info", {"path": ELF})[0] == 200
    text = run.stop()
    for marker in ("AddressSanitizer", "runtime error:", "LeakSanitizer", "SUMMARY:"):
        assert marker not in run.stderr, run.stderr[-3000:]
    assert "http: GET /api/info 200" in text and c.token not in text
    assert all(LINE.match(line) for line in text.splitlines())
    assert "page: event: " + "x" * 500 in text                   # a long field, written whole
    assert "\x00" not in text and "\x01" not in text


# --- POST /api/log: the same checks in both editions --------------------------------

@pytest.fixture(scope="module")
def c_client(vex_binary, tmp_path_factory):
    run = Run(vex_binary, tmp_path_factory.mktemp("c-log") / "vex-log.txt")
    yield run.client
    run.stop()


@pytest.fixture(scope="module")
def py_client():
    httpd, workspace = server.create_server(port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield Client(httpd.server_address[1], workspace.token)
    httpd.shutdown()
    httpd.server_close()
    workspace.close()


LOG_BODIES = [
    ({"events": [FAILED_FETCH]}, 204),
    ({"events": []}, 204),
    ({"events": [{}] * 20}, 204),
    ({"events": [{"error": "x" * 500}]}, 204),
    ({"events": [{"error": "\u00e9" * 250}]}, 204),             # 500 bytes of UTF-8
    ({"events": [{"ms": 1.5, "count": -3, "time": "now"}]}, 204),
    ({"events": [{"error": "x" * 501}]}, 400),
    ({"events": [{"error": "\u00e9" * 251}]}, 400),
    ({"events": [{}] * 21}, 400),
    ({"events": [{"ok": True}]}, 400),
    ({"events": [{"error": None}]}, 400),
    ({"events": [{"error": ["Failed to fetch"]}]}, 400),
    ({"events": [{"error": {"message": "x"}}]}, 400),
    ({"events": ["Failed to fetch"]}, 400),
    ({"events": {"kind": "network"}}, 400),
    ({"notes": []}, 400),
    ([], 400),
    ("not json {", 400),
    ("", 400),
    ({"events": [{"error": "x" * 400}] * 40}, 413),            # more than 16 KiB
]


@pytest.mark.parametrize("body, status", LOG_BODIES)
def test_log_route_checks_its_body_like_python(c_client, py_client, body, status):
    data = body if isinstance(body, str) else json.dumps(body)
    answers = [client.call("POST", "log", body=data.encode()) for client in (c_client, py_client)]
    assert answers[0] == answers[1], answers
    assert answers[0][0] == status, answers
    if status == 204:
        assert answers[0][1] == b""
    else:
        assert set(answers[0][1]) == {"error"}
        assert "Failed to fetch" not in answers[0][1]["error"]  # the body is never echoed


@pytest.mark.parametrize("edition", ["c", "python"])
def test_log_route_needs_the_token_and_post(c_client, py_client, edition):
    client = c_client if edition == "c" else py_client
    body = json.dumps({"events": [FAILED_FETCH]}).encode()
    assert client.request("POST", "/api/log", body=body, token=False)[0] == 403
    assert client.request("POST", "/api/log", body=body, token="wrong")[0] == 403
    assert client.request("GET", "/api/log")[0] == 404
    status, ctype, data = client.request("POST", "/api/log", body=body)
    assert (status, data) == (204, b"")
