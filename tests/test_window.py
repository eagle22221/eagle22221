"""`vex gui` opens the interface in its own app window, not a browser tab.

The window is a Chromium-family browser (Edge, Chrome, Chromium) started in
app mode with a throw-away profile. These tests stand a small script in for the
browser, so they check what vex launches and how it behaves when the window
closes, without needing a display.

Every `vex gui` test runs against both editions: the Python package and the
native C program (c/build/vex, built on demand). They must launch the same
things and print the same text.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

import pytest

from vex import server, window

ROOT = Path(__file__).resolve().parent.parent
C_DIR = ROOT / "c"

FAKE = """#!{python}
import json, os, sys, time
with open(os.environ["VEX_FAKE_LOG"] + ".tmp", "w") as f:
    json.dump({{"argv": sys.argv[1:], "pid": os.getpid()}}, f)
os.replace(os.environ["VEX_FAKE_LOG"] + ".tmp", os.environ["VEX_FAKE_LOG"])
time.sleep(float(os.environ.get("VEX_FAKE_SECS", "0")))
sys.exit(int(os.environ.get("VEX_FAKE_EXIT", "0")))
"""



def _c_edition():
    """The native build of the C edition (built once; reuses test_c_gui's make
    step). VEX_TEST_SANITIZED=1 runs the AddressSanitizer/UBSan build instead."""
    from test_c_gui import COMPILER, MAKE, _make
    if not (MAKE and COMPILER and C_DIR.is_dir()):
        pytest.skip("the C edition needs make and a C compiler")
    target, name = ("asan", "vex-asan") if os.environ.get("VEX_TEST_SANITIZED") else ("all", "vex")
    if name not in _BUILT:
        _make(target)
        _BUILT.add(name)
    return [str(C_DIR / "build" / name)]


_BUILT = set()
EDITIONS = {"python": lambda: [sys.executable, "-m", "vex"], "c": _c_edition}
WINDOW_HINT, BROWSER_HINT = server.WINDOW_HINT, server.BROWSER_HINT
FALLBACK_NOTE, LOST_NOTE = server.FALLBACK_NOTE, server.LOST_NOTE


def _script(path: Path, text: str) -> Path:
    path.write_text(text)
    path.chmod(0o755)
    return path


class Run:
    """One `vex gui` process with stand-in browsers."""

    def __init__(self, tmp_path, edition, args=(), app_browser=True, secs=0, exit_code=0,
                 env_extra=None):
        self.edition = edition
        self.app_log = tmp_path / "app.json"          # the app-window browser was started
        self.tab_log = tmp_path / "tab.json"          # the ordinary browser was started
        fake = FAKE.format(python=sys.executable)
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        app = _script(tmp_path / "fake-app-browser", fake)
        _script(bin_dir / "xdg-open", fake)           # what the C edition falls back to
        tab = _script(tmp_path / "fake-tab-browser", fake)
        env = {"PATH": str(bin_dir), "HOME": str(tmp_path), "PYTHONPATH": str(ROOT),
               "VEX_FAKE_SECS": str(secs), "VEX_FAKE_EXIT": str(exit_code),
               "TMPDIR": str(tmp_path)}
        if app_browser:
            env["VEX_BROWSER"] = str(app)
        env.update(env_extra or {})
        # The ordinary browser: Python's webbrowser honours $BROWSER, the C
        # edition runs xdg-open; both stand-ins write tab.json.
        env["BROWSER"] = str(tab)
        # One process cannot give two children different environments, so the
        # stand-ins tell themselves apart by name.
        wrapper = ("#!{python}\nimport os, sys\n"
                   "name = os.path.basename(sys.argv[0])\n"
                   "os.environ['VEX_FAKE_LOG'] = {tab!r} if name in ('xdg-open', 'fake-tab-browser') else {app!r}\n"
                   "if name != 'fake-app-browser':\n"
                   "    os.environ['VEX_FAKE_SECS'] = '0'; os.environ['VEX_FAKE_EXIT'] = '0'\n"
                   ).format(python=sys.executable, tab=str(self.tab_log), app=str(self.app_log))
        body = fake.split("\n", 1)[1]
        for script in (app, tab, bin_dir / "xdg-open"):
            _script(script, wrapper + body)
        self.proc = subprocess.Popen(EDITIONS[edition]() + ["gui", *args], env=env,
                                     cwd=str(tmp_path), stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
        self.output = ""

    def read_until(self, needle, timeout=15):
        deadline = time.time() + timeout
        fd = self.proc.stdout.fileno()
        os.set_blocking(fd, False)
        while needle not in self.output:
            assert time.time() < deadline, f"never printed {needle!r}; got:\n{self.output}"
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                time.sleep(0.05)
                continue
            assert chunk, f"exited without {needle!r}; got:\n{self.output}"
            self.output += chunk.decode()
        return self.output

    def url(self):
        line = [l for l in self.read_until("#token=").splitlines() if "#token=" in l][0]
        return line.strip()

    def port(self):
        return int(self.url().split("127.0.0.1:", 1)[1].split("/", 1)[0])

    def rest(self, timeout=15):
        """Everything it printed, once it has ended."""
        self.proc.wait(timeout=timeout)
        fd = self.proc.stdout.fileno()
        os.set_blocking(fd, True)
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return self.output
            self.output += chunk.decode()

    def log(self, path, timeout=10):
        deadline = time.time() + timeout
        while not path.exists():
            assert time.time() < deadline, f"{path.name} was never written"
            time.sleep(0.05)
        return json.loads(path.read_text())

    def interrupt(self):
        self.proc.send_signal(signal.SIGINT)
        return self.proc.wait(timeout=15)

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.proc.stdout.close()
        self.proc.stderr.close()


def _starter(tmp_path, edition):
    made = []

    def start(**kw):
        made.append(Run(tmp_path, edition, **kw))
        return made[-1]
    return start, made


@pytest.fixture(params=sorted(EDITIONS))
def run(request, tmp_path):
    start, made = _starter(tmp_path, request.param)
    yield start
    for r in made:
        r.close()


@pytest.fixture
def run_c(tmp_path):
    """For what only the C edition does."""
    start, made = _starter(tmp_path, "c")
    yield start
    for r in made:
        r.close()


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


# --- the app window ---------------------------------------------------------

def _banner(url, hint):
    return f"vex is running at:\n\n  {url}\n\n{hint}\n"


def _profile(argv):
    return [a for a in argv if a.startswith("--user-data-dir=")][0].split("=", 1)[1]


def _idle_connection(r):
    """A client that connects and then says nothing, as a browser's spare
    connection can. It must not keep vex from stopping."""
    sock = socket.create_connection(("127.0.0.1", r.port()), timeout=5)
    time.sleep(0.3)                                     # let the server take it
    return sock


def test_gui_opens_its_own_window_and_stops_when_it_closes(run):
    r = run(secs=4)                                     # the "window" stays open 4 s
    url = r.url()
    argv = r.log(r.app_log)["argv"]
    assert f"--app={url}" in argv                       # app mode: no tabs, no address bar
    profile = _profile(argv)
    assert os.path.isdir(profile)                       # a profile of its own...
    assert "--no-first-run" in argv and "--no-default-browser-check" in argv
    assert not r.tab_log.exists()                       # the ordinary browser stays out of it
    assert "own window" in r.read_until("own window")
    assert r.proc.wait(timeout=15) == 0                 # the window closed, so vex stopped
    assert not os.path.exists(profile)                  # ...that is thrown away afterwards


def test_what_it_prints_when_the_window_closes(run):
    r = run(secs=4)
    url = r.url()
    assert r.rest() == _banner(url, WINDOW_HINT) + "\nstopped.\n"
    assert r.proc.returncode == 0


def test_ctrl_c_closes_the_window_too(run):
    r = run(secs=120)
    url = r.url()
    log = r.log(r.app_log)
    pid, profile = log["pid"], _profile(log["argv"])
    assert _alive(pid)
    r.read_until(WINDOW_HINT)
    assert r.interrupt() == 0
    deadline = time.time() + 10
    while _alive(pid) and time.time() < deadline:
        time.sleep(0.05)
    assert not _alive(pid)
    assert not os.path.exists(profile)                  # the throw-away profile is gone too
    assert r.rest() == _banner(url, WINDOW_HINT) + "\nstopped.\n"


def test_a_window_that_cannot_open_falls_back_to_the_browser(run):
    r = run(secs=0, exit_code=1)                        # the app browser fails at once
    url = r.url()
    assert r.log(r.tab_log)["argv"][-1] == url
    r.read_until("web browser instead")
    assert r.proc.poll() is None                        # still serving
    assert r.interrupt() == 0
    assert r.rest() == _banner(url, WINDOW_HINT) + FALLBACK_NOTE + "\n\nstopped.\n"


def test_a_window_vex_cannot_follow_keeps_it_running(run):
    # An already-running browser can take the window over and let the launched
    # process end at once (status 0). vex must not mistake that for "closed".
    r = run(secs=0, exit_code=0)
    url = r.url()
    r.log(r.app_log)
    r.read_until("could not follow")
    assert not r.tab_log.exists()
    assert r.proc.poll() is None
    assert r.interrupt() == 0
    assert r.rest() == _banner(url, WINDOW_HINT) + LOST_NOTE + "\n\nstopped.\n"


def test_without_an_app_browser_it_opens_the_ordinary_browser(run):
    r = run(app_browser=False)
    url = r.url()
    assert r.log(r.tab_log)["argv"][-1] == url
    assert "Press Ctrl+C to stop." in r.read_until("Press Ctrl+C")
    assert not r.app_log.exists()
    assert r.interrupt() == 0
    assert r.rest() == _banner(url, BROWSER_HINT) + "\nstopped.\n"


def test_browser_flag_forces_an_ordinary_browser_tab(run):
    r = run(args=["--browser"], secs=120)
    url = r.url()
    assert r.log(r.tab_log)["argv"][-1] == url
    assert not r.app_log.exists()
    assert r.interrupt() == 0
    assert r.rest() == _banner(url, BROWSER_HINT) + "\nstopped.\n"


@pytest.mark.parametrize("args", [["--no-browser"], ["--browser", "--no-browser"]])
def test_no_browser_opens_nothing(run, args):
    r = run(args=args, secs=120)
    url = r.url()
    r.read_until("Press Ctrl+C to stop.")
    time.sleep(0.5)
    assert not r.app_log.exists() and not r.tab_log.exists()
    assert r.interrupt() == 0
    assert r.rest() == _banner(url, BROWSER_HINT) + "\nstopped.\n"


def test_the_file_to_open_travels_in_the_link(run, tmp_path):
    target = tmp_path / "some file.bin"
    target.write_bytes(b"\x7fELF")
    r = run(args=[str(target)], secs=4)
    url = r.url()
    assert url.endswith("&open=" + quote(str(target), safe=""))
    assert f"--app={url}" in r.log(r.app_log)["argv"]
    assert r.proc.wait(timeout=15) == 0


def test_ctrl_c_stops_it_while_a_client_holds_a_connection_open(run):
    r = run(args=["--no-browser"])
    r.read_until(BROWSER_HINT)
    with _idle_connection(r):
        started = time.time()
        assert r.interrupt() == 0
        assert time.time() - started < 5


def test_closing_the_window_stops_it_while_a_client_holds_a_connection_open(run):
    r = run(secs=4)
    r.read_until(WINDOW_HINT)
    with _idle_connection(r):
        assert r.proc.wait(timeout=10) == 0


def test_it_still_serves_while_the_window_is_open(run):
    r = run(secs=120)
    port = r.port()
    r.read_until(WINDOW_HINT)
    import http.client
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/")
    resp = conn.getresponse()
    assert resp.status == 200 and b"<html" in resp.read().lower()
    conn.close()
    assert r.interrupt() == 0


# --- what only the C edition does ----------------------------------------------

def test_c_window_log_traces_the_front_end_decisions(run_c, tmp_path):
    # A windowed program has nowhere to print: %VEX_WINDOW_LOG% (here
    # $VEX_WINDOW_LOG) records which front end was tried and what happened.
    log = tmp_path / "window.log"
    r = run_c(secs=4, env_extra={"VEX_WINDOW_LOG": str(log)})
    r.url()
    assert r.proc.wait(timeout=15) == 0
    text = log.read_text()
    steps = ["gui: serving on http://127.0.0.1:", "gui: front end: the app window",
             "app window: started", "app window: closed", "app window: profile deleted",
             "gui: stopping (the window was closed)", "gui: stopped"]
    if os.name == "nt":                                 # vex's own window comes first there
        steps.insert(1, "gui: front end: the native window")
    at = 0
    for step in steps:                                  # all of them, in this order
        assert step in text[at:], text
        at = text.index(step, at)
    assert "#token=" not in text                        # the session token stays out of it
    assert all(line.startswith("[") and " ms] " in line for line in text.splitlines())


@pytest.mark.parametrize("case, steps", [
    ({"app_browser": False}, ("app window: no browser", "gui: front end: a browser tab")),
    ({"secs": 0, "exit_code": 1}, ("app window: failed", "gui: front end: a browser tab")),
    ({"secs": 0, "exit_code": 0}, ("app window: lost",)),
    ({"args": ["--browser"]}, ("gui: front end: a browser tab",)),
    ({"args": ["--no-browser"]}, ("gui: --no-browser: nothing to open",)),
])
def test_c_window_log_says_why_it_fell_back(run_c, tmp_path, case, steps):
    log = tmp_path / "window.log"
    r = run_c(env_extra={"VEX_WINDOW_LOG": str(log)}, **case)
    r.url()
    r.read_until("Press Ctrl+C to stop.")
    deadline = time.time() + 10
    while not all(step in (log.read_text() if log.exists() else "") for step in steps):
        assert time.time() < deadline, log.read_text() if log.exists() else "(no log)"
        time.sleep(0.05)
    assert r.interrupt() == 0
    assert "gui: stopping (interrupted)" in log.read_text()


def test_c_window_log_records_a_start_up_error(run_c, tmp_path):
    # The windowed program shows its errors in a box, which can be dismissed
    # unread: the log keeps them too.
    log = tmp_path / "window.log"
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        r = run_c(args=["--port", str(taken.getsockname()[1])],
                  env_extra={"VEX_WINDOW_LOG": str(log)})
        assert r.proc.wait(timeout=15) == 1
    assert "vex: error: could not bind to the port" in r.proc.stderr.read().decode()
    assert "error: could not bind to the port" in log.read_text()
    assert not r.app_log.exists() and not r.tab_log.exists()


def test_c_without_a_log_setting_nothing_is_written(run_c, tmp_path):
    r = run_c(secs=4)
    r.url()
    assert r.proc.wait(timeout=15) == 0
    assert not list(tmp_path.glob("*.log"))


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGHUP])
def test_c_being_told_to_stop_closes_the_window_and_deletes_the_profile(run_c, sig):
    r = run_c(secs=120)
    url = r.url()
    log = r.log(r.app_log)
    pid, profile = log["pid"], _profile(log["argv"])
    r.read_until(WINDOW_HINT)
    r.proc.send_signal(sig)
    assert r.proc.wait(timeout=15) == 0
    deadline = time.time() + 10
    while _alive(pid) and time.time() < deadline:
        time.sleep(0.05)
    assert not _alive(pid) and not os.path.exists(profile)
    assert r.rest() == _banner(url, WINDOW_HINT) + "\nstopped.\n"


def test_c_a_hangup_ignored_from_the_start_stays_ignored(tmp_path):
    # `nohup vex gui &`: closing the terminal must not stop it.
    proc = subprocess.Popen(EDITIONS["c"]() + ["gui", "--no-browser"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            preexec_fn=lambda: signal.signal(signal.SIGHUP, signal.SIG_IGN))
    try:
        assert b"Press Ctrl+C" in proc.stdout.readline() + proc.stdout.readline() + \
            proc.stdout.readline() + proc.stdout.readline() + proc.stdout.readline()
        proc.send_signal(signal.SIGHUP)
        time.sleep(0.5)
        assert proc.poll() is None
        proc.send_signal(signal.SIGINT)
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()


@pytest.mark.skipif(not os.path.exists("/proc/self/status"), reason="reads /proc")
@pytest.mark.parametrize("edition", sorted(EDITIONS))
def test_the_browser_does_not_inherit_an_ignored_sigpipe(tmp_path, edition):
    # vex ignores SIGPIPE for its sockets; the browser it starts must not.
    seen = tmp_path / "sigign"
    browser = _script(tmp_path / "browser", f"#!/bin/sh\ngrep SigIgn /proc/$$/status > {seen}.tmp\n"
                                            f"mv {seen}.tmp {seen}\nsleep 4\n")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "PYTHONPATH": str(ROOT),
           "VEX_BROWSER": str(browser), "TMPDIR": str(tmp_path)}
    proc = subprocess.run(EDITIONS[edition]() + ["gui"], env=env, capture_output=True, timeout=30)
    assert proc.returncode == 0
    mask = int(seen.read_text().split()[1], 16)
    assert not mask & (1 << (signal.SIGPIPE - 1))


def test_c_help_lists_the_browser_option():
    out = subprocess.run(EDITIONS["c"]() + ["--help"], capture_output=True, text=True).stdout
    assert "gui [FILE] [--port N] [--browser] [--no-browser]" in out


# --- finding a browser ------------------------------------------------------

def test_vex_browser_names_the_program_to_use(tmp_path):
    exe = _script(tmp_path / "my-browser", "#!/bin/sh\n")
    assert window.find_browser({"VEX_BROWSER": str(exe), "PATH": ""}) == str(exe)
    assert window.find_browser({"VEX_BROWSER": str(tmp_path / "missing"), "PATH": ""}) is None


@pytest.mark.skipif(os.name == "nt", reason="PATH search is the Linux rule")
def test_known_browsers_are_found_on_the_path_in_order(tmp_path):
    for name in ("chromium", "microsoft-edge"):
        _script(tmp_path / name, "#!/bin/sh\n")
    assert window.find_browser({"PATH": str(tmp_path)}) == str(tmp_path / "chromium")
    _script(tmp_path / "google-chrome", "#!/bin/sh\n")
    assert window.find_browser({"PATH": str(tmp_path)}) == str(tmp_path / "google-chrome")
    assert window.find_browser({"PATH": str(tmp_path / "empty")}) is None


def test_firefox_is_not_used_for_the_window(tmp_path):
    _script(tmp_path / "firefox", "#!/bin/sh\n")        # has no app mode
    assert window.find_browser({"PATH": str(tmp_path)}) is None


def test_command_line_for_the_window():
    argv = window.command("/b", "http://127.0.0.1:5/#token=t&open=%2Fa%20b", "/tmp/p")
    assert argv[0] == "/b"
    assert "--app=http://127.0.0.1:5/#token=t&open=%2Fa%20b" in argv
    assert "--user-data-dir=/tmp/p" in argv
    assert "--disable-background-mode" in argv          # the process must end with the window
    assert any(a.startswith("--window-size=") for a in argv)


# --- the window's icon --------------------------------------------------------

from test_server import client     # noqa: E402,F401  (pytest fixture)


@pytest.mark.parametrize("size", [48, 256])
def test_page_offers_png_icons_for_the_window_and_taskbar(client, size):
    # An app window takes its title-bar and taskbar icon from the page icons;
    # PNG works everywhere an SVG icon may not.
    page = client.request("GET", "/", token=False)[2].decode()
    assert (f'<link rel="icon" type="image/png" sizes="{size}x{size}" '
            f'href="/static/icon-{size}.png">') in page
    status, ctype, body = client.request("GET", f"/static/icon-{size}.png", token=False)
    assert status == 200 and ctype == "image/png"
    assert body[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = int.from_bytes(body[16:20], "big"), int.from_bytes(body[20:24], "big")
    assert (width, height) == (size, size)
