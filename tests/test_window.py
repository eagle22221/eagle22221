"""`vex gui` opens the interface in its own app window, not a browser tab.

The window is a Chromium-family browser (Edge, Chrome, Chromium) started in
app mode with a throw-away profile. These tests stand a small script in for the
browser, so they check what vex launches and how it behaves when the window
closes, without needing a display.
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from vex import window

ROOT = Path(__file__).resolve().parent.parent

FAKE = """#!{python}
import json, os, sys, time
with open(os.environ["VEX_FAKE_LOG"] + ".tmp", "w") as f:
    json.dump({{"argv": sys.argv[1:], "pid": os.getpid()}}, f)
os.replace(os.environ["VEX_FAKE_LOG"] + ".tmp", os.environ["VEX_FAKE_LOG"])
time.sleep(float(os.environ.get("VEX_FAKE_SECS", "0")))
sys.exit(int(os.environ.get("VEX_FAKE_EXIT", "0")))
"""

EDITIONS = {"python": [sys.executable, "-m", "vex"]}


def _script(path: Path, text: str) -> Path:
    path.write_text(text)
    path.chmod(0o755)
    return path


class Run:
    """One `vex gui` process with stand-in browsers."""

    def __init__(self, tmp_path, edition, args=(), app_browser=True, secs=0, exit_code=0):
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
        self.proc = subprocess.Popen(EDITIONS[edition] + ["gui", *args], env=env, cwd=str(tmp_path),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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


@pytest.fixture(params=sorted(EDITIONS))
def run(request, tmp_path):
    made = []

    def start(**kw):
        made.append(Run(tmp_path, request.param, **kw))
        return made[-1]
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

def test_gui_opens_its_own_window_and_stops_when_it_closes(run):
    r = run(secs=4)                                     # the "window" stays open 4 s
    url = r.url()
    argv = r.log(r.app_log)["argv"]
    assert f"--app={url}" in argv                       # app mode: no tabs, no address bar
    profile = [a for a in argv if a.startswith("--user-data-dir=")][0].split("=", 1)[1]
    assert os.path.isdir(profile)                       # a profile of its own...
    assert "--no-first-run" in argv and "--no-default-browser-check" in argv
    assert not r.tab_log.exists()                       # the ordinary browser stays out of it
    assert "own window" in r.read_until("own window")
    assert r.proc.wait(timeout=15) == 0                 # the window closed, so vex stopped
    assert not os.path.exists(profile)                  # ...that is thrown away afterwards


def test_ctrl_c_closes_the_window_too(run):
    r = run(secs=120)
    r.url()
    pid = r.log(r.app_log)["pid"]
    assert _alive(pid)
    assert r.interrupt() == 0
    deadline = time.time() + 10
    while _alive(pid) and time.time() < deadline:
        time.sleep(0.05)
    assert not _alive(pid)


def test_a_window_that_cannot_open_falls_back_to_the_browser(run):
    r = run(secs=0, exit_code=1)                        # the app browser fails at once
    url = r.url()
    assert r.log(r.tab_log)["argv"][-1] == url
    r.read_until("web browser instead")
    assert r.proc.poll() is None                        # still serving
    assert r.interrupt() == 0


def test_a_window_vex_cannot_follow_keeps_it_running(run):
    # An already-running browser can take the window over and let the launched
    # process end at once (status 0). vex must not mistake that for "closed".
    r = run(secs=0, exit_code=0)
    r.url()
    r.log(r.app_log)
    r.read_until("could not follow")
    assert not r.tab_log.exists()
    assert r.proc.poll() is None
    assert r.interrupt() == 0


def test_without_an_app_browser_it_opens_the_ordinary_browser(run):
    r = run(app_browser=False)
    url = r.url()
    assert r.log(r.tab_log)["argv"][-1] == url
    assert "Press Ctrl+C to stop." in r.read_until("Press Ctrl+C")
    assert not r.app_log.exists()
    assert r.interrupt() == 0


def test_browser_flag_forces_an_ordinary_browser_tab(run):
    r = run(args=["--browser"], secs=120)
    url = r.url()
    assert r.log(r.tab_log)["argv"][-1] == url
    assert not r.app_log.exists()
    assert r.interrupt() == 0


def test_no_browser_opens_nothing(run):
    r = run(args=["--no-browser"], secs=120)
    r.url()
    r.read_until("Press Ctrl+C to stop.")
    time.sleep(0.5)
    assert not r.app_log.exists() and not r.tab_log.exists()
    assert r.interrupt() == 0


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
