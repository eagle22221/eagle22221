"""Opening the interface in its own window instead of a browser tab.

The window is a Chromium-family browser (Edge, Chrome, Chromium, Brave) started
in "app mode": one page, no tabs and no address bar. It gets a throw-away
profile, so it shares nothing with the browser the user works in, the launched
process lives exactly as long as the window, and nothing is left behind.

When no such browser is installed vex falls back to an ordinary browser tab.
"""
import os
import shutil
import subprocess
from typing import Iterator, List, Mapping, Optional

# Names searched on the PATH (Linux and other Unix systems), best first.
PATH_NAMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
              "microsoft-edge", "microsoft-edge-stable", "brave-browser")
MAC_APPS = ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium")
# Windows: Edge ships with the system, so it comes first.
WINDOWS_EXES = ("msedge.exe", "chrome.exe")
WINDOWS_PLACES = (r"Microsoft\Edge\Application\msedge.exe",
                  r"Google\Chrome\Application\chrome.exe")
WINDOW_SIZE = (1360, 900)
# A window that "closes" sooner than this was never ours to follow: either the
# browser could not start, or a running browser took the window over.
QUICK_EXIT_SECS = 3.0


def _windows_candidates(env: Mapping[str, str]) -> Iterator[str]:
    try:
        import winreg
    except ImportError:                 # not Windows
        return
    for exe in WINDOWS_EXES:
        for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}"
                with winreg.OpenKey(root, key) as handle:
                    value, _kind = winreg.QueryValueEx(handle, None)
                    yield str(value).strip('"')
            except OSError:
                continue
    for place in WINDOWS_PLACES:
        for base in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
            if env.get(base):
                yield os.path.join(env[base], place)


def find_browser(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """The browser to open the window with, or None when there is none.
    $VEX_BROWSER, when set, names the program and nothing else is tried."""
    env = os.environ if env is None else env
    chosen = env.get("VEX_BROWSER")
    if chosen is not None:
        return chosen if os.path.isfile(chosen) else None
    candidates = list(_windows_candidates(env)) if os.name == "nt" else list(MAC_APPS)
    for path in candidates:
        if os.path.isfile(path):
            return path
    if os.name != "nt":
        for name in PATH_NAMES:
            found = shutil.which(name, path=env.get("PATH", ""))
            if found:
                return found
    return None


def command(browser: str, url: str, profile_dir: str) -> List[str]:
    return [browser, f"--app={url}", f"--user-data-dir={profile_dir}",
            "--no-first-run", "--no-default-browser-check", "--disable-background-mode",
            f"--window-size={WINDOW_SIZE[0]},{WINDOW_SIZE[1]}"]


def open_window(url: str, profile_dir: str,
                env: Optional[Mapping[str, str]] = None) -> Optional[subprocess.Popen]:
    """Start the app window. Returns its process, or None if it cannot be opened."""
    browser = find_browser(env)
    if browser is None:
        return None
    try:
        os.makedirs(profile_dir, exist_ok=True)
        return subprocess.Popen(command(browser, url, profile_dir), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        return None


def close_window(proc: Optional[subprocess.Popen]) -> None:
    """Close the window if it is still open, and wait for it to go."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            proc.kill()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
