"""The redesigned web interface (vex/web): the "vex Pro" layout, its views and
the animated background. These read the files the server sends, which are the
ones the C edition embeds, so they hold for both editions."""
import http.client
import json
import re
import shutil
import subprocess
import threading
from pathlib import Path
from urllib.parse import quote

import pytest

import vex
from vex import server

REPO = Path(__file__).resolve().parent.parent
WEB = REPO / "vex" / "web"


class Client:
    def __init__(self, httpd, workspace):
        self.port = httpd.server_address[1]
        self.token = workspace.token

    def get(self, url, token=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", url, headers={"X-Vex-Token": self.token} if token else {})
        resp = conn.getresponse()
        data = resp.read()
        ctype = resp.getheader("Content-Type", "")
        conn.close()
        return resp.status, ctype, data

    def text(self, url):
        status, _, body = self.get(url)
        assert status == 200, url
        return body.decode()


@pytest.fixture(scope="module")
def client():
    httpd, workspace = server.create_server(port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield Client(httpd, workspace)
    httpd.shutdown()
    httpd.server_close()
    workspace.close()


@pytest.fixture(scope="module")
def page(client):
    return client.text("/")


@pytest.fixture(scope="module")
def script(client):
    return client.text("/static/app.js")


@pytest.fixture(scope="module")
def css(client):
    return client.text("/static/app.css")


def without_comments(source):
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"(?m)(^|[^:\\])//.*$", r"\1", source)


def registry(script):
    """[(id, entry text)] of const VIEWS, in order."""
    block = script[script.index("const VIEWS = {"):script.index("};", script.index("const VIEWS = {"))]
    return re.findall(r"^\s+(\w+): (\{ label: [^\n]*\}),$", block, re.M)


# --- the sidebar ------------------------------------------------------------------

def test_sidebar_has_the_logo_lockup_and_the_credit_with_the_wave(page):
    aside = page[page.index('<aside class="sidebar"'):page.index("</aside>")]
    head = aside[aside.index('class="sidebar-head"'):aside.index('<nav')]
    assert 'src="/static/logo.svg"' in head
    assert 'vex <span class="brand-pro">Pro</span>' in head and "Binary Analysis Suite" in head
    foot = aside[aside.index('class="sidebar-foot"'):]
    assert 'class="wave"' in foot and "Developed by SS" in foot


def test_sidebar_groups_follow_the_design_with_only_views_vex_has(script):
    views = registry(script)
    ids = [view for view, _ in views]
    group = {view: re.search(r"group: (null|'(\w+)')", entry).group(2) for view, entry in views}
    assert ids[0] == "overview" and group["overview"] is None
    assert [v for v in ids if group[v] == "analysis"] == [
        "techniques", "code", "strings", "imports", "exports", "sections", "bytes"]
    assert [v for v in ids if group[v] == "resources"] == ["assets"]
    assert [v for v in ids if group[v] == "advanced"] == ["entropy", "split", "decode", "modify"]
    for title in ("'Analysis'", "'Resources'", "'Advanced'"):
        assert f"title: {title}" in script
    labels = " ".join(re.findall(r"(?:label|side): '([^']+)'", script[:script.index("function renderNav")]))
    assert "Code (Disassembly)" in labels and "Bytes (Hex)" in labels and "Patching / Modify" in labels
    for missing in ("Decompiler", "Emulation", "Diff", "Scripting", "Certificates", "Debug Info", "Tables"):
        assert missing not in labels, missing


def test_every_view_renders_and_has_an_icon_in_the_sprite_line_style(script, page):
    symbols = dict(re.findall(r'<symbol id="i-(\w+)"([^>]*)>', page))
    for view, entry in registry(script):
        render = re.search(r"render: (\w+)", entry).group(1)
        assert f"async function {render}(box)" in script, render
        name = re.search(r"icon: '(\w+)'", entry).group(1)
        assert symbols.get(name) == symbols["techniques"], name


def test_view_tab_row_and_tools_menu_name_only_registered_views(script):
    ids = {view for view, _ in registry(script)}
    for const in ("TAB_ROW", "TOOLS"):
        listed = re.search(rf"const {const} = \[([^\]]*)\]", script).group(1)
        names = re.findall(r"'(\w+)'", listed)
        assert names and set(names) <= ids, const
    assert re.findall(r"'(\w+)'", re.search(r"const TOOLS = \[([^\]]*)\]", script).group(1)) == [
        "split", "decode", "modify", "assets"]


def test_exports_have_their_own_view(script):
    source = script[script.index("async function renderExports(box)"):]
    source = source[:source.index("\n}\n")]
    assert set(re.findall(r"\bapi\('([^']+)'", source)) == {"exports"}
    imports = script[script.index("async function renderImports(box)"):]
    assert "api('exports'" not in imports[:imports.index("\n}\n")]


# --- top bar, file header, status bar ------------------------------------------

def test_top_bar_has_file_tabs_settings_and_help_but_no_dead_controls(page):
    bar = page[page.index('<header class="topbar">'):page.index("</header>")]
    assert 'id="filetabs" role="tablist"' in bar and 'id="tab-add"' in bar
    assert 'id="settings-button"' in bar and 'id="help-button"' in bar
    assert 'id="motion-toggle"' in bar and 'id="theme-dark"' in bar and 'id="theme-light"' in bar
    for absent in ("notification", "bell", "minimi", "maximi"):
        assert absent not in bar.lower(), absent
    about = page[page.index('id="about-dialog"'):]
    assert "Developed by SS" in about[:about.index("</dialog>")]


def test_about_shows_the_version_of_both_editions(script):
    version = re.search(r"const VEX_VERSION = '([^']+)'", script).group(1)
    assert version == vex.__version__
    header = (REPO / "c" / "src" / "common.h").read_text()
    assert f'#define VEX_VERSION "{version}"' in header


def test_file_header_actions_and_report(script):
    head = script[script.index("function renderFileHead()"):script.index("function statusItem(")]
    for label in ("'Open File'", "'Refresh'", "'Export Report'", "'Tools'"):
        assert label in head, label
    for tile in ("'EXE'", "'DLL'", "'ELF'", "'SO'"):
        assert tile in script
    report = script[script.index("// --- report ---"):script.index("// --- code ---")]
    assert "saveBlob(blob, `${name}.vex-report.${kind === 'json' ? 'json' : 'md'}`)" in report
    assert "fetch(" not in report  # built in the page from the usual API calls


def test_settings_are_remembered_only_inside_try(script):
    code = without_comments(script)
    for line in code.splitlines():
        if "localStorage" in line or "sessionStorage" in line:
            assert re.search(r"\btry \{", line), line.strip()


# --- entropy ----------------------------------------------------------------------

def test_entropy_is_read_from_the_api_and_drawn_as_inline_svg(script):
    assert "api('entropy', { path: state.path, points })" in script
    entropy = script[script.index("// --- entropy ---"):script.index("// --- overview ---")]
    assert "error.status === 404" in entropy and "error.status >= 500" in entropy  # older servers
    assert "createElementNS" in script and "svg('path'" in entropy and "svg('circle'" in entropy
    assert "goToOffset(p.offset)" in entropy and "show('bytes')" in entropy  # click -> Bytes
    assert "<script" not in entropy and "import(" not in entropy


def test_entropy_route_has_the_shape_the_page_reads(client):
    pe = quote(str(REPO / "tests" / "fixtures" / "bin" / "hello_pe64.exe"), safe="")
    assert client.get(f"/api/entropy?path={pe}")[0] == 403  # needs the session token
    status, _, body = client.get(f"/api/entropy?path={pe}&points=48", token=True)
    assert status == 200, body
    data = json.loads(body)
    assert isinstance(data["size"], int) and isinstance(data["block"], int) and data["block"] > 0
    assert 0 <= data["overall"] <= 8 and data["points"]
    offsets = [p["offset"] for p in data["points"]]
    assert offsets == sorted(offsets) and offsets[0] == 0 and offsets[-1] < data["size"]
    assert all(0 <= p["entropy"] + 1e-9 <= 8 + 1e-9 for p in data["points"])


# --- the animated background --------------------------------------------------

STEP = 0.25  # seconds: the one clock every background animation steps on


def keyframes(css):
    found = {}
    for name, body in re.findall(r"@keyframes\s+([\w-]+)\s*\{((?:[^{}]*\{[^{}]*\})*)[^{}]*\}", without_comments(css)):
        stops = re.findall(r"([\d.]+%|from|to)\s*\{([^}]*)\}", body)
        found[name] = (stops, set(re.findall(r"([\w-]+)\s*:", body)))
    return found


def test_animations_only_move_and_fade_never_blur(css):
    frames = keyframes(css)
    assert {"drift-a", "drift-b", "drift-c", "float", "flow"} <= set(frames)
    for name, (_, props) in frames.items():
        assert props <= {"transform", "opacity"}, name
    code = without_comments(css)
    assert not re.search(r"transition:[^;]*\bfilter\b", code)
    assert "blur(" not in code.replace("backdrop-filter: blur(3px)", "")  # only the open dialog's scrim


def test_background_is_layered_glows_motes_and_wave(page, css):
    backdrop = page[page.index('<div class="backdrop" aria-hidden="true">'):page.index('<div class="app">')]
    assert backdrop.count('class="glow ') == 3 and backdrop.count('class="mote"') >= 12
    code = without_comments(css)
    for cls in (".glow-a", ".glow-b", ".glow-c"):
        rule = re.search(re.escape(cls) + r" \{([^}]*)\}", code).group(1)
        assert "radial-gradient" in rule
    wave = (WEB / "wave.svg").read_text()
    assert "<script" not in wave and "href" not in wave


def test_background_steps_on_one_slow_clock_and_stops_when_asked(css):
    code = without_comments(css)
    first = code.index(':root:not([data-motion="off"]) .glow-a')
    motion = code[code.rindex("@media (prefers-reduced-motion: no-preference) {", 0, first):]
    motion = motion[:motion.index("\n}\n")]
    frames = keyframes(css)
    rules = re.findall(r"^\s+(:root:not\(\[data-motion=\"off\"\]\) [^{]+)\{([^}]*)\}", motion, re.M)
    assert len(rules) >= 8
    current = {}
    for selector, body in rules:
        decl = dict(re.findall(r"(animation(?:-[\w-]+)?):\s*([^;]+);", body))
        if "animation" in decl:
            name, duration, steps = re.match(r"([\w-]+) ([\d.]+)s steps\((\d+)\)", decl["animation"]).groups()
            current = {"name": name, "duration": float(duration), "steps": int(steps)}
            entry = dict(current)
        else:
            entry = dict(current)
            if "animation-duration" in decl:
                entry["duration"] = float(decl["animation-duration"].rstrip("s"))
            if "animation-timing-function" in decl:
                entry["steps"] = int(re.match(r"steps\((\d+)\)", decl["animation-timing-function"]).group(1))
        if "animation-delay" in decl:
            delay = abs(float(decl["animation-delay"].rstrip("s")))
            assert (delay / STEP).is_integer(), selector
        segments = len(frames[entry["name"]][0]) - 1 or 1
        step = entry["duration"] / segments / entry["steps"]
        assert abs(step - STEP) < 1e-9, (selector, step)
    assert re.search(r"@media \(prefers-reduced-motion: reduce\) \{\s*\* \{[^}]*animation: none !important", code)


def test_motion_setting_is_wired_and_respects_reduced_motion(script):
    assert "dataset.motion = on ? 'on' : 'off'" in script
    assert "remember('vex-motion'" in script and "recall('vex-motion') !== 'off'" in script
    assert "matchMedia('(prefers-reduced-motion: reduce)')" in script


def test_wave_tile_is_seamless(client):
    status, ctype, body = client.get("/static/wave.svg")
    assert (status, ctype) == (200, "image/svg+xml")
    svg = body.decode()
    width = int(re.search(r'viewBox="0 0 (\d+) \d+"', svg).group(1))
    paths = re.findall(r'<path d="M0 ([\d.]+) ([^"]*?)L%d ([\d.]+)' % width, svg)
    assert len(paths) >= 10
    for first, _, last in paths:
        assert abs(float(first) - float(last)) < 0.01  # each line ends where the next tile starts


# --- fonts and the policy -----------------------------------------------------------

def test_fonts_named_by_the_stylesheet_are_served_with_their_licences(client, css):
    urls = re.findall(r'url\("(/static/fonts/[^"]+)"\)', css)
    assert any("inter-latin" in u for u in urls) and any("ibm-plex-mono" in u for u in urls)
    for url in urls:
        status, ctype, body = client.get(url)
        assert (status, ctype) == (200, "font/woff2") and body[:4] == b"wOF2", url
    assert (WEB / "fonts" / "OFL-Inter.txt").read_text().startswith("Copyright")


def test_page_keeps_to_the_content_security_policy(page, script):
    assert not re.search(r"<script(?![^>]*\bsrc=)", page)
    assert not re.search(r"\son\w+=", page) and not re.search(r"\sstyle=", page)
    code = without_comments(script)
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert banned not in code, banned
    assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", code)


def test_script_is_valid_javascript():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    result = subprocess.run([node, "--check", str(WEB / "app.js")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
