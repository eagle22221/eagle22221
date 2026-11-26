"""The redesigned web interface (vex/web): the "vex Pro" layout, its views and
the animated background. These read the files the server sends, which are the
ones the C edition embeds, so they hold for both editions."""
import http.client
import json
import math
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

def test_sidebar_has_the_logo_lockup_and_the_credit(page):
    aside = page[page.index('<aside class="sidebar"'):page.index("</aside>")]
    head = aside[aside.index('class="sidebar-head"'):aside.index('<nav')]
    assert 'src="/static/logo.svg"' in head
    assert 'vex <span class="brand-pro">Pro</span>' in head and "Binary Analysis Suite" in head
    foot = aside[aside.index('class="sidebar-foot"'):]
    assert "Developed by SS" in foot
    assert "wave" not in aside  # the background's ribbons replaced the foot's wave


def rule(code, selector):
    """Declarations of the first top-level rule with exactly this selector."""
    found = re.search(r"(?m)^" + re.escape(selector) + r" \{([^}]*)\}", code)
    assert found, selector
    return found.group(1)


def test_sidebar_shares_the_background_with_the_main_area(css):
    code = without_comments(css)
    sidebar = rule(code, ".sidebar")
    for prop in ("background", "border", "box-shadow", "border-radius"):
        assert not re.search(rf"(^|[\s;]){prop}\s*:", sidebar), prop
    # only the phone layout, where the menu drops over the ribbons, gives it a panel
    phone = code[code.index("@media (max-width: 760px)"):]
    assert re.search(r"\.sidebar \{[^}]*background:", phone[:phone.index("\n}\n")])


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

def keyframes(css):
    found = {}
    for name, body in re.findall(r"@keyframes\s+([\w-]+)\s*\{((?:[^{}]*\{[^{}]*\})*)[^{}]*\}", without_comments(css)):
        stops = re.findall(r"([\d.]+%|from|to)\s*\{([^}]*)\}", body)
        found[name] = (stops, set(re.findall(r"([\w-]+)\s*:", body)))
    return found


BACKDROP_ANIMATIONS = {"breathe", "ribbon-a", "ribbon-b", "speck", "twinkle"}
BACKDROP_CLASS = r"\.(backdrop|glow|ribbons?|sparkles?|specks?|motes?)\b"


def test_animations_only_move_and_fade_never_blur(css):
    frames = keyframes(css)
    assert BACKDROP_ANIMATIONS <= set(frames)
    for name, (_, props) in frames.items():
        assert props <= {"transform", "opacity"}, name
    code = without_comments(css)
    assert not re.search(r"transition:[^;]*\bfilter\b", code)
    assert not re.search(r"will-change:[^;]*\bfilter\b", code)
    assert "blur(" not in code.replace("backdrop-filter: blur(3px)", "")  # only the open dialog's scrim
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", code):
        if re.search(BACKDROP_CLASS, selector.split(",")[-1]):
            assert not re.search(r"(^|[\s;])(filter|transition)\s*:", body), selector.strip()


def backdrop(page):
    return page[page.index('<div class="backdrop" aria-hidden="true">'):page.index('<div class="app">')]


def test_background_is_glows_ribbons_sparkles_and_motes(page, css):
    layers = backdrop(page)
    assert layers.count('class="glow ') == 3 and layers.count('class="mote"') >= 12
    assert layers.count('class="speck"') >= 12
    ribbons = re.findall(r'<div class="ribbons ribbons-(\w)"><div class="ribbon ribbon-\1"></div></div>', layers)
    assert len(ribbons) >= 2
    code = without_comments(css)
    for cls in (".glow-a", ".glow-b", ".glow-c"):
        assert "radial-gradient" in rule(code, cls)
    # each ribbon layer has its own tile in each theme, and the tilt that makes
    # the ribbons rise is a fixed skew on the (unanimated) parent
    for n in ribbons:
        for theme in ("dark", "light"):
            assert f'url("/static/ribbons-{theme}-{n}.svg")' in code, (n, theme)
    wrapper = rule(code, ".ribbons")
    assert "skewY(" in wrapper and "atan2(" in wrapper
    assert "animation" not in wrapper
    # the sparkle fields are painted into the sky itself, in both themes
    for selector, theme in ((".backdrop", "dark"), (':root[data-theme="light"] .backdrop', "light")):
        sky = rule(code, selector)
        for n in ("a", "b"):
            assert f'url("/static/sparkles-{theme}-{n}.svg")' in sky, (theme, n)


def test_light_theme_is_a_blue_sky_with_white_text_on_it(css):
    code = without_comments(css)
    sky = code[code.index(':root[data-theme="light"] .backdrop {'):]
    sky = sky[:sky.index("}")]
    for colour in ("#1636B8", "#1F5AE0", "#2F86EA", "#49B7EA"):
        assert colour in sky
    on_sky = rule(code, ':root[data-theme="light"] :is(.sidebar, .topbar, .scroller)')
    assert "--ink: #FFFFFF" in on_sky and "text-shadow: var(--sky-shadow)" in on_sky
    cards = code[code.index(':root[data-theme="light"],\n:root[data-theme="light"] :is(.card'):]
    cards = cards[:cards.index("}")]
    for surface in (".card", ".box", ".popover", ".dialog", ".statusbar", ".filetab.is-active", "input"):
        assert surface in cards[:cards.index("{")], surface
    assert "--ink: #1B1938" in cards and "text-shadow: none" in cards


def motion_block(css):
    code = without_comments(css)
    first = code.index(':root:not([data-motion="off"]) .glow-a')
    motion = code[code.rindex("@media (prefers-reduced-motion: no-preference) {", 0, first):]
    return motion[:motion.index("\n}\n")]


def backdrop_animations(css):
    """{selector: {name, duration, timing, delay}} for every rule of the
    backdrop's motion block, later rules filling in from the base rule."""
    rules = re.findall(r"^\s+(:root:not\(\[data-motion=\"off\"\]\) [^{]+)\{([^}]*)\}", motion_block(css), re.M)
    found, base = {}, {}
    for selector, body in rules:
        decl = dict(re.findall(r"(animation(?:-[\w-]+)?):\s*([^;]+);", body))
        if "animation" in decl:
            parts = decl["animation"].split()
            times = [float(p.rstrip("s")) for p in parts if re.fullmatch(r"-?[\d.]+s", p)]
            base[selector.split(":")[-1].split()[-1].split(":")[0]] = entry = {
                "name": parts[0], "duration": times[0], "delay": times[1] if len(times) > 1 else 0.0,
                "timing": next(p for p in parts if p in ("linear", "ease-in-out", "ease", "ease-in", "ease-out")
                               or p.startswith(("steps(", "cubic-bezier("))),
                "text": decl["animation"]}
        else:
            cls = re.search(r"\.([\w-]+):nth-child", selector).group(1)
            entry = dict(base["." + cls])
            entry["text"] = body
            if "animation-duration" in decl:
                entry["duration"] = float(decl["animation-duration"].rstrip("s"))
            if "animation-delay" in decl:
                entry["delay"] = float(decl["animation-delay"].rstrip("s"))
            if "animation-timing-function" in decl:
                entry["timing"] = decl["animation-timing-function"].strip()
        found[selector.strip()] = entry
    return found


def test_background_moves_smoothly_at_a_calm_but_visible_pace(css):
    """Continuous motion at the display's frame rate (no steps(), which looked
    choppy): steady for what flows, eased for what breathes and twinkles."""
    anims = backdrop_animations(css)
    assert len(anims) >= 8
    assert "steps(" not in motion_block(css)
    by_name = {}
    for selector, a in anims.items():
        assert not a["timing"].startswith("steps("), selector
        by_name.setdefault(a["name"], []).append(a)
        assert "infinite" in a["text"] or "animation-" in a["text"], selector
    assert {a["timing"] for n in ("ribbon-a", "ribbon-b", "speck") for a in by_name[n]} == {"linear"}
    assert {a["timing"] for n in ("breathe", "twinkle") for a in by_name[n]} == {"ease-in-out"}
    # the near ribbons 30-60 px a second (one tile per cycle), the far ones about half that
    near = 1800 / by_name["ribbon-a"][0]["duration"]
    far = 2100 / by_name["ribbon-b"][0]["duration"]
    assert 30 <= near <= 60 and 0.35 <= far / near <= 0.65, (near, far)
    # the specks drift noticeably slower than the near ribbons
    stops = dict(keyframes(css)["speck"][0])
    dx, dy = map(int, re.search(r"translate3d\((-?\d+)px, (-?\d+)px, 0\)", stops["100%"]).groups())
    for a in by_name["speck"]:
        assert 5 <= math.hypot(dx, dy) / a["duration"] <= near / 2, a
    # a breath in and out every 10-20 s; a twinkle every few seconds
    for a in by_name["breathe"]:
        assert "alternate" in a["text"] and 10 <= 2 * a["duration"] <= 20, a
    for a in by_name["twinkle"]:
        assert 2 <= a["duration"] <= 6, a


def test_background_stops_when_motion_is_off_or_reduced(css):
    """Every backdrop animation is in the one block that runs only when the
    Settings switch is on and reduced motion was not asked for."""
    code = without_comments(css)
    block = motion_block(css)
    assert re.search(r"@media \(prefers-reduced-motion: reduce\) \{\s*\* \{[^}]*animation: none !important", code)
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", block):
        if "animation" in body:
            assert selector.strip().startswith(':root:not([data-motion="off"]) '), selector.strip()
    outside = code.replace(block, "")
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", outside):
        if re.search(BACKDROP_CLASS, selector.split(",")[-1]):
            assert not re.search(r"(^|[\s;])animation(-name)?\s*:", body), selector.strip()


def test_motion_setting_is_wired_and_respects_reduced_motion(script):
    assert "dataset.motion = on ? 'on' : 'off'" in script
    assert "remember('vex-motion'" in script and "recall('vex-motion') !== 'off'" in script
    assert "matchMedia('(prefers-reduced-motion: reduce)')" in script


def test_moving_layers_are_promoted(css):
    """Whatever is animated sits on a compositor layer of its own, so a frame
    is composited, never repainted."""
    code = without_comments(css)
    for name in ("glow", "ribbon", "speck", "mote"):
        body = rule(code, f".{name}")
        promoted = re.search(r"will-change:\s*([^;]+);", body)
        assert promoted, name
        assert set(re.split(r",\s*", promoted.group(1).strip())) <= {"transform", "opacity"}, name
    moved = {n for n, (_, props) in keyframes(css).items() if n in BACKDROP_ANIMATIONS and "transform" in props}
    assert moved == {"ribbon-a", "ribbon-b", "speck", "twinkle"}
    for name in ("ribbon", "speck", "mote"):
        assert "transform" in re.search(r"will-change:\s*([^;]+);", rule(code, f".{name}")).group(1), name


def test_theme_change_never_takes_a_backdrop_layer_out(css):
    """An animation restarts when its element stops being rendered; a theme
    may hide a backdrop layer, but never take it out with display: none."""
    code = without_comments(css)
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", code):
        if re.search(BACKDROP_CLASS, selector.split(",")[-1]):
            assert "display: none" not in body, selector.strip()


def tile(client, name):
    status, ctype, body = client.get(f"/static/{name}")
    assert (status, ctype) == (200, "image/svg+xml"), name
    svg = body.decode()
    assert "<script" not in svg and not re.search(r"\bon\w+=", svg)
    assert all(ref.startswith("#") for ref in re.findall(r'href="([^"]*)"', svg))  # nothing outside the file
    width, height = map(int, re.search(r'viewBox="0 0 (\d+) (\d+)"', svg).groups())
    return svg, width, height


def test_ribbon_tiles_are_seamless_and_flow_one_tile_per_cycle(client, css):
    code = without_comments(css)
    for n in ("a", "b"):
        layer = rule(code, f".ribbon-{n}")
        size = re.search(r"background-size: (\d+)px (\d+)px", layer).groups()
        shift = re.search(rf"@keyframes ribbon-{n} \{{ from {{ transform: translate3d\(-(\d+)px, 0, 0\); }} "
                          rf"to {{ transform: translate3d\(0, 0, 0\); }} \}}", code).group(1)
        for theme in ("dark", "light"):
            svg, width, height = tile(client, f"ribbons-{theme}-{n}.svg")
            assert size == (str(width), str(height)) and shift == str(width)
            assert f"width: calc(100vw + {width}px)" in layer
            paths = re.findall(r'<path id="\w+" d="M([^"]*)Z"/>', svg)
            assert len(paths) >= 2
            for d in paths:
                points = [tuple(map(float, p.split())) for p in re.split(r"[ML]", d) if p]
                turn = max(range(len(points)), key=lambda i: points[i][0])
                for edge in (points[:turn + 1], points[turn + 1:]):
                    xs = [x for x, _ in edge]
                    assert min(xs) < 0 and max(xs) > width  # drawn past both ends, so the glow wraps too
                    at = {round(x, 1): y for x, y in edge}
                    pairs = [(y, at[round(x + width, 1)]) for x, y in at.items() if round(x + width, 1) in at]
                    assert len(pairs) >= 10
                    for y, y2 in pairs:
                        assert abs(y - y2) < 0.11  # each edge carries on where the next tile starts


def test_sparkle_tiles_wrap_seamlessly(client, css):
    code = without_comments(css)
    for selector, theme in ((".backdrop", "dark"), (':root[data-theme="light"] .backdrop', "light")):
        sky = rule(code, selector)
        for n in ("a", "b"):
            size = tuple(map(int, re.search(rf'url\("/static/sparkles-{theme}-{n}\.svg"\) 0 0 / (\d+)px (\d+)px repeat',
                                            sky).groups()))
            svg, width, height = tile(client, f"sparkles-{theme}-{n}.svg")
            assert (width, height) == size
            dots = [(float(x), float(y), float(r)) for x, y, r in
                    re.findall(r'<circle cx="([-\d.]+)" cy="([-\d.]+)" r="([\d.]+)"', svg)]
            assert len(dots) >= 20
            seen = {(round(x), round(y), r) for x, y, r in dots}
            for x, y, r in dots:  # whatever crosses an edge is drawn again on the other side
                for crosses, (dx, dy) in ((x - r < 0, (width, 0)), (x + r > width, (-width, 0)),
                                          (y - r < 0, (0, height)), (y + r > height, (0, -height))):
                    if crosses:
                        assert (round(x + dx), round(y + dy), r) in seen, (theme, n, x, y)


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
