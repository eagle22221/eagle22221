"""The opening animation (vex/web/intro.css + intro.js): served by the Python
server with the right types, embedded in the C edition the same way, and kept
to the page's strict Content-Security-Policy (no inline code or styles, nothing
from outside)."""
import http.client
import importlib.util
import pathlib
import re
import shutil
import subprocess
import threading

import pytest

from vex import server

REPO = pathlib.Path(__file__).resolve().parent.parent
WEB = REPO / "vex" / "web"
SVG_NS = "http://www.w3.org/2000/svg"


class Client:
    def __init__(self, httpd):
        self.port = httpd.server_address[1]

    def get(self, url):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", url)
        resp = conn.getresponse()
        data = resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return resp.status, headers, data


@pytest.fixture(scope="module")
def client():
    httpd, workspace = server.create_server(port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield Client(httpd)
    httpd.shutdown()
    httpd.server_close()
    workspace.close()


@pytest.fixture(scope="module")
def js():
    return (WEB / "intro.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def css():
    return (WEB / "intro.css").read_text(encoding="utf-8")


def code_only(source):
    """JavaScript or CSS with its comments taken out."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"(?m)(^|[^:\\])//.*$", r"\1", source)


# --- served ------------------------------------------------------------------

@pytest.mark.parametrize("name, ctype", [
    ("intro.css", "text/css; charset=utf-8"),
    ("intro.js", "text/javascript; charset=utf-8"),
])
def test_intro_files_are_served_with_their_types_and_the_policy(client, name, ctype):
    status, headers, body = client.get(f"/static/{name}")
    assert status == 200
    assert headers["content-type"] == ctype
    assert headers["x-content-type-options"] == "nosniff"  # so the type is what counts
    assert headers["content-security-policy"] == server.CSP
    assert body == (WEB / name).read_bytes()


def test_fonts_the_intro_names_are_served(client, css):
    urls = re.findall(r"url\(\s*[\"']?([^\"')]+)", code_only(css))
    assert urls, "intro.css names its fonts"
    for url in urls:
        status, headers, body = client.get("/static/" + url)
        assert (status, headers["content-type"]) == (200, "font/woff2"), url
        assert body[:4] == b"wOF2"


def test_the_c_edition_embeds_the_intro_with_the_same_types():
    spec = importlib.util.spec_from_file_location("embed_web", REPO / "c" / "tools" / "embed_web.py")
    embed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(embed)
    found = {path: ctype for path, ctype, _ in embed.collect(str(WEB))}
    assert found["intro.css"] == server.CONTENT_TYPES[".css"]
    assert found["intro.js"] == server.CONTENT_TYPES[".js"]


# --- the content security policy ---------------------------------------------

def test_intro_script_builds_its_overlay_without_markup_strings_or_eval(js):
    code = code_only(js)
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
                   "eval(", "new Function", "cssText", "javascript:", "import(", "importScripts"):
        assert banned not in code, banned
    assert not re.search(r"setAttribute\(\s*['\"](style|on\w+)['\"]", code)  # inline styles or handlers
    assert not re.search(r"\.style\s*=[^=]", code)                            # whole style strings
    assert not re.search(r"set(Timeout|Interval)\(\s*['\"`]", code)          # string timers
    assert "createElementNS" in code and "createElement(" in code


def test_intro_script_sets_styles_only_through_the_cssom(js):
    code = code_only(js)
    uses = re.findall(r"\.style\.(\w+)\(", code)
    assert uses and set(uses) == {"setProperty"}  # custom properties for the glide
    assert all(name.startswith("--vxi-") for name in re.findall(r"setProperty\(\s*'([^']+)'", code))


def test_intro_loads_nothing_from_outside(js, css):
    for source in (code_only(js), code_only(css)):
        external = [u for u in re.findall(r"(?:https?:)?//[\w.-]+[^\s'\")]*", source) if u != SVG_NS]
        assert not external
    assert not re.search(r"\bfetch\(|XMLHttpRequest|WebSocket", code_only(js))
    assert "@import" not in code_only(css)
    for url in re.findall(r"url\(\s*[\"']?([^\"')]+)", code_only(css)):
        assert not url.startswith(("/", "data:", "http")) and ".." not in url, url


def test_intro_styles_animate_only_cheap_properties(css):
    animated = set()
    for block in re.findall(r"@keyframes\s+[\w-]+\s*\{((?:[^{}]*\{[^{}]*\})*)[^{}]*\}", code_only(css)):
        animated |= set(re.findall(r"([\w-]+)\s*:", block))
    assert animated and animated <= {"transform", "opacity", "stroke-dashoffset"}


def test_intro_script_is_valid_javascript(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    result = subprocess.run([node, "--check", str(WEB / "intro.js")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


# --- how it behaves (read from the source) -----------------------------------

def test_intro_is_skippable_once_per_session_and_respects_reduced_motion(js):
    code = code_only(js)
    for key in ("'Escape'", "'Enter'", "' '"):
        assert key in code
    assert "addEventListener('click'" in code
    assert "sessionStorage" in code and "vex-intro-played" in code
    assert "prefers-reduced-motion: reduce" in code
    assert "'aria-hidden', 'true'" in code


def test_index_loads_the_intro_from_the_head_after_its_stylesheet(client):
    status, _, body = client.get("/")
    page = body.decode()
    if "/static/intro.js" not in page:
        pytest.skip("index.html does not load the intro yet")
    head = page[:page.index("</head>")]
    script = re.search(r"<script[^>]*src=\"/static/intro\.js\"[^>]*>", head)
    assert script, "intro.js must load from <head>"
    assert not re.search(r"\b(defer|async|type=\"module\")", script.group(0))  # runs before <body>
    assert '<link rel="stylesheet" href="/static/intro.css">' in head
    assert head.index("/static/intro.css") < head.index("/static/intro.js")
