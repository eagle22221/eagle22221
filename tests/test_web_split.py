"""The Split view of the web interface: the page registers it, and it talks to
the server only through the documented /api/split contract (docs/dev/split-spec.md),
which is all the C edition's server shares with the Python one."""
import http.client
import json
import re
import threading
from urllib.parse import quote

import pytest

from vex import server
from conftest import fixture_path

PE = str(fixture_path("hello_pe64.exe"))
PIECE_KEYS = {"path", "kind", "name", "offset", "size", "address", "note"}


class Client:
    def __init__(self, httpd, workspace):
        self.port = httpd.server_address[1]
        self.token = workspace.token

    def request(self, method, url, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, url, headers={"X-Vex-Token": self.token} if token else {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, (json.loads(data) if "json" in resp.getheader("Content-Type", "") else data)

    def text(self, url):
        status, body = self.request("GET", url, token=False)
        assert status == 200, url
        return body.decode()

    def split(self, method, **params):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        return self.request(method, f"/api/split?{query}")


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
def script(client):
    return client.text("/static/app.js")


def split_view_source(script):
    start = script.index("// --- split ---")
    return script[start:script.index("// --- modify ---", start)]


# --- the page -----------------------------------------------------------------

def test_split_view_is_registered_between_assets_and_modify(script):
    views = script[script.index("const VIEWS = {"):script.index("function renderNav")]
    order = re.findall(r"^\s+(\w+): \{ label: '([^']+)'", views, re.M)
    names = [name for name, _ in order]
    assert ("split", "Split") in order
    assert names.index("assets") + 1 == names.index("split") < names.index("modify")
    entry = re.search(r"split: \{[^}]*\}", views).group(0)
    assert "render: renderSplit" in entry and "icon: 'split'" in entry and "kinds: ['binary']" in entry


def test_split_icon_is_in_the_sprite_in_the_same_line_style(client):
    page = client.text("/")
    symbols = dict(re.findall(r'<symbol id="i-(\w+)"([^>]*)>', page))
    assert "split" in symbols
    assert symbols["split"] == symbols["techniques"]  # same viewBox, stroke and caps


def test_split_view_uses_only_the_split_api(script):
    source = split_view_source(script)
    assert "async function renderSplit(box)" in source
    assert set(re.findall(r"\bapi\('([^']+)'", source)) == {"split"}
    assert "api('split', { path })" in source  # the preview: GET, nothing written
    assert "api('split', { path, dest }, { method: 'POST' })" in source
    assert "path + '_split'" in source and "await ask(" in source
    assert "Split into a folder…" in source


def test_split_view_says_what_it_does_and_shows_every_field(script):
    source = split_view_source(script)
    assert "The program itself is not changed and nothing is run." in source
    for title in ("Parts", "Embedded files", "Resources"):
        assert f"title: '{title}'" in source
    for field in ("pieces", "count", "bytes", "dest", "index"):
        assert re.search(rf"\.{field}\b", source), field
    for field in PIECE_KEYS:
        assert f"piece.{field}" in source, field
    assert "notice is-ok" in source and "notice is-error" in source


def test_split_view_keeps_to_the_content_security_policy(client, script):
    source = split_view_source(script)
    assert "innerHTML" not in source and "insertAdjacentHTML" not in source
    assert "style:" not in source  # no inline styles; the look lives in app.css
    page = client.text("/")
    assert not re.search(r"<script(?![^>]*\bsrc=)", page) and not re.search(r"\son\w+=", page)


def test_split_styles_use_the_existing_tokens(client):
    css = client.text("/static/app.css")
    block = css[css.index("/* --- split"):css.index("/* --- open dialog")]
    assert ".pieces" in block
    assert "font-family" not in block and not re.search(r"#[0-9a-fA-F]{3,8}\b", block)
    assert set(re.findall(r"var\((--[\w-]+)\)", block)) <= set(re.findall(r"^\s+(--[\w-]+):", css, re.M))


# --- the contract the view relies on ------------------------------------------

def test_preview_has_the_shape_the_view_reads(client):
    status, preview = client.split("GET", path=PE)
    assert status == 200, preview
    assert preview["dest"] is None and preview["index"] == "index.txt"
    assert preview["pieces"] and all(set(p) >= PIECE_KEYS for p in preview["pieces"])
    saved = [p for p in preview["pieces"] if p["path"]]
    assert preview["count"] == len(saved)
    assert preview["bytes"] == sum(p["size"] for p in saved)
    for piece in preview["pieces"]:
        assert isinstance(piece["offset"], int) and isinstance(piece["size"], int)
        assert piece["address"] is None or piece["address"].startswith("0x")
        assert piece["path"] or piece["note"]  # the "Saved as" column is never blank


def test_split_reports_the_folder_and_refuses_a_second_run_with_a_message(client, tmp_path):
    dest = tmp_path / "pieces"
    _, preview = client.split("GET", path=PE)
    status, done = client.split("POST", path=PE, dest=dest)
    assert status == 200, done
    assert done["dest"] == str(dest) and done["count"] == preview["count"]
    assert done["pieces"] == preview["pieces"]
    assert (dest / done["index"]).is_file()
    assert all((dest / p["path"]).is_file() for p in done["pieces"] if p["path"])
    status, refused = client.split("POST", path=PE, dest=dest)
    assert status == 400
    assert refused["error"] == f"{dest} is not empty; choose a new or empty folder"
