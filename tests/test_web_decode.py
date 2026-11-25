"""The Decode view of the web interface: the page registers it, and it talks to
the server only through the documented /api/decode contract (docs/dev/decode-spec.md),
which is all the C edition's server shares with the Python one. The view must build
its operation palette from GET /api/decode/ops at runtime and grey out operations the
serving edition marks unavailable, so it degrades correctly when the C edition serves
these same static files."""
import http.client
import json
import re
import threading
from urllib.parse import quote

import pytest

from vex import server
from conftest import fixture_path

ELF = str(fixture_path("hello_elf64"))


class Client:
    def __init__(self, httpd, workspace):
        self.port = httpd.server_address[1]
        self.token = workspace.token

    def request(self, method, url, body=None, token=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, url, body=body, headers={"X-Vex-Token": self.token} if token else {})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, (json.loads(data) if "json" in resp.getheader("Content-Type", "") else data)

    def text(self, url):
        status, body = self.request("GET", url, token=False)
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
def script(client):
    return client.text("/static/app.js")


def decode_view_source(script):
    start = script.index("// --- decode ---")
    return script[start:script.index("// --- start ---", start)]


# --- the page -----------------------------------------------------------------

def test_decode_view_is_registered_after_split_and_before_modify(script):
    views = script[script.index("const VIEWS = {"):script.index("function renderNav")]
    order = re.findall(r"^\s+(\w+): \{ label: '([^']+)'", views, re.M)
    names = [name for name, _ in order]
    assert ("decode", "Decode") in order
    assert names.index("split") + 1 == names.index("decode") == names.index("modify") - 1
    entry = re.search(r"decode: \{[^}]*\}", views).group(0)
    assert "render: renderDecode" in entry and "icon: 'decode'" in entry and "kinds: ['binary']" in entry
    assert "group: 'advanced'" in entry


def test_decode_icon_is_in_the_sprite_in_the_same_line_style(client):
    page = client.text("/")
    symbols = dict(re.findall(r'<symbol id="i-(\w+)"([^>]*)>', page))
    assert "decode" in symbols
    # same viewBox, stroke width and line caps as the other rail icons
    assert symbols["decode"] == symbols["techniques"]


def test_decode_view_uses_only_the_decode_api(script):
    source = decode_view_source(script)
    assert "async function renderDecode(box)" in source
    # exactly the three documented endpoints, nothing else
    assert set(re.findall(r"\bapi\('([^']+)'", source)) == {"decode/ops", "decode", "decode/solve"}
    assert "api('decode/ops', {})" in source                                  # catalogue: GET
    assert "api('decode', {}, { method: 'POST'" in source                     # pipeline: POST
    assert "api('decode/solve', {}, { method: 'POST'" in source               # solvers: POST
    # the POST body is the documented {source, recipe} / {source, name} shape
    assert "JSON.stringify({ source: decodeSourceBody(" in source and "recipe: recipeBody()" in source
    assert "name: select.value" in source


def test_decode_view_builds_the_palette_from_the_catalogue_not_a_hard_coded_list(script):
    source = decode_view_source(script)
    # it iterates the catalogue the server sends, keyed on the documented fields
    assert "api('decode/ops', {})" in source
    assert "catalogue.groups" in source and "group.ops" in source
    assert "op.available === false" in source and "is-unavailable" in source
    assert "disabled: unavailable" in source
    # it must NOT carry its own copy of the operation list: no catalogue op name
    # appears as a literal (only solver names and their target ops are mapped)
    for op_name in ("from-base64", "to-base64", "from-hex", "gunzip", "zlib-inflate",
                    "vigenere", "atbash", "railfence", "chacha20", "rc4"):
        assert op_name not in source, op_name


def test_decode_view_offers_every_source_and_shows_the_result(script):
    source = decode_view_source(script)
    for label in ("Text", "Hex", "Base64", "From this file"):
        assert f"label: '{label}'" in source
    # input sources: file range + its offset/length, and a size readout
    assert "kind: 'file'" in source and "offset:" in source and "length:" in source
    assert "decodeInputSize" in source and "sizeReadout" in source
    # output: text, hexdump toggle, size, looks_like, per-step sizes
    assert "looks_like" in source
    assert "Hex dump" in source and "D.hexdump" in source
    assert "decode-steplist" in source and "r.steps" in source
    # a failing step is surfaced and marked
    assert "is-failed" in source and "r.error" in source
    # auto-solve: ranked candidates with score + params, loadable into the recipe
    assert "Auto-solve" in source and "candidate-score" in source
    assert "Load into recipe" in source and "loadCandidate" in source
    # reorder / remove steps
    assert "moveStep" in source and "removeStep" in source


def test_decode_view_keeps_to_the_content_security_policy(client, script):
    source = decode_view_source(script)
    assert "innerHTML" not in source and "insertAdjacentHTML" not in source
    page = client.text("/")
    assert not re.search(r"<script(?![^>]*\bsrc=)", page) and not re.search(r"\son\w+=", page)


def test_decode_styles_use_the_existing_tokens(client):
    css = client.text("/static/app.css")
    block = css[css.index("/* --- decode"):css.index("/* --- responsive")]
    assert ".decode-grid" in block and ".op-chip" in block and ".recipe-step" in block
    # no raw colours: everything is a design token already defined on :root
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", block)
    assert set(re.findall(r"var\((--[\w-]+)\)", block)) <= set(re.findall(r"^\s+(--[\w-]+):", css, re.M))


# --- the contract the view relies on ------------------------------------------
# These run only once a server edition actually serves the decode routes; the
# routes are written separately, so the assertions above are what gate the UI.

def _ops(client):
    status, data = client.request("GET", "/api/decode/ops")
    if status == 404:
        pytest.skip("decode routes are not present in this build")
    assert status == 200, data
    return data


def test_ops_catalogue_has_the_shape_the_view_reads(client):
    cat = _ops(client)
    assert isinstance(cat.get("groups"), list) and isinstance(cat.get("solvers"), list)
    assert cat["groups"], "the catalogue lists at least one group"
    for group in cat["groups"]:
        assert "name" in group and isinstance(group["ops"], list)
        for op in group["ops"]:
            assert {"name", "params", "summary", "available"} <= set(op)
            assert isinstance(op["available"], bool)
            for param in op["params"]:
                assert {"name", "required", "type"} <= set(param)
    for solver in cat["solvers"]:
        assert "name" in solver and "summary" in solver


def test_pipeline_runs_a_recipe_against_a_text_source(client):
    _ops(client)
    body = json.dumps({"source": {"kind": "text", "value": "Hello"},
                       "recipe": [{"op": "to-base64", "params": {}}]})
    status, data = client.request("POST", "/api/decode", body=body)
    assert status == 200, data
    assert data["ok"] is True
    assert data["text"].strip() == "SGVsbG8="
    assert [s["op"] for s in data["steps"]] == ["to-base64"]


def test_a_failing_step_reports_an_error_and_the_steps_so_far(client):
    _ops(client)
    body = json.dumps({"source": {"kind": "text", "value": "not base64 !!!"},
                       "recipe": [{"op": "from-base64", "params": {}}]})
    status, data = client.request("POST", "/api/decode", body=body)
    assert status == 200, data
    assert data["ok"] is False and data["error"]
    # the UI marks recipe[len(steps)] as the failed step
    assert len(data["steps"]) == 0
