"""The local web server behind `binspect gui`: API behaviour and the
protections that stop other web pages from driving it."""
import http.client
import json
import threading
from urllib.parse import quote

import pytest

from binspect import server
from conftest import FIXTURES, fixture_bytes, fixture_path

ELF = str(fixture_path("hello_elf64"))


class Client:
    def __init__(self, httpd, workspace):
        self.port = httpd.server_address[1]
        self.token = workspace.token
        self.workspace = workspace

    def request(self, method, url, body=None, token=True, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if token:
            h["X-Binspect-Token"] = self.token if token is True else token
        conn.request(method, url, body=body, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, resp.getheader("Content-Type", ""), data

    def get(self, url, **kw):
        status, ctype, data = self.request("GET", url, **kw)
        return status, (json.loads(data) if "json" in ctype else data)

    def api(self, name, **params):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        status, data = self.get(f"/api/{name}?{query}")
        assert status == 200, data
        return data


@pytest.fixture(scope="module")
def client():
    httpd, workspace = server.create_server(port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield Client(httpd, workspace)
    httpd.shutdown()
    httpd.server_close()
    workspace.close()


# --- pages and static files ------------------------------------------------

def test_index_page_is_served(client):
    status, body = client.get("/", token=False)
    assert status == 200 and b"<title>binspect" in body


def test_fonts_are_served_from_the_package(client):
    status, ctype, body = client.request(
        "GET", "/static/fonts/ibm-plex-mono-latin-400-normal.woff2", token=False)
    assert (status, ctype) == (200, "font/woff2") and body[:4] == b"wOF2"


def test_static_path_cannot_escape_the_web_directory(client):
    for url in ("/static/../server.py", "/static/..%2fserver.py", "/static/%2e%2e/cli.py"):
        assert client.get(url, token=False)[0] == 404


# --- access control --------------------------------------------------------

def test_api_requires_the_session_token(client):
    assert client.get(f"/api/info?path={quote(ELF)}", token=False)[0] == 403
    assert client.get(f"/api/info?path={quote(ELF)}", token="wrong")[0] == 403


def test_requests_for_another_host_name_are_refused(client):
    # DNS-rebinding defence: a page on evil.example resolving to 127.0.0.1
    status, _ = client.get(f"/api/info?path={quote(ELF)}", headers={"Host": "evil.example"})
    assert status == 403


def test_responses_do_not_grant_cross_origin_access(client):
    conn = http.client.HTTPConnection("127.0.0.1", client.port, timeout=10)
    conn.request("GET", f"/api/info?path={quote(ELF)}",
                 headers={"X-Binspect-Token": client.token, "Origin": "http://evil.example"})
    resp = conn.getresponse()
    resp.read()
    assert resp.getheader("Access-Control-Allow-Origin") is None
    conn.close()


# --- analysis API ----------------------------------------------------------

def test_info(client):
    info = client.api("info", path=ELF)
    assert (info["format"], info["arch"], info["entry"]) == ("ELF", "x86_64", "0x10e0")


def test_disassembly_of_a_function(client):
    listing = client.api("disasm", path=ELF, at="main")
    assert len(listing["instructions"]) == 50 and listing["name"] == "main"
    short = client.api("disasm", path=ELF, at="0x1237", count=2)
    assert [i["address"] for i in short["instructions"]] == ["0x1237", "0x123e"]


def test_strings_search_is_case_insensitive_and_limited(client):
    found = client.api("strings", path=ELF, q="FIXTURE")
    assert found["total"] == 2
    assert [s["text"] for s in found["items"]] == [
        "s3cr3t-fixture-key", "Hello from the binspect ELF fixture"]
    limited = client.api("strings", path=ELF, limit=3)
    assert len(limited["items"]) == 3 and limited["total"] > 3


def test_functions_filter(client):
    found = client.api("functions", path=ELF, q="pass")
    assert [f["name"] for f in found["items"]] == ["check_password"]


def test_xrefs(client):
    rows = client.api("xrefs", path=ELF, target="puts")
    assert [r["address"] for r in rows] == ["0x10a4", "0x123e", "0x1246", "0x1264"]


def test_hexdump(client):
    dump = client.api("hexdump", path=ELF, address="0x2004", length=18)
    assert dump["rows"][0]["ascii"] == "s3cr3t-fixture-k"


def test_tables(client):
    assert any(s["name"] == ".text" for s in client.api("sections", path=ELF))
    assert any(i["name"] == "puts" for i in client.api("imports", path=ELF))
    assert client.api("exports", path=str(fixture_path("sample.dll")))[0]["name"] == "sample_add"
    assert any(s["name"] == "main" for s in client.api("symbols", path=ELF)["items"])


def test_layout_describes_the_file_to_scale(client):
    layout = client.api("layout", path=str(fixture_path("hello_pe64.exe")))
    assert layout["size"] == 3072
    regions = [(r["name"], r["offset"], r["size"], r["kind"]) for r in layout["regions"]]
    assert regions == [
        ("headers", 0, 0x400, "headers"),
        (".text", 0x400, 0x200, "code"),
        (".rdata", 0x600, 0x200, "data"),
        (".pdata", 0x800, 0x200, "data"),
        ("symbol table", 0xA00, 0xF3, "meta"),      # 9 symbols * 18 + 81-byte strings
        ("padding", 0xAF3, 0x10D, "padding"),
    ]


# --- errors ----------------------------------------------------------------

def test_missing_file_is_a_json_error(client):
    status, data = client.get("/api/info?path=/no/such/file")
    assert status == 404 and "error" in data


def test_non_binary_is_a_json_error(client, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello")
    status, data = client.get(f"/api/info?path={quote(str(f))}")
    assert status == 400 and "not an ELF or PE" in data["error"]


def test_unknown_endpoint(client):
    assert client.get("/api/nope")[0] == 404


def test_missing_parameter_is_reported(client):
    status, data = client.get("/api/info")
    assert status == 400 and "path" in data["error"]


# --- opening files ---------------------------------------------------------

def test_browse_lists_directory_entries(client):
    listing = client.api("browse", dir=str(FIXTURES))
    names = {e["name"]: e for e in listing["entries"]}
    assert names["hello_elf64"]["is_dir"] is False
    assert names["hello_elf64"]["size"] == 16232
    assert listing["path"] == str(FIXTURES)
    assert listing["parent"] == str(FIXTURES.parent)


def test_open_classifies_what_was_opened(client, tmp_path):
    assert client.api("open", path=ELF)["kind"] == "binary"
    assert client.api("open", path=str(tmp_path))["kind"] == "folder"
    note = tmp_path / "note.txt"
    note.write_text("x")
    assert client.api("open", path=str(note))["kind"] == "unknown"


def test_upload_stores_the_file_in_the_session_folder(client):
    data = fixture_bytes("bare_elf32")
    status, _, body = client.request("POST", "/api/upload?name=..%2F..%2Fevil.bin", body=data)
    assert status == 200
    path = json.loads(body)["path"]
    assert path.startswith(client.workspace.tempdir) and path.endswith("evil.bin")
    assert ".." not in path
    assert client.api("info", path=path)["arch"] == "x86"


def test_analysis_is_reloaded_when_the_file_changes(client, tmp_path):
    f = tmp_path / "prog"
    f.write_bytes(fixture_bytes("bare_elf32"))
    assert client.api("info", path=str(f))["arch"] == "x86"
    f.write_bytes(fixture_bytes("bare_arm64"))
    assert client.api("info", path=str(f))["arch"] == "aarch64"
