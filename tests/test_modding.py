"""Modding features as the user reaches them: CLI commands and the web API
for Windows resources and patches. Offsets come from the fixture facts used
elsewhere in the suite (llvm-readobj / strings -t x)."""
import http.client
import json
import shutil
import threading
from urllib.parse import quote

import pytest

import binspect
from binspect import resources, server
from binspect.cli import main
from conftest import fixture_bytes, fixture_path

PE = str(fixture_path("hello_pe64.exe"))
RES = str(fixture_path("resdemo.exe"))


def run(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


# --- resources (CLI) -------------------------------------------------------

def test_resources_list_json(capsys):
    code, out, _ = run(capsys, "--json", "resources", "list", RES)
    data = json.loads(out)
    assert code == 0 and len(data["items"]) == 11
    by_key = {(r["type"], r["name"]): r for r in data["items"]}
    assert by_key[("RCDATA", "#101")]["size"] == 43
    assert by_key[("MANIFEST", "#1")]["language"] == 1033
    assert data["version"]["ProductName"] == "Binspect Resource Demo"


def test_resources_extract_writes_one_file_per_resource(capsys, tmp_path):
    code, out, _ = run(capsys, "resources", "extract", RES, str(tmp_path / "res"))
    assert code == 0 and "Extracted 11 resources" in out
    files = {p.name: p for p in (tmp_path / "res").iterdir()}
    assert len(files) == 11
    assert files["RCDATA_101_1033.bin"].stat().st_size == 43
    # icon groups are rebuilt into complete .ico files: 6-byte header, two
    # 16-byte directory entries, then the 296- and 304-byte images
    ico = files["GROUP_ICON_1_1033.ico"].read_bytes()
    assert ico[:6] == b"\x00\x00\x01\x00\x02\x00" and len(ico) == 6 + 2 * 16 + 296 + 304


def test_resources_replace_saves_a_new_program(capsys, tmp_path):
    new = tmp_path / "new.bin"
    new.write_bytes(b"replacement payload")
    out_path = tmp_path / "modded.exe"
    code, out, _ = run(capsys, "resources", "replace", RES, "rcdata", "101",
                       str(new), "-o", str(out_path))
    assert code == 0 and "Replaced" in out
    modded = binspect.load(out_path)
    res = next(r for r in resources.list_resources(modded)
               if (r.type, r.name) == ("RCDATA", "#101"))
    assert resources.read_resource(modded, res) == b"replacement payload"
    assert fixture_path("resdemo.exe").read_bytes() == fixture_bytes("resdemo.exe")


def test_resources_replace_unknown_resource_is_a_clean_error(capsys, tmp_path):
    new = tmp_path / "new.bin"
    new.write_bytes(b"x")
    code, _, err = run(capsys, "resources", "replace", RES, "RCDATA", "999",
                       str(new), "-o", str(tmp_path / "o.exe"))
    assert code == 1 and "no resource of type RCDATA named 999" in err
    assert not (tmp_path / "o.exe").exists()


# --- patch (CLI) -----------------------------------------------------------

def test_patch_string_writes_a_modified_copy(capsys, tmp_path):
    out_path = tmp_path / "out.exe"
    code, out, _ = run(capsys, "patch", "string", PE, "Hello from", "HELLO FROM",
                       "-o", str(out_path))
    assert code == 0 and "Saved" in out
    assert out_path.read_bytes()[0x630:0x63A] == b"HELLO FROM"
    assert fixture_bytes("hello_pe64.exe")[0x630:0x63A] == b"Hello from"


def test_patch_bytes_at_address_and_at_file_offset(capsys, tmp_path):
    by_addr, by_off = tmp_path / "a.exe", tmp_path / "b.exe"
    assert run(capsys, "patch", "bytes", PE, "0x140002030", "41 42", "-o", str(by_addr))[0] == 0
    assert run(capsys, "patch", "bytes", PE, "0x630", "0x41,0x42", "--offset",
               "-o", str(by_off))[0] == 0
    assert by_addr.read_bytes()[0x630:0x632] == b"AB"
    assert by_addr.read_bytes() == by_off.read_bytes()


def test_patch_nop_accepts_a_function_name(capsys, tmp_path):
    out_path = tmp_path / "out.exe"
    code, out, _ = run(capsys, "patch", "nop", PE, "print", "2", "-o", str(out_path))
    assert code == 0
    assert "0x140001020: 56 57 -> 90 90" in out          # push rsi; push rdi
    assert out_path.read_bytes()[0x420:0x422] == b"\x90\x90"


def test_patch_needs_a_destination(capsys):
    code, _, err = run(capsys, "patch", "bytes", PE, "0x140002030", "41")
    assert code == 1 and "-o OUT" in err and "--in-place" in err


def test_patch_in_place_keeps_a_backup(capsys, tmp_path):
    target = tmp_path / "prog.exe"
    shutil.copy(PE, target)
    assert run(capsys, "patch", "bytes", str(target), "0x140002030", "41", "--in-place")[0] == 0
    assert target.read_bytes()[0x630:0x631] == b"A"
    assert (tmp_path / "prog.exe.bak").read_bytes() == fixture_bytes("hello_pe64.exe")


def test_patch_rejects_text_that_is_not_hex(capsys, tmp_path):
    code, _, err = run(capsys, "patch", "bytes", PE, "0x140002030", "zz", "-o",
                       str(tmp_path / "o.exe"))
    assert code == 1 and "hex" in err
    assert not (tmp_path / "o.exe").exists()


# --- web API ---------------------------------------------------------------

class Api:
    def __init__(self):
        self.httpd, self.ws = server.create_server(port=0)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def call(self, method, name, body=None, **params):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        conn.request(method, f"/api/{name}?{query}", body=body,
                     headers={"X-Binspect-Token": self.ws.token})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        if "json" in resp.getheader("Content-Type", ""):
            data = json.loads(data)
        return resp.status, data

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.ws.close()


@pytest.fixture(scope="module")
def api():
    a = Api()
    yield a
    a.close()


def test_api_lists_resources_and_serves_their_data(api):
    status, data = api.call("GET", "resources", path=RES)
    assert status == 200 and len(data["items"]) == 11
    rc = next(r for r in data["items"] if (r["type"], r["name"]) == ("RCDATA", "#101"))
    status, raw = api.call("GET", "resource/data", path=RES, index=rc["index"])
    assert status == 200 and len(raw) == 43
    group = next(r for r in data["items"] if r["type"] == "GROUP_ICON")
    status, ico = api.call("GET", "resource/icon", path=RES, index=group["index"])
    assert status == 200 and ico[:4] == b"\x00\x00\x01\x00" and len(ico) == 638
    assert api.call("GET", "resource/data", path=RES, index=99)[0] == 404


def test_api_resources_of_a_linux_program_is_an_empty_list(api):
    status, data = api.call("GET", "resources", path=str(fixture_path("hello_elf64")))
    assert status == 200 and data == {"items": [], "version": {}}


def test_api_replaces_a_resource(api, tmp_path):
    _, data = api.call("GET", "resources", path=RES)
    rc = next(r for r in data["items"] if (r["type"], r["name"]) == ("RCDATA", "#101"))
    out = tmp_path / "m.exe"
    status, done = api.call("POST", "resource/replace", body=b"abc", path=RES,
                            index=rc["index"], out=str(out))
    assert status == 200 and done["size"] == 3
    modded = binspect.load(out)
    res = next(r for r in resources.list_resources(modded)
               if (r.type, r.name) == ("RCDATA", "#101"))
    assert resources.read_resource(modded, res) == b"abc"


def test_api_patches(api, tmp_path):
    out = tmp_path / "p.exe"
    status, done = api.call("POST", "patch/bytes", path=PE, out=str(out),
                            address="0x140002030", hex="41 42")
    assert status == 200
    assert (done["address"], done["old"], done["new"]) == ("0x140002030", "48 65", "41 42")
    assert out.read_bytes()[0x630:0x632] == b"AB"

    status, done = api.call("POST", "patch/nop", path=PE, out=str(out),
                            address="print", length=2)
    assert status == 200 and done["new"] == "90 90"
    assert out.read_bytes()[0x420:0x422] == b"\x90\x90"

    status, done = api.call("POST", "patch/string", path=PE, out=str(out),
                            old="Wide fixture", new="WIDE", encoding="utf16")
    assert status == 200 and len(done["patches"]) == 1
    assert out.read_bytes()[0x600:0x608] == "WIDE".encode("utf-16-le")


def test_api_patch_errors_are_reported_and_write_nothing(api, tmp_path):
    out = tmp_path / "p.exe"
    status, data = api.call("POST", "patch/bytes", path=PE, out=str(out),
                            address="0x140002030", hex="not hex")
    assert status == 400 and "hex" in data["error"]
    status, data = api.call("POST", "patch/bytes", path=PE, out=str(tmp_path),
                            address="0x140002030", hex="41")
    assert status == 400 and "folder" in data["error"]
    status, data = api.call("POST", "patch/bytes", path=PE, out=str(out),
                            address="0x150000000", hex="41")
    assert status == 400
    assert not out.exists()
