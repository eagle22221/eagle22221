"""Modding features as the user reaches them: CLI commands and the web API
for Windows resources and patches. Offsets come from the fixture facts used
elsewhere in the suite (llvm-readobj / strings -t x)."""
import http.client
import json
import shutil
import threading
from urllib.parse import quote

import pytest

import vex
from vex import resources, server
from vex.cli import main
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
    modded = vex.load(out_path)
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

    def call(self, method, endpoint, body=None, **params):
        query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=10)
        conn.request(method, f"/api/{endpoint}?{query}", body=body,
                     headers={"X-Vex-Token": self.ws.token})
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
    modded = vex.load(out)
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


# --- asset packs (CLI) -----------------------------------------------------

@pytest.fixture
def pack(tmp_path):
    """A small ZIP-based pack (.pk3) written with the standard library."""
    import zipfile
    path = tmp_path / "game" / "assets.pk3"
    path.parent.mkdir()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("textures/logo.png", b"\x89PNG fake logo")
        z.writestr("scripts/config.json", b'{"lives": 3}')
        z.writestr("readme.txt", b"hello pack\n")
    return path


def zip_contents(path):
    import zipfile
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def test_assets_list(capsys, pack):
    code, out, _ = run(capsys, "--json", "assets", "list", str(pack))
    data = json.loads(out)
    assert code == 0 and (data["format"], data["count"], data["writable"]) == ("zip", 3, True)
    assert [e["name"] for e in data["items"]] == [
        "textures/logo.png", "scripts/config.json", "readme.txt"]
    assert data["items"][2]["size"] == 11
    code, out, _ = run(capsys, "--json", "assets", "list", str(pack), "--grep", r"\.json$")
    assert [e["name"] for e in json.loads(out)["items"]] == ["scripts/config.json"]


def test_assets_extract_all_and_selected(capsys, pack, tmp_path):
    code, out, _ = run(capsys, "assets", "extract", str(pack), str(tmp_path / "all"))
    assert code == 0 and "Extracted 3 files" in out
    assert (tmp_path / "all" / "scripts" / "config.json").read_bytes() == b'{"lives": 3}'
    run(capsys, "assets", "extract", str(pack), str(tmp_path / "one"), "readme.txt")
    assert [p.name for p in (tmp_path / "one").rglob("*") if p.is_file()] == ["readme.txt"]


def test_assets_replace_writes_a_new_pack_and_leaves_the_original(capsys, pack, tmp_path):
    before = pack.read_bytes()
    new = tmp_path / "new.json"
    new.write_bytes(b'{"lives": 99}')
    out_path = tmp_path / "modded.pk3"
    code, out, _ = run(capsys, "assets", "replace", str(pack), "scripts/config.json",
                       str(new), "-o", str(out_path))
    assert code == 0 and "Replaced scripts/config.json" in out
    assert zip_contents(out_path) == {
        "textures/logo.png": b"\x89PNG fake logo",
        "scripts/config.json": b'{"lives": 99}',
        "readme.txt": b"hello pack\n",
    }
    assert pack.read_bytes() == before


def test_assets_add_appends_a_file(capsys, pack, tmp_path):
    new = tmp_path / "extra.txt"
    new.write_bytes(b"extra")
    out_path = tmp_path / "modded.pk3"
    assert run(capsys, "assets", "add", str(pack), "mods/extra.txt", str(new),
               "-o", str(out_path))[0] == 0
    contents = zip_contents(out_path)
    assert contents["mods/extra.txt"] == b"extra" and len(contents) == 4


def test_assets_errors_are_clean(capsys, pack, tmp_path):
    new = tmp_path / "x"
    new.write_bytes(b"x")
    code, _, err = run(capsys, "assets", "replace", str(pack), "no/such/file", str(new),
                       "-o", str(tmp_path / "o.pk3"))
    assert code == 1 and "no/such/file" in err and not (tmp_path / "o.pk3").exists()
    code, _, err = run(capsys, "assets", "list", str(new))
    assert code == 1 and err.startswith("vex: error:")


def test_engine_command_reports_packs_next_to_a_program(capsys, pack):
    shutil.copy(PE, pack.parent / "game.exe")
    code, out, _ = run(capsys, "--json", "engine", str(pack.parent))
    data = json.loads(out)
    assert code == 0 and data["root"] == str(pack.parent)
    assert [p["relative"] for p in data["packs"]] == ["assets.pk3"]
    assert isinstance(data["matches"], list)
    code, out, _ = run(capsys, "engine", str(pack.parent / "game.exe"))
    assert code == 0 and "assets.pk3" in out


# --- asset packs (web API) -------------------------------------------------

def test_api_lists_and_serves_pack_files(api, pack):
    status, data = api.call("GET", "archive/list", path=str(pack))
    assert status == 200
    assert (data["format"], data["count"], data["total"]) == ("zip", 3, 3)
    status, data = api.call("GET", "archive/list", path=str(pack), q="LOGO")
    assert [e["name"] for e in data["items"]] == ["textures/logo.png"]
    status, raw = api.call("GET", "archive/file", path=str(pack), name="readme.txt")
    assert (status, raw) == (200, b"hello pack\n")
    assert api.call("GET", "archive/file", path=str(pack), name="nope.txt")[0] == 404


def test_api_extracts_and_replaces_pack_files(api, pack, tmp_path):
    status, done = api.call("POST", "archive/extract", path=str(pack), dest=str(tmp_path / "x"))
    assert status == 200 and done["count"] == 3
    assert (tmp_path / "x" / "readme.txt").read_bytes() == b"hello pack\n"

    out = tmp_path / "modded.pk3"
    status, done = api.call("POST", "archive/replace", body=b"changed", path=str(pack),
                            name="readme.txt", out=str(out))
    assert status == 200 and zip_contents(out)["readme.txt"] == b"changed"
    # a name that is not in the pack is added
    status, done = api.call("POST", "archive/replace", body=b"new", path=str(pack),
                            name="mods/new.txt", out=str(out))
    assert status == 200 and zip_contents(out)["mods/new.txt"] == b"new"


def test_api_never_overwrites_the_pack_it_is_reading(api, pack):
    before = pack.read_bytes()
    status, data = api.call("POST", "archive/replace", body=b"x", path=str(pack),
                            name="readme.txt", out=str(pack))
    assert status == 400 and "new name" in data["error"]
    assert pack.read_bytes() == before


def test_api_open_and_browse_recognise_packs(api, pack):
    assert api.call("GET", "open", path=str(pack))[1]["kind"] == "archive"
    _, listing = api.call("GET", "browse", dir=str(pack.parent))
    assert {e["name"]: e["kind"] for e in listing["entries"]} == {"assets.pk3": "archive"}


def test_api_engine_lists_matches_and_packs(api, pack):
    status, data = api.call("GET", "engine", path=str(pack.parent))
    assert status == 200 and [p["relative"] for p in data["packs"]] == ["assets.pk3"]
    assert api.call("GET", "engine", path="/no/such/folder")[0] == 404
