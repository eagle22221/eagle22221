"""The entropy profile: `vex entropy FILE [--points N]` and GET /api/entropy.

Shannon entropy in bits per byte along the file, one point per block of
max(256, ceil(size / points)) bytes, plus the entropy of the whole file.
Every expected value here is worked out from the file's bytes with
math.log2 and collections.Counter; the code under test is never asked.
"""
import collections
import json
import math
import random
import re
from urllib.parse import quote

import pytest

import vex
from vex import server, views
from vex.cli import main
from vex.model import Binary
from conftest import FIXTURES, fixture_bytes, fixture_path
from test_server import client  # noqa: F401  (the running server, reused)

FIXTURE_NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())
# The smallest file vex loads: a 64-bit ELF header with nothing else in it.
ELF_HEADER = b"\x7fELF\x02\x01\x01" + bytes(57)
SIZES = [0, 1, 255, 256, 257, 256 * 64, 256 * 64 + 1]
LARGE = 3 * 1024 * 1024
POINTS = [1, 8, 64, 1024]
# requested number of points -> the number used
CLAMPED = {0: 1, -1: 1, -5000: 1, 1025: 1024, 5000: 1024, 10 ** 12: 1024, 10 ** 40: 1024}
SCALE = "0" + " " * 38 + "8"


# --- the reference, worked out here -------------------------------------------

def shannon(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    total = len(data)
    return -sum(n / total * math.log2(n / total) for n in collections.Counter(data).values())


def expected(data: bytes, points: int = 64) -> dict:
    points = max(1, min(points, 1024))
    size = len(data)
    block = max(256, -(-size // points))
    return {"size": size, "block": block, "overall": round(shannon(data), 3),
            "points": [{"offset": offset, "entropy": round(shannon(data[offset:offset + block]), 3)}
                       for offset in range(0, size, block)]}


def body(size: int, seed: int = 0) -> bytes:
    """`size` bytes that are not all alike: stretches of random bytes, of one
    repeated byte and of text."""
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        kind, n = rng.randrange(3), rng.randrange(1, 5000)
        if kind == 0:
            out += rng.randbytes(n)
        elif kind == 1:
            out += bytes([rng.randrange(256)]) * n
        else:
            out += (b"the quick brown fox jumps over the lazy dog " * (n // 44 + 1))[:n]
    return bytes(out[:size])


def program(size: int, seed: int = 0) -> bytes:
    """A file of exactly `size` bytes that vex loads (size >= 64)."""
    assert size >= len(ELF_HEADER)
    return ELF_HEADER + body(size - len(ELF_HEADER), seed)


def bits(value: float) -> str:
    return f"{abs(value):.2f}"


@pytest.fixture(scope="module")
def large():
    return program(LARGE, seed=3)


# --- the view -----------------------------------------------------------------

@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_every_fixture_matches_the_reference(name):
    data = fixture_bytes(name)
    binary = vex.load(fixture_path(name))
    assert views.entropy_profile(binary) == expected(data, 64)
    for points in POINTS:
        assert views.entropy_profile(binary, points) == expected(data, points), points


@pytest.mark.parametrize("size", SIZES + [LARGE])
@pytest.mark.parametrize("points", POINTS + [64 + 7])
def test_constructed_sizes_match_the_reference(size, points):
    data = body(size, seed=size)
    profile = views.entropy_profile(Binary(data), points)
    assert profile == expected(data, points)
    block = profile["block"]
    assert block == max(256, math.ceil(size / points)) if size else block == 256
    offsets = [p["offset"] for p in profile["points"]]
    assert offsets == list(range(0, size, block))
    assert len(offsets) == math.ceil(size / block) <= points
    assert all(0 <= p["entropy"] <= 8 for p in profile["points"])
    assert 0 <= profile["overall"] <= 8


def test_the_large_file_matches_the_reference(large):
    for points in POINTS:
        assert views.entropy_profile(Binary(large), points) == expected(large, points)


# (size, points) -> (block, number of points), worked out by hand
BLOCKS = {
    (0, 64): (256, 0), (1, 64): (256, 1), (255, 64): (256, 1), (256, 64): (256, 1),
    (257, 64): (256, 2), (16384, 64): (256, 64), (16385, 64): (257, 64),
    (16385, 1024): (256, 65), (100, 1): (256, 1), (1000, 1): (1000, 1),
    (LARGE, 64): (49152, 64), (LARGE, 1024): (3072, 1024), (LARGE + 1, 1024): (3073, 1024),
    (LARGE, 1): (LARGE, 1), (LARGE, 1000): (3146, 1000),
}


@pytest.mark.parametrize("size, points", sorted(BLOCKS))
def test_block_size_and_point_count(size, points):
    profile = views.entropy_profile(Binary(bytes(size)), points)
    assert (profile["block"], len(profile["points"])) == BLOCKS[size, points]
    assert profile["size"] == size


def test_known_values():
    empty = views.entropy_profile(Binary(b""))
    assert empty == {"size": 0, "block": 256, "overall": 0.0, "points": []}
    assert json.dumps(empty) == '{"size": 0, "block": 256, "overall": 0.0, "points": []}'
    assert views.entropy_profile(Binary(b"x")) == {
        "size": 1, "block": 256, "overall": 0.0, "points": [{"offset": 0, "entropy": 0.0}]}
    every_byte = views.entropy_profile(Binary(bytes(range(256))))
    assert every_byte["overall"] == 8.0 and every_byte["points"] == [{"offset": 0, "entropy": 8.0}]
    halves = views.entropy_profile(Binary(bytes(256) + bytes(range(256)) * 2 + b"ab" * 128))
    assert [p["entropy"] for p in halves["points"]] == [0.0, 8.0, 8.0, 1.0]
    assert [p["offset"] for p in halves["points"]] == [0, 256, 512, 768]
    # three quarters zeros, one quarter 0xff: 0.811278... bits per byte
    assert views.entropy_profile(Binary(bytes(192) + b"\xff" * 64))["overall"] == 0.811


def test_values_are_rounded_like_the_sections_view():
    binary = vex.load(fixture_path("hello_elf64"))
    profile = views.entropy_profile(binary)
    for value in [profile["overall"]] + [p["entropy"] for p in profile["points"]]:
        assert value == round(value, 3)
    whole = views.info(binary)["entropy"]
    assert profile["overall"] == whole        # info rounds the whole file the same way


@pytest.mark.parametrize("requested", sorted(CLAMPED))
def test_points_are_clamped_to_1_to_1024(requested):
    data = body(LARGE // 2, seed=7)
    assert views.entropy_profile(Binary(data), requested) == expected(data, CLAMPED[requested])


# --- the command line ---------------------------------------------------------

def run(capsys, *args):
    try:
        code = main([str(a) for a in args])
    except SystemExit as exc:
        code = exc.code
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_cli_json_is_the_profile(capsys, name):
    data, path = fixture_bytes(name), fixture_path(name)
    assert run(capsys, "--json", "entropy", path) == \
        (0, json.dumps(expected(data), indent=2) + "\n", "")
    assert run(capsys, "--json", "entropy", path, "--points", "8") == \
        (0, json.dumps(expected(data, 8), indent=2) + "\n", "")


@pytest.mark.parametrize("size", [64, 255, 256, 257, 256 * 64, 256 * 64 + 1, LARGE])
@pytest.mark.parametrize("points", [None] + POINTS)
def test_cli_json_of_constructed_files(capsys, tmp_path, size, points):
    data = program(size, seed=size)
    path = tmp_path / "prog"
    path.write_bytes(data)
    extra = [] if points is None else ["--points", points]
    code, out, err = run(capsys, "--json", "entropy", path, *extra)
    assert (code, err) == (0, "")
    assert out == json.dumps(expected(data, 64 if points is None else points), indent=2) + "\n"


def check_text(out: str, want: dict) -> None:
    lines = out.split("\n")
    assert lines.pop() == ""
    assert lines[0] == (f"Size {want['size']} bytes, block {want['block']} bytes, "
                        f"overall entropy {bits(want['overall'])} bits/byte")
    if not want["points"]:
        assert lines == lines[:1]
        return
    assert lines[1] == ""
    offset_width = max(6, max(len(f"{p['offset']:#x}") for p in want["points"]))
    assert lines[2] == "Offset".rjust(offset_width) + "  Entropy  " + SCALE
    assert lines[3] == "-" * offset_width + "  -------  " + "-" * 40
    rows = lines[4:]
    assert len(rows) == len(want["points"])
    for row, point in zip(rows, want["points"]):
        bar = "#" * int(point["entropy"] * 40 / 8)
        assert row == (f"{point['offset']:#x}".rjust(offset_width) + "  " +
                       bits(point["entropy"]).rjust(7) + "  " + bar).rstrip()
        assert len(bar) <= 40


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_cli_text_of_fixtures(capsys, name):
    code, out, err = run(capsys, "entropy", fixture_path(name))
    assert (code, err) == (0, "")
    check_text(out, expected(fixture_bytes(name)))
    code, out, err = run(capsys, "entropy", fixture_path(name), "--points", "1024")
    check_text(out, expected(fixture_bytes(name), 1024))


def test_cli_text_of_the_large_file(capsys, tmp_path, large):
    path = tmp_path / "large"
    path.write_bytes(large)
    for points in POINTS:
        code, out, err = run(capsys, "entropy", path, "--points", points)
        assert (code, err) == (0, "")
        check_text(out, expected(large, points))


def test_cli_text_exactly(capsys, tmp_path):
    data = ELF_HEADER + bytes(256 - 64) + bytes(range(256)) * 2 + bytes(10)
    path = tmp_path / "prog"
    path.write_bytes(data)
    first = bits(round(shannon(data[:256]), 3))
    assert first == "0.25"
    code, out, err = run(capsys, "entropy", path)
    assert (code, err) == (0, "")
    assert out == (
        f"Size 778 bytes, block 256 bytes, overall entropy {bits(round(shannon(data), 3))} "
        "bits/byte\n"
        "\n"
        f"Offset  Entropy  {SCALE}\n"
        "------  -------  ----------------------------------------\n"
        "   0x0     0.25  #\n"
        " 0x100     8.00  ########################################\n"
        " 0x200     8.00  ########################################\n"
        " 0x300     0.00\n")


@pytest.mark.parametrize("given, used", [
    ("8", 8), ("0x10", 16), ("0", 1), ("-3", 1), ("99999", 1024), ("1_000", 1000),
    (" 12 ", 12), ("1024", 1024), ("1025", 1024), (str(10 ** 40), 1024)])
def test_cli_points_option(capsys, given, used):
    data, path = fixture_bytes("hello_pe64.exe"), fixture_path("hello_pe64.exe")
    code, out, err = run(capsys, "--json", "entropy", path, "--points", given)
    assert (code, err) == (0, "") and json.loads(out) == expected(data, used)
    code, out, err = run(capsys, "--json", "entropy", f"--points={given}", path)
    assert (code, err) == (0, "") and json.loads(out) == expected(data, used)


@pytest.mark.parametrize("given", ["abc", "", "1.5", "0x", "8 8", "010"])
def test_cli_points_must_be_a_number(capsys, given):
    code, out, err = run(capsys, "entropy", fixture_path("hello_elf64"), "--points", given)
    assert (code, out) == (2, "")
    assert err.endswith(f"error: argument --points: invalid _int value: {given!r}\n")


def test_cli_errors(capsys, tmp_path):
    missing, empty, text = tmp_path / "missing", tmp_path / "empty", tmp_path / "notes.txt"
    empty.write_bytes(b"")
    text.write_text("plain text, not a program\n")
    assert run(capsys, "entropy", missing) == \
        (1, "", f"vex: error: cannot read {missing}: No such file or directory\n")
    assert run(capsys, "entropy", empty) == (1, "", "vex: error: file is empty\n")
    assert run(capsys, "--json", "entropy", text) == \
        (1, "", "vex: error: not an ELF or PE file (no \\x7fELF or MZ signature)\n")
    assert run(capsys, "entropy", tmp_path) == \
        (1, "", f"vex: error: cannot read {tmp_path}: Is a directory\n")
    code, out, err = run(capsys, "entropy")
    assert (code, out) == (2, "") and err.endswith("required: FILE\n")


def test_cli_help(capsys):
    code, out, _ = run(capsys, "--help")
    assert code == 0 and re.search(r"^\s+entropy\s+\S", out, re.M)
    code, out, _ = run(capsys, "entropy", "--help")
    assert code == 0 and "--points N" in out and "1024" in out


# --- the API ------------------------------------------------------------------

def api_get(client, **params):  # noqa: F811
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
    return client.get(f"/api/entropy?{query}")


def test_route_is_registered():
    assert "entropy" in server.GET_ROUTES and "entropy" not in server.POST_ROUTES


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_api_fixtures(client, name):  # noqa: F811
    data, path = fixture_bytes(name), str(fixture_path(name))
    assert client.api("entropy", path=path) == expected(data)
    for points in POINTS:
        assert client.api("entropy", path=path, points=points) == expected(data, points)


@pytest.mark.parametrize("size", [64, 255, 256, 257, 256 * 64, 256 * 64 + 1])
def test_api_constructed_files(client, tmp_path, size):  # noqa: F811
    data = program(size, seed=size + 1)
    path = tmp_path / f"prog{size}"
    path.write_bytes(data)
    for points in [None] + POINTS:
        params = {} if points is None else {"points": points}
        assert client.api("entropy", path=path, **params) == \
            expected(data, 64 if points is None else points)


def test_api_large_file(client, tmp_path, large):  # noqa: F811
    path = tmp_path / "large"
    path.write_bytes(large)
    for points in POINTS:
        assert client.api("entropy", path=path, points=points) == expected(large, points)


@pytest.mark.parametrize("given, used", [
    ("", 64), ("0x20", 32), ("0", 1), ("-1", 1), ("1025", 1024), ("5000", 1024),
    (" 9 ", 9), ("1_0", 10), (str(10 ** 30), 1024), (str(-10 ** 30), 1)])
def test_api_points_parameter(client, given, used):  # noqa: F811
    path = fixture_path("sample.dll")
    assert client.api("entropy", path=path, points=given) == \
        expected(fixture_bytes("sample.dll"), used)


def test_api_errors(client, tmp_path):  # noqa: F811
    elf = fixture_path("hello_elf64")
    empty, text = tmp_path / "empty", tmp_path / "notes.txt"
    empty.write_bytes(b"")
    text.write_text("plain text, not a program\n")
    number = (400, {"error": "parameter points must be a number"})
    for bad in ("abc", "1.5", "0x", "010"):
        assert api_get(client, path=elf, points=bad) == number, bad
    assert api_get(client) == (400, {"error": "missing parameter: path"})
    assert api_get(client, path="") == (400, {"error": "missing parameter: path"})
    assert api_get(client, path=tmp_path / "missing") == \
        (404, {"error": f"no such file or folder: {tmp_path / 'missing'}"})
    assert api_get(client, path=empty) == (400, {"error": "file is empty"})
    status, data = api_get(client, path=text)
    assert status == 400 and "not an ELF or PE" in data["error"]
    status, data = api_get(client, path=tmp_path)
    assert status == 400 and "error" in data
