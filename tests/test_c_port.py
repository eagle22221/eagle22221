"""The native C version of vex (c/) against the Python implementation.

The Python package is the reference: for every command the C program must
print the same JSON. Most tests here are differential: run both on the same
input, json.loads both outputs and compare. The rest cover error behaviour,
hostile input (under AddressSanitizer/UBSan), patching and the Windows build.
"""
import contextlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import vex
from vex import views
from vex.cli import main as python_main
from conftest import FIXTURES, fixture_bytes, fixture_path

C_DIR = Path(__file__).resolve().parent.parent / "c"
MAKE = shutil.which("make")
COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
MINGW = shutil.which("x86_64-w64-mingw32-gcc")

pytestmark = pytest.mark.skipif(
    not (MAKE and COMPILER and C_DIR.is_dir()),
    reason="the C port needs make and a C compiler")

FIXTURE_NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())
ELF_FIXTURES = [n for n in FIXTURE_NAMES if fixture_bytes(n)[:4] == b"\x7fELF"]
PE_FIXTURES = [n for n in FIXTURE_NAMES if fixture_bytes(n)[:2] == b"MZ"]

SYSTEM_BINARIES = [p for p in (
    "/usr/bin/ls", "/usr/bin/python3", "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib/x86_64-linux-gnu/libz.so.1",
    "/usr/lib/x86_64-linux-gnu/libstdc++.so.6",
) if os.path.isfile(p)]


# --- running the two implementations -------------------------------------------

NO_DISASSEMBLER = "this build has no disassembler"


def _make(target):
    if not list(C_DIR.glob("third_party/capstone-*/src/cs.c")):
        # A fresh checkout: get the disassembler source (best effort; without
        # it the build works and the tests that need disassembly are skipped).
        subprocess.run(["sh", str(C_DIR / "fetch_capstone.sh")], capture_output=True,
                       timeout=300, check=False)
    proc = subprocess.run([MAKE, "-C", str(C_DIR), target], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"make {target} failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")


@pytest.fixture(scope="session")
def c_binary():
    """The native build. VEX_TEST_SANITIZED=1 runs every test against
    the AddressSanitizer/UBSan build instead (slower, but any memory error in
    any command then fails the test that reaches it)."""
    if os.environ.get("VEX_TEST_SANITIZED"):
        _make("asan")
        return C_DIR / "build" / "vex-asan"
    _make("all")
    return C_DIR / "build" / "vex"


@pytest.fixture(scope="session")
def asan_binary():
    _make("asan")
    return C_DIR / "build" / "vex-asan"


def run_c(binary, *args, timeout=120, env=None):
    proc = subprocess.run([str(binary), *map(str, args)], capture_output=True,
                          timeout=timeout, env=env)
    out, err = proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")
    if NO_DISASSEMBLER in err + out[-200:] and Path(binary).parent == C_DIR / "build":
        pytest.skip("the C program was built without Capstone: run c/fetch_capstone.sh")
    return proc.returncode, out, err


def run_python(*args):
    """The Python CLI in-process: (exit status, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = python_main([str(a) for a in args])
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


# Parts of the Python `report` that were added to the reference after this
# port was written and that the C program does not produce yet. They are left
# out of the comparison (everything else in the report must still match);
# test_report_parts_missing_from_the_c_port starts failing when this is stale.
NOT_PORTED_REPORT_KEYS = ()


def strip_path(data):
    """Drop the two fields that are allowed to differ (formatting of the path
    as given on the command line)."""
    if isinstance(data, dict):
        if "info" in data and isinstance(data["info"], dict):       # a report
            data = {k: v for k, v in data.items() if k not in NOT_PORTED_REPORT_KEYS}
            data["info"] = strip_path(data["info"])
        if "path" in data and "format" in data:
            data = {k: v for k, v in data.items() if k not in ("path", "name")}
    return data


def assert_same_json(binary, *args):
    """Both implementations succeed and print the same data."""
    code, out, err = run_c(binary, "--json", *args)
    py_code, py_out, py_err = run_python("--json", *args)
    assert (code, err) == (py_code, "") and py_code == 0, (args, code, err, py_err)
    mine, reference = json.loads(out), json.loads(py_out)
    assert strip_path(mine) == strip_path(reference), args
    return mine


def assert_same_outcome(binary, *args):
    """Same data on success; on failure the same exit status and a message."""
    code, out, err = run_c(binary, "--json", *args)
    py_code, py_out, py_err = run_python("--json", *args)
    assert code == py_code, (args, code, err, py_code, py_err)
    if code == 0:
        assert strip_path(json.loads(out)) == strip_path(json.loads(py_out)), args
    else:
        assert err.startswith("vex: error: ") or "\nvex: error: " in err
    return code


# --- differential tests: every read-only command on every fixture ---------------

READ_COMMANDS = [
    ("info",), ("sections",), ("imports",), ("exports",),
    ("symbols",), ("symbols", "--grep", "main"), ("symbols", "--grep", "_"),
    ("strings",), ("strings", "-n", "8"), ("strings", "--min", "1"),
    ("strings", "-e", "ascii"), ("strings", "-e", "utf16", "-n", "6"),
    ("strings", "--tagged"), ("strings", "--grep", "fixture"),
    ("strings", "--encoding=all", "--grep", "dll", "-n", "5"),
    ("hexdump",), ("hexdump", "--offset", "0x10", "-n", "48"),
    ("hexdump", "--offset", "0", "--length", "0x1000"), ("hexdump", "-n", "0"),
    ("functions",), ("functions", "--grep", "sub_"), ("functions", "--grep", "main"),
    ("disasm",), ("disasm", "-n", "5"), ("disasm", "--count", "200"), ("disasm", "-n", "0"),
    ("report",),
]


def _command_id(command):
    return " ".join(command)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
@pytest.mark.parametrize("command", READ_COMMANDS, ids=_command_id)
def test_read_only_commands_match_python(c_binary, name, command):
    assert_same_json(c_binary, command[0], fixture_path(name), *command[1:])


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_info_reports_the_path_as_given(c_binary, name):
    path = str(fixture_path(name))
    info = json.loads(run_c(c_binary, "--json", "info", path)[1])
    assert (info["path"], info["name"]) == (path, name)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_segments_and_layout_match_the_python_views(c_binary, name):
    """`segments` and `layout` are extra commands of the C program; they print
    views.segments() and views.layout(), which the Python CLI does not expose."""
    path = fixture_path(name)
    b = vex.load(path)
    assert json.loads(run_c(c_binary, "--json", "segments", path)[1]) == views.segments(b)
    assert json.loads(run_c(c_binary, "--json", "layout", path)[1]) == views.layout(b)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_hexdump_at_addresses(c_binary, name):
    b = vex.load(fixture_path(name))
    wanted = [m[0] for m in b.maps] + [m[0] + m[2] - 1 for m in b.maps]
    if b.entry is not None:
        wanted.append(b.entry)
    for address in wanted:
        assert_same_json(c_binary, "hexdump", fixture_path(name), hex(address), "-n", "40")


@pytest.mark.parametrize("path", SYSTEM_BINARIES)
@pytest.mark.parametrize("command", [
    ("info",), ("sections",), ("imports",), ("exports",), ("symbols",),
    ("strings", "-n", "6"), ("strings", "--tagged"), ("hexdump", "-n", "512"),
], ids=_command_id)
def test_system_binaries_match_python(c_binary, path, command):
    assert_same_json(c_binary, command[0], path, *command[1:])


CODE_BINARIES = SYSTEM_BINARIES


@pytest.mark.parametrize("path", CODE_BINARIES)
@pytest.mark.parametrize("command", [
    ("functions",), ("disasm",), ("disasm", "-n", "300"), ("xrefs", "malloc"),
    ("xrefs", "--string", "%s"), ("report",),
], ids=_command_id)
def test_system_binary_code_analysis_matches_python(c_binary, path, command):
    assert_same_outcome(c_binary, command[0], path, *command[1:])


@pytest.mark.parametrize("path", CODE_BINARIES)
def test_system_binary_functions_disassemble_like_python(c_binary, path):
    functions = json.loads(run_python("--json", "functions", path)[1])
    rng = random.Random(len(functions))
    # every Python run sweeps the whole program again: fewer samples for big ones
    count = 25 if len(functions) < 2000 else 6
    for f in rng.sample(functions, min(count, len(functions))):
        assert_same_json(c_binary, "disasm", path, f["address"])
        assert_same_outcome(c_binary, "xrefs", path, f["name"])


# --- names, cross-references and disassembly on the fixtures -------------------------

def _locations(name):
    """Things a user could pass as LOCATION/TARGET for this fixture."""
    b = vex.load(fixture_path(name))
    functions = json.loads(run_python("--json", "functions", fixture_path(name))[1])
    names = [f["name"] for f in functions] + [f["address"] for f in functions]
    names += [s.name for s in b.symbols[:40]] + [e.name for e in b.exports[:20]]
    for imp in b.imports:
        names += [imp.name, f"{imp.library}!{imp.name}", f"{str(imp.library).upper()}!{imp.name}"]
        if imp.address is not None:
            names.append(hex(imp.address))
    names += ["entry", " entry ", "no_such_function", "nolib!puts", "!", "", "0x0", "-1",
              "12345678901234567890123", "main+4", "MAIN"]
    names += [hex(s.vaddr + 1) for s in b.sections[:6] if s.vaddr]
    return list(dict.fromkeys(names))


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_locations_resolve_like_python(c_binary, name):
    path = fixture_path(name)
    for location in _locations(name):
        assert_same_outcome(c_binary, "disasm", path, location)
        assert_same_outcome(c_binary, "disasm", path, location, "-n", "3")
        assert_same_outcome(c_binary, "xrefs", path, location)
        assert_same_outcome(c_binary, "hexdump", path, location, "-n", "24")


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_xrefs_by_string_content_match_python(c_binary, name):
    path = fixture_path(name)
    strings = json.loads(run_python("--json", "strings", path)[1])
    wanted = [s["text"] for s in strings if s["address"]][:60]
    wanted += ["fixture", "e", "%", "no such string anywhere", "\"quoted\" it's"]
    for text in dict.fromkeys(wanted):
        assert_same_outcome(c_binary, "xrefs", path, "--string", text)
    assert_same_outcome(c_binary, "xrefs", path)                        # needs a target
    assert_same_outcome(c_binary, "xrefs", path, "--string", "")
    assert_same_outcome(c_binary, "xrefs", path, "entry", "--string", "e")


def test_disassembly_text_and_comments(c_binary):
    """Spot checks with values from tests/test_cli.py, then the whole text."""
    path = fixture_path("hello_elf64")
    listing = json.loads(run_c(c_binary, "--json", "disasm", path, "main")[1])
    insns = listing["instructions"]
    assert listing["name"] == "main" and len(insns) == 50
    assert insns[0]["address"] == "0x11f2" and insns[0]["mnemonic"] == "endbr64"
    assert insns[-1]["comment"] == "__stack_chk_fail@plt"
    rows = json.loads(run_c(c_binary, "--json", "xrefs", path, "puts")[1])
    assert [r["address"] for r in rows] == ["0x10a4", "0x123e", "0x1246", "0x1264"]
    assert rows[1] == {"address": "0x123e", "kind": "call", "function": "main+0x4c",
                       "text": "call 0x10a0"}
    for name in FIXTURE_NAMES:
        for args in (("disasm",), ("disasm", "-n", "40"), ("functions",), ("xrefs", "entry")):
            full = (args[0], fixture_path(name), *args[1:])
            assert run_c(c_binary, *full) == run_python(*full), full
    coloured = ("--color", "always", "disasm", path, "main")
    assert run_c(c_binary, *coloured) == run_python(*coloured)


@pytest.mark.parametrize("path", SYSTEM_BINARIES)
def test_system_binary_segments_and_layout(c_binary, path):
    b = vex.load(path)
    assert json.loads(run_c(c_binary, "--json", "segments", path)[1]) == views.segments(b)
    assert json.loads(run_c(c_binary, "--json", "layout", path)[1]) == views.layout(b)


# --- text output ------------------------------------------------------------------

TEXT_COMMANDS = [("info",), ("sections",), ("imports",), ("exports",), ("symbols",),
                 ("strings", "--tagged"), ("strings", "-e", "utf16"),
                 ("hexdump", "-n", "64"), ("report",)]


@pytest.mark.parametrize("name", FIXTURE_NAMES)
@pytest.mark.parametrize("command", TEXT_COMMANDS, ids=_command_id)
def test_text_output_follows_the_python_layout(c_binary, name, command):
    """Only the JSON has to match, but the text renderers are a straight port,
    so for ordinary files the text is the same too."""
    args = (command[0], fixture_path(name), *command[1:])
    mine, reference = run_c(c_binary, *args), run_python(*args)
    if command == ("report",) and "\n== Techniques ==\n" in reference[1]:
        pytest.skip("the Techniques part of the report is not in the C program yet")
    assert mine == reference


def test_report_parts_missing_from_the_c_port(c_binary):
    """Fails (as an unexpected pass) once the C report has every part of the
    Python report: then empty NOT_PORTED_REPORT_KEYS and delete this test."""
    path = fixture_path("hello_pe64.exe")
    mine = json.loads(run_c(c_binary, "--json", "report", path)[1])
    reference = json.loads(run_python("--json", "report", path)[1])
    assert set(reference) - set(mine) == set()


def test_colour_only_on_request_and_never_with_no_color(c_binary):
    path = fixture_path("hello_elf64")
    assert "\x1b[" not in run_c(c_binary, "info", path)[1]         # a pipe: plain
    coloured = run_c(c_binary, "--color", "always", "info", path)[1]
    assert coloured == run_python("--color", "always", "info", path)[1]
    assert "\x1b[1;36m== Overview ==\x1b[0m" in coloured
    env = dict(os.environ, NO_COLOR="1")
    assert "\x1b[" not in run_c(c_binary, "--color", "auto", "info", path, env=env)[1]
    assert "\x1b[" not in run_c(c_binary, "--json", "--color", "always", "info", path)[1]


def test_version_and_help(c_binary):
    assert run_c(c_binary, "--version") == (0, f"vex {vex.__version__}\n", "")
    code, out, _ = run_c(c_binary, "--help")
    assert code == 0
    for word in ("info", "sections", "imports", "exports", "symbols", "strings", "hexdump",
                 "report", "patch", "disasm", "functions", "xrefs", "--json", "--color",
                 "not a regular expression"):
        assert word in out
    assert run_c(c_binary, "strings", "--help")[0] == 0


def test_a_file_without_a_command_gets_a_report(c_binary):
    """Dropping a file on vex.exe starts it with just that path."""
    path = fixture_path("hello_pe64.exe")
    assert run_c(c_binary, path) == run_c(c_binary, "report", path)
    assert run_c(c_binary, "--json", path) == run_c(c_binary, "--json", "report", path)
    assert run_c(c_binary, path)[0] == 0


def test_grep_is_a_plain_substring_match(c_binary):
    """Documented difference: the Python --grep takes a regular expression."""
    path = fixture_path("hello_elf64")
    rows = json.loads(run_c(c_binary, "--json", "symbols", path, "--grep", "add_")[1])
    assert [r["name"] for r in rows] == ["add_numbers"]
    assert json.loads(run_c(c_binary, "--json", "symbols", path, "--grep", "^main$")[1]) == []
    assert json.loads(run_c(c_binary, "--json", "symbols", path, "--grep", "MAIN")[1]) == []
    rows = json.loads(run_c(c_binary, "--json", "strings", path, "--grep", "example.com")[1])
    assert [r["text"] for r in rows] == ["Visit http://example.com/docs for help"]


# --- errors -------------------------------------------------------------------------

def _files_that_do_not_load(tmp_path):
    cases = {
        "missing": tmp_path / "no" / "such" / "file.bin",
        "folder": tmp_path,
    }
    pe = fixture_bytes("hello_pe64.exe")
    optional_header = struct.unpack_from("<I", pe, 0x3C)[0] + 24
    contents = {
        "notes.txt": b"just some notes",
        "empty.bin": b"",
        "short_elf": fixture_bytes("hello_elf64")[:10],
        "cut_elf_header": fixture_bytes("hello_elf64")[:40],
        "bad_class": b"\x7fELF\x07" + fixture_bytes("hello_elf64")[5:],
        "bad_order": b"\x7fELF\x02\x09" + fixture_bytes("hello_elf64")[6:],
        "dos.exe": fixture_bytes("hello_pe64.exe")[:0x40],
        "tiny_mz": b"MZ\x90\x00",
        "cut_pe_header": pe[:optional_header + 60],
        "bad_magic.exe": pe[:optional_header] + b"\x00\x00" + pe[optional_header + 2:],
        "rom_magic.exe": pe[:optional_header] + b"\x07\x01" + pe[optional_header + 2:],
    }
    for name, data in contents.items():
        (tmp_path / name).write_bytes(data)
        cases[name] = tmp_path / name
    return cases


@pytest.mark.parametrize("command", ["info", "sections", "strings", "hexdump", "report"])
def test_unreadable_and_foreign_files_fail_like_python(c_binary, tmp_path, command):
    for label, path in _files_that_do_not_load(tmp_path).items():
        mine, reference = run_c(c_binary, command, path), run_python(command, path)
        assert mine == reference, label
        assert mine[0] == 1 and mine[1] == "" and mine[2].startswith("vex: error: ")


@pytest.mark.parametrize("args", [
    ("hexdump", "0xdeadbeef00"), ("hexdump", "-1"), ("hexdump", "--offset", "0x100000"),
    ("hexdump", "--offset", "-5"), ("hexdump", "0x0", "-n", "16"),
    ("hexdump", "--offset", "0xffffffffffffffffffff"),
    ("hexdump", "1_0"), ("hexdump", "0o17"), ("hexdump", "0b101"), ("hexdump", "010"),
], ids=_command_id)
@pytest.mark.parametrize("name", ["hello_elf64", "hello_pe64.exe", "libsample.so"])
def test_bad_locations_fail_like_python(c_binary, name, args):
    """A location that is not in the file: exit 1 and the same message."""
    full = (args[0], fixture_path(name), *args[1:])
    mine, reference = run_c(c_binary, *full), run_python(*full)
    if "010" in args:           # a name, not a number: needs the disassembler
        assert mine[0] == reference[0] == 1 and mine[2].startswith("vex: error: ")
    else:
        assert mine == reference
    assert mine[0] in (0, 1)


@pytest.mark.parametrize("args", [
    (), ("frobnicate",), ("info",), ("strings", "FILE", "-n", "many"),
    ("strings", "FILE", "-n", "0x10"), ("strings", "FILE", "-e", "latin1"),
    ("--color", "pink", "info", "FILE"), ("info", "FILE", "extra"),
    ("hexdump", "FILE", "--offset", "zz"), ("symbols", "FILE", "--grep"),
    ("info", "FILE", "--frobnicate"), ("patch", "FILE"), ("patch",),
    ("patch", "bytes", "FILE", "0x0"), ("patch", "nop", "FILE", "0x0", "two", "-o", "x"),
], ids=_command_id)
def test_usage_errors_exit_with_status_2(c_binary, args):
    args = tuple(str(fixture_path("hello_elf64")) if a == "FILE" else a for a in args)
    code, out, err = run_c(c_binary, *args)
    assert (code, out) == (2, "") and "vex: error: " in err and "usage: " in err
    assert run_python(*args)[0] == 2


# --- string tagging -----------------------------------------------------------------

def _blank_elf(payload: bytes) -> bytes:
    """A 64-byte ELF header with no tables, followed by the payload."""
    header = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1,
                                                             0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    return header + b"\n" + payload


CLASSIFY_CASES = [
    "connect to 192.168.1.10 now", "999.1.1.1", "version 1.2.3", "mail admin@example.org",
    "C:\\Windows\\System32\\cmd.exe", "/etc/passwd", "hello world", "a/b",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "ftp://files.example.net/a.bin", "puts@GLIBC_2.2.5", "__cxa_finalize@GLIBC_2.2.5",
    "name@plt", "a@b", "1.2.3.4", ".1.2.3.4", "1.2.3.4.", "1.2.3.4.5", "01.002.3.4",
    "256.1.1.1", "1234.1.1.1", "x1.2.3.4y", "1.2.3.4:80 and 300.1.1.1", "a.b@c.de", ".@c.de",
    "+-.@x.yz", "me@host.c", "me@host.co1", "me@host.co-x", "me@a.b.c.museum!", "me@-.io",
    "x@y.zz_", "x@y..zz", "http://ab", "http://abc", "xhttp://abc.de", "_http://abc",
    "h://abc", "a1+.-://x/y", "abcdefghijk://xyz", "9ab://xyz", "git+ssh://host/x y",
    "hklm\\x", "HKCU\\Software", "xHKLM\\a", "HKEY_\\a", "HKEY_A_B\\c", "hkey_users\\x",
    "HKU\\", "_HKCR\\x", "HKLM/x", "c:\\x", "ab:\\x", "c:\\ x", "c:\\*", "\\\\srv\\share",
    "\\\\\\srv\\share$", "\\\\srv\\", "\\\\a.b-c$\\d", "/usr", "/usrlocal", "x/usr",
    "./lib/x", "//lib", "a:/tmp", "/tmp/", " /opt", "/a/", "/a", "/a+b/c", "/a b/c",
    "see /dev/null.", "file:///etc/hosts", "\t/home/user\t", "/library/x", "/proc", "/sy",
]


def _near_miss(rng):
    """Text that is, or is nearly, something the tagger recognises."""
    pick = rng.choice
    kind = rng.randrange(6)
    if kind == 0:
        quad = ".".join(str(pick([0, 1, 10, 192, 255, 256, 999, 1234, 7]))
                        for _ in range(pick([3, 4, 4, 4, 5])))
        return pick(["", "x", ".", " ", "v", ":"]) + quad + pick(["", ".", " ", ":80", "x", "/24"])
    if kind == 1:
        local = "".join(pick(["a", "b1", "_", ".", "+", "-"]) for _ in range(rng.randrange(4)))
        domain = ".".join(pick(["ex", "a-b", "c1", "", "museum", "co", "x", "io9", "de"])
                          for _ in range(rng.randrange(1, 4)))
        return pick(["", " ", "<", "-", "."]) + local + "@" + domain + \
            pick(["", ".", "_", " ", ">", "1", "-x"])
    if kind == 2:
        scheme = pick(["http", "https", "ftp", "a", "ab", "x+y.z-", "abcdefghij",
                       "abcdefghijk", "9p", "h_t", "git+ssh"])
        return pick(["", " ", "_", "x", "("]) + scheme + pick(["://", ":/", "//", "://"]) + \
            pick(["a", "ab", "abc", "a b c", "ex.com/p?q=1", 'a"bc', "<x>y", "abc def"])
    if kind == 3:
        return pick(["", " ", "_", "x", "\\"]) + \
            pick(["HKLM", "hkcu", "HKCR", "HKU", "HKEY_", "HKEY_LOCAL_MACHINE", "hkey_users",
                  "HKEY_A1", "HKX"]) + pick(["\\", "/", "", " \\", "\\Software"])
    if kind == 4:
        return pick(["", " ", "x", "1", "\\"]) + \
            pick(["C:\\", "c:/", "C:", "\\\\", "\\\\srv", "\\\\s.r-v$\\", "\\\\srv\\sh",
                  "CD:\\"]) + pick(["", "Windows", "a b", "*", ":x", "dir\\file.txt", " "])
    return pick(["", " ", "x", ".", ":", "/", "=", "("]) + "/" + \
        pick(["etc", "usr", "bin", "a", "a.b+c", "lib64", "", "tmp", "home", "x y", "sys",
              "opt", "root", "dev", "proc", "var", "e"]) + pick(["", "/", "/x", "/x/y.z", " /", "//"])


def test_string_tags_match_python(c_binary, tmp_path):
    rng = random.Random(2024)
    cases = list(CLASSIFY_CASES)
    for _ in range(6000):
        cases.append(" ".join(_near_miss(rng) for _ in range(rng.choice([1, 1, 1, 2, 3]))))
    for _ in range(3000):
        cases.append("".join(rng.choice("ab1.@/\\:_-+ H$") for _ in range(rng.randrange(1, 14))))
    path = tmp_path / "tags.elf"
    path.write_bytes(_blank_elf("\n".join(cases).encode("ascii") + b"\n"))
    rows = assert_same_json(c_binary, "strings", path, "-n", "1", "-e", "ascii")
    tagged = [r for r in rows if r["tags"]]
    assert len(rows) > 8000 and 1000 < len(tagged) < len(rows) - 1000
    for tag in ("url", "ipv4", "email", "registry", "path"):
        assert sum(1 for r in tagged if tag in r["tags"]) > 100, tag
    by_text = {r["text"]: r["tags"] for r in rows}
    assert by_text["mail admin@example.org"] == ["email"]
    assert by_text["connect to 192.168.1.10 now"] == ["ipv4"]
    assert by_text["999.1.1.1"] == [] and by_text["puts@GLIBC_2.2.5"] == []
    assert_same_json(c_binary, "strings", path, "--tagged")


def test_utf16_and_overlapping_string_runs_match_python(c_binary, tmp_path):
    rng = random.Random(7)
    chunks = []
    for _ in range(4000):
        kind = rng.randrange(5)
        text = bytes(rng.choice(b"abcXYZ 019\t~") for _ in range(rng.randrange(1, 9)))
        if kind == 0:
            chunks.append(text)
        elif kind == 1:
            chunks.append(text.decode().encode("utf-16-le"))
        elif kind == 2:
            chunks.append(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4))))
        elif kind == 3:
            chunks.append(b"\0" * rng.randrange(1, 3))
        else:
            chunks.append(text[:1] + b"\0" + text)
    path = tmp_path / "runs.elf"
    path.write_bytes(_blank_elf(b"".join(chunks)))
    for options in (("-n", "1"), ("-n", "2"), ("-n", "3", "-e", "utf16"), ("-e", "ascii"),
                    ("-n", "5"), ("-n", "0"), ("-n", "-3"), ("-n", "100000")):
        assert_same_json(c_binary, "strings", path, *options)


# --- names that are not valid UTF-8 -------------------------------------------------

def _noise(rng, length):
    """Bytes that exercise a UTF-8 decoder: valid sequences, cut-off ones,
    overlong forms, surrogates, stray continuation bytes."""
    samples = [b"a", b"Z", b"_", b" ", b"\t", b"\x1c", b"\x7f", b"\xc2\xa0", b"\xc3\xa9",
               b"\xe2\x82\xac", b"\xe2\x80\x83", b"\xf0\x9f\x98\x80", b"\xe3\x80\x80",
               b"\xc0\xaf", b"\xc1\xbf", b"\xe0\x80\x80", b"\xe0\x9f\xbf", b"\xed\xa0\x80",
               b"\xed\x9f\xbf", b"\xf0\x80\x80\x80", b"\xf0\x8f\xbf\xbf", b"\xf4\x90\x80\x80",
               b"\xf4\x8f\xbf\xbf", b"\xf5\x80", b"\xff", b"\xfe", b"\x80", b"\xbf", b"\xc2",
               b"\xe2", b"\xe2\x82", b"\xf0", b"\xf0\x9f", b"\xf0\x9f\x98", b"\xdf", b"\xef",
               b"\xef\xbf", b"\xef\xbf\xbd", b"\xc2\x85", b"\xe1\x9a\x80", b"\x01", b"\\", b'"']
    out = bytearray()
    while len(out) < length:
        out += rng.choice(samples) if rng.random() < 0.8 else bytes([rng.randrange(1, 256)])
    return bytes(out[:length])


def test_undecodable_names_are_replaced_like_python(c_binary, tmp_path):
    rng = random.Random(99)
    elf = vex.load(fixture_path("hello_elf64"))
    by_name = {s.name: s for s in elf.sections}
    pe_data = fixture_bytes("hello_pe64.exe")
    section_table = struct.unpack_from("<I", pe_data, 0x3C)[0] + 24 + \
        struct.unpack_from("<H", pe_data, struct.unpack_from("<I", pe_data, 0x3C)[0] + 20)[0]
    dll = vex.load(fixture_path("sample.dll"))
    for round_ in range(120):
        # ELF: symbol names (.strtab, .dynstr), section names, the .comment text
        data = bytearray(fixture_bytes("hello_elf64"))
        for name in (".strtab", ".dynstr", ".shstrtab", ".comment", ".interp"):
            s = by_name[name]
            noise = _noise(rng, s.size)
            for i in range(s.size):
                # keep the string boundaries, change the characters
                if data[s.offset + i] != 0 and rng.random() < 0.5:
                    data[s.offset + i] = noise[i]
        path = tmp_path / "names.elf"
        path.write_bytes(data)
        for command in ("info", "sections", "symbols", "imports", "exports"):
            assert_same_json(c_binary, command, path)
        # PE: section names, import and export names
        data = bytearray(pe_data)
        for index in range(3):
            data[section_table + 40 * index:section_table + 40 * index + 8] = \
                _noise(rng, rng.randrange(1, 9)).ljust(8, b"\0")
        path = tmp_path / "names.exe"
        path.write_bytes(data)
        for command in ("info", "sections", "symbols"):
            assert_same_json(c_binary, command, path)
        data = bytearray(fixture_bytes("sample.dll"))
        for s in dll.sections:
            if s.name in (".rdata", ".edata", ".idata"):
                noise = _noise(rng, s.size)
                for i in range(s.size):
                    if 0x20 <= data[s.offset + i] < 0x7F and rng.random() < 0.3:
                        data[s.offset + i] = noise[i]
        path = tmp_path / "names.dll"
        path.write_bytes(data)
        for command in ("info", "imports", "exports", "symbols"):
            assert_same_outcome(c_binary, command, path)


# --- other architectures and byte orders ----------------------------------------------

CROSS_TARGETS = [
    "mips-linux-gnu", "mipsel-linux-gnu", "mips64-linux-gnuabi64", "powerpc-linux-gnu",
    "powerpc64-linux-gnu", "powerpc64le-linux-gnu", "armeb-linux-gnueabi",
    "arm-linux-gnueabi", "aarch64-linux-gnu", "aarch64_be-linux-gnu", "riscv64-linux-gnu",
    "i386-linux-gnu", "x86_64-linux-gnu", "s390x-linux-gnu", "sparc-linux-gnu",
    "sparcv9-linux-gnu", "i686-w64-mingw32", "x86_64-w64-mingw32", "aarch64-w64-mingw32",
    "armv7-w64-mingw32",
]

CROSS_SOURCE = r"""
extern int external_counter;
extern int external_call(const char *text, int n);
int visible_number = 5;
static int hidden_number = 7;
const char *greeting = "hello from the other byte order: http://example.org/be";
const unsigned short wide_text[] = {'W', 'i', 'd', 'e', ' ', 's', 't', 'r', 0};
static int helper(int a) { return a * 3 + hidden_number; }
int exported_add(int a, int b) { return helper(a) + b + visible_number; }
int exported_call(int n) { return external_call(greeting, n) + external_counter; }
void _start(void) { exported_call(exported_add(1, 2)); for (;;) { } }
"""


@pytest.fixture(scope="session")
def cross_binaries(tmp_path_factory):
    """Objects, executables and shared libraries for many CPUs (both byte
    orders, 32 and 64 bit), built with clang and lld when they are installed."""
    clang = shutil.which("clang")
    if not clang:
        return []
    folder = tmp_path_factory.mktemp("cross")
    source = folder / "cross.c"
    source.write_text(CROSS_SOURCE)
    externals = folder / "externals.c"      # PE links need every symbol defined
    externals.write_text("int external_counter = 3;\n"
                         "int external_call(const char *text, int n) { return text[0] + n; }\n")
    built = []
    for target in CROSS_TARGETS:
        base = [clang, f"--target={target}", "-O1", "-g0", "-fno-stack-protector"]
        variants = {
            "o": ["-c"],
            "so": ["-fPIC", "-shared", "-nostdlib", "-fuse-ld=lld"],
            "pie": ["-fPIE", "-pie", "-nostdlib", "-fuse-ld=lld", "-Wl,-z,now",
                    "-Wl,--unresolved-symbols=ignore-all", "-Wl,--build-id"],
            "stripped": ["-fPIC", "-shared", "-nostdlib", "-fuse-ld=lld", "-Wl,-s",
                         "-Wl,--hash-style=sysv", "-Wl,-soname,libcross.so.1",
                         "-Wl,-rpath,/opt/cross/lib"],
        }
        if "mingw" in target:               # Windows programs: PE for four CPUs
            prefix = "_" if target.startswith("i686") else ""
            windows = ["-nostdlib", "-fuse-ld=lld", str(externals)]
            variants = {"o": ["-c"],
                        "exe": windows + [f"-Wl,--entry={prefix}_start"],
                        "dll": windows + ["-shared", f"-Wl,--entry={prefix}exported_add"]}
        for kind, flags in variants.items():
            out = folder / f"{target}.{kind}"
            proc = subprocess.run(base + flags + ["-o", str(out), str(source)],
                                  capture_output=True)
            if proc.returncode == 0 and out.is_file():
                built.append(out)
    return built


CROSS_COMMANDS = [("info",), ("sections",), ("imports",), ("exports",), ("symbols",),
                  ("strings",), ("strings", "--tagged"), ("hexdump",)]
CROSS_CODE_COMMANDS = [("functions",), ("disasm",), ("disasm", "exported_call"),
                       ("disasm", "_start", "-n", "12"), ("xrefs", "exported_add"),
                       ("xrefs", "external_call"), ("xrefs", "--string", "hello from"),
                       ("xrefs", "greeting"), ("hexdump", "visible_number", "-n", "8"),
                       ("report",)]


def test_other_architectures_and_byte_orders_match_python(c_binary, cross_binaries):
    if not cross_binaries:
        pytest.skip("clang is not installed")
    seen = set()
    for path in cross_binaries:
        try:
            b = vex.load(path)
        except vex.VexError:
            continue                            # e.g. a COFF object: not ELF/PE
        seen.add((b.format, b.bits, b.endian))
        for command in CROSS_COMMANDS:
            assert_same_json(c_binary, command[0], path, *command[1:])
        for command in CROSS_CODE_COMMANDS:     # may fail: "no disassembler for ... 's390x'"
            assert_same_outcome(c_binary, command[0], path, *command[1:])
        assert json.loads(run_c(c_binary, "--json", "segments", path)[1]) == views.segments(b)
        assert json.loads(run_c(c_binary, "--json", "layout", path)[1]) == views.layout(b)
    assert {("ELF", 32, "big"), ("ELF", 64, "big"), ("ELF", 32, "little"),
            ("ELF", 64, "little")} <= seen
    if shutil.which("ld.lld"):
        assert {("PE", 32, "little"), ("PE", 64, "little")} <= seen


# --- hostile input ------------------------------------------------------------------
# A reverse-engineering tool is pointed at broken and malicious files on
# purpose. The sanitizer build must survive every one of them (exit status 0
# or 1: a sanitizer report, a crash or a hang is a failure) and must still
# agree with the Python parser about what the damaged file contains.

from test_robustness import mutations  # noqa: E402  (the same mutation strategy)

HOSTILE_VIEWS = {
    "info": lambda b: strip_path(views.info(b)),
    "sections": views.sections,
    "segments": views.segments,
    "imports": views.imports,
    "exports": views.exports,
    "symbols": views.symbols,
    "strings": views.strings,
    "layout": views.layout,
}


# The code-analysis commands for the hostile-input runs.
HOSTILE_CODE_COMMANDS = {"functions": ("functions",), "disasm": ("disasm", "-n", "8")}


def _code_reference(blob):
    """functions and the first instructions as Python sees them: the data, the
    error message, or None where the reference itself breaks down."""
    from vex.analysis import Analysis
    b = vex.load_bytes(blob)
    try:
        a = Analysis(b)
    except vex.VexError as exc:
        return {name: str(exc) for name in HOSTILE_CODE_COMMANDS}
    out = {}
    for name, view in (("functions", lambda: views.functions(a)),
                       ("disasm", lambda: views.disassembly(a, None, 8))):
        try:
            out[name] = json.loads(json.dumps(view()))
        except vex.VexError as exc:
            out[name] = str(exc)
        except Exception:               # noqa: BLE001 - a crash of the reference
            out[name] = None
    return out


def _reference(blob):
    """What the Python implementation makes of the bytes: {command: data}, or
    the error message when it refuses to load them."""
    try:
        b = vex.load_bytes(blob)
    except vex.VexError as exc:
        return str(exc)
    return {command: json.loads(json.dumps(view(b))) for command, view in HOSTILE_VIEWS.items()}


def check_hostile(asan_binary, folder, blobs, code=True):
    """Run every command of the sanitizer build on every blob (in parallel)
    and compare with Python; `code` includes the disassembly commands."""
    paths = []
    for index, blob in enumerate(blobs):
        path = folder / f"{index:04d}.bin"
        path.write_bytes(blob)
        paths.append(path)
    commands = {name: (name,) for name in HOSTILE_VIEWS}
    if code:
        commands.update(HOSTILE_CODE_COMMANDS)

    def run_all(path):
        return {name: run_c(asan_binary, "--json", args[0], path, *args[1:], timeout=60)
                for name, args in commands.items()}

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 2) as pool:
        outcomes = list(pool.map(run_all, paths))
    loaded = 0
    for path, blob, outcome in zip(paths, blobs, outcomes):
        expected = _reference(blob)
        if code and not isinstance(expected, str):
            expected.update(_code_reference(blob))
        for name, (status, out, err) in outcome.items():
            where = f"{name} {path.name}"
            assert status in (0, 1), (where, status, err[-2000:])
            wanted = expected if isinstance(expected, str) else expected[name]
            if isinstance(wanted, str):
                assert (status, out, err) == (1, "", f"vex: error: {wanted}\n"), where
            elif wanted is not None:
                assert status == 0 and err == "", (where, err)
                assert strip_path(json.loads(out)) == wanted, where
        loaded += not isinstance(expected, str)
    return loaded


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_corrupted_copies_are_handled_like_python(asan_binary, tmp_path, name):
    data = fixture_bytes(name)
    blobs = list(mutations(data, seed=sum(name.encode()), count=250))
    blobs += [data[:cut] for cut in range(0, min(len(data), 0x480), 23)]
    loaded = check_hostile(asan_binary, tmp_path, blobs)
    assert loaded > len(blobs) // 2        # most mutations still load: the views ran


def test_random_bytes_with_a_valid_signature_are_handled_like_python(asan_binary, tmp_path):
    rng = random.Random(7)
    blobs = []
    for magic in (b"\x7fELF\x02\x01\x01", b"\x7fELF\x01\x01\x01", b"\x7fELF\x02\x02\x01",
                  b"\x7fELF\x01\x02\x01", b"MZ"):
        for _ in range(60):
            blobs.append(magic + bytes(rng.randrange(256) for _ in range(rng.randrange(600))))
    # MZ files whose e_lfanew points at a plausible PE header made of noise
    pe = fixture_bytes("hello_pe64.exe")
    start = struct.unpack_from("<I", pe, 0x3C)[0]
    for _ in range(120):
        noise = bytes(rng.randrange(256) for _ in range(rng.randrange(600)))
        blobs.append(pe[:start + 26] + noise)
        blobs.append(pe[:start + 24] + rng.choice([b"\x0b\x01", b"\x0b\x02"]) + noise)
    check_hostile(asan_binary, tmp_path, blobs)


def test_huge_counts_do_not_hang_or_exhaust_memory(asan_binary, tmp_path):
    blobs = []
    elf = bytearray(fixture_bytes("hello_elf64"))
    elf[0x3C:0x3E] = b"\xff\xff"                    # e_shnum
    blobs.append(bytes(elf))
    elf = bytearray(fixture_bytes("hello_elf64"))
    elf[0x38:0x3A] = b"\xff\xff"                    # e_phnum
    blobs.append(bytes(elf))
    pe = bytearray(fixture_bytes("hello_pe64.exe"))
    pe[0x7E:0x80] = b"\xff\xff"                     # NumberOfSections
    blobs.append(bytes(pe))
    for name in ("hello_elf64", "libsample.so", "hello_pe64.exe", "sample.dll"):
        data = fixture_bytes(name)
        for pos in range(0, min(len(data), 0x400) - 8, 4):
            for filler in (b"\xff" * 8, b"\xff\xff\xff\x7f" * 2):
                blobs.append(data[:pos] + filler + data[pos + 8:])
    check_hostile(asan_binary, tmp_path, blobs)


def test_headerless_and_big_endian_binaries_survive_corruption(asan_binary, cross_binaries,
                                                               tmp_path):
    """The same treatment for other CPUs and byte orders, and for files
    without section headers (stripped the way packers and malware do it)."""
    if not cross_binaries:
        pytest.skip("clang is not installed")
    rng = random.Random(11)
    blobs = []
    for path in cross_binaries:
        data = path.read_bytes()
        if data[:2] == b"MZ":                       # Windows programs for four CPUs
            blobs += list(mutations(data, seed=rng.randrange(1 << 30), count=10))
        if data[:4] != b"\x7fELF":
            continue
        blobs.append(data)
        little = "<" if data[5] == 1 else ">"
        headerless = bytearray(data)
        if data[4] == 2:                            # 64-bit: e_shoff, e_shnum, e_shstrndx
            struct.pack_into(little + "Q", headerless, 0x28, 0)
            struct.pack_into(little + "HH", headerless, 0x3C, 0, 0)
        else:
            struct.pack_into(little + "I", headerless, 0x20, 0)
            struct.pack_into(little + "HH", headerless, 0x30, 0, 0)
        blobs.append(bytes(headerless))
        blobs += list(mutations(bytes(headerless), seed=rng.randrange(1 << 30), count=6))
        blobs += list(mutations(data, seed=rng.randrange(1 << 30), count=6))
    check_hostile(asan_binary, tmp_path, blobs)


# --- patching -------------------------------------------------------------------------
# Both programs get the same arguments in two folders with the same layout;
# afterwards the folders must hold the same files with the same bytes.

def patch_both(c_binary, tmp_path, monkeypatch, source, args, prepare=None, json_mode=True):
    """Run `patch ARGS` with each implementation on its own copy of `source`
    (called "prog"). Returns (exit status, parsed output, files) of the C run
    after checking that Python did exactly the same."""
    outcomes = []
    for who in ("c", "python"):
        folder = tmp_path / who
        folder.mkdir()
        target = folder / "prog"
        if isinstance(source, bytes):
            target.write_bytes(source)
        else:
            shutil.copy(fixture_path(source), target)
        if prepare:
            prepare(folder)
        full = (["--json"] if json_mode else []) + ["patch", *args]
        if who == "c":
            proc = subprocess.run([str(c_binary), *full], cwd=folder, capture_output=True,
                                  timeout=60)
            code, out, err = proc.returncode, proc.stdout.decode(), proc.stderr.decode()
            if NO_DISASSEMBLER in err:
                pytest.skip("the C program was built without Capstone")
        else:
            monkeypatch.chdir(folder)
            code, out, err = run_python(*full)
            monkeypatch.undo()
        data = out
        if json_mode and code == 0:
            data = json.loads(out)
            data["out"] = os.path.relpath(data["out"], folder)
        files = {p.name: (p.read_bytes(), p.stat().st_mode & 0o7777)
                 for p in folder.iterdir() if p.is_file()}
        outcomes.append((code, data, files, err))
    mine, reference = outcomes
    assert mine == reference, args
    shutil.rmtree(tmp_path / "c")
    shutil.rmtree(tmp_path / "python")
    return mine[0], mine[1], mine[2]


PE64 = "hello_pe64.exe"


def test_patch_string_writes_a_modified_copy(c_binary, tmp_path, monkeypatch):
    code, data, files = patch_both(c_binary, tmp_path, monkeypatch, PE64,
                                   ("string", "prog", "Hello from", "HELLO FROM", "-o", "out.exe"))
    assert code == 0 and data["message"] == "Saved out.exe" and data["out"] == "out.exe"
    assert files["out.exe"][0][0x630:0x63A] == b"HELLO FROM"
    assert files["prog"][0] == fixture_bytes(PE64) and set(files) == {"prog", "out.exe"}
    assert data["patches"] == [{"out": "out.exe", "offset": 0x630, "address": "0x140002030",
                                "old": "48 65 6c 6c 6f 20 66 72 6f 6d",
                                "new": "48 45 4c 4c 4f 20 46 52 4f 4d"}]


@pytest.mark.parametrize("source, args", [
    (PE64, ("string", "prog", "Hello from", "Bye", "-o", "out.exe")),                # padded
    (PE64, ("string", "prog", "Wide fixture", "WIDE", "-e", "utf16", "-o", "out.exe")),
    (PE64, ("string", "prog", "Wide", "Widé", "--encoding", "utf16", "-o", "out.exe")),
    (PE64, ("string", "prog", "e", "E", "-o", "out.exe")),                          # many hits
    (PE64, ("string", "prog", "ll", "LL", "-o", "out.exe")),
    ("hello_elf64", ("string", "prog", "fixture", "FIXTURE", "-o", "out")),
    ("hello_elf64", ("string", "prog", "GCC", "gcc", "-o", "out")),                  # no address
    ("libsample.so", ("string", "prog", "sample", "", "--output", "out")),
    (b"plain notes, not a program\n", ("string", "prog", "notes", "NOTES", "-o", "out")),
    (b"aaaaaaa", ("string", "prog", "aa", "b", "-o", "out")),                       # overlaps
    (PE64, ("bytes", "prog", "0x140002030", "41 42", "-o", "out.exe")),
    (PE64, ("bytes", "prog", "0x630", "0x41,0x42", "--offset", "-o", "out.exe")),
    (PE64, ("bytes", "prog", "1584", "4a4B\t4c\n4D", "--offset", "-o", "out.exe")),
    (PE64, ("bytes", "prog", "0", "00", "--offset", "-o", "out.exe")),
    (PE64, ("bytes", "prog", "0xbff", "ff", "--offset", "-o", "out.exe")),         # last byte
    (PE64, ("nop", "prog", "0x140001020", "2", "-o", "out.exe")),
    (PE64, ("nop", "prog", "0x420", "0x10", "--offset", "-o", "out.exe")),
    ("hello_pe32.exe", ("nop", "prog", "0x401050", "3", "-o", "out.exe")),
    ("bare_arm64", ("nop", "prog", "0x2101a0", "8", "-o", "out")),
    ("bare_elf32", ("nop", "prog", "0x401120", "1", "-o", "out")),
    ("hello_elf64", ("bytes", "prog", "0x10e0", "c3", "-o", "out")),
], ids=lambda v: " ".join(v) if isinstance(v, tuple) else None)
def test_patches_match_python(c_binary, tmp_path, monkeypatch, source, args):
    code, data, files = patch_both(c_binary, tmp_path, monkeypatch, source, args)
    assert code == 0 and len(data["patches"]) >= 1
    out = files[args[-1]][0]
    assert len(out) == len(files["prog"][0]) and out != files["prog"][0]
    assert set(files) == {"prog", args[-1]}                 # no temp files left behind


def test_patch_accepts_names(c_binary, tmp_path, monkeypatch):
    code, out, files = patch_both(c_binary, tmp_path, monkeypatch, PE64,
                                  ("nop", "prog", "print", "2", "-o", "out.exe"), json_mode=False)
    assert code == 0 and "0x140001020: 56 57 -> 90 90" in out
    assert files["out.exe"][0][0x420:0x422] == b"\x90\x90"
    for source, args in [
        ("hello_elf64", ("bytes", "prog", "main", "c3", "-o", "out")),
        ("hello_elf64", ("nop", "prog", "add_numbers", "8", "-o", "out")),
        ("hello_elf64", ("bytes", "prog", "entry", "90", "--in-place")),
        (PE64, ("bytes", "prog", "KERNEL32.dll!WriteFile", "00", "-o", "out")),
    ]:
        assert patch_both(c_binary, tmp_path, monkeypatch, source, args)[0] == 0
    for source, args in [
        ("hello_elf64", ("bytes", "prog", "no_such_name", "c3", "-o", "out")),
        ("hello_elf64", ("bytes", "prog", "puts", "c3 c3 c3 c3 c3 c3 c3 c3 c3", "-o", "out")),
    ]:
        code, _, files = patch_both(c_binary, tmp_path, monkeypatch, source, args)
        assert set(files) == {"prog"} or code == 0


def test_patch_text_output_matches_python(c_binary, tmp_path, monkeypatch):
    code, out, _ = patch_both(c_binary, tmp_path, monkeypatch, PE64,
                              ("nop", "prog", "0x140001020", "2", "-o", "out.exe"),
                              json_mode=False)
    assert code == 0 and out == "0x140001020: 56 57 -> 90 90\nSaved out.exe\n"
    code, out, _ = patch_both(c_binary, tmp_path, monkeypatch, b"some notes",
                              ("string", "prog", "notes", "N", "-o", "o"), json_mode=False)
    assert out == "file offset 0x5: 6e 6f 74 65 73 -> 4e 00 00 00 00\nSaved o\n"


@pytest.mark.parametrize("source, args", [
    (PE64, ("bytes", "prog", "0x140002030", "41")),                      # no destination
    (PE64, ("bytes", "prog", "0x140002030", "41", "-o", "out", "--in-place")),
    (PE64, ("bytes", "prog", "0x140002030", "41", "-o", "")),
    (PE64, ("bytes", "prog", "0x140002030", "zz", "-o", "out")),
    (PE64, ("bytes", "prog", "0x140002030", "414", "-o", "out")),
    (PE64, ("bytes", "prog", "0x140002030", "4 1", "-o", "out")),
    (PE64, ("bytes", "prog", "0x140002030", "0X41", "-o", "out")),
    (PE64, ("bytes", "prog", "0x140002030", "", "-o", "out")),
    (PE64, ("bytes", "prog", "0x140002030", "0x", "-o", "out")),
    (PE64, ("bytes", "prog", "0x150000000", "41", "-o", "out")),         # unmapped
    (PE64, ("bytes", "prog", "0x1400021ff", "41 42", "-o", "out")),      # crosses the end
    (PE64, ("bytes", "prog", "-1", "41", "-o", "out")),
    (PE64, ("bytes", "prog", "0xc00", "41", "--offset", "-o", "out")),   # one past the end
    (PE64, ("bytes", "prog", "0xbff", "41 42", "--offset", "-o", "out")),
    (PE64, ("bytes", "prog", "-1", "41", "--offset", "-o", "out")),
    (PE64, ("bytes", "prog", "0xffffffffffffffffffffffff", "41", "--offset", "-o", "out")),
    (PE64, ("bytes", "prog", "0xffffffffffffffffffffffff", "41", "-o", "out")),
    (PE64, ("nop", "prog", "0x140001020", "0", "-o", "out")),
    (PE64, ("nop", "prog", "0x140001020", "-4", "-o", "out")),
    (PE64, ("nop", "prog", "0x140001020", "0x100000", "-o", "out")),
    ("bare_arm64", ("nop", "prog", "0x2101a0", "6", "-o", "out")),       # partial instruction
    ("hello_elf64", ("nop", "prog", "0x4010", "4", "-o", "out")),        # .bss
    (PE64, ("string", "prog", "Hello", "Hello, hello", "-o", "out")),    # longer
    (PE64, ("string", "prog", "", "x", "-o", "out")),
    (PE64, ("string", "prog", "no such text", "x", "-o", "out")),
    (PE64, ("string", "prog", "it's \"quoted\"\n\\", "x", "-o", "out")),
    (PE64, ("string", "prog", "can't", "x", "-o", "out")),
    (PE64, ("string", "prog", "Héllo", "x", "-o", "out")),          # not ASCII
    (PE64, ("string", "prog", "Hello", "€€ \U0001f600", "-o", "out")),
    (PE64, ("string", "prog", "Héllo 世界", "x", "-e", "utf16", "-o", "out")),
    (PE64, ("string", "prog", "Hello", "x", "-o", "missing/folder/out")),
    (PE64, ("bytes", "prog", "0x140002030", "41", "-o", "missing/out")),
    (PE64, ("string", "nothing_here", "a", "b", "-o", "out")),
    (PE64, ("bytes", "nothing_here", "0", "41", "--offset", "-o", "out")),
    (b"plain notes", ("bytes", "prog", "0", "41", "--offset", "-o", "out")),   # not ELF/PE
    (b"plain notes", ("nop", "prog", "0", "1", "-o", "out")),
], ids=lambda v: " ".join(v) if isinstance(v, tuple) else None)
def test_refused_patches_fail_like_python_and_write_nothing(c_binary, tmp_path, monkeypatch,
                                                            source, args):
    code, out, files = patch_both(c_binary, tmp_path, monkeypatch, source, args)
    assert code == 1 and out == "" and set(files) == {"prog"}


def test_patch_in_place_keeps_one_backup(c_binary, tmp_path, monkeypatch):
    original = fixture_bytes(PE64)
    code, _, files = patch_both(c_binary, tmp_path, monkeypatch, PE64,
                                ("bytes", "prog", "0x140002030", "41", "--in-place"))
    assert code == 0 and set(files) == {"prog", "prog.bak"}
    assert files["prog"][0][0x630:0x631] == b"A" and files["prog.bak"][0] == original

    # A second patch must not overwrite the pristine backup.
    def already_patched(folder):
        (folder / "prog.bak").write_bytes(b"the only pristine copy")
    _, _, files = patch_both(c_binary, tmp_path, monkeypatch, PE64,
                             ("string", "prog", "Hello", "HELLO", "--in-place"),
                             prepare=already_patched)
    assert files["prog.bak"][0] == b"the only pristine copy"
    assert files["prog"][0][0x630:0x635] == b"HELLO"

    # Naming the input as the output is the same thing, however it is spelled.
    _, _, files = patch_both(c_binary, tmp_path, monkeypatch, PE64,
                             ("nop", "prog", "0x140001020", "2", "-o", "./prog"))
    assert files["prog.bak"][0] == original and files["prog"][0][0x420:0x422] == b"\x90\x90"

    def linked(folder):
        os.symlink("prog", folder / "alias")
    _, _, files = patch_both(c_binary, tmp_path, monkeypatch, PE64,
                             ("bytes", "prog", "0x630", "58", "--offset", "-o", "alias"),
                             prepare=linked)
    assert files["prog.bak"][0] == original and files["prog"][0][0x630:0x631] == b"X"
    assert files["alias"][0] == files["prog"][0]


def test_patch_output_keeps_the_permission_bits(c_binary, tmp_path, monkeypatch):
    for mode in (0o755, 0o640, 0o600):
        def set_mode(folder, mode=mode):
            os.chmod(folder / "prog", mode)
            (folder / "out").write_bytes(b"an older output file")
        _, _, files = patch_both(c_binary, tmp_path, monkeypatch, PE64,
                                 ("bytes", "prog", "0x630", "58", "--offset", "-o", "out"),
                                 prepare=set_mode)
        assert files["out"][1] == mode and len(files["out"][0]) == len(fixture_bytes(PE64))


# --- builds ---------------------------------------------------------------------------

def test_build_without_capstone_reports_the_missing_disassembler(c_binary, tmp_path):
    """CAPSTONE=0: every command exists; the code-analysis ones fail cleanly."""
    build = tmp_path / "plain"
    proc = subprocess.run([MAKE, "-C", str(C_DIR), "CAPSTONE=0", f"BUILD={build}"],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr[-3000:]
    binary = build / "vex"
    path = fixture_path("hello_elf64")
    for args in (("functions", path), ("disasm", path), ("xrefs", path, "main"),
                 ("hexdump", path, "main"), ("patch", "nop", path, "main", "1", "-o", "x")):
        assert run_c(binary, *args) == (1, "", "vex: error: this build has no disassembler\n")
    assert run_c(binary, "--json", "info", path) == run_c(c_binary, "--json", "info", path)
    report = json.loads(run_c(binary, "--json", "report", path)[1])
    assert report["functions"] is None
    assert report["functions_error"] == "this build has no disassembler"
    full = json.loads(run_c(c_binary, "--json", "report", path)[1])
    assert {k: v for k, v in report.items() if not k.startswith("functions")} == \
        {k: v for k, v in full.items() if k != "functions"}
    assert "(unavailable: this build has no disassembler)" in run_c(binary, "report", path)[1]


@pytest.mark.skipif(not MINGW, reason="MinGW-w64 is not installed")
def test_windows_build_is_a_standalone_64_bit_console_program(c_binary):
    proc = subprocess.run([MAKE, "-C", str(C_DIR), "windows"], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert "warning" not in proc.stdout + proc.stderr
    exe = C_DIR / "build" / "vex.exe"
    b = vex.load(exe)
    assert (b.format, b.bits, b.arch, b.kind) == ("PE", 64, "x86_64", "executable")
    assert b.metadata["subsystem"] == "console"
    # static: nothing but DLLs that are part of Windows itself
    assert {lib.lower() for lib in b.libraries} <= {
        "kernel32.dll", "msvcrt.dll", "shell32.dll", "ws2_32.dll"}
    assert not b.symbols                                         # stripped
    from vex import resources                                    # the file icon is embedded
    assert any(r.type == "GROUP_ICON" for r in resources.list_resources(b))
    imported = {i.name for i in b.imports}
    assert {"GetConsoleProcessList", "SetConsoleMode", "MoveFileExW",
            "CommandLineToArgvW"} <= imported
    # ... and the C program reads its own Windows build exactly like Python does
    for command in (("info",), ("sections",), ("imports",), ("exports",), ("symbols",),
                    ("strings", "--tagged"), ("disasm", "-n", "64"), ("hexdump",)):
        assert_same_json(c_binary, command[0], exe, *command[1:])
    assert json.loads(run_c(c_binary, "--json", "layout", exe)[1]) == views.layout(b)
