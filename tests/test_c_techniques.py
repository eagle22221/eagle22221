"""The native C `techniques` command against the Python implementation.

For every fixture the C program's `--json techniques` output must equal the
Python CLI's, parsed. The two evasion fixtures carry real signals; the PE one
exercises every import- and section-based category at once.
"""
import contextlib
import io
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from vex.cli import main as python_main
from conftest import FIXTURES, fixture_path

C_DIR = Path(__file__).resolve().parent.parent / "c"
MAKE = shutil.which("make")
COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")

pytestmark = pytest.mark.skipif(
    not (MAKE and COMPILER and C_DIR.is_dir()),
    reason="the C port needs make and a C compiler")

FIXTURE_NAMES = sorted(p.name for p in FIXTURES.iterdir() if p.is_file())


@pytest.fixture(scope="session")
def c_binary():
    proc = subprocess.run([MAKE, "-C", str(C_DIR), "all"], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail(f"make all failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-3000:]}")
    return C_DIR / "build" / "vex"


def c_techniques(c_binary, path):
    proc = subprocess.run([str(c_binary), "--json", "techniques", str(path)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def python_techniques(path):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = python_main(["--json", "techniques", str(path)])
    assert code == 0
    return json.loads(out.getvalue())


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_techniques_match_python(c_binary, name):
    path = fixture_path(name)
    assert c_techniques(c_binary, path) == python_techniques(path), name


def test_evasion_pe_has_every_import_and_section_category(c_binary):
    path = fixture_path("evasion_pe64.exe")
    mine = c_techniques(c_binary, path)
    reference = python_techniques(path)
    assert mine == reference
    categories = {t["category"] for t in mine}
    assert {"packing", "anti-debug", "anti-vm", "injection", "hooking"} <= categories


def test_evasion_elf_matches_python(c_binary):
    path = fixture_path("evasion_elf64")
    assert c_techniques(c_binary, path) == python_techniques(path)
