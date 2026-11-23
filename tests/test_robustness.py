"""Hostile-input checks: a reverse-engineering tool is pointed at broken and
malicious files on purpose. Whatever the bytes, loading must either succeed
or raise a BinspectError, and the views built on a loaded file must not crash."""
import random

import pytest

import binspect
from binspect import strings, views
from binspect.analysis import Analysis
from conftest import fixture_bytes

FIXTURES = ["hello_elf64", "hello_elf64_stripped", "bare_elf32", "bare_arm64",
            "libsample.so", "hello_pe64.exe", "hello_pe32.exe", "sample.dll",
            "netprobe.exe"]


def exercise(data: bytes) -> None:
    """Everything a user can trigger for one file."""
    try:
        b = binspect.load_bytes(data)
    except binspect.BinspectError:
        return
    views.info(b)
    views.sections(b)
    views.segments(b)
    views.imports(b)
    views.exports(b)
    views.symbols(b)
    views.layout(b)
    strings.extract(b)
    views.hexdump(b, offset=0, length=64)
    try:
        a = Analysis(b)
        views.functions(a)
        views.disassembly(a, None, 8)
        if b.entry is not None:
            a.xrefs([b.entry])
    except binspect.BinspectError:
        pass


def mutations(data: bytes, seed: int, count: int):
    rng = random.Random(seed)
    header = min(len(data), 0x400)
    for _ in range(count):
        buf = bytearray(data)
        kind = rng.randrange(4)
        if kind == 0:       # flip a few bytes in the headers, where structure lives
            for _ in range(rng.randrange(1, 6)):
                buf[rng.randrange(header)] = rng.randrange(256)
        elif kind == 1:     # flip bytes anywhere
            for _ in range(rng.randrange(1, 12)):
                buf[rng.randrange(len(buf))] = rng.randrange(256)
        elif kind == 2:     # overwrite a 4-byte field with an extreme value
            pos = rng.randrange(max(1, header - 4))
            buf[pos:pos + 4] = rng.choice([b"\xff\xff\xff\xff", b"\x00\x00\x00\x80",
                                           b"\xff\xff\xff\x7f", b"\x00\x00\x00\x00"])
        else:               # truncate
            del buf[rng.randrange(1, len(buf)):]
        yield bytes(buf)


@pytest.mark.parametrize("name", FIXTURES)
def test_corrupted_copies_never_crash(name):
    data = fixture_bytes(name)
    for mutated in mutations(data, seed=sum(name.encode()), count=250):
        exercise(mutated)


@pytest.mark.parametrize("name", FIXTURES)
def test_every_truncation_point_in_the_headers_is_handled(name):
    data = fixture_bytes(name)
    for cut in range(0, min(len(data), 0x480), 3):
        exercise(data[:cut])


def test_random_bytes_with_a_valid_signature_are_handled():
    rng = random.Random(7)
    for magic in (b"\x7fELF\x02\x01\x01", b"\x7fELF\x01\x01\x01", b"\x7fELF\x02\x02\x01", b"MZ"):
        for _ in range(60):
            exercise(magic + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 600))))


def test_huge_counts_do_not_hang_or_exhaust_memory():
    # e_shnum = 0xffff with a section table that claims to fit: must finish fast.
    data = bytearray(fixture_bytes("hello_elf64"))
    data[0x3C:0x3E] = b"\xff\xff"
    exercise(bytes(data))
    # PE claiming 65535 sections
    pe = bytearray(fixture_bytes("hello_pe64.exe"))
    pe[0x7E:0x80] = b"\xff\xff"
    exercise(bytes(pe))
