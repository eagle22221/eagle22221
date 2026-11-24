"""Static technique detection: the 'dissect cheats and anti-cheat' view.

Expected values are derived by hand from the fixtures' imports, section names,
section entropy and strings (see `vex imports/sections/strings` on each),
never from the detector itself. The detector only identifies and explains
techniques a binary uses; it does nothing to defeat them.
"""
import pytest

import vex
from vex import techniques
from conftest import fixture_bytes


def by_category(found):
    return {t.category: t for t in found}


# --- a binary built to exercise every detector -----------------------------

def test_windows_evasion_fixture_reports_every_category(load_fixture):
    found = by_category(techniques.analyze(load_fixture("evasion_pe64.exe")))
    assert set(found) == {"packing", "anti-debug", "anti-vm", "injection", "hooking"}


def test_packer_section_names_the_packer_and_notes_entropy(load_fixture):
    t = by_category(techniques.analyze(load_fixture("evasion_pe64.exe")))["packing"]
    assert t.confidence == "high"
    assert 'section "UPX1" (UPX)' in t.evidence
    assert any("entropy 7.5" in e for e in t.evidence)
    assert "unpack" in t.explanation.lower()


def test_anti_debug_lists_the_imports_that_prove_it(load_fixture):
    t = by_category(techniques.analyze(load_fixture("evasion_pe64.exe")))["anti-debug"]
    assert t.confidence == "high"
    assert t.evidence == [
        "imports CheckRemoteDebuggerPresent",
        "imports GetTickCount",
        "imports IsDebuggerPresent",
        "imports NtQueryInformationProcess",
        "imports OutputDebugStringA",
    ]


def test_injection_needs_the_core_api_combination(load_fixture):
    t = by_category(techniques.analyze(load_fixture("evasion_pe64.exe")))["injection"]
    assert t.confidence == "high"
    assert t.evidence == [
        "imports CreateRemoteThread",
        "imports VirtualAllocEx",
        "imports WriteProcessMemory",
    ]


def test_hooking_from_set_windows_hook(load_fixture):
    t = by_category(techniques.analyze(load_fixture("evasion_pe64.exe")))["hooking"]
    assert t.confidence == "high" and t.evidence == ["imports SetWindowsHookExW"]


def test_anti_vm_collects_distinct_vendor_markers(load_fixture):
    t = by_category(techniques.analyze(load_fixture("evasion_pe64.exe")))["anti-vm"]
    assert t.confidence == "high"          # VirtualBox, VMware, QEMU and Sandboxie
    assert 'string "VBoxGuest"' in t.evidence
    assert 'string "vmtoolsd"' in t.evidence
    assert 'string "SbieDll.dll"' in t.evidence


# --- the Linux fixture -----------------------------------------------------

def test_linux_ptrace_is_anti_debug(load_fixture):
    found = by_category(techniques.analyze(load_fixture("evasion_elf64")))
    assert set(found) == {"anti-debug", "anti-vm"}
    assert found["anti-debug"].confidence == "high"
    assert found["anti-debug"].evidence == ["imports ptrace"]
    assert "ptrace" in found["anti-debug"].explanation or "debug" in found["anti-debug"].explanation.lower()


def test_one_virtual_machine_family_is_only_medium_confidence(load_fixture):
    t = by_category(techniques.analyze(load_fixture("evasion_elf64")))["anti-vm"]
    assert t.confidence == "medium"        # only the VirtualBox family appears
    assert t.evidence == ['string "VBoxGuest"', 'string "vboxservice"']


# --- ordinary programs must stay quiet -------------------------------------

@pytest.mark.parametrize("name", ["hello_pe64.exe", "hello_elf64", "sample.dll",
                                  "hello_pe32.exe", "bare_elf32", "libsample.so"])
def test_ordinary_binaries_report_nothing(load_fixture, name):
    assert techniques.analyze(load_fixture(name)) == []


def test_results_are_ordered_by_category_then_confidence(load_fixture):
    found = techniques.analyze(load_fixture("evasion_pe64.exe"))
    order = [t.category for t in found]
    assert order == sorted(order)          # stable, category-sorted output


# --- the building blocks ---------------------------------------------------

def test_executable_high_entropy_section_without_a_packer_name_is_packing():
    # Rename the packer section so only the executable-entropy signal remains.
    data = bytearray(fixture_bytes("evasion_pe64.exe"))
    pos = data.find(b"UPX1")
    data[pos:pos + 4] = b".blob"[:4]
    t = by_category(techniques.analyze(vex.load_bytes(bytes(data))))["packing"]
    assert t.confidence == "high"
    assert any("entropy" in e and "executable" in e for e in t.evidence)
    assert not any("(UPX)" in e for e in t.evidence)


def test_device_io_control_in_a_user_program_flags_a_driver_channel():
    found = techniques.analyze(_pe_importing("DeviceIoControl"))
    t = by_category(found)["driver"]
    assert t.confidence == "medium" and t.evidence == ["imports DeviceIoControl"]


def test_native_subsystem_is_a_kernel_driver(load_fixture):
    # Flip the subsystem of a normal PE to native (1); kind becomes "driver".
    data = bytearray(fixture_bytes("hello_pe64.exe"))
    data[0xD4] = 1                          # Subsystem field in the optional header
    b = vex.load_bytes(bytes(data))
    assert b.kind == "driver"
    t = by_category(techniques.analyze(b))["driver"]
    assert t.confidence == "high"
    assert any("native" in e.lower() or "driver" in e.lower() for e in t.evidence)


def test_appended_data_is_reported_as_overlay():
    b = vex.load_bytes(fixture_bytes("hello_pe64.exe") + b"PAYLOAD" * 100)
    t = by_category(techniques.analyze(b))["overlay"]
    assert t.confidence == "medium"
    assert any("700" in e or "appended" in e.lower() for e in t.evidence)


def _pe_importing(symbol):
    """A copy of evasion_pe64 with one (long) import name overwritten in place,
    so the import table lists `symbol`. Used to add a single flagged import."""
    data = bytearray(fixture_bytes("evasion_pe64.exe"))
    old = b"CheckRemoteDebuggerPresent"
    assert len(symbol) <= len(old)
    pos = data.find(old)
    data[pos:pos + len(old)] = symbol.encode().ljust(len(old), b"\0")
    return vex.load_bytes(bytes(data))


def test_markers_in_a_packed_section_are_ignored_but_not_in_normal_data():
    base = fixture_bytes("evasion_pe64.exe")   # UPX1 raw at 0xc00, .rdata raw at 0x600
    # A marker hidden in the high-entropy UPX1 section must not count.
    hidden = bytearray(base)
    hidden[0xC00:0xC0A] = b"vboxtray\x00\x00"
    ev = by_category(techniques.analyze(vex.load_bytes(bytes(hidden))))["anti-vm"].evidence
    assert 'string "vboxtray"' not in ev
    # The same marker in ordinary data is reported.
    shown = bytearray(base)
    shown[0xB00:0xB0A] = b"vboxtray\x00\x00"
    ev = by_category(techniques.analyze(vex.load_bytes(bytes(shown))))["anti-vm"].evidence
    assert 'string "vboxtray"' in ev
