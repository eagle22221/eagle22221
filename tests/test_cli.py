"""Command-line behaviour: what a user sees on stdout/stderr and exit codes."""
import json

import pytest

from vex.cli import main
from conftest import fixture_path

ELF = str(fixture_path("hello_elf64"))
PE = str(fixture_path("hello_pe64.exe"))
DLL = str(fixture_path("sample.dll"))


def run(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out, out.err


def run_json(capsys, *args):
    code, out, _ = run(capsys, "--json", *args)
    assert code == 0
    return json.loads(out)


# --- info ------------------------------------------------------------------

def test_info_json_reports_identity_and_security(capsys):
    info = run_json(capsys, "info", ELF)
    assert (info["format"], info["arch"], info["bits"], info["kind"]) == \
        ("ELF", "x86_64", 64, "executable")
    assert info["entry"] == "0x10e0"
    assert info["security"]["relro"] == "full"
    assert info["libraries"] == ["libc.so.6"]
    assert info["hashes"]["md5"] == "c021be708cbd3f996eac31716b8e2b90"


def test_info_text_is_human_readable(capsys):
    code, out, _ = run(capsys, "info", PE)
    assert code == 0
    assert "PE 64-bit x86_64" in out
    assert "0x140001060" in out
    assert "KERNEL32.dll" in out
    assert "2023-11-14T22:13:20Z" in out


def test_addresses_are_hex_strings_so_64_bit_values_survive_json(capsys):
    info = run_json(capsys, "info", PE)
    assert info["image_base"] == "0x140000000"


# --- tables ----------------------------------------------------------------

def test_sections_json(capsys):
    rows = {r["name"]: r for r in run_json(capsys, "sections", ELF)}
    assert rows[".text"]["address"] == "0x10e0"
    assert rows[".text"]["perms"] == "r-x"
    assert rows[".text"]["size"] == 0x1D7
    assert 0 < rows[".text"]["entropy"] < 8


def test_imports_text_groups_by_library(capsys):
    _, out, _ = run(capsys, "imports", PE)
    assert "KERNEL32.dll" in out
    assert "WriteFile" in out and "0x1400020e0" in out


def test_exports_text_shows_forwarders(capsys):
    _, out, _ = run(capsys, "exports", DLL)
    assert "sample_add" in out and "0x180001000" in out
    assert "KERNEL32.Sleep" in out


def test_symbols_grep_filters_by_regex(capsys):
    rows = run_json(capsys, "symbols", ELF, "--grep", "^(main|add_)")
    assert sorted(r["name"] for r in rows) == ["add_numbers", "main"]


def test_functions_json_lists_names_and_sizes(capsys):
    rows = {r["name"]: r for r in run_json(capsys, "functions", ELF)}
    assert rows["main"] == {"address": "0x11f2", "size": 197, "name": "main", "source": "symbol"}


# --- strings ---------------------------------------------------------------

def test_strings_grep_and_tag_filter(capsys):
    rows = run_json(capsys, "strings", ELF, "--grep", "fixture")
    assert [r["text"] for r in rows] == [
        "s3cr3t-fixture-key", "Hello from the binspect ELF fixture"]
    tagged = run_json(capsys, "strings", ELF, "--tagged")
    assert all(r["tags"] for r in tagged)
    assert any(r["text"].startswith("Visit http://") for r in tagged)


def test_strings_minimum_length_and_encoding(capsys):
    rows = run_json(capsys, "strings", PE, "-e", "utf16", "-n", "6")
    assert [r["text"] for r in rows] == ["Wide fixture string"]


# --- disassembly -----------------------------------------------------------

def test_disasm_of_a_function_covers_exactly_that_function(capsys):
    listing = run_json(capsys, "disasm", ELF, "main")
    insns = listing["instructions"]
    assert listing["name"] == "main"
    assert len(insns) == 50
    assert insns[0]["address"] == "0x11f2" and insns[0]["mnemonic"] == "endbr64"
    assert insns[-1]["address"] == "0x12b2"
    assert insns[-1]["comment"] == "__stack_chk_fail@plt"


def test_disasm_count_and_default_location(capsys):
    listing = run_json(capsys, "disasm", ELF, "-n", "3")
    assert listing["name"] == "_start"                  # default: entry point
    assert [i["address"] for i in listing["instructions"]] == ["0x10e0", "0x10e4", "0x10e6"]


def test_disasm_text_shows_bytes_instruction_and_comment(capsys):
    _, out, _ = run(capsys, "disasm", ELF, "0x1237", "-n", "2")
    lines = [l for l in out.splitlines() if l.strip().startswith("0x")]
    assert "48 8d 3d fa 0d 00 00" in lines[0]
    assert "lea rdi, [rip + 0xdfa]" in lines[0]
    assert '; "Hello from the binspect ELF fixture"' in lines[0]
    assert "; puts@plt" in lines[1]


# --- xrefs -----------------------------------------------------------------

def test_xrefs_to_import(capsys):
    rows = run_json(capsys, "xrefs", ELF, "puts")
    assert [r["address"] for r in rows] == ["0x10a4", "0x123e", "0x1246", "0x1264"]
    assert rows[1] == {"address": "0x123e", "kind": "call", "function": "main+0x4c",
                       "text": "call 0x10a0"}


def test_xrefs_by_string_content(capsys):
    rows = run_json(capsys, "xrefs", ELF, "--string", "binspect ELF")
    assert [(r["address"], r["function"]) for r in rows] == [("0x1237", "main+0x45")]


def test_xrefs_requires_a_target(capsys):
    code, _, err = run(capsys, "xrefs", ELF)
    assert code == 1 and "target" in err.lower()


# --- hexdump ---------------------------------------------------------------

def test_hexdump_at_address(capsys):
    _, out, _ = run(capsys, "hexdump", ELF, "0x2004", "-n", "18")
    assert "73 33 63 72 33 74 2d 66 69 78 74 75 72 65 2d 6b" in out
    assert "s3cr3t-fixture-k" in out
    assert out.count("\n") == 2                         # 16 bytes + 2 bytes


def test_hexdump_by_file_offset_works_outside_loaded_ranges(capsys):
    _, out, _ = run(capsys, "hexdump", ELF, "--offset", "0x3010", "-n", "4")
    assert "47 43 43 3a" in out and "GCC:" in out


# --- report ----------------------------------------------------------------

def test_report_combines_the_main_views(capsys):
    code, out, _ = run(capsys, "report", PE)
    assert code == 0
    for heading in ("Overview", "Security", "Sections", "Imports", "Interesting strings", "Functions"):
        assert heading in out
    assert "https://example.com/update/check" in out
    data = run_json(capsys, "report", PE)
    assert set(data) >= {"info", "sections", "imports", "exports", "strings", "functions"}


# --- errors and presentation -----------------------------------------------

def test_missing_file_is_a_clean_error(capsys):
    code, out, err = run(capsys, "info", "/no/such/file.bin")
    assert code == 1 and out == ""
    assert err.startswith("vex: error:") and "Traceback" not in err


def test_non_binary_input_is_a_clean_error(capsys, tmp_path):
    text = tmp_path / "notes.txt"
    text.write_text("just some notes")
    code, _, err = run(capsys, "info", str(text))
    assert code == 1 and "not an ELF or PE file" in err


def test_unknown_location_is_a_clean_error(capsys):
    code, _, err = run(capsys, "disasm", ELF, "no_such_function")
    assert code == 1 and "no_such_function" in err


def test_bad_regex_is_a_clean_error(capsys):
    code, _, err = run(capsys, "strings", ELF, "--grep", "([")
    assert code == 1 and "regular expression" in err


def test_output_is_plain_when_not_a_terminal_and_coloured_on_request(capsys):
    _, plain, _ = run(capsys, "info", ELF)
    assert "\x1b[" not in plain
    _, coloured, _ = run(capsys, "--color", "always", "info", ELF)
    assert "\x1b[" in coloured


def test_no_color_environment_variable_wins_over_auto(capsys, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    _, out, _ = run(capsys, "info", ELF)
    assert "\x1b[" not in out


def test_no_arguments_prints_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_gui_command_starts_the_server_with_its_options(monkeypatch):
    from vex import server
    calls = []
    monkeypatch.setattr(server, "serve", lambda *a, **kw: calls.append((a, kw)) or 0)
    with pytest.raises(SystemExit) as exc:
        main(["gui", ELF, "--port", "9123", "--no-browser"])
    assert exc.value.code == 0
    assert calls == [((ELF, 9123, False), {"app_window": True})]
    with pytest.raises(SystemExit):
        main(["gui", "--browser"])                  # a browser tab, not vex's own window
    assert calls[1] == ((None, 0, True), {"app_window": False})


def test_session_link_carries_the_token_in_the_fragment():
    from vex import server
    httpd, ws = server.create_server(port=0, token="tok")
    try:
        url = server.session_url(httpd, ws, ELF)
        port = httpd.server_address[1]
        assert url.startswith(f"http://127.0.0.1:{port}/#token=tok&open=")
        assert "hello_elf64" in url and "?" not in url     # never sent to the server
    finally:
        httpd.server_close()
        ws.close()


def test_techniques_json_lists_categories_with_evidence(capsys):
    rows = run_json(capsys, "techniques", str(fixture_path("evasion_pe64.exe")))
    cats = {r["category"]: r for r in rows}
    assert set(cats) == {"packing", "anti-debug", "anti-vm", "injection", "hooking"}
    assert cats["injection"]["confidence"] == "high"
    assert "imports VirtualAllocEx" in cats["injection"]["evidence"]
    assert cats["packing"]["title"] and cats["packing"]["explanation"]


def test_techniques_text_is_quiet_for_an_ordinary_program(capsys):
    code, out, _ = run(capsys, "techniques", ELF)
    assert code == 0 and "No notable" in out


def test_report_includes_techniques_when_present(capsys):
    code, out, _ = run(capsys, "report", str(fixture_path("evasion_pe64.exe")))
    assert code == 0 and "Techniques" in out and "Anti-debugging" in out
    data = run_json(capsys, "report", str(fixture_path("evasion_pe64.exe")))
    assert any(t["category"] == "injection" for t in data["techniques"])
