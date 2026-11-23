"""Command-line interface: `binspect <command> FILE ...`."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from . import __version__, load, views
from .analysis import Analysis
from .errors import BinspectError, MissingDependencyError, UnsupportedError


# --- terminal styling ----------------------------------------------------------

class Style:
    CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
             "blue": "34", "magenta": "35", "cyan": "36"}

    def __init__(self, enabled: bool):
        self.enabled = enabled
        if enabled and os.name == "nt":
            os.system("")           # switches the Windows console to ANSI mode

    def __call__(self, text: str, *names: str) -> str:
        if not self.enabled or not names:
            return text
        return f"\x1b[{';'.join(self.CODES[n] for n in names)}m{text}\x1b[0m"


def _use_colour(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


def _table(headers: Sequence[str], rows: Sequence[Sequence[object]], st: Style,
           right: Sequence[int] = ()) -> List[str]:
    """Aligned text table; `right` lists the column indexes to right-align."""
    cells = [["" if c is None else str(c) for c in row] for row in rows]
    widths = [max([len(h)] + [len(r[i]) for r in cells]) for i, h in enumerate(headers)]

    def fmt(row, style=None):
        parts = [c.rjust(widths[i]) if i in right else c.ljust(widths[i])
                 for i, c in enumerate(row)]
        line = "  ".join(parts).rstrip()
        return st(line, style) if style else line

    return [fmt(headers, "bold"), st("  ".join("-" * w for w in widths), "dim")] + \
        [fmt(r) for r in cells]


def _heading(title: str, st: Style) -> List[str]:
    return ["", st(f"== {title} ==", "bold", "cyan")]


_STATE_COLOUR = {"good": "green", "bad": "red", "warn": "yellow"}
_KIND_COLOUR = {"call": "green", "jump": "yellow", "ret": "magenta"}


# --- text renderers -------------------------------------------------------------

def _render_info(d: dict, st: Style) -> List[str]:
    md = d["metadata"]
    rows = [
        ("File", d["name"] or "<memory>"),
        ("Format", f"{d['format']} {d['bits']}-bit {d['arch']}, {d['endian']}-endian, {d['kind']}"),
        ("Entry point", d["entry"] or "none"),
        ("Image base", d["image_base"]),
        ("Size", f"{d['size']} bytes"),
        ("Entropy", f"{d['entropy']:.2f} bits/byte" +
         ("  (high: packed or encrypted?)" if d["entropy"] > 7.2 else "")),
        ("MD5", d["hashes"]["md5"]),
        ("SHA-1", d["hashes"]["sha1"]),
        ("SHA-256", d["hashes"]["sha256"]),
        ("Libraries", ", ".join(d["libraries"]) or "none"),
    ]
    labels = {
        "interpreter": "Interpreter", "build_id": "Build ID", "soname": "SONAME",
        "compiler": "Compiler", "source_files": "Source files",
        "timestamp": "Timestamp", "subsystem": "Subsystem",
        "linker_version": "Linker version", "dll_name": "Internal name",
        "pdb_path": "PDB path", "imphash": "Import hash",
    }
    for key, label in labels.items():
        if key in md:
            value = md[key]
            rows.append((label, ", ".join(value) if isinstance(value, list) else str(value)))
    if "overlay" in md:
        rows.append(("Overlay", f"{md['overlay']['size']} bytes appended at offset "
                                 f"{md['overlay']['offset']:#x}"))
    width = max(len(r[0]) for r in rows)
    out = _heading("Overview", st)
    out += [f"{st(label.ljust(width), 'bold')}  {value}" for label, value in rows]
    out += _heading("Security", st)
    sec = d["security_details"]
    width = max((len(r["label"]) for r in sec), default=0)
    for r in sec:
        colour = _STATE_COLOUR.get(r["state"])
        out.append(f"{r['label'].ljust(width)}  " +
                   (st(r["value"], colour, "bold") if colour else r["value"]))
    if d["warnings"]:
        out += _heading("Warnings", st)
        out += [st(f"! {w}", "yellow") for w in d["warnings"]]
    return out


def _render_sections(rows: List[dict], st: Style) -> List[str]:
    def ent(r):
        text = f"{r['entropy']:.2f}"
        return text + (" !" if r["entropy"] > 7.2 else "")
    return _table(
        ["Name", "Address", "VSize", "Offset", "Size", "Perm", "Entropy", "Type"],
        [(r["name"], r["address"] or "-", f"{r['vsize']:#x}", f"{r['offset']:#x}",
          f"{r['size']:#x}", r["perms"], ent(r), r["type"]) for r in rows],
        st, right=(2, 3, 4, 6))


def _render_imports(rows: List[dict], st: Style) -> List[str]:
    if not rows:
        return ["(no imports)"]
    out: List[str] = []
    current = object()
    for r in rows:
        if r["library"] != current:
            current = r["library"]
            title = current or "(library not recorded)"
            if out:
                out.append("")
            out.append(st(title, "bold", "cyan"))
        extra = []
        if r["version"]:
            extra.append(r["version"])
        if r["delayed"]:
            extra.append("delay-loaded")
        out.append(f"  {r['address'] or '-':<14}  {r['name']}" +
                   (st("  [" + ", ".join(extra) + "]", "dim") if extra else ""))
    return out


def _render_exports(rows: List[dict], st: Style) -> List[str]:
    if not rows:
        return ["(no exports)"]
    return _table(["Ordinal", "Address", "Name", "Forwarded to"],
                  [("" if r["ordinal"] is None else r["ordinal"], r["address"] or "-",
                    r["name"], r["forwarder"] or "") for r in rows], st, right=(0,))


def _render_symbols(rows: List[dict], st: Style) -> List[str]:
    if not rows:
        return ["(no symbols)"]
    return _table(["Address", "Size", "Type", "Bind", "Section", "Name"],
                  [(r["address"], r["size"], r["type"], r["binding"], r["section"] or "",
                    r["name"]) for r in rows], st, right=(1,))


def _render_strings(rows: List[dict], st: Style) -> List[str]:
    if not rows:
        return ["(no strings)"]
    out = []
    for r in rows:
        where = r["address"] or f"@{r['offset']:#x}"
        tags = st(" [" + ",".join(r["tags"]) + "]", "yellow") if r["tags"] else ""
        wide = st(" (utf16)", "dim") if r["encoding"] == "utf16" else ""
        out.append(f"{where:<14}  {(r['section'] or ''):<10}  {r['text']}{tags}{wide}")
    return out


def _render_functions(rows: List[dict], st: Style) -> List[str]:
    if not rows:
        return ["(no functions)"]
    return _table(["Address", "Size", "Found by", "Name"],
                  [(r["address"], r["size"], r["source"], r["name"]) for r in rows],
                  st, right=(1,))


def _render_disassembly(d: dict, st: Style) -> List[str]:
    insns = d["instructions"]
    out = []
    width = max((len(i["bytes"]) for i in insns), default=0)
    width = width + width // 2          # room for a space after every byte
    text_width = min(44, max((len(f"{i['mnemonic']} {i['operands']}".strip())
                              for i in insns), default=0))
    for i in insns:
        if i["label"]:
            out += ["", st(f"{i['label']}:", "bold", "cyan")]
        raw = " ".join(i["bytes"][n:n + 2] for n in range(0, len(i["bytes"]), 2))
        mnemonic = st(i["mnemonic"], _KIND_COLOUR.get(i["kind"], "blue"))
        text = f"{i['mnemonic']} {i['operands']}".strip()
        pad = " " * max(0, text_width - len(text))
        line = f"  {st(i['address'] + ':', 'dim')}  {st(raw.ljust(width), 'dim')}  " \
               f"{mnemonic}{' ' + i['operands'] if i['operands'] else ''}"
        if i["comment"]:
            line += f"{pad}  {st('; ' + i['comment'], 'green')}"
        out.append(line)
    return out


def _render_xrefs(rows: List[dict], st: Style) -> List[str]:
    if not rows:
        return ["(no references found)"]
    return _table(["Address", "Kind", "In", "Instruction"],
                  [(r["address"], r["kind"], r["function"] or "", r["text"]) for r in rows], st)


def _render_hexdump(d: dict, st: Style) -> List[str]:
    return [f"{st(format(r['offset'], '08x'), 'dim')}  {(r['address'] or ''):<12}  "
            f"{r['hex']:<47}  |{r['ascii']}|" for r in d["rows"]]


def _render_report(d: dict, st: Style) -> List[str]:
    out = _render_info(d["info"], st)
    out += _heading("Sections", st) + _render_sections(d["sections"], st)
    out += _heading("Imports", st) + _render_imports(d["imports"], st)
    if d["exports"]:
        out += _heading("Exports", st) + _render_exports(d["exports"], st)
    out += _heading("Interesting strings", st)
    out += _render_strings(d["strings"][:60], st) if d["strings"] else ["(none tagged)"]
    if len(d["strings"]) > 60:
        out.append(st(f"... {len(d['strings']) - 60} more (binspect strings --tagged)", "dim"))
    out += _heading("Functions", st)
    if d["functions"] is None:
        out.append("(unavailable: " + d.get("functions_error", "no disassembler") + ")")
    else:
        out += _render_functions(d["functions"][:60], st)
        if len(d["functions"]) > 60:
            out.append(st(f"... {len(d['functions']) - 60} more (binspect functions)", "dim"))
    return out


# --- commands -------------------------------------------------------------------

def _int(text: str) -> int:
    return int(text, 0)


def _cmd_info(args, st):
    return views.info(load(args.file)), _render_info


def _cmd_sections(args, st):
    return views.sections(load(args.file)), _render_sections


def _cmd_imports(args, st):
    return views.imports(load(args.file)), _render_imports


def _cmd_exports(args, st):
    return views.exports(load(args.file)), _render_exports


def _cmd_symbols(args, st):
    return views.symbols(load(args.file), args.grep), _render_symbols


def _cmd_strings(args, st):
    return views.strings(load(args.file), args.min, args.encoding, args.grep,
                         args.tagged), _render_strings


def _cmd_functions(args, st):
    return views.functions(Analysis(load(args.file)), args.grep), _render_functions


def _cmd_disasm(args, st):
    return views.disassembly(Analysis(load(args.file)), args.location,
                             args.count), _render_disassembly


def _cmd_xrefs(args, st):
    return views.xrefs(Analysis(load(args.file)), args.target, args.string), _render_xrefs


def _cmd_hexdump(args, st):
    b = load(args.file)
    address = None
    if args.location is not None and args.offset is None:
        try:
            address = int(args.location, 0)
        except ValueError:
            address = Analysis(b).resolve(args.location)[0]
    return views.hexdump(b, address, args.offset, args.length), _render_hexdump


def _cmd_report(args, st):
    b = load(args.file)
    try:
        data = views.report(b, Analysis(b))
    except (MissingDependencyError, UnsupportedError) as exc:
        data = views.report(b, None)
        data["functions_error"] = str(exc)
    return data, _render_report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="binspect",
        description="Static reverse-engineering toolkit for Linux (ELF) and Windows (PE) "
                    "binaries. Files are only read, never run.")
    p.add_argument("--version", action="version", version=f"binspect {__version__}")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                   help="colour the output (default: only on a terminal)")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    def add(name, func, help_text, file_help="ELF or PE file to analyse"):
        sp = sub.add_parser(name, help=help_text, description=help_text)
        sp.add_argument("file", metavar="FILE", help=file_help)
        sp.set_defaults(func=func)
        return sp

    add("info", _cmd_info, "identity, hashes, metadata and security mitigations")
    add("sections", _cmd_sections, "section table with permissions and entropy")
    add("imports", _cmd_imports, "functions imported from other libraries")
    add("exports", _cmd_exports, "functions this file offers to others")
    sp = add("symbols", _cmd_symbols, "named addresses kept in the file")
    sp.add_argument("--grep", metavar="REGEX", help="only names matching REGEX")
    sp = add("strings", _cmd_strings, "printable text found in the file")
    sp.add_argument("-n", "--min", type=int, default=4, metavar="N",
                    help="minimum length (default 4)")
    sp.add_argument("-e", "--encoding", choices=("all", "ascii", "utf16"), default="all")
    sp.add_argument("--grep", metavar="REGEX", help="only strings matching REGEX")
    sp.add_argument("--tagged", action="store_true",
                    help="only URLs, IP addresses, e-mails, paths and registry keys")
    sp = add("functions", _cmd_functions, "functions found in the code")
    sp.add_argument("--grep", metavar="REGEX", help="only names matching REGEX")
    sp = add("disasm", _cmd_disasm, "disassemble a function or address range")
    sp.add_argument("location", nargs="?", metavar="LOCATION",
                    help="function/symbol/import name, 0x address, or 'entry' (default)")
    sp.add_argument("-n", "--count", type=int, metavar="N",
                    help="number of instructions (default: the whole function, else 32)")
    sp = add("xrefs", _cmd_xrefs, "find the code that uses an address, function or string")
    sp.add_argument("target", nargs="?", metavar="TARGET",
                    help="function/symbol/import name or 0x address")
    sp.add_argument("--string", metavar="TEXT", help="references to strings containing TEXT")
    sp = add("hexdump", _cmd_hexdump, "raw bytes at an address or file offset")
    sp.add_argument("location", nargs="?", metavar="LOCATION",
                    help="0x address or name (default: entry point)")
    sp.add_argument("--offset", type=_int, metavar="N", help="file offset instead of address")
    sp.add_argument("-n", "--length", type=_int, default=256, metavar="BYTES")
    add("report", _cmd_report, "everything at a glance")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    st = Style(_use_colour(args.color) and not args.json)
    try:
        data, renderer = args.func(args, st)
    except BinspectError as exc:
        print(f"binspect: error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"binspect: error: cannot read {getattr(args, 'file', 'file')}: "
              f"{exc.strerror or exc}", file=sys.stderr)
        return 1
    try:
        if args.json:
            print(json.dumps(data, indent=2))
        else:
            print("\n".join(renderer(data, st)).lstrip("\n"))
    except BrokenPipeError:         # e.g. piped into `head`
        sys.stderr.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
