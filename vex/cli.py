"""Command-line interface: `vex <command> FILE ...`."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional, Sequence

from . import __version__, load, views
from .analysis import Analysis
from .errors import VexError, MissingDependencyError, UnsupportedError


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


_CONFIDENCE_COLOUR = {"high": "red", "medium": "yellow"}


def _render_techniques(rows: List[dict], st: Style) -> List[str]:
    if not rows:
        return [st("No notable protection or evasion techniques found.", "green")]
    out = [st("vex identifies these techniques; it does not defeat them.", "dim")]
    for r in rows:
        out += ["", st(f"{r['title']}  [{r['confidence']}]",
                       "bold", _CONFIDENCE_COLOUR.get(r["confidence"], "cyan"))]
        out += [f"  - {e}" for e in r["evidence"]]
        out.append(st("  " + r["explanation"], "dim"))
    return out


def _render_report(d: dict, st: Style) -> List[str]:
    out = _render_info(d["info"], st)
    if d.get("techniques"):
        out += _heading("Techniques", st) + _render_techniques(d["techniques"], st)
    out += _heading("Sections", st) + _render_sections(d["sections"], st)
    out += _heading("Imports", st) + _render_imports(d["imports"], st)
    if d["exports"]:
        out += _heading("Exports", st) + _render_exports(d["exports"], st)
    out += _heading("Interesting strings", st)
    out += _render_strings(d["strings"][:60], st) if d["strings"] else ["(none tagged)"]
    if len(d["strings"]) > 60:
        out.append(st(f"... {len(d['strings']) - 60} more (vex strings --tagged)", "dim"))
    out += _heading("Functions", st)
    if d["functions"] is None:
        out.append("(unavailable: " + d.get("functions_error", "no disassembler") + ")")
    else:
        out += _render_functions(d["functions"][:60], st)
        if len(d["functions"]) > 60:
            out.append(st(f"... {len(d['functions']) - 60} more (vex functions)", "dim"))
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


def _cmd_techniques(args, st):
    return views.techniques(load(args.file)), _render_techniques


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


# --- modding commands -----------------------------------------------------------

def _render_engine(d: dict, st: Style) -> List[str]:
    out = [st(f"Looked in {d['root']}", "dim")]
    if not d["matches"]:
        out.append("No known game engine recognised.")
    for m in d["matches"]:
        details = ", ".join(f"{k}: {v}" for k, v in m["details"].items())
        out += ["", st(m["engine"], "bold", "cyan") +
                f"  ({m['confidence']} confidence{'; ' + details if details else ''})"]
        out += [f"  why: {e}" for e in m["evidence"]]
        out += [f"  next: {a}" for a in m["advice"]]
    out += _heading("Asset packs vex can open", st)
    out += [f"  {p['relative']}  ({p['size']} bytes)" for p in d["packs"]] or ["  (none found)"]
    return out


def _render_archive(d: dict, st: Style) -> List[str]:
    out = [st(f"{d['format']} pack, {d['count']} files" +
              ("" if d["writable"] else " (read-only)"), "bold")]
    out += [st(f"! {note}", "yellow") for note in d["notes"]]
    rows = [(e["name"], e["size"], ", ".join(
        w for w, on in (("compressed", e["compressed"]), ("encrypted", e["encrypted"])) if on))
        for e in d["items"]]
    return out + _table(["Name", "Size", "Stored"], rows, st, right=(1,))


def _render_resources(d: dict, st: Style) -> List[str]:
    if not d["items"]:
        return ["(no resources)"]
    out = _table(["Type", "Name", "Language", "Size", "Offset"],
                 [(r["type"], r["name"], r["language"], r["size"], f"{r['offset']:#x}")
                  for r in d["items"]], st, right=(2, 3, 4))
    if d["version"]:
        out += _heading("Version information", st)
        out += [f"{k}: {v}" for k, v in d["version"].items()]
    return out


def _render_split(d: dict, st: Style) -> List[str]:
    return _table(["Offset", "Size", "Kind", "File", "Name", "Note"],
                  [(f"{p['offset']:#x}", p["size"], p["kind"], p["path"] or "-", p["name"],
                    p["note"]) for p in d["pieces"]], st, right=(0, 1))


def _render_done(d: dict, st: Style) -> List[str]:
    out = [f"{p['address'] or 'file offset ' + format(p['offset'], '#x')}: "
           f"{p['old']} -> {p['new']}" for p in d.get("patches", [])]
    return out + [st(d["message"], "green", "bold")]


def _cmd_engine(args, st):
    return views.engine(args.file), _render_engine


def _read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _cmd_assets(args, st):
    from . import archives
    archive = archives.open_archive(args.file)
    if args.action == "list":
        return views.archive_listing(archive, args.grep), _render_archive
    if args.action == "extract":
        written = archive.extract(args.dest, args.names or None)
        return {"dest": os.path.abspath(args.dest), "count": len(written),
                "message": f"Extracted {len(written)} files to {args.dest}"}, _render_done
    data = _read_file(args.newfile)
    change = {"replacements": {args.name: data}} if args.action == "replace" \
        else {"additions": {args.name: data}}
    archive.repack(args.output, **change)
    verb = "Replaced" if args.action == "replace" else "Added"
    return {"out": os.path.abspath(args.output),
            "message": f"{verb} {args.name}; saved {args.output}"}, _render_done


def _cmd_resources(args, st):
    from . import resources
    binary = load(args.file)
    items = resources.list_resources(binary)
    if args.action == "list":
        return views.resources(binary), _render_resources
    if args.action == "extract":
        os.makedirs(args.dest, exist_ok=True)
        for res in items:
            is_icon = res.type == "GROUP_ICON"
            data = resources.icon_file(binary, res) if is_icon \
                else resources.read_resource(binary, res)
            stem = "".join(ch if ch.isalnum() or ch in "-_" else "_"
                           for ch in f"{res.type}_{res.name.lstrip('#')}_{res.language}")
            with open(os.path.join(args.dest, stem + (".ico" if is_icon else ".bin")), "wb") as f:
                f.write(data)
        return {"dest": os.path.abspath(args.dest), "count": len(items),
                "message": f"Extracted {len(items)} resources to {args.dest}"}, _render_done
    wanted = [r for r in items if r.type.lower() == args.type.lower()
              and r.name.lstrip("#") == args.name.lstrip("#")]
    if not wanted:
        raise VexError(f"no resource of type {args.type} named {args.name}; "
                            f"see: vex resources list {args.file}")
    updated = resources.replace_resource(args.file, args.output, wanted[0],
                                         _read_file(args.newfile))
    return {"out": os.path.abspath(args.output), "size": updated.size,
            "message": f"Replaced {args.type} {args.name}; saved {args.output}"}, _render_done


def _cmd_split(args, st):
    from . import split
    result = split.split(load(args.file), args.dest)
    summary = f"Saved {result['count']} files to {args.dest}"
    return result, lambda d, st: _render_split(d, st) + [st(summary, "green", "bold")]


def _cmd_patch(args, st):
    from . import patch
    if bool(args.output) == bool(args.in_place):
        raise VexError("say where to save: -o OUT for a modified copy, or "
                            "--in-place to change the file (a .bak backup is kept)")
    out = args.file if args.in_place else args.output
    if args.action == "string":
        results = patch.replace_string(args.file, out, args.old, args.new, args.encoding)
    else:
        binary = load(args.file)
        if args.offset:
            where = {"offset": int(args.location, 0)}
        else:
            try:
                where = {"vaddr": int(args.location, 0)}
            except ValueError:
                where = {"vaddr": Analysis(binary).resolve(args.location)[0]}
        if args.action == "nop":
            data = patch.nop_bytes(binary, args.length)
        else:
            try:
                data = bytes.fromhex(args.hex.replace("0x", "").replace(",", " "))
            except ValueError:
                raise VexError("bytes must be hex, for example: \"90 90 eb 05\"") from None
        results = [patch.apply_patch(args.file, out, data, **where)]
    return {"out": os.path.abspath(out),
            "patches": [views.patch_result(out, r) for r in results],
            "message": f"Saved {out}"}, _render_done


def _cmd_gui(args, st):
    from . import server
    raise SystemExit(server.serve(args.file, args.port, not args.no_browser))


# --- decode & cipher workbench --------------------------------------------------

def _decode_hexdump(data: bytes, st: Style, limit: int = 256) -> List[str]:
    shown = data[:limit]
    lines = []
    for i in range(0, len(shown), 16):
        chunk = shown[i:i + 16]
        hexpart = " ".join(f"{c:02x}" for c in chunk)
        text = "".join(chr(c) if 0x20 <= c <= 0x7E else "." for c in chunk)
        lines.append(f"{st(format(i, '08x'), 'dim')}  {hexpart:<47}  |{text}|")
    if len(data) > limit:
        lines.append(st(f"... {len(data) - limit} more bytes", "dim"))
    return lines


def _fmt_param(p: dict) -> str:
    value = "|".join(p["choices"]) if p.get("choices") else p["type"].upper()
    text = f"{p['name']}={value}"
    return text if p["required"] else f"[{text}]"


def _render_decode_ops(d: dict, st: Style) -> List[str]:
    out: List[str] = []
    for group in d["groups"]:
        out += _heading(group["name"], st)
        for o in group["ops"]:
            params = " ".join(_fmt_param(p) for p in o["params"])
            tag = "" if o["available"] else st("  (unavailable in this build)", "dim")
            out.append(f"  {st(o['name'], 'bold')} {params}".rstrip() +
                       f"  {st('- ' + o['summary'], 'dim')}{tag}")
    out += _heading("Solvers", st)
    for s in d["solvers"]:
        out.append(f"  {st(s['name'], 'bold')}  {st('- ' + s['summary'], 'dim')}")
    return out


def _render_decode_solve(d: dict, st: Style) -> List[str]:
    if not d["ok"]:
        return [st(f"error: {d['error']}", "red")]
    if not d["candidates"]:
        return ["(no candidates)"]
    out = []
    for i, c in enumerate(d["candidates"], 1):
        params = ", ".join(f"{k}={v}" for k, v in c["params"].items())
        preview = c["text"].replace("\n", " ").replace("\r", " ")[:60]
        score = st(f"{c['score']:.2f}", "bold")
        out.append(f"{i:2}. {score}  {params:<20}  {preview}")
    return out


def _render_decode(result: dict, raw: bytes, out_msg: Optional[str],
                   st: Style) -> List[str]:
    if out_msg is not None:
        return [st(out_msg, "green", "bold")]
    out: List[str] = []
    if result["steps"]:
        out.append(st("steps: " + " -> ".join(s["op"] for s in result["steps"]), "dim"))
    if not result["ok"]:
        out.append(st(f"error: {result['error']}", "red"))
    out.append(result["text"])
    out += _decode_hexdump(raw, st)
    out.append(f"{result['size']} bytes · looks like {result['looks_like']}")
    return out


def _decode_source(args):
    from . import decode
    if args.file is not None:
        data = _read_file(args.file)
        return lambda: decode.source_bytes("file", data=data, offset=args.offset,
                                           length=args.length)
    if args.text is not None:
        return lambda: decode.source_bytes("text", args.text)
    if args.hex is not None:
        return lambda: decode.source_bytes("hex", args.hex)
    if args.base64 is not None:
        return lambda: decode.source_bytes("base64", args.base64)
    if args.source is not None:
        return lambda: decode.source_bytes("text", args.source)
    raise VexError("give a source: --text, --hex, --base64, --file, or a bare TEXT argument")


def _cmd_decode(args, st):
    from . import decode
    if args.list:
        return decode.ops(), _render_decode_ops
    get_source = _decode_source(args)
    if args.solve:
        return decode.solve(args.solve, get_source), _render_decode_solve
    try:
        recipe = decode.parse_recipe(args.recipe)
    except decode.RecipeError as exc:
        print(f"vex: error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    if args.out and os.path.exists(args.out):
        raise VexError(f"{args.out} exists")
    er = decode.execute(get_source, recipe)
    result = decode.result_object(er)
    out_msg = None
    if args.out and er.ok:
        with open(args.out, "wb") as f:
            f.write(er.data)
        out_msg = f"wrote {len(er.data)} bytes to {os.path.abspath(args.out)}"
    return result, lambda d, s: _render_decode(d, er.data, out_msg, s)


def _add_decode(sub) -> None:
    sp = sub.add_parser(
        "decode", help="decode, decrypt and chain transforms (a local CyberChef)",
        description="Apply reversible transforms and supplied-key decryptions to data "
                    "you provide or select, and chain them into a recipe.")
    src = sp.add_mutually_exclusive_group()
    src.add_argument("--text", metavar="S", help="UTF-8 text")
    src.add_argument("--hex", metavar="S", help="a hex blob (spaces, 0x, : and , ignored)")
    src.add_argument("--base64", metavar="S", help="a base64 blob")
    src.add_argument("--file", metavar="PATH", help="bytes from a file")
    sp.add_argument("source", nargs="?", metavar="TEXT", help="text to decode (same as --text)")
    sp.add_argument("--offset", type=_int, default=0, metavar="O",
                    help="start offset for --file (default 0)")
    sp.add_argument("--length", type=_int, default=None, metavar="N",
                    help="bytes to read for --file (default: to the end)")
    sp.add_argument("--recipe", metavar="SPEC", default="",
                    help='operations to apply, e.g. "from-base64|gunzip|xor:key_text=KEY"')
    sp.add_argument("--solve", metavar="NAME",
                    help="run a solver: caesar, xor-single, xor-keylen, substitution")
    sp.add_argument("--out", metavar="FILE", help="write the raw output bytes (never overwrites)")
    sp.add_argument("--list", action="store_true", help="list available operations and solvers")
    sp.set_defaults(func=_cmd_decode)


def _add_modding(sub) -> None:
    sp = sub.add_parser("engine", help="identify a game's engine and find its asset packs")
    sp.add_argument("file", metavar="PATH", help="a game folder or its executable")
    sp.set_defaults(func=_cmd_engine)

    sp = sub.add_parser("assets", help="list, extract or replace files in an asset pack")
    actions = sp.add_subparsers(dest="action", metavar="ACTION")
    actions.required = True
    a = actions.add_parser("list", help="show the files in a pack")
    a.add_argument("file", metavar="PACK")
    a.add_argument("--grep", metavar="REGEX", help="only names matching REGEX")
    a = actions.add_parser("extract", help="unpack files into a folder")
    a.add_argument("file", metavar="PACK")
    a.add_argument("dest", metavar="FOLDER")
    a.add_argument("names", nargs="*", metavar="NAME", help="only these files (default: all)")
    for verb, text in (("replace", "swap one file in a pack"), ("add", "add a file to a pack")):
        a = actions.add_parser(verb, help=text + ", saving a new pack")
        a.add_argument("file", metavar="PACK")
        a.add_argument("name", metavar="NAME", help="path of the file inside the pack")
        a.add_argument("newfile", metavar="NEWFILE", help="file on disk with the new contents")
        a.add_argument("-o", "--output", required=True, metavar="OUT",
                       help="where to save the modified pack (the original is untouched)")
    sp.set_defaults(func=_cmd_assets)

    sp = sub.add_parser("resources", help="icons, version info and data inside a Windows program")
    actions = sp.add_subparsers(dest="action", metavar="ACTION")
    actions.required = True
    a = actions.add_parser("list", help="show the resources")
    a.add_argument("file", metavar="FILE")
    a = actions.add_parser("extract", help="save every resource into a folder")
    a.add_argument("file", metavar="FILE")
    a.add_argument("dest", metavar="FOLDER")
    a = actions.add_parser("replace", help="swap one resource, saving a new program")
    a.add_argument("file", metavar="FILE")
    a.add_argument("type", metavar="TYPE", help="e.g. RCDATA, MANIFEST, VERSION")
    a.add_argument("name", metavar="NAME", help="resource name or number, as listed")
    a.add_argument("newfile", metavar="NEWFILE")
    a.add_argument("-o", "--output", required=True, metavar="OUT")
    sp.set_defaults(func=_cmd_resources)

    sp = sub.add_parser("patch", help="change bytes, instructions or text in a program")
    actions = sp.add_subparsers(dest="action", metavar="ACTION")
    actions.required = True

    def common(a):
        a.add_argument("-o", "--output", metavar="OUT", help="save a modified copy here")
        a.add_argument("--in-place", action="store_true",
                       help="change FILE itself; the original is kept as FILE.bak")

    a = actions.add_parser("bytes", help="overwrite bytes at an address")
    a.add_argument("file", metavar="FILE")
    a.add_argument("location", metavar="LOCATION", help="0x address or name")
    a.add_argument("hex", metavar="HEX", help='new bytes, e.g. "90 90 eb 05"')
    a.add_argument("--offset", action="store_true", help="LOCATION is a file offset")
    common(a)
    a = actions.add_parser("nop", help="replace instructions with no-ops")
    a.add_argument("file", metavar="FILE")
    a.add_argument("location", metavar="LOCATION", help="0x address or name")
    a.add_argument("length", type=_int, metavar="BYTES", help="how many bytes to blank out")
    a.add_argument("--offset", action="store_true", help="LOCATION is a file offset")
    common(a)
    a = actions.add_parser("string", help="replace text in place (same length or shorter)")
    a.add_argument("file", metavar="FILE")
    a.add_argument("old", metavar="OLD")
    a.add_argument("new", metavar="NEW")
    a.add_argument("-e", "--encoding", choices=("ascii", "utf16"), default="ascii")
    common(a)
    sp.set_defaults(func=_cmd_patch)

    sp = sub.add_parser("gui", help="open the graphical interface in your browser")
    sp.add_argument("file", nargs="?", metavar="PATH", help="file or game folder to open")
    sp.add_argument("--port", type=int, default=0, help="port to listen on (default: any free)")
    sp.add_argument("--no-browser", action="store_true", help="only print the link")
    sp.set_defaults(func=_cmd_gui)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vex",
        description="Reverse-engineering toolkit for Linux (ELF) and Windows (PE) programs "
                    "and game asset packs. Files are never run; originals are never "
                    "changed unless you ask.")
    p.add_argument("--version", action="version", version=f"vex {__version__}")
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
    add("techniques", _cmd_techniques,
        "protection and evasion techniques: packing, anti-debug, anti-VM, "
        "injection, hooking, drivers")
    add("report", _cmd_report, "everything at a glance")
    sp = add("split", _cmd_split, "save the parts of a program as separate files: its "
             "sections, files embedded in it and its resources")
    sp.add_argument("dest", metavar="FOLDER", help="new or empty folder to save into")
    _add_decode(sub)
    _add_modding(sub)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:        # never die on a character the Windows console cannot show
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    st = Style(_use_colour(args.color) and not args.json)
    try:
        data, renderer = args.func(args, st)
    except VexError as exc:
        print(f"vex: error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"vex: error: cannot read {getattr(args, 'file', 'file')}: "
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
