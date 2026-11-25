"""Local web interface: `vex gui`.

A small HTTP server bound to 127.0.0.1 that serves the single-page UI in
vex/web and a JSON API over the same views the command line prints.

It can read (and, for modding, write) local files on the user's behalf, so
three things keep other web pages in the same browser from driving it:
  * every API call needs a random per-session token (sent in a header,
    which a cross-site page cannot set);
  * the Host header must be this server's own address, which defeats DNS
    rebinding;
  * no CORS headers are ever sent.
"""
from __future__ import annotations

import errno
import hmac
import itertools
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import webbrowser
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlsplit

from . import load, views, window
from .analysis import Analysis
from .errors import VexError
from .model import Binary

WEB_DIR = Path(__file__).parent / "web"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8", ".woff2": "font/woff2",
    ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8", ".png": "image/png",
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; "
       "img-src 'self' blob: data:; connect-src 'self'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")
MAX_UPLOAD = 4 << 30
MAX_CACHED = 3


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Raw:
    """A non-JSON API response (file download, image, ...)."""

    def __init__(self, data: bytes, content_type: str, filename: Optional[str] = None):
        self.data = data
        self.content_type = content_type
        self.filename = filename


class Workspace:
    """Per-session state: access token, scratch folder, loaded files."""

    def __init__(self, token: Optional[str] = None):
        self.token = token or secrets.token_urlsafe(24)
        self.tempdir = tempfile.mkdtemp(prefix="vex-")
        self.lock = threading.RLock()
        self._cache: "OrderedDict[str, tuple]" = OrderedDict()
        self._uploads = 0

    def close(self) -> None:
        shutil.rmtree(self.tempdir, ignore_errors=True)

    def _entry(self, path: str) -> list:
        path = os.path.abspath(path)
        stat = os.stat(path)
        stamp = (stat.st_mtime_ns, stat.st_size)
        entry = self._cache.get(path)
        if entry is None or entry[0] != stamp:      # new, or changed on disk
            entry = [stamp, load(path), None, {}]
            self._cache[path] = entry
        self._cache.move_to_end(path)
        while len(self._cache) > MAX_CACHED:
            self._cache.popitem(last=False)
        return entry

    def binary(self, path: str) -> Binary:
        return self._entry(path)[1]

    def analysis(self, path: str) -> Analysis:
        entry = self._entry(path)
        if entry[2] is None:
            entry[2] = Analysis(entry[1])
        return entry[2]

    def memo(self, path: str, key, compute: Callable):
        """Cache a derived result (e.g. the string list) with the loaded file."""
        store = self._entry(path)[3]
        if key not in store:
            store[key] = compute()
        return store[key]

    def new_upload_path(self, name: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(name.replace("\\", "/")))
        safe = safe.lstrip(".") or "upload.bin"
        self._uploads += 1
        folder = os.path.join(self.tempdir, f"upload{self._uploads}")
        os.makedirs(folder)
        return os.path.join(folder, safe)


class Params:
    def __init__(self, query: str):
        self._q = parse_qs(query, keep_blank_values=True)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        values = self._q.get(name)
        return values[0] if values else default

    def need(self, name: str) -> str:
        value = self.get(name)
        if not value:
            raise ApiError(400, f"missing parameter: {name}")
        return value

    def number(self, name: str, default: Optional[int] = None) -> Optional[int]:
        value = self.get(name)
        if value in (None, ""):
            return default
        try:
            return int(value, 0)
        except ValueError:
            raise ApiError(400, f"parameter {name} must be a number") from None


def _page(rows: list, p: Params, default_limit: int) -> dict:
    start = max(0, p.number("offset", 0))
    limit = max(1, min(p.number("limit", default_limit), 20000))
    return {"total": len(rows), "items": rows[start:start + limit]}


def _contains(needle: Optional[str]):
    needle = (needle or "").lower()
    return (lambda text: needle in text.lower()) if needle else (lambda text: True)


# --- API handlers: (workspace, params, body) -> JSON-able data or Raw -----------

def _api_info(ws, p, body):
    return views.info(ws.binary(p.need("path")))


def _api_layout(ws, p, body):
    return views.layout(ws.binary(p.need("path")))


def _api_sections(ws, p, body):
    return views.sections(ws.binary(p.need("path")))


def _api_segments(ws, p, body):
    return views.segments(ws.binary(p.need("path")))


def _api_imports(ws, p, body):
    return views.imports(ws.binary(p.need("path")))


def _api_exports(ws, p, body):
    return views.exports(ws.binary(p.need("path")))


def _api_symbols(ws, p, body):
    match = _contains(p.get("q"))
    rows = [s for s in views.symbols(ws.binary(p.need("path"))) if match(s["name"])]
    return _page(rows, p, 2000)


def _api_strings(ws, p, body):
    path = p.need("path")
    minimum = max(1, p.number("min", 4))
    encoding = p.get("encoding", "all")
    if encoding not in ("all", "ascii", "utf16"):
        raise ApiError(400, "encoding must be all, ascii or utf16")
    rows = ws.memo(path, ("strings", minimum, encoding),
                   lambda: views.strings(ws.binary(path), minimum, encoding))
    match = _contains(p.get("q"))
    tagged = p.get("tagged") in ("1", "true")
    rows = [s for s in rows if match(s["text"]) and (s["tags"] or not tagged)]
    return _page(rows, p, 500)


def _api_functions(ws, p, body):
    match = _contains(p.get("q"))
    rows = [f for f in views.functions(ws.analysis(p.need("path"))) if match(f["name"])]
    return _page(rows, p, 5000)


def _api_disasm(ws, p, body):
    count = p.number("count")
    if count is not None:
        count = max(1, min(count, 5000))
    return views.disassembly(ws.analysis(p.need("path")), p.get("at") or None, count)


def _api_xrefs(ws, p, body):
    return views.xrefs(ws.analysis(p.need("path")), p.get("target"), p.get("string"))


def _api_techniques(ws, p, body):
    return views.techniques(ws.binary(p.need("path")))


def _api_entropy(ws, p, body):
    points = p.number("points", 64)
    return views.entropy_profile(ws.binary(p.need("path")), points)


def _api_hexdump(ws, p, body):
    length = max(1, min(p.number("length", 512), 65536))
    return views.hexdump(ws.binary(p.need("path")), p.number("address"),
                         p.number("offset"), length)


def _file_kind(path: str) -> str:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return "unknown"
    if magic == b"\x7fELF" or magic[:2] == b"MZ":
        return "binary"
    try:
        from . import archives
        if archives.is_archive(path):
            return "archive"
    except Exception:
        pass
    return "unknown"


def _api_open(ws, p, body):
    path = os.path.abspath(p.need("path"))
    if os.path.isdir(path):
        return {"kind": "folder", "path": path}
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return {"kind": _file_kind(path), "path": path, "name": os.path.basename(path)}


def _api_browse(ws, p, body):
    path = os.path.abspath(p.get("dir") or os.path.expanduser("~"))
    entries = []
    with os.scandir(path) as it:
        for entry in it:
            try:
                is_dir = entry.is_dir()
                size = None if is_dir else entry.stat().st_size
            except OSError:
                continue
            entries.append({"name": entry.name, "is_dir": is_dir, "size": size,
                            "kind": "folder" if is_dir else _file_kind(entry.path)})
            if len(entries) >= 5000:
                break
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    parent = os.path.dirname(path)
    roots = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")] \
        if os.name == "nt" else ["/"]
    return {"path": path, "parent": parent if parent != path else None,
            "home": os.path.expanduser("~"), "roots": roots, "entries": entries}


def _api_upload(ws, p, body):
    path = ws.new_upload_path(p.need("name"))
    with open(path, "wb") as f:
        shutil.copyfileobj(body, f)
    return {"path": path, "name": os.path.basename(path)}


# --- modding API: engines, asset packs, resources, patches -----------------------

MAX_PREVIEW = 64 << 20


def _api_engine(ws, p, body):
    return views.engine(p.need("path"))


def _archive(ws, p):
    from . import archives
    path = os.path.abspath(p.need("path"))
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return path, archives.open_archive(path)


def _api_archive_list(ws, p, body):
    _path, archive = _archive(ws, p)
    listing = views.archive_listing(archive)
    match = _contains(p.get("q"))
    page = _page([e for e in listing.pop("items") if match(e["name"])], p, 400)
    page.update(listing)
    return page


def _api_archive_file(ws, p, body):
    _path, archive = _archive(ws, p)
    name = p.need("name")
    entry = next((e for e in archive.entries if e.name == name), None)
    if entry is None:
        raise ApiError(404, f"no file named {name!r} in this pack")
    if entry.size > MAX_PREVIEW:
        raise ApiError(413, "this file is too large to preview; extract the pack instead")
    return Raw(archive.read(name), "application/octet-stream", os.path.basename(name))


def _api_archive_extract(ws, p, body):
    _path, archive = _archive(ws, p)
    dest = os.path.abspath(p.need("dest"))
    names = [p.get("name")] if p.get("name") else None
    written = archive.extract(dest, names)
    return {"dest": dest, "count": len(written)}


def _output_path(p: Params, source: str) -> str:
    out = os.path.abspath(p.need("out"))
    if os.path.isdir(out):
        raise ApiError(400, f"{out} is a folder; give a file name to save to")
    if not os.path.isdir(os.path.dirname(out)):
        raise ApiError(400, f"the folder {os.path.dirname(out)} does not exist")
    return out


def _api_archive_replace(ws, p, body):
    path, archive = _archive(ws, p)
    name = p.need("name")
    out = _output_path(p, path)
    if out == path:
        raise ApiError(400, "save the modified pack under a new name; "
                            "the original is left untouched")
    data = body.read()
    if any(e.name == name for e in archive.entries):
        archive.repack(out, replacements={name: data})
    else:
        archive.repack(out, additions={name: data})
    return {"out": out, "name": name, "size": len(data)}


def _resource(ws, p):
    from . import resources
    binary = ws.binary(p.need("path"))
    items = resources.list_resources(binary)
    index = p.number("index")
    if index is None or not 0 <= index < len(items):
        raise ApiError(404, "no such resource")
    return resources, binary, items[index]


def _api_resources(ws, p, body):
    return views.resources(ws.binary(p.need("path")))


def _api_resource_data(ws, p, body):
    resources, binary, res = _resource(ws, p)
    return Raw(resources.read_resource(binary, res), "application/octet-stream")


def _api_resource_icon(ws, p, body):
    resources, binary, res = _resource(ws, p)
    return Raw(resources.icon_file(binary, res), "application/octet-stream")


def _api_resource_replace(ws, p, body):
    resources, binary, res = _resource(ws, p)
    path = os.path.abspath(p.need("path"))
    out = _output_path(p, path)
    updated = resources.replace_resource(path, out, res, body.read())
    return {"out": out, "size": updated.size}


def _patch_target(ws, p) -> dict:
    """Where to write: a raw file offset, or an address / name in the program."""
    offset = p.number("offset")
    if offset is not None:
        return {"offset": offset}
    text = p.need("address")
    try:
        return {"vaddr": int(text, 0)}
    except ValueError:
        return {"vaddr": ws.analysis(p.need("path")).resolve(text)[0]}


def _api_patch_bytes(ws, p, body):
    from . import patch
    path = os.path.abspath(p.need("path"))
    text = re.sub(r"[\s,]|0x", "", p.need("hex"))
    try:
        data = bytes.fromhex(text)
    except ValueError:
        raise ApiError(400, "bytes must be written in hex, for example: 90 90 eb 05") from None
    if not data:
        raise ApiError(400, "no bytes given")
    out = _output_path(p, path)
    return views.patch_result(out, patch.apply_patch(path, out, data, **_patch_target(ws, p)))


def _api_patch_nop(ws, p, body):
    from . import patch
    path = os.path.abspath(p.need("path"))
    length = p.number("length")
    if not length or length < 1 or length > 1 << 20:
        raise ApiError(400, "the number of bytes must be at least 1")
    out = _output_path(p, path)
    filler = patch.nop_bytes(ws.binary(path), length)
    return views.patch_result(out, patch.apply_patch(path, out, filler, **_patch_target(ws, p)))


def _api_patch_string(ws, p, body):
    from . import patch
    path = os.path.abspath(p.need("path"))
    out = _output_path(p, path)
    results = patch.replace_string(path, out, p.need("old"), p.get("new") or "",
                                   p.get("encoding") or "ascii")
    return {"out": out, "patches": [views.patch_result(out, r) for r in results]}


# --- decode & cipher workbench ---------------------------------------------------

# JSON is read no deeper than this many nested lists and objects, as the C
# edition reads it (J_MAX_DEPTH in c/src/json.h).
JSON_MAX_DEPTH = 512
_JSON_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
_JSON_NOT_A_BRACKET = re.compile(r"[^\[\]{}]+")
_JSON_STEP = {"[": 1, "{": 1, "]": -1, "}": -1}


def _json_too_deep(raw: bytes) -> bool:
    """Is this document (one json.loads has read) nested deeper than
    JSON_MAX_DEPTH? Measured on the text, so that the earlier value of a
    repeated key, which json.loads drops, counts as well."""
    text = raw.decode(json.detect_encoding(raw), "surrogatepass")
    if text.count("[") + text.count("{") <= JSON_MAX_DEPTH:
        return False                    # too few brackets to be that deep
    brackets = _JSON_NOT_A_BRACKET.sub("", _JSON_STRING.sub("", text))
    deepest = max(itertools.accumulate(map(_JSON_STEP.__getitem__, brackets)), default=0)
    return deepest > JSON_MAX_DEPTH


def _json_body(body) -> dict:
    """Parse a POST request body as a JSON object; a malformed body is 400,
    and so is one nested deeper than JSON_MAX_DEPTH."""
    raw = body.read() or b"{}"
    try:
        parsed = json.loads(raw)
    except (ValueError, RecursionError):
        raise ApiError(400, "request body must be JSON") from None
    if _json_too_deep(raw):
        raise ApiError(400, "request body must be JSON")
    if not isinstance(parsed, dict):
        raise ApiError(400, "request body must be a JSON object")
    return parsed


def _decode_source(ws, source) -> Callable:
    """A callable producing the source bytes. A `file` source resolves against
    the open workspace program, bounded to the file (as other POST routes do)."""
    from . import decode
    if not isinstance(source, dict):
        raise ApiError(400, "source must be an object")
    kind = source.get("kind")
    if kind in ("text", "hex", "base64"):
        value = source.get("value") or ""
        return lambda: decode.source_bytes(kind, value)
    if kind == "file":
        path = source.get("path")
        # A path that is not text (or holds a NUL) names no file.
        if not path or not isinstance(path, str) or "\x00" in path:
            raise ApiError(400, "a file source needs a path")
        try:
            os.fsencode(path)
        except UnicodeEncodeError:      # a lone surrogate: no file has that name
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT),
                                    os.path.abspath(path)) from None
        data = ws.binary(path).data
        offset, length = source.get("offset") or 0, source.get("length")
        return lambda: decode.source_bytes("file", data=data, offset=offset, length=length)
    raise ApiError(400, "source kind must be text, hex, base64 or file")


def _api_decode_ops(ws, p, body):
    from . import decode
    return decode.ops()


def _api_decode(ws, p, body):
    from . import decode
    req = _json_body(body)
    get_source = _decode_source(ws, req.get("source"))
    steps = req.get("recipe") or []
    if not isinstance(steps, (list, dict, str)):
        raise ApiError(400, "recipe must be a list of steps")
    recipe = [(str(step.get("op")), step.get("params") or {})
              for step in steps if isinstance(step, dict)]
    return decode.run(get_source, recipe)


def _api_decode_solve(ws, p, body):
    from . import decode
    req = _json_body(body)
    get_source = _decode_source(ws, req.get("source"))
    return decode.solve(str(req.get("name")), get_source)


def _split_plan(ws, p):
    from . import split
    path = p.need("path")
    binary = ws.binary(path)
    return split, binary, ws.memo(path, "split", lambda: split.plan(binary))


def _api_split_preview(ws, p, body):
    split, binary, pieces = _split_plan(ws, p)
    return split.preview(binary, pieces)


def _api_split(ws, p, body):
    dest = p.need("dest")
    split, binary, pieces = _split_plan(ws, p)
    return split.split(binary, dest, pieces)


GET_ROUTES: Dict[str, Callable] = {
    "info": _api_info, "layout": _api_layout, "sections": _api_sections,
    "segments": _api_segments, "imports": _api_imports, "exports": _api_exports,
    "symbols": _api_symbols, "strings": _api_strings, "functions": _api_functions,
    "disasm": _api_disasm, "xrefs": _api_xrefs, "hexdump": _api_hexdump, "techniques": _api_techniques,
    "entropy": _api_entropy,
    "open": _api_open, "browse": _api_browse,
    "engine": _api_engine, "archive/list": _api_archive_list,
    "archive/file": _api_archive_file, "resources": _api_resources,
    "resource/data": _api_resource_data, "resource/icon": _api_resource_icon,
    "split": _api_split_preview, "decode/ops": _api_decode_ops,
}
POST_ROUTES: Dict[str, Callable] = {
    "upload": _api_upload, "archive/extract": _api_archive_extract,
    "archive/replace": _api_archive_replace, "resource/replace": _api_resource_replace,
    "patch/bytes": _api_patch_bytes, "patch/nop": _api_patch_nop,
    "patch/string": _api_patch_string, "split": _api_split,
    "decode": _api_decode, "decode/solve": _api_decode_solve,
}


class _Body:
    """File-like view of exactly Content-Length bytes of the request body."""

    def __init__(self, stream, length: int):
        self.stream, self.left = stream, length

    def read(self, size: int = -1) -> bytes:
        if self.left <= 0:
            return b""
        size = self.left if size < 0 else min(size, self.left)
        data = self.stream.read(size)
        self.left -= len(data)
        return data


class Handler(BaseHTTPRequestHandler):
    server_version = "vex"
    protocol_version = "HTTP/1.1"
    workspace: Workspace

    def log_message(self, fmt, *args):      # keep the terminal quiet
        pass

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    # -- plumbing -------------------------------------------------------------

    def _send(self, status: int, data: bytes, content_type: str,
              extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", CSP)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, status: int, payload) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _dispatch(self, method: str) -> None:
        port = self.server.server_address[1]
        length = int(self.headers.get("Content-Length") or 0)
        body = _Body(self.rfile, length)
        try:
            if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
                raise ApiError(403, "request refused: unexpected Host header")
            url = urlsplit(self.path)
            route = unquote(url.path)
            if route.startswith("/api/"):
                self._api(method, route[5:], Params(url.query), body, length)
            elif method == "GET":
                self._static(route)
            else:
                raise ApiError(404, "not found")
        except ApiError as exc:
            self._json(exc.status, {"error": str(exc)})
        except FileNotFoundError as exc:
            self._json(404, {"error": f"no such file or folder: {exc.filename or exc}"})
        except VexError as exc:
            self._json(400, {"error": str(exc)})
        except OSError as exc:
            self._json(400, {"error": f"{exc.strerror or exc}: {exc.filename or ''}".strip(": ")})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:            # a bug: report it, keep serving
            self._json(500, {"error": f"internal error: {type(exc).__name__}: {exc}"})
        finally:
            body.read()                     # keep the connection in sync

    def _api(self, method: str, name: str, params: Params, body, length: int) -> None:
        supplied = self.headers.get("X-Vex-Token") or ""
        if not hmac.compare_digest(supplied.encode(), self.workspace.token.encode()):
            raise ApiError(403, "missing or wrong session token")
        handler = (GET_ROUTES if method == "GET" else POST_ROUTES).get(name)
        if handler is None:
            raise ApiError(404, f"unknown API endpoint: {name}")
        if length > MAX_UPLOAD:
            raise ApiError(413, "upload too large")
        with self.workspace.lock:
            result = handler(self.workspace, params, body)
        if isinstance(result, Raw):
            extra = {"Content-Security-Policy": "sandbox; default-src 'none'"}
            if result.filename:
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", result.filename)
                extra["Content-Disposition"] = f'attachment; filename="{safe}"'
            self._send(200, result.data, result.content_type, extra)
        else:
            self._json(200, result)

    def _static(self, route: str) -> None:
        if route in ("/", "/index.html"):
            target = WEB_DIR / "index.html"
        elif route.startswith("/static/"):
            target = WEB_DIR / route[len("/static/"):]
        else:
            raise ApiError(404, "not found")
        root = os.path.realpath(WEB_DIR)
        real = os.path.realpath(target)
        if os.path.commonpath([root, real]) != root or not os.path.isfile(real):
            raise ApiError(404, "not found")
        ctype = CONTENT_TYPES.get(os.path.splitext(real)[1].lower())
        if ctype is None:
            raise ApiError(404, "not found")
        with open(real, "rb") as f:
            self._send(200, f.read(), ctype)


def create_server(port: int = 0, token: Optional[str] = None
                  ) -> Tuple[ThreadingHTTPServer, Workspace]:
    """Server bound to the loopback interface only. port=0 picks a free port."""
    workspace = Workspace(token)
    handler = type("BoundHandler", (Handler,), {"workspace": workspace})
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    httpd.daemon_threads = True
    return httpd, workspace


def session_url(httpd, workspace: Workspace, path: Optional[str] = None) -> str:
    # The token travels in the URL fragment, which browsers never send to servers.
    url = f"http://127.0.0.1:{httpd.server_address[1]}/#token={workspace.token}"
    if path:
        url += "&open=" + quote(os.path.abspath(path), safe="")
    return url


WINDOW_HINT = "It opened in its own window. Close that window, or press Ctrl+C here, to stop."
BROWSER_HINT = "Press Ctrl+C to stop."
FALLBACK_NOTE = ("\nThe app window could not be opened, so vex opened in your web browser "
                 "instead. " + BROWSER_HINT)
LOST_NOTE = ("\nvex could not follow its window, so it will keep running. " + BROWSER_HINT)


def _open_in_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _follow_window(proc, started: float, httpd, url: str) -> None:
    """Wait for the app window to close, then stop serving. A window that goes
    at once was never opened (fall back to the browser) or was taken over by a
    browser that is already running (keep serving)."""
    status = proc.wait()
    if httpd.stopping:
        return
    if time.monotonic() - started >= window.QUICK_EXIT_SECS:
        httpd.shutdown()
        return
    if status != 0:
        _open_in_browser(url)
    print(FALLBACK_NOTE if status != 0 else LOST_NOTE)
    sys.stdout.flush()


def serve(path: Optional[str] = None, port: int = 0, open_browser: bool = True,
          app_window: bool = True) -> int:
    """Serve the interface until stopped. It opens in its own window when a
    suitable browser is installed (and `app_window` is set), else in a tab."""
    httpd, workspace = create_server(port)
    httpd.stopping = False
    proc = None
    try:        # from here on, Ctrl+C at any moment stops vex the same clean way
        url = session_url(httpd, workspace, path)
        started = time.monotonic()
        if open_browser and app_window:
            proc = window.open_window(url, os.path.join(workspace.tempdir, "window"))
        print(f"vex is running at:\n\n  {url}\n\n{WINDOW_HINT if proc else BROWSER_HINT}")
        sys.stdout.flush()
        if proc is not None:
            threading.Thread(target=_follow_window, args=(proc, started, httpd, url),
                             daemon=True).start()
        elif open_browser:
            _open_in_browser(url)
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.stopping = True
        print("\nstopped.")
        window.close_window(proc)
        httpd.server_close()
        workspace.close()
    return 0
