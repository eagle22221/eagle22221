"""Local web interface: `binspect gui`.

A small HTTP server bound to 127.0.0.1 that serves the single-page UI in
binspect/web and a JSON API over the same views the command line prints.

It can read (and, for modding, write) local files on the user's behalf, so
three things keep other web pages in the same browser from driving it:
  * every API call needs a random per-session token (sent in a header,
    which a cross-site page cannot set);
  * the Host header must be this server's own address, which defeats DNS
    rebinding;
  * no CORS headers are ever sent.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import webbrowser
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import parse_qs, quote, unquote, urlsplit

from . import load, views
from .analysis import Analysis
from .errors import BinspectError
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
        self.tempdir = tempfile.mkdtemp(prefix="binspect-")
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


GET_ROUTES: Dict[str, Callable] = {
    "info": _api_info, "layout": _api_layout, "sections": _api_sections,
    "segments": _api_segments, "imports": _api_imports, "exports": _api_exports,
    "symbols": _api_symbols, "strings": _api_strings, "functions": _api_functions,
    "disasm": _api_disasm, "xrefs": _api_xrefs, "hexdump": _api_hexdump,
    "open": _api_open, "browse": _api_browse,
}
POST_ROUTES: Dict[str, Callable] = {"upload": _api_upload}


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
    server_version = "binspect"
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
        except BinspectError as exc:
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
        supplied = self.headers.get("X-Binspect-Token") or ""
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


def serve(path: Optional[str] = None, port: int = 0, open_browser: bool = True) -> int:
    httpd, workspace = create_server(port)
    url = session_url(httpd, workspace, path)
    print(f"binspect is running at:\n\n  {url}\n\nPress Ctrl+C to stop.")
    sys.stdout.flush()
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
        workspace.close()
    return 0
