"""Live bridge — EventBus -> browser, over Server-Sent Events (SSE).

Stdlib only (http.server), so it adds no dependency and bundles cleanly into the
frozen .exe. SSE (not WebSocket) because the stream is one-directional: engine -> UI.

- Subscribes to an EventBus; every published Event is fanned out to connected
  browsers as `data: {json}\n\n`.
- Keeps a capped replay buffer, so a browser that connects (or refreshes) mid-scan
  rebuilds the full graph — SSE has no built-in replay.
- Binds 127.0.0.1 only: engagement data never leaves the host.

Note: the front-end (web/index.html) currently loads 3d-force-graph from a CDN. For
offline / field use, vendor that JS locally before shipping in the exe (see
docs/LIVE_GRAPH.md).
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue
from typing import Callable, Optional

from ..events import Event, EventBus


def _web_dir() -> str:
    """Locate the web/ asset dir in both source and frozen (PyInstaller) runs."""
    if getattr(sys, "frozen", False):
        return os.path.join(getattr(sys, "_MEIPASS", ""), "redness", "live", "web")
    return os.path.join(os.path.dirname(__file__), "web")


_WEB_DIR = _web_dir()

_CTYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json",
    ".txt": "text/plain; charset=utf-8",
}


class LiveServer:
    def __init__(self, bus: EventBus, host: str = "127.0.0.1", port: int = 8765,
                 buffer_cap: int = 5000,
                 on_scan: Optional[Callable[[dict], None]] = None):
        self.bus = bus
        self.host = host
        self.port = port
        # Called with the posted params when the GUI starts a scan. None => /scan disabled.
        self.on_scan = on_scan
        # CSRF token injected into the page and required by POST /scan. A cross-origin
        # site can't read it (same-origin policy), so it can't forge a scan request.
        self.token = secrets.token_urlsafe(18)
        self._buffer: list[str] = []
        self._clients: set[Queue] = set()
        self._cap = buffer_cap
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        bus.subscribe(self._on_event)

    # -- pub/sub core (unit-testable without a socket) ----------------------- #
    @staticmethod
    def _payload(event: Event) -> str:
        return json.dumps({
            "kind": event.kind.value,
            "data": event.data,
            "engine": event.engine,
            "ts": event.ts,
        })

    def _on_event(self, event: Event) -> None:
        payload = self._payload(event)
        with self._lock:
            self._buffer.append(payload)
            if len(self._buffer) > self._cap:
                self._buffer = self._buffer[-self._cap:]
            clients = list(self._clients)
        for q in clients:
            q.put(payload)

    def register(self) -> Queue:
        """New SSE client: get a queue pre-loaded with the replay buffer."""
        q: Queue = Queue()
        with self._lock:
            for payload in self._buffer:
                q.put(payload)
            self._clients.add(q)
        return q

    def unregister(self, q: Queue) -> None:
        with self._lock:
            self._clients.discard(q)

    # -- HTTP server --------------------------------------------------------- #
    def start(self) -> str:
        handler = _make_handler(self)
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        # If port was 0, learn the actual bound port.
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


def _make_handler(live: LiveServer):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):        # silence default stderr logging
            pass

        def _serve_static(self, rel: str):
            # Resolve safely under _WEB_DIR (block path traversal).
            base = os.path.realpath(_WEB_DIR)
            path = os.path.realpath(os.path.join(base, rel))
            if not (path == base or path.startswith(base + os.sep)) or not os.path.isfile(path):
                self.send_error(404)
                return
            ctype = _CTYPES.get(os.path.splitext(path)[1].lower(), "application/octet-stream")
            with open(path, "rb") as fh:
                body = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._serve_index()
            elif path == "/events":
                self._serve_events()
            else:
                self._serve_static(path.lstrip("/"))   # vendor/, css, logo, etc.

        def _serve_index(self):
            path = os.path.join(_WEB_DIR, "index.html")
            if not os.path.isfile(path):
                self.send_error(404)
                return
            with open(path, encoding="utf-8") as fh:
                html = fh.read()
            # Inject the CSRF token and whether scanning is enabled.
            html = html.replace("__CSRF_TOKEN__", live.token)
            html = html.replace("__SCAN_ENABLED__", "1" if live.on_scan else "0")
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path.split("?", 1)[0] != "/scan":
                self.send_error(404)
                return
            if live.on_scan is None:
                self.send_error(403, "scanning disabled")
                return
            if self.headers.get("X-REDNESS-Token", "") != live.token:
                self.send_error(403, "bad token")
                return
            try:
                length = int(self.headers.get("Content-Length", 0))
                params = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self.send_error(400, "bad json")
                return
            # Run the scan off the request thread so the POST returns immediately.
            threading.Thread(target=live.on_scan, args=(params,), daemon=True).start()
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"started"}')

        def _serve_events(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = live.register()
            try:
                while True:
                    try:
                        payload = q.get(timeout=15)
                    except Empty:
                        self.wfile.write(b": ping\n\n")   # heartbeat
                        self.wfile.flush()
                        continue
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                live.unregister(q)

    return Handler
