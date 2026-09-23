"""Live bridge - EventBus -> browser, over Server-Sent Events (SSE).

Stdlib only (http.server), so it adds no dependency and bundles cleanly into the
frozen .exe. SSE (not WebSocket) because the stream is one-directional: engine -> UI.

- Subscribes to an EventBus; every published Event is fanned out to connected
  browsers as `data: {json}\n\n`.
- Keeps a capped replay buffer, so a browser that connects (or refreshes) mid-scan
  rebuilds the full graph - SSE has no built-in replay.
- Binds 127.0.0.1 only: engagement data never leaves the host.

Note: the front-end (web/index.html) currently loads 3d-force-graph from a CDN. For
offline / field use, vendor that JS locally before shipping in the exe (see
docs/LIVE_GRAPH.md).
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue
from typing import Callable, Optional

from ..events import Event, EventBus


class _LiveHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a platform-aware address-reuse policy.

    http.server.HTTPServer sets ``allow_reuse_address = 1`` unconditionally, which
    maps to SO_REUSEADDR. On Windows SO_REUSEADDR does NOT mean "reuse a TIME_WAIT
    port" (POSIX) - it lets a *second* socket bind a port another socket is already
    using. With many short-lived servers on port 0 (the test suite), two of them
    can then land on the same ephemeral port and requests get routed to the wrong
    server or reset mid-flight (WinError 10054) - the transient bridge-test failures.

    So: keep SO_REUSEADDR on POSIX (clean restart of the fixed production port past
    TIME_WAIT), but on Windows take the port exclusively via SO_EXCLUSIVEADDRUSE so
    the OS never hands it to anyone else.
    """

    daemon_threads = True
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # Mutually exclusive with SO_REUSEADDR; allow_reuse_address is False on
            # nt so the base server_bind() won't also set SO_REUSEADDR.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def _web_dir() -> str:
    """Locate the web/ asset dir in both source and frozen (PyInstaller) runs."""
    if getattr(sys, "frozen", False):
        return os.path.join(getattr(sys, "_MEIPASS", ""), "redness", "live", "web")
    return os.path.join(os.path.dirname(__file__), "web")


_WEB_DIR = _web_dir()


def _is_loopback(host: str) -> bool:
    """True only for loopback binds. The offensive channel refuses anything else (never 0.0.0.0)."""
    return host in {"127.0.0.1", "localhost", "::1"} or host.startswith("127.")

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
                 on_scan: Optional[Callable[[dict], None]] = None,
                 on_action: Optional[Callable[[dict], None]] = None,
                 action_catalog: Optional[list] = None,
                 on_arm: Optional[Callable[[dict], dict]] = None,
                 on_execute: Optional[Callable[[dict], None]] = None,
                 enable_offensive: bool = False):
        self.bus = bus
        self.host = host
        self.port = port
        # Called with posted params for a GUI-initiated scan / right-click action.
        # None => that endpoint is disabled (403).
        self.on_scan = on_scan
        self.on_action = on_action
        # Serializable action list (GET /actions) so the GUI builds context menus.
        self.action_catalog = action_catalog or []
        # CSRF token injected into the page and required by POST /scan. A cross-origin
        # site can't read it (same-origin policy), so it can't forge a scan request.
        self.token = secrets.token_urlsafe(18)
        # Offensive channel (arm/execute) - OFF unless explicitly enabled at launch.
        # It carries a SEPARATE, more-privileged token that is NOT injected into the page:
        # the operator reads it from the console and pastes it into the GUI, so page access
        # alone can never fire an offensive action. Refused entirely on a non-loopback bind.
        self.on_arm = on_arm
        self.on_execute = on_execute
        self.offensive_enabled = bool(enable_offensive)
        if self.offensive_enabled and not _is_loopback(host):
            raise RuntimeError(
                f"refusing to enable the offensive channel on non-loopback bind {host!r} "
                "(offensive actions require host=127.0.0.1)")
        self.offensive_token = secrets.token_urlsafe(24) if self.offensive_enabled else None
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
        self._httpd = _LiveHTTPServer((self.host, self.port), handler)
        # If port was 0, learn the actual bound port.
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.url

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def stop(self) -> None:
        # Deterministic, idempotent teardown: stop the serve loop, close the
        # listening socket, then join the serve thread so the port is fully
        # released before the next server (or test) binds.
        httpd, self._httpd = self._httpd, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5)


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
            elif path == "/actions":
                cat = live.action_catalog if live.on_action else []
                if not live.offensive_enabled:      # hide offensive actions unless armed at launch
                    cat = [a for a in cat if not a.get("offensive")]
                self._serve_json(cat)
            else:
                self._serve_static(path.lstrip("/"))   # vendor/, css, logo, etc.

        def _serve_json(self, obj):
            self._serve_json_code(obj, 200)

        def _serve_json_code(self, obj, code):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _serve_index(self):
            path = os.path.join(_WEB_DIR, "index.html")
            if not os.path.isfile(path):
                self.send_error(404)
                return
            with open(path, encoding="utf-8") as fh:
                html = fh.read()
            # Inject the CSRF token and whether scanning is enabled. The offensive token is
            # deliberately NOT injected - only whether the channel is enabled, so the GUI can
            # show the "paste offensive token" field; the token itself stays on the console.
            html = html.replace("__CSRF_TOKEN__", live.token)
            html = html.replace("__SCAN_ENABLED__", "1" if live.on_scan else "0")
            html = html.replace("__OFFENSIVE_ENABLED__", "1" if live.offensive_enabled else "0")
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _drain_body(self) -> bytes:
            """Read the whole request body so the socket receive buffer is empty.

            An early error return (bad token, etc.) that closes the connection while
            the request body is still unread makes Windows send an RST - the client
            then sees a connection reset (WinError 10054) instead of our response.
            Draining first keeps the close graceful. Returns the raw body bytes.
            """
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                length = 0
            return self.rfile.read(length) if length > 0 else b""

        def _handle_offensive(self, path, body: bytes):
            # Separate, more-privileged gate: the offensive channel must be enabled at launch
            # AND the caller must present the console-only offensive token. Neither the read
            # token nor page access is enough. (Body already drained by do_POST.)
            if not live.offensive_enabled:
                self.send_error(403, "offensive channel disabled")
                return
            if self.headers.get("X-Redness-Offensive", "") != live.offensive_token:
                self.send_error(403, "bad offensive token")
                return
            try:
                params = json.loads(body or b"{}")
            except (ValueError, json.JSONDecodeError):
                self.send_error(400, "bad json")
                return
            if path == "/action/arm":
                if live.on_arm is None:
                    self.send_error(403, "endpoint disabled")
                    return
                try:
                    result = live.on_arm(params)               # {arm_token, expires_in, banner}
                except Exception as e:                          # ArmError (rate-limit / not offensive)
                    code = 429 if "rate" in str(e).lower() else 400
                    self._serve_json_code({"error": str(e)}, code)
                    return
                self._serve_json(result)
                return
            # /action/execute - the confirmation rides an HTTP header, never the body.
            if live.on_execute is None:
                self.send_error(403, "endpoint disabled")
                return
            params = dict(params)
            params["confirm"] = self.headers.get("X-Redness-Confirm", "")
            threading.Thread(target=live.on_execute, args=(params,), daemon=True).start()
            self._serve_json_code({"status": "executing"}, 202)

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            # Always drain the request body first, before any token/route check that
            # might error out early - see _drain_body() for why (Windows RST race).
            body = self._drain_body()
            if path in ("/action/arm", "/action/execute"):
                self._handle_offensive(path, body)
                return
            handler = {"/scan": live.on_scan, "/action": live.on_action}.get(path)
            if path not in ("/scan", "/action"):
                self.send_error(404)
                return
            if handler is None:
                self.send_error(403, "endpoint disabled")
                return
            if self.headers.get("X-REDNESS-Token", "") != live.token:
                self.send_error(403, "bad token")           # cross-origin can't read the token
                return
            try:
                params = json.loads(body or b"{}")
            except (ValueError, json.JSONDecodeError):
                self.send_error(400, "bad json")
                return
            # Run off the request thread so the POST returns immediately.
            threading.Thread(target=handler, args=(params,), daemon=True).start()
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
