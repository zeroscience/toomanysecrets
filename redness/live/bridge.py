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
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue

from ..events import Event, EventBus

_WEB_DIR = os.path.join(os.path.dirname(__file__), "web")


class LiveServer:
    def __init__(self, bus: EventBus, host: str = "127.0.0.1", port: int = 8765,
                 buffer_cap: int = 5000):
        self.bus = bus
        self.host = host
        self.port = port
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

        def _serve_static(self, rel: str, ctype: str):
            path = os.path.join(_WEB_DIR, rel)
            if not os.path.isfile(path):
                self.send_error(404)
                return
            with open(path, "rb") as fh:
                body = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._serve_static("index.html", "text/html; charset=utf-8")
            elif self.path == "/events":
                self._serve_events()
            else:
                self.send_error(404)

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
