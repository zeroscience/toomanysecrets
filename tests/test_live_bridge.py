"""LiveServer tests - pub/sub, replay buffer, and a real SSE round-trip.

Run:  python tests/test_live_bridge.py    (or)   python -m pytest -q
"""
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redness.events import Event, EventBus, EventKind  # noqa: E402
from redness.live.bridge import LiveServer  # noqa: E402


def test_replay_buffer_prefills_new_client():
    bus = EventBus()
    srv = LiveServer(bus, port=0)                      # no start(); pub/sub only
    bus.publish(Event(EventKind.NODE, {"id": "dc", "label": "dc", "type": "domain"}))
    bus.publish(Event(EventKind.STATUS, {"message": "hi"}))

    q = srv.register()                                 # connects "after" events
    first = json.loads(q.get_nowait())
    second = json.loads(q.get_nowait())
    assert first["kind"] == "node" and first["data"]["id"] == "dc"
    assert second["kind"] == "status"


def test_live_event_reaches_registered_client():
    bus = EventBus()
    srv = LiveServer(bus, port=0)
    q = srv.register()
    bus.publish(Event(EventKind.FINDING, {"finding": {"id": "x", "severity": "high"}}))
    got = json.loads(q.get(timeout=2))
    assert got["kind"] == "finding"
    assert got["data"]["finding"]["severity"] == "high"


def test_sse_http_roundtrip():
    """Start the server on an ephemeral port and read one SSE frame over HTTP."""
    bus = EventBus()
    srv = LiveServer(bus, port=0)
    url = srv.start()
    try:
        bus.publish(Event(EventKind.STATUS, {"message": "streaming works"}))
        with urllib.request.urlopen(url + "events", timeout=3) as resp:
            # readline returns the SSE data line as soon as it's flushed.
            payload = None
            for _ in range(10):
                raw = resp.readline()
                if raw.startswith(b"data:"):
                    payload = json.loads(raw[len(b"data:"):].strip())
                    break
            assert payload is not None
            assert payload["kind"] == "status"
            assert payload["data"]["message"] == "streaming works"
    finally:
        srv.stop()


def test_index_html_served():
    bus = EventBus()
    srv = LiveServer(bus, port=0)
    url = srv.start()
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            html = resp.read().decode("utf-8", "replace")
        assert "ForceGraph3D" in html and "/events" in html
    finally:
        srv.stop()


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
