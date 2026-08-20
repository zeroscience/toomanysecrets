"""Event bus - the seam between enumeration and any live consumer (a 3D GUI later).

Engines already normalize everything into `Finding` objects. This bus lets them
*stream* those (plus graph nodes/edges and status ticks) as they happen, so the same
data drives both the batch `.docx` report and a future live visualization - without
the engines knowing anything about the UI.

Design goals:
- Zero deps, synchronous, thread-safe enough for a background enum thread + UI reader.
- A subscriber that never raises back into the engine (a broken UI can't break a scan).
- Graph-shaped events (node/edge) so a force-directed 3D graph can render live.

A GUI subscribes (e.g. bridges these to WebSocket/SSE frames); the CLI can subscribe a
no-op or a progress printer. See docs/LIVE_GRAPH.md.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class EventKind(str, Enum):
    STATUS = "status"      # human-readable progress: {"message": ...}
    FINDING = "finding"    # a Finding surfaced: {"finding": <Finding.to_dict()>}
    NODE = "node"          # graph node: {"id","label","type","meta"}
    EDGE = "edge"          # graph edge: {"src","dst","label"}
    PROBE = "probe"        # something being tested right now (for animation): {"target","test"}
    DONE = "done"          # engine finished: {"engine": ...}


@dataclass
class Event:
    kind: EventKind
    data: dict[str, Any] = field(default_factory=dict)
    engine: str = ""
    ts: float = 0.0


Subscriber = Callable[[Event], None]


class EventBus:
    def __init__(self) -> None:
        self._subs: list[Subscriber] = []
        self._lock = threading.Lock()

    def subscribe(self, fn: Subscriber) -> Subscriber:
        with self._lock:
            self._subs.append(fn)
        return fn                     # returned so callers can later unsubscribe

    def unsubscribe(self, fn: Subscriber) -> None:
        with self._lock:
            if fn in self._subs:
                self._subs.remove(fn)

    def publish(self, event: Event) -> None:
        import time
        if not event.ts:
            event.ts = time.time()
        with self._lock:
            subs = list(self._subs)
        for fn in subs:
            try:
                fn(event)
            except Exception:
                # A misbehaving consumer must never break enumeration.
                pass


# A shared default bus engines publish to when no explicit bus is injected.
default_bus = EventBus()
